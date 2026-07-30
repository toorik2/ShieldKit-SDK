/*
 * Real-store Q-07 measurement primitive.  This deliberately does not call
 * the Q-04 checkpoint probes: each mode has one explicit authenticated audit
 * boundary and reports a non-qualifying record for a parent to aggregate.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeSync,
  fsyncSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";

import { canonicalJson, parseStrictJson } from "../packages/profile/load.mjs";
import {
  openQ04PersistentNullifierStore,
} from "../packages/pool/v2/qualification/persistent-nullifier-store.mjs";
import {
  q04HistorySeed,
} from "../packages/pool/v2/qualification/q04-schedule.mjs";
import {
  createQ07SingleHistoryKeyStream,
  verifyQ07SingleHistoryDataset,
  V2_Q07_MAIN_HISTORY_COUNT,
} from "./v2-q07-dataset.mjs";

export const Q07_STORE_WORKER_SCHEMA =
  "shieldkit-v2-direct/q07-store-worker-config/v1";
export const Q07_STORE_WORKER_OUTPUT_SCHEMA =
  "shieldkit-v2-direct/q07-store-worker-output/v1";
export const Q07_STORE_WORKER_MODES = Object.freeze([
  "full-history-build",
  "reference-insert",
  "warm-insert",
  "full-store-audit",
  "suffix-insert",
  "reopened-handle-path",
]);

const MAX_STREAM_ENTRIES = 100_001;
const HEX32 = /^[0-9a-f]{64}$/;
const FIXED_COUNTER_KEYS = Object.freeze([
  "productionLeafHashCalls",
  "productionLogicalPathSiblingLookups",
  "productionMutationLeafHashCalls",
  "productionMutationNodeHashCalls",
  "productionLeafReads",
  "productionOrderLookups",
  "productionPathAdapterNodeReads",
  "productionPathOverrideHits",
  "productionPredecessorValidationLeafHashCalls",
  "productionPostMembershipNodeHashCalls",
  "productionPostMembershipNodeReads",
  "productionRootAdapterNodeReads",
  "productionTotalAdapterNodeReads",
]);

export class Q07StoreWorkerError extends Error {
  constructor(message) {
    super(message);
    this.name = "Q07StoreWorkerError";
  }
}

const fail = (message) => { throw new Q07StoreWorkerError(message); };
const freeze = (value) => Object.freeze(value);
const exactKeys = (value, keys, label) => {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
};
const integer = (value, low, high, label) => {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(`${label} must be an integer from ${low} through ${high}`);
  }
  return value;
};
const hex32 = (value, label) => {
  if (typeof value !== "string" || !HEX32.test(value)) fail(`${label} must be lowercase 32-byte hex`);
  return Buffer.from(value, "hex");
};
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const elapsed = (started) => Number((performance.now() - started).toFixed(6));

function privateParent(path, label) {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path) {
    fail(`${label} must be an absolute normalized path`);
  }
  const parent = dirname(path);
  let observed;
  try { observed = lstatSync(parent); } catch { fail(`${label} parent is unavailable`); }
  if (
    !observed.isDirectory() || observed.isSymbolicLink() ||
    realpathSync(parent) !== parent ||
    (observed.mode & 0o777) !== 0o700 ||
    (typeof process.getuid === "function" && observed.uid !== process.getuid())
  ) fail(`${label} parent must be a direct user-owned mode-0700 directory`);
  return path;
}

function privateFile(path, label) {
  let observed;
  try { observed = lstatSync(path); } catch { fail(`${label} is unavailable`); }
  if (
    !observed.isFile() || observed.isSymbolicLink() || observed.nlink !== 1 ||
    realpathSync(path) !== path ||
    (observed.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" && observed.uid !== process.getuid())
  ) fail(`${label} must be a direct single-link user-owned mode-0600 file`);
  return observed;
}

function absent(path, label) {
  if (existsSync(path)) fail(`${label} must not already exist`);
}

function closedStore(path, label) {
  privateParent(path, label);
  privateFile(path, label);
  for (const sidecar of [`${path}-wal`, `${path}-shm`]) {
    if (existsSync(sidecar)) fail(`${label} must be closed (SQLite sidecar exists)`);
  }
}

function noSidecars(path, label) {
  for (const sidecar of [`${path}-wal`, `${path}-shm`]) {
    if (existsSync(sidecar)) fail(`${label} left a SQLite sidecar after close`);
  }
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, constants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function parseExpectedState(value, label) {
  exactKeys(value, ["logicalDigestSha256", "normalCount", "root", "transcriptChainSha256"], label);
  return freeze({
    normalCount: integer(value.normalCount, 0, MAX_STREAM_ENTRIES, `${label}.normalCount`),
    root: hex32(value.root, `${label}.root`),
    transcriptChainSha256: hex32(value.transcriptChainSha256, `${label}.transcriptChainSha256`),
    logicalDigestSha256: hex32(value.logicalDigestSha256, `${label}.logicalDigestSha256`).toString("hex"),
  });
}

function modeKeys(mode) {
  const common = ["databasePath", "dataset", "endOrdinal", "historyIndex", "mode", "resultPath", "schema"];
  if (mode === "full-history-build") return common;
  if (mode === "full-store-audit") return [...common, "expectedPreparedState"];
  if (mode === "reference-insert") return [...common, "expectedPreparedState", "preparedDatabaseSha256", "preparedStorePath"];
  if (mode === "warm-insert") return [...common, "expectedPostState", "expectedPreparedState", "preparedDatabaseSha256", "preparedStorePath"];
  if (mode === "suffix-insert") return [...common, "expectedPostState", "expectedPreparedState", "preparedDatabaseSha256", "preparedStorePath", "startOrdinal"];
  if (mode === "reopened-handle-path") return [...common, "expectedPreparedState", "preparedDatabaseSha256", "preparedStorePath", "readPhysicalIndex"];
  fail("Q-07 worker mode is unsupported");
}

function parseDataset(value) {
  exactKeys(value, ["mainCount", "path", "sha256", "transcriptSha256"], "dataset");
  const mainCount = integer(value.mainCount, 2, V2_Q07_MAIN_HISTORY_COUNT, "dataset.mainCount");
  return freeze({
    mainCount,
    path: privateParent(value.path, "dataset.path"),
    sha256: hex32(value.sha256, "dataset.sha256").toString("hex"),
    transcriptSha256: hex32(value.transcriptSha256, "dataset.transcriptSha256").toString("hex"),
  });
}

function parseConfig(value) {
  if (value === null || Array.isArray(value) || typeof value !== "object") fail("Q-07 worker config must be an object");
  if (value.schema !== Q07_STORE_WORKER_SCHEMA) fail("Q-07 worker config schema differs");
  if (!Q07_STORE_WORKER_MODES.includes(value.mode)) fail("Q-07 worker mode is unsupported");
  exactKeys(value, modeKeys(value.mode), "Q-07 worker config");
  const mode = value.mode;
  const config = {
    mode,
    historyIndex: integer(value.historyIndex, 0, 3, "historyIndex"),
    dataset: parseDataset(value.dataset),
    endOrdinal: integer(value.endOrdinal, 1, MAX_STREAM_ENTRIES, "endOrdinal"),
    databasePath: privateParent(value.databasePath, "databasePath"),
    resultPath: privateParent(value.resultPath, "resultPath"),
  };
  if (config.endOrdinal > config.dataset.mainCount + 1) fail("endOrdinal exceeds the bound dataset");
  if (["full-store-audit", "reference-insert", "warm-insert", "suffix-insert", "reopened-handle-path"].includes(mode)) {
    config.expectedPreparedState = parseExpectedState(value.expectedPreparedState, "expectedPreparedState");
  }
  if (["reference-insert", "warm-insert", "suffix-insert", "reopened-handle-path"].includes(mode)) {
    config.preparedStorePath = privateParent(value.preparedStorePath, "preparedStorePath");
    config.preparedDatabaseSha256 = hex32(value.preparedDatabaseSha256, "preparedDatabaseSha256").toString("hex");
  }
  if (["warm-insert", "suffix-insert"].includes(mode)) {
    config.expectedPostState = parseExpectedState(value.expectedPostState, "expectedPostState");
  }
  if (mode === "suffix-insert") {
    config.startOrdinal = integer(value.startOrdinal, 1, config.endOrdinal, "startOrdinal");
    if (config.startOrdinal !== config.expectedPreparedState.normalCount + 1) fail("suffix startOrdinal must follow expectedPreparedState.normalCount");
  }
  if (["reference-insert", "warm-insert"].includes(mode) && config.expectedPreparedState.normalCount + 1 !== config.endOrdinal) {
    fail(`${mode} requires endOrdinal immediately after expectedPreparedState.normalCount`);
  }
  if (["full-store-audit", "reopened-handle-path"].includes(mode) && config.expectedPreparedState.normalCount !== config.endOrdinal) {
    fail(`${mode} endOrdinal differs from expectedPreparedState.normalCount`);
  }
  if (mode === "reopened-handle-path") {
    config.readPhysicalIndex = integer(value.readPhysicalIndex, 0, config.expectedPreparedState.normalCount + 1, "readPhysicalIndex");
  }
  if (config.databasePath === config.resultPath) fail("databasePath and resultPath must differ");
  return freeze(config);
}

function verifiedDataset(config) {
  const testOnlyMainCount = config.dataset.mainCount === V2_Q07_MAIN_HISTORY_COUNT
    ? undefined : config.dataset.mainCount;
  const verified = verifyQ07SingleHistoryDataset({ path: config.dataset.path, testOnlyMainCount });
  if (verified.sha256 !== config.dataset.sha256 || verified.transcriptSha256 !== config.dataset.transcriptSha256 || verified.mainCount !== config.dataset.mainCount) {
    fail("dataset SHA-256, transcript, or main count differs from config binding");
  }
  const stream = createQ07SingleHistoryKeyStream({ testOnlyMainCount });
  const keys = [];
  for (let entry = stream.next(); entry !== null; entry = stream.next()) keys.push(Buffer.from(entry.key, "hex"));
  return freeze({ verified, keys: freeze(keys) });
}

function stateMatches(store, expected, label) {
  const state = store.state();
  if (
    state.normalCount !== expected.normalCount || !state.root.equals(expected.root) ||
    !state.transcriptChainSha256.equals(expected.transcriptChainSha256)
  ) fail(`${label} root, count, or transcript differs`);
  return state;
}

function auditRecord(audit) {
  return freeze({
    normalCount: audit.normalCount,
    root: hex(audit.root),
    transcriptChainSha256: hex(audit.transcriptChainSha256),
    logicalDigestSha256: audit.logicalDigestSha256,
    leafCount: audit.leafCount,
    nodeCount: audit.nodeCount,
    orderCount: audit.orderCount,
  });
}

function fixedCounters(mutation, postPath = null) {
  const m = mutation.metrics;
  const value = {
    productionLeafHashCalls: m.leafHashCalls,
    productionLogicalPathSiblingLookups: m.logicalPathSiblingLookups,
    productionMutationLeafHashCalls: m.mutationLeafHashCalls,
    productionMutationNodeHashCalls: m.nodeHashCalls,
    productionLeafReads: m.leafReads,
    productionOrderLookups: m.orderLookups,
    productionPathAdapterNodeReads: m.pathAdapterNodeReads,
    productionPathOverrideHits: m.pathOverrideHits,
    productionPredecessorValidationLeafHashCalls: m.predecessorValidationLeafHashCalls,
    productionPostMembershipNodeHashCalls: postPath?.metrics.nodeHashCalls ?? 0,
    productionPostMembershipNodeReads: postPath?.metrics.nodeReads ?? 0,
    productionRootAdapterNodeReads: m.rootAdapterNodeReads,
    productionTotalAdapterNodeReads: m.nodeReads,
  };
  for (const key of FIXED_COUNTER_KEYS) integer(value[key], 0, Number.MAX_SAFE_INTEGER, `fixed counter ${key}`);
  return freeze(value);
}

function emptyCounters(postPath = null) {
  const value = Object.fromEntries(FIXED_COUNTER_KEYS.map((key) => [key, 0]));
  if (postPath !== null) {
    value.productionPostMembershipNodeHashCalls = postPath.metrics.nodeHashCalls;
    value.productionPostMembershipNodeReads = postPath.metrics.nodeReads;
  }
  return freeze(value);
}

function insertOne(store, key) {
  const before = store.state();
  return store.insert({ expectedCount: before.normalCount, expectedRoot: before.root, key });
}

function createAtomically(config, build) {
  absent(config.databasePath, "databasePath");
  absent(`${config.databasePath}-wal`, "databasePath WAL sidecar");
  absent(`${config.databasePath}-shm`, "databasePath SHM sidecar");
  const stage = mkdtempSync(join(dirname(config.databasePath), ".q07-store-stage-"));
  chmodSync(stage, 0o700);
  const stagedPath = join(stage, `store-${randomBytes(8).toString("hex")}.sqlite`);
  let ready = false;
  let moved = false;
  try {
    const store = openQ04PersistentNullifierStore({ create: true, historyIndex: config.historyIndex, path: stagedPath, seed: q04HistorySeed(config.historyIndex) });
    let result;
    try { result = build(store, stagedPath); }
    finally { store.close(); }
    ready = true;
    return result;
  } finally {
    if (ready && existsSync(stagedPath)) {
      noSidecars(stagedPath, "staged database");
      chmodSync(stagedPath, 0o600);
      // link(2) gives the final name a no-replace atomic install. The staged
      // name is removed immediately, leaving the delivered database nlink=1.
      linkSync(stagedPath, config.databasePath);
      unlinkSync(stagedPath);
      moved = true;
      fsyncDirectory(dirname(config.databasePath));
    }
    if (existsSync(stagedPath)) unlinkSync(stagedPath);
    for (const sidecar of [`${stagedPath}-wal`, `${stagedPath}-shm`]) {
      if (existsSync(sidecar)) unlinkSync(sidecar);
    }
    if (moved || !existsSync(stagedPath)) rmdirSync(stage);
  }
}

function atomicClone(source, target) {
  closedStore(source, "preparedStorePath");
  absent(target, "databasePath");
  absent(`${target}-wal`, "databasePath WAL sidecar");
  absent(`${target}-shm`, "databasePath SHM sidecar");
  const stage = mkdtempSync(join(dirname(target), ".q07-store-clone-"));
  chmodSync(stage, 0o700);
  const staged = join(stage, "store.sqlite");
  let moved = false;
  try {
    copyFileSync(source, staged, constants.COPYFILE_EXCL);
    chmodSync(staged, 0o600);
    privateFile(staged, "staged database clone");
    linkSync(staged, target);
    unlinkSync(staged);
    moved = true;
    fsyncDirectory(dirname(target));
  } finally {
    if (existsSync(staged)) unlinkSync(staged);
    if (moved || !existsSync(staged)) rmdirSync(stage);
  }
  closedStore(target, "databasePath clone");
}

function closedStorage(path) {
  closedStore(path, "databasePath");
  const database = statSync(path).size;
  return freeze({ database, wal: 0, shm: 0, total: database, sha256: sha256File(path) });
}

function sha256File(path) {
  privateFile(path, "database file");
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const hash = createHash("sha256");
    const chunk = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      const count = readSync(descriptor, chunk, 0, chunk.length, null);
      if (count === 0) break;
      hash.update(chunk.subarray(0, count));
    }
    return hash.digest("hex");
  } finally { closeSync(descriptor); }
}

function finalize(result, config, stream, path) {
  return freeze({
    schema: Q07_STORE_WORKER_OUTPUT_SCHEMA,
    qualification: "not-qualified",
    qualificationBoundary: "indexed-nullifier-store-microbenchmark-only",
    mode: config.mode,
    productionStore: "Q04PersistentNullifierStore(depth=32)",
    historyIndex: config.historyIndex,
    endOrdinal: config.endOrdinal,
    dataset: freeze({
      schema: stream.verified.schema,
      mainCount: stream.verified.mainCount,
      count: stream.verified.count,
      sha256: stream.verified.sha256,
      transcriptSha256: stream.verified.transcriptSha256,
    }),
    database: freeze({ path, closedFileBytes: closedStorage(path) }),
    ...result,
  });
}

function buildHistory(config, stream) {
  let buildWallMs;
  let inserted = 0;
  let lastCounters = null;
  createAtomically(config, (store) => {
    const started = performance.now();
    for (const key of stream.keys.slice(0, config.endOrdinal)) {
      const mutation = insertOne(store, key);
      // Normal leaves are allocated after the two sentinels, so the newly
      // appended leaf's physical index is the committed normal count plus one.
      const path = store.membershipPath(store.state().normalCount + 1);
      if (!path.root.equals(mutation.mutation.root)) fail("post-insert membership root differs");
      lastCounters = fixedCounters(mutation.mutation, path);
      inserted += 1;
    }
    buildWallMs = elapsed(started);
    if (store.state().normalCount !== config.endOrdinal) fail("built store count differs from endOrdinal");
  });
  const store = openQ04PersistentNullifierStore({ create: false, historyIndex: config.historyIndex, path: config.databasePath, seed: q04HistorySeed(config.historyIndex) });
  let audit;
  let finalAuditWallMs;
  try {
    const started = performance.now();
    audit = store.audit();
    finalAuditWallMs = elapsed(started);
    if (audit.normalCount !== config.endOrdinal) fail("final audit count differs from endOrdinal");
  } finally { store.close(); }
  return finalize({
    measurement: freeze({ scope: "indexed-nullifier-full-history-build", wallMs: buildWallMs, inserted }),
    finalAudit: auditRecord(audit),
    finalAuditWallMs,
    fixedDepthOperationCounts: lastCounters,
  }, config, stream, config.databasePath);
}

function cloneAndBindPreparedStore(config) {
  closedStore(config.preparedStorePath, "preparedStorePath");
  if (sha256File(config.preparedStorePath) !== config.preparedDatabaseSha256) {
    fail("preparedStorePath SHA-256 differs from preparedDatabaseSha256");
  }
  atomicClone(config.preparedStorePath, config.databasePath);
  const store = openQ04PersistentNullifierStore({ create: false, historyIndex: config.historyIndex, path: config.databasePath, seed: q04HistorySeed(config.historyIndex) });
  let state;
  let bindingWallMs;
  try {
    const started = performance.now();
    state = stateMatches(store, config.expectedPreparedState, "prepared store");
    bindingWallMs = elapsed(started);
  } finally { store.close(); }
  return freeze({ bindingWallMs, preparedState: freeze({ normalCount: state.normalCount, root: hex(state.root), transcriptChainSha256: hex(state.transcriptChainSha256) }) });
}

function warmSample(config, stream) {
  const before = cloneAndBindPreparedStore(config);
  const store = openQ04PersistentNullifierStore({ create: false, historyIndex: config.historyIndex, path: config.databasePath, seed: q04HistorySeed(config.historyIndex) });
  let mutation;
  let measuredWallMs;
  let postState;
  try {
    const started = performance.now();
    mutation = insertOne(store, stream.keys[config.endOrdinal - 1]);
    measuredWallMs = elapsed(started);
    postState = stateMatches(store, config.expectedPostState, "warm-insert post state");
  } finally { store.close(); }
  return finalize({
    authentication: before,
    measurement: freeze({ scope: "indexed-nullifier-warm-insert-derive-commit-only", wallMs: measuredWallMs, inserted: 1 }),
    fixedDepthOperationCounts: fixedCounters(mutation.mutation),
    postState: freeze({ normalCount: postState.normalCount, root: hex(postState.root), transcriptChainSha256: hex(postState.transcriptChainSha256) }),
  }, config, stream, config.databasePath);
}

function referenceInsert(config, stream) {
  const before = cloneAndBindPreparedStore(config);
  const store = openQ04PersistentNullifierStore({
    create: false,
    historyIndex: config.historyIndex,
    path: config.databasePath,
    seed: q04HistorySeed(config.historyIndex),
  });
  let mutation;
  let audit;
  let referenceWallMs;
  try {
    const started = performance.now();
    mutation = insertOne(store, stream.keys[config.endOrdinal - 1]);
    audit = store.audit();
    referenceWallMs = elapsed(started);
    if (audit.normalCount !== config.endOrdinal) {
      fail("reference-insert post state has the wrong count");
    }
  } finally {
    store.close();
  }
  return finalize({
    authentication: before,
    preparation: freeze({
      scope: "indexed-nullifier-reference-insert-and-full-audit-not-a-performance-sample",
      wallMs: referenceWallMs,
      inserted: 1,
    }),
    fixedDepthOperationCounts: fixedCounters(mutation.mutation),
    finalAudit: auditRecord(audit),
  }, config, stream, config.databasePath);
}

function suffixReplay(config, stream) {
  const before = cloneAndBindPreparedStore(config);
  const store = openQ04PersistentNullifierStore({ create: false, historyIndex: config.historyIndex, path: config.databasePath, seed: q04HistorySeed(config.historyIndex) });
  let inserted = 0;
  let lastCounters = null;
  let measuredWallMs;
  let postState;
  try {
    const started = performance.now();
    for (let ordinal = config.startOrdinal - 1; ordinal < config.endOrdinal; ordinal += 1) {
      const mutation = insertOne(store, stream.keys[ordinal]);
      lastCounters = fixedCounters(mutation.mutation);
      inserted += 1;
    }
    measuredWallMs = elapsed(started);
    postState = stateMatches(store, config.expectedPostState, "suffix-insert post state");
  } finally { store.close(); }
  return finalize({
    authentication: before,
    measurement: freeze({ scope: "indexed-nullifier-suffix-insert", wallMs: measuredWallMs, inserted, startOrdinal: config.startOrdinal }),
    fixedDepthOperationCounts: lastCounters,
    postState: freeze({ normalCount: postState.normalCount, root: hex(postState.root), transcriptChainSha256: hex(postState.transcriptChainSha256) }),
  }, config, stream, config.databasePath);
}

function snapshotAuthentication(config, stream) {
  closedStore(config.databasePath, "databasePath");
  const started = performance.now();
  const store = openQ04PersistentNullifierStore({ create: false, historyIndex: config.historyIndex, path: config.databasePath, seed: q04HistorySeed(config.historyIndex) });
  let authenticated;
  try {
    stateMatches(store, config.expectedPreparedState, "full-store audit pre-state");
    const audit = store.audit();
    if (audit.logicalDigestSha256 !== config.expectedPreparedState.logicalDigestSha256) fail("full-store audit logical digest differs");
    authenticated = audit;
  }
  finally { store.close(); }
  return finalize({
    measurement: freeze({ scope: "indexed-nullifier-full-store-audit", wallMs: elapsed(started), inserted: 0 }),
    finalAudit: auditRecord(authenticated),
    fixedDepthOperationCounts: emptyCounters(),
  }, config, stream, config.databasePath);
}

function reopenedHandlePath(config, stream) {
  const authentication = cloneAndBindPreparedStore(config);
  const started = performance.now();
  const store = openQ04PersistentNullifierStore({ create: false, historyIndex: config.historyIndex, path: config.databasePath, seed: q04HistorySeed(config.historyIndex) });
  let state;
  let path;
  try {
    state = store.state();
    path = store.membershipPath(config.readPhysicalIndex);
    if (state.normalCount !== config.expectedPreparedState.normalCount || !state.root.equals(config.expectedPreparedState.root) || !path.root.equals(state.root)) {
      fail("reopened-handle state or membership root differs from prepared expectation");
    }
  } finally { store.close(); }
  return finalize({
    authentication,
    measurement: freeze({ scope: "indexed-nullifier-reopened-handle-path", wallMs: elapsed(started), inserted: 0, readPhysicalIndex: config.readPhysicalIndex }),
    reopenedHandleTelemetry: freeze({ osCacheEvictionAttempted: false, childProcessRequired: true, pathTreeDepth: path.metrics.treeDepth }),
    fixedDepthOperationCounts: emptyCounters(path),
    observedState: freeze({ normalCount: state.normalCount, root: hex(state.root), transcriptChainSha256: hex(state.transcriptChainSha256) }),
  }, config, stream, config.databasePath);
}

function writeFully(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(descriptor, bytes, offset, bytes.length - offset);
    if (written <= 0) fail("result write made no progress");
    offset += written;
  }
}

/** Atomically publish exactly one canonical JSON line; never overwrite a result. */
function writeAtomicResult(path, result) {
  absent(path, "resultPath");
  const stage = mkdtempSync(join(dirname(path), ".q07-result-stage-"));
  chmodSync(stage, 0o700);
  const staged = join(stage, "result.json");
  let moved = false;
  let descriptor;
  try {
    descriptor = openSync(staged, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    writeFully(descriptor, Buffer.from(`${canonicalJson(result)}\n`, "utf8"));
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    chmodSync(staged, 0o600);
    privateFile(staged, "staged result");
    linkSync(staged, path);
    unlinkSync(staged);
    moved = true;
    fsyncDirectory(dirname(path));
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(staged)) unlinkSync(staged);
    if (moved || !existsSync(staged)) rmdirSync(stage);
  }
  privateFile(path, "resultPath");
}

/** Run one strict real-store operation and atomically write its canonical result. */
export function runQ07StoreWorker(input) {
  const config = parseConfig(input);
  const stream = verifiedDataset(config);
  let result;
  if (config.mode === "full-history-build") result = buildHistory(config, stream);
  else if (config.mode === "reference-insert") result = referenceInsert(config, stream);
  else if (config.mode === "warm-insert") result = warmSample(config, stream);
  else if (config.mode === "suffix-insert") result = suffixReplay(config, stream);
  else if (config.mode === "full-store-audit") result = snapshotAuthentication(config, stream);
  else result = reopenedHandlePath(config, stream);
  writeAtomicResult(config.resultPath, result);
  return result;
}

function readCliConfig(path) {
  privateParent(path, "config path");
  const named = privateFile(path, "config path");
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  let value;
  try {
    const initial = fstatSync(descriptor);
    if (
      initial.dev !== named.dev || initial.ino !== named.ino ||
      initial.nlink !== 1 || (initial.mode & 0o777) !== 0o600
    ) fail("config path changed before it was read");
    const bytes = readFileSync(descriptor);
    const final = fstatSync(descriptor);
    if (
      final.dev !== initial.dev || final.ino !== initial.ino ||
      final.size !== initial.size || final.mtimeMs !== initial.mtimeMs ||
      final.ctimeMs !== initial.ctimeMs || final.nlink !== 1
    ) fail("config path changed while it was read");
    value = parseStrictJson(bytes);
  } catch (error) {
    if (error instanceof Q07StoreWorkerError) throw error;
    fail(`config is invalid JSON: ${error.message}`);
  } finally {
    closeSync(descriptor);
  }
  return value;
}

function isMain() {
  return process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname);
}

if (isMain()) {
  try {
    if (process.argv.length !== 3) fail("usage: node v2-q07-store-worker.mjs /absolute/private/config.json");
    runQ07StoreWorker(readCliConfig(process.argv[2]));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
