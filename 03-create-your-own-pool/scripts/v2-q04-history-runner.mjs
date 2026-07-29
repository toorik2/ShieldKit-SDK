#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parseStrictJson } from "../packages/profile/load.mjs";
import {
  createIndependentIndexedNullifierTree,
} from "../packages/pool/v2/qualification/independent-indexed-nullifier-tree.mjs";
import {
  createIndependentPoseidonOracle,
} from "../packages/pool/v2/qualification/independent-poseidon-oracle.mjs";
import {
  generateQ04HistoryKeys,
  Q04_ENTRIES_PER_HISTORY,
  Q04_HISTORY_SEED_HEX,
  q04HistorySeed,
} from "../packages/pool/v2/qualification/q04-schedule.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const segmentWorkerPath = resolve(here, "v2-q04-segment-worker.mjs");
const reopenWorkerPath = resolve(here, "v2-q04-reopen-worker.mjs");
const CONFIG_SCHEMA = "shieldkit-v2-direct/q04-history-config/v1";
const SEGMENT_CONFIG_SCHEMA =
  "shieldkit-v2-direct/q04-segment-config/v1";
const SEGMENT_OUTPUT_SCHEMA =
  "shieldkit-v2-direct/q04-segment-output/v2";
const REOPEN_CONFIG_SCHEMA =
  "shieldkit-v2-direct/q04-reopen-config/v1";
const REOPEN_OUTPUT_SCHEMA =
  "shieldkit-v2-direct/q04-reopen-output/v1";
const TRANSITION_SCHEMA =
  "shieldkit-v2-direct/q04-transition-measurement/v1";
const RESULT_SCHEMA = "shieldkit-v2-direct/q04-history-result/v3";
const INPUT_TRANSCRIPT_DOMAIN =
  "ShieldKit/PoolActionV2Direct/Q04/input-transcript/v1\0";
const PATH_DIGEST_DOMAIN =
  "ShieldKit/PoolActionV2Direct/Q04/path-digest/v1\0";
const STORE_INITIAL_DOMAIN =
  "ShieldKit/PoolActionV2Direct/Q04/persistent-store/v1\0";
const STORE_TRANSITION_DOMAIN =
  "ShieldKit/PoolActionV2Direct/Q04/persistent-transition/v1\0";
const HEX_64 = /^[0-9a-f]{64}$/;
const MAX_WORKER_RECORD_CHARS = 256 * 1024;
const MAX_WORKER_STDERR_CHARS = 1024 * 1024;

class Q04HistoryRunnerError extends Error {
  constructor(message) {
    super(message);
    this.name = "Q04HistoryRunnerError";
  }
}

const fail = (message) => {
  throw new Q04HistoryRunnerError(message);
};
const exactKeys = (value, expected, label) => {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) fail(`${label} has missing or unknown properties`);
  return value;
};
const integer = (value, low, high, label) => {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(`${label} must be an integer from ${low} through ${high}`);
  }
  return value;
};
const finiteNonNegative = (value, label) => {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    fail(`${label} must be a finite non-negative number`);
  }
  return value;
};
const canonicalAbsolutePath = (value, label) => {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    resolve(value) !== value
  ) fail(`${label} must be an absolute normalized path`);
  return value;
};
const hex64 = (value, label) => {
  if (typeof value !== "string" || !HEX_64.test(value)) {
    fail(`${label} must be exactly 32 lowercase hexadecimal bytes`);
  }
  return value;
};
const hex = (value) =>
  typeof value === "bigint"
    ? value.toString(16).padStart(64, "0")
    : Buffer.from(value).toString("hex");
const u32be = (value) => {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
};
const encodedFr = (value) =>
  Buffer.from(value.toString(16).padStart(64, "0"), "hex");
const resourceDelta = (before, after) => ({
  userCpuMicros: after.userCPUTime - before.userCPUTime,
  systemCpuMicros: after.systemCPUTime - before.systemCPUTime,
  voluntaryContextSwitches:
    after.voluntaryContextSwitches - before.voluntaryContextSwitches,
  involuntaryContextSwitches:
    after.involuntaryContextSwitches - before.involuntaryContextSwitches,
});

function assertPrivateDirectory(path) {
  const observed = lstatSync(path);
  if (
    !observed.isDirectory() ||
    observed.isSymbolicLink() ||
    realpathSync(path) !== path ||
    (observed.mode & 0o777) !== 0o700 ||
    (
      typeof process.getuid === "function" &&
      observed.uid !== process.getuid()
    )
  ) fail("Q-04 history output directory must be direct user-owned mode 0700");
}

function readConfig(filename) {
  const path = canonicalAbsolutePath(filename, "Q-04 history config path");
  const descriptor = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  let bytes;
  let observed;
  try {
    observed = fstatSync(descriptor);
    if (
      !observed.isFile() ||
      observed.nlink !== 1 ||
      observed.size === 0 ||
      observed.size > 64 * 1024 ||
      (observed.mode & 0o777) !== 0o600 ||
      (
        typeof process.getuid === "function" &&
        observed.uid !== process.getuid()
      )
    ) fail(
      "Q-04 history config must be a bounded single-link " +
        "user-owned mode-0600 regular file",
    );
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      after.dev !== observed.dev ||
      after.ino !== observed.ino ||
      after.size !== observed.size ||
      after.mtimeMs !== observed.mtimeMs
    ) fail("Q-04 history config changed while being read");
  } finally {
    closeSync(descriptor);
  }
  const named = lstatSync(path);
  if (
    named.isSymbolicLink() ||
    named.dev !== observed.dev ||
    named.ino !== observed.ino ||
    realpathSync(path) !== path
  ) fail("Q-04 history config path changed or traverses a symbolic link");
  const config = parseStrictJson(bytes);
  exactKeys(config, [
    "checkpointInterval",
    "entryCount",
    "historyIndex",
    "outputDirectory",
    "parameterSourcePath",
    "qualifying",
    "schema",
  ], "Q-04 history config");
  if (config.schema !== CONFIG_SCHEMA) fail("Q-04 history config schema differs");
  const historyIndex = integer(config.historyIndex, 0, 3, "historyIndex");
  const entryCount = integer(
    config.entryCount,
    1,
    Q04_ENTRIES_PER_HISTORY,
    "entryCount",
  );
  const checkpointInterval = integer(
    config.checkpointInterval,
    1,
    entryCount,
    "checkpointInterval",
  );
  if (entryCount % checkpointInterval !== 0) {
    fail("Q-04 history entry count must be divisible by checkpoint interval");
  }
  if (typeof config.qualifying !== "boolean") {
    fail("Q-04 history qualifying must be boolean");
  }
  if (
    config.qualifying &&
    (
      entryCount !== Q04_ENTRIES_PER_HISTORY ||
      checkpointInterval !== 1_000
    )
  ) fail("qualifying Q-04 history must be exactly 25,000 by 1,000");
  const outputDirectory = canonicalAbsolutePath(
    config.outputDirectory,
    "Q-04 history output directory",
  );
  assertPrivateDirectory(outputDirectory);
  return Object.freeze({
    checkpointInterval,
    entryCount,
    historyIndex,
    outputDirectory,
    parameterSourcePath: canonicalAbsolutePath(
      config.parameterSourcePath,
      "Q-04 Poseidon parameter source path",
    ),
    qualifying: config.qualifying,
    configSha256: createHash("sha256").update(bytes).digest("hex"),
  });
}

function initialStoreTranscript(historyIndex, seed) {
  return createHash("sha256")
    .update(STORE_INITIAL_DOMAIN, "ascii")
    .update(u32be(historyIndex))
    .update(seed)
    .digest();
}

function transitionDigest(ordinal, key, transition) {
  const digest = createHash("sha256")
    .update(STORE_TRANSITION_DOMAIN, "ascii")
    .update(u32be(ordinal))
    .update(key)
    .update(encodedFr(transition.preRoot))
    .update(encodedFr(transition.intermediateRoot))
    .update(encodedFr(transition.postRoot))
    .update(u32be(transition.predecessor.index))
    .update(Buffer.from(transition.predecessor.key, "hex"))
    .update(u32be(transition.predecessor.successorIndex))
    .update(Buffer.from(transition.predecessor.successorKey, "hex"))
    .update(u32be(transition.append.index));
  for (const value of transition.predecessorPath) {
    digest.update(encodedFr(value));
  }
  for (const value of transition.append.emptyPath) {
    digest.update(encodedFr(value));
  }
  return digest.digest();
}

function pathDigest(values) {
  const digest = createHash("sha256")
    .update(PATH_DIGEST_DOMAIN, "ascii")
    .update(u32be(values.length));
  for (const value of values) {
    digest.update(
      typeof value === "bigint"
        ? encodedFr(value)
        : Buffer.from(hex64(value, "Q-04 path element"), "hex"),
    );
  }
  return digest.digest("hex");
}

function requireEqual(actual, expected, label) {
  try {
    if (
      typeof expected === "object" &&
      expected !== null
    ) {
      const left = JSON.stringify(actual);
      const right = JSON.stringify(expected);
      if (left !== right) fail(`${label} differs`);
    } else if (actual !== expected) {
      fail(`${label} differs`);
    }
  } catch (error) {
    if (error instanceof Q04HistoryRunnerError) throw error;
    fail(`${label} cannot be compared`);
  }
}

function expectedLeaf(leaf) {
  return {
    type: leaf.type,
    index: leaf.index,
    key: leaf.key,
    successorIndex: leaf.successorIndex,
    successorKey: leaf.successorKey,
  };
}

function compareTransition(actual, expected, ordinal, key) {
  requireEqual(actual.ordinal, ordinal, "Q-04 transition ordinal");
  requireEqual(actual.key, key.toString("hex"), "Q-04 transition key");
  requireEqual(actual.preRoot, hex(expected.preRoot), "Q-04 pre-root");
  requireEqual(
    actual.intermediateRoot,
    hex(expected.intermediateRoot),
    "Q-04 intermediate root",
  );
  requireEqual(actual.postRoot, hex(expected.postRoot), "Q-04 post-root");
  requireEqual(
    actual.predecessor,
    expectedLeaf(expected.predecessor),
    "Q-04 predecessor",
  );
  requireEqual(
    actual.updatedPredecessor,
    expectedLeaf(expected.updatedPredecessor),
    "Q-04 updated predecessor",
  );
  const predecessorPath = expected.predecessorPath.map(hex);
  const emptyPath = expected.append.emptyPath.map(hex);
  const postPath = expected.postMembershipPath.map(hex);
  requireEqual(
    actual.predecessorPath,
    predecessorPath,
    "Q-04 predecessor membership path",
  );
  requireEqual(actual.append.index, expected.append.index, "Q-04 append index");
  requireEqual(
    actual.append.newLeaf,
    expectedLeaf(expected.append.newLeaf),
    "Q-04 appended leaf",
  );
  requireEqual(
    actual.append.emptyPath,
    emptyPath,
    "Q-04 empty append non-membership path",
  );
  requireEqual(
    actual.postMembershipPath,
    postPath,
    "Q-04 post-insertion membership path",
  );
  requireEqual(
    actual.operationCounts.productionLeafHashCalls,
    actual.operationCounts.productionPredecessorValidationLeafHashCalls
      + actual.operationCounts.productionMutationLeafHashCalls,
    "Q-04 production leaf-hash count must equal its emitted components",
  );
  requireEqual(
    actual.operationCounts.productionPredecessorValidationLeafHashCalls,
    1,
    "Q-04 production predecessor-validation leaf-hash count",
  );
  requireEqual(
    actual.operationCounts.productionMutationLeafHashCalls,
    2,
    "Q-04 production mutation leaf-hash count",
  );
  requireEqual(
    actual.operationCounts.productionMutationNodeHashCalls,
    128,
    "Q-04 production node-hash count",
  );
  requireEqual(
    actual.operationCounts.productionLogicalPathSiblingLookups,
    64,
    "Q-04 production logical path-sibling lookup count",
  );
  requireEqual(
    actual.operationCounts.productionPathOverrideHits,
    1,
    "Q-04 production path-override hit count",
  );
  requireEqual(
    actual.operationCounts.productionPathAdapterNodeReads,
    63,
    "Q-04 production path-adapter node-read count",
  );
  requireEqual(
    actual.operationCounts.productionRootAdapterNodeReads,
    1,
    "Q-04 production root-adapter node-read count",
  );
  requireEqual(
    actual.operationCounts.productionTotalAdapterNodeReads,
    actual.operationCounts.productionPathAdapterNodeReads
      + actual.operationCounts.productionRootAdapterNodeReads,
    "Q-04 production total adapter node reads must equal its emitted components",
  );
  requireEqual(
    actual.operationCounts.productionTotalAdapterNodeReads,
    64,
    "Q-04 production total adapter node-read count",
  );
  requireEqual(
    actual.operationCounts.productionPostMembershipNodeHashCalls,
    32,
    "Q-04 production post-membership node-hash count",
  );
  requireEqual(
    actual.operationCounts.productionPostMembershipNodeReads,
    32,
    "Q-04 production post-membership node-read count",
  );
  requireEqual(
    actual.operationCounts.productionLeafReads,
    2,
    "Q-04 production leaf-read count",
  );
  requireEqual(
    actual.operationCounts.productionOrderLookups,
    2,
    "Q-04 production order-lookup count",
  );
  requireEqual(expected.metrics.leafHashCalls, 2, "Q-04 oracle leaf hashes");
  requireEqual(expected.metrics.nodeHashCalls, 160, "Q-04 oracle node hashes");
  return {
    predecessorPathSha256: pathDigest(predecessorPath),
    emptyAppendPathSha256: pathDigest(emptyPath),
    postMembershipPathSha256: pathDigest(postPath),
  };
}

function writePrivateJson(path, value) {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const descriptor = openSync(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow,
    0o600,
  );
  try {
    const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
    let offset = 0;
    while (offset < bytes.length) {
      offset += writeSync(
        descriptor,
        bytes,
        offset,
        bytes.length - offset,
      );
    }
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function openTranscript(path) {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const descriptor = openSync(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollow,
    0o600,
  );
  const digest = createHash("sha256");
  let bytes = 0;
  return Object.freeze({
    append(value) {
      const line = Buffer.from(`${JSON.stringify(value)}\n`);
      let offset = 0;
      while (offset < line.length) {
        offset += writeSync(
          descriptor,
          line,
          offset,
          line.length - offset,
        );
      }
      digest.update(line);
      bytes += line.length;
    },
    close() {
      fsyncSync(descriptor);
      closeSync(descriptor);
      chmodSync(path, 0o600);
      return Object.freeze({
        path,
        bytes,
        sha256: digest.digest("hex"),
      });
    },
  });
}

function validateStorage(value, label, { open = false } = {}) {
  exactKeys(
    value,
    open
      ? [
          "fileBytes",
          "freeListCount",
          "journalMode",
          "pageCount",
          "pageSize",
          "synchronous",
          "totalFileBytes",
        ]
      : ["fileBytes", "totalFileBytes"],
    label,
  );
  exactKeys(
    value.fileBytes,
    ["database", "shm", "wal"],
    `${label} file bytes`,
  );
  const database = integer(
    value.fileBytes.database,
    0,
    Number.MAX_SAFE_INTEGER,
    `${label} database bytes`,
  );
  const wal = integer(
    value.fileBytes.wal,
    0,
    Number.MAX_SAFE_INTEGER,
    `${label} WAL bytes`,
  );
  const shm = integer(
    value.fileBytes.shm,
    0,
    Number.MAX_SAFE_INTEGER,
    `${label} SHM bytes`,
  );
  requireEqual(
    value.totalFileBytes,
    database + wal + shm,
    `${label} total bytes`,
  );
  if (open) {
    for (const field of ["freeListCount", "pageCount", "pageSize"]) {
      integer(
        value[field],
        0,
        Number.MAX_SAFE_INTEGER,
        `${label} ${field}`,
      );
    }
    requireEqual(value.journalMode, "wal", `${label} journal mode`);
    integer(
      value.synchronous,
      0,
      Number.MAX_SAFE_INTEGER,
      `${label} synchronous`,
    );
  }
  return value;
}

function validateLifecycleMeasurement(value, label) {
  exactKeys(value, [
    "closeWallMs",
    "fsReadOps",
    "fsWriteOps",
    "involuntaryContextSwitches",
    "peakRssBytes",
    "readBytes",
    "systemCpuMicros",
    "userCpuMicros",
    "voluntaryContextSwitches",
    "wallMs",
    "writeBytes",
  ], label);
  finiteNonNegative(value.wallMs, `${label} wallMs`);
  finiteNonNegative(value.closeWallMs, `${label} closeWallMs`);
  for (const field of [
    "fsReadOps",
    "fsWriteOps",
    "involuntaryContextSwitches",
    "peakRssBytes",
    "readBytes",
    "systemCpuMicros",
    "userCpuMicros",
    "voluntaryContextSwitches",
    "writeBytes",
  ]) {
    integer(
      value[field],
      0,
      Number.MAX_SAFE_INTEGER,
      `${label} ${field}`,
    );
  }
  return value;
}

function validateReopenRecord(record) {
  exactKeys(record, [
    "afterEntry",
    "audit",
    "historyIndex",
    "logicalStoreSha256",
    "measurement",
    "openAndAuditWallMs",
    "pid",
    "postCloseStorage",
    "preCloseStorage",
    "root",
    "schema",
    "transcriptChainSha256",
    "type",
  ], "Q-04 reopen output");
  if (record.schema !== REOPEN_OUTPUT_SCHEMA) {
    fail("Q-04 reopen output schema differs");
  }
  requireEqual(record.type, "reopen", "Q-04 reopen output type");
  integer(record.pid, 1, Number.MAX_SAFE_INTEGER, "Q-04 reopen PID");
  integer(
    record.historyIndex,
    0,
    3,
    "Q-04 reopen history index",
  );
  integer(
    record.afterEntry,
    1,
    Q04_ENTRIES_PER_HISTORY,
    "Q-04 reopen entry",
  );
  hex64(record.root, "Q-04 reopen root");
  hex64(
    record.transcriptChainSha256,
    "Q-04 reopen transcript",
  );
  hex64(record.logicalStoreSha256, "Q-04 reopen logical digest");
  exactKeys(record.audit, [
    "foreignKeyViolations",
    "integrityCheck",
    "leafCount",
    "nodeCount",
    "normalCount",
    "orderCount",
  ], "Q-04 reopen audit");
  integer(
    record.audit.normalCount,
    1,
    Q04_ENTRIES_PER_HISTORY,
    "Q-04 reopen normal count",
  );
  for (const field of ["leafCount", "nodeCount", "orderCount"]) {
    integer(
      record.audit[field],
      0,
      Number.MAX_SAFE_INTEGER,
      `Q-04 reopen ${field}`,
    );
  }
  requireEqual(
    record.audit.integrityCheck,
    "ok",
    "Q-04 reopen integrity",
  );
  requireEqual(
    record.audit.foreignKeyViolations,
    0,
    "Q-04 reopen foreign-key violations",
  );
  finiteNonNegative(
    record.openAndAuditWallMs,
    "Q-04 reopen open-and-audit time",
  );
  validateStorage(
    record.preCloseStorage,
    "Q-04 reopen pre-close storage",
    { open: true },
  );
  validateStorage(
    record.postCloseStorage,
    "Q-04 reopen post-close storage",
  );
  validateLifecycleMeasurement(
    record.measurement,
    "Q-04 reopen measurement",
  );
  return record;
}

function validateSegmentRecord(record) {
  if (record.type === "start") {
    exactKeys(record, [
      "foreignKeyViolations",
      "historyIndex",
      "integrityCheck",
      "logicalStoreSha256",
      "normalCount",
      "pid",
      "reopenWallMs",
      "root",
      "schema",
      "startEntry",
      "transcriptChainSha256",
      "type",
    ], "Q-04 segment start output");
    integer(record.pid, 1, Number.MAX_SAFE_INTEGER, "Q-04 segment PID");
    integer(record.historyIndex, 0, 3, "Q-04 segment history index");
    integer(
      record.startEntry,
      0,
      Q04_ENTRIES_PER_HISTORY - 1,
      "Q-04 segment start entry",
    );
    integer(
      record.normalCount,
      0,
      Q04_ENTRIES_PER_HISTORY,
      "Q-04 segment normal count",
    );
    hex64(record.root, "Q-04 segment start root");
    hex64(
      record.transcriptChainSha256,
      "Q-04 segment start transcript",
    );
    hex64(
      record.logicalStoreSha256,
      "Q-04 segment start logical digest",
    );
    requireEqual(record.integrityCheck, "ok", "Q-04 segment integrity");
    requireEqual(
      record.foreignKeyViolations,
      0,
      "Q-04 segment foreign-key violations",
    );
    finiteNonNegative(record.reopenWallMs, "Q-04 segment reopen time");
    return record;
  }
  if (record.type === "transition") {
    exactKeys(record, [
      "append",
      "historyIndex",
      "intermediateRoot",
      "key",
      "measurement",
      "operationCounts",
      "ordinal",
      "postMembershipPath",
      "postRoot",
      "preRoot",
      "predecessor",
      "predecessorPath",
      "schema",
      "transcriptChainSha256",
      "transitionDigestSha256",
      "type",
      "updatedPredecessor",
    ], "Q-04 segment transition output");
    exactKeys(record.predecessor, [
      "index",
      "key",
      "successorIndex",
      "successorKey",
      "type",
    ], "Q-04 segment predecessor");
    exactKeys(record.updatedPredecessor, [
      "index",
      "key",
      "successorIndex",
      "successorKey",
      "type",
    ], "Q-04 segment updated predecessor");
    exactKeys(record.append, [
      "emptyPath",
      "index",
      "newLeaf",
    ], "Q-04 segment append");
    exactKeys(record.append.newLeaf, [
      "index",
      "key",
      "successorIndex",
      "successorKey",
      "type",
    ], "Q-04 segment appended leaf");
    exactKeys(record.operationCounts, [
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
    ], "Q-04 segment operation counts");
    exactKeys(record.measurement, [
      "fsReadOps",
      "fsWriteOps",
      "involuntaryContextSwitches",
      "rssBytes",
      "systemCpuMicros",
      "userCpuMicros",
      "voluntaryContextSwitches",
      "wallMicros",
    ], "Q-04 segment transition measurement");
    if (
      !Array.isArray(record.predecessorPath) ||
      record.predecessorPath.length !== 32 ||
      !Array.isArray(record.append.emptyPath) ||
      record.append.emptyPath.length !== 32 ||
      !Array.isArray(record.postMembershipPath) ||
      record.postMembershipPath.length !== 32
    ) fail("Q-04 segment transition paths must each contain 32 elements");
    return record;
  }
  if (record.type === "end") {
    exactKeys(record, [
      "audit",
      "endEntry",
      "historyIndex",
      "logicalStoreSha256",
      "phaseMeasurement",
      "pid",
      "postCloseStorage",
      "preCloseStorage",
      "probes",
      "root",
      "schema",
      "segmentMeasurement",
      "transcriptChainSha256",
      "type",
    ], "Q-04 segment end output");
    exactKeys(record.audit, [
      "foreignKeyViolations",
      "integrityCheck",
      "leafCount",
      "nodeCount",
      "normalCount",
      "orderCount",
    ], "Q-04 segment end audit");
    integer(
      record.pid,
      1,
      Number.MAX_SAFE_INTEGER,
      "Q-04 segment end PID",
    );
    integer(
      record.historyIndex,
      0,
      3,
      "Q-04 segment end history index",
    );
    integer(
      record.endEntry,
      1,
      Q04_ENTRIES_PER_HISTORY,
      "Q-04 segment end entry",
    );
    if (!Array.isArray(record.probes) || record.probes.length !== 5) {
      fail("Q-04 segment end must contain exactly five probes");
    }
    for (const probe of record.probes) {
      exactKeys(probe, [
        "accepted",
        "caseId",
        "caseSha256",
        "errorCode",
        "expectedOutcome",
        "inputSha256",
        "kind",
        "postStateSha256",
        "preStateSha256",
        "rejection",
        "resultSha256",
        "stateUnchanged",
      ], "Q-04 segment rejection probe");
    }
    return record;
  }
  fail(`Q-04 segment emitted unsupported record type ${record.type}`);
}

async function runReopen({ configPath }) {
  const lifecycleStartedAt = process.hrtime.bigint();
  const child = spawn(process.execPath, [reopenWorkerPath, configPath], {
    cwd: resolve(here, "../.."),
    env: {
      ...process.env,
      NODE_NO_WARNINGS: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const pid = child.pid;
  integer(pid, 1, Number.MAX_SAFE_INTEGER, "Q-04 reopen child PID");
  let stdout = "";
  let stderr = "";
  let stdoutExceeded = false;
  let stderrExceeded = false;
  let spawnError = null;
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    if (stdout.length < MAX_WORKER_RECORD_CHARS) {
      stdout += chunk.slice(
        0,
        MAX_WORKER_RECORD_CHARS - stdout.length,
      );
    }
    if (stdout.length >= MAX_WORKER_RECORD_CHARS) {
      stdoutExceeded = true;
      child.kill("SIGKILL");
    }
  });
  child.stderr.on("data", (chunk) => {
    if (stderr.length < MAX_WORKER_STDERR_CHARS) {
      stderr += chunk.slice(
        0,
        MAX_WORKER_STDERR_CHARS - stderr.length,
      );
    }
    if (stderr.length >= MAX_WORKER_STDERR_CHARS) {
      stderrExceeded = true;
      child.kill("SIGKILL");
    }
  });
  child.once("error", (error) => {
    spawnError = error;
  });
  const result = await new Promise((resolveClose) => {
    child.once("close", (code, signal) => resolveClose({ code, signal }));
  });
  if (spawnError !== null) {
    fail(`Q-04 reopen process failed to spawn: ${spawnError.message}`);
  }
  if (stdoutExceeded) {
    fail("Q-04 reopen output exceeded the bounded limit");
  }
  if (stderrExceeded) {
    fail("Q-04 reopen stderr exceeded the bounded limit");
  }
  if (result.code !== 0 || result.signal !== null) {
    fail(
      `Q-04 reopen exited code=${result.code} signal=${result.signal}: ` +
        stderr.trim(),
    );
  }
  if (stderr.length !== 0) {
    fail("Q-04 successful reopen emitted unexpected stderr");
  }
  const lines = stdout.split(/\r?\n/u).filter((line) => line.length !== 0);
  if (lines.length !== 1) {
    fail("Q-04 reopen must emit exactly one nonempty JSON record");
  }
  const record = validateReopenRecord(
    parseStrictJson(Buffer.from(lines[0])),
  );
  requireEqual(record.pid, pid, "Q-04 reopen process PID");
  return Object.freeze({
    closeExitCode: result.code,
    parentLifecycleWallMs:
      Number(process.hrtime.bigint() - lifecycleStartedAt) / 1e6,
    pid,
    record,
  });
}

async function runSegment({
  configPath,
  onRecord,
}) {
  const child = spawn(process.execPath, [segmentWorkerPath, configPath], {
    cwd: resolve(here, "../.."),
    env: {
      ...process.env,
      NODE_NO_WARNINGS: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let spawnError = null;
  child.once("error", (error) => {
    spawnError = error;
  });
  let stderr = "";
  let stderrExceeded = false;
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    if (stderr.length < MAX_WORKER_STDERR_CHARS) {
      stderr += chunk.slice(
        0,
        MAX_WORKER_STDERR_CHARS - stderr.length,
      );
    }
    if (stderr.length >= MAX_WORKER_STDERR_CHARS) {
      stderrExceeded = true;
      child.kill("SIGKILL");
    }
  });
  const consume = (async () => {
    let pending = "";
    for await (const chunk of child.stdout) {
      pending += chunk;
      let newline = pending.indexOf("\n");
      while (newline !== -1) {
        let line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (line.endsWith("\r")) line = line.slice(0, -1);
        if (line.length === 0) {
          fail("Q-04 segment emitted an empty output record");
        }
        if (line.length > MAX_WORKER_RECORD_CHARS) {
          fail("Q-04 segment output record exceeds the bounded limit");
        }
        const record = validateSegmentRecord(
          parseStrictJson(Buffer.from(line)),
        );
        if (record.schema !== SEGMENT_OUTPUT_SCHEMA) {
          fail("Q-04 segment output schema differs");
        }
        await onRecord(record, child.pid);
        newline = pending.indexOf("\n");
      }
      if (pending.length > MAX_WORKER_RECORD_CHARS) {
        fail("Q-04 segment output record exceeds the bounded limit");
      }
    }
    if (pending.length !== 0) {
      fail("Q-04 segment emitted an unterminated output record");
    }
  })();
  const closed = new Promise((resolveClose) => {
    child.once("close", (code, signal) => resolveClose({ code, signal }));
  });
  try {
    const [result] = await Promise.all([closed, consume]);
    if (spawnError !== null) {
      fail(`Q-04 segment process failed to spawn: ${spawnError.message}`);
    }
    if (stderrExceeded) {
      fail("Q-04 segment stderr exceeded the bounded limit");
    }
    if (result.code !== 0 || result.signal !== null) {
      fail(
        `Q-04 segment exited code=${result.code} signal=${result.signal}: ` +
          stderr.trim(),
      );
    }
    if (stderr.length !== 0) {
      fail("Q-04 successful segment emitted unexpected stderr");
    }
    return Object.freeze({
      closeExitCode: result.code,
      pid: child.pid,
      stderr,
    });
  } catch (error) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
      await closed;
    }
    throw error;
  }
}

export async function runQ04History(configPath) {
  const config = readConfig(configPath);
  const startedAt = process.hrtime.bigint();
  const seed = q04HistorySeed(config.historyIndex);
  const keys = generateQ04HistoryKeys({
    historyIndex: config.historyIndex,
    entryCount: config.entryCount,
  });
  const inputTranscript = createHash("sha256")
    .update(INPUT_TRANSCRIPT_DOMAIN, "ascii")
    .update(seed);
  keys.forEach((key) => inputTranscript.update(key));

  const oracle = createIndependentPoseidonOracle({
    parameterSourcePath: config.parameterSourcePath,
  });
  const tree = createIndependentIndexedNullifierTree({ oracle });
  const databasePath = join(config.outputDirectory, "store.sqlite");
  const transitionPath = join(
    config.outputDirectory,
    `history-${config.historyIndex}-transitions.ndjson`,
  );
  const transcript = openTranscript(transitionPath);
  const checkpoints = [];
  let expectedStoreTranscript = initialStoreTranscript(
    config.historyIndex,
    seed,
  );
  let expectedLogicalDigest = null;
  const workerPids = new Set();
  let acceptedEntries = 0;
  let peakRssBytes = process.resourceUsage().maxRSS * 1024;
  let readBytes = 0;
  let writeBytes = 0;
  let finalStorage = null;

  try {
    for (
      let startEntry = 0;
      startEntry < config.entryCount;
      startEntry += config.checkpointInterval
    ) {
      const endEntry = startEntry + config.checkpointInterval;
      const segmentConfigPath = join(
        config.outputDirectory,
        `segment-${String(endEntry).padStart(5, "0")}.json`,
      );
      writePrivateJson(segmentConfigPath, {
        schema: SEGMENT_CONFIG_SCHEMA,
        historyIndex: config.historyIndex,
        seed: Q04_HISTORY_SEED_HEX[config.historyIndex],
        databasePath,
        startEntry,
        endEntry,
        checkpointInterval: config.checkpointInterval,
        expectedStartRoot: hex(tree.state().root),
        expectedStartTranscript: expectedStoreTranscript.toString("hex"),
        expectedStartLogicalDigest: expectedLogicalDigest,
      });

      let startRecord = null;
      let endRecord = null;
      let expectedOrdinal = startEntry + 1;
      const segment = await runSegment({
        configPath: segmentConfigPath,
        onRecord: async (record, pid) => {
          if (record.type === "start") {
            if (startRecord !== null || expectedOrdinal !== startEntry + 1) {
              fail("Q-04 segment emitted duplicate or late start");
            }
            if (workerPids.has(pid)) {
              fail("Q-04 worker PID was unexpectedly reused");
            }
            workerPids.add(pid);
            requireEqual(record.pid, pid, "Q-04 segment PID");
            requireEqual(
              record.historyIndex,
              config.historyIndex,
              "Q-04 segment history index",
            );
            requireEqual(record.startEntry, startEntry, "Q-04 segment start");
            requireEqual(record.normalCount, startEntry, "Q-04 reopened count");
            requireEqual(
              record.root,
              hex(tree.state().root),
              "Q-04 reopened root",
            );
            requireEqual(
              record.transcriptChainSha256,
              expectedStoreTranscript.toString("hex"),
              "Q-04 reopened transcript",
            );
            if (
              expectedLogicalDigest !== null &&
              record.logicalStoreSha256 !== expectedLogicalDigest
            ) fail("Q-04 reopened logical store digest differs");
            requireEqual(record.integrityCheck, "ok", "Q-04 SQLite integrity");
            requireEqual(
              record.foreignKeyViolations,
              0,
              "Q-04 foreign-key violations",
            );
            startRecord = record;
            return;
          }
          if (record.type === "transition") {
            if (
              startRecord === null ||
              endRecord !== null ||
              record.ordinal !== expectedOrdinal
            ) fail("Q-04 segment transition ordering differs");
            const key = keys[record.ordinal - 1];
            const oracleResourcesBefore = process.resourceUsage();
            const oracleTimeBefore = process.hrtime.bigint();
            const expected = tree.insert(key);
            const oracleTimeAfter = process.hrtime.bigint();
            const oracleResourcesAfter = process.resourceUsage();
            const pathDigests = compareTransition(
              record,
              expected,
              record.ordinal,
              key,
            );
            const expectedTransitionDigest = transitionDigest(
              record.ordinal,
              key,
              expected,
            );
            requireEqual(
              record.transitionDigestSha256,
              expectedTransitionDigest.toString("hex"),
              "Q-04 transition digest",
            );
            expectedStoreTranscript = createHash("sha256")
              .update(expectedStoreTranscript)
              .update(expectedTransitionDigest)
              .digest();
            requireEqual(
              record.transcriptChainSha256,
              expectedStoreTranscript.toString("hex"),
              "Q-04 transcript chain",
            );
            transcript.append({
              schema: TRANSITION_SCHEMA,
              historyIndex: config.historyIndex,
              ordinal: record.ordinal,
              key: record.key,
              preRoot: record.preRoot,
              intermediateRoot: record.intermediateRoot,
              postRoot: record.postRoot,
              pathDigests,
              actual: {
                transitionDigestSha256: record.transitionDigestSha256,
                transcriptChainSha256: record.transcriptChainSha256,
                operationCounts: record.operationCounts,
                measurement: record.measurement,
              },
              oracle: {
                transitionDigestSha256:
                  expectedTransitionDigest.toString("hex"),
                transcriptChainSha256:
                  expectedStoreTranscript.toString("hex"),
                operationCounts: expected.metrics,
                measurement: {
                  wallMicros:
                    Number(oracleTimeAfter - oracleTimeBefore) / 1e3,
                  ...resourceDelta(
                    oracleResourcesBefore,
                    oracleResourcesAfter,
                  ),
                  rssBytes: process.memoryUsage.rss(),
                },
              },
              discrepancies: 0,
            });
            acceptedEntries += 1;
            expectedOrdinal += 1;
            peakRssBytes = Math.max(
              peakRssBytes,
              record.measurement.rssBytes,
              process.memoryUsage.rss(),
            );
            return;
          }
          if (record.type === "end") {
            if (
              startRecord === null ||
              endRecord !== null ||
              expectedOrdinal !== endEntry + 1
            ) fail("Q-04 segment ended before its exact transition count");
            requireEqual(record.pid, pid, "Q-04 segment end PID");
            requireEqual(
              record.historyIndex,
              config.historyIndex,
              "Q-04 segment end history index",
            );
            requireEqual(record.endEntry, endEntry, "Q-04 segment end entry");
            requireEqual(
              record.root,
              hex(tree.state().root),
              "Q-04 checkpoint root",
            );
            requireEqual(
              record.transcriptChainSha256,
              expectedStoreTranscript.toString("hex"),
              "Q-04 checkpoint transcript",
            );
            requireEqual(
              record.audit.normalCount,
              endEntry,
              "Q-04 checkpoint count",
            );
            requireEqual(
              record.audit.integrityCheck,
              "ok",
              "Q-04 checkpoint integrity",
            );
            requireEqual(
              record.audit.foreignKeyViolations,
              0,
              "Q-04 checkpoint foreign-key violations",
            );
            endRecord = record;
            return;
          }
          fail(`Q-04 segment emitted unsupported record type ${record.type}`);
        },
      });
      if (startRecord === null || endRecord === null) {
        fail("Q-04 segment omitted its start or end record");
      }
      validateStorage(
        endRecord.preCloseStorage,
        "Q-04 segment pre-close storage",
        { open: true },
      );
      validateStorage(
        endRecord.postCloseStorage,
        "Q-04 segment post-close storage",
      );
      validateLifecycleMeasurement(
        endRecord.segmentMeasurement,
        "Q-04 segment measurement",
      );
      exactKeys(endRecord.phaseMeasurement, [
        "checkpointProbeAuditWallMs",
        "openAndStartAuditWallMs",
        "scheduleGenerationWallMs",
        "transitionLoopWallMs",
      ], "Q-04 segment phase measurement");
      Object.entries(endRecord.phaseMeasurement).forEach(([field, value]) =>
        finiteNonNegative(value, `Q-04 segment phase ${field}`)
      );

      assertPrivateDirectory(config.outputDirectory);
      const reopenConfigPath = join(
        config.outputDirectory,
        `reopen-${String(endEntry).padStart(5, "0")}.json`,
      );
      writePrivateJson(reopenConfigPath, {
        schema: REOPEN_CONFIG_SCHEMA,
        historyIndex: config.historyIndex,
        seed: Q04_HISTORY_SEED_HEX[config.historyIndex],
        databasePath,
        expectedCount: endEntry,
        expectedRoot: endRecord.root,
        expectedTranscript: endRecord.transcriptChainSha256,
        expectedLogicalDigest: endRecord.logicalStoreSha256,
      });
      const reopen = await runReopen({ configPath: reopenConfigPath });
      const reopenRecord = reopen.record;
      if (workerPids.has(reopen.pid)) {
        fail("Q-04 reopen PID was unexpectedly reused");
      }
      workerPids.add(reopen.pid);
      assertPrivateDirectory(config.outputDirectory);
      requireEqual(
        reopenRecord.historyIndex,
        config.historyIndex,
        "Q-04 fresh reopen history index",
      );
      requireEqual(
        reopenRecord.afterEntry,
        endEntry,
        "Q-04 fresh reopen entry",
      );
      requireEqual(
        reopenRecord.root,
        endRecord.root,
        "Q-04 fresh reopen root",
      );
      requireEqual(
        reopenRecord.transcriptChainSha256,
        endRecord.transcriptChainSha256,
        "Q-04 fresh reopen transcript",
      );
      requireEqual(
        reopenRecord.logicalStoreSha256,
        endRecord.logicalStoreSha256,
        "Q-04 fresh reopen logical digest",
      );
      requireEqual(
        reopenRecord.audit.normalCount,
        endEntry,
        "Q-04 fresh reopen count",
      );

      expectedLogicalDigest = reopenRecord.logicalStoreSha256;
      readBytes += endRecord.segmentMeasurement.readBytes;
      readBytes += reopenRecord.measurement.readBytes;
      writeBytes += endRecord.segmentMeasurement.writeBytes;
      writeBytes += reopenRecord.measurement.writeBytes;
      peakRssBytes = Math.max(
        peakRssBytes,
        endRecord.segmentMeasurement.peakRssBytes,
        reopenRecord.measurement.peakRssBytes,
      );
      finalStorage = reopenRecord.postCloseStorage;
      const probes = endRecord.probes.map((probe) => ({
        caseId: probe.caseId,
        caseSha256: probe.caseSha256,
        kind: probe.kind,
        expectedOutcome: probe.expectedOutcome,
        accepted: probe.accepted,
        stateUnchanged: probe.stateUnchanged,
        errorCode: probe.errorCode,
        inputSha256: probe.inputSha256,
        preStateSha256: probe.preStateSha256,
        postStateSha256: probe.postStateSha256,
        rejection: probe.rejection,
        resultSha256: probe.resultSha256,
      }));
      requireEqual(
        probes.map(({ kind }) => kind),
        [
          "duplicate",
          "ordering",
          "successor-pointer",
          "alias",
          "noncanonical-field",
        ],
        "Q-04 checkpoint probe order",
      );
      if (
        probes.some((probe) =>
          probe.accepted ||
          !probe.stateUnchanged ||
          probe.preStateSha256 !== probe.postStateSha256
        )
      ) fail("Q-04 checkpoint adversarial probe was not safely rejected");
      checkpoints.push({
        afterEntry: endEntry,
        closeExitCode: segment.closeExitCode,
        reopenExitCode: reopen.closeExitCode,
        actualRoot: endRecord.root,
        oracleRoot: hex(tree.state().root),
        logicalStoreSha256: endRecord.logicalStoreSha256,
        actualTranscriptSha256: endRecord.transcriptChainSha256,
        oracleTranscriptSha256: expectedStoreTranscript.toString("hex"),
        probes,
        discrepancies: 0,
        unexpectedAccepts: 0,
        workerPid: endRecord.pid,
        reopenPid: reopenRecord.pid,
        writerOpenAndAuditWallMs: startRecord.reopenWallMs,
        reopenOpenAndAuditWallMs: reopenRecord.openAndAuditWallMs,
        reopenParentLifecycleWallMs: reopen.parentLifecycleWallMs,
        phaseMeasurement: endRecord.phaseMeasurement,
        segmentMeasurement: endRecord.segmentMeasurement,
        reopenMeasurement: reopenRecord.measurement,
        storage: {
          segmentPreClose: endRecord.preCloseStorage,
          segmentPostClose: endRecord.postCloseStorage,
          reopenPreClose: reopenRecord.preCloseStorage,
          reopenPostClose: reopenRecord.postCloseStorage,
        },
      });
    }
    if (acceptedEntries !== config.entryCount) {
      fail("Q-04 history accepted-entry count differs");
    }
    const transitionArtifact = transcript.close();
    const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    return Object.freeze({
      schema: RESULT_SCHEMA,
      configSha256: config.configSha256,
      qualifying: config.qualifying,
      index: config.historyIndex,
      seed: seed.toString("hex"),
      acceptedEntries,
      inputTranscriptSha256: inputTranscript.digest("hex"),
      actualTranscriptSha256: expectedStoreTranscript.toString("hex"),
      oracleTranscriptSha256: expectedStoreTranscript.toString("hex"),
      finalActualRoot: checkpoints.at(-1).actualRoot,
      finalOracleRoot: hex(tree.state().root),
      comparisons: Object.freeze({
        transitions: acceptedEntries,
        predecessorMembershipPaths: acceptedEntries,
        emptyAppendNonMembershipPaths: acceptedEntries,
        postInsertionMembershipPaths: acceptedEntries,
        discrepancies: 0,
      }),
      checkpoints: Object.freeze(checkpoints),
      measurements: Object.freeze({
        elapsedMs,
        peakRssBytes,
        databaseBytes: finalStorage.fileBytes.database,
        walBytes: finalStorage.fileBytes.wal,
        shmBytes: finalStorage.fileBytes.shm,
        totalFileBytes: finalStorage.totalFileBytes,
        readBytes,
        writeBytes,
      }),
      transitionArtifact,
      oracleMetadata: Object.freeze({
        poseidon: oracle.metadata,
        tree: tree.metadata,
      }),
    });
  } catch (error) {
    try {
      transcript.close();
    } catch {}
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    if (process.argv.length !== 3) {
      fail(
        "usage: node v2-q04-history-runner.mjs /absolute/path/to/config.json",
      );
    }
    const result = await runQ04History(process.argv[2]);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
