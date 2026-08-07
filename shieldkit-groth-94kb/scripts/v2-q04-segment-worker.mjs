#!/usr/bin/env node
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { parseStrictJson } from "../packages/profile/load.mjs";
import {
  openQ04PersistentNullifierStore,
} from "../packages/pool/v2/qualification/persistent-nullifier-store.mjs";
import {
  generateQ04HistoryKeys,
  Q04_ENTRIES_PER_HISTORY,
  Q04_HISTORY_SEED_HEX,
} from "../packages/pool/v2/qualification/q04-schedule.mjs";
import {
  runQ04CheckpointProbes,
} from "../packages/pool/v2/qualification/q04-checkpoint-probes.mjs";

const CONFIG_SCHEMA = "shieldkit-v2-direct/q04-segment-config/v1";
const OUTPUT_SCHEMA = "shieldkit-v2-direct/q04-segment-output/v2";
const HEX_64 = /^[0-9a-f]{64}$/;

class Q04SegmentWorkerError extends Error {
  constructor(message) {
    super(message);
    this.name = "Q04SegmentWorkerError";
  }
}

const fail = (message) => {
  throw new Q04SegmentWorkerError(message);
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
const hex64 = (value, label, { nullable = false } = {}) => {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !HEX_64.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
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
const same = (left, right) =>
  Buffer.from(left).equals(Buffer.from(right));
const hex = (value) =>
  typeof value === "bigint"
    ? value.toString(16).padStart(64, "0")
    : Buffer.from(value).toString("hex");
const encodeLeaf = (leaf) => ({
  type: leaf.type,
  index: leaf.index,
  key: leaf.key,
  successorIndex: leaf.successorIndex,
  successorKey: leaf.successorKey,
});
const encodePath = (path) => path.map(hex);
const resourceDelta = (before, after) => ({
  userCpuMicros: after.userCPUTime - before.userCPUTime,
  systemCpuMicros: after.systemCPUTime - before.systemCPUTime,
  voluntaryContextSwitches:
    after.voluntaryContextSwitches - before.voluntaryContextSwitches,
  involuntaryContextSwitches:
    after.involuntaryContextSwitches - before.involuntaryContextSwitches,
  fsReadOps: after.fsRead - before.fsRead,
  fsWriteOps: after.fsWrite - before.fsWrite,
});
const processIo = () => {
  const fields = Object.fromEntries(
    readFileSync("/proc/self/io", "utf8")
      .trim()
      .split("\n")
      .map((line) => {
        const separator = line.indexOf(":");
        if (separator === -1) fail("/proc/self/io contains a malformed row");
        return [
          line.slice(0, separator),
          Number(line.slice(separator + 1).trim()),
        ];
      }),
  );
  if (
    !Number.isSafeInteger(fields.read_bytes) ||
    !Number.isSafeInteger(fields.write_bytes)
  ) fail("/proc/self/io is missing exact read_bytes/write_bytes counters");
  return {
    readBytes: fields.read_bytes,
    writeBytes: fields.write_bytes,
  };
};
const secureClosedFileSize = (path) => {
  let descriptor;
  try {
    descriptor = openSync(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
  } catch (error) {
    if (error && error.code === "ENOENT") return 0;
    throw error;
  }
  try {
    const before = fstatSync(descriptor);
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600 ||
      (
        typeof process.getuid === "function" &&
        before.uid !== process.getuid()
      )
    ) fail("Q-04 closed store file is not a private direct regular file");
    const named = lstatSync(path);
    if (
      named.isSymbolicLink() ||
      named.dev !== before.dev ||
      named.ino !== before.ino ||
      realpathSync(path) !== path
    ) fail("Q-04 closed store file path changed during measurement");
    const after = fstatSync(descriptor);
    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size ||
      after.mtimeMs !== before.mtimeMs
    ) fail("Q-04 closed store file changed during measurement");
    return before.size;
  } finally {
    closeSync(descriptor);
  }
};
const closedStorage = (databasePath) => {
  const fileBytes = {};
  for (const [name, path] of [
    ["database", databasePath],
    ["wal", `${databasePath}-wal`],
    ["shm", `${databasePath}-shm`],
  ]) {
    fileBytes[name] = secureClosedFileSize(path);
  }
  return {
    fileBytes,
    totalFileBytes:
      Object.values(fileBytes).reduce((sum, size) => sum + size, 0),
  };
};
const emit = (value) => {
  process.stdout.write(`${JSON.stringify({
    schema: OUTPUT_SCHEMA,
    ...value,
  })}\n`);
};

function readConfig(filename) {
  const path = canonicalAbsolutePath(filename, "Q-04 segment config path");
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
      "Q-04 segment config must be a bounded single-link " +
        "user-owned mode-0600 regular file",
    );
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      after.dev !== observed.dev ||
      after.ino !== observed.ino ||
      after.size !== observed.size ||
      after.mtimeMs !== observed.mtimeMs
    ) fail("Q-04 segment config changed while being read");
  } finally {
    closeSync(descriptor);
  }
  const named = lstatSync(path);
  if (
    named.isSymbolicLink() ||
    named.dev !== observed.dev ||
    named.ino !== observed.ino ||
    realpathSync(path) !== path
  ) {
    fail("Q-04 segment config must not traverse symbolic links");
  }
  const config = parseStrictJson(bytes);
  exactKeys(config, [
    "checkpointInterval",
    "databasePath",
    "endEntry",
    "expectedStartLogicalDigest",
    "expectedStartRoot",
    "expectedStartTranscript",
    "historyIndex",
    "schema",
    "seed",
    "startEntry",
  ], "Q-04 segment config");
  if (config.schema !== CONFIG_SCHEMA) fail("Q-04 segment config schema differs");
  const historyIndex = integer(config.historyIndex, 0, 3, "historyIndex");
  const startEntry = integer(
    config.startEntry,
    0,
    Q04_ENTRIES_PER_HISTORY - 1,
    "startEntry",
  );
  const endEntry = integer(
    config.endEntry,
    startEntry + 1,
    Q04_ENTRIES_PER_HISTORY,
    "endEntry",
  );
  const checkpointInterval = integer(
    config.checkpointInterval,
    1,
    Q04_ENTRIES_PER_HISTORY,
    "checkpointInterval",
  );
  if (
    endEntry - startEntry !== checkpointInterval ||
    endEntry % checkpointInterval !== 0
  ) fail("Q-04 segment must end at exactly one checkpoint");
  if (config.seed !== Q04_HISTORY_SEED_HEX[historyIndex]) {
    fail("Q-04 segment seed differs from the fixed history");
  }
  return Object.freeze({
    checkpointInterval,
    databasePath: canonicalAbsolutePath(
      config.databasePath,
      "Q-04 database path",
    ),
    endEntry,
    expectedStartLogicalDigest: hex64(
      config.expectedStartLogicalDigest,
      "expectedStartLogicalDigest",
      { nullable: true },
    ),
    expectedStartRoot: hex64(config.expectedStartRoot, "expectedStartRoot"),
    expectedStartTranscript: hex64(
      config.expectedStartTranscript,
      "expectedStartTranscript",
    ),
    historyIndex,
    seed: config.seed,
    startEntry,
  });
}

export async function runQ04SegmentWorker(configPath) {
  const lifecycleStartedAt = process.hrtime.bigint();
  const lifecycleStartResources = process.resourceUsage();
  const lifecycleStartIo = processIo();
  const config = readConfig(configPath);
  const seed = Buffer.from(config.seed, "hex");
  const scheduleStartedAt = process.hrtime.bigint();
  const keys = generateQ04HistoryKeys({
    historyIndex: config.historyIndex,
    entryCount: config.endEntry,
  });
  const scheduleFinishedAt = process.hrtime.bigint();
  const openedAt = process.hrtime.bigint();
  const store = openQ04PersistentNullifierStore({
    path: config.databasePath,
    create: config.startEntry === 0,
    historyIndex: config.historyIndex,
    seed,
  });
  let endPayload;
  let checkpointFinishedAt;
  let transitionLoopStartedAt;
  let transitionLoopFinishedAt;
  try {
    const startAudit = store.audit();
    const startState = store.state();
    if (
      startState.normalCount !== config.startEntry ||
      hex(startState.root) !== config.expectedStartRoot ||
      hex(startState.transcriptChainSha256) !==
        config.expectedStartTranscript ||
      (
        config.expectedStartLogicalDigest !== null &&
        startAudit.logicalDigestSha256 !==
          config.expectedStartLogicalDigest
      )
    ) fail("Q-04 fresh-process reopened state differs from checkpoint");
    emit({
      type: "start",
      pid: process.pid,
      historyIndex: config.historyIndex,
      startEntry: config.startEntry,
      root: hex(startState.root),
      transcriptChainSha256: hex(startState.transcriptChainSha256),
      logicalStoreSha256: startAudit.logicalDigestSha256,
      normalCount: startAudit.normalCount,
      integrityCheck: startAudit.integrityCheck,
      foreignKeyViolations: startAudit.foreignKeyViolations,
      reopenWallMs: Number(process.hrtime.bigint() - openedAt) / 1e6,
    });

    let lastKey;
    let aliasEvidence;
    transitionLoopStartedAt = process.hrtime.bigint();
    for (
      let ordinal = config.startEntry + 1;
      ordinal <= config.endEntry;
      ordinal += 1
    ) {
      const key = keys[ordinal - 1];
      const inputKey = Buffer.from(key);
      const beforeResources = process.resourceUsage();
      const beforeTime = process.hrtime.bigint();
      const before = store.state();
      const expectedRootInput = Buffer.from(before.root);
      const actual = store.insert({
        expectedCount: before.normalCount,
        expectedRoot: expectedRootInput,
        key: inputKey,
      });
      const postMembership = store.membershipPath(
        actual.mutation.witness.append.index,
      );
      const afterTime = process.hrtime.bigint();
      const afterResources = process.resourceUsage();
      const transitionRecord = {
        type: "transition",
        historyIndex: config.historyIndex,
        ordinal,
        key: hex(key),
        preRoot: hex(actual.mutation.witness.preRoot),
        intermediateRoot: hex(actual.mutation.witness.intermediateRoot),
        postRoot: hex(actual.mutation.witness.postRoot),
        predecessor: encodeLeaf(actual.mutation.witness.predecessor),
        updatedPredecessor:
          encodeLeaf(actual.mutation.witness.updatedPredecessor),
        predecessorPath:
          encodePath(actual.mutation.witness.predecessorPath),
        append: {
          index: actual.mutation.witness.append.index,
          newLeaf: encodeLeaf(actual.mutation.witness.append.newLeaf),
          emptyPath: encodePath(actual.mutation.witness.append.path),
        },
        postMembershipPath: encodePath(postMembership.siblings),
        transitionDigestSha256: actual.transitionDigestSha256,
        transcriptChainSha256: actual.transcriptChainSha256,
        operationCounts: {
          productionLeafHashCalls: actual.mutation.metrics.leafHashCalls,
          productionPredecessorValidationLeafHashCalls:
            actual.mutation.metrics.predecessorValidationLeafHashCalls,
          productionMutationLeafHashCalls:
            actual.mutation.metrics.mutationLeafHashCalls,
          productionMutationNodeHashCalls:
            actual.mutation.metrics.nodeHashCalls,
          productionLogicalPathSiblingLookups:
            actual.mutation.metrics.logicalPathSiblingLookups,
          productionPathOverrideHits:
            actual.mutation.metrics.pathOverrideHits,
          productionPathAdapterNodeReads:
            actual.mutation.metrics.pathAdapterNodeReads,
          productionRootAdapterNodeReads:
            actual.mutation.metrics.rootAdapterNodeReads,
          productionTotalAdapterNodeReads: actual.mutation.metrics.nodeReads,
          productionLeafReads: actual.mutation.metrics.leafReads,
          productionOrderLookups: actual.mutation.metrics.orderLookups,
          productionPostMembershipNodeHashCalls:
            postMembership.metrics.nodeHashCalls,
          productionPostMembershipNodeReads:
            postMembership.metrics.nodeReads,
        },
        measurement: {
          wallMicros: Number(afterTime - beforeTime) / 1e3,
          ...resourceDelta(beforeResources, afterResources),
          rssBytes: process.memoryUsage.rss(),
        },
      };
      if (ordinal === config.endEntry) {
        lastKey = Buffer.from(key);
        const durableRoot = transitionRecord.postRoot;
        const appendedIndex = actual.mutation.witness.append.index;
        aliasEvidence = {
          inputKey,
          expectedRootInput,
          stateRootResult: before.root,
          writeRootResult: actual.writes.root,
          mutationLeafKeyResult:
            actual.mutation.nullifierLeaves.at(-1).key,
          membershipRootResult: postMembership.root,
        };
        Object.values(aliasEvidence).forEach((buffer) => buffer.fill(0xff));
        const afterAlias = store.audit();
        if (
          !same(store.leaf(appendedIndex).key, key) ||
          hex(afterAlias.root) !== durableRoot
        ) {
          fail("Q-04 store retained an aliased caller or result buffer");
        }
      }
      emit(transitionRecord);
    }
    transitionLoopFinishedAt = process.hrtime.bigint();

    const checkpointStartedAt = process.hrtime.bigint();
    const probes = runQ04CheckpointProbes({
      store,
      lastKey,
      aliasEvidence,
    });
    const finalAudit = store.audit();
    const finalState = store.state();
    const preCloseStorage = store.storageMetrics();
    checkpointFinishedAt = process.hrtime.bigint();
    endPayload = {
      type: "end",
      pid: process.pid,
      historyIndex: config.historyIndex,
      endEntry: config.endEntry,
      root: hex(finalState.root),
      transcriptChainSha256: hex(finalState.transcriptChainSha256),
      logicalStoreSha256: finalAudit.logicalDigestSha256,
      audit: {
        normalCount: finalAudit.normalCount,
        leafCount: finalAudit.leafCount,
        nodeCount: finalAudit.nodeCount,
        orderCount: finalAudit.orderCount,
        integrityCheck: finalAudit.integrityCheck,
        foreignKeyViolations: finalAudit.foreignKeyViolations,
      },
      probes,
      preCloseStorage,
      phaseMeasurement: {
        scheduleGenerationWallMs:
          Number(scheduleFinishedAt - scheduleStartedAt) / 1e6,
        openAndStartAuditWallMs:
          Number(transitionLoopStartedAt - openedAt) / 1e6,
        transitionLoopWallMs:
          Number(transitionLoopFinishedAt - transitionLoopStartedAt) / 1e6,
        checkpointProbeAuditWallMs:
          Number(checkpointFinishedAt - checkpointStartedAt) / 1e6,
      },
    };
  } finally {
    const closeStartedAt = process.hrtime.bigint();
    store.close();
    const closedAt = process.hrtime.bigint();
    if (endPayload !== undefined) {
      const endResources = process.resourceUsage();
      const endIo = processIo();
      emit({
        ...endPayload,
        postCloseStorage: closedStorage(config.databasePath),
        segmentMeasurement: {
          wallMs: Number(closedAt - lifecycleStartedAt) / 1e6,
          closeWallMs: Number(closedAt - closeStartedAt) / 1e6,
          peakRssBytes: endResources.maxRSS * 1024,
          readBytes:
            endIo.readBytes - lifecycleStartIo.readBytes,
          writeBytes:
            endIo.writeBytes - lifecycleStartIo.writeBytes,
          ...resourceDelta(lifecycleStartResources, endResources),
        },
      });
    }
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    if (process.argv.length !== 3) {
      fail(
        "usage: node v2-q04-segment-worker.mjs /absolute/path/to/config.json",
      );
    }
    await runQ04SegmentWorker(process.argv[2]);
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
