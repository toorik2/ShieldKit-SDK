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
  Q04_ENTRIES_PER_HISTORY,
  Q04_HISTORY_SEED_HEX,
} from "../packages/pool/v2/qualification/q04-schedule.mjs";

const CONFIG_SCHEMA = "shieldkit-v2-direct/q04-reopen-config/v1";
const OUTPUT_SCHEMA = "shieldkit-v2-direct/q04-reopen-output/v1";
const HEX_64 = /^[0-9a-f]{64}$/;

class Q04ReopenWorkerError extends Error {
  constructor(message) {
    super(message);
    this.name = "Q04ReopenWorkerError";
  }
}

const fail = (message) => {
  throw new Q04ReopenWorkerError(message);
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
const hex = (value) => Buffer.from(value).toString("hex");
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
  ) fail("/proc/self/io is missing read_bytes/write_bytes");
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

function readConfig(filename) {
  const path = canonicalAbsolutePath(filename, "Q-04 reopen config path");
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
      "Q-04 reopen config must be a bounded single-link " +
        "user-owned mode-0600 regular file",
    );
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      after.dev !== observed.dev ||
      after.ino !== observed.ino ||
      after.size !== observed.size ||
      after.mtimeMs !== observed.mtimeMs
    ) fail("Q-04 reopen config changed while being read");
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
    fail("Q-04 reopen config must not traverse symbolic links");
  }
  const config = parseStrictJson(bytes);
  exactKeys(config, [
    "databasePath",
    "expectedCount",
    "expectedLogicalDigest",
    "expectedRoot",
    "expectedTranscript",
    "historyIndex",
    "schema",
    "seed",
  ], "Q-04 reopen config");
  if (config.schema !== CONFIG_SCHEMA) fail("Q-04 reopen config schema differs");
  const historyIndex = integer(config.historyIndex, 0, 3, "historyIndex");
  if (config.seed !== Q04_HISTORY_SEED_HEX[historyIndex]) {
    fail("Q-04 reopen seed differs from fixed history");
  }
  return Object.freeze({
    databasePath: canonicalAbsolutePath(
      config.databasePath,
      "Q-04 reopen database path",
    ),
    expectedCount: integer(
      config.expectedCount,
      1,
      Q04_ENTRIES_PER_HISTORY,
      "expectedCount",
    ),
    expectedLogicalDigest: hex64(
      config.expectedLogicalDigest,
      "expectedLogicalDigest",
    ),
    expectedRoot: hex64(config.expectedRoot, "expectedRoot"),
    expectedTranscript: hex64(
      config.expectedTranscript,
      "expectedTranscript",
    ),
    historyIndex,
    seed: config.seed,
  });
}

export function runQ04ReopenWorker(configPath) {
  const lifecycleStartedAt = process.hrtime.bigint();
  const startResources = process.resourceUsage();
  const startIo = processIo();
  const config = readConfig(configPath);
  const openedAt = process.hrtime.bigint();
  const store = openQ04PersistentNullifierStore({
    path: config.databasePath,
    create: false,
    historyIndex: config.historyIndex,
    seed: Buffer.from(config.seed, "hex"),
  });
  let record;
  try {
    const audit = store.audit();
    const state = store.state();
    if (
      state.normalCount !== config.expectedCount ||
      hex(state.root) !== config.expectedRoot ||
      hex(state.transcriptChainSha256) !== config.expectedTranscript ||
      audit.logicalDigestSha256 !== config.expectedLogicalDigest ||
      audit.integrityCheck !== "ok" ||
      audit.foreignKeyViolations !== 0
    ) fail("Q-04 fresh reopen verification differs from checkpoint");
    record = {
      schema: OUTPUT_SCHEMA,
      type: "reopen",
      pid: process.pid,
      historyIndex: config.historyIndex,
      afterEntry: config.expectedCount,
      root: hex(state.root),
      transcriptChainSha256: hex(state.transcriptChainSha256),
      logicalStoreSha256: audit.logicalDigestSha256,
      audit: {
        normalCount: audit.normalCount,
        leafCount: audit.leafCount,
        nodeCount: audit.nodeCount,
        orderCount: audit.orderCount,
        integrityCheck: audit.integrityCheck,
        foreignKeyViolations: audit.foreignKeyViolations,
      },
      preCloseStorage: store.storageMetrics(),
      openAndAuditWallMs:
        Number(process.hrtime.bigint() - openedAt) / 1e6,
    };
  } finally {
    const closeStartedAt = process.hrtime.bigint();
    store.close();
    const closedAt = process.hrtime.bigint();
    if (record !== undefined) {
      const endResources = process.resourceUsage();
      const endIo = processIo();
      record.postCloseStorage = closedStorage(config.databasePath);
      record.measurement = {
        wallMs: Number(closedAt - lifecycleStartedAt) / 1e6,
        closeWallMs: Number(closedAt - closeStartedAt) / 1e6,
        peakRssBytes: endResources.maxRSS * 1024,
        readBytes: endIo.readBytes - startIo.readBytes,
        writeBytes: endIo.writeBytes - startIo.writeBytes,
        ...resourceDelta(startResources, endResources),
      };
    }
  }
  return Object.freeze(record);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    if (process.argv.length !== 3) {
      fail(
        "usage: node v2-q04-reopen-worker.mjs /absolute/path/to/config.json",
      );
    }
    process.stdout.write(
      `${JSON.stringify(runQ04ReopenWorker(process.argv[2]))}\n`,
    );
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
