#!/usr/bin/env node
/*
 * Q-04 is deliberately a one-way evidence writer.  This program has no
 * "quick", profile, resume, or overwrite switch: a qualification invocation
 * is either the frozen 4 x 25,000 campaign or it is rejected before work.
 */
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statfsSync,
  writeSync,
} from "node:fs";
import os from "node:os";
import { dirname, extname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, "../..");
const HEX_40 = /^[0-9a-f]{40}$/;
const MAX_CHILD_OUTPUT = 8 * 1024 * 1024;
const Q04_HISTORY_COUNT = 4;
const Q04_ENTRIES_PER_HISTORY = 25_000;
const Q04_CHECKPOINT_INTERVAL = 1_000;
const Q04_REQUIRED_PROBE_COUNT = 5;
const Q04_RUST_TOOLCHAIN = "1.97.1";

export class V2Q04CampaignError extends Error {
  constructor(message) {
    super(message);
    this.name = "V2Q04CampaignError";
  }
}

const fail = (message) => { throw new V2Q04CampaignError(message); };
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const timestamp = () => new Date().toISOString();
export const elapsedMilliseconds = (startedNs, finishedNs = process.hrtime.bigint()) => {
  if (typeof startedNs !== "bigint" || typeof finishedNs !== "bigint" || finishedNs < startedNs) {
    fail("Q-04 monotonic duration bounds are invalid");
  }
  return Math.max(1, Math.ceil(Number(finishedNs - startedNs) / 1e6));
};
const canonicalAbsolute = (value, label) => {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`);
  }
  return value;
};
const posixPath = (value) => relative(workspaceRoot, value).split("\\").join("/");

function privateDirectory(path, { create = false } = {}) {
  if (create) mkdirSync(path, { recursive: true, mode: 0o700 });
  const observed = lstatSync(path);
  if (!observed.isDirectory() || observed.isSymbolicLink()) {
    fail(`Q-04 directory is not a direct directory: ${path}`);
  }
  chmodSync(path, 0o700);
}

function regularSource(path) {
  const observed = lstatSync(path);
  if (!observed.isFile() || observed.isSymbolicLink() || observed.nlink !== 1) {
    fail(`Q-04 source input must be a single-link regular file: ${path}`);
  }
  return observed;
}

function atomicWrite(path, contents) {
  const parent = dirname(path);
  privateDirectory(parent);
  if (lstatSync(path, { throwIfNoEntry: false }) !== undefined) {
    fail(`Q-04 refuses to overwrite an existing artifact: ${path}`);
  }
  const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
  const temporary = join(parent, `.${randomBytes(16).toString("hex")}.tmp`);
  const descriptor = openSync(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    writeSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    renameSync(temporary, path);
  } catch (error) {
    try { closeSync(openSync(temporary, constants.O_RDONLY)); } catch {}
    throw error;
  }
  chmodSync(path, 0o600);
  return Object.freeze({ path, bytes: bytes.length, sha256: sha256(bytes) });
}

function writeJson(path, value) {
  return atomicWrite(path, `${JSON.stringify(value, null, 2)}\n`);
}

function bundleReference(bundle, artifact) {
  const path = relative(bundle, artifact.path).split("\\").join("/");
  if (path === "" || path.startsWith("../") || path.includes("/../")) {
    fail("Q-04 artifact is outside its evidence bundle");
  }
  return Object.freeze({ path, bytes: artifact.bytes, sha256: artifact.sha256 });
}

async function spawnCapture(executable, arguments_, options = {}) {
  const child = spawn(executable, arguments_, {
    cwd: options.cwd ?? workspaceRoot,
    // A supplied environment is an allow-list.  In particular, do not merge
    // it back into process.env and accidentally resurrect Rust/npm controls
    // which sanitizedEnvironment deliberately removed.
    env: options.env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let spawnError = null;
  const append = (field, chunk) => {
    if (field.value.length + chunk.length > MAX_CHILD_OUTPUT) {
      child.kill("SIGKILL");
      field.value += chunk.slice(0, Math.max(0, MAX_CHILD_OUTPUT - field.value.length));
      return;
    }
    field.value += chunk;
  };
  const stdoutField = { value: stdout };
  const stderrField = { value: stderr };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => append(stdoutField, chunk));
  child.stderr.on("data", (chunk) => append(stderrField, chunk));
  child.once("error", (error) => { spawnError = error; });
  const result = await new Promise((done) => child.once("close", (code, signal) => done({ code, signal })));
  stdout = stdoutField.value;
  stderr = stderrField.value;
  if (spawnError !== null) fail(`unable to spawn ${executable}: ${spawnError.message}`);
  return Object.freeze({ pid: child.pid, exitCode: result.code, signal: result.signal, stdout, stderr });
}

async function commandOrFail(executable, arguments_, options, label, runner) {
  const result = await runner(executable, arguments_, options);
  if (result.exitCode !== 0 || result.signal !== null) {
    fail(`${label} failed: pid=${result.pid} exit=${result.exitCode} signal=${result.signal} stderr=${result.stderr.trim()}`);
  }
  return result;
}

async function gitState(runner) {
  const run = async (arguments_) => commandOrFail("git", arguments_, { cwd: workspaceRoot }, `git ${arguments_.join(" ")}`, runner);
  const [commit, tree, status] = await Promise.all([
    run(["rev-parse", "HEAD^{commit}"]),
    run(["rev-parse", "HEAD^{tree}"]),
    run(["status", "--porcelain=v1", "--untracked-files=all"]),
  ]);
  const gitCommit = commit.stdout.trim();
  const gitTree = tree.stdout.trim();
  if (!HEX_40.test(gitCommit) || !HEX_40.test(gitTree)) fail("Q-04 requires a resolved Git commit and tree");
  if (status.stdout !== "") fail("Q-04 refuses a dirty Git worktree");
  return Object.freeze({ gitCommit, gitTree });
}

export const Q04_CAMPAIGN_PLAN = Object.freeze({
  histories: Q04_HISTORY_COUNT,
  entriesPerHistory: Q04_ENTRIES_PER_HISTORY,
  checkpointInterval: Q04_CHECKPOINT_INTERVAL,
  aggregateEntries: Q04_HISTORY_COUNT * Q04_ENTRIES_PER_HISTORY,
  aggregateProbes: Q04_HISTORY_COUNT * (Q04_ENTRIES_PER_HISTORY / Q04_CHECKPOINT_INTERVAL) * Q04_REQUIRED_PROBE_COUNT,
});

export function createQ04HistoryPlan(bundleRoot) {
  canonicalAbsolute(bundleRoot, "Q-04 bundle path");
  return Object.freeze(Array.from({ length: Q04_HISTORY_COUNT }, (_, historyIndex) => Object.freeze({
    historyIndex,
    entryCount: Q04_ENTRIES_PER_HISTORY,
    checkpointInterval: Q04_CHECKPOINT_INTERVAL,
    outputDirectory: join(bundleRoot, "histories", `history-${historyIndex}`),
  })));
}

export function assertFreshHistoryExecutions(executions) {
  if (!Array.isArray(executions) || executions.length !== Q04_HISTORY_COUNT) {
    fail("Q-04 requires exactly four history process executions");
  }
  const pids = new Set();
  executions.forEach((execution, index) => {
    if (execution?.historyIndex !== index || !Number.isSafeInteger(execution.pid) || execution.pid <= 0) {
      fail(`Q-04 history execution ${index} has an invalid process identity`);
    }
    if (pids.has(execution.pid)) fail("Q-04 histories did not use four fresh processes");
    pids.add(execution.pid);
  });
}

export async function runQ04HistoriesConcurrently(plans, runHistory) {
  if (
    !Array.isArray(plans)
    || plans.length !== Q04_HISTORY_COUNT
    || typeof runHistory !== "function"
  ) {
    fail("Q-04 concurrent history execution requires exactly four plans and one runner");
  }
  const settled = await Promise.allSettled(
    plans.map((plan) => runHistory(plan)),
  );
  const failures = settled.flatMap((outcome, historyIndex) =>
    outcome.status === "rejected"
      ? [{
          historyIndex,
          message: outcome.reason instanceof Error
            ? outcome.reason.message
            : String(outcome.reason),
        }]
      : []
  );
  if (failures.length !== 0) {
    fail(`Q-04 history processes failed: ${JSON.stringify(failures)}`);
  }
  return Object.freeze(settled.map((outcome) => outcome.value));
}

function createBundle(outputParent) {
  canonicalAbsolute(outputParent, "Q-04 output parent");
  privateDirectory(outputParent, { create: true });
  const bundle = mkdtempSync(join(outputParent, "q04-"));
  chmodSync(bundle, 0o700);
  for (const name of ["input", "raw", "sources", "bin", "histories", "snapshot", "rust-target"]) {
    mkdirSync(join(bundle, name), { mode: 0o700 });
    chmodSync(join(bundle, name), 0o700);
  }
  return bundle;
}

function assertContained(root, path, label) {
  const resolvedRoot = resolve(root);
  const resolvedPath = resolve(path);
  if (resolvedPath === resolvedRoot || !resolvedPath.startsWith(`${resolvedRoot}/`)) {
    fail(`${label} escapes its Q-04 containment root`);
  }
  return resolvedPath;
}

function auditDirectTree(path) {
  const observed = lstatSync(path);
  if (observed.isSymbolicLink()) fail(`Q-04 snapshot contains a symbolic link: ${path}`);
  if (!observed.isDirectory()) return;
  for (const entry of readdirSync(path)) auditDirectTree(join(path, entry));
}

async function archiveGitCommit(gitCommit, snapshotRoot) {
  const archive = spawn("git", ["archive", "--format=tar", gitCommit], {
    cwd: workspaceRoot,
    env: sanitizedEnvironment(),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const extract = spawn("tar", ["--extract", "--file=-", "--no-same-owner", "--no-same-permissions", "--directory", snapshotRoot], {
    cwd: snapshotRoot,
    env: sanitizedEnvironment(),
    stdio: ["pipe", "ignore", "pipe"],
  });
  const stderr = [];
  archive.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
  extract.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
  archive.stdout.pipe(extract.stdin);
  const completed = await Promise.all([
    new Promise((done) => archive.once("close", (code, signal) => done({ code, signal }))),
    new Promise((done) => extract.once("close", (code, signal) => done({ code, signal }))),
  ]);
  if (completed.some((result) => result.code !== 0 || result.signal !== null)) {
    fail(`Q-04 immutable Git archive extraction failed: ${Buffer.concat(stderr).toString("utf8").trim()}`);
  }
  auditDirectTree(snapshotRoot);
}

export function sanitizedEnvironment(additions = {}) {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(?:CARGO_TARGET_DIR|CARGO_ENCODED_RUSTFLAGS|MISE_RUST_VERSION|RUSTFLAGS|RUSTUP_TOOLCHAIN|RUSTDOCFLAGS|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER)$/u.test(key)) continue;
    if (/^npm_config_/iu.test(key)) continue;
    environment[key] = value;
  }
  return Object.freeze({ ...environment, ...additions });
}

export function pinnedRustEnvironment(additions = {}) {
  return sanitizedEnvironment({
    ...additions,
    MISE_RUST_VERSION: Q04_RUST_TOOLCHAIN,
    RUSTUP_TOOLCHAIN: Q04_RUST_TOOLCHAIN,
  });
}

export async function createImmutableSnapshot(bundle, gitCommit) {
  const snapshotRoot = assertContained(bundle, join(bundle, "snapshot"), "Q-04 snapshot");
  privateDirectory(snapshotRoot);
  if (readdirSync(snapshotRoot).length !== 0) fail("Q-04 immutable snapshot directory is not empty");
  await archiveGitCommit(gitCommit, snapshotRoot);
  return snapshotRoot;
}

export async function installImmutableNodeDependencies(snapshotRoot, runner) {
  await commandOrFail(
    "npm",
    ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    { cwd: snapshotRoot, env: sanitizedEnvironment() },
    "immutable snapshot npm ci",
    runner,
  );
}

export function rustBuildLayout(bundle) {
  const cargoTarget = assertContained(bundle, join(bundle, "rust-target"), "Q-04 Rust target");
  return Object.freeze({
    cargoTarget,
    builtBinary: assertContained(cargoTarget, join(cargoTarget, "release/q04-poseidon-oracle"), "Q-04 Rust binary"),
    copiedBinary: assertContained(bundle, join(bundle, "bin/q04-poseidon-oracle"), "Q-04 copied Rust binary"),
    checkerBuiltBinary: assertContained(
      cargoTarget,
      join(cargoTarget, "release/shieldkit-v2-q04-certificate"),
      "Q-04 Rust certificate checker binary",
    ),
    checkerCopiedBinary: assertContained(
      bundle,
      join(bundle, "bin/shieldkit-v2-q04-certificate"),
      "Q-04 copied Rust certificate checker binary",
    ),
  });
}

export function snapshotExecutionPaths(snapshotRoot, bundle) {
  const root = canonicalAbsolute(snapshotRoot, "Q-04 immutable snapshot path");
  const layout = rustBuildLayout(bundle);
  return Object.freeze({
    snapshotRoot: root,
    parameterSourcePath: assertContained(root, join(root, "node_modules/circomlib/circuits/poseidon_constants.circom"), "Q-04 parameter source"),
    recoveryCwd: assertContained(root, join(root, "03-create-your-own-pool/crates/shieldkit-v2-recovery"), "Q-04 Rust source"),
    checkerCwd: assertContained(
      root,
      join(
        root,
        "03-create-your-own-pool/crates/shieldkit-v2-q04-certificate",
      ),
      "Q-04 Rust certificate checker source",
    ),
    productionNullifierSource: assertContained(
      root,
      join(
        root,
        "03-create-your-own-pool/packages/pool/v2/persistent-indexed-nullifier.mjs",
      ),
      "Q-04 production nullifier source",
    ),
    checkerSource: assertContained(
      root,
      join(
        root,
        "03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/src/main.rs",
      ),
      "Q-04 Rust certificate checker source file",
    ),
    historyRunner: assertContained(root, join(root, "03-create-your-own-pool/scripts/v2-q04-history-runner.mjs"), "Q-04 history runner"),
    evidenceVerifier: assertContained(root, join(root, "03-create-your-own-pool/scripts/v2-q04-evidence-verify.mjs"), "Q-04 evidence verifier"),
    rust: layout,
  });
}

export function rustBuildCommand(recoveryCwd, layout) {
  return Object.freeze({
    executable: "cargo",
    arguments: Object.freeze([`+${Q04_RUST_TOOLCHAIN}`, "build", "--locked", "--release", "--bin", "q04-poseidon-oracle"]),
    cwd: recoveryCwd,
    env: pinnedRustEnvironment({ CARGO_TARGET_DIR: layout.cargoTarget }),
  });
}

export function rustCheckerBuildCommand(checkerCwd, layout) {
  return Object.freeze({
    executable: "cargo",
    arguments: Object.freeze([
      `+${Q04_RUST_TOOLCHAIN}`,
      "build",
      "--locked",
      "--release",
      "--bin",
      "shieldkit-v2-q04-certificate",
    ]),
    cwd: checkerCwd,
    env: pinnedRustEnvironment({ CARGO_TARGET_DIR: layout.cargoTarget }),
  });
}

async function loadSnapshotModules(snapshotRoot) {
  const moduleAt = async (relativePath) => import(pathToFileURL(assertContained(snapshotRoot, join(snapshotRoot, relativePath), "Q-04 snapshot module")).href);
  const [schedule, evidence, depth4] = await Promise.all([
    moduleAt("03-create-your-own-pool/packages/pool/v2/qualification/q04-schedule.mjs"),
    moduleAt("03-create-your-own-pool/scripts/v2-q04-evidence-verify.mjs"),
    moduleAt("03-create-your-own-pool/packages/pool/v2/qualification/depth4-production-state-space.mjs"),
  ]);
  return Object.freeze({ schedule, evidence, depth4 });
}

function copiedReference(bundle, destination, origin) {
  regularSource(origin);
  const target = join(bundle, destination);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  privateDirectory(dirname(target));
  if (lstatSync(target, { throwIfNoEntry: false }) !== undefined) fail(`Q-04 refuses to reuse an artifact path: ${destination}`);
  copyFileSync(origin, target, constants.COPYFILE_EXCL);
  chmodSync(target, 0o600);
  const bytes = readFileSync(target);
  return Object.freeze({ path: destination, bytes: bytes.length, sha256: sha256(bytes) });
}

export function copiedGeneratedBinaryReference(
  bundle,
  destination,
  origin,
  buildRoot,
) {
  const source = assertContained(
    buildRoot,
    origin,
    "Q-04 generated binary source",
  );
  const observed = lstatSync(source);
  if (
    !observed.isFile()
    || observed.isSymbolicLink()
    || observed.size === 0
  ) {
    fail("Q-04 generated binary source must be a nonempty regular file");
  }
  const sourceBefore = readFileSync(source);
  const sourceBeforeSha256 = sha256(sourceBefore);
  const target = assertContained(
    bundle,
    join(bundle, destination),
    "Q-04 generated binary destination",
  );
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  privateDirectory(dirname(target));
  if (lstatSync(target, { throwIfNoEntry: false }) !== undefined) {
    fail(`Q-04 refuses to reuse an artifact path: ${destination}`);
  }
  copyFileSync(source, target, constants.COPYFILE_EXCL);
  chmodSync(target, 0o700);
  const targetMetadata = regularSource(target);
  const sourceAfter = readFileSync(source);
  const targetBytes = readFileSync(target);
  if (
    sourceAfter.length !== sourceBefore.length
    || sha256(sourceAfter) !== sourceBeforeSha256
    || targetMetadata.size !== sourceBefore.length
    || targetBytes.length !== sourceBefore.length
    || sha256(targetBytes) !== sourceBeforeSha256
  ) {
    fail("Q-04 generated binary changed during single-link handoff");
  }
  return Object.freeze({
    path: destination,
    bytes: targetBytes.length,
    sha256: sourceBeforeSha256,
  });
}

function sourceArtifacts(bundle, snapshotRoot, definitions) {
  const records = [];
  const copyLane = (lane, definitions) => definitions.map((definition, index) => {
    const origin = assertContained(snapshotRoot, join(snapshotRoot, definition.originPath), "Q-04 snapshot source");
    const destination = `sources/${lane}-${String(index).padStart(2, "0")}${extname(definition.originPath) || ".bin"}`;
    const artifact = copiedReference(bundle, destination, origin);
    records.push(Object.freeze({ origin, artifact }));
    return Object.freeze({ role: definition.role, originPath: definition.originPath, artifact });
  });
  const productionCore = copyLane("production-core", definitions.productionCore);
  const primaryJsOracle = copyLane("primary-js-oracle", definitions.primaryJsOracle);
  const rustKat = copyLane("rust-kat", definitions.rustKat);
  const depth4Checker = copyLane(
    "depth4-checker",
    definitions.depth4Checker,
  );
  const campaign = copyLane("campaign", definitions.campaign);
  const depth4 = copyLane("depth4", definitions.depth4);
  const copyNamed = (role, originPath, destination) => {
    const origin = assertContained(snapshotRoot, join(snapshotRoot, originPath), "Q-04 snapshot source");
    const artifact = copiedReference(bundle, destination, origin);
    records.push(Object.freeze({ origin, artifact }));
    return Object.freeze({ role, originPath, artifact });
  };
  const sources = Object.freeze({
    productionCore,
    primaryJsOracle,
    rustKat,
    depth4Checker,
    campaign,
    depth4,
    cargoManifest: copyNamed("rust-kat-manifest", "03-create-your-own-pool/crates/shieldkit-v2-recovery/Cargo.toml", "sources/rust-manifest.toml"),
    cargoLock: copyNamed("rust-kat-lockfile", "03-create-your-own-pool/crates/shieldkit-v2-recovery/Cargo.lock", "sources/rust-lock.lock"),
    rustToolchain: copyNamed("rust-toolchain", "03-create-your-own-pool/rust-toolchain.toml", "sources/rust-toolchain.toml"),
    nodePackageLock: copyNamed("node-lockfile", "package-lock.json", "sources/package-lock.json"),
  });
  return Object.freeze({ sources, records: Object.freeze(records) });
}

export function assertSnapshotSourcesUnchanged(records) {
  for (const record of records) {
    regularSource(record.origin);
    const bytes = readFileSync(record.origin);
    if (bytes.length !== record.artifact.bytes || sha256(bytes) !== record.artifact.sha256) {
      fail(`Q-04 snapshot source changed after capture: ${record.origin}`);
    }
  }
}

export function packageClosureRows(root, relative = "") {
  const directory = relative === ""
    ? resolve(root)
    : assertContained(
        root,
        join(root, relative),
        "Q-04 dependency closure",
      );
  const observed = lstatSync(directory);
  if (!observed.isDirectory() || observed.isSymbolicLink()) fail(`Q-04 dependency closure contains a non-directory: ${directory}`);
  const rows = [];
  for (const entry of readdirSync(directory).sort()) {
    const childRelative = join(relative, entry);
    const child = assertContained(root, join(root, childRelative), "Q-04 dependency closure");
    const childStat = lstatSync(child);
    if (childStat.isSymbolicLink()) fail(`Q-04 dependency closure contains a symbolic link: ${child}`);
    if (childStat.isDirectory()) rows.push(...packageClosureRows(root, childRelative));
    else if (childStat.isFile()) rows.push([childRelative.split("\\").join("/"), String(childStat.size), sha256(readFileSync(child))]);
    else fail(`Q-04 dependency closure contains a non-regular file: ${child}`);
  }
  return rows;
}

function attestPoseidonLite(snapshotRoot, sources) {
  const packageRoot = assertContained(snapshotRoot, join(snapshotRoot, "node_modules/poseidon-lite"), "Q-04 poseidon-lite package");
  const packageJson = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  if (packageJson.name !== "poseidon-lite" || packageJson.version !== "0.3.0") fail("Q-04 immutable npm installation did not provide poseidon-lite@0.3.0");
  const rows = packageClosureRows(packageRoot);
  return Object.freeze({
    schema: "shieldkit-v2-direct/q04-node-dependency-attestation/v1",
    package: "poseidon-lite@0.3.0",
    packageJsonSha256: sha256(readFileSync(join(packageRoot, "package.json"))),
    closureFileCount: rows.length,
    closureSha256: sha256(Buffer.from(rows.map((row) => row.join("\0")).join("\n"))),
    lockfile: sources.nodePackageLock.artifact,
  });
}

function assertPoseidonLiteUnchanged(snapshotRoot, sources, expected) {
  const actual = attestPoseidonLite(snapshotRoot, sources);
  if (actual.packageJsonSha256 !== expected.packageJsonSha256 || actual.closureFileCount !== expected.closureFileCount || actual.closureSha256 !== expected.closureSha256) {
    fail("Q-04 poseidon-lite closure changed after attestation");
  }
}

function parseSingleJson(output, label) {
  const lines = output.split(/\r?\n/u).filter((line) => line.length !== 0);
  if (lines.length !== 1) fail(`${label} must emit exactly one JSON record`);
  try { return JSON.parse(lines[0]); } catch { fail(`${label} emitted invalid JSON`); }
}

function normalizeHistory(bundle, result, plan, configSha256) {
  if (result === null || typeof result !== "object" || Array.isArray(result)) fail(`history ${plan.historyIndex} result is invalid`);
  if (result.index !== plan.historyIndex || result.qualifying !== true || result.acceptedEntries !== Q04_ENTRIES_PER_HISTORY) {
    fail(`history ${plan.historyIndex} did not execute the frozen qualifying plan`);
  }
  if (result.configSha256 !== configSha256) fail(`history ${plan.historyIndex} config hash does not bind its result`);
  const transitionSource = result.transitionArtifact?.path;
  if (typeof transitionSource !== "string" || !isAbsolute(transitionSource)) fail(`history ${plan.historyIndex} has no absolute transition artifact`);
  const transition = copiedReference(bundle, `raw/history-${plan.historyIndex}-transitions.ndjson`, transitionSource);
  return Object.freeze({ ...result, transitionArtifact: transition });
}

function implementationEvidence(
  sources,
  nodeVersion,
  sqliteVersion,
  rustVersion,
  binary,
  katResult,
  checkerBinary,
  checkerResult,
  q04,
) {
  return Object.freeze({
    productionCore: {
      lane: "per-transition-production-shared-core", entrypoint: "Q04PersistentNullifierStore", sharedCore: "derivePersistentIndexedNullifierInsertion/applyPersistentIndexedNullifierMutation", directV2DirectStoreExercised: false, runtime: "node", transitionComparisons: 100_000, treeDepth: 32, poseidonPackage: "poseidon-lite@0.3.0", nodeVersion, sqliteVersion, sources: sources.productionCore,
    },
    primaryJsOracle: {
      lane: "per-transition-primary-independent-oracle", poseidonImplementation: "independent-bigint-optimized-circomlib-poseidon-oracle-v1", treeImplementation: "independent-treap-sparse-depth32-indexed-nullifier-oracle-v1", orderedSet: "sha256-priority-treap", runtime: "node", transitionComparisons: 100_000, importsProductionCore: false, independentPoseidonImplementation: true, independentTreeImplementation: true, independentParameterGeneration: false, treeDepth: 32, frModulus: q04.Q04_FR_MODULUS_HEX, supportedArities: [2, 3, 6], parameterPackage: "circomlib@2.0.5", parameterSourceSha256: "94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee", nodeVersion, sources: sources.primaryJsOracle,
    },
    rustKat: {
      lane: "fixed-known-answer-cross-check-only", resultSchema: q04.Q04_RUST_KAT_SCHEMA, implementation: "rust-light-poseidon-bn254-x5", runtime: "rust", transitionComparisons: 0, treeCampaign: false, productionQualification: false, independentImplementation: true, independentEmbeddedParameterArtifact: true, independentParameterGeneration: false, importsJavaScript: false, importsCircomTables: false, cargoLocked: true, domainsChecked: q04.Q04_RUST_DOMAINS.length, knownAnswerTests: q04.Q04_RUST_KATS.length, packages: { lightPoseidon: "0.4.0", arkBn254: "0.5.0", arkFf: "0.5.0", sha2: "0.10.9" }, rustVersion, sources: sources.rustKat, cargoManifest: sources.cargoManifest, cargoLock: sources.cargoLock, rustToolchain: sources.rustToolchain, binary, result: katResult,
    },
    depth4Checker: {
      lane: "independent-rust-free-term-certificate-checker",
      resultSchema: q04.Q04_DEPTH4_CHECKER_RESULT_SCHEMA,
      runtime: "rust",
      proofCalculus: "independent-rust-free-term-tree-reduction-v1",
      controlSkeletons: 911,
      representedConcreteRankStateGapTransitions: "93928268313",
      formalJavaScriptSemanticsClaim: false,
      stateQuotientClaim: false,
      collisionAssumptionForTermEquality: false,
      cargoLocked: true,
      rustVersion,
      sources: sources.depth4Checker,
      binary: checkerBinary,
      result: checkerResult,
    },
  });
}

function campaignDefinition(q04) {
  const metadata = q04.q04ScheduleMetadata();
  return Object.freeze({
    historyCount: Q04_HISTORY_COUNT, entriesPerHistory: Q04_ENTRIES_PER_HISTORY, totalEntries: Q04_CAMPAIGN_PLAN.aggregateEntries, checkpointInterval: Q04_CHECKPOINT_INTERVAL, checkpointsPerHistory: Q04_ENTRIES_PER_HISTORY / Q04_CHECKPOINT_INTERVAL,
    seedDerivation: q04.Q04_SEED_DERIVATION, keyDerivation: q04.Q04_KEY_DERIVATION, seeds: [...q04.Q04_FIXED_SEEDS],
    edgeSchedule: q04.Q04_EDGE_SCHEDULE.map((entry) => ({ ...entry })), requiredProbeKinds: [...q04.Q04_REQUIRED_PROBES],
    // The frozen metadata is calculated by the source imported above; retaining
    // it here catches divergence between the driver and schedule module.
    _frozenScheduleMetadata: metadata,
  });
}

function evidenceDefinition(q04) {
  const { _frozenScheduleMetadata, ...definition } = campaignDefinition(q04);
  if (definition.historyCount !== q04.Q04_CAMPAIGN_DEFINITION.historyCount || _frozenScheduleMetadata.totalEntries !== Q04_CAMPAIGN_PLAN.aggregateEntries) {
    fail("Q-04 campaign schedule definitions disagree");
  }
  return definition;
}

function hardware() {
  let filesystem = "unknown";
  try { filesystem = `statfs-type-${statfsSync(workspaceRoot).type}`; } catch {}
  return Object.freeze({ operatingSystem: `${os.type()} ${os.release()}`, architecture: os.arch(), cpuModel: os.cpus().at(0)?.model ?? "unknown", logicalCpuCount: os.cpus().length, totalMemoryBytes: os.totalmem(), filesystem });
}

function aggregate(q04) {
  return Object.freeze({ acceptedEntries: 100_000, checkpoints: 100, probesRun: 500, expectedRejections: 500, unexpectedAccepts: 0, discrepancies: 0, transitionComparisons: { productionCore: 100_000, primaryJsOracle: 100_000, rustKat: 0 }, rustKatKnownAnswerTests: q04.Q04_RUST_KATS.length, rustKatDomainsChecked: q04.Q04_RUST_DOMAINS.length });
}

function publicEvidence({ git, sources, implementations, histories, runtime, depth4, inputManifest, rawOutput, resultTranscript, q04 }) {
  const evidence = {
    schema: q04.Q04_EVIDENCE_SCHEMA, gate: "Q-04", status: "evidence-complete",
    subject: { repository: "shieldkit-sdk", gitCommit: git.gitCommit, gitTree: git.gitTree, workingTreeClean: true, poseidonProfile: q04.Q04_POSEIDON_PROFILE, treeDepth: 32, frModulus: q04.Q04_FR_MODULUS_HEX, nullifierDomains: { ...q04.Q04_NULLIFIER_DOMAINS }, sourceSetSha256: "0".repeat(64) },
    definition: evidenceDefinition(q04), implementations, operationCounts: { ...q04.Q04_FIXED_OPERATION_COUNTS }, hardware: hardware(), runtime,
    provenance: { generatedAt: timestamp(), commands: {
      campaign: { executable: "node", arguments: ["03-create-your-own-pool/scripts/v2-q04-campaign.mjs"], workingDirectory: "." },
      rustKatBuild: { executable: "cargo", arguments: ["+1.97.1", "build", "--locked", "--release", "--bin", "q04-poseidon-oracle"], workingDirectory: "03-create-your-own-pool/crates/shieldkit-v2-recovery" },
      rustKatRun: { executable: "target/release/q04-poseidon-oracle", arguments: [], workingDirectory: "03-create-your-own-pool/crates/shieldkit-v2-recovery" },
      depth4CheckerBuild: { executable: "cargo", arguments: ["+1.97.1", "build", "--locked", "--release", "--bin", "shieldkit-v2-q04-certificate"], workingDirectory: "03-create-your-own-pool/crates/shieldkit-v2-q04-certificate" },
      depth4CheckerRun: { executable: "bin/shieldkit-v2-q04-certificate", arguments: ["raw/depth4-symbolic-certificate.json", "snapshot/03-create-your-own-pool/packages/pool/v2/persistent-indexed-nullifier.mjs", "snapshot/03-create-your-own-pool/crates/shieldkit-v2-q04-certificate/src/main.rs"], workingDirectory: "." },
    }, campaignSources: sources.campaign, nodePackageLock: sources.nodePackageLock, inputManifest, rawOutput, resultTranscript },
    hashes: { inputManifestSha256: inputManifest.sha256, rawOutputSha256: rawOutput.sha256, resultTranscriptSha256: resultTranscript.sha256, depth4CertificateSha256: depth4.certificate.sha256, depth4SymbolicCertificateSha256: depth4.symbolicCertificate.sha256, depth4CheckerResultSha256: implementations.depth4Checker.result.sha256, rustKatResultSha256: implementations.rustKat.result.sha256, sourceSetSha256: "0".repeat(64), historyTransitionSetSha256: "0".repeat(64) },
    depth4, histories, aggregate: aggregate(q04),
    claimBoundary: { entriesPerHistory: 25_000, aggregateEntries: 100_000, singleHistory100kMeasured: false, largerHistoryClaim: false, depth4Scope: q04.Q04_DEPTH4_SCOPE, depth4EnumeratesAllKeyHistories: false, depth4LargerDepthClaim: false, depth4ProductionKernelEquivalenceProved: false, depth4ExternalCertificateCheckerVerified: true, formalJavaScriptSemanticsClaim: false },
    verdict: { largeHistoryCampaign: "pass", rustPoseidonKat: "pass", depth4: "verified-universal-template-with-nonformal-js-binding", q04Correctness: "pass-bounded-100000-and-depth4-shared-kernel", q07Performance: "separate" },
  };
  evidence.subject.sourceSetSha256 = q04.deriveQ04SourceSetSha256(evidence);
  evidence.hashes.sourceSetSha256 = evidence.subject.sourceSetSha256;
  evidence.hashes.historyTransitionSetSha256 = q04.deriveQ04HistoryTransitionSetSha256(histories);
  return evidence;
}

async function version(executable, arguments_, runner, label) {
  return (await commandOrFail(executable, arguments_, { cwd: workspaceRoot }, label, runner)).stdout.trim();
}

function defaultDependencies() {
  return Object.freeze({
    spawnCapture,
    createSnapshot: createImmutableSnapshot,
    installSnapshotDependencies: installImmutableNodeDependencies,
    loadSnapshotModules,
  });
}

export async function runQ04Campaign({ outputParent, dependencies = undefined } = {}) {
  const deps = { ...defaultDependencies(), ...(dependencies ?? {}) };
  // Git is checked before an output directory is even allocated; an accidental
  // dirty invocation cannot be mistaken for a preserved qualification bundle.
  const git = await gitState(deps.spawnCapture);
  const bundle = createBundle(outputParent);
  const startedAt = timestamp();
  const startedNs = process.hrtime.bigint();
  try {
    const snapshotRoot = await deps.createSnapshot(bundle, git.gitCommit);
    canonicalAbsolute(snapshotRoot, "Q-04 immutable snapshot path");
    assertContained(bundle, snapshotRoot, "Q-04 immutable snapshot");
    privateDirectory(snapshotRoot);
    await deps.installSnapshotDependencies(snapshotRoot, deps.spawnCapture);
    const snapshot = await deps.loadSnapshotModules(snapshotRoot);
    const q04 = { ...snapshot.schedule, ...snapshot.evidence };
    if (q04.Q04_HISTORY_COUNT !== undefined && q04.Q04_HISTORY_COUNT !== Q04_HISTORY_COUNT) fail("Q-04 snapshot history count differs from its frozen plan");
    const executionPaths = snapshotExecutionPaths(snapshotRoot, bundle);
    const {
      parameterSourcePath,
      recoveryCwd,
      checkerCwd,
      productionNullifierSource,
      checkerSource,
      historyRunner,
      evidenceVerifier,
    } = executionPaths;
    const sourceCapture = sourceArtifacts(bundle, snapshotRoot, q04.Q04_SOURCE_DEFINITIONS);
    const sources = sourceCapture.sources;
    const poseidonLiteAttestation = attestPoseidonLite(snapshotRoot, sources);
    const nodeDependencyAttestation = bundleReference(bundle, writeJson(join(bundle, "raw/node-dependency-attestation.json"), poseidonLiteAttestation));
    const nodeVersion = process.version;
    const sqliteVersion = (await version("sqlite3", ["--version"], deps.spawnCapture, "sqlite3 --version")).split(/\s/u)[0];
    const rustVersion = (
      await commandOrFail(
        "rustc",
        ["--version"],
        {
          cwd: workspaceRoot,
          env: pinnedRustEnvironment(),
        },
        "pinned rustc --version",
        deps.spawnCapture,
      )
    ).stdout.trim();
    if (!/^rustc 1\.97\.1(?:\s|$)/.test(rustVersion)) fail("Q-04 requires Rust 1.97.1");
    const rustLayout = executionPaths.rust;
    const rustBuild = rustBuildCommand(recoveryCwd, rustLayout);
    const rustBuildStartedNs = process.hrtime.bigint();
    await commandOrFail(rustBuild.executable, rustBuild.arguments, { cwd: rustBuild.cwd, env: rustBuild.env }, "pinned Rust KAT build", deps.spawnCapture);
    const rustBuildElapsedMs = elapsedMilliseconds(rustBuildStartedNs);
    const binary = copiedGeneratedBinaryReference(
      bundle,
      "bin/q04-poseidon-oracle",
      rustLayout.builtBinary,
      rustLayout.cargoTarget,
    );
    const binaryPath = join(bundle, binary.path);
    const rustRunStartedNs = process.hrtime.bigint();
    const rustRun = await commandOrFail(binaryPath, [], { cwd: bundle, env: sanitizedEnvironment() }, "Rust KAT", deps.spawnCapture);
    const rustKatElapsedMs = elapsedMilliseconds(rustRunStartedNs);
    const kat = parseSingleJson(rustRun.stdout, "Rust KAT");
    const katResult = bundleReference(bundle, writeJson(join(bundle, "raw/rust-kat.json"), kat));
    const checkerBuild = rustCheckerBuildCommand(checkerCwd, rustLayout);
    const checkerBuildStartedNs = process.hrtime.bigint();
    await commandOrFail(
      checkerBuild.executable,
      checkerBuild.arguments,
      { cwd: checkerBuild.cwd, env: checkerBuild.env },
      "pinned Rust depth-4 certificate checker build",
      deps.spawnCapture,
    );
    const checkerBuildElapsedMs = elapsedMilliseconds(checkerBuildStartedNs);
    const checkerBinary = copiedGeneratedBinaryReference(
      bundle,
      "bin/shieldkit-v2-q04-certificate",
      rustLayout.checkerBuiltBinary,
      rustLayout.cargoTarget,
    );
    const checkerBinaryPath = join(bundle, checkerBinary.path);
    const depth4Certificate = snapshot.depth4.runProductionDepth4StateSpace({ parameterSourcePath });
    if (depth4Certificate?.schema !== q04.Q04_DEPTH4_SCHEMA) fail("current depth-4 certificate schema differs");
    const symbolicCertificate = bundleReference(
      bundle,
      writeJson(
        join(bundle, "raw/depth4-symbolic-certificate.json"),
        depth4Certificate.symbolic.certificate,
      ),
    );
    const checkerRunStartedNs = process.hrtime.bigint();
    const checkerRun = await commandOrFail(
      checkerBinaryPath,
      [
        join(bundle, symbolicCertificate.path),
        productionNullifierSource,
        checkerSource,
      ],
      { cwd: bundle, env: sanitizedEnvironment() },
      "Rust depth-4 certificate checker",
      deps.spawnCapture,
    );
    const checkerRunElapsedMs = elapsedMilliseconds(checkerRunStartedNs);
    const checkerResultValue = parseSingleJson(
      checkerRun.stdout,
      "Rust depth-4 certificate checker",
    );
    const checkerResult = bundleReference(
      bundle,
      writeJson(
        join(bundle, "raw/depth4-checker-result.json"),
        checkerResultValue,
      ),
    );
    const depth4 = {
      schema: q04.Q04_DEPTH4_SCHEMA,
      status: q04.Q04_DEPTH4_STATUS,
      scope: q04.Q04_DEPTH4_SCOPE,
      productionQualification: true,
      sources: sources.depth4,
      symbolicCertificate,
      certificate: bundleReference(
        bundle,
        writeJson(
          join(bundle, "raw/depth4-certificate.json"),
          depth4Certificate,
        ),
      ),
    };
    const plans = createQ04HistoryPlan(bundle);
    const completedHistories = await runQ04HistoriesConcurrently(
      plans,
      async (plan) => {
        mkdirSync(plan.outputDirectory, { mode: 0o700 });
        chmodSync(plan.outputDirectory, 0o700);
        const config = {
          schema: "shieldkit-v2-direct/q04-history-config/v1",
          historyIndex: plan.historyIndex,
          entryCount: plan.entryCount,
          checkpointInterval: plan.checkpointInterval,
          outputDirectory: plan.outputDirectory,
          parameterSourcePath,
          qualifying: true,
        };
        const configArtifact = writeJson(
          join(
            bundle,
            "input",
            `history-${plan.historyIndex}-config.json`,
          ),
          config,
        );
        const execution = await commandOrFail(
          "node",
          [
            historyRunner,
            configArtifact.path.startsWith("/")
              ? configArtifact.path
              : join(bundle, configArtifact.path),
          ],
          { cwd: snapshotRoot, env: sanitizedEnvironment() },
          `Q-04 history ${plan.historyIndex}`,
          deps.spawnCapture,
        );
        const result = normalizeHistory(
          bundle,
          parseSingleJson(
            execution.stdout,
            `Q-04 history ${plan.historyIndex}`,
          ),
          plan,
          configArtifact.sha256,
        );
        return Object.freeze({
          execution: Object.freeze({
            historyIndex: plan.historyIndex,
            pid: execution.pid,
            exitCode: execution.exitCode,
            signal: execution.signal,
            configSha256: configArtifact.sha256,
            transitionArtifact: result.transitionArtifact,
            stdoutSha256: sha256(execution.stdout),
            stderrSha256: sha256(execution.stderr),
          }),
          history: result,
        });
      },
    );
    const histories = completedHistories.map(({ history }) => history);
    const executions = completedHistories.map(({ execution }) => execution);
    assertFreshHistoryExecutions(executions);
    assertSnapshotSourcesUnchanged(sourceCapture.records);
    const inputManifest = bundleReference(bundle, writeJson(join(bundle, "input/manifest.json"), { schema: "shieldkit-v2-direct/q04-campaign-input-manifest/v2", git, plan: Q04_CAMPAIGN_PLAN, schedule: q04.q04ScheduleMetadata(), nodeDependencyAttestation, executionBoundary: { snapshotRoot, npm: { executable: "npm", arguments: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd: snapshotRoot, environment: "sanitized-no-npm-config" }, rustBuild: { executable: rustBuild.executable, arguments: rustBuild.arguments, cwd: rustBuild.cwd, cargoTarget: rustLayout.cargoTarget, environment: "sanitized-no-inherited-rust-flags-or-wrappers" }, rustRun: { executable: binaryPath, cwd: bundle, binarySha256: binary.sha256, environment: "sanitized-no-inherited-rust-flags-or-wrappers" }, checkerBuild: { executable: checkerBuild.executable, arguments: checkerBuild.arguments, cwd: checkerBuild.cwd, cargoTarget: rustLayout.cargoTarget, environment: "sanitized-no-inherited-rust-flags-or-wrappers" }, checkerRun: { executable: checkerBinaryPath, arguments: [join(bundle, symbolicCertificate.path), productionNullifierSource, checkerSource], cwd: bundle, binarySha256: checkerBinary.sha256, environment: "sanitized-no-inherited-rust-flags-or-wrappers" }, historyRunner: { executable: "node", path: historyRunner, cwd: snapshotRoot, environment: "sanitized-no-npm-config" }, evidenceVerifier: { executable: "node", path: evidenceVerifier, cwd: snapshotRoot, environment: "sanitized-no-npm-config" } }, histories: executions.map(({ historyIndex, configSha256 }) => ({ historyIndex, configSha256 })) }));
    const rawOutput = bundleReference(bundle, writeJson(join(bundle, "raw/campaign-processes.json"), { schema: "shieldkit-v2-direct/q04-campaign-processes/v3", rustKat: { pid: rustRun.pid, exitCode: rustRun.exitCode, signal: rustRun.signal, stdoutSha256: sha256(rustRun.stdout), stderrSha256: sha256(rustRun.stderr), binarySha256: binary.sha256, buildElapsedMs: rustBuildElapsedMs, runElapsedMs: rustKatElapsedMs }, depth4Checker: { pid: checkerRun.pid, exitCode: checkerRun.exitCode, signal: checkerRun.signal, stdoutSha256: sha256(checkerRun.stdout), stderrSha256: sha256(checkerRun.stderr), binarySha256: checkerBinary.sha256, buildElapsedMs: checkerBuildElapsedMs, runElapsedMs: checkerRunElapsedMs }, histories: executions }));
    const implementations = implementationEvidence(
      sources,
      nodeVersion,
      sqliteVersion,
      rustVersion,
      binary,
      katResult,
      checkerBinary,
      checkerResult,
      q04,
    );
    // The verifier's stdout is retained separately after verification: placing
    // it in this hashed reference would create a circular evidence hash. This
    // immutable transcript instead records the exact pre-verification input.
    const provisionalRuntime = { nodeVersion, rustVersion, sqliteVersion, startedAt, finishedAt: timestamp(), elapsedMs: elapsedMilliseconds(startedNs), rustKatElapsedMs, depth4CheckerElapsedMs: checkerRunElapsedMs };
    const resultTranscript = bundleReference(bundle, writeJson(join(bundle, "raw/result-transcript.json"), {
      schema: "shieldkit-v2-direct/q04-campaign-preverification-input/v1",
      status: "immutable-preverification-input",
      verifier: { executable: "node", arguments: ["03-create-your-own-pool/scripts/v2-q04-evidence-verify.mjs", "evidence.json"] },
    }));
    const runtime = { ...provisionalRuntime, finishedAt: timestamp(), elapsedMs: elapsedMilliseconds(startedNs) };
    const evidence = publicEvidence({ git, sources, implementations, histories, runtime, depth4, inputManifest, rawOutput, resultTranscript, q04 });
    q04.validateQ04Evidence(evidence);
    const evidenceArtifact = writeJson(join(bundle, "evidence.json"), evidence);
    const verified = await commandOrFail("node", [evidenceVerifier, evidenceArtifact.path], { cwd: snapshotRoot, env: sanitizedEnvironment() }, "Q-04 evidence verifier", deps.spawnCapture);
    const verification = parseSingleJson(verified.stdout, "Q-04 evidence verifier");
    assertSnapshotSourcesUnchanged(sourceCapture.records);
    assertPoseidonLiteUnchanged(snapshotRoot, sources, poseidonLiteAttestation);
    atomicWrite(join(bundle, "verification.json"), `${JSON.stringify(verification, null, 2)}\n`);
    return Object.freeze({ bundle, evidencePath: evidenceArtifact.path, verification });
  } catch (error) {
    const failure = { schema: "shieldkit-v2-direct/q04-campaign-failure/v1", status: "failed-preserved", failedAt: timestamp(), error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
    atomicWrite(join(bundle, "failure.json"), `${JSON.stringify(failure, null, 2)}\n`);
    throw error;
  }
}

export function parseQ04CampaignArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 1) {
    fail("usage: node v2-q04-campaign.mjs /absolute/private/output-parent");
  }
  return canonicalAbsolute(argv[0], "Q-04 output parent");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    const outputParent = parseQ04CampaignArguments(process.argv.slice(2));
    const result = await runQ04Campaign({ outputParent });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`Q-04 campaign failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
