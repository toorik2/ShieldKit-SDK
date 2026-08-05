import assert from "node:assert/strict";
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  Q04_CAMPAIGN_PLAN,
  V2Q04CampaignError,
  assertFreshHistoryExecutions,
  assertSnapshotSourcesUnchanged,
  createQ04HistoryPlan,
  copiedGeneratedBinaryReference,
  elapsedMilliseconds,
  installImmutableNodeDependencies,
  packageClosureRows,
  parseQ04CampaignArguments,
  pinnedRustEnvironment,
  rustBuildLayout,
  rustBuildCommand,
  rustCheckerBuildCommand,
  runQ04Campaign,
  runQ04HistoriesConcurrently,
  sanitizedEnvironment,
} from "./v2-q04-campaign.mjs";

test("Q-04 campaign plan is immutable and exactly four fresh 25k histories", () => {
  assert.ok(Object.isFrozen(Q04_CAMPAIGN_PLAN));
  assert.deepEqual(Q04_CAMPAIGN_PLAN, {
    histories: 4,
    entriesPerHistory: 25_000,
    checkpointInterval: 1_000,
    aggregateEntries: 100_000,
    aggregateProbes: 500,
  });
  const plans = createQ04HistoryPlan(join(tmpdir(), "q04-campaign-plan"));
  assert.equal(plans.length, 4);
  assert.ok(Object.isFrozen(plans));
  assert.ok(plans.every((plan, index) =>
    plan.historyIndex === index &&
    plan.entryCount === 25_000 &&
    plan.checkpointInterval === 1_000 &&
    plan.outputDirectory.endsWith(`/history-${index}`)
  ));
  assert.throws(() => { Q04_CAMPAIGN_PLAN.histories = 1; }, TypeError);
});

test("Q-04 CLI has no test or reduced-campaign arguments", () => {
  assert.throws(
    () => parseQ04CampaignArguments([]),
    V2Q04CampaignError,
  );
  assert.throws(
    () => parseQ04CampaignArguments([join(tmpdir(), "q04"), "--test"]),
    /usage/u,
  );
  assert.throws(
    () => parseQ04CampaignArguments(["relative"]),
    /absolute normalized/u,
  );
});

test("Q-04 binds exactly four distinct fresh history process identities", () => {
  assert.doesNotThrow(() => assertFreshHistoryExecutions([
    { historyIndex: 0, pid: 101 },
    { historyIndex: 1, pid: 102 },
    { historyIndex: 2, pid: 103 },
    { historyIndex: 3, pid: 104 },
  ]));
  assert.throws(() => assertFreshHistoryExecutions([
    { historyIndex: 0, pid: 101 },
    { historyIndex: 1, pid: 101 },
    { historyIndex: 2, pid: 103 },
    { historyIndex: 3, pid: 104 },
  ]), /fresh processes/u);
});

test("Q-04 launches all four independent histories before awaiting completion", async () => {
  const plans = createQ04HistoryPlan(join(tmpdir(), "q04-concurrent-plan"));
  const started = [];
  let release;
  const barrier = new Promise((resolve) => {
    release = resolve;
  });
  const completion = runQ04HistoriesConcurrently(plans, async (plan) => {
    started.push(plan.historyIndex);
    await barrier;
    return plan.historyIndex;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(started, [0, 1, 2, 3]);
  release();
  assert.deepEqual(await completion, [0, 1, 2, 3]);
});

test("Q-04 scrubs inherited build/package controls and pins npm to the snapshot cwd", async (t) => {
  const snapshot = mkdtempSync(join(tmpdir(), "q04-campaign-snapshot-"));
  t.after(() => rmSync(snapshot, { recursive: true, force: true }));
  const environment = sanitizedEnvironment({ CARGO_TARGET_DIR: "/private/q04-target" });
  assert.equal(environment.CARGO_TARGET_DIR, "/private/q04-target");
  assert.equal(environment.RUSTFLAGS, undefined);
  assert.equal(environment.RUSTC_WRAPPER, undefined);
  assert.equal(environment.npm_config_userconfig, undefined);
  const rustEnvironment = pinnedRustEnvironment();
  assert.equal(rustEnvironment.MISE_RUST_VERSION, "1.97.1");
  assert.equal(rustEnvironment.RUSTUP_TOOLCHAIN, "1.97.1");
  const calls = [];
  await installImmutableNodeDependencies(snapshot, async (executable, arguments_, options) => {
    calls.push({ executable, arguments_, options });
    return { pid: 11, exitCode: 0, signal: null, stdout: "", stderr: "" };
  });
  assert.deepEqual(calls[0].executable, "npm");
  assert.deepEqual(calls[0].arguments_, ["ci", "--ignore-scripts", "--no-audit", "--no-fund"]);
  assert.equal(calls[0].options.cwd, snapshot);
  assert.equal(calls[0].options.env.CARGO_TARGET_DIR, undefined);
});

test("Q-04 detects source mutation after its snapshot evidence capture", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "q04-campaign-source-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const source = join(directory, "captured.mjs");
  const before = Buffer.from("export const stable = true;\n");
  writeFileSync(source, before, { mode: 0o600 });
  const record = { origin: source, artifact: { bytes: before.length, sha256: createHash("sha256").update(before).digest("hex") } };
  assert.doesNotThrow(() => assertSnapshotSourcesUnchanged([record]));
  writeFileSync(source, "export const stable = false;\n", { mode: 0o600 });
  assert.throws(() => assertSnapshotSourcesUnchanged([record]), /source changed after capture/u);
});

test("Q-04 dependency attestation walks its package root and rejects links", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "q04-dependency-closure-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(join(directory, "nested"));
  writeFileSync(join(directory, "package.json"), "{}\n");
  writeFileSync(join(directory, "nested", "index.js"), "export {};\n");
  assert.deepEqual(
    packageClosureRows(directory).map(([path, size]) => [path, size]),
    [
      ["nested/index.js", "11"],
      ["package.json", "3"],
    ],
  );
  symlinkSync(join(directory, "nested"), join(directory, "linked"));
  assert.throws(
    () => packageClosureRows(directory),
    /contains a symbolic link/u,
  );
});

test("Q-04 records elapsed time from monotonic measurements, never a placeholder", () => {
  assert.equal(elapsedMilliseconds(100n, 100n), 1);
  assert.equal(elapsedMilliseconds(1_000_000n, 3_000_001n), 3);
  assert.throws(() => elapsedMilliseconds(2n, 1n), /monotonic duration bounds/u);
});

test("Q-04 Rust layout cannot select a checkout-stale binary", (t) => {
  const bundle = mkdtempSync(join(tmpdir(), "q04-campaign-rust-layout-"));
  t.after(() => rmSync(bundle, { recursive: true, force: true }));
  const layout = rustBuildLayout(bundle);
  assert.equal(layout.cargoTarget, join(bundle, "rust-target"));
  assert.equal(layout.builtBinary, join(bundle, "rust-target/release/q04-poseidon-oracle"));
  assert.equal(layout.copiedBinary, join(bundle, "bin/q04-poseidon-oracle"));
  assert.equal(
    layout.checkerBuiltBinary,
    join(bundle, "rust-target/release/shieldkit-v2-q04-certificate"),
  );
  assert.equal(
    layout.checkerCopiedBinary,
    join(bundle, "bin/shieldkit-v2-q04-certificate"),
  );
  assert.ok(!layout.builtBinary.includes("shieldkit-v2-recovery/target"));
  const command = rustBuildCommand("/immutable/snapshot/shieldkit-groth/crates/shieldkit-v2-recovery", layout);
  assert.equal(command.cwd, "/immutable/snapshot/shieldkit-groth/crates/shieldkit-v2-recovery");
  assert.equal(command.env.CARGO_TARGET_DIR, layout.cargoTarget);
  assert.equal(command.env.MISE_RUST_VERSION, "1.97.1");
  assert.equal(command.env.RUSTUP_TOOLCHAIN, "1.97.1");
  assert.equal(command.env.RUSTFLAGS, undefined);
  assert.deepEqual(command.arguments, ["+1.97.1", "build", "--locked", "--release", "--bin", "q04-poseidon-oracle"]);
  const checkerCommand = rustCheckerBuildCommand(
    "/immutable/snapshot/shieldkit-groth/crates/shieldkit-v2-q04-certificate",
    layout,
  );
  assert.equal(
    checkerCommand.cwd,
    "/immutable/snapshot/shieldkit-groth/crates/shieldkit-v2-q04-certificate",
  );
  assert.equal(checkerCommand.env.CARGO_TARGET_DIR, layout.cargoTarget);
  assert.equal(checkerCommand.env.MISE_RUST_VERSION, "1.97.1");
  assert.equal(checkerCommand.env.RUSTUP_TOOLCHAIN, "1.97.1");
  assert.deepEqual(checkerCommand.arguments, [
    "+1.97.1",
    "build",
    "--locked",
    "--release",
    "--bin",
    "shieldkit-v2-q04-certificate",
  ]);
});

test("Q-04 detaches Cargo hard-linked binaries before execution", (t) => {
  const bundle = mkdtempSync(join(tmpdir(), "q04-binary-handoff-"));
  t.after(() => rmSync(bundle, { recursive: true, force: true }));
  const rustTarget = join(bundle, "rust-target");
  mkdirSync(join(rustTarget, "release", "deps"), { recursive: true });
  const origin = join(rustTarget, "release", "qualifier");
  const cargoLink = join(rustTarget, "release", "deps", "qualifier-copy");
  writeFileSync(origin, "qualified-binary");
  linkSync(origin, cargoLink);
  assert.equal(lstatSync(origin).nlink, 2);
  const artifact = copiedGeneratedBinaryReference(
    bundle,
    "bin/qualifier",
    origin,
    rustTarget,
  );
  const detached = join(bundle, artifact.path);
  assert.equal(lstatSync(detached).nlink, 1);
  assert.equal(lstatSync(detached).mode & 0o777, 0o700);
  assert.equal(readFileSync(detached, "utf8"), "qualified-binary");
  writeFileSync(cargoLink, "mutated-hard-link");
  assert.equal(readFileSync(detached, "utf8"), "qualified-binary");
});

test("Q-04 rejects a dirty tree before allocating a bundle", async (t) => {
  const parent = mkdtempSync(join(tmpdir(), "q04-campaign-dirty-"));
  chmodSync(parent, 0o700);
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  let calls = 0;
  const spawnCapture = async (_executable, arguments_) => {
    calls += 1;
    if (arguments_[0] === "status") return { pid: 3, exitCode: 0, signal: null, stdout: " M tracked-file\n", stderr: "" };
    return { pid: calls, exitCode: 0, signal: null, stdout: "d162a105433a4d42d6070652894a4b39f35ab420\n", stderr: "" };
  };
  await assert.rejects(
    runQ04Campaign({ outputParent: parent, dependencies: { spawnCapture } }),
    /dirty Git worktree/u,
  );
  assert.deepEqual(readdirSync(parent), []);
});

test("Q-04 preserves a private failed bundle without retries or cleanup", async (t) => {
  const parent = mkdtempSync(join(tmpdir(), "q04-campaign-failure-"));
  chmodSync(parent, 0o700);
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  let npmCalls = 0;
  const spawnCapture = async (executable, arguments_) => {
    if (executable === "git" && arguments_[0] === "status") return { pid: 3, exitCode: 0, signal: null, stdout: "", stderr: "" };
    if (executable === "git" && arguments_[1] === "HEAD^{commit}") return { pid: 1, exitCode: 0, signal: null, stdout: "d162a105433a4d42d6070652894a4b39f35ab420\n", stderr: "" };
    if (executable === "git") return { pid: 2, exitCode: 0, signal: null, stdout: "141c03a5e8a384302de669d7328089c287a40513\n", stderr: "" };
    throw new Error(`unexpected command ${executable}`);
  };
  await assert.rejects(runQ04Campaign({ outputParent: parent, dependencies: {
    spawnCapture,
    createSnapshot: async (bundle) => join(bundle, "snapshot"),
    installSnapshotDependencies: async () => { npmCalls += 1; throw new V2Q04CampaignError("immutable snapshot npm ci failed: intentional test failure"); },
  } }), /immutable snapshot npm ci failed/u);
  assert.equal(npmCalls, 1, "campaign must not retry a failed qualifying command");
  const bundles = readdirSync(parent);
  assert.equal(bundles.length, 1);
  const bundle = join(parent, bundles[0]);
  assert.equal(lstatSync(bundle).mode & 0o777, 0o700);
  const failure = JSON.parse(readFileSync(join(bundle, "failure.json")));
  assert.equal(failure.status, "failed-preserved");
  assert.equal(lstatSync(join(bundle, "failure.json")).mode & 0o777, 0o600);
});
