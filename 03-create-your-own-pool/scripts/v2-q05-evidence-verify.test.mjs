/* TEST-ONLY: validates local Q-05 evidence closure; never qualification. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { BABYJUB_SUBGROUP_ORDER } from '../packages/recover/portable-core.mjs';
import { deriveDirectV2Address } from '../packages/action/v2/notes.mjs';
import {
  Q05_DEPENDENCY_INVENTORY_SCHEMA,
  Q05_EXECUTION_SNAPSHOT_SCHEMA,
  Q05_MINIMUM_NODE_VERSION,
  Q05_SOURCE_DEFINITIONS,
  Q05_VALIDATED_PROPERTIES,
  assertQ05SafeHostEnvironment,
  createQ05ExecutionSnapshotForTestOnly,
  destroyQ05ExecutionSnapshot,
  isQ05SupportedNodeVersion,
  q05ControlledEnvironment,
  q05Git,
  runQ05JsEvidenceForTestOnly,
  runQ05RustEvidenceForTestOnly,
  validateQ05ExecutionSnapshot,
  validateQ05JsEvidence,
  validateQ05JsReport,
  validateQ05RustEvidence,
  validateQ05TrackedIndexFlags,
  validateQ05ValidatedProperties,
} from './v2-q05-evidence-verify.mjs';

// The production entrypoints require an empty Node preload/loader argument
// vector. Node propagates test-runner flags through process.execArgv, so this
// test-only process clears them after the runner has already initialized.
process.execArgv.length = 0;

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
let cachedJs;
let cachedRust;
const jsEvidence = () => {
  cachedJs ??= runQ05JsEvidenceForTestOnly();
  return structuredClone(cachedJs);
};
const rustEvidence = () => {
  cachedRust ??= runQ05RustEvidenceForTestOnly();
  return structuredClone(cachedRust);
};
const resealJsStdout = (value) => {
  value.stdout = `${JSON.stringify(value.report)}\n`;
  value.stdoutSha256 = sha256(value.stdout);
};

test('[test-only] Q05 Node policy exactly matches the repository >=22.5 runtime floor', () => {
  assert.equal(Q05_MINIMUM_NODE_VERSION, '22.5.0');
  for (const version of ['v22.5.0', 'v22.23.1', 'v23.0.0', 'v25.9.0', 'v100.0.0']) {
    assert.equal(isQ05SupportedNodeVersion(version), true, version);
  }
  for (const version of ['v22.4.99', 'v21.99.99', '22.5.0', 'v22.5', 'v22.5.0-rc.1', '', null]) {
    assert.equal(isQ05SupportedNodeVersion(version), false, String(version));
  }
});

test('[test-only] Q05 transcript is dynamically counted, complete, and deterministic', () => {
  const evidence = jsEvidence();
  assert.equal(evidence.report.totalChecks, 152);
  assert.equal(evidence.report.transcript.labels.length, evidence.report.totalChecks);
  assert.equal(validateQ05JsEvidence(evidence).totalChecks, 152);
  assert.equal(
    JSON.stringify(runQ05JsEvidenceForTestOnly().report.transcript),
    JSON.stringify(evidence.report.transcript),
  );
});

test('[test-only] Q05 JS transcript tampering is rejected after report and stream resealing', () => {
  const changed = jsEvidence();
  changed.report.transcript.labels[0] = 'canonicalNonzeroSecretCases:substituted';
  changed.report.transcript.sha256 = sha256(JSON.stringify(changed.report.transcript.labels));
  resealJsStdout(changed);
  assert.throws(() => validateQ05JsEvidence(changed), /transcript labels/u);
});

test('[test-only] Q05 covers exact BabyJub order for both secret roles', () => {
  const report = jsEvidence().report;
  assert.equal(report.passed.invalidSpendSecretCases, 3);
  assert.equal(report.passed.invalidIncomingViewSecretCases, 3);
  assert.equal(report.transcript.labels.includes('invalidSpendSecretCases:zero'), true);
  assert.equal(report.transcript.labels.includes('invalidSpendSecretCases:babyjub-subgroup-order'), true);
  assert.equal(report.transcript.labels.includes('invalidSpendSecretCases:bn254-scalar-field-modulus'), true);
  assert.equal(report.transcript.labels.includes('invalidIncomingViewSecretCases:zero'), true);
  assert.equal(report.transcript.labels.includes('invalidIncomingViewSecretCases:babyjub-subgroup-order'), true);
  assert.equal(report.transcript.labels.includes('invalidIncomingViewSecretCases:bn254-scalar-field-modulus'), true);
  const base = {
    networkId: 2,
    profileId: '11'.repeat(32),
    instanceId: '22'.repeat(32),
    spendSecret: fr(3),
    incomingViewSecret: fr(4),
  };
  assert.throws(() => deriveDirectV2Address({ ...base, spendSecret: fr(BABYJUB_SUBGROUP_ORDER) }), /subgroup scalar/u);
  assert.throws(() => deriveDirectV2Address({ ...base, incomingViewSecret: fr(BABYJUB_SUBGROUP_ORDER) }), /subgroup scalar/u);
  assert.equal(validateQ05JsReport(report).totalChecks, 152);
});

test('[test-only] Q05 runtime tampering is rejected', () => {
  const changed = jsEvidence();
  changed.execution.runtime.executable.sha256 = '00'.repeat(32);
  assert.throws(() => validateQ05JsEvidence(changed), /Node runtime differs/u);
});

test('[test-only] Q05 rejects host Node loader and preload contamination', () => {
  const cleanHome = q05ControlledEnvironment('node').variables.HOME;
  assert.throws(
    () => assertQ05SafeHostEnvironment({ HOME: cleanHome, NODE_OPTIONS: '--require=/tmp/evil.cjs' }, []),
    /NODE_OPTIONS/u,
  );
  assert.throws(
    () => assertQ05SafeHostEnvironment({ HOME: cleanHome, LD_PRELOAD: '/tmp/evil.so' }, []),
    /LD_PRELOAD/u,
  );
  assert.throws(
    () => assertQ05SafeHostEnvironment({ HOME: cleanHome, LD_LIBRARY_PATH: '/tmp/evil-libraries' }, []),
    /LD_LIBRARY_PATH/u,
  );
  assert.throws(
    () => assertQ05SafeHostEnvironment({ HOME: cleanHome, LD_AUDIT: '/tmp/evil-audit.so' }, []),
    /LD_AUDIT/u,
  );
  assert.throws(
    () => assertQ05SafeHostEnvironment({ HOME: '/tmp/attacker-home' }, []),
    /HOME/u,
  );
  assert.throws(
    () => assertQ05SafeHostEnvironment({ HOME: cleanHome }, ['--import=/tmp/evil.mjs']),
    /process\.execArgv/u,
  );
});

test('[test-only] Q05 clears hostile Git, Rust wrapper, flags, and npm configuration', () => {
  const hostile = {
    GIT_CONFIG_GLOBAL: '/tmp/evil-gitconfig',
    GIT_OBJECT_DIRECTORY: '/tmp/evil-objects',
    NODE_OPTIONS: '--import=/tmp/evil.mjs',
    RUSTC: '/tmp/evil-rustc',
    RUSTC_WRAPPER: '/tmp/evil-wrapper',
    RUSTC_WORKSPACE_WRAPPER: '/tmp/evil-workspace-wrapper',
    RUSTFLAGS: '-C linker=/tmp/evil-linker',
    CARGO_ENCODED_RUSTFLAGS: 'evil',
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS: 'evil',
    npm_config_node_options: '--require=/tmp/evil.cjs',
    NPM_CONFIG_USERCONFIG: '/tmp/evil-npmrc',
  };
  const git = q05ControlledEnvironment('git', hostile);
  const node = q05ControlledEnvironment('node', hostile);
  const cargo = q05ControlledEnvironment('cargo', hostile);
  assert.equal(git.variables.GIT_CONFIG_GLOBAL, '/dev/null');
  assert.equal('GIT_OBJECT_DIRECTORY' in git.variables, false);
  assert.equal('NODE_OPTIONS' in node.variables, false);
  assert.match(cargo.variables.RUSTC, /\/1\.97\.1-[^/]+\/bin\/rustc$/u);
  for (const key of [
    'RUSTC_WRAPPER',
    'RUSTC_WORKSPACE_WRAPPER',
    'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS',
    'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS',
    'npm_config_node_options',
    'NPM_CONFIG_USERCONFIG',
  ]) assert.equal(key in cargo.variables, false, key);
});

test('[test-only] Q05 rejects assume-unchanged and skip-worktree index flags', () => {
  assert.equal(validateQ05TrackedIndexFlags('H normal.mjs\0H nested/file.mjs\0'), true);
  assert.throws(() => validateQ05TrackedIndexFlags('h hidden-change.mjs\0'), /non-normal Git index flag/u);
  assert.throws(() => validateQ05TrackedIndexFlags('S skipped-change.mjs\0'), /non-normal Git index flag/u);
});

test('[test-only] Q05 Git execution ignores a hostile inherited object directory', () => {
  const previous = process.env.GIT_OBJECT_DIRECTORY;
  process.env.GIT_OBJECT_DIRECTORY = '/tmp/q05-attacker-objects';
  try {
    assert.match(q05Git(['rev-parse', 'HEAD'], 'contaminated Git probe'), /^[0-9a-f]{40}\n$/u);
  } finally {
    if (previous === undefined) delete process.env.GIT_OBJECT_DIRECTORY;
    else process.env.GIT_OBJECT_DIRECTORY = previous;
  }
});

test('[test-only] Q05 rejects extra JS stdout and stderr after attacker resealing', () => {
  const stdoutChanged = jsEvidence();
  stdoutChanged.stdout += 'extra-output\n';
  stdoutChanged.stdoutSha256 = sha256(stdoutChanged.stdout);
  assert.throws(() => validateQ05JsEvidence(stdoutChanged), /stdout is not exactly/u);

  const stderrChanged = jsEvidence();
  stderrChanged.stderr = 'extra-error\n';
  stderrChanged.stderrSha256 = sha256(stderrChanged.stderr);
  assert.throws(() => validateQ05JsEvidence(stderrChanged), /unexpected stderr/u);
});

test('[test-only] Q05 exact validated properties resist same-length resealing', () => {
  validateQ05ValidatedProperties(Q05_VALIDATED_PROPERTIES);
  const changed = [...Q05_VALIDATED_PROPERTIES];
  changed[0] = 'attacker-resealed-property';
  assert.equal(changed.length, Q05_VALIDATED_PROPERTIES.length);
  assert.throws(() => validateQ05ValidatedProperties(changed), /validatedProperties differs/u);
});

test('[test-only] Q05 secure source closure binds generator, verifier, corpus, and pinned Rust inputs', () => {
  const roles = new Set(Q05_SOURCE_DEFINITIONS.map((value) => value.role));
  for (const role of ['q05-generator', 'q05-verifier', 'q05-js-corpus', 'q05-rust-tests', 'q05-rust-toolchain']) assert.equal(roles.has(role), true);
});

test('[test-only] Q05 exact-HEAD snapshot performs fresh npm ci and binds immutable dependencies', () => {
  const snapshot = createQ05ExecutionSnapshotForTestOnly();
  try {
    const record = validateQ05ExecutionSnapshot(snapshot);
    assert.equal(record.schema, Q05_EXECUTION_SNAPSHOT_SCHEMA);
    assert.equal(record.git.replaceObjectsDisabled, true);
    assert.equal(record.npmInstall.command.join(' '), 'npm ci --ignore-scripts --no-audit --no-fund --loglevel=silent');
    assert.equal(record.npmInstall.cache, 'fresh-mode-0700');
    assert.equal(record.dependencyInventory.schema, Q05_DEPENDENCY_INVENTORY_SCHEMA);
    assert.deepEqual(record.dependencyInventory.packages.map(({ name, version }) => [name, version]), [
      ['@noble/hashes', '1.8.0'],
      ['poseidon-lite', '0.3.0'],
    ]);
    assert.equal(record.dependencyInventory.packages.every((entry) => entry.fileCount > 0), true);
  } finally {
    destroyQ05ExecutionSnapshot(snapshot);
  }
});

test('[test-only] Q05 Cargo execution ignores hostile inherited Rust wrappers', () => {
  const previous = process.env.RUSTC_WRAPPER;
  process.env.RUSTC_WRAPPER = '/tmp/q05-attacker-rustc-wrapper';
  try {
    assert.equal(validateQ05RustEvidence(rustEvidence()).tests, 5);
  } finally {
    if (previous === undefined) delete process.env.RUSTC_WRAPPER;
    else process.env.RUSTC_WRAPPER = previous;
  }
});

test('[test-only] Q05 Rust transcript uses an empty fresh target, never a cached target', () => {
  const evidence = rustEvidence();
  assert.equal(validateQ05RustEvidence(evidence).tests, 5);
  assert.equal(evidence.execution.cargoTarget.kind, 'fresh-temporary-mode-0700');
  assert.equal(evidence.execution.cargoTarget.initialEntries, 0);
  assert.match(evidence.selectedExecutable.targetRelativePath, /^debug\/deps\/notes-[0-9a-f]{16}$/u);
  assert.match(evidence.selectedExecutable.sha256, /^[0-9a-f]{64}$/u);
  const changed = rustEvidence();
  changed.testNames[0] = 'substituted_test_name';
  assert.throws(() => validateQ05RustEvidence(changed), /test names/u);
});

test('[test-only] Q05 rejects arbitrary extra Rust output even after hash resealing', () => {
  const stdoutChanged = rustEvidence();
  stdoutChanged.stdout += 'attacker-extra-stdout\n';
  stdoutChanged.stdoutSha256 = sha256(stdoutChanged.stdout);
  assert.throws(() => validateQ05RustEvidence(stdoutChanged), /Rust stdout contains unexpected/u);

  const stderrChanged = rustEvidence();
  stderrChanged.stderr += 'attacker-extra-stderr\n';
  stderrChanged.stderrSha256 = sha256(stderrChanged.stderr);
  assert.throws(() => validateQ05RustEvidence(stderrChanged), /Rust stderr contains unexpected/u);
});

test('[test-only] Q05 Rust toolchain path and hash tampering is rejected', () => {
  const pathChanged = rustEvidence();
  pathChanged.toolchain.rustc.resolvedPath = '/tmp/not-rustc';
  assert.throws(() => validateQ05RustEvidence(pathChanged), /toolchain differs/u);

  const hashChanged = rustEvidence();
  hashChanged.toolchain.cargo.sha256 = '00'.repeat(32);
  assert.throws(() => validateQ05RustEvidence(hashChanged), /toolchain differs/u);
});

test('[test-only] Q05 generator usage failure is caught without an uncaught stack', () => {
  const result = spawnSync(process.execPath, ['scripts/v2-q05-evidence.mjs'], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
    env: process.env,
  });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'Q05 evidence generation failed: usage: v2-q05-evidence.mjs --out /absolute/new-bundle-directory\n');
});
