import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../packages/profile/load.mjs';

import {
  assertV2Q01CleanCommittedCheckoutForTest,
  assertV2Q01TrackedSourceInventoryForTest,
  assertV2Q01TrackedSourcesUnchangedForTest,
  parseV2Q01CommitBoundArguments,
  probeV2Q01RuntimeBindingForTest,
  probeV2Q01SanitizedChildrenForTest,
  q01TestFixtures,
  runV2Q01CommitBoundEvidence,
  runV2Q01CommitBoundEvidenceForTest,
  runV2Q01FourImplementationCycleForTest,
  snapshotV2Q01TrackedSourcesForTest,
  V2Q01CommitBoundEvidenceError,
  verifyV2Q01CommitBoundBundle,
  verifyV2Q01CommitBoundBundleForTest,
} from './v2-q01-commit-bound-evidence.mjs';

const root = () => mkdtempSync(join(tmpdir(), 'shieldkit-q01-pre-'));
const hash = (value) => createHash('sha256').update(value).digest('hex');

function resealArtifact(bundle, name, mutate) {
  const path = join(bundle, name);
  const value = JSON.parse(readFileSync(path, 'utf8'));
  mutate(value);
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  writeFileSync(path, bytes);
  chmodSync(path, 0o600);
  const manifestPath = join(bundle, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const entry = manifest.artifacts.find((item) => item.path === name);
  assert.ok(entry);
  entry.bytes = bytes.length;
  entry.sha256 = hash(bytes);
  writeFileSync(manifestPath, canonicalJson(manifest));
  chmodSync(manifestPath, 0o600);
}

test('Q-01 production source gate refuses a dirty/uncommitted checkout before any lane', () => {
  const repository = root();
  try {
    writeFileSync(join(repository, 'source.mjs'), 'export const value = 1;\n');
    for (const args of [
      ['init', '-q'],
      ['add', 'source.mjs'],
    ]) {
      const result = spawnSync('/usr/bin/git', args, {
        cwd: repository,
        env: {
          LANG: 'C',
          LC_ALL: 'C',
          TZ: 'UTC',
          PATH: '/usr/bin:/bin',
          GIT_CONFIG_COUNT: '0',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_CONFIG_NOSYSTEM: '1',
        },
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
    }
    assert.throws(
      () => assertV2Q01CleanCommittedCheckoutForTest(repository),
      /clean committed source checkout/u,
    );
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test('Q-01 test fixture seals exactly four lanes and remains publicly nonqualifying', async () => {
  const parent = root();
  try {
    const result = await runV2Q01CommitBoundEvidenceForTest({
      outputDirectory: parent,
      ...q01TestFixtures(),
    });
    assert.equal(result.status, 'verified-test-only-local-nonqualifying');
    assert.equal(result.reference, 'javascript-reference-orchestrator');
    assert.deepEqual(
      result.implementations,
      ['typescript', 'rust', 'circuit', 'covenant'],
    );
    assert.equal(result.executed, false);
    assert.equal(result.localOnly, true);
    assert.equal(result.preCeremony, true);
    assert.equal(result.signed, false);
    assert.equal(result.finalArtifacts, false);
    assert.equal(result.finalQualification, false);
    assert.equal(lstatSync(result.bundlePath).mode & 0o777, 0o700);
    for (const name of [
      'manifest.json',
      'source-set.json',
      'qualification.json',
      'execution.json',
    ]) {
      assert.equal(lstatSync(join(result.bundlePath, name)).mode & 0o777, 0o600);
    }
    const qualification = JSON.parse(
      readFileSync(join(result.bundlePath, 'qualification.json'), 'utf8'),
    );
    assert.equal(
      qualification.reference.role,
      'reference-orchestrator-not-one-of-four',
    );
    assert.equal(qualification.implementations.length, 4);
    assert.throws(
      () => verifyV2Q01CommitBoundBundle(result.bundlePath),
      /test-only Q-01 evidence is nonqualifying/u,
    );
    assert.equal(
      verifyV2Q01CommitBoundBundleForTest(result.bundlePath).status,
      'verified-test-only-local-nonqualifying',
    );
    writeFileSync(join(result.bundlePath, 'manifest.json'), '{}');
    chmodSync(join(result.bundlePath, 'manifest.json'), 0o600);
    assert.throws(
      () => verifyV2Q01CommitBoundBundleForTest(result.bundlePath),
      V2Q01CommitBoundEvidenceError,
    );
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('Q-01 verifier fails closed on implementation-lane omission', async () => {
  const parent = root();
  try {
    const result = await runV2Q01CommitBoundEvidenceForTest({
      outputDirectory: parent,
      ...q01TestFixtures(),
    });
    resealArtifact(result.bundlePath, 'qualification.json', (value) => {
      value.implementations.pop();
    });
    assert.throws(
      () => verifyV2Q01CommitBoundBundleForTest(result.bundlePath),
      /exactly four implementation lanes/u,
    );
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('Q-01 verifier rejects sealed lane-output transcript tampering', async () => {
  const parent = root();
  try {
    const result = await runV2Q01CommitBoundEvidenceForTest({
      outputDirectory: parent,
      ...q01TestFixtures(),
    });
    resealArtifact(result.bundlePath, 'execution.json', (value) => {
      value.implementations[0].output.qualification.sha256BeU128.digestHex =
        '0'.repeat(64);
    });
    assert.throws(
      () => verifyV2Q01CommitBoundBundleForTest(result.bundlePath),
      /execution\/output binding differs/u,
    );
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('Q-01 verifier rejects tool identity and sanitized-environment drift', async () => {
  const parent = root();
  try {
    const tool = await runV2Q01CommitBoundEvidenceForTest({
      outputDirectory: parent,
      ...q01TestFixtures(),
    });
    resealArtifact(tool.bundlePath, 'execution.json', (value) => {
      value.runtime.node.executableSha256 = '0'.repeat(64);
    });
    assert.throws(
      () => verifyV2Q01CommitBoundBundleForTest(tool.bundlePath),
      /execution evidence boundary/u,
    );

    const environment = await runV2Q01CommitBoundEvidenceForTest({
      outputDirectory: parent,
      ...q01TestFixtures(),
    });
    resealArtifact(environment.bundlePath, 'source-set.json', (value) => {
      value.runtime.environmentPolicy.node.LANG = 'host-controlled';
    });
    assert.throws(
      () => verifyV2Q01CommitBoundBundleForTest(environment.bundlePath),
      /runtime environment policy/u,
    );
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('Q-01 complete tracked-source snapshot detects live byte drift', () => {
  const repository = root();
  try {
    writeFileSync(join(repository, 'package-lock.json'), '{}\n');
    writeFileSync(join(repository, 'source.mjs'), 'export const value = 1;\n');
    for (const args of [
      ['init', '-q'],
      ['add', 'package-lock.json', 'source.mjs'],
    ]) {
      const result = spawnSync('/usr/bin/git', args, {
        cwd: repository,
        env: {
          LANG: 'C',
          LC_ALL: 'C',
          TZ: 'UTC',
          PATH: '/usr/bin:/bin',
          GIT_CONFIG_COUNT: '0',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_CONFIG_NOSYSTEM: '1',
        },
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
    }
    const snapshot = snapshotV2Q01TrackedSourcesForTest(repository);
    assert.equal(
      assertV2Q01TrackedSourcesUnchangedForTest(repository, snapshot),
      true,
    );
    writeFileSync(join(repository, 'source.mjs'), 'export const value = 2;\n');
    assert.throws(
      () => assertV2Q01TrackedSourcesUnchangedForTest(repository, snapshot),
      /tracked source drifted/u,
    );
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test('Q-01 current source inventory is bytewise ordered and deterministic', () => {
  const first = assertV2Q01TrackedSourceInventoryForTest();
  const second = assertV2Q01TrackedSourceInventoryForTest();
  assert.deepEqual(second, first);
  assert.ok(first.files.length > 0);
  assert.ok(first.locks.length > 0);
});

test('Q-01 child environment ignores ambient Git, Node, npm, Rust, and Cargo controls', () => {
  const names = [
    'GIT_DIR',
    'GIT_CONFIG_COUNT',
    'NODE_OPTIONS',
    'NODE_PATH',
    'NODE_V8_COVERAGE',
    'npm_config_prefix',
    'RUSTFLAGS',
    'CARGO_TARGET_DIR',
  ];
  const prior = new Map(names.map((name) => [name, process.env[name]]));
  try {
    for (const name of names) process.env[name] = '/tmp/host-controlled';
    const probe = probeV2Q01SanitizedChildrenForTest();
    assert.deepEqual(probe.node.controls, []);
    assert.deepEqual({ ...probe.node.environment }, {
      LANG: 'C',
      LC_ALL: 'C',
      TZ: 'UTC',
      NODE_V8_COVERAGE: '',
    });
    assert.match(probe.git.executable, /^\/(?:usr\/)?bin\/git$/u);
    assert.equal(probe.environmentPolicy.inheritAmbient, false);
  } finally {
    for (const [name, value] of prior) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('Q-01 full runtime probe binds Node dependencies, Cargo sources, and all toolchains', () => {
  const probe = probeV2Q01RuntimeBindingForTest();
  assert.ok(probe.nodeInventoryEntries > 100);
  assert.match(probe.nodeInventorySha256, /^[0-9a-f]{64}$/u);
  assert.ok(probe.cargoDependencyPackages > 10);
  assert.match(probe.cargoDependencyInventorySha256, /^[0-9a-f]{64}$/u);
  assert.equal(probe.toolchains.rust.channel, '1.97.1');
  assert.ok(probe.toolchains.rust.sysrootInventory.entries > 100);
  assert.match(
    probe.toolchains.rust.sysrootInventory.inventorySha256,
    /^[0-9a-f]{64}$/u,
  );
  assert.equal(probe.toolchains.typescript.version, '5.9.3');
  assert.equal(probe.toolchains.circuit.circomVersion, '0.2.23');
  assert.equal(probe.toolchains.circuit.circomlibVersion, '2.0.5');
  assert.equal(probe.toolchains.covenant.libauthVersion, '3.1.0-next.8');
  assert.equal(probe.environmentPolicy.inheritAmbient, false);
});

test('Q-01 real bounded cycle executes reference plus exactly four implementation lanes', {
  timeout: 120_000,
}, () => {
  const started = performance.now();
  const cycle = runV2Q01FourImplementationCycleForTest();
  const elapsedMs = Math.round(performance.now() - started);
  assert.equal(cycle.reference.id, 'javascript-reference-orchestrator');
  assert.equal(
    cycle.reference.role,
    'reference-orchestrator-not-one-of-four',
  );
  assert.deepEqual(
    cycle.implementations.map((entry) => entry.id),
    ['typescript', 'rust', 'circuit', 'covenant'],
  );
  assert.equal(
    cycle.implementations.some((entry) => entry.id === 'javascript'),
    false,
  );
  for (const entry of [cycle.reference, ...cycle.implementations]) {
    assert.equal(entry.executed, true);
    assert.ok(entry.commands.length > 0);
    assert.equal(
      entry.outputSha256,
      hash(Buffer.from(canonicalJson(entry.output), 'utf8')),
    );
    for (const command of entry.commands) {
      assert.equal(command.exitStatus, 0);
      assert.equal(command.signal, null);
      assert.equal(command.stdoutSha256, hash(Buffer.from(command.stdout)));
      assert.equal(command.stderrSha256, hash(Buffer.from(command.stderr)));
      assert.equal(command.environment.LANG, 'C');
      assert.equal(command.environment.LC_ALL, 'C');
      assert.equal(command.environment.TZ, 'UTC');
      for (const forbidden of [
        'NODE_OPTIONS',
        'NODE_PATH',
        'npm_config_prefix',
        'RUSTFLAGS',
        'CARGO_ENCODED_RUSTFLAGS',
      ]) {
        assert.equal(Object.hasOwn(command.environment, forbidden), false);
      }
    }
  }
  const [typescript, rust, circuit, covenant] =
    cycle.implementations.map((entry) => entry.output);
  assert.deepEqual({ ...typescript.qualification.state }, {
    mutations: 32_640,
    acceptedCanonicalDistinct: 24_842,
    rejected: 7_798,
  });
  assert.deepEqual({ ...typescript.qualification.packet }, {
    mutations: 140_760,
    acceptedCanonicalDistinct: 88_727,
    rejected: 52_033,
  });
  assert.equal(
    canonicalJson({ ...rust.qualification, surface: 'typescript' }),
    canonicalJson(typescript.qualification),
  );
  assert.equal(circuit.tests, 1);
  assert.equal(circuit.mutationRejections, 2);
  assert.equal(covenant.tests, 6);
  assert.equal(covenant.packetDigestReconstructed, true);
  assert.equal(cycle.agreement.typescriptRustStrictMutationParity, true);
  assert.equal(cycle.agreement.circuitDigestAndLimbsMatched, true);
  assert.equal(cycle.agreement.covenantDigestReconstructionMatched, true);
  console.log(`Q01_REAL_CYCLE=${JSON.stringify({
    elapsedMs,
    reference: {
      id: cycle.reference.id,
      outputSha256: cycle.reference.outputSha256,
    },
    implementations: cycle.implementations.map((entry) => ({
      id: entry.id,
      outputSha256: entry.outputSha256,
    })),
    stateMutations: cycle.agreement.stateMutations,
    packetMutations: cycle.agreement.packetMutations,
    publicInputVectors: cycle.agreement.publicInputVectors,
    circuitTests: circuit.tests,
    covenantTests: covenant.tests,
  })}`);
});

test('Q-01 command parsing and public seam are exact', async () => {
  assert.throws(
    () => parseV2Q01CommitBoundArguments([]),
    V2Q01CommitBoundEvidenceError,
  );
  assert.deepEqual(
    parseV2Q01CommitBoundArguments(['--verify', '/bundle'], '/cwd'),
    { mode: 'verify', bundlePath: '/bundle' },
  );
  await assert.rejects(
    () => runV2Q01CommitBoundEvidence({
      outputDirectory: '/tmp',
      source: {},
    }),
    /accepts only outputDirectory/u,
  );
});
