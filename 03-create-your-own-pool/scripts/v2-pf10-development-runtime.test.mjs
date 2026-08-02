import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../packages/action/v2/topology.mjs';
import {
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from '../packages/unlock-builder/v2/structural-covenants.mjs';
import {
  buildDirectV2Pf10DevelopmentRuntime,
  DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA,
  validateDirectV2Pf10LibauthEvidence,
} from '../packages/unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  PF10_RUNTIME_ARTIFACT_SCHEMA,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  parseV2Pf10DevelopmentRuntimeArguments,
  runV2Pf10DevelopmentRuntime,
  V2_PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
} from './v2-pf10-development-runtime.mjs';

const instanceId = 'ab'.repeat(32);
const qualifiedInstanceId =
  'e57f10131d659926c14e6363b0f5339b2c9578a4d9267e37f852289c75c1056c';
const repositoryRoot = path.resolve(import.meta.dirname, '../..');
const profilePackagePath = path.join(
  repositoryRoot,
  '.codex-build/v2-development-profile/profile-package.json',
);
const profileCorePath = path.join(
  repositoryRoot,
  '.codex-build/v2-development-profile/profile-core.json',
);
const libauthEvidencePath = path.join(
  repositoryRoot,
  '.codex-build/v2-pf10-libauth-qualification/libauth.json',
);
const qualifiedTerminalProgramBytes = Object.freeze({
  raw: 9_359,
  redeem: 6_740,
});

const hex = (value) => Buffer.from(value).toString('hex');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const qualifiedRuntimeInputs = async () => {
  const [profilePackage, profileCore, libauthEvidence] = await Promise.all([
    readFile(profilePackagePath, 'utf8').then(JSON.parse),
    readFile(profileCorePath, 'utf8').then(JSON.parse),
    readFile(libauthEvidencePath),
  ]);
  const proofArtifacts = Object.freeze(Object.fromEntries(
    Object.entries(profilePackage.proofArtifacts)
      .filter(([name]) => [
        'provingKey',
        'r1cs',
        'verificationKey',
        'witnessWasm',
      ].includes(name))
      .map(([name, record]) => [
        name === 'witnessWasm' ? 'wasm' : name,
        Object.freeze({
          path: path.resolve(repositoryRoot, record.path),
          sha256: record.sha256,
        }),
      ]),
  ));
  return Object.freeze({
    libauthEvidence,
    profileCore,
    profileId: profilePackage.profileId,
    proofArtifacts,
  });
};

const requiredArguments = () => [
  '--instance-id', instanceId,
  '--output', 'runtime-package',
  '--profile-core', 'profile/profile-core.json',
  '--profile-package', 'profile/profile-package.json',
  '--qualification-evidence', 'proof/qualification-evidence.json',
  '--libauth-evidence', 'qualification/libauth-evidence.json',
  '--temporary-root', 'temporary',
];

test('PF10 development-runtime CLI requires the exact option set and canonical instance id', () => {
  assert.equal(
    V2_PF10_CANONICAL_QUALIFICATION_RECORD_SCHEMA,
    'shieldkit-v2-direct-pf10-canonical-qualification-record-v1',
  );
  assert.deepEqual(
    parseV2Pf10DevelopmentRuntimeArguments(requiredArguments(), '/runtime'),
    {
      instanceId,
      outputDirectory: path.resolve('/runtime/runtime-package'),
      profileCorePath: path.resolve('/runtime/profile/profile-core.json'),
      profilePackagePath: path.resolve('/runtime/profile/profile-package.json'),
      qualificationEvidencePath: path.resolve(
        '/runtime/proof/qualification-evidence.json',
      ),
      libauthEvidencePath: path.resolve(
        '/runtime/qualification/libauth-evidence.json',
      ),
      temporaryRoot: path.resolve('/runtime/temporary'),
    },
  );

  for (const argv of [
    undefined,
    ['--instance-id', instanceId],
    [...requiredArguments(), '--output', 'again'],
    ['--unknown', 'forbidden', ...requiredArguments()],
    [
      '--instance-id', 'AB'.repeat(32),
      '--output', 'runtime-package',
      '--profile-core', 'profile/profile-core.json',
      '--profile-package', 'profile/profile-package.json',
      '--qualification-evidence', 'proof/qualification-evidence.json',
      '--libauth-evidence', 'qualification/libauth-evidence.json',
      '--temporary-root', 'temporary',
    ],
    [
      '--instance-id', instanceId,
      '--output', '--profile-core', 'profile/profile-core.json',
      '--profile-package', 'profile/profile-package.json',
      '--qualification-evidence', 'proof/qualification-evidence.json',
      '--libauth-evidence', 'qualification/libauth-evidence.json',
      '--temporary-root', 'temporary',
    ],
  ]) {
    assert.throws(
      () => parseV2Pf10DevelopmentRuntimeArguments(argv, '/runtime'),
      /CLI arguments|missing required|duplicate CLI option|unknown or positional|32 lowercase|missing value/,
    );
  }
});

test('PF10 runtime builder rejects a per-instance Libauth evidence record with a wrong supplied hash', async () => {
  const inputs = await qualifiedRuntimeInputs();
  await assert.rejects(
    buildDirectV2Pf10DevelopmentRuntime({
      repositoryRoot,
      temporaryRoot: path.join(repositoryRoot, '.codex-build/unused-runtime-test'),
      profileId: inputs.profileId,
      instanceId: qualifiedInstanceId,
      proofArtifacts: inputs.proofArtifacts,
      libauthEvidence: {
        path: libauthEvidencePath,
        sha256: '33'.repeat(32),
      },
    }),
    /PF10 Libauth evidence SHA-256 differs from the supplied profile pin/,
  );
});

test('PF10 Libauth evidence fails closed on per-instance and runtime-material identity drift', async () => {
  const inputs = await qualifiedRuntimeInputs();
  const evidence = JSON.parse(inputs.libauthEvidence.toString('utf8'));
  const proofArtifactHashes = Object.freeze(Object.fromEntries(
    Object.entries(inputs.proofArtifacts).map(([name, record]) => [
      name,
      record.sha256,
    ]),
  ));
  const validate = (overrides = {}) => validateDirectV2Pf10LibauthEvidence({
    bytes: inputs.libauthEvidence,
    expectedTerminalProgramBytes: qualifiedTerminalProgramBytes,
    profileId: inputs.profileId,
    instanceId: qualifiedInstanceId,
    proofArtifactHashes,
    runtimeMaterialSha256: evidence.identity.runtimeMaterialSha256,
    ...overrides,
  });

  assert.throws(
    () => validate({ instanceId: '00'.repeat(32) }),
    /identity or topology is not bound to this runtime/,
  );
  assert.throws(
    () => validate({ runtimeMaterialSha256: '00'.repeat(32) }),
    /runtime material hash is not bound to this runtime/,
  );
  assert.throws(
    () => validate({
      expectedTerminalProgramBytes: Object.freeze({
        raw: qualifiedTerminalProgramBytes.raw - 1,
        redeem: qualifiedTerminalProgramBytes.redeem,
      }),
    }),
    /terminal program bytes do not match the pinned verification-key runtime/,
  );
});

test('PF10 development-runtime rejects malformed and non-profile JSON before any runtime build', async (t) => {
  const buildRoot = path.join(process.cwd(), '.codex-build');
  await mkdir(buildRoot, { recursive: true, mode: 0o700 });
  const temporaryRoot = await mkdtemp(
    path.join(buildRoot, 'v2-runtime-schema-'),
  );
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const malformedProfile = path.join(temporaryRoot, 'malformed.json');
  const invalidProfile = path.join(temporaryRoot, 'invalid.json');
  const symlinkedProfile = path.join(temporaryRoot, 'symlinked-profile.json');
  await writeFile(malformedProfile, '{');
  await writeFile(invalidProfile, '{}');
  await symlink(invalidProfile, symlinkedProfile);

  const run = (profileCorePath) => runV2Pf10DevelopmentRuntime([
    '--instance-id', instanceId,
    '--output', path.join(temporaryRoot, 'output'),
    '--profile-core', profileCorePath,
    '--profile-package', path.join(temporaryRoot, 'unused-package.json'),
    '--qualification-evidence', path.join(temporaryRoot, 'unused-evidence.json'),
    '--libauth-evidence', path.join(temporaryRoot, 'unused-libauth.json'),
    '--temporary-root', path.join(temporaryRoot, 'temporary'),
  ], {
    cwd: temporaryRoot,
    repositoryRoot: process.cwd(),
  });

  await assert.rejects(run(malformedProfile), /profile core is not JSON/);
  await assert.rejects(run(invalidProfile), /profile core has missing or unknown properties/);
  await assert.rejects(
    run(symlinkedProfile),
    /profile core must be one nonempty canonical regular file/,
  );
});

test('PF10 runtime bundle source retains every v2 profile, provenance, and setup artifact at mode 0600', async () => {
  const source = await readFile(
    new URL('./v2-pf10-development-runtime.mjs', import.meta.url),
    'utf8',
  );
  assert.equal(
    PF10_RUNTIME_ARTIFACT_SCHEMA,
    'shieldkit-v2-direct-pf10-runtime-artifact-v3',
  );
  assert.match(source, /open\(filename, 'wx', 0o600\)/);
  for (const artifactId of [
    'profile-core',
    'development-profile-package',
    'pf10-base-verifier-sources',
    'pf10-topology-spec',
    'toolchain-manifest',
    'circuit-build-attestation',
    'development-setup-attestation',
    'relation-source-manifest',
    'proof-circuit-symbols',
    'proof-initial-proving-key',
    'proof-powers-of-tau',
    'proof-proving-key',
    'proof-r1cs',
    'proof-verification-key',
    'proof-witness-wasm',
    'pf10-libauth-evidence',
  ]) {
    assert.match(source, new RegExp(`'${artifactId}'`));
  }
  assert.match(
    source,
    /libauthEvidenceArtifactId:\s*runtimeIds\.libauthEvidence/,
  );
  for (const group of [
    'profileArtifacts',
    'attestationArtifacts',
    'setupArtifacts',
    'proofArtifacts',
  ]) {
    assert.match(source, new RegExp(`${group}: Object\\.freeze\\(`));
  }
});

test('PF10 runtime pins 1200-sat verifier/binding carriers and a distinct 2500-sat dust-safe state carrier', async (t) => {
  const inputs = await qualifiedRuntimeInputs();
  const { profileCore } = inputs;
  const temporaryRoot = await mkdtemp(path.join(
    repositoryRoot,
    '.codex-build/v2-runtime-dust-base-',
  ));
  t.after(() => rm(temporaryRoot, { recursive: true, force: true }));
  const runtime = await buildDirectV2Pf10DevelopmentRuntime({
    repositoryRoot,
    temporaryRoot,
    profileId: inputs.profileId,
    instanceId: qualifiedInstanceId,
    proofArtifacts: inputs.proofArtifacts,
    libauthEvidence: {
      path: libauthEvidencePath,
      sha256: sha256(inputs.libauthEvidence),
    },
  });
  assert.equal(runtime.libauthEvidence.bytes, inputs.libauthEvidence.length);
  assert.deepEqual(runtime.libauthEvidence.data, inputs.libauthEvidence);
  assert.equal(
    runtime.libauthEvidence.path,
    '.codex-build/v2-pf10-libauth-qualification/libauth.json',
  );
  assert.equal(runtime.libauthEvidence.schema, DIRECT_V2_PF10_LIBAUTH_EVIDENCE_SCHEMA);
  assert.equal(runtime.libauthEvidence.sha256, sha256(inputs.libauthEvidence));
  const expectedBaseValues = Object.freeze({
    verifierSats: Object.freeze(
      Array(DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length).fill('1200'),
    ),
    bindingSats: '1200',
    stateSats: '2500',
    minimumChangeSats: '546',
  });
  const expectedHelper = Buffer.from(buildDirectV2StateHelper({
    bindingLock: runtime.structural.bindingLock,
    verifierLocks: runtime.structural.verifierLocks,
    verifierBaseValues: expectedBaseValues.verifierSats,
    bindingBaseValueSats: expectedBaseValues.bindingSats,
    stateBaseValueSats: expectedBaseValues.stateSats,
    denominationSats: profileCore.denominationSats,
    stateCategory: runtime.instanceId,
    minimumChangeSats: expectedBaseValues.minimumChangeSats,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  }));
  const expectedStateUnlock = Buffer.from(
    buildDirectV2StateTrampolineUnlock(expectedHelper),
  );
  const expectedStateLock = Buffer.from(buildDirectV2StateTrampolineLock({
    helper: expectedHelper,
    bindingLock: runtime.structural.bindingLock,
    topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  }));
  assert.deepEqual(runtime.baseValues, expectedBaseValues);
  assert.deepEqual(
    {
      helperHex: hex(runtime.structural.stateHelper),
      helperUnlockHex: hex(runtime.structural.stateUnlock),
      stateLockHex: hex(runtime.structural.stateLock),
    },
    {
      helperHex: hex(expectedHelper),
      helperUnlockHex: hex(expectedStateUnlock),
      stateLockHex: hex(expectedStateLock),
    },
  );
});
