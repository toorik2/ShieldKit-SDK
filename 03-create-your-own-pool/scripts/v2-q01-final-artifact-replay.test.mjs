/* TEST-ONLY: no fixture in this file can produce a qualifying Q-01 result. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  V2_Q01_FINAL_REPLAY_SCHEMA,
  V2_Q01_FINAL_REPLAY_TEST_SCHEMA,
  V2Q01FinalArtifactReplayError,
  parseV2Q01FinalArtifactReplayArguments,
  revalidateV2Q01FinalArtifactReplayResult,
  revalidateV2Q01FinalArtifactReplayTestResultForTestOnly,
  runV2Q01FinalArtifactReplay,
  runV2Q01FinalArtifactReplayForTest,
} from './v2-q01-final-artifact-replay.mjs';
import {
  q01TestFixtures,
  runV2Q01CommitBoundEvidenceForTest,
  verifyV2Q01CommitBoundBundleForTest,
} from './v2-q01-commit-bound-evidence.mjs';
import {
  V2_D01_RESULT_SCHEMA,
} from './v2-final-ceremony-qualification.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  V2_RELATION_ENTRYPOINT,
  V2_RELATION_SOURCE_MANIFEST_SCHEMA,
} from '../packages/profile/v2/relation-source-manifest.mjs';

// node:test has already consumed these flags. Production execution requires an
// empty loader/preload vector, as do the neighboring final-gate tests.
process.execArgv.length = 0;

const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');
const canonical = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const hash = (label) => sha256(Buffer.from(label));
const GIT_COMMIT = '7'.repeat(40);
const GIT_TREE = '8'.repeat(40);
const PROFILE_ID = hash('profile-id');
const INSTANCE_ID = hash('instance-id');
const TOPOLOGY_ID = 'pf10-fused-q-genesis-v1';
const ROOT_ID = 'test-only-final-root';
const EXTERNAL_TEST_TEMP_ROOT = realpathSync('/tmp');

function privateDirectory(path) {
  mkdirSync(path, { mode: 0o700 });
  chmodSync(path, 0o700);
  return path;
}

function writeJcs(path, value, mode = 0o600) {
  writeFileSync(path, canonical(value), { mode });
  chmodSync(path, mode);
  return Object.freeze({
    bytes: readFileSync(path).length,
    sha256: sha256(readFileSync(path)),
  });
}

function clone(value) {
  return structuredClone(value);
}

function relationFixture() {
  return {
    schema: V2_RELATION_SOURCE_MANIFEST_SCHEMA,
    entrypoint: V2_RELATION_ENTRYPOINT,
    compiler: {
      npmPackage: 'circom2@0.2.23',
      circom: '2.2.3',
      optimization: 'O1',
      sanityCheck: 2,
    },
    sources: [{
      bytes: 123,
      includes: [],
      path: V2_RELATION_ENTRYPOINT,
      sha256: hash('frozen-relation-source'),
    }],
  };
}

async function scenario() {
  // The mandatory domain runner deliberately redirects tmpdir() into the
  // checkout. Final-replay evidence must remain outside the bound source root,
  // so this test uses the canonical OS temporary root explicitly.
  const root = mkdtempSync(
    resolve(EXTERNAL_TEST_TEMP_ROOT, 'shieldkit-q01-final-test-'),
  );
  chmodSync(root, 0o700);
  const q01Parent = privateDirectory(join(root, 'q01'));
  const fixtures = q01TestFixtures();
  const q01 = await runV2Q01CommitBoundEvidenceForTest({
    outputDirectory: q01Parent,
    source: fixtures.source,
    cycle: fixtures.cycle,
  });

  const paths = {
    profile: join(root, 'profile-core.json'),
    descriptor: join(root, 'descriptor.json'),
    manifest: join(root, 'manifest.json'),
    d01: join(root, 'd01.json'),
    ceremony: join(root, 'ceremony'),
    relation: join(root, 'relation-source-manifest.json'),
  };
  const profileDocument = {
    schema: 'shieldkit-test-only-final-profile',
    network: { id: 2, name: 'chipnet' },
  };
  const manifestDocument = {
    schema: 'shieldkit-test-only-final-manifest',
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
  };
  const relationDocument = relationFixture();
  writeJcs(paths.profile, profileDocument);
  writeJcs(paths.manifest, manifestDocument);
  writeJcs(paths.relation, relationDocument);
  privateDirectory(paths.ceremony);

  const descriptorDocument = {
    schema: 'shieldkit-test-only-signed-descriptor',
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    manifestSha256: sha256(canonical(manifestDocument)),
    relationSha256: sha256(canonical(relationDocument)),
    signature: 'test-only-valid-signature',
  };
  writeJcs(paths.descriptor, descriptorDocument);

  const releaseRoot = {
    rootId: ROOT_ID,
    profileId: PROFILE_ID,
    topology: { id: TOPOLOGY_ID },
  };
  const release = {
    profileId: PROFILE_ID,
    profileCoreSha256: sha256(canonical(profileDocument)),
    descriptorSigners: [],
    releaseBootstrapSha256: hash('release-bootstrap'),
    releaseRootId: ROOT_ID,
  };
  const descriptor = {
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    finalLocks: { topology: { id: TOPOLOGY_ID } },
    descriptor: {
      sha256: sha256(canonical(descriptorDocument)),
    },
    manifest: {
      filename: paths.manifest,
      sha256: sha256(canonical(manifestDocument)),
    },
    artifacts: new Map([[
      'final-relation-source-manifest',
      {
        filename: paths.relation,
        sha256: sha256(canonical(relationDocument)),
      },
    ]]),
  };
  const runtime = {
    eligibility: 'final-qualified',
    claims: {
      ceremonyQualified: true,
      developmentKey: false,
      finalKey: true,
      production: false,
      releaseQualified: false,
    },
    proofArtifacts: {
      r1cs: { sha256: hash('r1cs') },
      wasm: { sha256: hash('wasm') },
      provingKey: { sha256: hash('final-zkey') },
      verificationKey: { sha256: hash('verification-key') },
    },
    runtimeMaterial: { materialSha256: hash('runtime-material') },
    runtimeArtifactSha256: hash('runtime-artifact'),
    finalBuildEvidence: {
      relationSourceManifestArtifactId:
        'final-relation-source-manifest',
      relationSourceManifestSha256:
        sha256(canonical(relationDocument)),
    },
    finalEvidence: {
      sourceCommit: GIT_COMMIT,
      sourceTree: GIT_TREE,
      snarkjsToolchainSha256: hash('snarkjs-toolchain'),
      contributorCount: 5,
      transcriptSha256: hash('transcript'),
      beaconSha256: hash('beacon'),
      transcriptVerificationSha256s: [
        hash('transcript-verifier-a'),
        hash('transcript-verifier-b'),
      ],
      reproductionSha256s: [
        hash('reproduction-host-a'),
        hash('reproduction-host-b'),
      ],
    },
    finalZkeyEvidence: {
      r1csSha256: hash('r1cs'),
      powersOfTauSha256: hash('powers-of-tau'),
      finalZkeySha256: hash('final-zkey'),
      verificationKeySha256: hash('verification-key'),
      snarkjsToolchainManifestSha256:
        hash('snarkjs-toolchain-manifest'),
    },
  };
  const d01 = {
    schema: V2_D01_RESULT_SCHEMA,
    status: 'd01-qualified-final-key-not-production-or-release',
    d01Qualified: true,
    production: false,
    releaseQualified: false,
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    topologyId: TOPOLOGY_ID,
    descriptorSha256: descriptor.descriptor.sha256,
    manifestSha256: descriptor.manifest.sha256,
    releaseRootId: ROOT_ID,
    sourceCommit: GIT_COMMIT,
    sourceTree: GIT_TREE,
    r1csSha256: runtime.proofArtifacts.r1cs.sha256,
    ptauSha256: runtime.finalZkeyEvidence.powersOfTauSha256,
    finalZkeySha256: runtime.proofArtifacts.provingKey.sha256,
    verificationKeySha256:
      runtime.proofArtifacts.verificationKey.sha256,
    snarkjsToolchainSha256:
      runtime.finalEvidence.snarkjsToolchainSha256,
    contributorCount: 5,
    transcriptSha256: runtime.finalEvidence.transcriptSha256,
    beaconSha256: runtime.finalEvidence.beaconSha256,
    transcriptVerificationSha256s:
      runtime.finalEvidence.transcriptVerificationSha256s,
    reproductionSha256s: runtime.finalEvidence.reproductionSha256s,
    releaseBootstrapSha256: release.releaseBootstrapSha256,
    postCeremonyBindingSha256: hash('post-ceremony-binding'),
    ceremonyInventorySha256: hash('ceremony-inventory'),
  };
  writeJcs(paths.d01, d01);

  const frozenProfile = canonicalizeJcs(profileDocument);
  const frozenRelation = canonicalizeJcs(relationDocument);
  const state = {
    root,
    paths,
    q01Bundle: q01.bundlePath,
    profileDocument,
    manifestDocument,
    relationDocument,
    descriptorDocument,
    releaseRoot,
    release,
    descriptor,
    runtime,
    d01,
    frozenProfile,
    frozenRelation,
  };
  state.dependencies = {
    resolveReleaseRoot: (rootId) => {
      if (rootId !== ROOT_ID) throw new Error('test-only release root differs');
      return state.releaseRoot;
    },
    verifyProfileCore: (_root, bytes) => {
      if (bytes.toString('utf8') !== state.frozenProfile) {
        throw new Error('test-only profile root or hash differs');
      }
      return state.release;
    },
    verifyD01Evidence: async (options) => {
      if (options.ceremonyDirectory !== state.paths.ceremony) {
        throw new Error('test-only ceremony directory differs');
      }
      return state.d01;
    },
    loadDescriptor: async ({ descriptorPath }) => {
      const document = JSON.parse(readFileSync(descriptorPath, 'utf8'));
      if (document.signature !== 'test-only-valid-signature') {
        throw new Error('test-only descriptor signature mismatch');
      }
      if (
        document.manifestSha256 !== state.descriptor.manifest.sha256
        || document.relationSha256
          !== state.runtime.finalBuildEvidence
            .relationSourceManifestSha256
      ) {
        throw new Error('test-only signed descriptor pins differ');
      }
      return state.descriptor;
    },
    deriveRuntime: async () => state.runtime,
    verifyQ01Bundle: (path) =>
      verifyV2Q01CommitBoundBundleForTest(path),
    verifyRelationManifest: async (value) => {
      if (canonicalizeJcs(value) !== state.frozenRelation) {
        throw new Error('test-only frozen relation source drift');
      }
      return value;
    },
  };
  state.options = {
    profileCorePath: paths.profile,
    descriptorPath: paths.descriptor,
    finalManifestPath: paths.manifest,
    releaseRootId: ROOT_ID,
    d01ResultPath: paths.d01,
    ceremonyDirectory: paths.ceremony,
    q01PreBundle: state.q01Bundle,
    expectedCommit: GIT_COMMIT,
    expectedTree: GIT_TREE,
    outputDirectory: join(root, 'result'),
  };
  return state;
}

function dispose(state) {
  rmSync(state.root, { force: true, recursive: true });
}

function syncDescriptorAndD01(state) {
  writeJcs(state.paths.descriptor, state.descriptorDocument);
  state.descriptor.descriptor.sha256 =
    sha256(canonical(state.descriptorDocument));
  state.d01.descriptorSha256 = state.descriptor.descriptor.sha256;
  writeJcs(state.paths.d01, state.d01);
}

function resealQ01Qualification(bundle, mutate) {
  const qualificationPath = join(bundle, 'qualification.json');
  const qualification = JSON.parse(readFileSync(qualificationPath, 'utf8'));
  mutate(qualification);
  writeJcs(qualificationPath, qualification);
  const manifestPath = join(bundle, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const reference = manifest.artifacts.find(
    (entry) => entry.role === 'qualification',
  );
  reference.bytes = readFileSync(qualificationPath).length;
  reference.sha256 = sha256(readFileSync(qualificationPath));
  writeJcs(manifestPath, manifest);
}

function resealLaneOutput(qualification, id, mutate) {
  const lane = qualification.implementations.find(
    (entry) => entry.id === id,
  );
  mutate(lane.output);
  lane.outputSha256 = sha256(canonical(lane.output));
}

function validArguments(output = '/tmp/q01-final/output') {
  return [
    '--profile-core', '/tmp/q01-final/profile.json',
    '--descriptor', '/tmp/q01-final/descriptor.json',
    '--final-manifest', '/tmp/q01-final/manifest.json',
    '--release-root', ROOT_ID,
    '--d01-result', '/tmp/q01-final/d01.json',
    '--ceremony-dir', '/tmp/q01-final/ceremony',
    '--q01-pre-bundle', '/tmp/q01-final/q01-pre',
    '--expected-commit', GIT_COMMIT,
    '--expected-tree', GIT_TREE,
    '--output-dir', output,
  ];
}

test('Q-01 final replay CLI accepts only the exact absolute public interface', () => {
  const parsed = parseV2Q01FinalArtifactReplayArguments(validArguments());
  assert.equal(parsed.releaseRootId, ROOT_ID);
  assert.equal(parsed.expectedCommit, GIT_COMMIT);
  assert.throws(
    () => parseV2Q01FinalArtifactReplayArguments([
      ...validArguments(),
      '--test-only',
      'true',
    ]),
    V2Q01FinalArtifactReplayError,
  );
  assert.throws(
    () => parseV2Q01FinalArtifactReplayArguments(
      validArguments().map((entry) =>
        entry === '/tmp/q01-final/profile.json' ? 'relative.json' : entry),
    ),
    /absolute normalized path/u,
  );
});

test('Q-01 TEST-ONLY replay validates the complete fixture but is visibly nonqualifying', async () => {
  const state = await scenario();
  try {
    const result = await runV2Q01FinalArtifactReplayForTest(
      state.options,
      state.dependencies,
    );
    assert.equal(result.schema, V2_Q01_FINAL_REPLAY_TEST_SCHEMA);
    assert.equal(result.q01FinalReplayQualified, false);
    assert.equal(result.testOnly, true);
    assert.equal(result.production, false);
    assert.equal(result.releaseQualified, false);
    assert.deepEqual(
      result.replay.implementationIds,
      ['typescript', 'rust', 'circuit', 'covenant'],
    );
    assert.equal(result.q01Pre.counters.stateMutations, 32_640);
    assert.equal(result.q01Pre.counters.packetMutations, 140_760);
    assert.equal(result.q01Pre.counters.publicInputVectors, 88_727);
    const files = readdirSync(state.options.outputDirectory);
    assert.deepEqual(
      files,
      ['q01-final-artifact-replay-test-only.json'],
    );
    const artifactPath = join(state.options.outputDirectory, files[0]);
    assert.equal(statSync(state.options.outputDirectory).mode & 0o777, 0o700);
    assert.equal(statSync(artifactPath).mode & 0o777, 0o600);
    const bytes = readFileSync(artifactPath);
    const artifact = JSON.parse(bytes);
    assert.equal(bytes.toString('utf8'), canonicalizeJcs(artifact));
    revalidateV2Q01FinalArtifactReplayTestResultForTestOnly(artifact);
    assert.throws(
      () => revalidateV2Q01FinalArtifactReplayResult(artifact),
      /claim boundary/u,
    );
  } finally {
    dispose(state);
  }
});

test('public Q-01 runner rejects every injected verifier seam', async () => {
  const state = await scenario();
  try {
    await assert.rejects(
      () => runV2Q01FinalArtifactReplay(
        state.options,
        state.dependencies,
      ),
      /refuses injected dependencies, fixtures, or test doubles/u,
    );
    assert.equal(readdirSync(state.root).includes('result'), false);
  } finally {
    dispose(state);
  }
});

test('Q-01 final replay rejects wrong root, source, D-01, and runtime claims', async (t) => {
  await t.test('wrong compiled release root', async () => {
    const state = await scenario();
    try {
      state.options.releaseRootId = 'different-final-root';
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /release root differs/u,
      );
    } finally { dispose(state); }
  });
  await t.test('wrong source commit', async () => {
    const state = await scenario();
    try {
      state.options.expectedCommit = '9'.repeat(40);
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /reproduced source identity differ/u,
      );
    } finally { dispose(state); }
  });
  await t.test('self-resealed D-01 transcript drift', async () => {
    const state = await scenario();
    try {
      state.d01.transcriptSha256 = hash('different-transcript');
      writeJcs(state.paths.d01, state.d01);
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /post-ceremony binding differs at transcriptSha256/u,
      );
    } finally { dispose(state); }
  });
  await t.test('caller-supplied D-01 result cannot replace independently revalidated ceremony evidence', async () => {
    const state = await scenario();
    try {
      const forged = clone(state.d01);
      forged.ceremonyInventorySha256 = hash('forged-ceremony-inventory');
      writeJcs(state.paths.d01, forged);
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /differs from independently revalidated ceremony evidence/u,
      );
    } finally { dispose(state); }
  });
  await t.test('verified profile metadata must bind the selected compiled root', async () => {
    const state = await scenario();
    try {
      state.release.releaseRootId = 'different-final-root';
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /selected final release root metadata differs/u,
      );
    } finally { dispose(state); }
  });
  await t.test('development-key runtime claim', async () => {
    const state = await scenario();
    try {
      state.runtime.claims.developmentKey = true;
      state.runtime.claims.finalKey = false;
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /requires final-key, ceremony-qualified/u,
      );
    } finally { dispose(state); }
  });
});

test('Q-01 final replay rejects self-resealed semantic, packet, public-input, and topology drift', async (t) => {
  const mutations = [
    [
      'semantic vector count',
      (qualification) => {
        qualification.agreement.stateMutations += 1;
      },
      /implementation lanes disagree|agreement differs|mutation totals/u,
    ],
    [
      'packet bytes',
      (qualification) => resealLaneOutput(
        qualification,
        'circuit',
        (output) => { output.packetBytes += 1; },
      ),
      /compiled Circom codec\/public-limb vector output differs/u,
    ],
    [
      'public-input digest',
      (qualification) => resealLaneOutput(
        qualification,
        'circuit',
        (output) => { output.digestHex = hash('drifted-public-input'); },
      ),
      /compiled Circom codec\/public-limb vector output differs/u,
    ],
    [
      'covenant topology set',
      (qualification) => resealLaneOutput(
        qualification,
        'covenant',
        (output) => { output.topologies.reverse(); },
      ),
      /BCH covenant digest-reconstruction output differs/u,
    ],
  ];
  for (const [label, mutate, pattern] of mutations) {
    await t.test(label, async () => {
      const state = await scenario();
      try {
        const tampered = join(state.root, `q01-${label.replaceAll(' ', '-')}`);
        cpSync(state.q01Bundle, tampered, { recursive: true });
        chmodSync(tampered, 0o700);
        for (const name of readdirSync(tampered)) {
          chmodSync(join(tampered, name), 0o600);
        }
        resealQ01Qualification(tampered, mutate);
        state.options.q01PreBundle = tampered;
        await assert.rejects(
          () => runV2Q01FinalArtifactReplayForTest(
            state.options,
            state.dependencies,
          ),
          pattern,
        );
      } finally { dispose(state); }
    });
  }
});

test('Q-01 final replay independently rejects a self-resealed relation manifest drift', async () => {
  const state = await scenario();
  try {
    state.relationDocument.sources[0].sha256 =
      hash('self-resealed-different-relation-source');
    writeJcs(state.paths.relation, state.relationDocument);
    const relationSha256 = sha256(canonical(state.relationDocument));
    state.runtime.finalBuildEvidence.relationSourceManifestSha256 =
      relationSha256;
    state.descriptor.artifacts.set(
      'final-relation-source-manifest',
      { filename: state.paths.relation, sha256: relationSha256 },
    );
    state.descriptorDocument.relationSha256 = relationSha256;
    syncDescriptorAndD01(state);
    await assert.rejects(
      () => runV2Q01FinalArtifactReplayForTest(
        state.options,
        state.dependencies,
      ),
      /frozen relation source drift/u,
    );
  } finally {
    dispose(state);
  }
});

test('Q-01 final replay requires the relation artifact ID selected by final runtime material', async () => {
  const state = await scenario();
  try {
    const relation = state.descriptor.artifacts.get('final-relation-source-manifest');
    state.descriptor.artifacts.delete('final-relation-source-manifest');
    state.descriptor.artifacts.set('same-hash-wrong-role', relation);
    await assert.rejects(
      () => runV2Q01FinalArtifactReplayForTest(
        state.options,
        state.dependencies,
      ),
      /artifact identity or hash is invalid/u,
    );
  } finally {
    dispose(state);
  }
});

test('Q-01 final replay rejects descriptor signature drift even when wrapper hashes are resealed', async () => {
  const state = await scenario();
  try {
    state.descriptorDocument.signature = 'attacker-self-resealed-signature';
    syncDescriptorAndD01(state);
    await assert.rejects(
      () => runV2Q01FinalArtifactReplayForTest(
        state.options,
        state.dependencies,
      ),
      /descriptor signature mismatch/u,
    );
  } finally {
    dispose(state);
  }
});

test('Q-01 final replay rejects symlinks, unsafe modes, and preexisting output', async (t) => {
  await t.test('profile mode', async () => {
    const state = await scenario();
    try {
      chmodSync(state.paths.profile, 0o644);
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /mode-600/u,
      );
    } finally { dispose(state); }
  });
  await t.test('descriptor symlink', async () => {
    const state = await scenario();
    try {
      const link = join(state.root, 'descriptor-link.json');
      symlinkSync(state.paths.descriptor, link);
      state.options.descriptorPath = link;
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /single-link file/u,
      );
    } finally { dispose(state); }
  });
  await t.test('Q-01 bundle mode', async () => {
    const state = await scenario();
    try {
      chmodSync(state.q01Bundle, 0o755);
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /mode-700/u,
      );
    } finally { dispose(state); }
  });
  await t.test('preexisting output', async () => {
    const state = await scenario();
    try {
      privateDirectory(state.options.outputDirectory);
      const sentinel = join(state.options.outputDirectory, 'sentinel');
      writeFileSync(sentinel, 'do not overwrite', { mode: 0o600 });
      await assert.rejects(
        () => runV2Q01FinalArtifactReplayForTest(
          state.options,
          state.dependencies,
        ),
        /refuses a preexisting output directory/u,
      );
      assert.deepEqual(
        readdirSync(state.options.outputDirectory),
        ['sentinel'],
      );
    } finally { dispose(state); }
  });
});

test('Q-01 result revalidation rejects self-resealed claim and pin tampering', async () => {
  const state = await scenario();
  try {
    const result = await runV2Q01FinalArtifactReplayForTest(
      state.options,
      state.dependencies,
    );
    const artifact = JSON.parse(readFileSync(result.artifactPath, 'utf8'));
    const claim = clone(artifact);
    claim.production = true;
    assert.throws(
      () => revalidateV2Q01FinalArtifactReplayTestResultForTestOnly(claim),
      /claim boundary/u,
    );
    const relation = clone(artifact);
    relation.finalRelation.relationSourceManifestSha256 =
      hash('different-relation-pin');
    relation.d01.artifactSha256 = hash(canonical(relation.finalRelation));
    assert.throws(
      () => revalidateV2Q01FinalArtifactReplayTestResultForTestOnly({
        ...relation,
        unexpected: true,
      }),
      /missing or unknown properties/u,
    );
    assert.equal(V2_Q01_FINAL_REPLAY_SCHEMA.includes('test-only'), false);
  } finally {
    dispose(state);
  }
});

test('public Q-01 runner fails closed before inputs and writes one bounded 0600 failure', async () => {
  const state = await scenario();
  try {
    await assert.rejects(
      () => runV2Q01FinalArtifactReplay(state.options),
      /no approved V2 Direct final release roots|not approved/u,
    );
    assert.deepEqual(readdirSync(state.options.outputDirectory), ['failure.json']);
    const path = join(state.options.outputDirectory, 'failure.json');
    const failure = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(failure.schema, V2_Q01_FINAL_REPLAY_SCHEMA);
    assert.equal(failure.q01FinalReplayQualified, false);
    assert.equal(failure.production, false);
    assert.equal(failure.releaseQualified, false);
    assert.equal(failure.reason.length <= 2048, true);
    assert.equal(statSync(state.options.outputDirectory).mode & 0o777, 0o700);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(
      readFileSync(path, 'utf8'),
      canonicalizeJcs(failure),
    );
  } finally {
    dispose(state);
  }
});
