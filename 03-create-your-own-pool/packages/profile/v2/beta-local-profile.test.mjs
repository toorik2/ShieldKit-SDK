import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  canonicalizeJcs,
  deriveProfileId,
  V2_PROFILE_DOMAINS,
} from './profile-core.mjs';
import {
  createV2BetaLocalProfilePackage,
  deriveV2BetaLocalInstanceId,
  deriveV2BetaLocalProfileCore,
  validateV2BetaLocalProfilePackage,
  V2_BETA_LOCAL_ELIGIBILITY,
  V2BetaLocalProfileError,
} from './beta-local-profile.mjs';

const hash = (byte) => byte.repeat(64);
const core = () => ({
  schema: 'shieldkit-profile-core-v2-direct',
  network: { id: 2, name: 'chipnet' },
  denominationSats: '10000000',
  proof: {
    system: 'groth16', curve: 'bn254', relationId: 'shieldkit-pool-action-v2-direct',
    relationSha256: hash('1'), r1csSha256: hash('2'),
    verificationKeySha256: hash('3'), witnessWasmSha256: hash('4'),
  },
  trees: {
    note: { id: 'shieldkit-note-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-note-leaf-v2' },
    nullifier: { id: 'shieldkit-indexed-nullifier-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2' },
  },
  crypto: {
    babyJubCurveId: 'circomlib-babyjub-base8',
    poseidonId: 'circomlib-poseidon-bn254',
    domains: { ...V2_PROFILE_DOMAINS },
  },
  encodings: {
    state: 'shieldkit-pool-state-sks2-native128', packet: 'shieldkit-direct-action-sda2-552',
    address: 'shieldkit-address-v2-direct', record: 'shieldkit-note-record-v2-direct-128',
    unlock: 'shieldkit-rolling-bundle-unlock-v2-direct',
  },
  publicInputAbi: { id: 'shieldkit-sda2-sha256-be-u128x2', count: 2, limbBits: 128, digest: 'sha256' },
  baseVerifierArtifacts: [{ id: 'carrier-base', sha256: hash('5') }],
  toolchain: [{ name: 'snarkjs', version: '0.7.6', sha256: hash('6') }],
});

test('beta local instance identity is deterministic and domain bound', () => {
  const value = fixture();
  const input = {
    profileId: value.packageValue.profileId,
    ceremonyResultSha256: value.ceremony.resultSha256,
  };
  const instanceId = deriveV2BetaLocalInstanceId(input);
  assert.match(instanceId, /^[0-9a-f]{64}$/u);
  assert.equal(deriveV2BetaLocalInstanceId(input), instanceId);
  assert.notEqual(
    deriveV2BetaLocalInstanceId({
      ...input,
      ceremonyResultSha256: `sha256:${hash('e')}`,
    }),
    instanceId,
  );
});

const artifact = (path, sha256) => ({ bytes: 1, path, sha256 });

function fixture() {
  const base = core();
  const beta = deriveV2BetaLocalProfileCore({
    baseProfileCore: base,
    verificationKeySha256: hash('9'),
  });
  const ceremony = {
    ceremonyId: 'shieldkit-v2-beta-r3',
    b01ManifestSha256: `sha256:${hash('a')}`,
    preparationSha256: `sha256:${hash('b')}`,
    resultSha256: `sha256:${hash('c')}`,
    transcriptSha256: `sha256:${hash('d')}`,
    circuitSymbolsSha256: `sha256:${hash('7')}`,
    initialZkeySha256: `sha256:${hash('0')}`,
    powersOfTauSha256: `sha256:${hash('f')}`,
    betaProvingKeySha256: `sha256:${hash('8')}`,
    verificationKeySha256: `sha256:${hash('9')}`,
    source: { gitCommit: '1'.repeat(40), gitTree: '2'.repeat(40) },
  };
  const artifacts = {
    r1cs: artifact('proof/main.r1cs', hash('2')),
    witnessWasm: artifact('proof/main.wasm', hash('4')),
    circuitSymbols: artifact('proof/main.sym', hash('7')),
    initialZkey: artifact('provenance/initial.zkey', hash('0')),
    powersOfTau: artifact('provenance/powers.ptau', hash('f')),
    betaProvingKey: artifact('proof/beta.zkey', hash('8')),
    verificationKey: artifact('proof/verification-key.json', hash('9')),
  };
  const baseBytes = Buffer.from(canonicalizeJcs(base));
  const b01Manifest = {
    schema: 'shieldkit-v2-direct-b01-pre-freeze-v1',
    status: 'b01-pre-freeze-candidate-awaiting-independent-review',
    b01PreFreezeCandidate: true,
    reviewed: false,
    ceremonyAuthorized: false,
    production: false,
    releaseQualified: false,
    localOnly: true,
    preCeremony: true,
    claims: {
      developmentKey: true, finalKey: false, bchVm: false,
      production: false, releaseQualified: false,
    },
    source: { ...ceremony.source, repositoryRoot: '/fixture' },
    profile: {
      profileId: deriveProfileId(base),
      profileCoreSha256: createHash('sha256').update(baseBytes).digest('hex'),
      relationSha256: base.proof.relationSha256,
      r1csSha256: base.proof.r1csSha256,
      witnessWasmSha256: base.proof.witnessWasmSha256,
      verificationKeySha256: base.proof.verificationKeySha256,
    },
    runtime: {
      proofArtifacts: {
        circuitSymbols: artifacts.circuitSymbols.sha256,
        initialProvingKey: artifacts.initialZkey.sha256,
        powersOfTau: artifacts.powersOfTau.sha256,
        r1cs: artifacts.r1cs.sha256,
        verificationKey: base.proof.verificationKeySha256,
        witnessWasm: artifacts.witnessWasm.sha256,
      },
    },
    packetAbi: {},
    q01Pre: {},
    topology: {},
    boundaries: [],
  };
  ceremony.b01ManifestSha256 = `sha256:${createHash('sha256')
    .update(canonicalizeJcs(b01Manifest)).digest('hex')}`;
  const packageValue = createV2BetaLocalProfilePackage({
    baseProfileCore: base,
    b01Manifest,
    profileCore: beta.profileCore,
    profileCoreSha256: beta.profileCoreSha256,
    ceremony,
    artifacts,
  });
  return { base, beta, b01Manifest, ceremony, artifacts, packageValue };
}

test('beta profile changes only the VK commitment and is self-verifying', () => {
  const value = fixture();
  assert.notEqual(value.beta.profileId, deriveProfileId(value.base));
  assert.equal(value.beta.profileCore.proof.verificationKeySha256, hash('9'));
  const normalizedBase = structuredClone(value.base);
  normalizedBase.proof.verificationKeySha256 = hash('9');
  assert.equal(
    canonicalizeJcs(normalizedBase),
    canonicalizeJcs(value.beta.profileCore),
  );
  assert.equal(value.packageValue.eligibility, V2_BETA_LOCAL_ELIGIBILITY);
  assert.equal(value.packageValue.claims.betaSingleContributor, true);
  assert.equal(value.packageValue.claims.developmentKey, false);
  assert.equal(value.packageValue.claims.finalKey, false);
  assert.equal(
    canonicalizeJcs(validateV2BetaLocalProfilePackage(
      value.packageValue,
      value.beta.profileCore,
    )),
    canonicalizeJcs(value.packageValue),
  );
});

test('beta profile rejects promotion, artifact substitution, and unknown fields', () => {
  const { beta, packageValue } = fixture();
  const mutations = [
    (value) => { value.eligibility = 'development-only'; },
    (value) => { value.claims.finalKey = true; },
    (value) => { value.claims.production = true; },
    (value) => { value.artifacts.verificationKey.sha256 = hash('e'); },
    (value) => { value.artifacts.betaProvingKey.sha256 = hash('e'); },
    (value) => { value.artifacts.initialZkey.sha256 = hash('e'); },
    (value) => { value.artifacts.powersOfTau.sha256 = hash('e'); },
    (value) => { value.artifacts.circuitSymbols.sha256 = hash('e'); },
    (value) => { value.b01Manifest.profile.profileId = hash('e'); },
    (value) => { value.finalManifest = {}; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(packageValue);
    mutate(value);
    assert.throws(
      () => validateV2BetaLocalProfilePackage(value, beta.profileCore),
      V2BetaLocalProfileError,
    );
  }
});
