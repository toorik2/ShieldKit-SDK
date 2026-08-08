import assert from 'node:assert/strict';
import test from 'node:test';

import { canonicalizeJcs, DENOMINATION_SATS, deriveProfileId, ProfileCoreError, validateProfileCore, V2_PROFILE_DOMAINS } from './profile-core.mjs';

const hash = (byte) => byte.repeat(64);
const core = () => ({
  schema: 'shieldkit-profile-core-v2-direct', network: { id: 2, name: 'chipnet' }, denominationSats: '10000000',
  proof: { system: 'groth16', curve: 'bn254', relationId: 'shieldkit-pool-action-v2-direct', relationSha256: hash('1'), r1csSha256: hash('2'), verificationKeySha256: hash('3'), witnessWasmSha256: hash('4') },
  trees: { note: { id: 'shieldkit-note-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-note-leaf-v2' }, nullifier: { id: 'shieldkit-indexed-nullifier-tree-v2-depth32', depth: 32, leafSchemaId: 'shieldkit-indexed-nullifier-leaf-v2' } },
  crypto: { babyJubCurveId: 'circomlib-babyjub-base8', poseidonId: 'circomlib-poseidon-bn254', domains: { ...V2_PROFILE_DOMAINS } },
  encodings: { state: 'shieldkit-pool-state-sks2-native128', packet: 'shieldkit-direct-action-sda2-552', address: 'shieldkit-address-v2-direct', record: 'shieldkit-note-record-v2-direct-128', unlock: 'shieldkit-rolling-bundle-unlock-v2-direct' },
  publicInputAbi: { id: 'shieldkit-sda2-sha256-be-u128x2', count: 2, limbBits: 128, digest: 'sha256' },
  baseVerifierArtifacts: [{ id: 'carrier-base', sha256: hash('5') }, { id: 'state-base', sha256: hash('6') }],
  toolchain: [{ name: 'circom', version: '2.2.3', sha256: hash('7') }, { name: 'snarkjs', version: '0.7.6', sha256: hash('8') }],
});

test('JCS key-order invariance and RFC 8785 string/number forms', () => {
  assert.equal(canonicalizeJcs({ b: 1, a: [true, null, '€'] }), '{"a":[true,null,"€"],"b":1}');
  assert.equal(canonicalizeJcs({ '\u20ac': '€', '\r': '\n', '😀': -0, x: 1e-7, y: 1e21 }), '{"\\r":"\\n","x":1e-7,"y":1e+21,"€":"€","😀":0}');
  assert.equal(canonicalizeJcs([1e-6, 1e-7, 1e20, 1e21, 333333333.33333329, 1e-27]), '[0.000001,1e-7,100000000000000000000,1e+21,333333333.3333333,1e-27]');
  assert.throws(() => canonicalizeJcs({ x: Number.NaN }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs({ x: Number.POSITIVE_INFINITY }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs({ x: undefined }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs({ x: 1n }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs({ x: Symbol('x') }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs([, 1]), ProfileCoreError);
  assert.throws(() => canonicalizeJcs({ x: '\ud800' }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs({ toJSON() {} }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs({ get x() { return 1; } }), ProfileCoreError);
  assert.throws(() => canonicalizeJcs(Object.create(null)), ProfileCoreError);
});

test('derives the fixed hash-cycle-free profile ID independent of property order', () => {
  const value = core(); const reordered = { toolchain: value.toolchain, schema: value.schema, proof: value.proof, network: value.network, denominationSats: value.denominationSats, trees: value.trees, crypto: value.crypto, encodings: value.encodings, publicInputAbi: value.publicInputAbi, baseVerifierArtifacts: value.baseVerifierArtifacts };
  assert.equal(deriveProfileId(value), deriveProfileId(reordered));
  assert.equal(deriveProfileId(value), '4760d5456ee3b534313d99e9cbbd2f2881b33ca44b9d96ea4ab3791e123a6df5');
  assert.equal(validateProfileCore(value), value);
});

test('rejects denominations other than the relation-pinned 10000000 sats', () => {
  for (const denominationSats of ['0', '1', '9999999', '10000001', '2100000000000000']) {
    const value = core();
    value.denominationSats = denominationSats;
    assert.throws(() => validateProfileCore(value), new RegExp(`relation-pinned ${DENOMINATION_SATS}`));
  }
});

test('rejects all pinned schema, identifier, domain, hash, network, and order mutations', () => {
  const mutations = [
    (v) => { v.schema = 'shieldkit-profile-v2-direct'; },
    (v) => { v.network = { id: 1, name: 'chipnet' }; },
    (v) => { v.denominationSats = '01'; },
    (v) => { v.proof.system = 'plonk'; }, (v) => { v.proof.curve = 'bls12-381'; }, (v) => { v.proof.relationId = 'shielded-action-v2'; },
    (v) => { v.trees.note.id = 'wrong'; }, (v) => { v.trees.note.depth = 31; }, (v) => { v.trees.note.leafSchemaId = ''; },
    (v) => { v.trees.nullifier.id = 'wrong'; }, (v) => { v.trees.nullifier.depth = 31; }, (v) => { v.trees.nullifier.leafSchemaId = ''; },
    (v) => { v.crypto.babyJubCurveId = 'wrong'; }, (v) => { v.crypto.poseidonId = 'wrong'; },
    (v) => { delete v.crypto.domains.RHO; },
    (v) => { v.publicInputAbi.id = 'wrong'; }, (v) => { v.publicInputAbi.count = 1; }, (v) => { v.publicInputAbi.limbBits = 64; }, (v) => { v.publicInputAbi.digest = 'blake2'; },
    (v) => { v.baseVerifierArtifacts.reverse(); }, (v) => { v.toolchain.reverse(); },
    (v) => { v.baseVerifierArtifacts[1].id = v.baseVerifierArtifacts[0].id; }, (v) => { v.toolchain[1].name = v.toolchain[0].name; },
  ];
  for (const key of ['relationSha256', 'r1csSha256', 'verificationKeySha256', 'witnessWasmSha256']) mutations.push((v) => { v.proof[key] = 'sha256:'.concat(hash('a')); });
  for (const key of Object.keys(V2_PROFILE_DOMAINS)) mutations.push((v) => { v.crypto.domains[key] = hash('f'); });
  for (const key of ['state', 'packet', 'address', 'record', 'unlock']) mutations.push((v) => { v.encodings[key] = 'wrong'; });
  for (const mutate of mutations) {
    const value = structuredClone(core()); mutate(value); assert.throws(() => validateProfileCore(value), ProfileCoreError);
  }
});

test('rejects hash-cycle and instantiated-script fields as unknown profile-core keys', () => {
  for (const key of ['profileId', 'instanceId', 'stateLockingBytecode', 'bindingLockingBytecode', 'instantiatedScripts']) {
    const value = core(); value[key] = '00'; assert.throws(() => deriveProfileId(value), /missing or unknown/);
  }
});
