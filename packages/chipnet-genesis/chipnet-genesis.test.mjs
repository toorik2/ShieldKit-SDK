import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {
  createVirtualMachineBch2026,
  encodeTokenPrefix,
  instantiateSecp256k1,
} from '@bitauth/libauth';
import { buildVerifierProfileBundle } from '../profile-builder/profile-builder.mjs';
import {
  derivePf7SettlementKernelAuthority,
  encodeCanonicalPf7CarrierSourceSet,
} from '../core/pf7-authority.mjs';
import {
  ChipnetGenesisError,
  finalizeChipnetGenesisTransaction,
  planChipnetGenesisTransaction,
} from './chipnet-genesis.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const digest = (value) => `sha256:${sha256(value)}`;
const hex = (value) => Buffer.from(value).toString('hex');

function verifierSet() {
  const scripts = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'].map((name, index) => ({
    name,
    redeemBytecodeHex: Buffer.from([0x51, index + 1]).toString('hex'),
    lockingBytecodeHex: `aa20${sha256(createHash('sha256').update(Buffer.from([0x51, index + 1])).digest())}87`,
    sourceValueSatoshis: String(1_000 + index),
  }));
  const sourceSet = encodeCanonicalPf7CarrierSourceSet(scripts);
  const settlementKernel = derivePf7SettlementKernelAuthority(scripts.map((script) => ({
    role: script.name,
    lockingBytecode: Buffer.from(script.lockingBytecodeHex, 'hex'),
    valueSatoshis: BigInt(script.sourceValueSatoshis),
  }))).artifact;
  return Buffer.from(JSON.stringify({
    schema: 'shield.cash/bch-verifier-set/v1',
    settlementKernel,
    sourceSet: { encoding: 'libauth-transaction-outputs-v1', carrierCount: 7, sha256: digest(sourceSet) },
    scripts,
  }));
}

async function fixture(t) {
  const root = await mkdtemp(path.join(process.cwd(), '.shield-cash-chipnet-genesis-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inputTxid = sha256('profile-bound-category-input');
  const files = {
    'bch-verifier-set': ['bch-verifier-set', 'artifacts/verifier-set.json', verifierSet()],
    'constraint-system': ['constraint-system', 'artifacts/constraints.r1cs', Buffer.from('TEST-ONLY constraints')],
    'proving-key': ['proving-key', 'artifacts/proving.zkey', Buffer.from('TEST-ONLY proving key')],
    'public-input-abi': ['public-input-abi', 'artifacts/abi.json', Buffer.from('{"testOnly":true}')],
    'relation-definition': ['relation-definition', 'artifacts/relation.circom', Buffer.from('TEST-ONLY relation')],
    'verification-key': ['verification-key', 'artifacts/vk.json', Buffer.from('TEST-ONLY verification key')],
    'witness-generator': ['witness-generator', 'artifacts/witness.wasm', Buffer.from('TEST-ONLY witness generator')],
  };
  const source = path.join(root, 'source');
  for (const [, relative, contents] of Object.values(files)) {
    const filename = path.join(source, relative); await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, contents);
  }
  const compiler = path.join(source, 'toolchain/compiler'); const generator = path.join(source, 'toolchain/generator');
  await mkdir(path.dirname(compiler), { recursive: true }); await writeFile(compiler, 'TEST-ONLY compiler'); await writeFile(generator, 'TEST-ONLY generator');
  const bundle = await buildVerifierProfileBundle({
    destination: path.join(root, 'bundle'),
    profile: { proofSystem: 'groth16', curve: 'bn254', relation: { id: 'shielded-action-v2' }, publicInputAbi: { id: 'shielded-action-public-input-v1' } },
    setup: { mode: 'development-only', provenance: { method: 'local-initialization', initializerCommitment: digest('initializer') }, material: { phase1: { ptauSource: 'test-only-ptau', ptauSha256: digest('ptau') }, phase2: { initializationCommand: { argv: ['test', 'init'] }, contributionCommand: { argv: ['test', 'contribute'] }, randomnessCommitment: digest('randomness'), finalZkeySha256: digest(files['proving-key'][2]) } } },
    toolchain: { compiler: { name: 'test-compiler', version: '0', source: { sourcePath: compiler } }, generator: { name: 'test-generator', version: '0', source: { sourcePath: generator } } },
    network: { name: 'chipnet' },
    artifacts: Object.entries(files).map(([id, [kind, relative]]) => ({ id, kind, path: relative, source: { sourcePath: path.join(source, relative) } })),
    genesis: { categoryInputOutpoint: { txid: inputTxid, vout: '0' }, reserveCapSatoshis: '10000000' },
  });
  const secp = await instantiateSecp256k1(); const privateKey = Buffer.alloc(32, 7); const publicKey = secp.derivePublicKeyCompressed(privateKey);
  assert.notEqual(typeof publicKey, 'string');
  const request = {
    bundleDirectory: bundle.directory,
    expectedProfile: { network: 'chipnet', profileId: bundle.profileId, instanceId: bundle.instanceId },
    bindingCarrierBaseSatoshis: '1000', stateCarrierBaseSatoshis: '1080', minimumFeeRateSatoshisPerByte: '1',
    categoryInput: { outpointTransactionHashWire: hex(Buffer.from(inputTxid, 'hex').reverse()), outpointIndex: '0', publicKey: hex(publicKey), lockingBytecode: `76a914${createHash('ripemd160').update(createHash('sha256').update(publicKey).digest()).digest('hex')}88ac`, token: null, valueSatoshis: '25000000' },
  };
  return { request, privateKey, secp };
}

test('constructs a deterministic exact-fee state-NFT genesis and validates the real P2PKH BCH-2026 input', async (t) => {
  const { request, privateKey, secp } = await fixture(t);
  const plan = await planChipnetGenesisTransaction(request);
  assert.equal(plan.unsignedTransaction.inputs[0].unlockingBytecode.length, 0);
  assert.equal(plan.measurements.feeRateSatoshisPerByte, '1');
  assert.equal(plan.measurements.wireBytes, 397);
  assert.equal(plan.measurements.stateNftCommitmentBytes, 80);
  assert.ok(plan.measurements.stateLockingBytecodeBytes <= 190);
  assert.deepEqual(plan.blockers, []);
  const signature = secp.signMessageHashSchnorr(privateKey, Buffer.from(plan.signing.signingDigestHex, 'hex'));
  assert.notEqual(typeof signature, 'string');
  const finalized = await finalizeChipnetGenesisTransaction(request, hex(signature));
  assert.equal(finalized.measurements.bch2026StandardP2pkhVmAccepted, true);
  assert.equal(finalized.measurements.feeSatoshis, String(finalized.measurements.wireBytes));
  assert.equal(finalized.transaction.outputs.length, 2);
  assert.equal(finalized.transaction.outputs[0].valueSatoshis, 1080n);
  assert.equal(finalized.transaction.outputs[0].token.amount, 0n);
  assert.equal(finalized.transaction.outputs[0].token.nft.capability, 'mutable');
  assert.equal(encodeTokenPrefix(finalized.transaction.outputs[0].token).length, 115);
  assert.equal(finalized.transactionId.length, 64);
  const mutated = structuredClone(finalized.transaction); mutated.outputs[1].valueSatoshis -= 1n;
  assert.notEqual(createVirtualMachineBch2026(true).verify({ sourceOutputs: [{ valueSatoshis: 25_000_000n, lockingBytecode: finalized.sourceOutput.lockingBytecode ? Buffer.from(finalized.sourceOutput.lockingBytecode, 'hex') : undefined }], transaction: mutated }), true);
});

test('fails closed on category, fee, token, signature, and carrier-base mutations', async (t) => {
  const { request, privateKey, secp } = await fixture(t);
  await assert.rejects(() => planChipnetGenesisTransaction({ ...request, minimumFeeRateSatoshisPerByte: '2' }), ChipnetGenesisError);
  await assert.rejects(() => planChipnetGenesisTransaction({ ...request, bindingCarrierBaseSatoshis: '0' }), ChipnetGenesisError);
  await assert.rejects(() => planChipnetGenesisTransaction({ ...request, categoryInput: { ...request.categoryInput, token: { category: '00'.repeat(32) } } }), ChipnetGenesisError);
  await assert.rejects(() => planChipnetGenesisTransaction({ ...request, categoryInput: { ...request.categoryInput, outpointTransactionHashWire: '00'.repeat(32) } }), ChipnetGenesisError);
  const plan = await planChipnetGenesisTransaction(request);
  const signature = secp.signMessageHashSchnorr(privateKey, Buffer.from(plan.signing.signingDigestHex, 'hex'));
  assert.notEqual(typeof signature, 'string');
  const bad = Buffer.from(signature); bad[0] ^= 1;
  await assert.rejects(() => finalizeChipnetGenesisTransaction(request, hex(bad)), ChipnetGenesisError);
});
