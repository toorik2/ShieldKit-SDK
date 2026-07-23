import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  RECOVERY_RECORD_LAYOUT, RecoveryError, constructRecipientOutput, deriveRecipientAddress,
  deriveRecipientWallet, recoverRecipientOutput,
} from './recovery.mjs';
import { NODE_CRYPTO_BACKEND } from './node-backend.mjs';
import { FR_MODULUS, NOBLE_CRYPTO_BACKEND, bytesToHex } from './portable-core.mjs';

const id = () => randomBytes(32).toString('hex');
const publicRng = () => {
  let counter = 1;
  return Object.freeze({ bytes(length) {
    const output = Buffer.alloc(length); output[output.length - 1] = counter++;
    return output;
  } });
};

async function crossWalletFixture() {
  const profileId = id(); const instanceId = id(); const recipientSeed = randomBytes(32);
  const address = await deriveRecipientAddress({ seed: recipientSeed, profileId, instanceId });
  const sent = await constructRecipientOutput({ address, kind: 'transfer', slot: 0, rng: publicRng() });
  return { profileId, instanceId, recipientSeed, address, senderWitness: sent.output, chainOutput: Object.freeze({ outputCommitment: sent.output.cm, record: sent.record }) };
}

test('sender constructs a recipient output from a public address only; recipient recovers it', async () => {
  const { profileId, instanceId, recipientSeed, address, senderWitness, chainOutput } = await crossWalletFixture();
  assert.deepEqual(Object.keys(address).sort(), ['ak', 'instanceId', 'profileId', 'recoveryPublicKey', 'schema']);
  assert.equal(chainOutput.record.length, RECOVERY_RECORD_LAYOUT.bytes);
  assert.deepEqual(Object.keys(senderWitness).sort(), ['ak', 'cm', 'r', 'rho']);
  const recovered = await recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, ...chainOutput });
  assert.equal(recovered.ak, senderWitness.ak); assert.equal(recovered.cm, chainOutput.outputCommitment);
});

test('account-static derivation is seed-profile-instance separated and rejects a different seed', async () => {
  const seed = randomBytes(32); const profileId = id(); const instanceId = id();
  const first = await deriveRecipientWallet({ seed, profileId, instanceId });
  const otherSeed = await deriveRecipientWallet({ seed: randomBytes(32), profileId, instanceId });
  const otherProfile = await deriveRecipientWallet({ seed, profileId: id(), instanceId });
  const otherInstance = await deriveRecipientWallet({ seed, profileId, instanceId: id() });
  assert.notEqual(first.address.ak, otherSeed.address.ak); assert.notEqual(first.address.ak, otherProfile.address.ak); assert.notEqual(first.address.ak, otherInstance.address.ak);
  const sent = await constructRecipientOutput({ address: first.address, kind: 'deposit', slot: 0, rng: publicRng() });
  const chainOutput = { outputCommitment: sent.output.cm, record: sent.record };
  await assert.rejects(() => recoverRecipientOutput({ seed: randomBytes(32), profileId, instanceId, kind: 'deposit', slot: 0, ...chainOutput }), /authentication failed/);
});

test('recovery rejects wrong seed, profile, instance, kind, slot, and commitment', async () => {
  const { profileId, instanceId, recipientSeed, chainOutput } = await crossWalletFixture();
  const wrongSeed = randomBytes(32);
  const cases = [{ seed: wrongSeed }, { profileId: id() }, { instanceId: id() }, { kind: 'deposit' }, { slot: 1 }, { outputCommitment: id() }];
  for (const mutation of cases) await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, ...chainOutput, ...mutation }), RecoveryError);
});

test('record authentication binds ephemeral key, nonce, tag, ciphertext, AAD, and zero padding', async () => {
  const { profileId, instanceId, recipientSeed, chainOutput } = await crossWalletFixture();
  for (const offset of [2, 34, 46, 62, 190]) {
    const record = Buffer.from(chainOutput.record); record[offset] ^= 1;
    await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: chainOutput.outputCommitment, record }), offset === 190 ? /padding/ : /authentication failed/);
  }
});

test('strictly rejects noncanonical or zero fields, unknown properties, and CSPRNG failure', async () => {
  const { profileId, instanceId, recipientSeed, address, chainOutput } = await crossWalletFixture();
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, ak: '0'.repeat(64) }, kind: 'deposit', slot: 0 }), /nonzero/);
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, ak: FR_MODULUS.toString(16).padStart(64, '0') }, kind: 'deposit', slot: 0 }), /noncanonical/);
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, extra: true }, kind: 'deposit', slot: 0 }), /unknown/);
  await assert.rejects(() => deriveRecipientAddress({ seed: recipientSeed, profileId, instanceId, extra: true }), /unknown/);
  await assert.rejects(() => constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng: { bytes: () => { throw new Error('unavailable'); } } }), /CSPRNG failed/);
  await assert.rejects(() => constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng: { bytes: () => Buffer.alloc(1) } }), /invalid byte string/);
  await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: '0'.repeat(64), record: chainOutput.record }), /nonzero/);
  await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: FR_MODULUS.toString(16).padStart(64, '0'), record: chainOutput.record }), /noncanonical/);
  await assert.rejects(() => deriveRecipientAddress({ seed: Buffer.alloc(31), profileId, instanceId }), /exactly 32/);
});

test('pinned V1 vector is byte-identical across noble portable and native Node crypto backends', async () => {
  const seed = Buffer.from('11'.repeat(32), 'hex'); const profileId = '22'.repeat(32); const instanceId = '33'.repeat(32);
  const nobleAddress = await deriveRecipientAddress({ seed, profileId, instanceId, cryptoBackend: NOBLE_CRYPTO_BACKEND });
  const nodeAddress = await deriveRecipientAddress({ seed, profileId, instanceId, cryptoBackend: NODE_CRYPTO_BACKEND });
  assert.deepEqual(nodeAddress, nobleAddress);
  const noble = await constructRecipientOutput({ address: nobleAddress, kind: 'transfer', slot: 0, rng: publicRng(), cryptoBackend: NOBLE_CRYPTO_BACKEND });
  const node = await constructRecipientOutput({ address: nodeAddress, kind: 'transfer', slot: 0, rng: publicRng(), cryptoBackend: NODE_CRYPTO_BACKEND });
  assert.deepEqual(node.output, noble.output); assert.deepEqual(node.record, noble.record);
  assert.deepEqual({ ak: nobleAddress.ak, recoveryPublicKey: nobleAddress.recoveryPublicKey, cm: noble.output.cm, record: bytesToHex(noble.record) }, {
    ak: '292e2214a0ac4c974c51da62cf838b6b437a6175fa99d94a9ea3a41e793b96ad',
    recoveryPublicKey: 'fd9061976a7672d40aca2fe76b53f911ee10e50822c6692f73ecad0fe6a09b71',
    cm: '063e21cd16cfd9d223ce681d25c12ec18e267c2c460014d38531624d24c0ddd1',
    record: '01009952fb7e5383c522c954de94f2e4620d3e08cd9e7248ad23207f9ef55c904144000000000000000000000004abca919bb84c7406fa480585a3de6604338b7436ac001d44752f692b755c89208c0551257d8c51e2e938704e1848d5b4fb9f22cb7a3ffdaf2c5052d663f2c16a3f72aa0db7998b3a7c96c3cc199e700f03bf22f6b5c0da386de988b80e4f0cb4afb59c43d01093748e97cb37130d098992af40b029608e79cea7c9ade5488dd25348d9340d10dd85b63aa1f4dcd63f650000',
  });
  const recovered = await recoverRecipientOutput({ seed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: noble.output.cm, record: node.record, cryptoBackend: NODE_CRYPTO_BACKEND });
  assert.equal(recovered.cm, noble.output.cm);
});
