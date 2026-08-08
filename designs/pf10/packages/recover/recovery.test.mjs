import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  RECOVERY_RECORD_LAYOUT, RecoveryError, constructRecipientOutput, deriveRecipientAddress,
  deriveRecipientWallet, prepareRecipientRecoveryAccount, recoverPreparedRecipientOutput, recoverRecipientOutput,
} from './recovery.mjs';
import {
  BABYJUB_BASE8, BABYJUB_SUBGROUP_ORDER, FR_MODULUS, babyJubMul, bytesToHex,
  deriveRecipientNote,
} from './portable-core.mjs';

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
  assert.deepEqual(Object.keys(address).sort(), ['ak', 'instanceId', 'profileId', 'recoveryPublicKey', 'schema', 'spendPublicKey']);
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
  assert.notEqual(first.spendSecret, first.recoverySecret);
  assert.notEqual(first.address.ak, otherSeed.address.ak); assert.notEqual(first.address.ak, otherProfile.address.ak); assert.notEqual(first.address.ak, otherInstance.address.ak);
  const sent = await constructRecipientOutput({ address: first.address, kind: 'deposit', slot: 0, rng: publicRng() });
  const chainOutput = { outputCommitment: sent.output.cm, record: sent.record };
  await assert.rejects(() => recoverRecipientOutput({ seed: randomBytes(32), profileId, instanceId, kind: 'deposit', slot: 0, ...chainOutput }), /authentication failed/);
  const wrongSpend = await deriveRecipientNote({ profileId, instanceId, spendSecret: first.recoverySecret, recoveryPublicKey: first.address.recoveryPublicKey, rho: sent.output.rho, r: sent.output.r });
  assert.notEqual(wrongSpend.cm, sent.output.cm);
});

test('prepared account opens repeated outputs without changing record semantics or accepting forged preparation', async () => {
  const { profileId, instanceId, recipientSeed, chainOutput } = await crossWalletFixture();
  const account = await prepareRecipientRecoveryAccount({ seed: recipientSeed, profileId, instanceId });
  const prepared = await recoverPreparedRecipientOutput({ account, kind: 'transfer', slot: 0, ...chainOutput });
  const ordinary = await recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, ...chainOutput });
  assert.deepEqual(prepared, ordinary);
  await assert.rejects(
    () => recoverPreparedRecipientOutput({ account: { ...account }, kind: 'transfer', slot: 0, ...chainOutput }),
    (error) => error instanceof RecoveryError && error.code === 'INVALID_PREPARED_ACCOUNT',
  );
});

test('recovery rejects wrong seed, profile, instance, kind, slot, and commitment', async () => {
  const { profileId, instanceId, recipientSeed, chainOutput } = await crossWalletFixture();
  const wrongSeed = randomBytes(32);
  const cases = [{ seed: wrongSeed }, { profileId: id() }, { instanceId: id() }, { kind: 'deposit' }, { slot: 1 }, { outputCommitment: id() }];
  for (const mutation of cases) await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, ...chainOutput, ...mutation }), RecoveryError);
});

test('record authentication binds recipient and ephemeral points, ciphertexts, tag, and zero padding', async () => {
  const { profileId, instanceId, recipientSeed, chainOutput } = await crossWalletFixture();
  for (const offset of [2, 34, 66, 98, 130]) {
    const record = Buffer.from(chainOutput.record); record[offset] ^= 1;
    await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: chainOutput.outputCommitment, record }), offset === 130 ? /padding/ : /authentication failed|point/);
  }
});

test('rejects noncanonical recovery ciphertext field encodings before opening', async () => {
  const { profileId, instanceId, recipientSeed, chainOutput } = await crossWalletFixture();
  const record = Buffer.from(chainOutput.record);
  Buffer.from(FR_MODULUS.toString(16).padStart(64, '0'), 'hex').copy(record, 34);
  await assert.rejects(
    () => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: chainOutput.outputCommitment, record }),
    /authentication failed/,
  );
});

test('does not serialize a stable recipient address point into two records', async () => {
  const { address } = await crossWalletFixture();
  const rng = publicRng();
  const first = await constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng });
  const second = await constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng });
  const addressPoint = Buffer.from(address.recoveryPublicKey, 'hex');
  assert.notDeepEqual(first.record.subarray(2, 34), second.record.subarray(2, 34));
  assert.notDeepEqual(first.record.subarray(2, 34), addressPoint);
  assert.notDeepEqual(second.record.subarray(2, 34), addressPoint);
  assert.deepEqual(first.record.subarray(130), new Uint8Array(62));
});

test('rejects an owned-address recovery record poisoned with another valid note secret', async () => {
  const { profileId, instanceId, recipientSeed, address } = await crossWalletFixture();
  const rng = publicRng();
  const first = await constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng });
  const second = await constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng });
  await assert.rejects(
    () => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'deposit', slot: 0, outputCommitment: first.output.cm, record: second.record }),
    /authentication failed|commitment does not match/,
  );
});

test('uses the unique BabyJubJub scalar representative required by the circuit', async () => {
  const { profileId, instanceId, recipientSeed, address } = await crossWalletFixture();
  const wallet = await deriveRecipientWallet({ seed: recipientSeed, profileId, instanceId });
  const sent = await constructRecipientOutput({ address, kind: 'transfer', slot: 0, rng: publicRng() });
  const scalar = BigInt(`0x${wallet.spendSecret}`); const alias = scalar + BABYJUB_SUBGROUP_ORDER;
  // The alias produces the same public key but would produce a different
  // nullifier if it were admitted as a note spend secret.
  assert.ok(alias < (1n << 253n));
  assert.deepEqual(babyJubMul(BABYJUB_BASE8, scalar), babyJubMul(BABYJUB_BASE8, alias));
  await assert.rejects(
    () => deriveRecipientNote({ profileId, instanceId, spendSecret: alias.toString(16).padStart(64, '0'), recoveryPublicKey: wallet.address.recoveryPublicKey, rho: sent.output.rho, r: sent.output.r }),
    /outside the BabyJubJub subgroup order/,
  );
});

test('strictly rejects noncanonical or zero fields, unknown properties, and CSPRNG failure', async () => {
  const { profileId, instanceId, recipientSeed, address, chainOutput } = await crossWalletFixture();
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, ak: '0'.repeat(64) }, kind: 'deposit', slot: 0 }), /nonzero/);
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, ak: FR_MODULUS.toString(16).padStart(64, '0') }, kind: 'deposit', slot: 0 }), /noncanonical/);
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, extra: true }, kind: 'deposit', slot: 0 }), /unknown/);
  const other = await deriveRecipientAddress({ seed: randomBytes(32), profileId, instanceId });
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, spendPublicKey: other.spendPublicKey }, kind: 'deposit', slot: 0 }), /does not bind/);
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, recoveryPublicKey: other.recoveryPublicKey }, kind: 'deposit', slot: 0 }), /does not bind/);
  await assert.rejects(() => deriveRecipientAddress({ seed: recipientSeed, profileId, instanceId, extra: true }), /unknown/);
  await assert.rejects(() => constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng: { bytes: () => { throw new Error('unavailable'); } } }), /CSPRNG failed/);
  await assert.rejects(() => constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng: { bytes: () => Buffer.alloc(1) } }), /invalid byte string/);
  await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: '0'.repeat(64), record: chainOutput.record }), /nonzero/);
  await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: FR_MODULUS.toString(16).padStart(64, '0'), record: chainOutput.record }), /noncanonical/);
  await assert.rejects(() => deriveRecipientAddress({ seed: Buffer.alloc(31), profileId, instanceId }), /exactly 32/);
});

test('pinned V2 vector is deterministic for an explicitly supplied CSPRNG stream', async () => {
  const seed = Buffer.from('11'.repeat(32), 'hex'); const profileId = '22'.repeat(32); const instanceId = '33'.repeat(32);
  const address = await deriveRecipientAddress({ seed, profileId, instanceId });
  const first = await constructRecipientOutput({ address, kind: 'transfer', slot: 0, rng: publicRng() });
  const second = await constructRecipientOutput({ address, kind: 'transfer', slot: 0, rng: publicRng() });
  assert.deepEqual(second.output, first.output); assert.deepEqual(second.record, first.record);
  assert.equal(first.record[0], 2); assert.equal(first.record.length, 192); assert.equal(bytesToHex(first.record).length, 384);
  const recovered = await recoverRecipientOutput({ seed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: first.output.cm, record: first.record });
  assert.equal(recovered.cm, first.output.cm);
});
