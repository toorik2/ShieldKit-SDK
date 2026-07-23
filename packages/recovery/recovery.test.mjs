import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  RECOVERY_RECORD_LAYOUT, RecoveryError, constructRecipientOutput, deriveRecipientAddress,
  deriveRecipientWallet, recoverRecipientOutput,
} from './recovery.mjs';
import { FR_MODULUS } from '../core/shielded-transition.mjs';

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
  const address = await deriveRecipientAddress({ seed: recipientSeed, profileId, instanceId, addressIndex: 7 });
  const sent = await constructRecipientOutput({ address, kind: 'transfer', slot: 0, rng: publicRng() });
  return { profileId, instanceId, recipientSeed, address, sent };
}

test('sender constructs a recipient output from a public address only; recipient recovers it', async () => {
  const { profileId, instanceId, recipientSeed, address, sent } = await crossWalletFixture();
  assert.deepEqual(Object.keys(address).sort(), ['ak', 'instanceId', 'profileId', 'recoveryPublicKey', 'schema']);
  assert.equal(sent.record.length, RECOVERY_RECORD_LAYOUT.bytes);
  assert.deepEqual(Object.keys(sent.output).sort(), ['ak', 'cm', 'r', 'rho']);
  const recovered = await recoverRecipientOutput({ seed: recipientSeed, addressIndex: 7, profileId, instanceId, kind: 'transfer', slot: 0, output: sent.output, record: sent.record });
  assert.equal(recovered.ak, sent.output.ak); assert.equal(recovered.cm, sent.output.cm);
});

test('seed derivation is profile-instance-index separated and recovery requires the configured index', async () => {
  const seed = randomBytes(32); const profileId = id(); const instanceId = id();
  const first = await deriveRecipientWallet({ seed, profileId, instanceId, addressIndex: 0 });
  const second = await deriveRecipientWallet({ seed, profileId, instanceId, addressIndex: 1 });
  const otherProfile = await deriveRecipientWallet({ seed, profileId: id(), instanceId, addressIndex: 0 });
  const otherInstance = await deriveRecipientWallet({ seed, profileId, instanceId: id(), addressIndex: 0 });
  assert.notEqual(first.address.ak, second.address.ak); assert.notEqual(first.address.ak, otherProfile.address.ak); assert.notEqual(first.address.ak, otherInstance.address.ak);
  const sent = await constructRecipientOutput({ address: second.address, kind: 'deposit', slot: 0, rng: publicRng() });
  await assert.rejects(() => recoverRecipientOutput({ seed, addressIndex: 0, profileId, instanceId, kind: 'deposit', slot: 0, output: sent.output, record: sent.record }), /authority key/);
});

test('recovery rejects wrong seed, profile, instance, kind, slot, and commitment', async () => {
  const { profileId, instanceId, recipientSeed, sent } = await crossWalletFixture();
  const wrongSeed = randomBytes(32);
  const cases = [
    { seed: wrongSeed }, { profileId: id() }, { instanceId: id() }, { kind: 'deposit' }, { slot: 1 },
    { output: { ...sent.output, cm: id() } },
  ];
  for (const mutation of cases) {
    await assert.rejects(
      () => recoverRecipientOutput({ seed: recipientSeed, addressIndex: 7, profileId, instanceId, kind: 'transfer', slot: 0, output: sent.output, record: sent.record, ...mutation }),
      RecoveryError,
    );
  }
});

test('record authentication binds ephemeral key, nonce, tag, ciphertext, AAD, and zero padding', async () => {
  const { profileId, instanceId, recipientSeed, sent } = await crossWalletFixture();
  for (const offset of [2, 34, 46, 62, 190]) {
    const record = Buffer.from(sent.record); record[offset] ^= 1;
    await assert.rejects(
      () => recoverRecipientOutput({ seed: recipientSeed, addressIndex: 7, profileId, instanceId, kind: 'transfer', slot: 0, output: sent.output, record }),
      offset === 190 ? /padding/ : /authentication failed/,
    );
  }
});

test('strictly rejects noncanonical or zero fields, unknown properties, and CSPRNG failure', async () => {
  const { profileId, instanceId, recipientSeed, address, sent } = await crossWalletFixture();
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, ak: '0'.repeat(64) }, kind: 'deposit', slot: 0 }), /nonzero/);
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, ak: FR_MODULUS.toString(16).padStart(64, '0') }, kind: 'deposit', slot: 0 }), /noncanonical/);
  await assert.rejects(() => constructRecipientOutput({ address: { ...address, extra: true }, kind: 'deposit', slot: 0 }), /unknown/);
  await assert.rejects(() => deriveRecipientAddress({ seed: recipientSeed, profileId, instanceId, addressIndex: 0, extra: true }), /unknown/);
  await assert.rejects(() => constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng: { bytes: () => { throw new Error('unavailable'); } } }), /CSPRNG failed/);
  await assert.rejects(() => constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng: { bytes: () => Buffer.alloc(1) } }), /invalid byte string/);
  await assert.rejects(() => recoverRecipientOutput({ seed: recipientSeed, addressIndex: 7, profileId, instanceId, kind: 'transfer', slot: 0, output: { ...sent.output, rho: '0'.repeat(64) }, record: sent.record }), /nonzero/);
  await assert.rejects(() => deriveRecipientAddress({ seed: Buffer.alloc(31), profileId, instanceId, addressIndex: 0 }), /exactly 32/);
});
