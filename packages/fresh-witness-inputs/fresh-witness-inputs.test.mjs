import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { decodeActionPacket } from '../action-packet/action-packet.mjs';
import { createShieldedTransitionReference, frToHex } from '../core/shielded-transition.mjs';
import { loadVerifierProfileBundle } from '../core/verifier-profile.mjs';
import {
  decryptRecoveryRecord, encryptRecoveryRecord, generateFreshWitnessInputs,
} from './fresh-witness-inputs.mjs';

const execFileAsync = promisify(execFile);
const hex = (byte) => Buffer.alloc(32, byte).toString('hex');

test('recovery record is fixed-size authenticated X25519/ChaCha material', async () => {
  const reference = await createShieldedTransitionReference();
  const profileId = hex(0x11); const instanceId = hex(0x22);
  const raw = { sk: frToHex(11n), rho: frToHex(12n), r: frToHex(13n) };
  const note = reference.deriveNote({ ...raw, profileId, instanceId });
  const record = encryptRecoveryRecord({ kind: 'deposit', slot: 0, profileId, instanceId, outputNote: note, outputCm: note.cm, witnessSeed: hex(0x33) });
  assert.equal(record.length, 192);
  assert.deepEqual(decryptRecoveryRecord({ kind: 'deposit', slot: 0, profileId, instanceId, outputCm: note.cm, recipientNoteSecret: raw.sk, record }), { profileId, instanceId, rho: raw.rho, r: raw.r });
  const tampered = Buffer.from(record); tampered[62] ^= 1;
  assert.throws(() => decryptRecoveryRecord({ kind: 'deposit', slot: 0, profileId, instanceId, outputCm: note.cm, recipientNoteSecret: raw.sk, record: tampered }), /authentication failed/);
});

test('fresh generator fails before loading a bundle when fixed-point inputs are malformed', async () => {
  await assert.rejects(
    () => generateFreshWitnessInputs({ bundleDirectory: '/not-loaded', expectedProfile: {}, witnessSeed: hex(1), withdrawalScriptHash: hex(2), transactionContextDigests: { deposit: hex(3), transfer: hex(4) } }),
    /expectedProfile has missing or unknown properties/,
  );
});

test('authenticated development profile produces relation-valid chained packets', async (t) => {
  const bundleDirectory = process.env.SHIELD_FRESH_WITNESS_TEST_BUNDLE;
  if (!bundleDirectory) return t.skip('set SHIELD_FRESH_WITNESS_TEST_BUNDLE to an authenticated development-only bundle');
  const loaded = await loadVerifierProfileBundle(bundleDirectory);
  const expectedProfile = { network: 'chipnet', profileId: loaded.profileId, instanceId: loaded.instanceId };
  const result = await generateFreshWitnessInputs({ bundleDirectory, expectedProfile, witnessSeed: hex(0x41), withdrawalScriptHash: hex(0x42), transactionContextDigests: { deposit: hex(0x51), transfer: hex(0x52), withdrawal: hex(0x53) } });
  const reference = await createShieldedTransitionReference();
  assert.equal(result.profile.setupMode, 'development-only');
  for (const [kind, value] of Object.entries(result.actions)) {
    assert.equal(value.actionPacket.length, 752);
    const decoded = decodeActionPacket(value.actionPacket); assert.equal(decoded.kind, kind);
    const accepted = reference.transition({ ...value.action, publicInputs: value.publicInputs });
    assert.equal(accepted.actionPacket.toString('hex'), value.actionPacketHex);
    assert.equal(value.circuitInput.publicDigestHi, BigInt(`0x${value.publicInputs[0]}`).toString());
    assert.equal(value.circuitInput.publicDigestLo, BigInt(`0x${value.publicInputs[1]}`).toString());
  }
  const deposit = result.actions.deposit; const transfer = result.actions.transfer;
  const dNote = reference.deriveNote({ ...deposit.action.outputNote, profileId: result.profile.profileId, instanceId: result.profile.instanceId });
  const tNote = reference.deriveNote({ ...transfer.action.outputNote, profileId: result.profile.profileId, instanceId: result.profile.instanceId });
  assert.equal(decryptRecoveryRecord({ kind: 'deposit', slot: 0, profileId: result.profile.profileId, instanceId: result.profile.instanceId, outputCm: dNote.cm, recipientNoteSecret: dNote.sk, record: deposit.action.outputRecord }).rho, dNote.rho);
  assert.equal(decryptRecoveryRecord({ kind: 'transfer', slot: 0, profileId: result.profile.profileId, instanceId: result.profile.instanceId, outputCm: tNote.cm, recipientNoteSecret: tNote.sk, record: transfer.action.outputRecord }).r, tNote.r);
  assert.ok(result.actions.withdrawal.action.outputRecord.equals(Buffer.alloc(192)));
});

test('exact 9,977,099-byte G1 WASM accepts all generated relation inputs when supplied', async (t) => {
  const bundleDirectory = process.env.SHIELD_FRESH_WITNESS_TEST_BUNDLE; const wasm = process.env.SHIELD_FRESH_WITNESS_TEST_WASM;
  if (!bundleDirectory || !wasm) return t.skip('set SHIELD_FRESH_WITNESS_TEST_BUNDLE and SHIELD_FRESH_WITNESS_TEST_WASM');
  assert.equal((await stat(wasm)).size, 9_977_099);
  const loaded = await loadVerifierProfileBundle(bundleDirectory);
  const result = await generateFreshWitnessInputs({ bundleDirectory, expectedProfile: { network: 'chipnet', profileId: loaded.profileId, instanceId: loaded.instanceId }, witnessSeed: hex(0x61), withdrawalScriptHash: hex(0x62), transactionContextDigests: { deposit: hex(0x71), transfer: hex(0x72), withdrawal: hex(0x73) } });
  const root = await mkdtemp(path.join(tmpdir(), 'shield-fresh-witness-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const generator = path.join(path.dirname(wasm), 'generate_witness.js');
  for (const [kind, value] of Object.entries(result.actions)) {
    const input = path.join(root, `${kind}.json`); const witness = path.join(root, `${kind}.wtns`);
    await writeFile(input, `${JSON.stringify(value.circuitInput)}\n`);
    await execFileAsync(process.execPath, [generator, wasm, input, witness]);
    assert.equal((await stat(witness)).size, 19_301_356);
  }
  assert.ok((await readFile(path.join(root, 'deposit.wtns'))).length > 0);
});
