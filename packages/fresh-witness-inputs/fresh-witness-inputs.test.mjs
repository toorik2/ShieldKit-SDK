import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { decodeActionPacket } from '../action-packet/action-packet.mjs';
import { createShieldedTransitionReference } from '../core/shielded-transition.mjs';
import { loadVerifierProfileBundle } from '../core/verifier-profile.mjs';
import { generateFreshWitnessInputs } from './fresh-witness-inputs.mjs';

const execFileAsync = promisify(execFile);
const hex = (byte) => Buffer.alloc(32, byte).toString('hex');

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
  await assert.rejects(
    () => generateFreshWitnessInputs({ bundleDirectory, expectedProfile: { ...expectedProfile, profileId: `sha256:${hex(0xff)}` }, witnessSeed: hex(0x41), withdrawalScriptHash: hex(0x42), transactionContextDigests: { deposit: hex(0x51), transfer: hex(0x52), withdrawal: hex(0x53) } }),
    /expected profile binding mismatch: refusing hot swap/,
  );
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
  const dNote = reference.deriveOutputNote({ ...deposit.action.outputNote, profileId: result.profile.profileId, instanceId: result.profile.instanceId });
  const tNote = reference.deriveOutputNote({ ...transfer.action.outputNote, profileId: result.profile.profileId, instanceId: result.profile.instanceId });
  assert.equal(dNote.cm, decodeActionPacket(deposit.actionPacket).outputCommitment);
  assert.equal(tNote.cm, decodeActionPacket(transfer.actionPacket).outputCommitment);
  assert.deepEqual(Object.keys(deposit.action.outputNote).sort(), ['ak', 'r', 'rho']);
  assert.deepEqual(Object.keys(transfer.action.outputNote).sort(), ['ak', 'r', 'rho']);
  assert.ok(result.actions.withdrawal.action.outputRecord.equals(Buffer.alloc(192)));
  const malformedWithdrawal = { ...result.actions.withdrawal.action, outputRecord: Buffer.alloc(192, 1) };
  assert.throws(() => reference.transition({ ...malformedWithdrawal, publicInputs: result.actions.withdrawal.publicInputs }), /inactive output record must be all zero/);
});

test('authenticated G1 WASM accepts all generated relation inputs when supplied with a pinned generator', async (t) => {
  const bundleDirectory = process.env.SHIELD_FRESH_WITNESS_TEST_BUNDLE; const wasm = process.env.SHIELD_FRESH_WITNESS_TEST_WASM; const generator = process.env.SHIELD_FRESH_WITNESS_TEST_GENERATOR;
  if (!bundleDirectory || !wasm || !generator) return t.skip('set SHIELD_FRESH_WITNESS_TEST_BUNDLE, SHIELD_FRESH_WITNESS_TEST_WASM, and SHIELD_FRESH_WITNESS_TEST_GENERATOR');
  assert.equal((await stat(wasm)).size, 9_977_099);
  const loaded = await loadVerifierProfileBundle(bundleDirectory);
  const witnessArtifact = loaded.manifest.artifacts.find((artifact) => artifact.kind === 'witness-generator');
  assert.ok(witnessArtifact);
  assert.equal(`sha256:${createHash('sha256').update(await readFile(wasm)).digest('hex')}`, witnessArtifact.sha256);
  assert.ok((await stat(generator)).isFile());
  const result = await generateFreshWitnessInputs({ bundleDirectory, expectedProfile: { network: 'chipnet', profileId: loaded.profileId, instanceId: loaded.instanceId }, witnessSeed: hex(0x61), withdrawalScriptHash: hex(0x62), transactionContextDigests: { deposit: hex(0x71), transfer: hex(0x72), withdrawal: hex(0x73) } });
  const root = await mkdtemp(path.join(tmpdir(), 'shield-fresh-witness-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [kind, value] of Object.entries(result.actions)) {
    const input = path.join(root, `${kind}.json`); const witness = path.join(root, `${kind}.wtns`);
    await writeFile(input, `${JSON.stringify(value.circuitInput)}\n`);
    await execFileAsync(process.execPath, [generator, wasm, input, witness]);
    assert.equal((await stat(witness)).size, 19_301_356);
  }
  assert.ok((await readFile(path.join(root, 'deposit.wtns'))).length > 0);
});
