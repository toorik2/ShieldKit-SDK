import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { decodeActionPacket } from './packet.mjs';
import { createShieldedTransitionReference } from './transition.mjs';
import { loadVerifierProfileBundle } from '../profile/load.mjs';
import { generateFreshWitnessInputs } from './witness.mjs';

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

test('priorCycles continues actionSequence and note roots from completed history', async (t) => {
  const bundleDirectory = process.env.SHIELD_FRESH_WITNESS_TEST_BUNDLE
    || '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/.cache/profile-build-live/profile-bundle';
  let loaded;
  try {
    loaded = await loadVerifierProfileBundle(bundleDirectory);
  } catch {
    return t.skip('no authenticated development-only bundle available');
  }
  if (loaded.manifest.setup.mode !== 'development-only') return t.skip('bundle is not development-only');
  const expectedProfile = { network: 'chipnet', profileId: loaded.profileId, instanceId: loaded.instanceId };
  const digests0 = { deposit: hex(0x10), transfer: hex(0x11), withdrawal: hex(0x12) };
  const digests1 = { deposit: hex(0x20), transfer: hex(0x21), withdrawal: hex(0x22) };
  const first = await generateFreshWitnessInputs({
    bundleDirectory, expectedProfile, witnessSeed: hex(0x41), withdrawalScriptHash: hex(0x42),
    transactionContextDigests: digests0,
  });
  const second = await generateFreshWitnessInputs({
    bundleDirectory, expectedProfile, witnessSeed: hex(0x51), withdrawalScriptHash: hex(0x42),
    transactionContextDigests: digests1,
    priorCycles: [{ witnessSeed: hex(0x41), transactionContextDigests: digests0 }],
  });
  const d0 = decodeActionPacket(first.actions.withdrawal.actionPacket);
  const d1 = decodeActionPacket(second.actions.deposit.actionPacket);
  assert.equal(d0.postState.actionSequence, '3');
  assert.equal(d1.preState.actionSequence, '3');
  assert.equal(d1.preState.stateCommitment, d0.postState.stateCommitment);
  assert.equal(d1.preState.liveNoteCount, '0');
  assert.equal(second.priorCycleCount, 1);
  const reference = await createShieldedTransitionReference();
  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const value = second.actions[kind];
    const accepted = reference.transition({ ...value.action, publicInputs: value.publicInputs });
    assert.equal(accepted.actionPacket.toString('hex'), value.actionPacketHex);
  }
});

test('transferHops=0 builds deposit→withdrawal without transfer action', async (t) => {
  const bundleDirectory = process.env.SHIELD_FRESH_WITNESS_TEST_BUNDLE
    || '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/.cache/profile-build-live/profile-bundle';
  let loaded;
  try {
    loaded = await loadVerifierProfileBundle(bundleDirectory);
  } catch {
    return t.skip('no authenticated development-only bundle available');
  }
  if (loaded.manifest.setup.mode !== 'development-only') return t.skip('bundle is not development-only');
  const expectedProfile = { network: 'chipnet', profileId: loaded.profileId, instanceId: loaded.instanceId };
  const digests = { deposit: hex(0x81), transfer: hex(0x00), withdrawal: hex(0x83) };
  const result = await generateFreshWitnessInputs({
    bundleDirectory, expectedProfile, witnessSeed: hex(0x91), withdrawalScriptHash: hex(0x92),
    transactionContextDigests: digests, transferHops: 0,
  });
  assert.equal(result.transferHops, 0);
  assert.ok(result.actions.deposit);
  assert.ok(result.actions.withdrawal);
  assert.equal(result.actions.transfer, undefined);
  const dDep = decodeActionPacket(result.actions.deposit.actionPacket);
  const dWd = decodeActionPacket(result.actions.withdrawal.actionPacket);
  assert.equal(dDep.postState.liveNoteCount, '1');
  assert.equal(dWd.preState.stateCommitment, dDep.postState.stateCommitment);
  assert.equal(dWd.postState.liveNoteCount, '0');
  assert.equal(dWd.postState.actionSequence, '2'); // deposit + withdrawal only
  const reference = await createShieldedTransitionReference();
  for (const kind of ['deposit', 'withdrawal']) {
    const value = result.actions[kind];
    const accepted = reference.transition({ ...value.action, publicInputs: value.publicInputs });
    assert.equal(accepted.actionPacket.toString('hex'), value.actionPacketHex);
  }
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
