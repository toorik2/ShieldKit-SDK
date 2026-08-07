import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  lstat,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
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

const fixturePrerequisite = (message) => {
  throw new Error(`EXTERNAL_AUTHENTICATED_FIXTURE_REQUIRED: ${message}`);
};

async function authenticatedFixtureBundle() {
  const configuredRoot = process.env.SHIELD_EXTERNAL_FIXTURE_ROOT;
  const configuredBundle = process.env.SHIELD_FRESH_WITNESS_TEST_BUNDLE;
  if (typeof configuredRoot !== 'string' || configuredRoot.length === 0) {
    fixturePrerequisite(
      'set SHIELD_EXTERNAL_FIXTURE_ROOT to an absolute canonical fixture directory',
    );
  }
  if (typeof configuredBundle !== 'string' || configuredBundle.length === 0) {
    fixturePrerequisite(
      'set SHIELD_FRESH_WITNESS_TEST_BUNDLE to a bundle path relative to SHIELD_EXTERNAL_FIXTURE_ROOT',
    );
  }
  if (!path.isAbsolute(configuredRoot) || path.isAbsolute(configuredBundle)) {
    fixturePrerequisite(
      'SHIELD_EXTERNAL_FIXTURE_ROOT must be absolute and SHIELD_FRESH_WITNESS_TEST_BUNDLE must be relative',
    );
  }
  const root = path.resolve(configuredRoot);
  const rootMetadata = await lstat(root).catch(() =>
    fixturePrerequisite('SHIELD_EXTERNAL_FIXTURE_ROOT does not exist'));
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    fixturePrerequisite('SHIELD_EXTERNAL_FIXTURE_ROOT must be a real non-symlink directory');
  }
  const canonicalRoot = await realpath(root).catch(() =>
    fixturePrerequisite('SHIELD_EXTERNAL_FIXTURE_ROOT cannot be resolved'));
  if (canonicalRoot !== root) {
    fixturePrerequisite('SHIELD_EXTERNAL_FIXTURE_ROOT must not traverse symlinks');
  }
  const bundleDirectory = path.resolve(canonicalRoot, configuredBundle);
  if (
    bundleDirectory === canonicalRoot
    || !bundleDirectory.startsWith(`${canonicalRoot}${path.sep}`)
  ) {
    fixturePrerequisite('SHIELD_FRESH_WITNESS_TEST_BUNDLE must remain beneath SHIELD_EXTERNAL_FIXTURE_ROOT');
  }
  const loaded = await loadVerifierProfileBundle(bundleDirectory).catch((error) =>
    fixturePrerequisite(`SHIELD_FRESH_WITNESS_TEST_BUNDLE failed authenticated loading: ${error.message}`));
  assert.equal(
    loaded.manifest.setup.mode,
    'development-only',
    'authenticated external fixture must be development-only',
  );
  return Object.freeze({ bundleDirectory, fixtureRoot: canonicalRoot, loaded });
}

async function authenticatedFixtureFile(root, environmentName) {
  const configured = process.env[environmentName];
  if (typeof configured !== 'string' || configured.length === 0) {
    fixturePrerequisite(
      `set ${environmentName} to a file path relative to SHIELD_EXTERNAL_FIXTURE_ROOT`,
    );
  }
  if (path.isAbsolute(configured)) {
    fixturePrerequisite(`${environmentName} must be relative to SHIELD_EXTERNAL_FIXTURE_ROOT`);
  }
  const filename = path.resolve(root, configured);
  if (!filename.startsWith(`${root}${path.sep}`)) {
    fixturePrerequisite(`${environmentName} must remain beneath SHIELD_EXTERNAL_FIXTURE_ROOT`);
  }
  const metadata = await lstat(filename).catch(() =>
    fixturePrerequisite(`${environmentName} does not exist`));
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fixturePrerequisite(`${environmentName} must be a regular non-symlink file`);
  }
  const canonical = await realpath(filename).catch(() =>
    fixturePrerequisite(`${environmentName} cannot be resolved`));
  if (canonical !== filename || !canonical.startsWith(`${root}${path.sep}`)) {
    fixturePrerequisite(`${environmentName} must not traverse symlinks`);
  }
  return canonical;
}

test('fresh generator fails before loading a bundle when fixed-point inputs are malformed', async () => {
  await assert.rejects(
    () => generateFreshWitnessInputs({ bundleDirectory: '/not-loaded', expectedProfile: {}, witnessSeed: hex(1), withdrawalScriptHash: hex(2), transactionContextDigests: { deposit: hex(3), transfer: hex(4) } }),
    /expectedProfile has missing or unknown properties/,
  );
});

test('authenticated development profile produces relation-valid chained packets', async () => {
  const { bundleDirectory, loaded } = await authenticatedFixtureBundle();
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

test('priorCycles continues actionSequence and note roots from completed history', async () => {
  const { bundleDirectory, loaded } = await authenticatedFixtureBundle();
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

test('transferHops=0 builds deposit→withdrawal without transfer action', async () => {
  const { bundleDirectory, loaded } = await authenticatedFixtureBundle();
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
  const { bundleDirectory, fixtureRoot, loaded } = await authenticatedFixtureBundle();
  const wasm = await authenticatedFixtureFile(
    fixtureRoot,
    'SHIELD_FRESH_WITNESS_TEST_WASM',
  );
  const generator = await authenticatedFixtureFile(
    fixtureRoot,
    'SHIELD_FRESH_WITNESS_TEST_GENERATOR',
  );
  assert.equal((await stat(wasm)).size, 9_977_099);
  const witnessArtifact = loaded.manifest.artifacts.find((artifact) => artifact.kind === 'witness-generator');
  assert.ok(witnessArtifact);
  assert.equal(`sha256:${createHash('sha256').update(await readFile(wasm)).digest('hex')}`, witnessArtifact.sha256);
  assert.equal(
    `sha256:${createHash('sha256').update(await readFile(generator)).digest('hex')}`,
    loaded.manifest.toolchain.generator.sha256,
  );
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
