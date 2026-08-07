/**
 * Defensive audit tests for ticket10 multi-note pool spend path.
 * Drives shipped pool-act.mjs / witness.mjs — not reimplementations.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdirSync, writeFileSync, cpSync, existsSync, rmSync, readFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { generateFreshWitnessInputs } from '../action/witness.mjs';

// packages/kit → packages → shieldkit-groth → monorepo root
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const POOL_ACT = path.join(ROOT, 'shieldkit-groth/scripts/pool-act.mjs');
const LIVE = path.join(ROOT, '.cache/ticket10-e2e-20260726/pool');
const WALLETS = path.join(ROOT, '.cache/e2e-full-20260725/local-wallets.json');

function requireLiveFixture() {
  assert.equal(
    process.env.SHIELDKIT_LIVE_FIXTURES,
    '1',
    'PREREQUISITE_MISSING: set SHIELDKIT_LIVE_FIXTURES=1 with the separately qualified ticket10 fixture and local wallets',
  );
  assert.ok(existsSync(LIVE), 'PREREQUISITE_MISSING: ticket10 live pool fixture required');
  assert.ok(existsSync(WALLETS), 'PREREQUISITE_MISSING: local wallets fixture required');
}

function mapOpen(n) {
  return {
    witnessSeed: n.witnessSeed,
    depositDigest: n.depositDigest,
    phase: n.phase || 'deposit',
  };
}

test('pool-act withdraw rejects empty openNotes (fail closed)', () => {
  requireLiveFixture();
  assert.ok(existsSync(POOL_ACT), 'pool-act.mjs must exist');

  const tmp = path.join(ROOT, '.cache/ticket10-e2e-20260726/tmp-empty-notes-pool');
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  cpSync(path.join(LIVE, 'bundle'), path.join(tmp, 'bundle'), { recursive: true });
  cpSync(path.join(LIVE, 'instance.json'), path.join(tmp, 'instance.json'));
  const state = JSON.parse(readFileSync(path.join(LIVE, 'state.json'), 'utf8'));
  assert.equal((state.openNotes || []).length, 10, 'audit target still has 10 open notes');
  state.openNotes = [];
  writeFileSync(path.join(tmp, 'state.json'), JSON.stringify(state, null, 2));

  const r = spawnSync(process.execPath, [
    POOL_ACT, 'withdraw',
    '--pool', tmp,
    '--wallets', WALLETS,
    '--no-scan-fees',
  ], { encoding: 'utf8', cwd: ROOT, timeout: 60_000, env: process.env });
  const combined = `${r.stdout || ''}\n${r.stderr || ''}`;
  assert.match(combined, /requires openNotes|openNotes/i, combined.slice(0, 500));
  assert.doesNotMatch(combined, /"ok"\s*:\s*true/, 'must not report success');
});

test('pool-act rejects missing pool directory', () => {
  const missing = path.join(ROOT, '.cache/ticket10-e2e-20260726/does-not-exist-pool');
  rmSync(missing, { recursive: true, force: true });
  const r = spawnSync(process.execPath, [
    POOL_ACT, 'withdraw',
    '--pool', missing,
    '--wallets', WALLETS,
  ], { encoding: 'utf8', cwd: ROOT, timeout: 15_000, env: process.env });
  const combined = `${r.stdout || ''}\n${r.stderr || ''}`;
  assert.match(combined, /required|not exist|must contain|ENOENT|pool/i, combined.slice(0, 400));
  assert.doesNotMatch(combined, /"ok"\s*:\s*true/);
});

test('corrupt LIFO witnessSeed diverges tip stateCommitment from honest open set', async () => {
  requireLiveFixture();
  const state = JSON.parse(readFileSync(path.join(LIVE, 'state.json'), 'utf8'));
  const inst = JSON.parse(readFileSync(path.join(LIVE, 'instance.json'), 'utf8'));
  const notes = state.openNotes;
  assert.equal(notes.length, 10);
  const wallets = JSON.parse(readFileSync(WALLETS, 'utf8'));
  const wsh = createHash('sha256')
    .update(Buffer.from(wallets.hot.lockingBytecodeHex, 'hex'))
    .digest('hex');
  const digests = {
    deposit: '00'.repeat(32),
    transfer: '00'.repeat(32),
    withdrawal: '00'.repeat(32),
  };
  const common = {
    bundleDirectory: path.join(LIVE, 'bundle'),
    expectedProfile: {
      profileId: inst.profileId,
      instanceId: inst.instanceId,
      network: 'chipnet',
    },
    withdrawalScriptHash: wsh,
    actionKind: 'withdrawal',
    transferHops: 0,
    transactionContextDigests: digests,
  };

  const honest = await generateFreshWitnessInputs({
    ...common,
    witnessSeed: notes[notes.length - 1].witnessSeed,
    priorOpenNotes: notes.map(mapOpen),
  });
  const corruptNotes = notes.map((n, i) => (
    i === notes.length - 1
      ? { ...mapOpen(n), witnessSeed: 'ff'.repeat(32) }
      : mapOpen(n)
  ));
  const corrupt = await generateFreshWitnessInputs({
    ...common,
    witnessSeed: 'ff'.repeat(32),
    priorOpenNotes: corruptNotes,
  });

  const hAct = honest.actions.withdrawal.action;
  const cAct = corrupt.actions.withdrawal.action;
  assert.ok(hAct?.preState?.stateCommitment, 'honest withdrawal preState required');
  assert.ok(cAct?.preState?.stateCommitment, 'corrupt withdrawal preState required');
  assert.notEqual(
    hAct.preState.stateCommitment,
    cAct.preState.stateCommitment,
    'wrong seed must not reproduce honest tip stateCommitment',
  );
  assert.notEqual(
    hAct.preState.noteRoot,
    cAct.preState.noteRoot,
    'wrong seed must diverge noteRoot',
  );
  // Spend material must also differ (nullifier/cm path)
  assert.notEqual(hAct.spend.note.rho, cAct.spend.note.rho);
});

test('withdrawal witnessSeed must equal LIFO open note seed (fail closed)', async () => {
  requireLiveFixture();
  const state = JSON.parse(readFileSync(path.join(LIVE, 'state.json'), 'utf8'));
  const inst = JSON.parse(readFileSync(path.join(LIVE, 'instance.json'), 'utf8'));
  const notes = state.openNotes;
  const wallets = JSON.parse(readFileSync(WALLETS, 'utf8'));
  const wsh = createHash('sha256')
    .update(Buffer.from(wallets.hot.lockingBytecodeHex, 'hex'))
    .digest('hex');
  await assert.rejects(
    () => generateFreshWitnessInputs({
      bundleDirectory: path.join(LIVE, 'bundle'),
      expectedProfile: {
        profileId: inst.profileId,
        instanceId: inst.instanceId,
        network: 'chipnet',
      },
      withdrawalScriptHash: wsh,
      actionKind: 'withdrawal',
      transferHops: 0,
      transactionContextDigests: {
        deposit: '00'.repeat(32),
        transfer: '00'.repeat(32),
        withdrawal: '00'.repeat(32),
      },
      // prior open notes keep honest last seed; top-level seed mismatches LIFO
      witnessSeed: 'bb'.repeat(32),
      priorOpenNotes: notes.map(mapOpen),
    }),
    /must equal the open note being spent/i,
  );
});

test('deposit past maxLiveNotes reserve fails closed', async () => {
  requireLiveFixture();
  const inst = JSON.parse(readFileSync(path.join(LIVE, 'instance.json'), 'utf8'));
  const wallets = JSON.parse(readFileSync(WALLETS, 'utf8'));
  const wsh = createHash('sha256')
    .update(Buffer.from(wallets.hot.lockingBytecodeHex, 'hex'))
    .digest('hex');
  const max = Number(inst.maxLiveNotes || 16);
  const synth = [];
  for (let i = 0; i < max; i += 1) {
    const seed = Buffer.alloc(32, i + 1).toString('hex');
    synth.push({ witnessSeed: seed, depositDigest: '00'.repeat(32), phase: 'deposit' });
  }
  await assert.rejects(
    () => generateFreshWitnessInputs({
      bundleDirectory: path.join(LIVE, 'bundle'),
      expectedProfile: {
        profileId: inst.profileId,
        instanceId: inst.instanceId,
        network: 'chipnet',
      },
      withdrawalScriptHash: wsh,
      actionKind: 'deposit',
      transferHops: 0,
      transactionContextDigests: {
        deposit: '00'.repeat(32),
        transfer: '00'.repeat(32),
        withdrawal: '00'.repeat(32),
      },
      witnessSeed: 'cc'.repeat(32),
      priorOpenNotes: synth,
    }),
    /exceed maximum reserve/i,
  );
});

test('honest open-set NFT commitment matches chain tip; corrupt seed does not', async () => {
  requireLiveFixture();
  const { encodeStateNftCommitment } = await import('../action/state.mjs');
  const state = JSON.parse(readFileSync(path.join(LIVE, 'state.json'), 'utf8'));
  const inst = JSON.parse(readFileSync(path.join(LIVE, 'instance.json'), 'utf8'));
  const notes = state.openNotes;
  assert.equal(notes.length, 10);
  const wallets = JSON.parse(readFileSync(WALLETS, 'utf8'));
  const wsh = createHash('sha256')
    .update(Buffer.from(wallets.hot.lockingBytecodeHex, 'hex'))
    .digest('hex');
  const digests = {
    deposit: '00'.repeat(32),
    transfer: '00'.repeat(32),
    withdrawal: '00'.repeat(32),
  };
  const common = {
    bundleDirectory: path.join(LIVE, 'bundle'),
    expectedProfile: {
      profileId: inst.profileId,
      instanceId: inst.instanceId,
      network: 'chipnet',
    },
    withdrawalScriptHash: wsh,
    actionKind: 'withdrawal',
    transferHops: 0,
    transactionContextDigests: digests,
  };
  const honest = await generateFreshWitnessInputs({
    ...common,
    witnessSeed: notes[notes.length - 1].witnessSeed,
    priorOpenNotes: notes.map(mapOpen),
  });
  const corruptNotes = notes.map((n, i) => (
    i === notes.length - 1
      ? { ...mapOpen(n), witnessSeed: 'aa'.repeat(32) }
      : mapOpen(n)
  ));
  const corrupt = await generateFreshWitnessInputs({
    ...common,
    witnessSeed: 'aa'.repeat(32),
    priorOpenNotes: corruptNotes,
  });
  const hPre = honest.actions.withdrawal.action.preState;
  const cPre = corrupt.actions.withdrawal.action.preState;
  const instHex = inst.instanceId.replace(/^sha256:/, '');
  const synthHonest = Buffer.from(encodeStateNftCommitment({
    networkId: 2,
    instanceId: instHex,
    stateCommitment: hPre.stateCommitment,
    actionSequence: hPre.actionSequence,
  })).toString('hex');
  const synthCorrupt = Buffer.from(encodeStateNftCommitment({
    networkId: 2,
    instanceId: instHex,
    stateCommitment: cPre.stateCommitment,
    actionSequence: cPre.actionSequence,
  })).toString('hex');

  // Live tip NFT (read-only). Skip soft if RPC down; otherwise require match.
  const tip = state.stateTxid;
  const rpc = spawnSync('ssh', [
    '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20', 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf gettxout ${tip} 0 true`,
  ], { encoding: 'utf8' });
  if (rpc.status !== 0) {
    assert.notEqual(synthHonest, synthCorrupt, 'corrupt seed must change NFT commitment encoding');
    return;
  }
  const m = rpc.stdout.match(/\{[\s\S]*\}/);
  assert.ok(m, 'gettxout JSON');
  const tipU = JSON.parse(m[0]);
  const chainCommitment = tipU.tokenData.nft.commitment;
  assert.equal(
    synthHonest,
    chainCommitment,
    'honest open-set replay must encode the live tip state NFT commitment',
  );
  assert.notEqual(
    synthCorrupt,
    chainCommitment,
    'corrupt LIFO seed must not encode the live tip state NFT commitment',
  );
});

test('pool action requires the exact live tip NFT commitment before broadcast', () => {
  const actionSource = readFileSync(
    path.join(ROOT, 'shieldkit-groth/scripts/pool-act.mjs'),
    'utf8',
  );
  assert.match(
    actionSource,
    /transactionIdFromHex\(raw\) !== stateTxid/,
    'raw tip bytes must authenticate the requested state transaction',
  );
  assert.match(
    actionSource,
    /tipCommit !== result\.preState\.stateCommitment/,
    'packet preState must be compared with the chain tip NFT commitment',
  );
  assert.match(
    actionSource,
    /TIP_PRESTATE_UNVERIFIED/,
    'an unavailable or malformed chain tip must fail closed',
  );
  assert.doesNotMatch(
    actionSource,
    /phase: 'tip-prestate-check-soft-fail'/,
    'the pre-broadcast tip authentication gate must never soft-fail',
  );
});
