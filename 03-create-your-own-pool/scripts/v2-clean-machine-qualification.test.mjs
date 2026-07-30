/* TEST-ONLY: command doubles below never write a Q-08 host transcript. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import { lockingBytecodeToCashAddress } from '@bitauth/libauth';

import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';

import {
  parseV2Q08Arguments,
  runV2Q08CleanMachineQualification,
  validateV2Q08FundingCheckpoint,
  V2Q08CleanMachineQualificationError,
} from './v2-clean-machine-qualification.mjs';

test('Q-08 accepts only exact absolute one-shot inputs', async () => {
  assert.throws(() => parseV2Q08Arguments([]), V2Q08CleanMachineQualificationError);
  assert.throws(() => parseV2Q08Arguments([
    '--output-dir', 'relative', '--descriptor', '/a', '--final-manifest', '/b', '--profile-core', '/c', '--release-root', 'final-chipnet', '--command-plan', '/e', '--d02-closure', '/d02', '--funding-checkpoint', '/f', '--host-identity', '/g', '--host-role', 'clean-host-a', '--host-signing-key', '/h', '--expected-commit', '0'.repeat(40), '--expected-tree', '1'.repeat(40),
  ]), /absolute normalized/u);
  assert.throws(() => parseV2Q08Arguments([
    '--output-dir', '/a', '--descriptor', '/b', '--final-manifest', '/c', '--profile-core', '/d', '--trusted-signers', '/e', '--command-plan', '/f', '--d02-closure', '/d02', '--funding-checkpoint', '/g', '--host-identity', '/h', '--host-role', 'clean-host-a', '--host-signing-key', '/i', '--expected-commit', '0'.repeat(40), '--expected-tree', '1'.repeat(40),
  ]), /malformed or duplicated/u);
  await assert.rejects(
    runV2Q08CleanMachineQualification(
      { testOnly: false },
      { runner: async () => ({}) },
    ),
    /dependency injection is restricted to test-only/u,
  );
});

test('Q-08 production funding checkpoints reject the legacy unbound address/transaction shape', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q08-funding-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const raw = `0200000001${'11'.repeat(32)}0000000000ffffffff01e8030000000000000000000000`;
  const path = join(root, 'legacy-funding.json');
  writeFileSync(path, canonicalizeJcs({ schema: 'shieldkit-v2-direct-q08-out-of-band-funding-v1', status: 'funded-out-of-band', fundedAt: '2026-07-29T00:00:00.000Z', fundingAddress: 'bchtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2y8t8s', fundingTransactionHex: raw }));
  assert.throws(() => validateV2Q08FundingCheckpoint(path), /missing or unknown properties|fields are malformed/u);
});

test('Q-08 production funding checkpoints must start at the signed-manifest chain checkpoint', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q08-funding-checkpoint-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const lockingBytecodeHex = `76a914${'11'.repeat(20)}88ac`;
  const fundingAddress = lockingBytecodeToCashAddress({
    bytecode: Buffer.from(lockingBytecodeHex, 'hex'),
    prefix: 'bchtest',
  }).address;
  const raw = [
    '02000000',
    '01',
    '11'.repeat(32),
    '00000000',
    '00',
    'ffffffff',
    '01',
    'e803000000000000',
    '19',
    lockingBytecodeHex,
    '00000000',
  ].join('');
  const path = join(root, 'funding.json');
  writeFileSync(path, canonicalizeJcs({
    chainEvidence: {
      blockHeight: 100,
      checkpoint: { blockHash: '22'.repeat(32), chainWork: '1', height: 90 },
      merkleBranch: [],
      rawHeaders: [],
      tip: { blockHash: '33'.repeat(32), chainWork: '2', height: 105 },
      transactionCount: 1,
      transactionIndex: 0,
    },
    fundedAt: '2026-07-29T00:00:00.000Z',
    fundingAddress,
    fundingLockingBytecodeHex: lockingBytecodeHex,
    fundingOutputIndex: 0,
    fundingTransactionHex: raw,
    fundingValueSatoshis: '1000',
    provenanceDeclaration: {
      classification: 'declared-non-faucet-non-sponsor',
      scope: 'signer-assertion-not-independently-verified',
    },
    schema: 'shieldkit-v2-direct-q08-out-of-band-funding-v2',
    status: 'funded-out-of-band',
  }));
  assert.throws(
    () => validateV2Q08FundingCheckpoint(path, {
      expectedCheckpoint: {
        blockHash: '44'.repeat(32),
        chainWork: '1',
        height: 90,
      },
    }),
    /does not start at the signed-manifest Chipnet checkpoint/u,
  );
});

test('Q-08 bounded command doubles are test-only and cannot emit a host transcript', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-q08-test-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (name, value) => { const path = join(root, name); writeFileSync(path, JSON.stringify(value)); return path; };
  const raw = `0200000001${'11'.repeat(32)}0000000000ffffffff01e8030000000000000000000000`;
  const txid = parseV2RawTransaction(raw).txid;
  const manifestPath = write('manifest.json', { final: true });
  const manifestSha256 = createHash('sha256').update(readFileSync(manifestPath)).digest('hex');
  const descriptorPath = write('instance.json', { manifest: { path: 'manifest.json' } });
  const profileCorePath = write('profile.json', {});
  const d02ClosurePath = join(root, 'd02.json');
  writeFileSync(d02ClosurePath, canonicalizeJcs({ testOnly: true }));
  const d02ClosureSha256 = createHash('sha256')
    .update(readFileSync(d02ClosurePath))
    .digest('hex');
  const address = 'bchtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2y8t8s';
  const fundingPath = write('funding.json', { schema: 'shieldkit-v2-direct-q08-out-of-band-funding-v1', status: 'funded-out-of-band', fundedAt: '2026-07-29T00:00:00.000Z', fundingAddress: address, fundingTransactionHex: raw });
  const hostPath = write('host.json', { schema: 'shieldkit-v2-direct-q08-host-identity-v1', hostIdentity: '22'.repeat(32) });
  const commands = Object.fromEntries(['npmCi', 'wallet', 'fundingAddress', 'sync', 'deposit', 'transfer', 'withdraw', 'deleteLocalState', 'recover', 'recoveredSpend'].map((step) => [step, { executable: step === 'npmCi' ? 'npm' : 'q08-command', arguments: step === 'npmCi' ? ['ci', '--ignore-scripts', '--no-audit', '--no-fund'] : [step] }]));
  const planValue = {
    schema: 'shieldkit-v2-direct-q08-command-plan-v1',
    commands,
  };
  const planPath = join(root, 'plan.json');
  writeFileSync(planPath, canonicalizeJcs(planValue));
  const commandPlanSha256 = createHash('sha256')
    .update(readFileSync(planPath))
    .digest('hex');
  // TEST-ONLY inert references exercise the same strict result schema. They
  // deliberately do not name files and cannot constitute Q-08 qualification.
  const laneEvidence = {
    libauth: { path: 'test-only/libauth.json', sha256: 'a1'.repeat(32) },
    maintainer: { path: 'test-only/maintainer.json', sha256: 'a2'.repeat(32) },
    bchn: {
      mempool: { path: 'test-only/bchn-mempool.json', sha256: 'a3'.repeat(32) },
      mined: { path: 'test-only/bchn-mined.json', sha256: 'a4'.repeat(32) },
    },
    leanbch: { path: 'test-only/leanbch.json', sha256: 'a5'.repeat(32) },
  };
  const runnerEnvironments = [];
  const result = await runV2Q08CleanMachineQualification({
    testOnly: true, outputDirectory: join(root, 'output'), descriptorPath, finalManifestPath: manifestPath,
    profileCorePath, releaseRootId: 'test-only-root', commandPlanPath: planPath,
    d02ClosurePath, fundingCheckpointPath: fundingPath,
    hostIdentityPath: hostPath, hostRole: 'clean-host-a', expectedCommit: 'aa'.repeat(20), expectedTree: 'bb'.repeat(20),
  }, {
    runner: async (executable, arguments_, runnerOptions) => {
      runnerEnvironments.push(runnerOptions?.env);
      if (executable === 'git') {
        if (arguments_[0] === 'status') return { exitCode: 0, signal: null, stdout: '', stderr: '' };
        return { exitCode: 0, signal: null, stdout: `${arguments_[1] === 'HEAD^{commit}' ? 'aa'.repeat(20) : 'bb'.repeat(20)}\n`, stderr: '' };
      }
      if (executable === 'npm') return { exitCode: 0, signal: null, stdout: 'installed\n', stderr: '' };
      const step = arguments_[0];
      const status = { wallet: 'wallet-ready', fundingAddress: 'funding-address-displayed', sync: 'synced-from-genesis', deleteLocalState: 'local-state-deleted', recover: 'recovered-from-chain-history' }[step] ?? 'confirmed';
      const value = { schema: 'shieldkit-v2-direct-q08-step-result-v2', status, profileId: '33'.repeat(32), instanceId: '44'.repeat(32) };
      if (step === 'fundingAddress') value.fundingAddress = address;
      if (step === 'recover') value.recoveredNoteId = '77'.repeat(32);
      if (['deposit', 'transfer', 'withdraw', 'recoveredSpend'].includes(step)) Object.assign(value, { action: step === 'withdraw' || step === 'recoveredSpend' ? 'withdrawal' : step, rawTransactionHex: raw, transactionId: txid, laneEvidence });
      if (step === 'recoveredSpend') value.spentNoteId = '77'.repeat(32);
      return { exitCode: 0, signal: null, stdout: JSON.stringify(value), stderr: '' };
    },
    verifyFinalInputs: async () => ({
      profileId: '33'.repeat(32),
      profileSha256: '34'.repeat(32),
      instanceId: '44'.repeat(32),
      carrierCount: 7,
      descriptorSha256: '55'.repeat(32),
      manifestSha256,
      runtimeMaterialSha256: '66'.repeat(32),
      commandPlanSha256,
      d02AuditPolicySha256: '67'.repeat(32),
      d02ClosureSha256,
      sourcePinSha256: '88'.repeat(32),
      sourceCommit: 'aa'.repeat(20),
      sourceTree: 'bb'.repeat(20),
      networkId: 2,
      // TEST-ONLY injected identity, never a compiled/approved release root.
      releaseBootstrapSha256: '99'.repeat(32),
      releaseRootId: 'test-only-root',
    }),
  });
  assert.deepEqual(result, {
    schema: 'shieldkit-v2-direct-q08-attempt-record-v1',
    status: 'test-only-nonqualifying',
    q08Qualified: false,
  });
  assert.ok(!readFileSync(join(root, 'output', 'test-only.json'), 'utf8').includes('host-journey-complete'));
  assert.throws(() => readFileSync(join(root, 'output', 'q08-clean-host-transcript.json')), /ENOENT/u);
  const q08CommandEnvironments = runnerEnvironments.filter(
    (environment) => environment?.SHIELDKIT_Q08_OUTPUT_DIR !== undefined,
  );
  assert.equal(q08CommandEnvironments.length, 10);
  assert.ok(q08CommandEnvironments.every((environment) => environment.SHIELDKIT_Q08_OUTPUT_DIR === join(root, 'output')));
});
