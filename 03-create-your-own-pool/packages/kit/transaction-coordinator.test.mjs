import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  admitAndSendExactTransactionOnce,
  broadcastStagedOperation,
  commitStagedOperation,
  loadPendingOperation,
  rebroadcastStagedOperation,
  stageOperation,
  transactionIdFromHex,
} from './transaction-coordinator.mjs';

const transaction = (role, hex) => ({ role, hex, txid: transactionIdFromHex(hex) });

async function holdSQLiteLockInChild(filename) {
  const child = spawn(process.execPath, ['--input-type=module', '--eval', [
    "import { DatabaseSync } from 'node:sqlite';",
    `const db = new DatabaseSync(${JSON.stringify(filename)});`,
    "db.exec('PRAGMA busy_timeout=0; BEGIN IMMEDIATE;');",
    "process.stdout.write('locked\\n');",
    'setInterval(() => {}, 60_000);',
  ].join('\n')], { stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.stdout.once('data', (value) => {
      if (String(value) === 'locked\n') resolve();
      else reject(new Error(`lock child did not report readiness: ${String(value)}`));
    });
    child.stderr.once('data', value => reject(new Error(String(value))));
    child.once('exit', (code) => reject(new Error(`lock child exited before readiness (${code})`)));
  });
  return child;
}

async function killAndWait(child) {
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.kill('SIGKILL');
  await exited;
}

test('mandatory exact-send gate binds bytes and authorizes one TMA, durable callback, then one send', async () => {
  const rawTransactionHex = '01000000000000000000';
  const expectedTransactionId = transactionIdFromHex(rawTransactionHex);
  const calls = [];
  const rpc = {
    async testmempoolaccept(raw) {
      calls.push(['tma', raw]);
      return [{ allowed: true, txid: expectedTransactionId }];
    },
    async sendrawtransaction(raw) {
      calls.push(['send', raw]);
      return expectedTransactionId;
    },
    async getrawtransaction(txid, verbose) {
      calls.push(['readback', txid, verbose]);
      return { txid: expectedTransactionId, hex: rawTransactionHex };
    },
  };
  const result = await admitAndSendExactTransactionOnce({
    rpc, rawTransactionHex, expectedTransactionId,
    network: 'chipnet', setupMode: 'development-only',
    async beforeSendAttempt(bound) {
      calls.push(['durable', bound]);
      assert.equal(bound.transactionId, expectedTransactionId);
      assert.equal(bound.rawTransactionHex, rawTransactionHex);
    },
  });
  assert.deepEqual(calls.map(([name]) => name), ['tma', 'durable', 'send', 'readback']);
  assert.equal(calls[0][1], rawTransactionHex);
  assert.equal(calls[2][1], rawTransactionHex);
  assert.deepEqual(calls[3].slice(1), [expectedTransactionId, true]);
  assert.deepEqual(result.admission, { allowed: true, txid: expectedTransactionId });
  assert.deepEqual(result.readback, { transactionId: expectedTransactionId, rawTransactionHex });

  await assert.rejects(
    admitAndSendExactTransactionOnce({
      rpc, rawTransactionHex, expectedTransactionId: '00'.repeat(32),
      network: 'chipnet', setupMode: 'development-only', beforeSendAttempt: async () => {},
    }),
    (error) => error?.code === 'EXACT_BROADCAST_TXID_MISMATCH',
  );
  assert.equal(calls.filter(([name]) => name === 'send').length, 1);
});

test('mandatory exact-send gate has no send on authorization, TMA, or durability failure and marks send uncertainty', async () => {
  const rawTransactionHex = '01000000000000000000';
  const expectedTransactionId = transactionIdFromHex(rawTransactionHex);
  let sends = 0;
  const rpc = {
    async testmempoolaccept() { return [{ allowed: false, txid: expectedTransactionId }]; },
    async sendrawtransaction() { sends += 1; return expectedTransactionId; },
    async getrawtransaction() { return { txid: expectedTransactionId, hex: rawTransactionHex }; },
  };
  await assert.rejects(
    admitAndSendExactTransactionOnce({ rpc, rawTransactionHex, expectedTransactionId, network: 'mainnet', setupMode: 'development-only', beforeSendAttempt: async () => {} }),
    (error) => error?.code === 'EXACT_BROADCAST_NETWORK_REJECTED',
  );
  await assert.rejects(
    admitAndSendExactTransactionOnce({ rpc, rawTransactionHex, expectedTransactionId, network: 'chipnet', setupMode: 'development-only', beforeSendAttempt: async () => {} }),
    (error) => error?.code === 'EXACT_BROADCAST_MEMPOOL_REJECTED',
  );
  assert.equal(sends, 0);
  rpc.testmempoolaccept = async () => [{ allowed: true, txid: expectedTransactionId }];
  await assert.rejects(
    admitAndSendExactTransactionOnce({ rpc, rawTransactionHex, expectedTransactionId, network: 'chipnet', setupMode: 'development-only', beforeSendAttempt: async () => { throw new Error('durability failed'); } }),
    (error) => error?.code === 'EXACT_BROADCAST_DURABILITY_FAILED',
  );
  assert.equal(sends, 0);
  rpc.sendrawtransaction = async () => { sends += 1; throw new Error('disconnect after write'); };
  await assert.rejects(
    admitAndSendExactTransactionOnce({ rpc, rawTransactionHex, expectedTransactionId, network: 'chipnet', setupMode: 'development-only', beforeSendAttempt: async () => {} }),
    (error) => error?.code === 'EXACT_BROADCAST_SEND_INDETERMINATE' && error.sendAttempted === true,
  );
  assert.equal(sends, 1);
  rpc.sendrawtransaction = async () => { sends += 1; return expectedTransactionId; };
  rpc.getrawtransaction = async () => { throw new Error('not indexed yet'); };
  await assert.rejects(
    admitAndSendExactTransactionOnce({ rpc, rawTransactionHex, expectedTransactionId, network: 'chipnet', setupMode: 'development-only', beforeSendAttempt: async () => {} }),
    (error) => error?.code === 'EXACT_BROADCAST_READBACK_FAILED' && error.sendAttempted === true,
  );
  rpc.getrawtransaction = async () => ({ txid: expectedTransactionId, hex: '00' });
  await assert.rejects(
    admitAndSendExactTransactionOnce({ rpc, rawTransactionHex, expectedTransactionId, network: 'chipnet', setupMode: 'development-only', beforeSendAttempt: async () => {} }),
    (error) => error?.code === 'EXACT_BROADCAST_READBACK_INVALID' && error.sendAttempted === true,
  );
  assert.equal(sends, 3);
});

test('offline staging writes a 0600 journal and does not mutate live state', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-operation-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const statePath = path.join(root, 'state.json');
  await writeFile(statePath, '{"stateTxid":"old"}\n', { mode: 0o644 });
  const staged = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [transaction('prep', '01000000000000000000')],
    nextState: { stateTxid: 'new', openNotes: [{ secret: 'private' }] },
    ledgerRecord: { kind: 'deposit' },
  });
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).stateTxid, 'old');
  assert.equal((await stat(staged.journalPath)).mode & 0o777, 0o600);
  assert.equal(loadPendingOperation(root).journal.status, 'prepared');
});

test('operation journals require a private non-symlink boundary and create 0700/0600 artifacts', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-operation-boundary-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-operation-outside-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => Promise.all([rm(root, { recursive: true, force: true }), rm(outside, { recursive: true, force: true })])));
  const options = () => ({
    poolDirectory: root, kind: 'deposit', network: 'chipnet', setupMode: 'development-only',
    transactions: [transaction('prep', '01000000000000000000')], nextState: {}, ledgerRecord: {},
  });
  await symlink(outside, path.join(root, '.shieldkit'));
  assert.throws(() => stageOperation(options()), (error) => error?.code === 'OPERATION_DIRECTORY_INVALID');
  await unlink(path.join(root, '.shieldkit'));
  await chmod(root, 0o755);
  assert.throws(() => stageOperation(options()), (error) => error?.code === 'OPERATION_DIRECTORY_INVALID');
  await chmod(root, 0o700);
  await mkdir(path.join(root, '.shieldkit'), { mode: 0o700 });
  await chmod(path.join(root, '.shieldkit'), 0o755);
  assert.throws(() => stageOperation(options()), (error) => error?.code === 'OPERATION_DIRECTORY_INVALID');
  await chmod(path.join(root, '.shieldkit'), 0o700);
  const staged = stageOperation(options());
  assert.equal((await lstat(path.join(root, '.shieldkit'))).mode & 0o777, 0o700);
  assert.equal((await lstat(path.join(root, '.shieldkit', 'operations'))).mode & 0o777, 0o700);
  assert.equal((await lstat(staged.journalPath)).mode & 0o777, 0o600);
  assert.equal((await lstat(`${staged.journalPath}.send-lock.sqlite`)).mode & 0o777, 0o600);
  await unlink(staged.journalPath);
  await writeFile(path.join(outside, 'pending.json'), '{}\n', { mode: 0o600 });
  await symlink(path.join(outside, 'pending.json'), staged.journalPath);
  let sends = 0;
  await assert.rejects(
    broadcastStagedOperation({
      journalPath: staged.journalPath,
      rpc: {
        async testmempoolaccept() { return [{ allowed: true, txid: '00'.repeat(32) }]; },
        async sendrawtransaction() { sends += 1; return '00'.repeat(32); },
      },
    }),
    (error) => error?.code === 'OPERATION_DIRECTORY_INVALID',
  );
  assert.equal(sends, 0);
});

test('mainnet gate runs before the RPC send capability', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-mainnet-gate-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'mainnet',
    setupMode: 'development-only',
    transactions: [transaction('prep', '01000000000000000000')],
    nextState: {},
    ledgerRecord: {},
  });
  let sends = 0;
  await assert.rejects(
    broadcastStagedOperation({
      journalPath,
      rpc: {
        async sendrawtransaction() { sends += 1; },
        async testmempoolaccept() { return [{ allowed: true, txid: transaction('prep', '01000000000000000000').txid }]; },
      },
    }),
    /mainnet broadcast refused/,
  );
  assert.equal(sends, 0);
});

test('broadcast and commit are ordered, durable, and idempotent', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-commit-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const txs = [
    transaction('prep', '01000000000000000000'),
    transaction('settlement', '02000000000000000000'),
  ];
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'withdrawal',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: txs,
    nextState: { stateTxid: txs[1].txid, openNotes: [] },
    ledgerRecord: { kind: 'withdrawal' },
  });
  const sent = [];
  await broadcastStagedOperation({
    journalPath,
    rpc: {
      async testmempoolaccept(hex) {
        assert.equal(sent.length, hex === txs[0].hex ? 0 : 1);
        return [{ allowed: true, txid: transactionIdFromHex(hex) }];
      },
      async sendrawtransaction(hex) {
        sent.push(hex);
        return transactionIdFromHex(hex);
      },
      async getrawtransaction(txid, verbose) {
        assert.equal(verbose, true);
        const found = txs.find((entry) => entry.txid === txid);
        return found === undefined ? null : { txid, hex: found.hex };
      },
    },
  });
  const statePath = path.join(root, 'state.json');
  const ledgerPath = path.join(root, 'ledger.jsonl');
  const journal = loadPendingOperation(root).journal;
  assert.deepEqual(Object.keys(journal.transactions[0].readback).sort(), ['observedAt', 'rawTransactionSha256']);
  assert.match(journal.transactions[0].readback.rawTransactionSha256, /^[0-9a-f]{64}$/u);
  commitStagedOperation({ journalPath, statePath, ledgerPath });
  commitStagedOperation({ journalPath, statePath, ledgerPath });
  assert.deepEqual(sent, txs.map((tx) => tx.hex));
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).stateTxid, txs[1].txid);
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
  assert.equal((await stat(ledgerPath)).mode & 0o777, 0o600);
  assert.equal((await readFile(ledgerPath, 'utf8')).trim().split('\n').length, 1);
});

test('atomic commit repairs a pre-existing permissive state mode', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-mode-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const tx = transaction('prep', '01000000000000000000');
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'maintenance',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [tx],
    nextState: { ok: true },
    ledgerRecord: { kind: 'maintenance' },
  });
  const journal = JSON.parse(await readFile(journalPath, 'utf8'));
  journal.status = 'broadcast';
  await writeFile(journalPath, JSON.stringify(journal));
  await chmod(journalPath, 0o600);
  const statePath = path.join(root, 'state.json');
  await writeFile(statePath, '{}\n', { mode: 0o644 });
  commitStagedOperation({ journalPath, statePath, ledgerPath: path.join(root, 'ledger.jsonl') });
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
});

test('a post-send callback crash restarts by exact read-only reconciliation without a second send', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-readback-resume-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const tx = transaction('settlement', '01000000000000000000');
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [tx],
    nextState: {},
    ledgerRecord: {},
  });
  let sends = 0;
  let readbacks = 0;
  let reconciliationReads = 0;
  const rpc = {
    async testmempoolaccept() { return [{ allowed: true, txid: tx.txid }]; },
    async sendrawtransaction() { sends += 1; return tx.txid; },
    async getrawtransaction(requestedTxid, verbose) {
      reconciliationReads += 1;
      assert.equal(requestedTxid, tx.txid);
      assert.equal(verbose, true);
      return { txid: tx.txid, hex: tx.hex };
    },
  };
  await assert.rejects(
    broadcastStagedOperation({
      journalPath,
      rpc,
      async afterTransactionBroadcast({ readback }) {
        readbacks += 1;
        assert.deepEqual(readback, { transactionId: tx.txid, rawTransactionHex: tx.hex });
        throw new Error('readback unavailable');
      },
    }),
    /readback unavailable/,
  );
  assert.equal(loadPendingOperation(root).journal.status, 'ambiguous');
  assert.equal(loadPendingOperation(root).journal.transactions[0].status, 'indeterminate');
  await broadcastStagedOperation({
    journalPath,
    rpc,
  });
  assert.equal(loadPendingOperation(root).journal.status, 'broadcast');
  assert.equal(sends, 1);
  assert.equal(readbacks, 1);
  assert.equal(reconciliationReads, 2);
});

test('an unresolved post-send failure never resends on restart and requires explicit exact-rebroadcast acknowledgement', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-exact-rebroadcast-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const tx = transaction('settlement', '01000000000000000000');
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [tx],
    nextState: {},
    ledgerRecord: {},
  });
  let sends = 0;
  let reads = 0;
  const rpc = {
    async testmempoolaccept() { return [{ allowed: true, txid: tx.txid }]; },
    async sendrawtransaction() {
      sends += 1;
      if (sends === 1) throw new Error('connection closed after request write');
      return tx.txid;
    },
    async getrawtransaction() { reads += 1; throw new Error('not found'); },
  };
  await assert.rejects(
    broadcastStagedOperation({ journalPath, rpc }),
    (error) => error?.code === 'EXACT_BROADCAST_SEND_INDETERMINATE'
      && error.sendAttempted === true,
  );
  assert.equal(loadPendingOperation(root).journal.status, 'ambiguous');
  await assert.rejects(
    broadcastStagedOperation({ journalPath, rpc }),
    (error) => error?.code === 'RECONCILIATION_REQUIRED',
  );
  assert.equal(sends, 1);
  assert.equal(reads, 1);
  await assert.rejects(
    rebroadcastStagedOperation({ journalPath, rpc }),
    (error) => error?.code === 'EXACT_REBROADCAST_ACK_REQUIRED',
  );
  assert.equal(sends, 1);
  const priorAttemptToken = loadPendingOperation(root).journal.transactions[0].attemptToken;
  assert.match(priorAttemptToken, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  await assert.rejects(
    rebroadcastStagedOperation({
      journalPath, rpc, acknowledgedExactRebroadcast: true,
      priorAttemptToken: '00000000-0000-4000-8000-000000000000',
    }),
    (error) => error?.code === 'RECOVERY_TOKEN_MISMATCH',
  );
  assert.equal(sends, 1);
  rpc.getrawtransaction = async () => ({ txid: tx.txid, hex: tx.hex });
  await rebroadcastStagedOperation({
    journalPath,
    rpc,
    acknowledgedExactRebroadcast: true,
    priorAttemptToken,
  });
  assert.equal(loadPendingOperation(root).journal.status, 'broadcast');
  assert.equal(sends, 1);
  assert.equal(reads, 2);
});

test('one durable operation lock excludes a concurrent send and preserves one exact attempt', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-send-lock-race-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const tx = transaction('settlement', '01000000000000000000');
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [tx],
    nextState: {},
    ledgerRecord: {},
  });
  let releasePreflight; let preflightStarted;
  const preflightGate = new Promise((resolve) => { releasePreflight = resolve; });
  const preflightStartedGate = new Promise((resolve) => { preflightStarted = resolve; });
  let sends = 0;
  const rpc = {
    async testmempoolaccept() {
      preflightStarted();
      await preflightGate;
      return [{ allowed: true, txid: tx.txid }];
    },
    async sendrawtransaction() { sends += 1; return tx.txid; },
    async getrawtransaction() { return { txid: tx.txid, hex: tx.hex }; },
  };
  const first = broadcastStagedOperation({ journalPath, rpc });
  await preflightStartedGate;
  await assert.rejects(
    broadcastStagedOperation({ journalPath, rpc }),
    (error) => error?.code === 'OPERATION_LOCK_HELD',
  );
  releasePreflight();
  await first;
  assert.equal(sends, 1);
  const record = loadPendingOperation(root).journal.transactions[0];
  assert.equal(record.attempts, 1);
  assert.match(record.attemptToken, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
});

test('SQLite lifecycle lock excludes concurrent stage and commit without overwriting or duplicating the ledger', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-lifecycle-lock-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const tx = transaction('settlement', '01000000000000000000');
  const staged = stageOperation({
    poolDirectory: root, kind: 'deposit', network: 'chipnet', setupMode: 'development-only',
    transactions: [tx], nextState: { stateTxid: tx.txid }, ledgerRecord: { kind: 'deposit' },
  });
  const lock = await holdSQLiteLockInChild(`${staged.journalPath}.send-lock.sqlite`);
  assert.throws(
    () => stageOperation({
      poolDirectory: root, kind: 'replacement', network: 'chipnet', setupMode: 'development-only',
      transactions: [tx], nextState: {}, ledgerRecord: {},
    }),
    (error) => error?.code === 'OPERATION_LOCK_HELD',
  );
  await killAndWait(lock);
  assert.throws(
    () => stageOperation({
      poolDirectory: root, kind: 'replacement', network: 'chipnet', setupMode: 'development-only',
      transactions: [tx], nextState: {}, ledgerRecord: {},
    }),
    (error) => error?.code === 'PENDING_OPERATION',
  );
  await broadcastStagedOperation({
    journalPath: staged.journalPath,
    rpc: {
      async testmempoolaccept() { return [{ allowed: true, txid: tx.txid }]; },
      async sendrawtransaction() { return tx.txid; },
      async getrawtransaction() { return { txid: tx.txid, hex: tx.hex }; },
    },
  });
  const commitLock = await holdSQLiteLockInChild(`${staged.journalPath}.send-lock.sqlite`);
  assert.throws(
    () => commitStagedOperation({
      journalPath: staged.journalPath,
      statePath: path.join(root, 'state.json'),
      ledgerPath: path.join(root, 'ledger.jsonl'),
    }),
    (error) => error?.code === 'OPERATION_LOCK_HELD',
  );
  await killAndWait(commitLock);
  const commit = { journalPath: staged.journalPath, statePath: path.join(root, 'state.json'), ledgerPath: path.join(root, 'ledger.jsonl') };
  commitStagedOperation(commit);
  commitStagedOperation(commit);
  assert.equal((await readFile(commit.ledgerPath, 'utf8')).trim().split('\n').length, 1);
});

test('a crash-released SQLite lock needs no stale reclamation and preserves recovery tokens', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-send-lock-restart-'));
  t.after(async () => import('node:fs/promises').then(({ rm }) => rm(root, { recursive: true, force: true })));
  const tx = transaction('settlement', '01000000000000000000');
  const { journalPath } = stageOperation({
    poolDirectory: root,
    kind: 'deposit',
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: [tx],
    nextState: {},
    ledgerRecord: {},
  });
  let sends = 0;
  const rpc = {
    async testmempoolaccept() { return [{ allowed: true, txid: tx.txid }]; },
    async sendrawtransaction() { sends += 1; throw new Error('disconnect after request write'); },
    async getrawtransaction() { throw new Error('not observed yet'); },
  };
  await assert.rejects(broadcastStagedOperation({ journalPath, rpc }), (error) => error?.sendAttempted === true);
  const priorAttemptToken = loadPendingOperation(root).journal.transactions[0].attemptToken;
  const lock = await holdSQLiteLockInChild(`${journalPath}.send-lock.sqlite`);
  await assert.rejects(
    rebroadcastStagedOperation({
      journalPath, rpc, acknowledgedExactRebroadcast: true, priorAttemptToken,
    }),
    (error) => error?.code === 'OPERATION_LOCK_HELD',
  );
  // SIGKILL represents process termination: SQLite releases the kernel lock;
  // no PID inspection, stale filename, or lock-file mutation is required.
  await killAndWait(lock);
  await assert.rejects(
    rebroadcastStagedOperation({
      journalPath, rpc, acknowledgedExactRebroadcast: true,
      priorAttemptToken: '00000000-0000-4000-8000-000000000000',
    }),
    (error) => error?.code === 'RECOVERY_TOKEN_MISMATCH',
  );
  assert.equal(sends, 1);
  rpc.getrawtransaction = async () => ({ txid: tx.txid, hex: tx.hex });
  const recovered = await rebroadcastStagedOperation({
    journalPath, rpc, acknowledgedExactRebroadcast: true, priorAttemptToken,
  });
  assert.equal(recovered.status, 'broadcast');
  assert.equal(sends, 1);
});
