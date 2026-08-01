import assert from 'node:assert/strict';
import test from 'node:test';

import {
  executeV2BetaProductCliForTest,
  isV2BetaProductCliInvocation,
  renderV2BetaProductCliHuman,
  V2BetaProductCliError,
} from './beta-product-cli.mjs';

function dependencies(events) {
  return {
    createRpc: async () => { events.push('rpc'); return { branded: true }; },
    loadConfig: () => { events.push('config'); return { config: { persisted: true } }; },
    toContextConfig: () => ({ context: true }),
    deposit: async value => ({ status: 'accepted-zero-conf-beta-unqualified', transactionId: '11'.repeat(32), timingsMs: { commandTotal: 4 }, input: value }),
    inspectRecovery: async value => ({
      status: 'recovery-inspected-beta-unqualified', operationId: value.operationId,
      recovery: {
        exactRebroadcastAvailable: true,
        delivery: { attemptToken: '12345678-1234-4123-8123-123456789abc' },
      }, input: value,
    }),
    recovery: async value => ({ status: 'accepted-zero-conf-beta-unqualified', transactionId: '33'.repeat(32), timingsMs: { commandTotal: 6 }, input: value }),
    withdrawal: async value => ({ status: 'accepted-zero-conf-beta-unqualified', transactionId: '22'.repeat(32), timingsMs: { commandTotal: 5 }, input: value }),
    poolCreate: async value => ({ status: 'accepted-zero-conf-beta-unqualified', input: value }),
  };
}

test('recognizes only the new exact product invocations', () => {
  assert.equal(isV2BetaProductCliInvocation(['pool', 'create']), true);
  assert.equal(isV2BetaProductCliInvocation(['pool', 'prepare']), false);
  assert.equal(isV2BetaProductCliInvocation(['deposit']), true);
  assert.equal(isV2BetaProductCliInvocation(['withdraw', '--to', 'x']), true);
  assert.equal(isV2BetaProductCliInvocation(['recovery', 'inspect']), true);
  assert.equal(isV2BetaProductCliInvocation(['recovery', 'rebroadcast']), true);
  assert.equal(isV2BetaProductCliInvocation(['deposit', '--protocol', 'v1-legacy']), false);
  assert.equal(isV2BetaProductCliInvocation(['pool', 'add']), false);
});

test('dispatches pool creation without any separate per-pool preparation command', async () => {
  const created = await executeV2BetaProductCliForTest(
    ['pool', 'create', '--data-home', '/tmp/shieldkit-test'], dependencies([]),
  );
  assert.equal(created.command, 'pool-create');
  assert.equal(created.result.status, 'accepted-zero-conf-beta-unqualified');
  assert.deepEqual(created.result.input, { dataHome: '/tmp/shieldkit-test' });
  await assert.rejects(
    executeV2BetaProductCliForTest(['pool', 'prepare'], dependencies([])),
    error => error instanceof V2BetaProductCliError
      && error.code === 'BETA_CLI_UNKNOWN_COMMAND',
  );
});

test('accepts and propagates an exact pool-create funding transaction hint only', async () => {
  const fundingTxid = 'ab'.repeat(32);
  const created = await executeV2BetaProductCliForTest(
    ['pool', 'create', '--data-home', '/tmp/shieldkit-test', '--funding-txid', fundingTxid],
    dependencies([]),
  );
  assert.deepEqual(created.result.input, {
    dataHome: '/tmp/shieldkit-test', fundingTxid,
  });
  for (const argv of [
    ['pool', 'create', '--funding-txid', 'AB'.repeat(32)],
    ['pool', 'create', '--funding-txid', 'ab'.repeat(31)],
    ['deposit', '--funding-txid', fundingTxid],
  ]) {
    await assert.rejects(
      executeV2BetaProductCliForTest(argv, dependencies([])),
      error => error instanceof V2BetaProductCliError,
    );
  }
});

test('accepts one-invocation user wallet funding without placing a key on argv', async () => {
  const txid = 'cd'.repeat(32);
  const walletPath = '/tmp/shieldkit-user-wallet.json';
  const created = await executeV2BetaProductCliForTest(
    ['pool', 'create', '--data-home', '/tmp/shieldkit-test', '--funding-wallet', walletPath, '--funding-utxo', `${txid}:1`],
    dependencies([]),
  );
  assert.deepEqual(created.result.input, {
    dataHome: '/tmp/shieldkit-test', fundingWalletPath: walletPath, fundingUtxo: `${txid}:1`,
  });
  for (const argv of [
    ['pool', 'create', '--funding-wallet', walletPath],
    ['pool', 'create', '--funding-utxo', `${txid}:01`, '--funding-wallet', walletPath],
    ['pool', 'create', '--funding-wallet', 'relative.json', '--funding-utxo', `${txid}:0`],
    ['pool', 'create', '--funding-wallet', walletPath, '--funding-utxo', `${txid}:0`, '--funding-txid', txid],
    ['pool', 'create', '--private-key', '00'.repeat(32)],
  ]) {
    await assert.rejects(
      executeV2BetaProductCliForTest(argv, dependencies([])),
      error => error instanceof V2BetaProductCliError,
    );
  }
});

test('renders the secret-free pool funding rerun command for human output', () => {
  const rendered = renderV2BetaProductCliHuman({
    command: 'pool-create',
    result: {
      status: 'funding-required',
      fundingAddress: 'bchtest:qtest',
      rerunCommand: 'shieldkit pool create --funding-txid <64-lowercase-hex-bchn-transaction-id>',
    },
  });
  assert.match(rendered, /bchtest:qtest/u);
  assert.match(rendered, /--funding-txid/u);
});

test('dispatches deposit and withdrawal through loaded config and one BCHN capability', async () => {
  const depositEvents = [];
  const deposit = await executeV2BetaProductCliForTest(
    ['deposit', '--operation-id', 'deposit.1'], dependencies(depositEvents),
  );
  assert.equal(deposit.command, 'deposit');
  assert.equal(deposit.result.input.operationId, 'deposit.1');
  assert.deepEqual(depositEvents.sort(), ['config', 'rpc']);

  const withdrawal = await executeV2BetaProductCliForTest([
    'withdraw', '--to', 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv',
    '--note', 'note.1', '--human',
  ], dependencies([]));
  assert.equal(withdrawal.format, 'human');
  assert.equal(withdrawal.result.input.noteId, 'note.1');
});

test('dispatches only an explicitly acknowledged exact-rebroadcast recovery with operation and CAS token', async () => {
  const token = '12345678-1234-4123-8123-123456789abc';
  const recovered = await executeV2BetaProductCliForTest([
    'recovery', 'rebroadcast',
    '--operation-id', 'deposit.recovery.1',
    '--attempt-token', token,
    '--acknowledge-exact-rebroadcast',
  ], dependencies([]));
  assert.equal(recovered.command, 'recover-exact-rebroadcast');
  assert.deepEqual(recovered.result.input, {
    acknowledgedExactRebroadcast: true,
    config: { context: true },
    operationId: 'deposit.recovery.1',
    priorAttemptToken: token,
    rpc: { branded: true },
  });
  for (const argv of [
    ['recovery', 'rebroadcast', '--operation-id', 'deposit.recovery.1', '--attempt-token', token],
    ['recovery', 'rebroadcast', '--attempt-token', token, '--acknowledge-exact-rebroadcast'],
    ['recovery', 'rebroadcast', '--operation-id', 'deposit.recovery.1', '--attempt-token', 'stale', '--acknowledge-exact-rebroadcast'],
  ]) {
    await assert.rejects(
      executeV2BetaProductCliForTest(argv, dependencies([])),
      error => error instanceof V2BetaProductCliError,
    );
  }
});

test('dispatches read-only recovery inspection with its exact operation id and JSON envelope', async () => {
  const events = [];
  const inspected = await executeV2BetaProductCliForTest([
    'recovery', 'inspect', '--operation-id', 'deposit.recovery.1', '--data-home', '/tmp/shieldkit-test',
  ], dependencies(events));
  assert.equal(inspected.command, 'recovery-inspect');
  assert.equal(inspected.format, 'json');
  assert.deepEqual(inspected.result.input, {
    config: { context: true }, operationId: 'deposit.recovery.1', rpc: { branded: true },
  });
  assert.equal(inspected.result.recovery.exactRebroadcastAvailable, true);
  assert.equal(inspected.result.recovery.delivery.attemptToken, '12345678-1234-4123-8123-123456789abc');
  assert.deepEqual(events.sort(), ['config', 'rpc']);
  for (const argv of [
    ['recovery', 'inspect'],
    ['recovery', 'inspect', '--operation-id', 'deposit.recovery.1', '--attempt-token', '12345678-1234-4123-8123-123456789abc'],
  ]) {
    await assert.rejects(
      executeV2BetaProductCliForTest(argv, dependencies([])),
      error => error instanceof V2BetaProductCliError,
    );
  }
});

test('renders recovery inspection availability and current attempt token without a transaction result', () => {
  const rendered = renderV2BetaProductCliHuman({
    command: 'recovery-inspect',
    result: {
      status: 'recovery-inspected-beta-unqualified', operationId: 'deposit.recovery.1',
      recovery: {
        exactRebroadcastAvailable: true,
        delivery: { attemptToken: '12345678-1234-4123-8123-123456789abc' },
      },
    },
  });
  assert.match(rendered, /exact rebroadcast available: true/u);
  assert.match(rendered, /attempt token: 12345678-1234-4123-8123-123456789abc/u);
  assert.doesNotMatch(rendered, /transaction:/u);
});

test('rejects ambiguous, duplicate, unknown, and unsafe argument forms', async () => {
  const cases = [
    [['deposit', '--json', '--human'], 'BETA_CLI_FORMAT_CONFLICT'],
    [['deposit', '--operation-id', 'a', '--operation-id', 'b'], 'BETA_CLI_DUPLICATE_OPTION'],
    [['withdraw'], 'BETA_WITHDRAWAL_ADDRESS_REQUIRED'],
    [['pool', 'create', '--to', 'x'], 'BETA_CLI_OPTION_NOT_ALLOWED'],
    [['deposit', '--data-home', 'relative'], 'BETA_CLI_DATA_HOME_REJECTED'],
    [['recovery', 'inspect'], 'BETA_RECOVERY_INSPECT_OPERATION_REQUIRED'],
  ];
  for (const [argv, code] of cases) {
    await assert.rejects(
      executeV2BetaProductCliForTest(argv, dependencies([])),
      error => error instanceof V2BetaProductCliError && error.code === code,
    );
  }
});
