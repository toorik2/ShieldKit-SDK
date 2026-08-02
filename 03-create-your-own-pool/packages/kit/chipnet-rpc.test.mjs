import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertLayer1BchnChipnetRpc,
  CHIPNET_GENESIS_HASH,
  createLayer1BchnChipnetRpcForTest,
  LAYER1_BCHN_CHIPNET_BACKEND,
  observeLayer1BchnChipnetRpc,
} from './chipnet-rpc.mjs';

const TXID = 'ab'.repeat(32);
const RAW_TRANSACTION = '01000000000000000000';

function bchnFixture(calls, {
  genesis = CHIPNET_GENESIS_HASH,
  gettxoutResult = JSON.stringify({ bestblock: 'cd'.repeat(32), value: 1.25 }),
} = {}) {
  return async (method, args) => {
    calls.push({ method, args: [...args] });
    if (method === 'getblockhash') return genesis;
    if (method === 'getrawtransaction') {
      return args[1] ? JSON.stringify({ txid: args[0] }) : RAW_TRANSACTION;
    }
    if (method === 'gettxout') {
      return gettxoutResult;
    }
    if (method === 'scantxoutset') {
      return JSON.stringify({
        success: true,
        unspents: [{ txid: TXID, vout: 2, amount: 1.25 }],
      });
    }
    if (method === 'testmempoolaccept') {
      return JSON.stringify([{ txid: 'ef'.repeat(32), allowed: true }]);
    }
    if (method === 'sendrawtransaction') return 'ef'.repeat(32);
    throw new Error(`unexpected BCHN method ${method}`);
  };
}

test('creates a capability only after direct layer1 BCHN Chipnet proof without height polling', async () => {
  const calls = [];
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: bchnFixture(calls),
  });

  assert.equal(rpc.backend, LAYER1_BCHN_CHIPNET_BACKEND);
  assert.equal(rpc.label, 'layer1-node BCHN Chipnet');
  assert.equal(rpc.network, 'chipnet');
  assert.equal(rpc.genesis, CHIPNET_GENESIS_HASH);
  assert.equal(Object.hasOwn(rpc, 'initialHeight'), false);
  assert.strictEqual(assertLayer1BchnChipnetRpc(rpc), rpc);
  assert.deepEqual(observeLayer1BchnChipnetRpc(rpc), {
    backend: LAYER1_BCHN_CHIPNET_BACKEND,
    genesis: CHIPNET_GENESIS_HASH,
    methodCounts: {
      getblockhash: 1, getrawtransaction: 0, gettxout: 0, scantxoutset: 0,
      sendrawtransaction: 0, testmempoolaccept: 0,
    },
  });
  assert.deepEqual(calls, [
    { method: 'getblockhash', args: [0] },
  ]);
});

test('BCHN gettxout maps empty trimmed output and JSON null to a spent/missing result', async () => {
  for (const gettxoutResult of ['', ' \n\t ', 'null', '  null\n']) {
    const calls = [];
    const rpc = await createLayer1BchnChipnetRpcForTest({
      executeLayer1Cli: bchnFixture(calls, { gettxoutResult }),
    });
    assert.equal(await rpc.gettxout(TXID, 2), null);
  }
});

test('BCHN gettxout rejects nonempty malformed output and transport errors', async () => {
  for (const gettxoutResult of ['NULL', 'not-json', '{']) {
    const rpc = await createLayer1BchnChipnetRpcForTest({
      executeLayer1Cli: bchnFixture([], { gettxoutResult }),
    });
    await assert.rejects(rpc.gettxout(TXID, 2), SyntaxError);
  }
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: async (method, args) => {
      if (method === 'getblockhash') return CHIPNET_GENESIS_HASH;
      if (method === 'gettxout') throw new Error(`transport failed for ${args[0]}`);
      throw new Error(`unexpected BCHN method ${method}`);
    },
  });
  await assert.rejects(rpc.gettxout(TXID, 2), /transport failed/u);
});

test('refuses a reachable non-Chipnet layer1 BCHN before exposing methods', async () => {
  const calls = [];
  await assert.rejects(
    createLayer1BchnChipnetRpcForTest({
      executeLayer1Cli: bchnFixture(calls, { genesis: '00'.repeat(32) }),
    }),
    /not Chipnet/u,
  );
  assert.deepEqual(calls, [{ method: 'getblockhash', args: [0] }]);
});

test('BCHN-only handle exposes only direct zero-conf RPC methods without synthetic acceptance or height polling', async () => {
  const calls = [];
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: bchnFixture(calls),
  });
  calls.length = 0;

  assert.equal(await rpc.getrawtransaction(TXID), RAW_TRANSACTION);
  assert.deepEqual(await rpc.getrawtransaction(TXID, true), { txid: TXID });
  assert.deepEqual(await rpc.gettxout(TXID, 2), {
    bestblock: 'cd'.repeat(32), value: 1.25,
  });
  assert.deepEqual(
    await rpc.scanAddress('bchtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603'),
    [{ txid: TXID, vout: 2, sats: 125000000 }],
  );
  assert.deepEqual(await rpc.testmempoolaccept(RAW_TRANSACTION), [
    { txid: 'ef'.repeat(32), allowed: true },
  ]);
  assert.equal(await rpc.sendrawtransaction(RAW_TRANSACTION), 'ef'.repeat(32));
  assert.equal(Object.hasOwn(rpc, 'getblockcount'), false);
  assert.deepEqual(calls.map(({ method, args }) => ({ method, args })), [
    { method: 'getrawtransaction', args: [TXID, false] },
    { method: 'getrawtransaction', args: [TXID, true] },
    { method: 'gettxout', args: [TXID, 2, true] },
    {
      method: 'scantxoutset',
      args: ['start', 'bchtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfnhks603'],
    },
    { method: 'testmempoolaccept', args: [RAW_TRANSACTION] },
    { method: 'sendrawtransaction', args: [RAW_TRANSACTION, true] },
  ]);
  assert.equal(calls.some(({ method }) => /(?:blockcount|confirmation|blockchaininfo|chaintips)/u.test(method)), false);
  assert.deepEqual(observeLayer1BchnChipnetRpc(rpc).methodCounts, {
    getblockhash: 1, getrawtransaction: 2, gettxout: 1, scantxoutset: 1,
    sendrawtransaction: 1, testmempoolaccept: 1,
  });
});

test('BCHN-only handle validates requested arguments before the executor runs', async () => {
  const calls = [];
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: bchnFixture(calls),
  });
  calls.length = 0;

  await assert.rejects(rpc.gettxout(TXID, -1), /invalid gettxout arguments/u);
  await assert.rejects(rpc.testmempoolaccept('not-hex'), /invalid testmempoolaccept arguments/u);
  await assert.rejects(rpc.scanAddress('not-an-address'), /invalid scantxoutset arguments/u);
  assert.deepEqual(calls, []);
  assert.throws(
    () => assertLayer1BchnChipnetRpc({ backend: LAYER1_BCHN_CHIPNET_BACKEND }),
    /capability is required/u,
  );
});
