import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { lockingBytecodeToCashAddress } from '@bitauth/libauth';

import {
  assertV2ProductionChainClientCapability,
  createV2ChipnetChainClient,
  createV2FixtureOnlyChainTransport,
  V2_CANONICAL_HISTORY_PAGE_SCHEMA,
  V2_CANONICAL_HISTORY_REQUEST_SCHEMA,
  V2_CHAIN_CLIENT_MAX_RESPONSE_BYTES,
  V2_CHAIN_READ_RESPONSE_SCHEMA,
  V2_CHAIN_READ_RPC_ID,
} from './chain-client.mjs';
import { parseV2ChainConfig, V2_CHAIN_CONFIG_SCHEMA } from './chain-config.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { transactionId } from './transaction-policy.mjs';
import { buildRawTransaction } from './v2-test-fixtures.mjs';

const certificateSha256 = 'ab'.repeat(32);
const fundingLock = `76a914${'11'.repeat(20)}88ac`;
const fundingAddress = lockingBytecodeToCashAddress({
  bytecode: Buffer.from(fundingLock, 'hex'),
  prefix: 'bchtest',
}).address;
const canonicalHistoryDomain = Buffer.from(
  'ShieldKit V2 canonical history v1\0',
  'utf8',
);

function rawTransaction(tag) {
  return buildRawTransaction({
    outputValueSatoshis: 900_000n - BigInt(tag),
  });
}

function canonicalHistorySnapshotId({
  instanceId,
  genesis,
  tip,
  actionCount,
  historySha256,
}) {
  return createHash('sha256')
    .update(canonicalHistoryDomain)
    .update(canonicalizeJcs({
      instanceId,
      genesis: {
        transactionId: genesis.transactionId,
        height: genesis.height,
        blockHash: genesis.blockHash,
        outputIndex: genesis.outputIndex,
        initialStateHex: genesis.initialStateHex,
      },
      tip: {
        transactionId: tip.transactionId,
        outputIndex: tip.outputIndex,
        stateHex: tip.stateHex,
        actionSequence: tip.actionSequence,
        height: tip.height,
        blockHash: tip.blockHash,
      },
      actionCount,
      historySha256,
    }), 'utf8')
    .digest('hex');
}

function canonicalHistoryPage({
  actionCount = '2',
  actions = undefined,
  instanceId = '77'.repeat(32),
  nextCursor = null,
  pageStartIndex = '0',
} = {}) {
  const genesisRaw = rawTransaction(1);
  const genesis = {
    transactionId: transactionId(Buffer.from(genesisRaw, 'hex')),
    rawTransaction: genesisRaw,
    height: 100,
    blockHash: '11'.repeat(32),
    outputIndex: 3,
    initialStateHex: '22'.repeat(128),
  };
  const selectedActions = actions ?? Array.from(
    { length: Number(actionCount) - Number(pageStartIndex) },
    (_, offset) => {
      const actionRaw = rawTransaction(10 + offset);
      const fundingRaw = rawTransaction(30 + offset);
      return {
        index: String(Number(pageStartIndex) + offset),
        action: {
          transactionId: transactionId(Buffer.from(actionRaw, 'hex')),
          rawTransaction: actionRaw,
          height: 101 + offset,
          blockHash: `${String(3 + offset).padStart(2, '0')}`.repeat(32),
        },
        fundingPrevout: {
          transactionId: transactionId(Buffer.from(fundingRaw, 'hex')),
          rawTransaction: fundingRaw,
        },
      };
    },
  );
  const finalAction = selectedActions.at(-1);
  const tip = {
    transactionId: finalAction?.action.transactionId ?? genesis.transactionId,
    outputIndex: finalAction === undefined ? genesis.outputIndex : 4,
    stateHex: '44'.repeat(128),
    actionSequence: actionCount,
    height: finalAction === undefined ? genesis.height : finalAction.action.height,
    blockHash: finalAction === undefined ? genesis.blockHash : finalAction.action.blockHash,
    confirmations: 6,
  };
  const historySha256 = '55'.repeat(32);
  return {
    schema: V2_CANONICAL_HISTORY_PAGE_SCHEMA,
    instanceId,
    snapshotId: canonicalHistorySnapshotId({
      instanceId,
      genesis,
      tip,
      actionCount,
      historySha256,
    }),
    genesis,
    tip,
    actionCount,
    historySha256,
    pageStartIndex,
    actions: selectedActions,
    nextCursor,
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function config() {
  return parseV2ChainConfig({
    schema: V2_CHAIN_CONFIG_SCHEMA,
    protocol: 'v2-direct',
    network: 'chipnet',
    endpoint: {
      url: 'https://node.example.com/rpc',
      network: 'chipnet',
      tls: {
        certificateSha256,
        minVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        serverName: 'node.example.com',
      },
      allowRedirects: false,
    },
    confirmationDepth: 6,
    requestTimeoutMs: 15_000,
  });
}

function response(operation, result) {
  return Buffer.from(canonicalizeJcs({
    error: null,
    id: V2_CHAIN_READ_RPC_ID,
    jsonrpc: '2.0',
    result: {
      operation,
      result,
      schema: V2_CHAIN_READ_RESPONSE_SCHEMA,
    },
  }), 'utf8');
}

function fixtureTransport(handler) {
  return createV2FixtureOnlyChainTransport(async (request) => {
    assert.equal(request.endpoint.url, 'https://node.example.com/rpc');
    assert.equal(request.endpoint.network, 'chipnet');
    assert.equal(request.endpoint.allowRedirects, false);
    assert.equal(request.endpoint.tls.rejectUnauthorized, true);
    assert.equal(request.endpoint.tls.serverName, 'node.example.com');
    assert.equal(request.endpoint.tls.certificateSha256, certificateSha256);
    assert.equal(request.timeoutMs, 15_000);
    assert.equal(request.maxResponseBytes, V2_CHAIN_CLIENT_MAX_RESPONSE_BYTES);
    const body = JSON.parse(request.body.toString('utf8'));
    assert.equal(request.body.toString('utf8'), canonicalizeJcs(body));
    return handler(body);
  });
}

test('reads only bounded Chipnet lifecycle surfaces through a pinned fixture transport', async () => {
  const raw = buildRawTransaction();
  const txid = transactionId(Buffer.from(raw, 'hex'));
  const client = createV2ChipnetChainClient({
    chainConfig: config(),
    transport: fixtureTransport((body) => {
      assert.equal(body.id, V2_CHAIN_READ_RPC_ID);
      assert.equal(body.jsonrpc, '2.0');
      if (body.method === 'getrawtransaction') {
        assert.deepEqual(body.params, [txid, false]);
        return response('transaction', raw);
      }
      if (body.method === 'shieldkit_get_pool_tip') {
        assert.deepEqual(body.params, ['77'.repeat(32)]);
        return response('pool-tip', {
          actionSequence: 4,
          blockHash: '33'.repeat(32),
          confirmations: 6,
          height: 123,
          instanceId: '77'.repeat(32),
          network: 'chipnet',
          state: '44'.repeat(128),
          txid: '55'.repeat(32),
          vout: 2,
        });
      }
      assert.equal(body.method, 'shieldkit_get_wallet_utxos');
      assert.deepEqual(body.params, [fundingAddress, '77'.repeat(32)]);
      return response('wallet-utxos', {
        canonicalTip: {
          actionSequence: 4,
          blockHash: '33'.repeat(32),
          confirmations: 6,
          height: 123,
          instanceId: '77'.repeat(32),
          network: 'chipnet',
          state: '44'.repeat(128),
          txid: '55'.repeat(32),
          vout: 2,
        },
        cashAddress: fundingAddress,
        lockingBytecodeHex: fundingLock,
        utxos: [{
          lockingBytecodeHex: fundingLock,
          token: null,
          txid: '66'.repeat(32),
          valueSats: '10000000',
          vout: 1,
        }],
      });
    }),
  });
  assert.deepEqual(Object.keys(client).sort(), []);
  assert.equal(typeof client.broadcast, 'undefined');
  assert.equal(await client.fetchTransaction({ transactionId: txid }), raw);
  assert.deepEqual(
    await client.fetchAuthenticatedPoolTip({ instanceId: '77'.repeat(32) }),
    {
      actionSequence: 4,
      blockHash: '33'.repeat(32),
      confirmations: 6,
      height: 123,
      state: '44'.repeat(128),
      txid: '55'.repeat(32),
      vout: 2,
    },
  );
  assert.deepEqual(await client.queryWalletUtxos({
    cashAddress: fundingAddress,
    instanceId: '77'.repeat(32),
    lockingBytecodeHex: fundingLock,
  }), {
    canonicalTip: {
      actionSequence: 4,
      blockHash: '33'.repeat(32),
      confirmations: 6,
      height: 123,
      state: '44'.repeat(128),
      txid: '55'.repeat(32),
      vout: 2,
    },
    cashAddress: fundingAddress,
    lockingBytecodeHex: fundingLock,
    utxos: [{
      lockingBytecodeHex: fundingLock,
      token: null,
      txid: '66'.repeat(32),
      valueSats: '10000000',
      vout: 1,
    }],
  });
});

test('requires a frozen exact validated Chipnet configuration and a branded read transport', () => {
  const mutable = JSON.parse(JSON.stringify(config()));
  assert.throws(
    () => createV2ChipnetChainClient({ chainConfig: mutable }),
    (error) => error?.code === 'CHAIN_CONFIG_REQUIRED',
  );
  assert.throws(
    () => createV2ChipnetChainClient({
      chainConfig: config(),
      transport: { request: async () => Buffer.alloc(0), fixtureOnly: true },
    }),
    (error) => error?.code === 'CHAIN_TRANSPORT_REQUIRED',
  );
});

test('fails closed on noncanonical, mismatched, oversized, and malformed chain responses', async () => {
  const raw = buildRawTransaction();
  const txid = transactionId(Buffer.from(raw, 'hex'));
  const cases = [
    [
      'noncanonical JSON',
      Buffer.from(JSON.stringify({
        jsonrpc: '2.0', id: V2_CHAIN_READ_RPC_ID, error: null, result: {
          schema: V2_CHAIN_READ_RESPONSE_SCHEMA, operation: 'transaction', result: raw,
        },
      })),
    ],
    ['wrong operation', response('pool-tip', {})],
    ['oversized response', Buffer.alloc(V2_CHAIN_CLIENT_MAX_RESPONSE_BYTES + 1)],
    ['txid mismatch', response('transaction', `${raw}00`)],
  ];
  for (const [name, bytes] of cases) {
    await test(name, async () => {
      const client = createV2ChipnetChainClient({
        chainConfig: config(),
        transport: fixtureTransport(() => bytes),
      });
      await assert.rejects(
        () => client.fetchTransaction({ transactionId: txid }),
        (error) => error?.code === 'CHAIN_CLIENT_RESPONSE_INVALID',
      );
    });
  }
});

test('rejects insufficiently confirmed tips, unknown fields, non-P2PKH wallets, and token UTXOs', async () => {
  const client = createV2ChipnetChainClient({
    chainConfig: config(),
    transport: fixtureTransport((body) => {
      if (body.method === 'shieldkit_get_pool_tip') {
        return response('pool-tip', {
          actionSequence: 0,
          blockHash: '33'.repeat(32),
          confirmations: 5,
          height: 123,
          instanceId: '77'.repeat(32),
          network: 'chipnet',
          state: '44'.repeat(128),
          txid: '55'.repeat(32),
          vout: 0,
        });
      }
      return response('wallet-utxos', {
        canonicalTip: {
          actionSequence: 0,
          blockHash: '33'.repeat(32),
          confirmations: 6,
          height: 123,
          instanceId: '77'.repeat(32),
          network: 'chipnet',
          state: '44'.repeat(128),
          txid: '55'.repeat(32),
          vout: 0,
        },
        cashAddress: fundingAddress,
        lockingBytecodeHex: fundingLock,
        utxos: [{
          lockingBytecodeHex: fundingLock,
          token: { category: '00'.repeat(32) },
          txid: '66'.repeat(32),
          valueSats: '1',
          vout: 1,
        }],
      });
    }),
  });
  await assert.rejects(
    () => client.fetchAuthenticatedPoolTip({ instanceId: '77'.repeat(32) }),
    (error) => error?.code === 'CHAIN_CLIENT_INVALID',
  );
  await assert.rejects(
    () => client.queryWalletUtxos({
      cashAddress: fundingAddress,
      instanceId: '77'.repeat(32),
      lockingBytecodeHex: fundingLock,
    }),
    (error) => error?.code === 'CHAIN_CLIENT_RESPONSE_INVALID',
  );
  await assert.rejects(
    () => client.queryWalletUtxos({
      cashAddress: fundingAddress,
      instanceId: '77'.repeat(32),
      lockingBytecodeHex: `${fundingLock}00`,
    }),
    (error) => error?.code === 'CHAIN_CLIENT_INVALID',
  );
});

test('fetches a bounded, pinned canonical history page and returns only deeply frozen authenticated data', async () => {
  const page = canonicalHistoryPage();
  const client = createV2ChipnetChainClient({
    chainConfig: config(),
    transport: fixtureTransport((body) => {
      assert.equal(body.method, 'shieldkit_get_canonical_history_page');
      assert.deepEqual(body.params, [{
        schema: V2_CANONICAL_HISTORY_REQUEST_SCHEMA,
        instanceId: '77'.repeat(32),
        genesisTransactionId: page.genesis.transactionId,
        cursor: null,
        maxActions: 2,
      }]);
      return response('canonical-history-page', page);
    }),
  });
  const observed = await client.fetchCanonicalHistoryPage({
    instanceId: '77'.repeat(32),
    genesisTransactionId: page.genesis.transactionId,
    cursor: null,
    maxActions: 2,
  });
  assert.deepEqual(observed, page);
  const visit = (value) => {
    if (value && typeof value === 'object') {
      assert.equal(Object.isFrozen(value), true);
      for (const child of Object.values(value)) visit(child);
    }
  };
  visit(observed);
});

test('canonical-history request rejects exact-schema, identity, cursor, and action-count boundaries before a network read', async () => {
  const page = canonicalHistoryPage();
  let calls = 0;
  const client = createV2ChipnetChainClient({
    chainConfig: config(),
    transport: fixtureTransport(() => {
      calls += 1;
      return response('canonical-history-page', page);
    }),
  });
  const valid = {
    instanceId: '77'.repeat(32),
    genesisTransactionId: page.genesis.transactionId,
    cursor: null,
    maxActions: 1,
  };
  const invalid = [
    { ...valid, unexpected: true },
    { ...valid, instanceId: '77'.repeat(31) },
    { ...valid, genesisTransactionId: 'AA'.repeat(32) },
    { ...valid, cursor: '' },
    { ...valid, cursor: 'a+'.repeat(2) },
    { ...valid, cursor: 'a'.repeat(4097) },
    { ...valid, maxActions: 0 },
    { ...valid, maxActions: 9 },
    { ...valid, maxActions: 1.5 },
    { ...valid, maxActions: '1' },
  ];
  for (const request of invalid) {
    await assert.rejects(
      () => client.fetchCanonicalHistoryPage(request),
      (error) => error?.code === 'CHAIN_CLIENT_INVALID',
    );
  }
  assert.equal(calls, 0);
});

test('canonical-history page rejects malformed schema, identities, raw transactions, pagination, confirmations, and snapshot bindings', async () => {
  const base = canonicalHistoryPage();
  const request = {
    instanceId: base.instanceId,
    genesisTransactionId: base.genesis.transactionId,
    cursor: null,
    maxActions: 2,
  };
  const cases = [
    ['unknown page field', (page) => { page.extra = true; }],
    ['wrong page schema', (page) => { page.schema = 'shieldkit-v2-canonical-history-page-v0'; }],
    ['wrong requested instance', (page) => { page.instanceId = '78'.repeat(32); }],
    ['wrong requested genesis', (page) => { page.genesis.transactionId = '99'.repeat(32); }],
    ['genesis raw hash mismatch', (page) => { page.genesis.rawTransaction = rawTransaction(99); }],
    ['oversized genesis raw transaction', (page) => { page.genesis.rawTransaction = '00'.repeat(100_001); }],
    ['invalid genesis state width', (page) => { page.genesis.initialStateHex = '22'.repeat(127); }],
    ['insufficient tip confirmations', (page) => { page.tip.confirmations = 5; }],
    ['tip action sequence not canonical decimal', (page) => { page.tip.actionSequence = '02'; }],
    ['tip action sequence mismatches count', (page) => { page.tip.actionSequence = '1'; }],
    ['count exceeds uint32', (page) => { page.actionCount = '4294967296'; }],
    ['noncanonical page start', (page) => { page.pageStartIndex = '00'; }],
    ['page start beyond count', (page) => { page.pageStartIndex = '3'; }],
    ['actions exceed requested max', (page) => {
      page.actions.push(clone(page.actions[1]));
      page.actions[2].index = '2';
    }],
    ['actions exceed count', (page) => {
      page.actions[1].index = '2';
    }],
    ['noncontiguous action index', (page) => { page.actions[1].index = '9'; }],
    ['action raw hash mismatch', (page) => { page.actions[0].action.rawTransaction = rawTransaction(98); }],
    ['funding raw hash mismatch', (page) => { page.actions[0].fundingPrevout.rawTransaction = rawTransaction(97); }],
    ['terminal cursor supplied', (page) => { page.nextCursor = 'next_1'; }],
    ['nonterminal page lacks cursor', (page) => {
      page.actions.pop();
      page.nextCursor = null;
    }],
    ['nonterminal page is empty', (page) => {
      page.actions = [];
      page.nextCursor = 'next_1';
    }],
    ['invalid next cursor', (page) => {
      page.actions.pop();
      page.nextCursor = 'bad+';
    }],
    ['snapshot id mismatch', (page) => { page.snapshotId = '00'.repeat(32); }],
  ];
  for (const [name, mutate] of cases) {
    await test(name, async () => {
      const page = clone(base);
      mutate(page);
      const client = createV2ChipnetChainClient({
        chainConfig: config(),
        transport: fixtureTransport(() => response('canonical-history-page', page)),
      });
      await assert.rejects(
        () => client.fetchCanonicalHistoryPage(request),
        (error) => error?.code === 'CHAIN_CLIENT_RESPONSE_INVALID'
          || error?.code === 'CHAIN_CLIENT_INVALID',
      );
    });
  }
});

test('canonical-history page validates a nonterminal page, actionCount zero, and exact snapshot preimage exclusions', async () => {
  const nonterminal = canonicalHistoryPage({
    actionCount: '2',
    actions: undefined,
    nextCursor: 'cursor_1',
  });
  nonterminal.actions.pop();
  nonterminal.tip.actionSequence = '2';
  nonterminal.snapshotId = canonicalHistorySnapshotId({
    instanceId: nonterminal.instanceId,
    genesis: nonterminal.genesis,
    tip: nonterminal.tip,
    actionCount: nonterminal.actionCount,
    historySha256: nonterminal.historySha256,
  });
  const zero = canonicalHistoryPage({ actionCount: '0', actions: [] });
  const pages = [nonterminal, zero];
  let pageIndex = 0;
  const client = createV2ChipnetChainClient({
    chainConfig: config(),
    transport: fixtureTransport(() => response('canonical-history-page', pages[pageIndex++])),
  });
  const first = await client.fetchCanonicalHistoryPage({
    instanceId: nonterminal.instanceId,
    genesisTransactionId: nonterminal.genesis.transactionId,
    cursor: null,
    maxActions: 2,
  });
  assert.equal(first.actions.length, 1);
  assert.equal(first.nextCursor, 'cursor_1');
  const empty = await client.fetchCanonicalHistoryPage({
    instanceId: zero.instanceId,
    genesisTransactionId: zero.genesis.transactionId,
    cursor: 'cursor_1',
    maxActions: 1,
  });
  assert.deepEqual(empty.actions, []);
  assert.equal(empty.nextCursor, null);

  const confirmationDrift = clone(zero);
  confirmationDrift.tip.confirmations = 999;
  const clientWithConfirmationDrift = createV2ChipnetChainClient({
    chainConfig: config(),
    transport: fixtureTransport(() => response('canonical-history-page', confirmationDrift)),
  });
  const drift = await clientWithConfirmationDrift.fetchCanonicalHistoryPage({
    instanceId: zero.instanceId,
    genesisTransactionId: zero.genesis.transactionId,
    cursor: null,
    maxActions: 1,
  });
  assert.equal(drift.snapshotId, zero.snapshotId);
});

test('only pinned-TLS clients receive the production recovery capability', () => {
  const production = createV2ChipnetChainClient({
    chainConfig: config(),
  });
  assert.equal(
    assertV2ProductionChainClientCapability(production),
    production,
  );

  const fixture = createV2ChipnetChainClient({
    chainConfig: config(),
    transport: fixtureTransport(() => {
      throw new Error('fixture transport must not be invoked');
    }),
  });
  assert.throws(
    () => assertV2ProductionChainClientCapability(fixture),
    (error) => error?.code === 'PRODUCTION_CHAIN_CLIENT_REQUIRED',
  );
  assert.throws(
    () => assertV2ProductionChainClientCapability({
      fetchAuthenticatedPoolTip() {},
      fetchCanonicalHistoryPage() {},
      fetchTransaction() {},
      queryWalletUtxos() {},
    }),
    (error) => error?.code === 'PRODUCTION_CHAIN_CLIENT_REQUIRED',
  );
});
