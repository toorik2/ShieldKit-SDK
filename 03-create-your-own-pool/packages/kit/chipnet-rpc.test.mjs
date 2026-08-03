import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { encodeTokenPrefix } from '@bitauth/libauth';

import {
  assertChipnetProductRpc,
  assertLayer1BchnChipnetRpc,
  CHIPNET_GENESIS_HASH,
  createLayer1BchnChipnetRpcForTest,
  openPublicElectrumSessionForTest,
  createPublicChipnetFulcrumRpcForTest,
  LAYER1_BCHN_CHIPNET_BACKEND,
  observeChipnetProductRpc,
  observeLayer1BchnChipnetRpc,
  PUBLIC_CHIPNET_ELECTRUM,
} from './chipnet-rpc.mjs';

const TXID = 'ab'.repeat(32);
const RAW_TRANSACTION = '01000000000000000000';
const RAW_TRANSACTION_TXID =
  'd21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43';
const H = (byte) => byte.repeat(64);
const txidOf = (raw) => createHash('sha256').update(
  createHash('sha256').update(Buffer.from(raw, 'hex')).digest(),
).digest().reverse().toString('hex');
const le64 = (value) => Buffer.from(Uint8Array.from({ length: 8 }, (_, index) =>
  Number((BigInt(value) >> BigInt(index * 8)) & 0xffn),
)).toString('hex');
const serializedOutput = (valueSats, contentsHex) =>
  `${le64(valueSats)}${(contentsHex.length / 2).toString(16).padStart(2, '0')}${contentsHex}`;
const rawWithOneInput = (outputs) =>
  `0200000001${Buffer.from(H('f'), 'hex').reverse().toString('hex')}0000000000ffffffff${outputs.length.toString(16).padStart(2, '0')}${outputs.join('')}00000000`;

test('public Chipnet roles pin one sender and two independent read-only witnesses', () => {
  assert.deepEqual(PUBLIC_CHIPNET_ELECTRUM.map(({ host, port, tls }) => ({ host, port, tls })), [
    { host: 'chipnet.bch.ninja', port: 50002, tls: true },
    { host: 'chipnet.imaginary.cash', port: 50002, tls: true },
    { host: 'blackie.c3-soft.com', port: 64002, tls: true },
  ]);
});

function publicTransactionFixture() {
  const instanceId = Buffer.from(Uint8Array.from(
    { length: 32 }, (_, index) => index + 1,
  )).toString('hex');
  const commitment = H('2').repeat(4);
  const prefix = Buffer.from(encodeTokenPrefix({
    category: Uint8Array.from(Buffer.from(instanceId, 'hex').reverse()),
    amount: 0n,
    nft: {
      capability: 'mutable',
      commitment: Uint8Array.from(Buffer.from(commitment, 'hex')),
    },
  })).toString('hex');
  const lockingBytecodeHex = '51';
  const raw = rawWithOneInput([
    serializedOutput('546', `${prefix}${lockingBytecodeHex}`),
  ]);
  return Object.freeze({
    raw,
    transactionId: txidOf(raw),
    lockingBytecodeHex,
    instanceId,
    category: Buffer.from(instanceId, 'hex').reverse().toString('hex'),
    commitment,
    scripthash: createHash('sha256').update(
      Buffer.from(lockingBytecodeHex, 'hex'),
    ).digest().reverse().toString('hex'),
  });
}

function publicElectrumFixture({
  genesis = CHIPNET_GENESIS_HASH,
  negotiatedVersion = '1.6',
  broadcastError = undefined,
  outputInfo = undefined,
  outputInfoByHost = undefined,
  rawReadbackError = undefined,
  rawReadbackFailures = 0,
} = {}) {
  const transaction = publicTransactionFixture();
  const calls = [];
  const closes = [];
  const endpoints = Object.freeze([
    Object.freeze({ host: 'one.example', port: 50002, tls: true }),
    Object.freeze({ host: 'two.example', port: 50002, tls: true }),
  ]);
  const rawReadbackAttempts = new Map();
  const openSession = async (endpoint) => Object.freeze({
    async request(method, params) {
      calls.push(Object.freeze({ host: endpoint.host, method, params: [...params] }));
      if (method === 'server.features') return { genesis_hash: genesis };
      if (method === 'server.version') return ['Fulcrum', negotiatedVersion];
      if (method === 'blockchain.transaction.broadcast') {
        if (broadcastError !== undefined) throw broadcastError;
        return transaction.transactionId;
      }
      if (method === 'blockchain.transaction.get') {
        const attempts = (rawReadbackAttempts.get(endpoint.host) ?? 0) + 1;
        rawReadbackAttempts.set(endpoint.host, attempts);
        if (attempts <= rawReadbackFailures) throw new Error('not indexed yet');
        if (rawReadbackError !== undefined) throw rawReadbackError;
        return transaction.raw;
      }
      if (method === 'blockchain.utxo.get_info') {
        if (outputInfoByHost !== undefined
          && Object.hasOwn(outputInfoByHost, endpoint.host)) {
          return outputInfoByHost[endpoint.host];
        }
        return outputInfo ?? {
          value: 546,
          scripthash: transaction.scripthash,
          token_data: {
            amount: '0',
            category: transaction.category,
            nft: { capability: 'mutable', commitment: transaction.commitment },
          },
        };
      }
      if (method === 'blockchain.scripthash.listunspent') {
        return [{ tx_hash: transaction.transactionId, tx_pos: 0, value: 546 }];
      }
      throw new Error(`unexpected public Electrum method ${method}`);
    },
    close() { closes.push(endpoint.host); },
  });
  return Object.freeze({ calls, closes, endpoints, openSession, transaction });
}

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

test('single-pass action admission binds exact bytes before one composite executor call', async () => {
  const cliCalls = [];
  const admissionCalls = [];
  const stateOutput = {
    bestblock: 'cd'.repeat(32),
    value: 1.25,
    tokenData: { amount: '0' },
  };
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: bchnFixture(cliCalls),
    async executeLayer1Admission(request) {
      admissionCalls.push(request);
      return {
        transactionId: request.expectedTransactionId,
        rawTransaction: {
          txid: request.expectedTransactionId,
          hex: request.rawTransactionHex,
        },
        stateOutput,
      };
    },
  });
  cliCalls.length = 0;

  const result = await rpc.submitV2SinglePassAdmission(
    RAW_TRANSACTION,
    RAW_TRANSACTION_TXID,
    0,
  );
  assert.deepEqual(admissionCalls, [{
    expectedTransactionId: RAW_TRANSACTION_TXID,
    outputIndex: 0,
    rawTransactionHex: RAW_TRANSACTION,
  }]);
  assert.deepEqual(result, {
    transactionId: RAW_TRANSACTION_TXID,
    rawTransaction: {
      txid: RAW_TRANSACTION_TXID,
      hex: RAW_TRANSACTION,
    },
    stateOutput,
  });
  assert.deepEqual(cliCalls, []);
  assert.deepEqual(observeLayer1BchnChipnetRpc(rpc).methodCounts, {
    getblockhash: 1,
    getrawtransaction: 1,
    gettxout: 1,
    scantxoutset: 0,
    sendrawtransaction: 1,
    testmempoolaccept: 0,
  });
});

test('single-pass admission rejects mismatched bytes before counters or executor', async () => {
  let admissionCalls = 0;
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: bchnFixture([]),
    async executeLayer1Admission() {
      admissionCalls += 1;
      throw new Error('must not execute');
    },
  });
  const before = observeLayer1BchnChipnetRpc(rpc);
  await assert.rejects(
    rpc.submitV2SinglePassAdmission(RAW_TRANSACTION, TXID, 0),
    /transaction ID does not match/u,
  );
  assert.equal(admissionCalls, 0);
  assert.deepEqual(observeLayer1BchnChipnetRpc(rpc), before);
});

test('single-pass admission rejects malformed executor results fail closed', async () => {
  const malformed = [
    null,
    { transactionId: RAW_TRANSACTION_TXID, rawTransaction: {}, stateOutput: {} },
    {
      transactionId: RAW_TRANSACTION_TXID,
      rawTransaction: { txid: RAW_TRANSACTION_TXID, hex: '00' },
      stateOutput: {},
    },
    {
      transactionId: RAW_TRANSACTION_TXID,
      rawTransaction: { txid: RAW_TRANSACTION_TXID, hex: RAW_TRANSACTION },
      stateOutput: [],
    },
  ];
  for (const result of malformed) {
    const rpc = await createLayer1BchnChipnetRpcForTest({
      executeLayer1Cli: bchnFixture([]),
      async executeLayer1Admission() { return result; },
    });
    await assert.rejects(
      rpc.submitV2SinglePassAdmission(
        RAW_TRANSACTION,
        RAW_TRANSACTION_TXID,
        0,
      ),
      /result is malformed/u,
    );
  }
});

test('single-pass admission records one untrusted composite attempt on transport loss, never a TMA', async () => {
  const cliCalls = [];
  let admissionCalls = 0;
  const rpc = await createLayer1BchnChipnetRpcForTest({
    executeLayer1Cli: bchnFixture(cliCalls),
    async executeLayer1Admission() {
      admissionCalls += 1;
      throw new Error('test-only transport lost after request began');
    },
  });
  cliCalls.length = 0;

  await assert.rejects(
    rpc.submitV2SinglePassAdmission(
      RAW_TRANSACTION,
      RAW_TRANSACTION_TXID,
      0,
    ),
    /transport lost/u,
  );
  assert.equal(admissionCalls, 1);
  assert.deepEqual(cliCalls, []);
  assert.deepEqual(observeLayer1BchnChipnetRpc(rpc).methodCounts, {
    getblockhash: 1,
    getrawtransaction: 1,
    gettxout: 1,
    scantxoutset: 0,
    sendrawtransaction: 1,
    testmempoolaccept: 0,
  });
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

test('importing and constructing the public product transport never creates an SSH control directory', () => {
  const runtimeDirectory = mkdtempSync(path.join(os.tmpdir(), 'shieldkit-public-transport-'));
  try {
    const moduleUrl = new URL('./chipnet-rpc.mjs', import.meta.url).href;
    const program = `
      const { createPublicChipnetFulcrumRpcForTest } = await import(${JSON.stringify(moduleUrl)});
      const rpc = await createPublicChipnetFulcrumRpcForTest({
        endpoints: [
          { host: 'one.example', port: 50002, tls: true },
          { host: 'two.example', port: 50002, tls: true },
        ],
        openSession: async () => ({
          async request(method) {
            if (method === 'server.features') return { genesis_hash: ${JSON.stringify(CHIPNET_GENESIS_HASH)} };
            if (method === 'server.version') return ['Fulcrum', '1.6'];
            throw new Error('unexpected method');
          },
          close() {},
        }),
      });
      rpc.close();
    `;
    const child = spawnSync(process.execPath, ['--input-type=module', '--eval', program], {
      encoding: 'utf8',
      env: { ...process.env, XDG_RUNTIME_DIR: runtimeDirectory },
    });
    assert.equal(child.status, 0, child.stderr || child.stdout);
    assert.equal(existsSync(path.join(runtimeDirectory, 'shieldkit', 'ssh')), false);
  } finally {
    rmSync(runtimeDirectory, { force: true, recursive: true });
  }
});

test('public product transport pre-verifies two TLS/genesis-pinned providers, broadcasts once, and independently attests exact bytes', async () => {
  const fixture = publicElectrumFixture();
  const rpc = await createPublicChipnetFulcrumRpcForTest(fixture);
  assert.strictEqual(assertChipnetProductRpc(rpc), rpc);
  assert.equal(rpc.backend, 'public-chipnet-fulcrum-tls');
  assert.equal(Object.hasOwn(rpc, 'testmempoolaccept'), false);
  assert.equal(Object.hasOwn(rpc, 'sendrawtransaction'), false);

  const result = await rpc.submitV2SinglePassAdmission(
    fixture.transaction.raw,
    fixture.transaction.transactionId,
    0,
  );
  assert.equal(result.rawTransaction.hex, fixture.transaction.raw);
  assert.equal(result.stateOutput.valueSatoshis, '546');
  assert.equal(result.stateOutput.scriptPubKey.hex, '51');
  assert.equal(result.stateOutput.tokenData.nft.capability, 'mutable');
  assert.equal(result.stateOutput.tokenData.category, fixture.transaction.category);

  const broadcasts = fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.broadcast');
  assert.deepEqual(broadcasts, [{
    host: 'one.example',
    method: 'blockchain.transaction.broadcast',
    params: [fixture.transaction.raw],
  }]);
  assert.equal(fixture.calls.some((call) => call.host === 'one.example'
    && call.method === 'blockchain.transaction.get'), false);
  assert.deepEqual(
    fixture.calls.filter((call) => call.host === 'two.example'
      && /blockchain\.(?:transaction\.get|utxo\.get_info)/u.test(call.method))
      .map((call) => call.method),
    ['blockchain.transaction.get', 'blockchain.utxo.get_info'],
  );
  assert.deepEqual(observeChipnetProductRpc(rpc), {
    backend: 'public-chipnet-fulcrum-tls',
    genesis: CHIPNET_GENESIS_HASH,
    methodCounts: {
      getblockhash: 0, getrawtransaction: 1, gettxout: 1, scantxoutset: 0,
      sendrawtransaction: 1, testmempoolaccept: 0,
    },
    physicalMethodCounts: {
      'server.features': 2,
      'server.version': 2,
      'blockchain.transaction.broadcast': 1,
      'blockchain.transaction.get': 1,
      'blockchain.utxo.get_info': 1,
      'blockchain.scripthash.listunspent': 0,
    },
  });
  rpc.close();
  rpc.close();
  assert.deepEqual(fixture.closes, ['one.example', 'two.example']);
  await assert.rejects(
    rpc.getrawtransaction(fixture.transaction.transactionId),
    /capability is closed/u,
  );
});

test('three-provider product admission resolves from a two-provider exact-readback quorum without waiting for the broadcaster response', async () => {
  const fixture = publicElectrumFixture();
  const endpoints = Object.freeze([
    ...fixture.endpoints,
    Object.freeze({ host: 'three.example', port: 50002, tls: true }),
  ]);
  let releaseBroadcast;
  let broadcastSettled = false;
  let broadcastCalls = 0;
  const openSession = async (endpoint) => {
    const session = await fixture.openSession(endpoint);
    return Object.freeze({
      async request(method, params) {
        if (method === 'blockchain.transaction.broadcast') {
          broadcastCalls += 1;
          return new Promise((resolve) => {
            releaseBroadcast = () => {
              broadcastSettled = true;
              resolve(fixture.transaction.transactionId);
            };
          });
        }
        return session.request(method, params);
      },
      close: session.close,
    });
  };
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    endpoints,
    openSession,
    postBroadcastReadbackAttempts: 1,
    postBroadcastReadbackDelayMs: 0,
  });
  let admissionTimeout;
  const result = await Promise.race([
    rpc.submitV2SinglePassAdmission(
      fixture.transaction.raw,
      fixture.transaction.transactionId,
      0,
    ),
    new Promise((_, reject) => {
      admissionTimeout = setTimeout(
        () => reject(new Error('admission waited for the broadcaster response')),
        1_000,
      );
    }),
  ]);
  clearTimeout(admissionTimeout);
  assert.equal(broadcastSettled, false);
  assert.equal(result.transactionId, fixture.transaction.transactionId);
  assert.equal(result.rawTransaction.hex, fixture.transaction.raw);
  assert.equal(result.stateOutput.valueSatoshis, '546');
  for (const host of ['two.example', 'three.example']) {
    assert.equal(fixture.calls.some((call) => call.host === host
      && call.method === 'blockchain.transaction.get'), true);
    assert.equal(fixture.calls.some((call) => call.host === host
      && call.method === 'blockchain.utxo.get_info'), true);
  }
  assert.equal(fixture.calls.some((call) => call.host === 'one.example'
    && call.method === 'blockchain.transaction.get'), true);
  assert.equal(broadcastCalls, 1);
  releaseBroadcast();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(broadcastSettled, true);
  rpc.close();
});

test('three-provider admission stays indeterminate when fewer than two providers have exact visibility', async () => {
  const fixture = publicElectrumFixture({
    broadcastError: new Error('transport lost'),
    outputInfoByHost: { 'one.example': null, 'three.example': null },
  });
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    ...fixture,
    endpoints: Object.freeze([
      ...fixture.endpoints,
      Object.freeze({ host: 'three.example', port: 50002, tls: true }),
    ]),
    postBroadcastReadbackAttempts: 1,
    postBroadcastReadbackDelayMs: 0,
  });
  await assert.rejects(
    rpc.submitV2SinglePassAdmission(
      fixture.transaction.raw,
      fixture.transaction.transactionId,
      0,
    ),
    /outcome is indeterminate/u,
  );
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.broadcast').length, 1);
  rpc.close();
});

test('three-provider witness polling keeps the pre-verified read-only sessions instead of reconnecting them', async () => {
  const fixture = publicElectrumFixture();
  const endpoints = Object.freeze([
    ...fixture.endpoints,
    Object.freeze({ host: 'three.example', port: 50002, tls: true }),
  ]);
  const opens = new Map();
  const rawAttempts = new Map();
  const openSession = async (endpoint) => {
    opens.set(endpoint.host, (opens.get(endpoint.host) ?? 0) + 1);
    const session = await fixture.openSession(endpoint);
    return Object.freeze({
      async request(method, params) {
        if (method === 'blockchain.transaction.get' && endpoint.host !== 'one.example') {
          const attempts = (rawAttempts.get(endpoint.host) ?? 0) + 1;
          rawAttempts.set(endpoint.host, attempts);
          if (attempts === 1) throw new Error('not propagated yet');
        }
        return session.request(method, params);
      },
      close: session.close,
    });
  };
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    endpoints,
    openSession,
    postBroadcastReadbackAttempts: 2,
    postBroadcastReadbackDelayMs: 0,
  });
  const result = await rpc.submitV2SinglePassAdmission(
    fixture.transaction.raw,
    fixture.transaction.transactionId,
    0,
  );
  assert.equal(result.transactionId, fixture.transaction.transactionId);
  assert.deepEqual(Object.fromEntries(opens), {
    'one.example': 1,
    'two.example': 1,
    'three.example': 1,
  });
  assert.deepEqual(Object.fromEntries(rawAttempts), {
    'two.example': 2,
    'three.example': 2,
  });
  rpc.close();
});

test('public product transport uses listunspent only for pre-1.5 negotiated providers and derives token state from raw bytes', async () => {
  const fixture = publicElectrumFixture({ negotiatedVersion: '1.4' });
  const rpc = await createPublicChipnetFulcrumRpcForTest(fixture);
  const state = await rpc.gettxout(fixture.transaction.transactionId, 0);
  assert.equal(state.valueSatoshis, '546');
  assert.equal(state.tokenData.amount, '0');
  assert.equal(fixture.calls.some((call) => call.method === 'blockchain.utxo.get_info'), false);
  assert.equal(fixture.calls.filter((call) => call.method === 'blockchain.scripthash.listunspent').length, 2);
});

test('public product admission overlaps modern exact-raw and UTXO readback, then rejects adversarial token metadata', async () => {
  const fixture = publicElectrumFixture();
  const starts = [];
  let releaseRaw;
  let rawReleased = false;
  const openSession = async (endpoint) => Object.freeze({
    async request(method, params) {
      if (method === 'server.features' || method === 'server.version') {
        return fixture.openSession(endpoint).then((session) => session.request(method, params));
      }
      starts.push(`${endpoint.host}:${method}`);
      if (method === 'blockchain.transaction.broadcast') return fixture.transaction.transactionId;
      if (method === 'blockchain.transaction.get') {
        return new Promise((resolve) => { releaseRaw = resolve; });
      }
      if (method === 'blockchain.utxo.get_info') {
        assert.equal(rawReleased, false, 'UTXO read must begin before the exact raw response resolves');
        rawReleased = true;
        releaseRaw(fixture.transaction.raw);
        return {
          value: 546,
          scripthash: fixture.transaction.scripthash,
          token_data: {
            amount: '0', category: fixture.transaction.category,
            nft: { capability: 'mutable', commitment: fixture.transaction.commitment },
          },
        };
      }
      throw new Error(`unexpected public Electrum method ${method}`);
    },
    close() {},
  });
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    endpoints: fixture.endpoints,
    openSession,
  });
  await rpc.submitV2SinglePassAdmission(
    fixture.transaction.raw,
    fixture.transaction.transactionId,
    0,
  );
  assert.deepEqual(starts, [
    'one.example:blockchain.transaction.broadcast',
    'two.example:blockchain.transaction.get',
    'two.example:blockchain.utxo.get_info',
  ]);
  rpc.close();

  const adversarial = publicElectrumFixture({
    outputInfo: {
      value: 546,
      scripthash: fixture.transaction.scripthash,
      token_data: {
        amount: '0', category: '00'.repeat(32),
        nft: { capability: 'mutable', commitment: fixture.transaction.commitment },
      },
    },
  });
  const adversarialRpc = await createPublicChipnetFulcrumRpcForTest(adversarial);
  await assert.rejects(
    adversarialRpc.submitV2SinglePassAdmission(
      adversarial.transaction.raw,
      adversarial.transaction.transactionId,
      0,
    ),
    /token metadata disagrees/u,
  );
  adversarialRpc.close();
});

test('public gettxout overlaps two-provider raw consensus with modern UTXO visibility', async () => {
  const fixture = publicElectrumFixture();
  const starts = [];
  const rawResolvers = new Map();
  let rawResponseReleased = false;
  const openSession = async (endpoint) => Object.freeze({
    async request(method, params) {
      if (method === 'server.features' || method === 'server.version') {
        return fixture.openSession(endpoint).then((session) => session.request(method, params));
      }
      starts.push(`${endpoint.host}:${method}`);
      if (method === 'blockchain.transaction.get') {
        return new Promise((resolve) => { rawResolvers.set(endpoint.host, resolve); });
      }
      if (method === 'blockchain.utxo.get_info') {
        if (!rawResponseReleased) {
          assert.equal(rawResolvers.size, 2, 'both exact raw reads must be in flight');
          rawResponseReleased = true;
          for (const resolve of rawResolvers.values()) resolve(fixture.transaction.raw);
        }
        return {
          value: 546,
          scripthash: fixture.transaction.scripthash,
          token_data: {
            amount: '0', category: fixture.transaction.category,
            nft: { capability: 'mutable', commitment: fixture.transaction.commitment },
          },
        };
      }
      throw new Error(`unexpected public Electrum method ${method}`);
    },
    close() {},
  });
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    endpoints: fixture.endpoints,
    openSession,
  });
  const state = await rpc.gettxout(fixture.transaction.transactionId, 0);
  assert.equal(state.valueSatoshis, '546');
  assert.deepEqual(starts.slice(0, 3), [
    'one.example:blockchain.transaction.get',
    'two.example:blockchain.transaction.get',
    'one.example:blockchain.utxo.get_info',
  ]);
  rpc.close();
});

test('public product transport connects both providers concurrently and shares one exact raw read across concurrent state queries', async () => {
  const fixture = publicElectrumFixture();
  const started = [];
  const openSession = async (endpoint) => {
    started.push(endpoint.host);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(started.length, 2, 'provider startup must not serialize TLS handshakes');
    return fixture.openSession(endpoint);
  };
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    endpoints: fixture.endpoints,
    openSession,
  });
  const [raw, state] = await Promise.all([
    rpc.getrawtransaction(fixture.transaction.transactionId),
    rpc.gettxout(fixture.transaction.transactionId, 0),
  ]);
  assert.equal(raw, fixture.transaction.raw);
  assert.equal(state.valueSatoshis, '546');
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.get').length, 2);
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.utxo.get_info').length, 2);
  rpc.close();
});

test('public product transport resolves a broadcast error from dual exact raw and distinct secondary state readback without failover', async () => {
  const fixture = publicElectrumFixture({
    broadcastError: new Error('transport lost'),
    // The broadcasting provider may lag in its own UTXO index. It is not the
    // independent state attestor and must not delay an otherwise exact result.
    outputInfoByHost: { 'one.example': null },
  });
  const rpc = await createPublicChipnetFulcrumRpcForTest(fixture);
  const result = await rpc.submitV2SinglePassAdmission(
    fixture.transaction.raw,
    fixture.transaction.transactionId,
    0,
  );
  assert.equal(result.transactionId, fixture.transaction.transactionId);
  assert.equal(result.rawTransaction.hex, fixture.transaction.raw);
  assert.equal(result.stateOutput.valueSatoshis, '546');
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.broadcast').length, 1);
  for (const host of ['one.example', 'two.example']) {
    assert.equal(fixture.calls.some((call) => call.host === host
      && call.method === 'blockchain.transaction.get'), true);
  }
  assert.equal(fixture.calls.some((call) => call.host === 'one.example'
    && call.method === 'blockchain.utxo.get_info'), false);
  assert.equal(fixture.calls.some((call) => call.host === 'two.example'
    && call.method === 'blockchain.utxo.get_info'), true);
  assert.deepEqual(observeChipnetProductRpc(rpc).methodCounts, {
    getblockhash: 0, getrawtransaction: 1, gettxout: 1, scantxoutset: 0,
    sendrawtransaction: 1, testmempoolaccept: 0,
  });
});

test('public product transport keeps a broadcast error indeterminate when dual exact readback is unavailable', async () => {
  const fixture = publicElectrumFixture({
    broadcastError: new Error('transport lost'),
    rawReadbackError: new Error('not indexed'),
  });
  const rpc = await createPublicChipnetFulcrumRpcForTest(fixture);
  await assert.rejects(
    rpc.submitV2SinglePassAdmission(
      fixture.transaction.raw,
      fixture.transaction.transactionId,
      0,
    ),
    /outcome is indeterminate/u,
  );
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.broadcast').length, 1);
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.get').length, 2);
});

test('public product transport absorbs bounded independent-provider indexing lag without another send', async () => {
  const fixture = publicElectrumFixture({
    broadcastError: new Error('transport lost'),
    rawReadbackFailures: 2,
  });
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    ...fixture,
    postBroadcastReadbackAttempts: 3,
    postBroadcastReadbackDelayMs: 0,
  });
  const result = await rpc.submitV2SinglePassAdmission(
    fixture.transaction.raw,
    fixture.transaction.transactionId,
    0,
  );
  assert.equal(result.transactionId, fixture.transaction.transactionId);
  assert.equal(result.rawTransaction.hex, fixture.transaction.raw);
  assert.equal(result.stateOutput.valueSatoshis, '546');
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.broadcast').length, 1);
  for (const host of ['one.example', 'two.example']) {
    assert.equal(fixture.calls.filter((call) => call.host === host
      && call.method === 'blockchain.transaction.get').length, 3);
  }
});

test('public product transport replaces stale post-send sessions once and only polls the fresh pair', async () => {
  const fixture = publicElectrumFixture();
  const opens = new Map();
  const calls = [];
  const closes = [];
  const openSession = async (endpoint) => {
    const generation = (opens.get(endpoint.host) ?? 0) + 1;
    opens.set(endpoint.host, generation);
    return Object.freeze({
      async request(method, params) {
        calls.push({ generation, host: endpoint.host, method, params });
        if (method === 'server.features') return { genesis_hash: CHIPNET_GENESIS_HASH };
        if (method === 'server.version') return ['Fulcrum', '1.6'];
        if (method === 'blockchain.transaction.broadcast') throw new Error('ambiguous send');
        if (method === 'blockchain.transaction.get') {
          if (generation === 1) throw new Error('stale original session');
          return fixture.transaction.raw;
        }
        if (method === 'blockchain.utxo.get_info') {
          return {
            value: 546,
            scripthash: fixture.transaction.scripthash,
            token_data: {
              amount: '0', category: fixture.transaction.category,
              nft: { capability: 'mutable', commitment: fixture.transaction.commitment },
            },
          };
        }
        throw new Error(`unexpected public Electrum method ${method}`);
      },
      close() { closes.push(`${endpoint.host}:${generation}`); },
    });
  };
  const rpc = await createPublicChipnetFulcrumRpcForTest({
    endpoints: fixture.endpoints,
    openSession,
    postBroadcastReadbackAttempts: 2,
    postBroadcastReadbackDelayMs: 0,
  });
  const result = await rpc.submitV2SinglePassAdmission(
    fixture.transaction.raw,
    fixture.transaction.transactionId,
    0,
  );
  assert.equal(result.transactionId, fixture.transaction.transactionId);
  assert.deepEqual(Object.fromEntries(opens), {
    'one.example': 2,
    'two.example': 2,
  });
  assert.equal(calls.filter((call) =>
    call.method === 'blockchain.transaction.broadcast').length, 1);
  assert.equal(calls.some((call) => call.generation === 1
    && call.method === 'blockchain.transaction.get'), true);
  assert.equal(calls.some((call) => call.generation === 2
    && call.method === 'blockchain.transaction.get'), true);
  assert.deepEqual(closes.sort(), ['one.example:2', 'two.example:2']);
  rpc.close();
  assert.deepEqual(closes.sort(), [
    'one.example:1', 'one.example:2', 'two.example:1', 'two.example:2',
  ]);
});

test('public exact-send bootstrap resolves a broadcast error only from dual exact raw readback', async () => {
  const fixture = publicElectrumFixture({ broadcastError: new Error('transport lost') });
  const rpc = await createPublicChipnetFulcrumRpcForTest(fixture);
  const result = await rpc.submitExactTransaction(
    fixture.transaction.raw,
    fixture.transaction.transactionId,
  );
  assert.deepEqual(result, {
    transactionId: fixture.transaction.transactionId,
    rawTransaction: {
      txid: fixture.transaction.transactionId,
      hex: fixture.transaction.raw,
    },
  });
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.broadcast').length, 1);
  assert.equal(fixture.calls.filter((call) =>
    call.method === 'blockchain.transaction.get').length, 2);
});

test('public product transport rejects an unverified genesis and non-distinct provider set before exposing send capability', async () => {
  const wrongGenesis = publicElectrumFixture({ genesis: '00'.repeat(32) });
  await assert.rejects(
    createPublicChipnetFulcrumRpcForTest(wrongGenesis),
    /two distinct public Chipnet Fulcrum TLS endpoints/u,
  );
  const fixture = publicElectrumFixture();
  await assert.rejects(
    createPublicChipnetFulcrumRpcForTest({
      ...fixture,
      endpoints: [fixture.endpoints[0], fixture.endpoints[0]],
    }),
    /two distinct public Chipnet Fulcrum TLS endpoints/u,
  );
});

test('public product transport rejects malformed, obsolete, and unnegotiated protocol versions before send capability', async () => {
  for (const negotiatedVersion of ['bogus', '1.3', '2.0', null]) {
    const fixture = publicElectrumFixture({ negotiatedVersion });
    await assert.rejects(
      createPublicChipnetFulcrumRpcForTest(fixture),
      /two distinct public Chipnet Fulcrum TLS endpoints/u,
    );
    assert.equal(fixture.calls.some((call) =>
      call.method === 'blockchain.transaction.broadcast'), false);
  }
});

test('public Electrum session bounds in-flight requests and rejects them immediately on transport close', async () => {
  class FakeTlsSocket extends EventEmitter {
    authorized = true;
    destroyed = false;
    setEncoding() {}
    write(_value, callback) { callback?.(); return true; }
    destroy() { this.destroyed = true; }
  }
  const socket = new FakeTlsSocket();
  const sessionPromise = openPublicElectrumSessionForTest(
    { host: 'bounded.example', port: 50002, tls: true },
    { connectTls: () => socket },
  );
  setImmediate(() => socket.emit('secureConnect'));
  const session = await sessionPromise;
  const pending = Array.from({ length: 32 }, (_, index) =>
    session.request('bounded.test', [index]));
  await assert.rejects(
    session.request('bounded.test', [33]),
    /in-flight request limit exceeded/u,
  );
  socket.emit('close');
  const settled = await Promise.allSettled(pending);
  assert.equal(settled.every((entry) => entry.status === 'rejected'), true);
  assert.equal(settled.every((entry) => /connection closed/u.test(entry.reason.message)), true);
});
