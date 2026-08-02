import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { secp256k1 } from '@bitauth/libauth';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { CHIPNET_GENESIS_HASH, createLayer1BchnChipnetRpcForTest } from '../chipnet-rpc.mjs';

import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from './transaction-policy.mjs';
import { buildV2BetaChipnetBootstrapFunding } from '../../profile/v2/beta-chipnet-funding.mjs';
import {
  createV2ChipnetFundingWallet,
  loadV2ChipnetFundingWallet,
  persistV2ChipnetFundingWallet,
} from './funding-wallet.mjs';
import { assertV2BetaProductWallet } from './beta-product-wallet.mjs';
import {
  assertV2BetaProductPoolFundingCapability,
  consumeV2BetaProductPoolCreateRpc,
  createV2BetaProductPoolCreateRpcForTest,
  createV2BetaProductPoolFundingForTest,
  createV2BetaProductPoolFundingWithPoolCreateRpcForTest,
  recoverV2BetaProductPoolFunding,
  V2_BETA_PRODUCT_ACTION_MAXIMUM_FEE_SATS,
  V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS,
  V2_BETA_PRODUCT_BOOTSTRAP_BINDING_SCHEMA,
  V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS,
  V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS,
  V2_BETA_PRODUCT_FUNDING_WALLET_FILENAME,
} from './beta-product-pool-funding.mjs';

const TEST_KEY = '01'.padStart(64, '0');

test('bootstrap action reserves cover the denomination, full transaction cap, and dust-safe change', () => {
  assert.equal(V2_BETA_PRODUCT_ACTION_MAXIMUM_FEE_SATS, '100000');
  assert.equal(V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS, '546');
  assert.equal(V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS, '10100546');
  assert.equal(V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS, '100546');
  assert.equal(
    BigInt(V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS)
      - 10_000_000n
      - BigInt(V2_BETA_PRODUCT_ACTION_MAXIMUM_FEE_SATS),
    BigInt(V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS),
  );
  assert.equal(
    BigInt(V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS)
      - BigInt(V2_BETA_PRODUCT_ACTION_MAXIMUM_FEE_SATS),
    BigInt(V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS),
  );
});

const hash256Hex = (bytes) => createHash('sha256')
  .update(createHash('sha256').update(bytes).digest()).digest('hex');

function temporaryDataHome() {
  const directory = mkdtempSync(join(tmpdir(), 'shieldkit-pool-funding-'));
  chmodSync(directory, 0o700);
  return directory;
}

function rawSource(valueSats, lockingBytecodeHex, marker = '00') {
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(BigInt(valueSats));
  const raw = Buffer.concat([
    Buffer.from('0100000001', 'hex'), Buffer.alloc(32, Number.parseInt(marker, 16)),
    Buffer.from('ffffffff00ffffffff01', 'hex'),
    value,
    Buffer.from('19', 'hex'), Buffer.from(lockingBytecodeHex, 'hex'), Buffer.from('00000000', 'hex'),
  ]).toString('hex');
  return parseV2RawTransaction(raw);
}

function seamFor(rpc) {
  return {
    assertRpc: (value) => value,
    createRpc: async () => rpc,
    createWallet: ({ filename }) => createV2ChipnetFundingWallet(
      { filename }, { randomBytes: () => Buffer.from(TEST_KEY, 'hex') },
    ),
    loadWallet: loadV2ChipnetFundingWallet,
    persistWallet: persistV2ChipnetFundingWallet,
  };
}

function rpcFor(entries) {
  return {
    async scanAddress() { return entries.map(({ txid, vout, valueSats }) => ({ txid, vout, sats: Number(valueSats) })); },
    async gettxout(txid, vout) {
      const entry = entries.find((item) => item.txid === txid && item.vout === vout);
      return entry?.observed ?? null;
    },
    async getrawtransaction(txid) {
      const entry = entries.find((item) => item.txid === txid);
      if (!entry) throw new Error('missing');
      return entry.raw;
    },
  };
}

function entryFor({ lock, valueSats, marker, observed = undefined, raw = undefined }) {
  const transaction = rawSource(valueSats, lock, marker);
  return {
    txid: transaction.txid,
    vout: 0,
    valueSats: String(valueSats),
    observed: observed === undefined ? { valueSatoshis: String(valueSats), scriptPubKey: { hex: lock } } : observed,
    raw: raw === undefined ? transaction.rawTransactionHex : raw,
  };
}

function hintedRpc({ raw, observed = null }) {
  const calls = [];
  return {
    calls,
    rpc: {
      async scanAddress() { calls.push('scanAddress'); throw new Error('hinted funding must not scan'); },
      async getrawtransaction(txid, verbose) {
        calls.push(`getrawtransaction:${txid}:${verbose}`);
        return raw;
      },
      async gettxout(txid, vout) {
        calls.push(`gettxout:${txid}:${vout}`);
        return observed;
      },
    },
  };
}

test('first run creates the fixed 0600 private funding wallet and returns a secret-free funding-required record', async () => {
  const dataHome = temporaryDataHome();
  try {
    const result = await createV2BetaProductPoolFundingForTest(
      { dataHome }, seamFor(rpcFor([])),
    );
    assert.equal(result.status, 'funding-required');
    assert.equal(result.fundingWallet.cashAddress.startsWith('bchtest:'), true);
    assert.equal(JSON.stringify(result).includes(TEST_KEY), false);
    const resumed = await createV2BetaProductPoolFundingForTest(
      { dataHome }, seamFor(rpcFor([])),
    );
    assert.equal(resumed.status, 'funding-required');
    assert.equal(resumed.fundingWallet.cashAddress, result.fundingWallet.cashAddress);
    const walletPath = join(dataHome, 'shieldkit', 'v2-beta-product', 'funding', V2_BETA_PRODUCT_FUNDING_WALLET_FILENAME);
    assert.equal(lstatSync(walletPath).mode & 0o777, 0o600);
  } finally { rmSync(dataHome, { recursive: true, force: true }); }
});

test('one branded fixed-route BCHN RPC is reused for funding discovery and later orchestration', async () => {
  const dataHome = temporaryDataHome();
  try {
    const calls = [];
    const poolCreateRpc = await createV2BetaProductPoolCreateRpcForTest({
      createRpc: () => createLayer1BchnChipnetRpcForTest({
        executeLayer1Cli: async (method) => {
          calls.push(method);
          if (method === 'getblockhash') return CHIPNET_GENESIS_HASH;
          if (method === 'scantxoutset') return JSON.stringify({ unspents: [] });
          throw new Error(`unexpected ${method}`);
        },
      }),
    });
    const rpc = consumeV2BetaProductPoolCreateRpc(poolCreateRpc);
    const result = await createV2BetaProductPoolFundingWithPoolCreateRpcForTest(
      { dataHome },
      poolCreateRpc,
      {
        assertRpc: value => value,
        createWallet: ({ filename }) => createV2ChipnetFundingWallet(
          { filename }, { randomBytes: () => Buffer.from(TEST_KEY, 'hex') },
        ),
        loadWallet: loadV2ChipnetFundingWallet,
        persistWallet: persistV2ChipnetFundingWallet,
      },
    );
    assert.equal(result.status, 'funding-required');
    assert.equal(rpc.backend, 'layer1-bchn-chipnet');
    assert.deepEqual(calls, ['getblockhash', 'scantxoutset']);
    assert.throws(
      () => consumeV2BetaProductPoolCreateRpc({ ...poolCreateRpc }),
      error => error?.code === 'POOL_FUNDING_RPC_CAPABILITY_REQUIRED',
    );
  } finally { rmSync(dataHome, { recursive: true, force: true }); }
});

test('hinted shared pool-create RPC reads one raw transaction and its live mempool output without a scan', async () => {
  const dataHome = temporaryDataHome();
  try {
    const calls = [];
    const lock = '76a914'.concat('751e76e8199196d454941c45d1b3a323f1433bd6', '88ac');
    const transaction = rawSource('58000000', lock, '30');
    const poolCreateRpc = await createV2BetaProductPoolCreateRpcForTest({
      createRpc: () => createLayer1BchnChipnetRpcForTest({
        executeLayer1Cli: async (method) => {
          calls.push(method);
          if (method === 'getblockhash') return CHIPNET_GENESIS_HASH;
          if (method === 'getrawtransaction') return transaction.rawTransactionHex;
          if (method === 'gettxout') return JSON.stringify({
            confirmations: 0,
            valueSatoshis: '58000000',
            scriptPubKey: { hex: lock },
          });
          throw new Error(`unexpected ${method}`);
        },
      }),
    });
    const result = await createV2BetaProductPoolFundingWithPoolCreateRpcForTest(
      { dataHome, fundingTxid: transaction.txid }, poolCreateRpc,
      {
        assertRpc: value => value,
        createWallet: ({ filename }) => createV2ChipnetFundingWallet(
          { filename }, { randomBytes: () => Buffer.from(TEST_KEY, 'hex') },
        ),
        loadWallet: loadV2ChipnetFundingWallet,
        persistWallet: persistV2ChipnetFundingWallet,
      },
    );
    assert.equal(result.status, 'bootstrap-ready');
    assert.deepEqual(calls, [
      'getblockhash', 'getrawtransaction', 'gettxout',
    ]);
  } finally { rmSync(dataHome, { recursive: true, force: true }); }
});

test('shared pool-create RPC construction rejects an arbitrary structural lookalike', async () => {
  await assert.rejects(
    createV2BetaProductPoolCreateRpcForTest({ createRpc: async () => ({ backend: 'layer1-bchn-chipnet', network: 'chipnet' }) }),
    error => error?.code === 'POOL_FUNDING_RPC_CAPABILITY_REQUIRED',
  );
});

test('funding txid hint authenticates one unconfirmed BCHN output without scanning', async () => {
  const dataHome = temporaryDataHome();
  try {
    const lock = '76a914'.concat('751e76e8199196d454941c45d1b3a323f1433bd6', '88ac');
    const transaction = rawSource('58000000', lock, '31');
    const hinted = hintedRpc({
      raw: transaction.rawTransactionHex,
      observed: {
        confirmations: 0,
        valueSatoshis: '58000000',
        scriptPubKey: { hex: lock },
      },
    });
    const result = await createV2BetaProductPoolFundingForTest(
      { dataHome, fundingTxid: transaction.txid }, seamFor(hinted.rpc),
    );
    assert.equal(result.status, 'bootstrap-ready');
    assert.equal(result.source.txid, transaction.txid);
    assert.deepEqual(hinted.calls, [
      `getrawtransaction:${transaction.txid}:false`,
      `gettxout:${transaction.txid}:0`,
    ]);
  } finally { rmSync(dataHome, { recursive: true, force: true }); }
});

test('funding txid hint rejects malformed, mismatched, wrong-lock, tokenized, and spent observations without scan fallback', async () => {
  const lock = '76a914'.concat('751e76e8199196d454941c45d1b3a323f1433bd6', '88ac');
  const exact = rawSource('58000000', lock, '32');
  const wrongLock = rawSource('58000000', `76a914${'22'.repeat(20)}88ac`, '33');
  const cases = [
    { name: 'malformed', txid: 'aa'.repeat(32), raw: '00', observed: null, gettxout: false },
    { name: 'txid-mismatch', txid: 'bb'.repeat(32), raw: exact.rawTransactionHex, observed: null, gettxout: false },
    { name: 'wrong-lock', txid: wrongLock.txid, raw: wrongLock.rawTransactionHex, observed: null, gettxout: false },
    { name: 'tokenized', txid: exact.txid, raw: exact.rawTransactionHex, observed: { valueSatoshis: '58000000', scriptPubKey: { hex: lock }, tokenData: { category: '00'.repeat(32) } }, gettxout: true },
    { name: 'spent', txid: exact.txid, raw: exact.rawTransactionHex, observed: null, gettxout: true },
  ];
  for (const fixture of cases) {
    const dataHome = temporaryDataHome();
    try {
      const hinted = hintedRpc(fixture);
      const result = await createV2BetaProductPoolFundingForTest(
        { dataHome, fundingTxid: fixture.txid }, seamFor(hinted.rpc),
      );
      assert.equal(result.status, 'funding-required', fixture.name);
      assert.equal(hinted.calls.filter((call) => call === 'scanAddress').length, 0, fixture.name);
      assert.equal(hinted.calls.filter((call) => call.startsWith('getrawtransaction:')).length, 1, fixture.name);
      assert.equal(hinted.calls.filter((call) => call.startsWith('gettxout:')).length, fixture.gettxout ? 1 : 0, fixture.name);
    } finally { rmSync(dataHome, { recursive: true, force: true }); }
  }
});

test('one-invocation funding authenticates only the user-selected UTXO, copies private custody, and never scans', async () => {
  const dataHome = temporaryDataHome();
  const userHome = temporaryDataHome();
  try {
    const userWalletPath = join(userHome, 'user-wallet.json');
    const userWallet = await createV2ChipnetFundingWallet(
      { filename: userWalletPath }, { randomBytes: () => Buffer.from(TEST_KEY, 'hex') },
    );
    const transaction = rawSource('58000000', userWallet.lockingBytecodeHex, '43');
    const hinted = hintedRpc({
      raw: transaction.rawTransactionHex,
      observed: {
        confirmations: 0,
        valueSatoshis: '58000000',
        scriptPubKey: { hex: userWallet.lockingBytecodeHex },
      },
    });
    const result = await createV2BetaProductPoolFundingForTest(
      { dataHome, fundingWalletPath: userWalletPath, fundingUtxo: `${transaction.txid}:0` },
      seamFor(hinted.rpc),
    );
    assert.equal(result.status, 'bootstrap-ready');
    assert.deepEqual(result.source, {
      lockingBytecodeHex: userWallet.lockingBytecodeHex,
      token: null,
      txid: transaction.txid,
      valueSats: '58000000',
      vout: 0,
    });
    assert.deepEqual(hinted.calls, [
      `getrawtransaction:${transaction.txid}:false`, `gettxout:${transaction.txid}:0`,
    ]);
    assert.equal(JSON.stringify(result).includes(TEST_KEY), false);
    assert.equal(JSON.stringify(result).includes(userWalletPath), false);
    const retainedPath = join(dataHome, 'shieldkit', 'v2-beta-product', 'funding', V2_BETA_PRODUCT_FUNDING_WALLET_FILENAME);
    assert.equal(lstatSync(retainedPath).mode & 0o777, 0o600);
    assert.equal((await loadV2ChipnetFundingWallet({ filename: retainedPath })).privateKeyHex, userWallet.privateKeyHex);
  } finally {
    rmSync(dataHome, { recursive: true, force: true });
    rmSync(userHome, { recursive: true, force: true });
  }
});

test('one-invocation funding rejects spent, token-bearing, foreign, and insufficient exact UTXOs without scan or custody copy', async () => {
  const cases = [
    { name: 'spent', observed: null, value: '58000000', lock: 'own' },
    { name: 'token', observed: 'token', value: '58000000', lock: 'own' },
    { name: 'foreign', observed: 'normal', value: '58000000', lock: 'foreign' },
    { name: 'insufficient', observed: 'normal', value: '546', lock: 'own', code: 'POOL_FUNDING_USER_UTXO_INSUFFICIENT' },
  ];
  for (const fixture of cases) {
    const dataHome = temporaryDataHome();
    const userHome = temporaryDataHome();
    try {
      const userWalletPath = join(userHome, 'user-wallet.json');
      const userWallet = await createV2ChipnetFundingWallet(
        { filename: userWalletPath }, { randomBytes: () => Buffer.from(TEST_KEY, 'hex') },
      );
      const lock = fixture.lock === 'own' ? userWallet.lockingBytecodeHex : `76a914${'22'.repeat(20)}88ac`;
      const transaction = rawSource(fixture.value, lock, '44');
      const observed = fixture.observed === null ? null : {
        valueSatoshis: fixture.value,
        scriptPubKey: { hex: lock },
        ...(fixture.observed === 'token' ? { tokenData: { category: '00'.repeat(32) } } : {}),
      };
      const hinted = hintedRpc({ raw: transaction.rawTransactionHex, observed });
      await assert.rejects(
        createV2BetaProductPoolFundingForTest(
          { dataHome, fundingWalletPath: userWalletPath, fundingUtxo: `${transaction.txid}:0` },
          seamFor(hinted.rpc),
        ),
        error => error?.code === (fixture.code ?? 'POOL_FUNDING_USER_UTXO_REJECTED'),
        fixture.name,
      );
      assert.equal(hinted.calls.includes('scanAddress'), false, fixture.name);
      const retainedPath = join(dataHome, 'shieldkit', 'v2-beta-product', 'funding', V2_BETA_PRODUCT_FUNDING_WALLET_FILENAME);
      assert.throws(() => lstatSync(retainedPath), { code: 'ENOENT' }, fixture.name);
    } finally {
      rmSync(dataHome, { recursive: true, force: true });
      rmSync(userHome, { recursive: true, force: true });
    }
  }
});

test('ignores tokenized, spent, mismatched, and raw-tampered observations before selecting the smallest sufficient exact UTXO', async () => {
  const dataHome = temporaryDataHome();
  try {
    const lock = '76a914'.concat('751e76e8199196d454941c45d1b3a323f1433bd6', '88ac');
    const tokenized = entryFor({ lock, valueSats: '58000000', marker: '01', observed: { valueSatoshis: '58000000', scriptPubKey: { hex: lock }, token: { category: '00'.repeat(32) } } });
    const spent = entryFor({ lock, valueSats: '58000000', marker: '02', observed: null });
    const mismatched = entryFor({ lock, valueSats: '58000000', marker: '03', observed: { valueSatoshis: '58000000', scriptPubKey: { hex: `76a914${'22'.repeat(20)}88ac` } } });
    const rawTampered = entryFor({ lock, valueSats: '58000000', marker: '04', raw: rawSource('58000001', lock, '04').rawTransactionHex });
    const larger = entryFor({ lock, valueSats: '60000000', marker: '05' });
    const selected = entryFor({ lock, valueSats: '58000000', marker: '06' });
    const result = await createV2BetaProductPoolFundingForTest(
      { dataHome }, seamFor(rpcFor([larger, rawTampered, spent, selected, mismatched, tokenized])),
    );
    assert.equal(result.status, 'bootstrap-ready');
    assert.equal(result.source.txid, selected.txid);
    assert.equal(result.source.valueSats, '58000000');
    assert.equal(Object.hasOwn(result, 'bootstrap'), false);
    assert.equal(JSON.stringify(result).includes('rawTransactionHex'), false);
    assert.equal(JSON.stringify(result).includes(TEST_KEY), false);
    const capability = assertV2BetaProductPoolFundingCapability(result.capability);
    assert.throws(
      () => assertV2BetaProductPoolFundingCapability({ ...capability }),
      (error) => error?.code === 'POOL_FUNDING_CAPABILITY_REQUIRED',
    );
    const expectedBootstrap = buildV2BetaChipnetBootstrapFunding({
      depositReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS,
      fundingPrivateKeyHex: TEST_KEY,
      fundingPublicKeyHex: result.fundingWallet.compressedPublicKeyHex,
      genesisSourceSats: '2000000',
      source: {
        lockingBytecodeHex: result.fundingWallet.lockingBytecodeHex,
        outputIndex: 0,
        token: null,
        transactionId: selected.txid,
        valueSats: '58000000',
      },
      walletLockingBytecodeHex: result.fundingWallet.lockingBytecodeHex,
      withdrawalReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS,
    });
    const expectedOutput0 = parseSerializedSourceOutput(
      parseV2RawTransaction(expectedBootstrap.rawTransactionHex).outputs[0].serializedHex,
    );
    const binding = capability.bootstrapBinding();
    assert.equal(binding.schema, V2_BETA_PRODUCT_BOOTSTRAP_BINDING_SCHEMA);
    assert.equal(binding.sourceTransactionId, expectedBootstrap.transactionId);
    assert.equal(
      binding.instanceId,
      Buffer.from(binding.sourceTransactionId, 'hex').reverse().toString('hex'),
    );
    assert.equal(
      binding.rawTransactionSha256,
      createHash('sha256').update(Buffer.from(expectedBootstrap.rawTransactionHex, 'hex')).digest('hex'),
    );
    assert.deepEqual(binding.sourceFundingOutpoint, {
      transactionId: selected.txid,
      outputIndex: 0,
    });
    assert.deepEqual(binding.output0, {
      serializedOutputSha256: expectedOutput0.sha256,
      valueSats: '2000000',
      lockingBytecodeHex: result.fundingWallet.lockingBytecodeHex,
    });
    assert.deepEqual(binding.fundingWallet, result.fundingWallet);
    assert.equal(JSON.stringify(binding).includes('rawTransactionHex'), false);
    assert.equal(JSON.stringify(binding).includes(TEST_KEY), false);
    assert.throws(() => { binding.output0.valueSats = '1'; }, TypeError);
    assert.throws(() => { binding.sourceFundingOutpoint.outputIndex = 1; }, TypeError);
    const rebound = capability.bootstrapBinding();
    assert.notEqual(rebound, binding);
    assert.deepEqual(rebound, binding);
    const recoveredFunding = await recoverV2BetaProductPoolFunding({
      dataHome,
      sourceFundingRawTxHex: expectedBootstrap.rawTransactionHex,
    });
    assert.equal(recoveredFunding.status, 'bootstrap-ready');
    assert.equal(recoveredFunding.recovered, true);
    assert.deepEqual(
      assertV2BetaProductPoolFundingCapability(recoveredFunding.capability).bootstrapBinding(),
      binding,
    );
    const incompatibleBootstrap = buildV2BetaChipnetBootstrapFunding({
      depositReserveSats: '10000000',
      fundingPrivateKeyHex: TEST_KEY,
      fundingPublicKeyHex: result.fundingWallet.compressedPublicKeyHex,
      genesisSourceSats: '2000000',
      source: {
        lockingBytecodeHex: result.fundingWallet.lockingBytecodeHex,
        outputIndex: 0,
        token: null,
        transactionId: selected.txid,
        valueSats: '58000000',
      },
      walletLockingBytecodeHex: result.fundingWallet.lockingBytecodeHex,
      withdrawalReserveSats: '1000000',
    });
    await assert.rejects(
      recoverV2BetaProductPoolFunding({
        dataHome,
        sourceFundingRawTxHex: incompatibleBootstrap.rawTransactionHex,
      }),
      (error) => error?.code === 'POOL_FUNDING_LAYOUT_INCOMPATIBLE',
    );
    const tamperedBootstrap = `${expectedBootstrap.rawTransactionHex.slice(0, -2)}${
      expectedBootstrap.rawTransactionHex.endsWith('00') ? '01' : '00'
    }`;
    await assert.rejects(
      recoverV2BetaProductPoolFunding({ dataHome, sourceFundingRawTxHex: tamperedBootstrap }),
      (error) => error?.code === 'POOL_FUNDING_RECOVERY_REJECTED',
    );
    const serialization = '0100000000000000';
    const request = {
      algorithm: 'BCH_SCHNORR_SECP256K1',
      contextHash: 'aa'.repeat(32),
      digestHex: hash256Hex(Buffer.from(serialization, 'hex')),
      fundingInputIndex: 12,
      publicKeyHex: result.fundingWallet.compressedPublicKeyHex,
      sighashContract: 'SIGHASH_ALL|UTXOS|FORKID',
      sighashType: 0x61,
      signingSerializationHex: serialization,
    };
    const signature = capability.signActionFunding(request);
    assert.equal(signature.length, 64);
    assert.equal(secp256k1.verifySignatureSchnorr(
      signature,
      Buffer.from(result.fundingWallet.compressedPublicKeyHex, 'hex'),
      Buffer.from(request.digestHex, 'hex'),
    ), true);
    assert.throws(
      () => capability.signActionFunding({ ...request, digestHex: '00'.repeat(32) }),
      (error) => error?.code === 'POOL_FUNDING_SIGNING_REJECTED',
    );
    assert.throws(
      () => capability.signActionFunding({ ...request, publicKeyHex: `02${'00'.repeat(32)}` }),
      (error) => error?.code === 'POOL_FUNDING_SIGNING_REJECTED',
    );
    const walletDirectory = join(dataHome, 'product-wallet');
    mkdirSync(walletDirectory, { mode: 0o700 });
    const databasePath = join(walletDirectory, 'wallet.sqlite');
    const productWallet = capability.openProductWallet({
      databasePath,
      profileId: 'aa'.repeat(32),
      instanceId: 'bb'.repeat(32),
    });
    try {
      assert.equal(assertV2BetaProductWallet(productWallet), productWallet);
      const provisioned = capability.provisionProductWallet({ wallet: productWallet });
      assert.equal(provisioned.compressedPublicKeyHex, result.fundingWallet.compressedPublicKeyHex);
      assert.equal(JSON.stringify(provisioned).includes(TEST_KEY), false);
      assert.equal(productWallet.fundingWallets().some((entry) => entry.walletId === provisioned.walletId), true);
    } finally { productWallet.close(); }
    const reopened = capability.openProductWallet({
      databasePath,
      profileId: 'aa'.repeat(32),
      instanceId: 'bb'.repeat(32),
    });
    try {
      assert.equal(reopened.fundingWallets().filter((entry) =>
        entry.compressedPublicKeyHex === result.fundingWallet.compressedPublicKeyHex,
      ).length, 1);
    } finally { reopened.close(); }
    assert.throws(
      () => capability.openProductWallet({
        databasePath,
        profileId: 'cc'.repeat(32),
        instanceId: 'bb'.repeat(32),
      }),
      (error) => error?.code === 'WALLET_IDENTITY_MISMATCH',
    );
    assert.throws(
      () => capability.openProductWallet({
        databasePath: join(dataHome, 'missing-parent', 'wallet.sqlite'),
        profileId: 'aa'.repeat(32),
        instanceId: 'bb'.repeat(32),
      }),
      (error) => error?.code === 'UNSAFE_WALLET_PATH',
    );
  } finally { rmSync(dataHome, { recursive: true, force: true }); }
});

test('returns funding-required when every authenticated UTXO is insufficient for the exact five-by-five bootstrap', async () => {
  const dataHome = temporaryDataHome();
  try {
    const lock = '76a914'.concat('751e76e8199196d454941c45d1b3a323f1433bd6', '88ac');
    const insufficient = entryFor({ lock, valueSats: '53006005', marker: '07' });
    const result = await createV2BetaProductPoolFundingForTest(
      { dataHome }, seamFor(rpcFor([insufficient])),
    );
    assert.equal(result.status, 'funding-required');
    assert.equal(JSON.stringify(result).includes(TEST_KEY), false);
  } finally { rmSync(dataHome, { recursive: true, force: true }); }
});
