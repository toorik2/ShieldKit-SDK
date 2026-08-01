import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { decodeTransaction, encodeTransaction } from '@bitauth/libauth';

import { encodeStateNftCommitment } from '../../action/v2/state.mjs';
import { createDirectV2PoolModel } from '../../action/v2/transition.mjs';
import { buildV2BetaChipnetBootstrapFunding } from '../../profile/v2/beta-chipnet-funding.mjs';
import { openV2BetaIncrementalStore } from '../../profile/v2/beta-incremental-store.mjs';
import { deriveV2ChipnetFundingWallet } from './funding-wallet.mjs';
import {
  initializeV2BetaProductActionStoreForTest,
  V2BetaProductPoolCreateError,
} from './beta-product-pool-create.mjs';

const profileId = '42'.repeat(32);
const acceptance = '43'.repeat(32);
const genesisTxid = '44'.repeat(32);
const sourceTxid = '45'.repeat(32);
const hashes = Object.freeze({ material: '46'.repeat(32), manifest: '47'.repeat(32) });
const rejectsStore = (error) => error instanceof V2BetaProductPoolCreateError
  && error.code === 'BETA_POOL_ACTION_STORE_REJECTED';

function build({ privateKeyHex = '01'.padStart(64, '0'), depositReserveSats = '10000000' } = {}) {
  const wallet = deriveV2ChipnetFundingWallet({ privateKeyHex });
  const transaction = buildV2BetaChipnetBootstrapFunding({
    fundingPrivateKeyHex: wallet.privateKeyHex,
    fundingPublicKeyHex: wallet.compressedPublicKeyHex,
    walletLockingBytecodeHex: wallet.lockingBytecodeHex,
    source: {
      transactionId: sourceTxid,
      outputIndex: 0,
      valueSats: '70000000',
      lockingBytecodeHex: wallet.lockingBytecodeHex,
      token: null,
    },
    genesisSourceSats: '2000000',
    depositReserveSats,
    withdrawalReserveSats: '1000000',
  });
  return Object.freeze({ transaction, wallet });
}

function input({ rawTransaction, wallet, bootstrap = undefined }) {
  const txid = createHash('sha256').update(createHash('sha256').update(rawTransaction).digest()).digest().reverse().toString('hex');
  const instanceId = Buffer.from(txid, 'hex').reverse().toString('hex');
  const initialState = encodeStateNftCommitment(createDirectV2PoolModel({
    profileId, maximumLiveNotes: '100000', denominationSats: '10000000',
  }).state, { denominationSats: '10000000' });
  return Object.freeze({
    bootstrap: bootstrap ?? Object.freeze({
      sourceTransactionId: txid,
      instanceId,
      rawTransactionSha256: createHash('sha256').update(rawTransaction).digest('hex'),
      fundingWallet: Object.freeze({
        compressedPublicKeyHex: wallet.compressedPublicKeyHex,
        lockingBytecodeHex: wallet.lockingBytecodeHex,
        cashAddress: wallet.cashAddress,
      }),
    }),
    config: Object.freeze({ deploymentDirectory: '/accepted-deployment', storeDatabasePath: undefined }),
    deploymentBinding: Object.freeze({
      profileId,
      instanceId,
      sourceTransactionId: txid,
      genesisOutpoint: Object.freeze({ txid: genesisTxid, vout: 0 }),
      zeroConfEvidenceSha256: acceptance,
    }),
    rawSourceTransaction: rawTransaction,
    runtime: Object.freeze({
      identity: Object.freeze({ profileId, instanceId, denominationSats: '10000000' }),
      runtimeMaterialSha256: hashes.material,
      runtimeManifestSha256: hashes.manifest,
    }),
    wallet: Object.freeze({
      spendableFundingWallets: () => Object.freeze([Object.freeze({
        compressedPublicKeyHex: wallet.compressedPublicKeyHex,
        lockingBytecodeHex: wallet.lockingBytecodeHex,
        cashAddress: wallet.cashAddress,
      })]),
    }),
    genesis: Object.freeze({
      profileId, instanceId, initialState,
      genesisOutpoint: Object.freeze({ txid: genesisTxid, vout: 0 }),
      zeroConfEvidenceSha256: acceptance,
    }),
  });
}

function dependencies({ databasePath, genesis }) {
  return Object.freeze({
    loadCommittedGenesis: () => genesis,
    openStore: ({ databasePath: requested }) => {
      assert.equal(requested, databasePath);
      return openV2BetaIncrementalStore({ databasePath });
    },
  });
}

function storeInput(value) {
  const { genesis, ...inputValue } = value;
  return inputValue;
}

test('accepted pool-create bootstrap seeds exactly ten idempotent tokenless action funding UTXOs', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'shieldkit-pool-create-store-'));
  chmodSync(root, 0o700);
  const storeDirectory = path.join(root, 'store'); mkdirSync(storeDirectory, { mode: 0o700 });
  const databasePath = path.join(storeDirectory, 'pool.sqlite');
  try {
    const built = build();
    const value = input({ rawTransaction: Buffer.from(built.transaction.rawTransactionHex, 'hex'), wallet: built.wallet });
    const withPath = Object.freeze({ ...storeInput(value), config: Object.freeze({ ...value.config, storeDatabasePath: databasePath }) });
    const deps = dependencies({ databasePath, genesis: value.genesis });
    const first = initializeV2BetaProductActionStoreForTest(withPath, deps);
    assert.equal(first.actionFundingOutputs, 10);
    assert.match(first.actionFundingSetSha256, /^[0-9a-f]{64}$/u);
    assert.deepEqual(initializeV2BetaProductActionStoreForTest(withPath, deps), first);
    const store = openV2BetaIncrementalStore({ databasePath });
    try {
      assert.equal(store.assertBootstrapFundingComplete().setSha256.toString('hex'), first.actionFundingSetSha256);
      assert.deepEqual(store.availableFundingUtxos().map(({ vout, valueSats }) => [vout, valueSats]), [
        [1, '10000000'], [2, '10000000'], [3, '10000000'], [4, '10000000'], [5, '10000000'],
        [6, '1000000'], [7, '1000000'], [8, '1000000'], [9, '1000000'], [10, '1000000'],
      ]);
    } finally { store.close(); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('action-store bootstrap rejects altered accepted output values, locks, tokens, and provenance', () => {
  const built = build();
  const raw = Buffer.from(built.transaction.rawTransactionHex, 'hex');
  const base = input({ rawTransaction: raw, wallet: built.wallet });
  const deps = Object.freeze({ loadCommittedGenesis: () => base.genesis, openStore: () => { throw new Error('must not open'); } });
  assert.throws(() => initializeV2BetaProductActionStoreForTest(storeInput(base), deps), rejectsStore);

  const alteredValue = build({ depositReserveSats: '10000001' });
  const valueInput = input({ rawTransaction: Buffer.from(alteredValue.transaction.rawTransactionHex, 'hex'), wallet: alteredValue.wallet });
  assert.throws(() => initializeV2BetaProductActionStoreForTest(storeInput(valueInput), { ...deps, loadCommittedGenesis: () => valueInput.genesis }), rejectsStore);

  const alteredLock = build({ privateKeyHex: '02'.padStart(64, '0') });
  const lockRaw = Buffer.from(alteredLock.transaction.rawTransactionHex, 'hex');
  const lockInput = input({ rawTransaction: lockRaw, wallet: built.wallet });
  assert.throws(() => initializeV2BetaProductActionStoreForTest(storeInput(lockInput), { ...deps, loadCommittedGenesis: () => lockInput.genesis }), rejectsStore);

  const decoded = decodeTransaction(raw);
  assert.notEqual(typeof decoded, 'string');
  decoded.outputs[1].token = { category: Buffer.alloc(32, 0x51), amount: 1n };
  const tokenInput = input({ rawTransaction: Buffer.from(encodeTransaction(decoded)), wallet: built.wallet });
  assert.throws(() => initializeV2BetaProductActionStoreForTest(storeInput(tokenInput), { ...deps, loadCommittedGenesis: () => tokenInput.genesis }), rejectsStore);

  const provenanceInput = Object.freeze({
    ...storeInput(base),
    deploymentBinding: Object.freeze({ ...base.deploymentBinding, sourceTransactionId: 'ff'.repeat(32) }),
  });
  assert.throws(() => initializeV2BetaProductActionStoreForTest(provenanceInput, deps), rejectsStore);
});
