import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createRawSettlementJournal, extractRawSettlementHistory, RawSettlementHistoryError } from './raw-settlement-history.mjs';

const fixture = new URL('./fixtures/', import.meta.url);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
async function load() { const [genesis, deposit, transfer, withdrawal] = await Promise.all(['chipnet-development-genesis.json', 'chipnet-development-deposit.json', 'chipnet-development-transfer.json', 'chipnet-development-withdrawal.json'].map(async (name) => JSON.parse(await readFile(new URL(name, fixture))))); return { genesis, deposit, transfer, withdrawal, input: { genesisTransactionId: genesis.transactionId, profileId: genesis.profile.profileId.slice(7), instanceId: genesis.profile.instanceId.slice(7), stateNftCategory: genesis.profile.stateNftCategory, stateLockingBytecode: bytes(genesis.settlementConstants.stateLockingBytecode), stateLockSha256: '', stateCarrierBaseSatoshis: genesis.settlementConstants.stateCarrierBaseSatoshis, rawTransactions: [bytes(genesis.transactionHex), bytes(deposit.transactionHex), bytes(transfer.transactionHex), bytes(withdrawal.transactionHex)] } }; }

test('extracts exact authenticated anchors and packet chain from public raw genesis/deposit/transfer/withdrawal fixtures', async () => {
  const { input } = await load(); const { createHash } = await import('node:crypto'); input.stateLockSha256 = createHash('sha256').update(input.stateLockingBytecode).digest('hex');
  const history = extractRawSettlementHistory(input); assert.equal(history.packets.length, 3); assert.equal(history.initialState.length, 192); assert.equal(history.terminalState.length, 192); assert.equal(history.transactionIds.length, 4); assert.deepEqual(history.transactionIds, input.rawTransactions.map((_, index) => [input.genesisTransactionId, '56563c2c3a81857216853b53293c0cedc8f4baaa15b2430553be57a0d57a6cf1', 'ffa7fe6cb706546368a4f2dd14243a5c73a7d0dcc90d570f1238592387baa38b', '14f6363290f73fdd7e723491110c458de8efa8e90b7e7dfa6675381e1175c2e0'][index]));
});

test('rejects transaction, packet, state-category, ancestry, ordering, truncation, and equivocation mutations', async () => {
  const { input } = await load(); const { createHash } = await import('node:crypto'); input.stateLockSha256 = createHash('sha256').update(input.stateLockingBytecode).digest('hex');
  const cases = [
    { ...input, rawTransactions: [input.rawTransactions[0]] },
    { ...input, rawTransactions: [input.rawTransactions[1], input.rawTransactions[0]] },
    { ...input, rawTransactions: [input.rawTransactions[0], input.rawTransactions[1], input.rawTransactions[1]] },
    { ...input, stateNftCategory: '00'.repeat(32) },
    { ...input, rawTransactions: [input.rawTransactions[0], input.rawTransactions[1].subarray(0, -1)] },
  ];
  for (const value of cases) assert.throws(() => extractRawSettlementHistory(value), RawSettlementHistoryError);
});

test('raw journal rolls back and replays deterministic caller supplied branches', async () => {
  const { input } = await load(); const { createHash } = await import('node:crypto'); input.stateLockSha256 = createHash('sha256').update(input.stateLockingBytecode).digest('hex'); const { rawTransactions, ...config } = input;
  const journal = createRawSettlementJournal(config); journal.append(rawTransactions[0]); journal.append(rawTransactions[1]); assert.equal(journal.extract().packets.length, 1); journal.rollback(1); assert.equal(journal.snapshot().length, 1); journal.replay([rawTransactions[1]]); assert.equal(journal.extract().packets.length, 1);
});

test('synthetic structural journal exercises rollback and replay depths 1, 2, 10, and 100', async () => {
  const { input } = await load(); const { createHash } = await import('node:crypto'); input.stateLockSha256 = createHash('sha256').update(input.stateLockingBytecode).digest('hex'); const { rawTransactions, ...config } = input;
  const journal = createRawSettlementJournal(config); const synthetic = Array.from({ length: 101 }, () => rawTransactions[0]); for (const entry of synthetic) journal.append(entry);
  for (const depth of [1, 2, 10, 100]) { const before = journal.snapshot().length; journal.rollback(depth); assert.equal(journal.snapshot().length, before - depth); journal.replay(synthetic.slice(0, depth)); assert.equal(journal.snapshot().length, before); }
});

test('synthetic structural journal retains and snapshots a 10,000-entry replay workload', async () => {
  const { input } = await load(); const { createHash } = await import('node:crypto'); input.stateLockSha256 = createHash('sha256').update(input.stateLockingBytecode).digest('hex'); const { rawTransactions, ...config } = input;
  const journal = createRawSettlementJournal(config); const synthetic = Array.from({ length: 10_001 }, () => rawTransactions[0]); journal.replay(synthetic); assert.equal(journal.snapshot().length, 10_001); journal.rollback(10_000); assert.equal(journal.snapshot().length, 1);
});
