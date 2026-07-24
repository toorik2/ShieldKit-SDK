import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { decodeTransactionBch, encodeTransaction, hash256 } from '@bitauth/libauth';
import { createRawChainRecoveryJournal, extractProfileBoundSettlements, fetchBchnRawChainSegment, parseRawBchBlock, RawChainRecoveryError, verifyRawChainSegment } from './raw-chain-recovery.mjs';

const fixtureUrl = new URL('./fixtures/', import.meta.url);
const fromHex = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const hash = (value) => Buffer.from(hash256(value));
const display = (value) => Buffer.from(hash(value)).reverse().toString('hex');
const target = BigInt(`0x${'7fffff'.padEnd(64, '0')}`); const work = (1n << 256n) / (target + 1n);
const maximumTarget = '7fffff'.padEnd(64, '0');
const rpcWork = (value) => BigInt(value).toString(16).padStart(64, '0');
const u32 = (value) => Uint8Array.of(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
const merkle = (transactions) => {
  let level = transactions.map((transaction) => hash(transaction));
  while (level.length > 1) { if (level.length % 2 === 1) level.push(level.at(-1)); const next = []; for (let index = 0; index < level.length; index += 2) next.push(hash(Buffer.concat([level[index], level[index + 1]]))); level = next; }
  return level[0];
};
function mineBlock(previous, transactions, salt) {
  const head = new Uint8Array(80); head.set(u32(1), 0); head.set(fromHex(previous).reverse(), 4); head.set(merkle(transactions), 36); head.set(u32(salt), 68); head.set(Uint8Array.of(0xff, 0xff, 0x7f, 0x20), 72);
  for (let nonce = 0; nonce <= 0xffff_ffff; nonce += 1) { head.set(u32(nonce), 76); const id = display(head); if (BigInt(`0x${id}`) <= target) { const raw = new Uint8Array(81 + transactions.reduce((total, transaction) => total + transaction.length, 0)); raw.set(head); raw[80] = transactions.length; let offset = 81; for (const transaction of transactions) { raw.set(transaction, offset); offset += transaction.length; } return Object.freeze({ id, raw, header: new Uint8Array(head) }); } }
  throw new Error('test block did not mine');
}
const mutate = (raw, change) => { const transaction = decodeTransactionBch(raw); if (typeof transaction === 'string') throw new Error(transaction); change(transaction); return Uint8Array.from(encodeTransaction(transaction)); };
const expect = (fn, code) => assert.throws(fn, (error) => error instanceof RawChainRecoveryError && error.code === code);

async function fixtures() {
  const [genesis, deposit, transfer, withdrawal] = await Promise.all(['chipnet-development-genesis.json', 'chipnet-development-deposit.json', 'chipnet-development-transfer.json', 'chipnet-development-withdrawal.json'].map(async (name) => JSON.parse(await readFile(new URL(name, fixtureUrl)))));
  const stateLockingBytecode = fromHex(genesis.settlementConstants.stateLockingBytecode);
  const settlement = { genesisRawTransaction: fromHex(genesis.transactionHex), genesisTransactionId: genesis.transactionId, profileId: genesis.profile.profileId.slice(7), instanceId: genesis.profile.instanceId.slice(7), stateNftCategory: genesis.profile.stateNftCategory, stateLockingBytecode, stateLockSha256: createHash('sha256').update(stateLockingBytecode).digest('hex'), stateCarrierBaseSatoshis: genesis.settlementConstants.stateCarrierBaseSatoshis };
  return { settlement, deposit: fromHex(deposit.transactionHex), transfer: fromHex(transfer.transactionHex), withdrawal: fromHex(withdrawal.transactionHex) };
}
function chain(blocks) {
  const checkpoint = { blockHash: '00'.repeat(32), height: 100, chainwork: '100', maximumTarget }; const tip = { blockHash: blocks.at(-1).id, height: checkpoint.height + blocks.length, chainwork: (100n + work * BigInt(blocks.length)).toString(10) }; return { checkpoint, tip, rawBlocks: blocks.map((block) => block.raw) };
}

test('structurally parses existing Chipnet settlement fixtures inside locally mined non-consensus blocks', async () => {
  const values = await fixtures(); const first = mineBlock('00'.repeat(32), [values.deposit], 1); const second = mineBlock(first.id, [values.transfer], 2); const third = mineBlock(second.id, [values.withdrawal], 3); const input = chain([first, second, third]); const segment = verifyRawChainSegment(input);
  assert.equal(segment.blocks.length, 3); assert.equal(segment.blocks[2].height, 103); assert.equal(segment.tip.chainwork, input.tip.chainwork);
  const extracted = extractProfileBoundSettlements({ settlement: values.settlement, blocks: segment.blocks }); assert.deepEqual(extracted.settlementTransactionIds, [display(values.deposit), display(values.transfer), display(values.withdrawal)]); assert.equal(extracted.history.packets.length, 3);
  expect(() => extractProfileBoundSettlements({ settlement: { ...values.settlement, profileId: '00'.repeat(32) }, blocks: segment.blocks }), 'PROFILE_MISMATCH');
});

test('rejects truncation, broken linkage, malformed transactions, merkle corruption, and invalid proof of work', async () => {
  const values = await fixtures(); const first = mineBlock('00'.repeat(32), [values.deposit], 10); const second = mineBlock(first.id, [values.transfer], 11); const full = chain([first, second]);
  expect(() => verifyRawChainSegment({ ...full, rawBlocks: [first.raw] }), 'TRUNCATED_CHAIN');
  const badLink = mineBlock('11'.repeat(32), [values.transfer], 12); expect(() => verifyRawChainSegment({ ...full, rawBlocks: [first.raw, badLink.raw] }), 'HEADER_LINKAGE');
  const differentTransaction = mutate(values.deposit, (transaction) => { transaction.inputs[0].sequenceNumber ^= 1; }); const badMerkle = new Uint8Array(81 + differentTransaction.length); badMerkle.set(first.header); badMerkle[80] = 1; badMerkle.set(differentTransaction, 81); expect(() => parseRawBchBlock(badMerkle, { maximumTarget }), 'MERKLE_ROOT_MISMATCH');
  const malformedTransaction = new Uint8Array(first.raw.subarray(81)); malformedTransaction[4] = 0xff; const malformed = mineBlock('00'.repeat(32), [malformedTransaction], 13); expect(() => parseRawBchBlock(malformed.raw, { maximumTarget }), 'MALFORMED_TRANSACTION');
  const badPow = new Uint8Array(first.raw); for (let nonce = 0; nonce < 10000 && BigInt(`0x${display(badPow.subarray(0, 80))}`) <= target; nonce += 1) badPow[76] = (badPow[76] + 1) & 0xff; expect(() => parseRawBchBlock(badPow, { maximumTarget }), 'INVALID_PROOF_OF_WORK');
});

test('journal rolls back only to a strictly higher-work full branch and reports pending conflicts without selecting one', async () => {
  const values = await fixtures(); const one = mineBlock('00'.repeat(32), [values.deposit], 20); const alternateOne = mineBlock('00'.repeat(32), [values.deposit], 21); const alternateTwo = mineBlock(alternateOne.id, [values.transfer], 22); const journal = createRawChainRecoveryJournal({ checkpoint: chain([one]).checkpoint, settlement: values.settlement });
  const reconcile = (value, pendingTransactions) => ({ rawBlocks: value.rawBlocks, tip: value.tip, pendingTransactions });
  const initial = journal.reconcile(reconcile(chain([one]), [])); assert.equal(initial.rollbackDepth, 0); assert.equal(initial.confirmed.history.packets.length, 1);
  expect(() => journal.reconcile(reconcile(chain([alternateOne]), [])), 'PROVIDER_EQUIVOCATION');
  const replacement = journal.reconcile(reconcile(chain([alternateOne, alternateTwo]), [])); assert.equal(replacement.rollbackDepth, 1); assert.equal(replacement.appliedBlocks, 2); assert.equal(replacement.confirmed.history.packets.length, 2);
  const conflict = mutate(values.withdrawal, (transaction) => { transaction.inputs[0].sequenceNumber ^= 1; }); const state = journal.reconcile(reconcile(chain([alternateOne, alternateTwo]), [values.withdrawal, conflict])); assert.equal(state.pending.status, 'conflicted'); assert.equal(state.pending.transactions.length, 2);
  const oldTwo = mineBlock(one.id, [values.transfer], 23); const oldThree = mineBlock(oldTwo.id, [values.withdrawal], 24); const replacementTwo = mineBlock(one.id, [values.transfer], 25); const replacementThree = mineBlock(replacementTwo.id, [values.withdrawal], 26); const inert = mutate(values.deposit, (transaction) => { transaction.inputs = transaction.inputs.slice(0, 1); transaction.outputs = transaction.outputs.slice(0, 1); }); const replacementFour = mineBlock(replacementThree.id, [inert], 27); const deep = createRawChainRecoveryJournal({ checkpoint: chain([one]).checkpoint, settlement: values.settlement }); deep.reconcile(reconcile(chain([one, oldTwo, oldThree]), [])); const depthTwo = deep.reconcile(reconcile(chain([one, replacementTwo, replacementThree, replacementFour]), [])); assert.equal(depthTwo.rollbackDepth, 2); assert.equal(depthTwo.appliedBlocks, 3);
});

test('BCHN adapter derives a stable canonical Chipnet tip and every block hash by height without caller-supplied tip data', async () => {
  const values = await fixtures(); const first = mineBlock('00'.repeat(32), [values.deposit], 30); const input = chain([first]);
  const info = { chain: 'chipnet', pruned: false, initialblockdownload: false, blocks: input.tip.height, headers: input.tip.height, bestblockhash: first.id, chainwork: rpcWork(input.tip.chainwork) };
  const request = async (method, params) => {
    if (method === 'getblockchaininfo') return info;
    if (method === 'getblockhash' && params[0] === input.checkpoint.height) return input.checkpoint.blockHash;
    if (method === 'getblockhash' && params[0] === input.tip.height) return first.id;
    if (method === 'getblockheader' && params[0] === input.checkpoint.blockHash && params[1] === true) return { hash: input.checkpoint.blockHash, height: input.checkpoint.height, chainwork: rpcWork(input.checkpoint.chainwork), confirmations: 2 };
    if (method === 'getblockheader' && params[0] === first.id && params[1] === false) return Buffer.from(first.header).toString('hex');
    if (method === 'getblockheader' && params[0] === first.id && params[1] === true) return { hash: first.id, height: input.tip.height, previousblockhash: input.checkpoint.blockHash, chainwork: info.chainwork, confirmations: 1 };
    if (method === 'getblock') return Buffer.from(first.raw).toString('hex');
    throw new Error(`unexpected ${method}:${params}`);
  };
  const result = await fetchBchnRawChainSegment({ checkpoint: input.checkpoint, request }); assert.equal(result.blocks[0].id, first.id); assert.equal(result.tip.blockHash, first.id);
});

test('BCHN adapter rejects wrong networks, stale or unsynced nodes, verbose equivocation, and a reorg during fetch', async () => {
  const values = await fixtures(); const first = mineBlock('00'.repeat(32), [values.deposit], 31); const input = chain([first]);
  const info = { chain: 'chipnet', pruned: false, initialblockdownload: false, blocks: input.tip.height, headers: input.tip.height, bestblockhash: first.id, chainwork: rpcWork(input.tip.chainwork) };
  const request = (overrides = {}) => async (method, params) => {
    if (method === 'getblockchaininfo') return { ...info, ...(overrides.info ?? {}) };
    if (method === 'getblockhash' && params[0] === input.checkpoint.height) return overrides.checkpointHash ?? input.checkpoint.blockHash;
    if (method === 'getblockhash') return overrides.hash ?? first.id;
    if (method === 'getblockheader' && params[0] === input.checkpoint.blockHash && params[1] === true) return { hash: input.checkpoint.blockHash, height: input.checkpoint.height, chainwork: rpcWork(input.checkpoint.chainwork), confirmations: 2 };
    if (method === 'getblockheader' && params[1] === false) return Buffer.from(first.header).toString('hex');
    if (method === 'getblockheader' && params[1] === true) return { hash: first.id, height: input.tip.height, previousblockhash: input.checkpoint.blockHash, chainwork: overrides.headerChainwork ?? info.chainwork, confirmations: 1 };
    if (method === 'getblock') return Buffer.from(first.raw).toString('hex');
    throw new Error(`unexpected ${method}:${params}`);
  };
  await assert.rejects(() => fetchBchnRawChainSegment({ checkpoint: input.checkpoint, request: request({ info: { chain: 'main' } }) }), (error) => error instanceof RawChainRecoveryError && error.code === 'WRONG_NETWORK');
  await assert.rejects(() => fetchBchnRawChainSegment({ checkpoint: { ...input.checkpoint, height: input.tip.height + 1 }, request: request() }), (error) => error instanceof RawChainRecoveryError && error.code === 'NODE_STALE');
  await assert.rejects(() => fetchBchnRawChainSegment({ checkpoint: input.checkpoint, request: request({ info: { headers: input.tip.height + 1 } }) }), (error) => error instanceof RawChainRecoveryError && error.code === 'NODE_NOT_READY');
  await assert.rejects(() => fetchBchnRawChainSegment({ checkpoint: input.checkpoint, request: request({ info: { blocks: input.checkpoint.height + 10_001, headers: input.checkpoint.height + 10_001 } }) }), (error) => error instanceof RawChainRecoveryError && error.code === 'SCAN_RANGE_LIMIT');
  await assert.rejects(() => fetchBchnRawChainSegment({ checkpoint: input.checkpoint, request: request({ headerChainwork: rpcWork(BigInt(input.tip.chainwork) + 1n) }) }), (error) => error instanceof RawChainRecoveryError && error.code === 'RPC_EQUIVOCATION');
  const zeroSuffixInfo = { ...info, blocks: input.checkpoint.height, headers: input.checkpoint.height, bestblockhash: input.checkpoint.blockHash, chainwork: rpcWork(input.checkpoint.chainwork) };
  await assert.rejects(() => fetchBchnRawChainSegment({ checkpoint: input.checkpoint, request: request({ info: zeroSuffixInfo, checkpointHash: '22'.repeat(32) }) }), (error) => error instanceof RawChainRecoveryError && error.code === 'RPC_CHECKPOINT_MISMATCH');
  let infoCalls = 0; const reorgRequest = async (method, params) => {
    if (method === 'getblockchaininfo') { infoCalls += 1; return infoCalls === 1 ? info : { ...info, bestblockhash: '11'.repeat(32), chainwork: rpcWork(BigInt(input.tip.chainwork) + 1n) }; }
    if (method === 'getblockhash' && params[0] === input.checkpoint.height) return input.checkpoint.blockHash;
    if (method === 'getblockhash') return first.id;
    if (method === 'getblockheader' && params[0] === input.checkpoint.blockHash && params[1] === true) return { hash: input.checkpoint.blockHash, height: input.checkpoint.height, chainwork: rpcWork(input.checkpoint.chainwork), confirmations: 2 };
    if (method === 'getblockheader' && params[1] === false) return Buffer.from(first.header).toString('hex');
    if (method === 'getblockheader' && params[1] === true) return { hash: first.id, height: input.tip.height, previousblockhash: input.checkpoint.blockHash, chainwork: info.chainwork, confirmations: 1 };
    if (method === 'getblock') return Buffer.from(first.raw).toString('hex');
    throw new Error(`unexpected ${method}:${params}`);
  };
  await assert.rejects(() => fetchBchnRawChainSegment({ checkpoint: input.checkpoint, request: reorgRequest }), (error) => error instanceof RawChainRecoveryError && error.code === 'RPC_REORG_DURING_FETCH');
});
