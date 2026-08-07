import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { encodeTransaction } from '@bitauth/libauth';

import { CHIPNET_GENESIS_HASH, createLayer1BchnChipnetRpcForTest } from '../../kit/chipnet-rpc.mjs';
import { stageOperation, transactionIdFromHex } from '../../kit/transaction-coordinator.mjs';
import { atomicWriteJson, PRIVATE_FILE_MODE } from '../../kit/secure-files.mjs';
import {
  V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT,
  V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA,
  V2BetaFiveByFiveStoryError,
  broadcastV2BetaChipnetFiveByFiveStory,
  buildV2BetaChipnetFiveByFiveStory,
} from './beta-chipnet-five-by-five-story.mjs';
import { canonicalizeJcs } from './profile-core.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonicalSha256 = (value) => sha256(Buffer.from(canonicalizeJcs(value), 'utf8'));
const hex = (value) => Buffer.from(value).toString('hex');
const rejects = (code) => (error) => error instanceof V2BetaFiveByFiveStoryError && error.code === code;

function raw(index) {
  return hex(encodeTransaction({ version: 2, locktime: index, inputs: [{ outpointTransactionHash: new Uint8Array(32).fill(index + 1), outpointIndex: index, sequenceNumber: 0, unlockingBytecode: new Uint8Array() }], outputs: [{ valueSatoshis: 1000n, lockingBytecode: new Uint8Array([0x51]) }] }));
}

async function directory(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-beta-five-by-five-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true })); return root;
}

function stagedRecord(transactions) {
  const terminalStateHex = '5'.repeat(256); const actions = transactions.map((transaction, index) => ({ index, kind: index < 5 ? 'deposit' : 'withdrawal', transactionId: transaction.txid, rawTransactionSha256: sha256(Buffer.from(transaction.hex, 'hex')), contextHash: '6'.repeat(64), packetSha256: '7'.repeat(64), proofSha256: '8'.repeat(64), preStateSha256: '9'.repeat(64), postStateSha256: 'a'.repeat(64) })); const core = { schema: V2_BETA_FIVE_BY_FIVE_STORY_SCHEMA, status: 'staged-beta-unqualified', eligibility: 'beta-single-contributor-unqualified', claims: { broadcasted: false, mined: false, productionQualified: false }, profileId: '1'.repeat(64), instanceId: '2'.repeat(64), genesisTransactionId: '3'.repeat(64), terminalStateHex, terminalStateSha256: sha256(Buffer.from(terminalStateHex, 'hex')), actions };
  return { ...core, evidenceSha256: canonicalSha256(core) };
}

test('broadcast entrypoint refuses malformed/unbuilt stories before any BCHN call', async (t) => {
  const root = await directory(t);
  await assert.rejects(buildV2BetaChipnetFiveByFiveStory({}), rejects('BETA_STORY_INVALID'));
  await assert.rejects(broadcastV2BetaChipnetFiveByFiveStory({ acknowledgement: V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT, storyDirectory: root, rpc: {} }), rejects('BETA_STORY_RPC_REJECTED'));
});

test('broadcasts only a fully staged ten-transaction story and persists zero-conf acceptance', async (t) => {
  const root = await directory(t); const transactions = Array.from({ length: 10 }, (_, index) => { const rawTransactionHex = raw(index); return { role: index < 5 ? `deposit-${index + 1}` : `withdrawal-${index - 4}`, txid: transactionIdFromHex(rawTransactionHex), hex: rawTransactionHex }; });
  stageOperation({ poolDirectory: root, kind: 'v2-beta-chipnet-five-deposit-five-withdrawal', network: 'chipnet', setupMode: 'development-only', transactions, nextState: { status: 'accepted-zero-conf-beta-unqualified' }, ledgerRecord: { status: 'accepted-zero-conf-beta-unqualified' }, publicResult: { profileId: '1'.repeat(64), instanceId: '2'.repeat(64), actionCount: 10 } });
  atomicWriteJson(path.join(root, '.shieldkit', 'v2-beta-chipnet-five-by-five-story.json'), stagedRecord(transactions), { mode: PRIVATE_FILE_MODE });
  const calls = []; const rpc = await createLayer1BchnChipnetRpcForTest({ executeLayer1Cli: async (method, args) => { if (method === 'getblockhash') return CHIPNET_GENESIS_HASH; if (method === 'getblockcount') return '123'; if (method === 'testmempoolaccept') { const txid = transactionIdFromHex(args[0]); calls.push(`test:${txid}`); return JSON.stringify([{ allowed: true, txid }]); } if (method === 'sendrawtransaction') { const txid = transactionIdFromHex(args[0]); calls.push(`send:${txid}`); return txid; } if (method === 'getrawtransaction') { const transaction = transactions.find((entry) => entry.txid === args[0]); return JSON.stringify({ txid: transaction.txid, hex: transaction.hex }); } if (method === 'gettxout') return JSON.stringify({ tokenData: { category: '2'.repeat(64), amount: '0', nft: { capability: 'mutable', commitment: '5'.repeat(256) } } }); throw new Error(`unexpected ${method}`); } });
  const result = await broadcastV2BetaChipnetFiveByFiveStory({ acknowledgement: V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT, storyDirectory: root, rpc });
  assert.equal(result.broadcast, true); assert.equal(result.record.status, 'accepted-zero-conf-beta-unqualified'); assert.deepEqual(result.record.claims, { broadcasted: true, mined: false, productionQualified: false }); assert.equal(calls.length, 20);
});

test('rejects BCHN readback different from one exact staged byte string', async (t) => {
  const root = await directory(t); const transactions = Array.from({ length: 10 }, (_, index) => { const rawTransactionHex = raw(index); return { role: index < 5 ? `deposit-${index + 1}` : `withdrawal-${index - 4}`, txid: transactionIdFromHex(rawTransactionHex), hex: rawTransactionHex }; });
  stageOperation({ poolDirectory: root, kind: 'v2-beta-chipnet-five-deposit-five-withdrawal', network: 'chipnet', setupMode: 'development-only', transactions, nextState: {}, ledgerRecord: {}, publicResult: { profileId: '1'.repeat(64), instanceId: '2'.repeat(64), actionCount: 10 } }); atomicWriteJson(path.join(root, '.shieldkit', 'v2-beta-chipnet-five-by-five-story.json'), stagedRecord(transactions), { mode: PRIVATE_FILE_MODE });
  const rpc = await createLayer1BchnChipnetRpcForTest({ executeLayer1Cli: async (method, args) => { if (method === 'getblockhash') return CHIPNET_GENESIS_HASH; if (method === 'getblockcount') return '123'; if (method === 'testmempoolaccept') { const txid = transactionIdFromHex(args[0]); return JSON.stringify([{ allowed: true, txid }]); } if (method === 'sendrawtransaction') return transactionIdFromHex(args[0]); if (method === 'getrawtransaction') return JSON.stringify({ txid: args[0], hex: '00' }); if (method === 'gettxout') return 'null'; throw new Error(`unexpected ${method}`); } });
  await assert.rejects(broadcastV2BetaChipnetFiveByFiveStory({ acknowledgement: V2_BETA_FIVE_BY_FIVE_ACKNOWLEDGEMENT, storyDirectory: root, rpc }), rejects('BETA_STORY_READBACK_REJECTED'));
});
