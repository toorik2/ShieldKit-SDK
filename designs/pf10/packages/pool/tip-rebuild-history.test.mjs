/**
 * Drive shipped rebuildPublicTipFromHistory / FromRawTransactions on recover fixtures.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extractRawSettlementHistory } from '../recover/raw-settlement-history.mjs';
import { decodePortableActionPacket } from '../recover/portable-action-packet.mjs';
import {
  rebuildPublicTipFromHistory,
  rebuildPublicTipFromRawTransactions,
  TipRebuildError,
} from './tip-rebuild.mjs';

const fixture = new URL('../recover/fixtures/', import.meta.url);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

async function loadHistoryInput() {
  const [genesis, deposit, transfer, withdrawal] = await Promise.all(
    [
      'chipnet-development-genesis.json',
      'chipnet-development-deposit.json',
      'chipnet-development-transfer.json',
      'chipnet-development-withdrawal.json',
    ].map(async (name) => JSON.parse(await readFile(new URL(name, fixture)))),
  );
  const stateLockingBytecode = bytes(genesis.settlementConstants.stateLockingBytecode);
  return {
    genesis,
    deposit,
    transfer,
    withdrawal,
    input: {
      genesisTransactionId: genesis.transactionId,
      profileId: genesis.profile.profileId.slice(7),
      instanceId: genesis.profile.instanceId.slice(7),
      stateNftCategory: genesis.profile.stateNftCategory,
      stateLockingBytecode,
      stateLockSha256: createHash('sha256').update(stateLockingBytecode).digest('hex'),
      stateCarrierBaseSatoshis: genesis.settlementConstants.stateCarrierBaseSatoshis,
      rawTransactions: [
        bytes(genesis.transactionHex),
        bytes(deposit.transactionHex),
        bytes(transfer.transactionHex),
        bytes(withdrawal.transactionHex),
      ],
    },
  };
}

test('rebuildPublicTipFromHistory matches terminal packet postState vs tip NFT', async () => {
  const { input } = await loadHistoryInput();
  const history = extractRawSettlementHistory(input);
  const last = decodePortableActionPacket(history.packets.at(-1));
  const tip = rebuildPublicTipFromHistory({
    history,
    tipNft: {
      stateCommitment: last.postState.stateCommitment,
      actionSequence: last.postState.actionSequence,
      instanceId: last.postState.instanceId,
    },
  });
  assert.equal(tip.eventCount, 3);
  assert.equal(tip.state.actionSequence, last.postState.actionSequence);
  assert.equal(tip.state.stateCommitment, last.postState.stateCommitment);
  assert.ok(tip.noteLeaves.length >= 1);
});

test('rebuildPublicTipFromRawTransactions rejects truncated history', async () => {
  const { input } = await loadHistoryInput();
  assert.throws(
    () => rebuildPublicTipFromRawTransactions({
      ...input,
      rawTransactions: [input.rawTransactions[0]],
    }),
    (e) => e.code === 'TRUNCATED_HISTORY' || e.name === 'RawSettlementHistoryError',
  );
});

test('rebuildPublicTipFromHistory rejects tipNft commitment mismatch', async () => {
  const { input } = await loadHistoryInput();
  const history = extractRawSettlementHistory(input);
  assert.throws(
    () => rebuildPublicTipFromHistory({
      history,
      tipNft: {
        stateCommitment: 'ff'.repeat(32),
        actionSequence: '1',
      },
    }),
    (e) => e instanceof TipRebuildError && e.code === 'TIP_NFT_MISMATCH',
  );
});

test('rebuildPublicTipFromHistory rejects forged discontinuous packet preState', async () => {
  const { input } = await loadHistoryInput();
  const history = extractRawSettlementHistory(input);
  // Drop middle packet → continuity break when replaying remaining as-if sequential
  const forged = {
    ...history,
    packets: [history.packets[0], history.packets[2]],
  };
  // First packet ok; second packet's preState is not first postState → STATE_CONTINUITY
  assert.throws(
    () => rebuildPublicTipFromHistory({ history: forged }),
    (e) => e instanceof TipRebuildError && e.code === 'STATE_CONTINUITY',
  );
});

test('rebuildPublicTipFromRawTransactions happy path eventCount=3', async () => {
  const { input } = await loadHistoryInput();
  const history = extractRawSettlementHistory(input);
  const last = decodePortableActionPacket(history.packets.at(-1));
  const tip = rebuildPublicTipFromRawTransactions({
    ...input,
    tipNft: {
      stateCommitment: last.postState.stateCommitment,
      actionSequence: last.postState.actionSequence,
    },
  });
  assert.equal(tip.eventCount, 3);
  assert.equal(tip.state.liveNoteCount, last.postState.liveNoteCount);
});
