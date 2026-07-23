import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes } from 'node:crypto';
import { encodeActionPacket } from '../action-packet/action-packet.mjs';
import { ChainHistoryRecoveryError, recoverAuthenticatedChainHistory, serializeChainHistoryActions } from './chain-history.mjs';
import { encodePortableActionState } from './portable-action-packet.mjs';
import { constructRecipientOutput, deriveRecipientAddress, recoverRecipientOutput } from './recovery.mjs';

const hex = (byte) => byte.toString(16).padStart(2, '0').repeat(32);
const rng = () => { let counter = 1; return Object.freeze({ bytes(length) { const output = new Uint8Array(length); output[length - 1] = counter++; return output; } }); };
const actionState = ({ profileId, instanceId, sequence, next, live, reserve, marker }) => Object.freeze({
  profileId, instanceId, noteRoot: hex(marker), nullifierRoot: hex(marker + 1), nextLeafIndex: String(next), actionSequence: String(sequence),
  liveNoteCount: String(live), reserveSats: String(reserve), maximumReserve: '20000000', stateCommitment: hex(marker + 2),
});

async function historyFixture() {
  const profileId = randomBytes(32).toString('hex'); const instanceId = randomBytes(32).toString('hex'); const accountSeed = randomBytes(32);
  const address = await deriveRecipientAddress({ seed: accountSeed, profileId, instanceId });
  const deterministicRng = rng();
  const deposited = await constructRecipientOutput({ address, kind: 'deposit', slot: 0, rng: deterministicRng });
  const first = await recoverRecipientOutput({ seed: accountSeed, profileId, instanceId, kind: 'deposit', slot: 0, outputCommitment: deposited.output.cm, record: deposited.record });
  const transferred = await constructRecipientOutput({ address, kind: 'transfer', slot: 0, rng: deterministicRng });
  const initial = actionState({ profileId, instanceId, sequence: 0, next: 0, live: 0, reserve: 0, marker: 1 });
  const postDeposit = actionState({ profileId, instanceId, sequence: 1, next: 1, live: 1, reserve: 10_000_000, marker: 4 });
  const terminal = actionState({ profileId, instanceId, sequence: 2, next: 2, live: 1, reserve: 10_000_000, marker: 7 });
  const actions = [
    { kind: 'deposit', networkId: 2, preState: initial, postState: postDeposit, inputCommitment: hex(0), inputNullifier: hex(0), outputCommitment: deposited.output.cm, outputRecord: deposited.record, boundaryAmount: '10000000', withdrawalScriptHash: hex(0), transactionContextDigest: hex(20) },
    { kind: 'transfer', networkId: 2, preState: postDeposit, postState: terminal, inputCommitment: first.cm, inputNullifier: first.nf, outputCommitment: transferred.output.cm, outputRecord: transferred.record, boundaryAmount: '0', withdrawalScriptHash: hex(0), transactionContextDigest: hex(21) },
  ];
  const packets = serializeChainHistoryActions(actions);
  return { accountSeed, profileId, instanceId, initial, terminal, packets, actions, deposited, transferred };
}

test('authenticated packet history deterministically reconstructs V1 owned notes and nullifier state', async () => {
  const fixture = await historyFixture();
  const result = await recoverAuthenticatedChainHistory({
    accountSeed: fixture.accountSeed, profileId: fixture.profileId, instanceId: fixture.instanceId,
    history: { initialState: encodePortableActionState(fixture.initial), terminalState: encodePortableActionState(fixture.terminal), packets: fixture.packets },
  });
  assert.equal(result.schema, 'shield.cash/chain-history-recovery/v1');
  assert.equal(result.notes.length, 2); assert.equal(result.unspentNotes.length, 1); assert.equal(result.unspentNotes[0].cm, fixture.transferred.output.cm);
  assert.equal(result.notes[0].noteIndex, '0'); assert.equal(result.notes[0].spentAtActionSequence, '2');
  assert.deepEqual(result.spentNullifiers, [result.notes[0].nf]);
  assert.deepEqual(serializeChainHistoryActions(fixture.actions), fixture.packets, 'exact serialized fields must reproduce packet bytes');
  assert.deepEqual(Buffer.from(fixture.packets[0]), encodeActionPacket(fixture.actions[0]), 'portable action codec must match the existing Node codec');
  const directFields = await recoverAuthenticatedChainHistory({
    accountSeed: fixture.accountSeed, profileId: fixture.profileId, instanceId: fixture.instanceId,
    history: { initialState: encodePortableActionState(fixture.initial), terminalState: encodePortableActionState(fixture.terminal), actions: fixture.actions },
  });
  assert.deepEqual(directFields.unspentNotes.map((note) => note.cm), [fixture.transferred.output.cm]);
});

test('packet-history recovery rejects malformed, reordered, duplicate, truncated, and wrong-profile histories', async () => {
  const fixture = await historyFixture(); const base = {
    accountSeed: fixture.accountSeed, profileId: fixture.profileId, instanceId: fixture.instanceId,
    history: { initialState: encodePortableActionState(fixture.initial), terminalState: encodePortableActionState(fixture.terminal), packets: fixture.packets },
  };
  const cases = [
    [{ ...base, history: { ...base.history, packets: [fixture.packets[1], fixture.packets[0]] } }, 'HISTORY_DISCONTINUITY'],
    [{ ...base, history: { ...base.history, packets: [fixture.packets[0], fixture.packets[0], fixture.packets[1]] } }, 'DUPLICATE_PACKET'],
    [{ ...base, history: { ...base.history, packets: [fixture.packets[0]] } }, 'TERMINAL_STATE_MISMATCH'],
    [{ ...base, profileId: hex(99) }, 'PROFILE_MISMATCH'],
    [{ ...base, history: { ...base.history, packets: [fixture.packets[0].subarray(0, -1)] } }, 'INVALID_PACKET_BYTES'],
  ];
  for (const [input, code] of cases) await assert.rejects(() => recoverAuthenticatedChainHistory(input), (error) => error instanceof ChainHistoryRecoveryError && error.code === code);
});

test('history scan ignores an authenticated record not addressed to this account', async () => {
  const fixture = await historyFixture(); const anotherSeed = randomBytes(32);
  const result = await recoverAuthenticatedChainHistory({
    accountSeed: anotherSeed, profileId: fixture.profileId, instanceId: fixture.instanceId,
    history: { initialState: encodePortableActionState(fixture.initial), terminalState: encodePortableActionState(fixture.terminal), packets: fixture.packets },
  });
  assert.deepEqual(result.notes, []); assert.deepEqual(result.unspentNotes, []);
});
