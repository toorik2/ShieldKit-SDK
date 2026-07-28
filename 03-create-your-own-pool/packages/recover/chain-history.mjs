// Deterministic packet-history reconstruction. The caller supplies already
// authenticated BCH-derived packet bytes and both authenticated state anchors;
// this module performs no chain, indexer, storage, or network I/O.
import { isBytes, hex32 } from './portable-core.mjs';
import {
  ACTION_STATE_BYTES, PortableActionPacketError, decodePortableActionPacket,
  decodePortableActionState, encodePortableActionPacket, portableActionStatesEqual,
} from './portable-action-packet.mjs';
import { RecoveryError, prepareRecipientRecoveryAccount, recoverPreparedRecipientOutput } from './recovery.mjs';

const STATE_KEYS = Object.freeze(['profileId', 'instanceId', 'noteRoot', 'nullifierRoot', 'nextLeafIndex', 'actionSequence', 'liveNoteCount', 'reserveSats', 'maximumReserve', 'stateCommitment']);

export class ChainHistoryRecoveryError extends Error {
  constructor(code, message) { super(message); this.name = 'ChainHistoryRecoveryError'; this.code = code; }
}
const fail = (code, message) => { throw new ChainHistoryRecoveryError(code, message); };
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('INVALID_OBJECT', `${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};
const oneOfKeys = (value, label, alternatives) => {
  for (const expected of alternatives) {
    if (value !== null && !Array.isArray(value) && typeof value === 'object') {
      const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
      if (actual.length === wanted.length && actual.every((key, index) => key === wanted[index])) return;
    }
  }
  fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};
const id = (value, label) => { try { return hex32(value, label); } catch (error) { fail(error.code ?? 'INVALID_IDENTIFIER', error.message); } };
const seed = (value) => { if (!isBytes(value, 32)) fail('INVALID_ACCOUNT_SEED', 'accountSeed must contain exactly 32 bytes'); return new Uint8Array(value); };
const state = (value, label) => { try { return decodePortableActionState(value); } catch (error) { if (error instanceof PortableActionPacketError) fail(error.code, `${label}: ${error.message}`); throw error; } };
const exactState = (left, right) => portableActionStatesEqual(left, right);
const packet = (value, index) => { try { return decodePortableActionPacket(value); } catch (error) { if (error instanceof PortableActionPacketError) fail(error.code, `packet ${index}: ${error.message}`); throw error; } };
const fieldsPacket = (value, index) => { try { return encodePortableActionPacket(value); } catch (error) { if (error instanceof PortableActionPacketError) fail(error.code, `action ${index}: ${error.message}`); throw error; } };
const plus = (value, amount) => (BigInt(value) + amount).toString();

function assertProfile(stateValue, profileId, instanceId, label) {
  if (stateValue.profileId !== profileId || stateValue.instanceId !== instanceId) fail('PROFILE_MISMATCH', `${label} does not match requested profile and instance`);
}

function assertTransition(decoded, index) {
  const pre = decoded.preState; const post = decoded.postState;
  if (BigInt(pre.actionSequence) === 0xffff_ffff_ffff_ffffn || post.actionSequence !== plus(pre.actionSequence, 1n)) fail('INVALID_STATE_TRANSITION', `packet ${index} does not advance actionSequence by one`);
  const common = post.maximumReserve === pre.maximumReserve;
  if (!common) fail('INVALID_STATE_TRANSITION', `packet ${index} changes maximum reserve`);
  if (decoded.kind === 'deposit') {
    if (post.nextLeafIndex !== plus(pre.nextLeafIndex, 1n) || post.liveNoteCount !== plus(pre.liveNoteCount, 1n) || post.reserveSats !== plus(pre.reserveSats, 10_000_000n)) fail('INVALID_STATE_TRANSITION', `deposit packet ${index} has an invalid counter transition`);
  } else if (decoded.kind === 'transfer') {
    if (post.nextLeafIndex !== plus(pre.nextLeafIndex, 1n) || post.liveNoteCount !== pre.liveNoteCount || post.reserveSats !== pre.reserveSats) fail('INVALID_STATE_TRANSITION', `transfer packet ${index} has an invalid counter transition`);
  } else if (post.nextLeafIndex !== pre.nextLeafIndex || BigInt(pre.liveNoteCount) === 0n || BigInt(pre.reserveSats) < 10_000_000n || post.liveNoteCount !== plus(pre.liveNoteCount, -1n) || post.reserveSats !== plus(pre.reserveSats, -10_000_000n)) {
    fail('INVALID_STATE_TRANSITION', `withdrawal packet ${index} has an invalid counter transition`);
  }
}

function normalizeHistory(value) {
  oneOfKeys(value, 'authenticated history', [['initialState', 'packets', 'terminalState'], ['actions', 'initialState', 'terminalState']]);
  if (!isBytes(value.initialState, ACTION_STATE_BYTES) || !isBytes(value.terminalState, ACTION_STATE_BYTES)) fail('INVALID_HISTORY', 'history anchors must be exact 192-byte serialized states');
  const packets = value.packets === undefined
    ? serializeChainHistoryActions(value.actions)
    : (() => {
      if (!Array.isArray(value.packets)) fail('INVALID_HISTORY', 'authenticated history packets must be an array');
      return value.packets.map((value, index) => {
        if (!isBytes(value)) fail('INVALID_PACKET_BYTES', `packet ${index} must be a Uint8Array`);
        return new Uint8Array(value);
      });
    })();
  return Object.freeze({ initialState: new Uint8Array(value.initialState), terminalState: new Uint8Array(value.terminalState), packets });
}

function normaliseInput(value) {
  exactKeys(value, 'chain-history recovery input', ['accountSeed', 'history', 'instanceId', 'profileId']);
  return Object.freeze({ accountSeed: seed(value.accountSeed), history: normalizeHistory(value.history), profileId: id(value.profileId, 'profileId'), instanceId: id(value.instanceId, 'instanceId') });
}

/**
 * Recover one V2 account's notes from a caller-authenticated contiguous packet
 * segment. Start and terminal state anchors are mandatory: without them a
 * local parser cannot distinguish a complete history from a truncated prefix.
 */
export async function recoverAuthenticatedChainHistory(value) {
  const input = normaliseInput(value); const initial = state(input.history.initialState, 'initial state'); const terminal = state(input.history.terminalState, 'terminal state');
  assertProfile(initial, input.profileId, input.instanceId, 'initial state'); assertProfile(terminal, input.profileId, input.instanceId, 'terminal state');
  const account = await prepareRecipientRecoveryAccount({ seed: input.accountSeed, profileId: input.profileId, instanceId: input.instanceId });
  let previous = initial; const seenPackets = new Set(); const notesByNullifier = new Map(); const notesByCommitment = new Set(); const notes = [];
  for (let index = 0; index < input.history.packets.length; index += 1) {
    const packetBytes = input.history.packets[index]; const fingerprint = Array.from(packetBytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    if (seenPackets.has(fingerprint)) fail('DUPLICATE_PACKET', `packet ${index} duplicates an earlier packet`); seenPackets.add(fingerprint);
    const decoded = packet(packetBytes, index); assertProfile(decoded.preState, input.profileId, input.instanceId, `packet ${index} pre-state`); assertProfile(decoded.postState, input.profileId, input.instanceId, `packet ${index} post-state`);
    if (!exactState(previous, decoded.preState)) fail('HISTORY_DISCONTINUITY', `packet ${index} pre-state does not match the preceding authenticated state`);
    assertTransition(decoded, index);
    if (decoded.kind !== 'deposit') {
      // Spends are linked to owned notes by nullifier only.
      const spent = notesByNullifier.get(decoded.inputNullifier);
      if (spent !== undefined) {
        if (spent.spentAtActionSequence !== null) fail('DUPLICATE_NULLIFIER', `packet ${index} spends an already-spent owned note`);
        spent.spentAtActionSequence = decoded.postState.actionSequence;
      }
    }
    if (decoded.kind !== 'withdrawal') {
      // The current action shape has its single active output in slot zero.
      try {
        const note = await recoverPreparedRecipientOutput({ account, kind: decoded.kind, slot: 0, outputCommitment: decoded.outputCommitment, record: decoded.outputRecord });
        if (notesByCommitment.has(note.cm)) fail('DUPLICATE_COMMITMENT', `packet ${index} repeats an owned output commitment`);
        if (notesByNullifier.has(note.nf)) fail('DUPLICATE_NULLIFIER', `packet ${index} reuses an owned note nullifier`);
        notesByCommitment.add(note.cm);
        const owned = { ...note, noteIndex: decoded.preState.nextLeafIndex, createdAtActionSequence: decoded.postState.actionSequence, spentAtActionSequence: null };
        notesByNullifier.set(owned.nf, owned); notes.push(owned);
      } catch (error) {
        // A valid encrypted record for another recipient is indistinguishable
        // from an authentication failure by design. Structural packet errors
        // were rejected above; do not turn unrelated notes into scan failures.
        if (!(error instanceof RecoveryError) || error.code !== 'RECORD_AUTHENTICATION_FAILED') throw error;
      }
    }
    previous = decoded.postState;
  }
  if (!exactState(previous, terminal)) fail('TERMINAL_STATE_MISMATCH', 'terminal state does not match the authenticated packet history');
  const frozenNotes = notes.map((note) => Object.freeze(note)); const unspentNotes = frozenNotes.filter((note) => note.spentAtActionSequence === null);
  return Object.freeze({
    schema: 'shield.cash/chain-history-recovery/v2',
    qualification: 'deterministic local V2 packet reconstruction only; caller must authenticate BCH provenance, ordering, and both state anchors; no node sync, reorg, history-scale, or independent-implementation claim',
    profileId: input.profileId, instanceId: input.instanceId, initialState: Object.freeze(initial), terminalState: Object.freeze(terminal),
    notes: Object.freeze(frozenNotes), unspentNotes: Object.freeze(unspentNotes), spentNullifiers: Object.freeze(frozenNotes.filter((note) => note.spentAtActionSequence !== null).map((note) => note.nf)),
  });
}

/** Accept exact decoded action fields by serializing them through the portable codec. */
export function serializeChainHistoryActions(actions) {
  if (!Array.isArray(actions)) fail('INVALID_HISTORY', 'actions must be an array');
  return Object.freeze(actions.map((action, index) => fieldsPacket(action, index)));
}

export const CHAIN_HISTORY_LAYOUT = Object.freeze({ schema: 'shield.cash/chain-history-recovery/v2', actionPacketBytes: 752, actionPacketAbi: 'shielded-action-public-input-v1', actionStateBytes: ACTION_STATE_BYTES, activeOutputSlot: 0 });
