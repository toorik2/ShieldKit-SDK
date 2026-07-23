// Node-side, networkless extraction of authenticated history from caller-owned
// raw BCH transactions. This intentionally does not query a node or assert
// confirmation: provenance and raw transaction collection remain caller-owned.
import { decodeTransactionBch, hash256 } from '@bitauth/libauth';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, equalBytes, hexToBytes, isBytes } from './portable-core.mjs';
import { decodePortableActionPacket, encodePortableActionState } from './portable-action-packet.mjs';

const INPUT_PACKET_INDEX = 7; const INPUT_STATE_INDEX = 8; const SETTLEMENT_INPUTS = 10;
export class RawSettlementHistoryError extends Error { constructor(code, message) { super(message); this.name = 'RawSettlementHistoryError'; this.code = code; } }
const fail = (code, message) => { throw new RawSettlementHistoryError(code, message); };
const exactKeys = (v, l, k) => { if (v === null || Array.isArray(v) || typeof v !== 'object') fail('INVALID_OBJECT', `${l} must be an object`); const a = Object.keys(v).sort(); const b = [...k].sort(); if (a.length !== b.length || a.some((x, i) => x !== b[i])) fail('UNKNOWN_PROPERTY', `${l} has missing or unknown properties`); };
const hex32 = (v, l) => { if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v)) fail('INVALID_IDENTIFIER', `${l} must be 32 lowercase hexadecimal bytes`); return v; };
const raw = (v, l) => { if (!isBytes(v) || v.length === 0) fail('INVALID_RAW_TRANSACTION', `${l} must be a nonempty Uint8Array`); return new Uint8Array(v); };
const txid = (wire) => bytesToHex(new Uint8Array(hash256(wire)).reverse());
const lockHash = (lock) => bytesToHex(sha256(lock));
const stateCommitment = (instanceId, state) => {
  const out = new Uint8Array(80); out.set(Uint8Array.of(0x53, 0x48, 0x53, 0x54, 1, 2, 0, 0)); out.set(hexToBytes(instanceId), 8); out.set(hexToBytes(state.stateCommitment), 40);
  let sequence = BigInt(state.actionSequence); for (let i = 0; i < 8; i += 1) { out[72 + i] = Number(sequence & 0xffn); sequence >>= 8n; } return out;
};
function parse(value, index) { try { const decoded = decodeTransactionBch(value); if (typeof decoded === 'string') fail('TX_DECODE', `transaction ${index}: ${decoded}`); return decoded; } catch (e) { if (e instanceof RawSettlementHistoryError) throw e; fail('TX_DECODE', `transaction ${index} cannot be decoded`); } }
function stateOutput(output, expected, state, label) {
  if (output === undefined || !equalBytes(output.lockingBytecode, expected.stateLockingBytecode)) fail('STATE_LOCK', `${label} state locking bytecode differs`);
  if (output.token === undefined || output.token.amount !== 0n || output.token.nft === undefined || output.token.nft.capability !== 'mutable') fail('STATE_TOKEN', `${label} must carry only the mutable zero-amount state NFT`);
  if (bytesToHex(output.token.category) !== expected.stateNftCategory) fail('STATE_CATEGORY', `${label} state NFT category differs`);
  if (!equalBytes(output.token.nft.commitment, stateCommitment(expected.instanceId, state))) fail('STATE_COMMITMENT', `${label} state NFT commitment does not encode packet state`);
  if (output.valueSatoshis !== expected.stateCarrierBaseSatoshis + BigInt(state.reserveSats)) fail('STATE_VALUE', `${label} state value does not equal carrier base plus reserve`);
}
function packetFromInput(input) { const unlock = input.unlockingBytecode; if (!isBytes(unlock, 755) || unlock[0] !== 0x4d || unlock[1] !== 0xf0 || unlock[2] !== 0x02) fail('PACKET_PUSH', 'input 7 must be exactly canonical PUSHDATA2(752)'); return new Uint8Array(unlock.subarray(3)); }

/** Extract contiguous packet history from raw genesis plus raw ten-input settlements. */
export function extractRawSettlementHistory(value) {
  exactKeys(value, 'raw settlement history input', ['genesisTransactionId', 'instanceId', 'profileId', 'rawTransactions', 'stateCarrierBaseSatoshis', 'stateLockSha256', 'stateLockingBytecode', 'stateNftCategory']);
  if (typeof value.stateCarrierBaseSatoshis !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value.stateCarrierBaseSatoshis)) fail('STATE_CARRIER_BASE', 'stateCarrierBaseSatoshis must be canonical decimal');
  const expected = { profileId: hex32(value.profileId, 'profileId'), instanceId: hex32(value.instanceId, 'instanceId'), stateNftCategory: hex32(value.stateNftCategory, 'stateNftCategory'), stateLockingBytecode: raw(value.stateLockingBytecode, 'stateLockingBytecode'), stateCarrierBaseSatoshis: BigInt(value.stateCarrierBaseSatoshis) };
  if (hex32(value.stateLockSha256, 'stateLockSha256') !== lockHash(expected.stateLockingBytecode)) fail('STATE_LOCK_HASH', 'stateLockSha256 does not authenticate stateLockingBytecode');
  if (!Array.isArray(value.rawTransactions) || value.rawTransactions.length < 2) fail('TRUNCATED_HISTORY', 'raw history requires genesis and at least one settlement');
  const rows = value.rawTransactions.map((wire, index) => { const bytes = raw(wire, `rawTransactions[${index}]`); return Object.freeze({ bytes, id: txid(bytes), tx: parse(bytes, index) }); });
  const ids = new Set(); for (const row of rows) { if (ids.has(row.id)) fail('DUPLICATE_TRANSACTION', 'duplicate transaction ID in raw history'); ids.add(row.id); }
  if (rows[0].id !== hex32(value.genesisTransactionId, 'genesisTransactionId')) fail('GENESIS_ID', 'first raw transaction does not match genesisTransactionId');
  if (rows[0].tx.inputs.length === SETTLEMENT_INPUTS) fail('GENESIS_REQUIRED', 'first raw transaction must be the genesis/state parent');
  let parent = rows[0]; const packets = []; let initialState;
  for (let index = 1; index < rows.length; index += 1) {
    const row = rows[index]; if (row.tx.inputs.length !== SETTLEMENT_INPUTS) fail('SETTLEMENT_INPUT_COUNT', `transaction ${index} must contain exactly ten inputs`);
    const stateInput = row.tx.inputs[INPUT_STATE_INDEX];
    if (stateInput.outpointIndex !== 0 || bytesToHex(stateInput.outpointTransactionHash) !== parent.id) fail('STATE_ANCESTRY', `transaction ${index} input 8 must spend preceding transaction vout 0`);
    const packet = packetFromInput(row.tx.inputs[INPUT_PACKET_INDEX]); let decoded;
    try { decoded = decodePortableActionPacket(packet); } catch (e) { fail(e.code ?? 'PACKET_DECODE', `transaction ${index}: ${e.message}`); }
    if (decoded.preState.profileId !== expected.profileId || decoded.preState.instanceId !== expected.instanceId || decoded.postState.profileId !== expected.profileId || decoded.postState.instanceId !== expected.instanceId) fail('PROFILE_MISMATCH', `transaction ${index} packet profile or instance differs`);
    stateOutput(parent.tx.outputs[0], expected, decoded.preState, `transaction ${index} parent`); stateOutput(row.tx.outputs[0], expected, decoded.postState, `transaction ${index} successor`);
    if (packets.length > 0) { const prior = decodePortableActionPacket(packets.at(-1)); if (JSON.stringify(prior.postState) !== JSON.stringify(decoded.preState)) fail('STATE_CONTINUITY', `transaction ${index} packet pre-state is discontinuous`); } else initialState = encodePortableActionState(decoded.preState);
    packets.push(packet); parent = row;
  }
  return Object.freeze({ schema: 'shield.cash/raw-settlement-history/v1', qualification: 'offline raw-transaction structural extraction only; caller supplies authenticated BCH provenance and ordered transaction bytes; no node sync, confirmation, reorg, or independent-implementation claim', initialState, terminalState: encodePortableActionState(decodePortableActionPacket(packets.at(-1)).postState), packets: Object.freeze(packets), transactionIds: Object.freeze(rows.map((row) => row.id)) });
}

/** Deterministic append/rollback journal for caller-owned raw transaction branches. */
export function createRawSettlementJournal(config) { exactKeys(config, 'raw journal config', ['genesisTransactionId', 'instanceId', 'profileId', 'stateCarrierBaseSatoshis', 'stateLockSha256', 'stateLockingBytecode', 'stateNftCategory']); const entries = []; return Object.freeze({ append(rawTransaction) { entries.push(raw(rawTransaction, 'rawTransaction')); return entries.length; }, rollback(depth) { if (!Number.isSafeInteger(depth) || depth < 0 || depth >= entries.length) fail('JOURNAL_DEPTH', 'rollback depth must retain genesis'); entries.splice(entries.length - depth, depth); return entries.length; }, replay(rawTransactions) { if (!Array.isArray(rawTransactions)) fail('INVALID_HISTORY', 'replay requires an array'); for (const row of rawTransactions) entries.push(raw(row, 'rawTransaction')); return entries.length; }, extract() { return extractRawSettlementHistory({ ...config, rawTransactions: entries }); }, snapshot() { return Object.freeze(entries.map((entry) => new Uint8Array(entry))); } }); }
