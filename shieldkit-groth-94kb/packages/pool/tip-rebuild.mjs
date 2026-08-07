/**
 * Public tip rebuild — chain-as-log (genesis → now).
 *
 * Pure functions: feed ordered public tip events (or packets extracted from
 * raw settlements). No RPC. No private note secrets.
 *
 * Accept tip iff rebuilt stateCommitment + actionSequence match the tip NFT
 * fields supplied by the caller.
 */
import { createHash } from 'node:crypto';
import {
  decodePortableActionPacket,
  decodePortableActionState,
  encodePortableActionState,
} from '../recover/portable-action-packet.mjs';
import { extractRawSettlementHistory } from '../recover/raw-settlement-history.mjs';
import {
  createShieldedTransitionReference,
  DOMAIN_TAGS,
  frToHex,
} from '../action/transition.mjs';

export const PUBLIC_TIP_SCHEMA = 'shieldkit/public-tip/v1';

export class TipRebuildError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'TipRebuildError';
    this.code = code;
    Object.assign(this, extra);
  }
}

const fail = (code, message, extra) => {
  throw new TipRebuildError(code, message, extra);
};

const ZERO32 = '0'.repeat(64);
const HEX32 = /^[0-9a-f]{64}$/;

function hex32(v, label) {
  if (typeof v !== 'string' || !HEX32.test(v)) fail('INVALID_HEX', `${label} must be 64 lowercase hex chars`);
  return v;
}

function cloneState(s) {
  return {
    profileId: s.profileId,
    instanceId: s.instanceId,
    noteRoot: s.noteRoot,
    nullifierRoot: s.nullifierRoot,
    nextLeafIndex: String(s.nextLeafIndex),
    actionSequence: String(s.actionSequence),
    liveNoteCount: String(s.liveNoteCount),
    reserveSats: String(s.reserveSats),
    maximumReserve: String(s.maximumReserve),
    stateCommitment: s.stateCommitment,
  };
}

/**
 * Empty public tip at genesis (pre first deposit).
 * @param {{ profileId: string, instanceId: string, maximumReserve: string, emptyNoteRoot: string, emptyNullifierRoot: string }} g
 */
export function emptyPublicTip(g) {
  hex32(g.profileId, 'profileId');
  hex32(g.instanceId, 'instanceId');
  hex32(g.emptyNoteRoot, 'emptyNoteRoot');
  hex32(g.emptyNullifierRoot, 'emptyNullifierRoot');
  const state = {
    profileId: g.profileId,
    instanceId: g.instanceId,
    noteRoot: g.emptyNoteRoot,
    nullifierRoot: g.emptyNullifierRoot,
    nextLeafIndex: '0',
    actionSequence: '0',
    liveNoteCount: '0',
    reserveSats: '0',
    maximumReserve: String(g.maximumReserve),
    stateCommitment: ZERO32, // filled by protocol when first act commits; genesis tip uses empty + NFT
  };
  return Object.freeze({
    schema: PUBLIC_TIP_SCHEMA,
    state: Object.freeze(cloneState(state)),
    noteLeaves: Object.freeze([]),
    nullifierLeaves: Object.freeze([]),
    liveNoteIndices: Object.freeze([]),
    eventCount: 0,
  });
}

/**
 * Normalize a public tip event from a decoded action packet.
 * @param {object} packetDecoded — decodePortableActionPacket result
 */
export function publicTipEventFromPacket(packetDecoded) {
  if (!packetDecoded?.kind || !packetDecoded?.preState || !packetDecoded?.postState) {
    fail('INVALID_EVENT', 'packetDecoded requires kind, preState, postState');
  }
  const kind = packetDecoded.kind;
  if (kind !== 'deposit' && kind !== 'withdrawal' && kind !== 'transfer') {
    fail('INVALID_KIND', `unsupported kind ${kind}`);
  }
  return Object.freeze({
    kind,
    preState: cloneState(packetDecoded.preState),
    postState: cloneState(packetDecoded.postState),
    outputCommitment: packetDecoded.outputCommitment || ZERO32,
    inputNullifier: packetDecoded.inputNullifier || ZERO32,
    inputCommitment: packetDecoded.inputCommitment || ZERO32,
  });
}

function sameState(a, b) {
  const keys = [
    'profileId', 'instanceId', 'noteRoot', 'nullifierRoot', 'nextLeafIndex',
    'actionSequence', 'liveNoteCount', 'reserveSats', 'maximumReserve', 'stateCommitment',
  ];
  return keys.every((k) => String(a[k]) === String(b[k]));
}

/**
 * Rebuild public tip by replaying ordered public events.
 * @param {{
 *   initialState: object,
 *   events: object[],
 *   tipNft?: { stateCommitment: string, actionSequence: string, instanceId?: string },
 * }} input
 */
export function rebuildPublicTip(input) {
  if (!input || typeof input !== 'object') fail('INVALID_INPUT', 'rebuildPublicTip requires an object');
  if (!input.initialState || typeof input.initialState !== 'object') {
    fail('INVALID_INPUT', 'initialState required');
  }
  if (!Array.isArray(input.events)) fail('INVALID_INPUT', 'events must be an array');

  let state = cloneState(input.initialState);
  const noteLeaves = [];
  const nullifierLeaves = []; // [key, leafHex] — key = low 16 bytes of nullifier as decimal string when known
  const live = []; // noteIndex list

  for (let i = 0; i < input.events.length; i++) {
    const ev = input.events[i];
    if (!ev || typeof ev !== 'object') fail('INVALID_EVENT', `events[${i}] invalid`);
    if (!sameState(state, ev.preState)) {
      fail('STATE_CONTINUITY', `events[${i}] preState discontinuous`, {
        expectedSeq: state.actionSequence,
        gotSeq: ev.preState?.actionSequence,
      });
    }
    // Store raw packet field elements (commitments / nullifiers). Convert to
    // tree leaves (poseidon domain-tagged) only when exporting witness forest.
    if (ev.kind === 'deposit') {
      const cm = hex32(ev.outputCommitment, `events[${i}].outputCommitment`);
      if (cm === ZERO32) fail('INVALID_EVENT', `deposit events[${i}] missing outputCommitment`);
      const idx = noteLeaves.length;
      noteLeaves.push(cm); // commitment; leaf = H_NOTE_TREE_LEAF(cm) at forest export
      live.push(idx);
    } else if (ev.kind === 'withdrawal') {
      const nf = hex32(ev.inputNullifier, `events[${i}].inputNullifier`);
      if (nf === ZERO32) fail('INVALID_EVENT', `withdrawal events[${i}] missing inputNullifier`);
      // Sparse key = low 16 bytes of nullifier Fr (matches witness noteKey convention)
      const key = BigInt(`0x${nf.slice(32, 64)}`).toString();
      nullifierLeaves.push([key, nf]); // raw nf; leaf = H_NULLIFIER_TREE_LEAF(nf) at export
      if (live.length === 0) fail('LIVE_UNDERFLOW', `events[${i}] withdraw with empty live set`);
      live.pop();
    } else if (ev.kind === 'transfer') {
      const cm = hex32(ev.outputCommitment, `events[${i}].outputCommitment`);
      const nf = hex32(ev.inputNullifier, `events[${i}].inputNullifier`);
      if (cm === ZERO32 || nf === ZERO32) fail('INVALID_EVENT', `transfer events[${i}] incomplete`);
      const key = BigInt(`0x${nf.slice(32, 64)}`).toString();
      nullifierLeaves.push([key, nf]);
      if (live.length === 0) fail('LIVE_UNDERFLOW', `events[${i}] transfer with empty live set`);
      live.pop();
      const idx = noteLeaves.length;
      noteLeaves.push(cm);
      live.push(idx);
    } else {
      fail('INVALID_KIND', `events[${i}] kind ${ev.kind}`);
    }
    state = cloneState(ev.postState);
  }

  const tip = {
    schema: PUBLIC_TIP_SCHEMA,
    state: Object.freeze(cloneState(state)),
    /** Raw note commitments from packets (not yet domain-tagged tree leaves). */
    noteCommitments: Object.freeze([...noteLeaves]),
    /** @deprecated alias for noteCommitments during transition */
    noteLeaves: Object.freeze([...noteLeaves]),
    /** Raw nullifiers [sparseKey, nfHex] from packets. */
    nullifiers: Object.freeze(nullifierLeaves.map((row) => Object.freeze([...row]))),
    nullifierLeaves: Object.freeze(nullifierLeaves.map((row) => Object.freeze([...row]))),
    liveNoteIndices: Object.freeze([...live]),
    eventCount: input.events.length,
  };

  if (input.tipNft) {
    const nft = input.tipNft;
    hex32(nft.stateCommitment, 'tipNft.stateCommitment');
    if (String(nft.actionSequence) !== String(tip.state.actionSequence)) {
      fail('TIP_NFT_MISMATCH', 'rebuilt actionSequence does not match tip NFT', {
        rebuilt: tip.state.actionSequence,
        nft: String(nft.actionSequence),
      });
    }
    if (nft.stateCommitment !== tip.state.stateCommitment) {
      fail('TIP_NFT_MISMATCH', 'rebuilt stateCommitment does not match tip NFT', {
        rebuilt: tip.state.stateCommitment,
        nft: nft.stateCommitment,
      });
    }
    if (nft.instanceId && nft.instanceId !== tip.state.instanceId) {
      fail('TIP_NFT_MISMATCH', 'instanceId does not match tip NFT');
    }
  }

  return Object.freeze(tip);
}

/**
 * Rebuild from raw settlement history extraction (packets already authenticated).
 * @param {{
 *   history: ReturnType<typeof extractRawSettlementHistory>,
 *   tipNft?: { stateCommitment: string, actionSequence: string, instanceId?: string },
 * }} input
 */
function decodeInitialState(raw) {
  if (raw instanceof Uint8Array) return decodePortableActionState(raw);
  if (Buffer.isBuffer?.(raw)) return decodePortableActionState(new Uint8Array(raw));
  if (typeof raw === 'string' && /^[0-9a-f]+$/i.test(raw) && raw.length === 384) {
    return decodePortableActionState(Buffer.from(raw, 'hex'));
  }
  if (raw && typeof raw === 'object' && raw.profileId && raw.stateCommitment) {
    return cloneState(raw);
  }
  // extractRawSettlementHistory returns encodePortableActionState bytes as Uint8Array-like
  if (raw && typeof raw === 'object' && raw.length === 192) {
    return decodePortableActionState(Uint8Array.from(raw));
  }
  fail('INVALID_HISTORY', 'history.initialState is not decodable action state');
}

export function rebuildPublicTipFromHistory(input) {
  const history = input.history;
  if (!history?.packets?.length) fail('INVALID_HISTORY', 'history.packets required');
  const init = decodeInitialState(history.initialState);

  const events = history.packets.map((pkt, i) => {
    const bytes = pkt instanceof Uint8Array
      ? pkt
      : (pkt?.length === 752 ? Uint8Array.from(pkt) : Buffer.from(pkt));
    let decoded;
    try {
      decoded = decodePortableActionPacket(bytes);
    } catch (e) {
      fail('PACKET_DECODE', `packet[${i}]: ${e.message}`);
    }
    return publicTipEventFromPacket(decoded);
  });

  return rebuildPublicTip({ initialState: init, events, tipNft: input.tipNft });
}

/**
 * Rebuild from raw txs (networkless). Wraps extractRawSettlementHistory.
 */
export function rebuildPublicTipFromRawTransactions(config) {
  const { tipNft, ...historyInput } = config;
  const history = extractRawSettlementHistory(historyInput);
  return rebuildPublicTipFromHistory({ history, tipNft });
}

/**
 * Convert public tip → tipForest-shaped object for witness restore (no foreign secrets).
 * Domain-tags note commitments and nullifiers into tree leaves (poseidon).
 * openNoteMeta is empty; wallet merges owned note secrets at act time.
 *
 * Async: needs poseidon from transition reference.
 */
export async function publicTipToWitnessForest(publicTip) {
  if (!publicTip || publicTip.schema !== PUBLIC_TIP_SCHEMA) {
    fail('INVALID_TIP', 'publicTip.schema must be shieldkit/public-tip/v1');
  }
  const ref = await createShieldedTransitionReference();
  const cms = publicTip.noteCommitments || publicTip.noteLeaves || [];
  const noteLeaves = cms.map((cm) => {
    const leaf = ref.poseidon(DOMAIN_TAGS.NOTE_TREE_LEAF, BigInt(`0x${hex32(cm, 'noteCommitment')}`));
    return frToHex(leaf);
  });
  const rawNfs = publicTip.nullifiers || publicTip.nullifierLeaves || [];
  const nullifierLeaves = rawNfs.map((row) => {
    const nf = hex32(row[1], 'nullifier');
    const key = String(row[0]);
    const nfLeaf = frToHex(ref.poseidon(DOMAIN_TAGS.NULLIFIER_TREE_LEAF, BigInt(`0x${nf}`)));
    return Object.freeze([key, nfLeaf]);
  });
  return Object.freeze({
    schema: 'shieldkit/tip-forest/v1',
    state: Object.freeze(cloneState(publicTip.state)),
    noteLeaves: Object.freeze(noteLeaves),
    nullifierLeaves: Object.freeze(nullifierLeaves),
    openNoteMeta: Object.freeze([]),
  });
}

/**
 * Decode tip NFT commitment fields (80-byte SHST).
 * @param {Uint8Array|string} commitment
 */
export function decodeTipNftFields(commitment) {
  const buf = typeof commitment === 'string' ? Buffer.from(commitment, 'hex') : Buffer.from(commitment);
  if (buf.length !== 80) fail('INVALID_NFT', 'tip NFT commitment must be 80 bytes');
  if (buf.subarray(0, 4).toString('ascii') !== 'SHST') fail('INVALID_NFT', 'bad magic');
  return Object.freeze({
    networkId: buf[5],
    instanceId: buf.subarray(8, 40).toString('hex'),
    stateCommitment: buf.subarray(40, 72).toString('hex'),
    actionSequence: buf.readBigUInt64LE(72).toString(),
  });
}

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
