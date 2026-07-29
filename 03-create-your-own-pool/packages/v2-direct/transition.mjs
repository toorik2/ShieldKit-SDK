/**
 * Independent V2 Direct state-transition reference model.
 * Enforces deposit / transfer / withdrawal counter, reserve, and tree deltas.
 */
import {
  DENOMINATION_SATS,
  NETWORK_CHIPNET,
  ZERO_32_HEX,
} from './constants.mjs';
import { frFromHex, frToHex } from './crypto/fr.mjs';
import {
  computeNullifier,
  computeOutputNoteLeaf,
  freshOutputNote,
  frToHex as noteFrToHex,
} from './crypto/note.mjs';
import {
  actionPacketPublicLimbsHexV2,
  decodeActionPacketV2,
  digestActionPacketV2,
  encodeActionPacketV2,
} from './packet.mjs';
import {
  emptyGenesisStateFields,
  normalizePoolStateV2,
  poolStatesEqual,
} from './state.mjs';
import { createIndexedNullifierTree, emptyNullifierRoot } from './trees/indexed-nullifier.mjs';
import { createNoteTree, emptyNoteRoot } from './trees/note-tree.mjs';

export class TransitionV2Error extends Error {
  constructor(message) {
    super(message);
    this.name = 'TransitionV2Error';
  }
}

const fail = (m) => {
  throw new TransitionV2Error(m);
};

/**
 * Pure public state transition (no tree path proofs).
 * Used for covenant-side checks and codec KATs.
 */
export function applyPublicStateDelta(preState, kind, {
  outputNoteLeaf = ZERO_32_HEX,
  publicNullifier = ZERO_32_HEX,
  noteRootAfter,
  nullifierRootAfter,
} = {}) {
  const pre = normalizePoolStateV2(preState, 'pre-state');
  const noteCount = BigInt(pre.noteCount);
  const nullifierCount = BigInt(pre.nullifierCount);
  const live = BigInt(pre.liveNoteCount);
  const reserve = BigInt(pre.reserveSats);
  const maxLive = BigInt(pre.maximumLiveNotes);
  const seq = BigInt(pre.actionSequence);

  if (seq + 1n >= (1n << 33n)) fail('actionSequence overflow');

  let postNoteCount = noteCount;
  let postNullifierCount = nullifierCount;
  let postReserve = reserve;
  let postNoteRoot = pre.noteRoot;
  let postNullifierRoot = pre.nullifierRoot;

  if (kind === 'deposit') {
    if (noteCount >= 0xffffffffn) fail('noteCount overflow');
    if (live >= maxLive) fail('deposit would exceed maximumLiveNotes');
    postNoteCount = noteCount + 1n;
    postReserve = reserve + DENOMINATION_SATS;
    if (noteRootAfter === undefined) fail('deposit requires noteRootAfter');
    postNoteRoot = frToHex(frFromHex(noteRootAfter, 'noteRootAfter'));
    if (outputNoteLeaf === ZERO_32_HEX) fail('deposit requires active outputNoteLeaf');
    if (publicNullifier !== ZERO_32_HEX) fail('deposit nullifier must be inactive zero');
  } else if (kind === 'transfer') {
    if (noteCount >= 0xffffffffn) fail('noteCount overflow');
    if (nullifierCount >= 0xfffffffen) fail('nullifierCount overflow');
    postNoteCount = noteCount + 1n;
    postNullifierCount = nullifierCount + 1n;
    // live and reserve unchanged
    if (noteRootAfter === undefined || nullifierRootAfter === undefined) {
      fail('transfer requires noteRootAfter and nullifierRootAfter');
    }
    postNoteRoot = frToHex(frFromHex(noteRootAfter, 'noteRootAfter'));
    postNullifierRoot = frToHex(frFromHex(nullifierRootAfter, 'nullifierRootAfter'));
    if (outputNoteLeaf === ZERO_32_HEX) fail('transfer requires active outputNoteLeaf');
  } else if (kind === 'withdrawal') {
    if (nullifierCount >= 0xfffffffen) fail('nullifierCount overflow');
    if (live < 1n) fail('withdrawal requires preLive ≥ 1');
    if (reserve < DENOMINATION_SATS) fail('withdrawal reserve underflow');
    postNullifierCount = nullifierCount + 1n;
    postReserve = reserve - DENOMINATION_SATS;
    if (nullifierRootAfter === undefined) fail('withdrawal requires nullifierRootAfter');
    postNullifierRoot = frToHex(frFromHex(nullifierRootAfter, 'nullifierRootAfter'));
    // note root unchanged
    if (outputNoteLeaf !== ZERO_32_HEX) fail('withdrawal output leaf must be inactive zero');
  } else {
    fail('unknown action kind');
  }

  return normalizePoolStateV2({
    profileId: pre.profileId,
    noteRoot: postNoteRoot,
    nullifierRoot: postNullifierRoot,
    noteCount: postNoteCount.toString(),
    nullifierCount: postNullifierCount.toString(),
    maximumLiveNotes: pre.maximumLiveNotes,
    reserveSats: postReserve.toString(),
    actionSequence: (seq + 1n).toString(),
  }, 'post-state');
}

/**
 * Full in-memory pool engine for reference transitions with trees.
 */
export function createPoolEngineV2({
  profileId,
  instanceId,
  networkId = NETWORK_CHIPNET,
  maximumLiveNotes,
  noteDepth,
  nullifierDepth,
} = {}) {
  if (!profileId || !instanceId) fail('profileId and instanceId required');
  if (!maximumLiveNotes) fail('maximumLiveNotes required');

  const noteTree = createNoteTree(noteDepth !== undefined ? { depth: noteDepth } : {});
  const nullifierTree = createIndexedNullifierTree(
    nullifierDepth !== undefined ? { depth: nullifierDepth } : {},
  );

  let state = emptyGenesisStateFields({
    profileId,
    noteRoot: noteTree.emptyRoot,
    nullifierRoot: nullifierTree.root(),
    maximumLiveNotes,
  });

  const history = [];

  function tip() {
    return state;
  }

  function deposit({
    outputNoteLeaf,
    encryptedRecord,
    transactionContextHash = ZERO_32_HEX,
  }) {
    const pre = state;
    if (BigInt(pre.liveNoteCount) >= BigInt(pre.maximumLiveNotes)) {
      fail('FUNDING_OR_CAPACITY: deposit would exceed maximumLiveNotes');
    }
    // Capacity checked before tree mutation.
    const append = noteTree.append(outputNoteLeaf);
    const post = applyPublicStateDelta(pre, 'deposit', {
      outputNoteLeaf,
      publicNullifier: ZERO_32_HEX,
      noteRootAfter: append.postRoot,
    });
    const packet = encodeActionPacketV2({
      networkId,
      kind: 'deposit',
      flags: 0,
      instanceId,
      preState: pre,
      postState: post,
      publicNullifier: ZERO_32_HEX,
      outputNoteLeaf,
      encryptedRecord,
      withdrawalLockingBytecodeHash: ZERO_32_HEX,
      transactionContextHash,
    });
    state = post;
    const result = Object.freeze({
      kind: 'deposit',
      preState: pre,
      postState: post,
      packet,
      digest: digestActionPacketV2(packet).toString('hex'),
      publicInputs: actionPacketPublicLimbsHexV2(packet),
      noteAppend: append,
    });
    history.push(result);
    return result;
  }

  function transfer({
    spendSk,
    spendRho,
    spendCm,
    outputNoteLeaf,
    encryptedRecord,
    transactionContextHash = ZERO_32_HEX,
  }) {
    const pre = state;
    const nf = computeNullifier({
      profileId: pre.profileId,
      instanceId,
      sk: spendSk,
      rho: spendRho,
      cm: spendCm,
    });
    const nfHex = frToHex(nf);
    if (nullifierTree.contains(nfHex)) fail('duplicate nullifier');
    const nfInsert = nullifierTree.insert(nfHex);
    const append = noteTree.append(outputNoteLeaf);
    const post = applyPublicStateDelta(pre, 'transfer', {
      outputNoteLeaf,
      publicNullifier: nfHex,
      noteRootAfter: append.postRoot,
      nullifierRootAfter: nfInsert.postRoot,
    });
    const packet = encodeActionPacketV2({
      networkId,
      kind: 'transfer',
      flags: 0,
      instanceId,
      preState: pre,
      postState: post,
      publicNullifier: nfHex,
      outputNoteLeaf,
      encryptedRecord,
      withdrawalLockingBytecodeHash: ZERO_32_HEX,
      transactionContextHash,
    });
    state = post;
    const result = Object.freeze({
      kind: 'transfer',
      preState: pre,
      postState: post,
      packet,
      digest: digestActionPacketV2(packet).toString('hex'),
      publicInputs: actionPacketPublicLimbsHexV2(packet),
      publicNullifier: nfHex,
      noteAppend: append,
      nullifierInsert: nfInsert,
    });
    history.push(result);
    return result;
  }

  function withdraw({
    spendSk,
    spendRho,
    spendCm,
    withdrawalLockingBytecodeHash,
    transactionContextHash = ZERO_32_HEX,
  }) {
    const pre = state;
    const nf = computeNullifier({
      profileId: pre.profileId,
      instanceId,
      sk: spendSk,
      rho: spendRho,
      cm: spendCm,
    });
    const nfHex = frToHex(nf);
    if (nullifierTree.contains(nfHex)) fail('duplicate nullifier');
    if (BigInt(pre.liveNoteCount) < 1n) fail('no live notes to withdraw');
    const nfInsert = nullifierTree.insert(nfHex);
    const post = applyPublicStateDelta(pre, 'withdrawal', {
      outputNoteLeaf: ZERO_32_HEX,
      publicNullifier: nfHex,
      nullifierRootAfter: nfInsert.postRoot,
    });
    const packet = encodeActionPacketV2({
      networkId,
      kind: 'withdrawal',
      flags: 0,
      instanceId,
      preState: pre,
      postState: post,
      publicNullifier: nfHex,
      outputNoteLeaf: ZERO_32_HEX,
      encryptedRecord: Buffer.alloc(128),
      withdrawalLockingBytecodeHash,
      transactionContextHash,
    });
    state = post;
    const result = Object.freeze({
      kind: 'withdrawal',
      preState: pre,
      postState: post,
      packet,
      digest: digestActionPacketV2(packet).toString('hex'),
      publicInputs: actionPacketPublicLimbsHexV2(packet),
      publicNullifier: nfHex,
      nullifierInsert: nfInsert,
    });
    history.push(result);
    return result;
  }

  return Object.freeze({
    profileId,
    instanceId,
    networkId,
    tip,
    deposit,
    transfer,
    withdraw,
    noteTree,
    nullifierTree,
    history: () => [...history],
    emptyNoteRoot: noteTree.emptyRoot,
    emptyNullifierRoot: nullifierTree.root(),
  });
}

export {
  emptyNoteRoot,
  emptyNullifierRoot,
  poolStatesEqual,
  normalizePoolStateV2,
  decodeActionPacketV2,
};
