import {
  audit as auditNullifierTree,
  create as createNullifierTree,
  insert as insertNullifier,
} from './indexed-nullifier-tree.mjs';
import {
  append as appendNote,
  audit as auditNoteTree,
  create as createNoteTree,
  membershipPath,
  verifyMembershipPath,
} from './note-tree.mjs';
import {
  encodeActionPacket,
  actionPacketPublicLimbs,
  digestActionPacket,
  ENCRYPTED_RECORD_BYTES,
} from './packet.mjs';
import {
  hashEmptyNoteLeaf,
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
  hashNoteTreeNode,
  frFromCanonicalHex,
  frToCanonicalHex,
} from './poseidon.mjs';
import {
  encodeStateNftCommitment,
  validateStateNftCommitment,
} from './state.mjs';
import { isSupportedDirectV2NetworkId } from './network.mjs';

export const DIRECT_V2_NOTE_TREE_DEPTH = 32;
export const DIRECT_V2_NULLIFIER_TREE_DEPTH = 32;
export const DIRECT_V2_DENOMINATION_SATS = 10_000_000n;

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const ZERO_32 = '0'.repeat(64);
const MAX_NOTE_COUNT = 0xffff_ffffn;
const MAX_NULLIFIER_COUNT = 0xffff_fffen;
const MAX_ACTION_SEQUENCE_EXCLUSIVE = 1n << 33n;

export class DirectV2TransitionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2TransitionError';
  }
}

const fail = (message) => {
  throw new DirectV2TransitionError(message);
};

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function identifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function uint(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Buffer.from(value);
}

function stateContext(denominationSats) {
  return Object.freeze({ denominationSats: denominationSats.toString() });
}

function stateFromTrees({
  profileId,
  maximumLiveNotes,
  reserveSats,
  actionSequence,
  noteTree,
  nullifierTree,
}) {
  const note = auditNoteTree(noteTree);
  const nullifier = auditNullifierTree(nullifierTree);
  return Object.freeze({
    profileId,
    noteRoot: frToCanonicalHex(note.root),
    nullifierRoot: frToCanonicalHex(nullifier.root),
    noteCount: note.nextIndex.toString(),
    nullifierCount: nullifier.normalCount.toString(),
    maximumLiveNotes: maximumLiveNotes.toString(),
    reserveSats: reserveSats.toString(),
    actionSequence: actionSequence.toString(),
  });
}

function normalizePreState({
  preState,
  profileId,
  noteTree,
  nullifierTree,
  denominationSats,
}) {
  let normalized;
  try {
    normalized = validateStateNftCommitment(
      preState,
      stateContext(denominationSats),
    );
  } catch (error) {
    fail(`preState is invalid: ${error.message}`);
  }
  if (normalized.profileId !== profileId) fail('preState profileId mismatch');
  const note = auditNoteTree(noteTree);
  const nullifier = auditNullifierTree(nullifierTree);
  if (
    normalized.noteRoot !== frToCanonicalHex(note.root)
    || normalized.noteCount !== note.nextIndex.toString()
  ) {
    fail('preState does not match the note tree');
  }
  if (
    normalized.nullifierRoot !== frToCanonicalHex(nullifier.root)
    || normalized.nullifierCount !== nullifier.normalCount.toString()
  ) {
    fail('preState does not match the indexed nullifier tree');
  }
  return normalized;
}

function exactStateMatch(actual, expected, denominationSats) {
  if (expected === undefined) return;
  let actualBytes;
  let expectedBytes;
  try {
    actualBytes = encodeStateNftCommitment(actual, stateContext(denominationSats));
    expectedBytes = encodeStateNftCommitment(expected, stateContext(denominationSats));
  } catch (error) {
    fail(`expectedPostState is invalid: ${error.message}`);
  }
  if (!actualBytes.equals(expectedBytes)) fail('expectedPostState does not match the exact transition');
}

function outputFields(output) {
  exactKeys(output, 'output', ['encryptedRecord', 'outputNoteLeaf']);
  return Object.freeze({
    outputNoteLeaf: frToCanonicalHex(
      frFromCanonicalHex(output.outputNoteLeaf, 'output.outputNoteLeaf'),
    ),
    encryptedRecord: exactBytes(
      output.encryptedRecord,
      ENCRYPTED_RECORD_BYTES,
      'output.encryptedRecord',
    ),
  });
}

function spendFields(spend, noteTree) {
  exactKeys(spend, 'spend', ['inputNoteLeaf', 'noteIndex', 'publicNullifier']);
  const noteIndex = uint(spend.noteIndex, MAX_NOTE_COUNT, 'spend.noteIndex');
  if (noteIndex >= BigInt(noteTree.nextIndex)) fail('spend.noteIndex is not occupied');
  const inputNoteLeaf = frFromCanonicalHex(spend.inputNoteLeaf, 'spend.inputNoteLeaf');
  const publicNullifier = frToCanonicalHex(
    frFromCanonicalHex(spend.publicNullifier, 'spend.publicNullifier'),
  );
  const noteMembershipPath = membershipPath(noteTree, Number(noteIndex));
  verifyMembershipPath(
    noteTree,
    Number(noteIndex),
    inputNoteLeaf,
    noteMembershipPath,
  );
  return Object.freeze({
    inputNoteLeaf,
    noteIndex,
    noteMembershipPath,
    publicNullifier,
  });
}

export function createDirectV2PoolModel({
  profileId,
  maximumLiveNotes,
  denominationSats = DIRECT_V2_DENOMINATION_SATS.toString(),
}) {
  const profile = identifier(profileId, 'profileId');
  const denomination = uint(
    denominationSats,
    2_100_000_000_000_000n,
    'denominationSats',
  );
  if (denomination === 0n) fail('denominationSats must be nonzero');
  const maximum = uint(maximumLiveNotes, MAX_NOTE_COUNT, 'maximumLiveNotes');
  const noteTree = createNoteTree({
    depth: DIRECT_V2_NOTE_TREE_DEPTH,
    emptyLeafHash: hashEmptyNoteLeaf(),
    hashNode: hashNoteTreeNode,
  });
  const nullifierTree = createNullifierTree({
    depth: DIRECT_V2_NULLIFIER_TREE_DEPTH,
    hashLeaf: hashIndexedNullifierLeaf,
    hashNode: hashIndexedNullifierNode,
  });
  const state = stateFromTrees({
    profileId: profile,
    maximumLiveNotes: maximum,
    reserveSats: 0n,
    actionSequence: 0n,
    noteTree,
    nullifierTree,
  });
  try {
    validateStateNftCommitment(state, stateContext(denomination));
  } catch (error) {
    fail(`initial state is invalid: ${error.message}`);
  }
  return Object.freeze({
    denominationSats: denomination.toString(),
    noteTree,
    nullifierTree,
    state,
  });
}

export function applyDirectV2Transition(input) {
  const commonKeys = [
    'kind',
    'networkId',
    'profileId',
    'instanceId',
    'denominationSats',
    'preState',
    'noteTree',
    'nullifierTree',
    'transactionContextHash',
  ];
  const kindKeys = input?.kind === 'deposit'
    ? ['output']
    : input?.kind === 'transfer'
      ? ['output', 'spend']
      : input?.kind === 'withdrawal'
        ? ['spend', 'withdrawalLockingBytecodeHash']
        : [];
  const expectedKeys = [...commonKeys, ...kindKeys];
  if (input !== null && typeof input === 'object' && Object.hasOwn(input, 'expectedPostState')) {
    expectedKeys.push('expectedPostState');
  }
  exactKeys(input, 'transition', expectedKeys);
  if (!['deposit', 'transfer', 'withdrawal'].includes(input.kind)) {
    fail('transition kind is unsupported');
  }
  if (!isSupportedDirectV2NetworkId(input.networkId)) fail('transition network is unsupported');
  const profileId = identifier(input.profileId, 'profileId');
  const instanceId = identifier(input.instanceId, 'instanceId');
  const denominationSats = uint(
    input.denominationSats,
    2_100_000_000_000_000n,
    'denominationSats',
  );
  if (denominationSats === 0n) fail('denominationSats must be nonzero');
  const transactionContextHash = identifier(
    input.transactionContextHash,
    'transactionContextHash',
  );
  const pre = normalizePreState({
    preState: input.preState,
    profileId,
    noteTree: input.noteTree,
    nullifierTree: input.nullifierTree,
    denominationSats,
  });
  const preNoteCount = BigInt(pre.noteCount);
  const preNullifierCount = BigInt(pre.nullifierCount);
  const maximumLiveNotes = BigInt(pre.maximumLiveNotes);
  const preReserve = BigInt(pre.reserveSats);
  const preSequence = BigInt(pre.actionSequence);
  const preLive = preNoteCount - preNullifierCount;
  if (preSequence + 1n >= MAX_ACTION_SEQUENCE_EXCLUSIVE) {
    fail('actionSequence would overflow the V2 range');
  }

  let noteTree = input.noteTree;
  let nullifierTree = input.nullifierTree;
  let noteCount = preNoteCount;
  let nullifierCount = preNullifierCount;
  let reserveSats = preReserve;
  let publicNullifier = ZERO_32;
  let outputNoteLeaf = ZERO_32;
  let encryptedRecord = Buffer.alloc(ENCRYPTED_RECORD_BYTES);
  let withdrawalLockingBytecodeHash = ZERO_32;
  let noteWitness;
  let nullifierWitness;
  let spend;

  if (input.kind === 'deposit' || input.kind === 'transfer') {
    if (preNoteCount >= MAX_NOTE_COUNT) fail('noteCount cannot be incremented');
    if (input.kind === 'deposit' && preLive >= maximumLiveNotes) {
      fail('deposit exceeds maximumLiveNotes');
    }
    const output = outputFields(input.output);
    outputNoteLeaf = output.outputNoteLeaf;
    encryptedRecord = output.encryptedRecord;
    const appended = appendNote(
      noteTree,
      frFromCanonicalHex(outputNoteLeaf, 'outputNoteLeaf'),
    );
    noteTree = appended.tree;
    noteWitness = appended.witness;
    noteCount += 1n;
    if (input.kind === 'deposit') reserveSats += denominationSats;
  }

  if (input.kind === 'transfer' || input.kind === 'withdrawal') {
    if (preNullifierCount >= MAX_NULLIFIER_COUNT) {
      fail('nullifierCount cannot be incremented');
    }
    if (input.kind === 'withdrawal' && preLive < 1n) {
      fail('withdrawal underflows live notes');
    }
    spend = spendFields(input.spend, input.noteTree);
    publicNullifier = spend.publicNullifier;
    const inserted = insertNullifier(
      nullifierTree,
      Buffer.from(publicNullifier, 'hex'),
    );
    nullifierTree = inserted.tree;
    nullifierWitness = inserted.witness;
    nullifierCount += 1n;
    if (input.kind === 'withdrawal') {
      if (preReserve < denominationSats) fail('withdrawal underflows reserve');
      reserveSats -= denominationSats;
      withdrawalLockingBytecodeHash = identifier(
        input.withdrawalLockingBytecodeHash,
        'withdrawalLockingBytecodeHash',
      );
    }
  }

  const postState = stateFromTrees({
    profileId,
    maximumLiveNotes,
    reserveSats,
    actionSequence: preSequence + 1n,
    noteTree,
    nullifierTree,
  });
  exactStateMatch(postState, input.expectedPostState, denominationSats);
  const packet = encodeActionPacket({
    kind: input.kind,
    networkId: input.networkId,
    instanceId,
    preState: pre,
    postState,
    publicNullifier,
    outputNoteLeaf,
    encryptedRecord,
    withdrawalLockingBytecodeHash,
    transactionContextHash,
  }, stateContext(denominationSats));
  const digest = digestActionPacket(packet, stateContext(denominationSats));
  return Object.freeze({
    state: postState,
    noteTree,
    nullifierTree,
    packet,
    packetDigest: digest.toString('hex'),
    publicInputs: actionPacketPublicLimbs(packet, stateContext(denominationSats)),
    witness: Object.freeze({
      note: noteWitness,
      nullifier: nullifierWitness,
      spend,
    }),
  });
}
