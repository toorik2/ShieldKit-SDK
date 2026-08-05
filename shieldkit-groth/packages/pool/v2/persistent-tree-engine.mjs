/**
 * Normative persistent-tree primitives shared by the direct V2 store and
 * beta-only incremental consumers. This module owns only authenticated tree
 * derivation and packet assembly; it deliberately owns no wallet lifecycle,
 * chain-finality, or operation-state semantics.
 */
import {
  actionPacketPublicLimbs,
  digestActionPacket,
  encodeActionPacket,
} from "../../action/v2/packet.mjs";
import { encodeStateNftCommitment } from "../../action/v2/state.mjs";
import {
  hashEmptyNoteLeaf,
  hashNoteTreeNode,
} from "../../action/v2/poseidon.mjs";
import {
  derivePersistentIndexedNullifierInsertion,
  PersistentIndexedNullifierError,
} from "./persistent-indexed-nullifier.mjs";
import {
  createPersistentNullifierSqliteAccess,
  PERSISTENT_NULLIFIER_SQLITE_PROFILES,
} from "./persistent-indexed-nullifier-sqlite.mjs";

export const PERSISTENT_TREE_DEPTH = 32;
const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export class PersistentTreeEngineError extends Error {
  constructor(message) {
    super(message);
    this.name = "PersistentTreeEngineError";
  }
}

const fail = (message) => { throw new PersistentTreeEngineError(message); };
const same = (left, right) => Buffer.from(left).equals(Buffer.from(right));
const copy = (value) => Buffer.from(value);
function bytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must be exactly ${length} bytes`);
  }
  return Buffer.from(value);
}
function frBuffer(value, label) {
  const result = bytes(value, 32, label);
  if (BigInt(`0x${result.toString("hex")}`) >= BN254_FR_MODULUS) {
    fail(`${label} must be a canonical BN254 Fr`);
  }
  return result;
}
function frBigInt(value, label) {
  return BigInt(`0x${frBuffer(value, label).toString("hex")}`);
}
function encodedFr(value) {
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}
function hashTreePair(left, right, label) {
  try {
    return encodedFr(hashNoteTreeNode(
      frBigInt(left, `${label} left`),
      frBigInt(right, `${label} right`),
    ));
  } catch (error) {
    fail(`${label} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}
export function persistentTreeDefaults() {
  const values = [encodedFr(hashEmptyNoteLeaf())];
  for (let depth = 0; depth < PERSISTENT_TREE_DEPTH; depth += 1) {
    values.push(hashTreePair(values[depth], values[depth], "tree default"));
  }
  return Object.freeze(values);
}
export const PERSISTENT_NOTE_DEFAULTS = persistentTreeDefaults();

function storedNoteNode(db, depth, nodeIndex, defaults, overrides = null) {
  const key = `${depth}:${nodeIndex}`;
  const overridden = overrides?.get(key);
  if (overridden !== undefined) return overridden.nodeHash;
  const row = db.prepare(
    "SELECT node_hash FROM note_nodes WHERE depth=? AND node_index=?",
  ).get(depth, nodeIndex);
  return row ? frBuffer(row.node_hash, "note_nodes node") : defaults[depth];
}
function assertStoredNoteRoot(db, expected) {
  const row = db.prepare(
    "SELECT node_hash FROM note_nodes WHERE depth=32 AND node_index=0",
  ).get();
  if (!row || !same(row.node_hash, expected)) {
    fail("note tree stored root does not match the canonical pre-state");
  }
}

/** Derive the O(depth) mutation for a sequential note append. */
export function derivePersistentNoteAppendMutation(
  db,
  packet,
  { verifyPostRoot = true, defaults = PERSISTENT_NOTE_DEFAULTS } = {},
) {
  const index = Number(packet.preState.noteCount);
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 32) {
    fail("packet note count is outside the depth-32 tree");
  }
  if (db.prepare(
    "SELECT node_hash FROM note_nodes WHERE depth=0 AND node_index=?",
  ).get(index)) fail("note append position is already occupied");
  assertStoredNoteRoot(db, Buffer.from(packet.preState.noteRoot, "hex"));
  let cursor = index;
  let node = frBuffer(Buffer.from(packet.outputNoteLeaf, "hex"), "packet output note leaf");
  const noteNodes = [];
  const noteFrontier = [];
  const siblings = [];
  for (let depth = 0; depth < PERSISTENT_TREE_DEPTH; depth += 1) {
    noteNodes.push({ depth, nodeIndex: cursor, nodeHash: node });
    const bit = cursor & 1;
    const sibling = storedNoteNode(db, depth, cursor ^ 1, defaults);
    siblings.push(frBigInt(sibling, `note append sibling ${depth}`));
    if (bit === 0) {
      noteFrontier.push({ depth, nodeHash: node });
    } else {
      const frontier = db.prepare(
        "SELECT node_hash FROM note_frontier WHERE depth=?",
      ).get(depth);
      if (!frontier || !same(frontier.node_hash, sibling)) {
        fail("note frontier does not authenticate the sequential append path");
      }
    }
    node = bit === 0
      ? hashTreePair(node, sibling, "note tree")
      : hashTreePair(sibling, node, "note tree");
    cursor = Math.floor(cursor / 2);
  }
  noteNodes.push({ depth: PERSISTENT_TREE_DEPTH, nodeIndex: 0, nodeHash: node });
  if (verifyPostRoot && !same(node, Buffer.from(packet.postState.noteRoot, "hex"))) {
    fail("derived note append root does not match the packet post-state");
  }
  return Object.freeze({
    noteNodes: Object.freeze(noteNodes),
    noteFrontier: Object.freeze(noteFrontier),
    root: node,
    witness: Object.freeze({
      depth: PERSISTENT_TREE_DEPTH,
      index,
      outputNoteLeaf: frBigInt(Buffer.from(packet.outputNoteLeaf, "hex"), "packet output note leaf"),
      preRoot: frBigInt(Buffer.from(packet.preState.noteRoot, "hex"), "packet note pre-root"),
      postRoot: frBigInt(node, "derived note post-root"),
      emptyAppendPath: Object.freeze(siblings),
      membershipPath: Object.freeze([...siblings]),
    }),
  });
}

/** Derive an O(depth) membership path from persisted note nodes. */
export function derivePersistentNoteMembershipWitness(db, {
  noteIndex,
  inputNoteLeaf,
  expectedRoot,
}, { defaults = PERSISTENT_NOTE_DEFAULTS } = {}) {
  if (!Number.isSafeInteger(noteIndex) || noteIndex < 0 || noteIndex >= 2 ** 32) {
    fail("selected note index is outside the depth-32 tree");
  }
  const storedLeaf = db.prepare(
    "SELECT node_hash FROM note_nodes WHERE depth=0 AND node_index=?",
  ).get(noteIndex);
  const leaf = frBuffer(inputNoteLeaf, "selected note leaf");
  if (!storedLeaf || !same(storedLeaf.node_hash, leaf)) {
    fail("selected note leaf differs from the persistent note tree");
  }
  const siblings = [];
  let cursor = noteIndex;
  let node = leaf;
  for (let depth = 0; depth < PERSISTENT_TREE_DEPTH; depth += 1) {
    const sibling = storedNoteNode(db, depth, cursor ^ 1, defaults);
    siblings.push(frBigInt(sibling, `selected note membership path sibling ${depth}`));
    node = (cursor & 1) === 0
      ? hashTreePair(node, sibling, "selected note membership path")
      : hashTreePair(sibling, node, "selected note membership path");
    cursor = Math.floor(cursor / 2);
  }
  if (!same(node, expectedRoot)) {
    fail("selected note membership path does not prove the canonical note root");
  }
  return Object.freeze({ noteMembershipPath: Object.freeze(siblings), root: node });
}

/** Derive an indexed-nullifier insertion against the production table layout. */
export function derivePersistentNullifierInsertionMutation(
  db,
  packet,
  { verifyPostRoot = true } = {},
) {
  let mutation;
  try {
    mutation = derivePersistentIndexedNullifierInsertion({
      expectedPreRoot: Buffer.from(packet.preState.nullifierRoot, "hex"),
      key: Buffer.from(packet.publicNullifier, "hex"),
      normalCount: Number(packet.preState.nullifierCount),
      adapter: createPersistentNullifierSqliteAccess({
        db,
        profile: PERSISTENT_NULLIFIER_SQLITE_PROFILES.production,
        raise: fail,
      }).adapter,
    });
  } catch (error) {
    if (error instanceof PersistentIndexedNullifierError) fail(error.message);
    throw error;
  }
  if (verifyPostRoot && !same(mutation.root, Buffer.from(packet.postState.nullifierRoot, "hex"))) {
    fail("derived nullifier insertion root does not match the packet post-state");
  }
  return mutation;
}

/** Assemble the direct-V2 post-state from authenticated persistent trees. */
export function derivePersistentPacketPostState(db, {
  binding,
  preState,
  kind,
  publicNullifier,
  outputNoteLeaf,
}) {
  const packet = {
    kind,
    preState,
    publicNullifier: frBuffer(publicNullifier, "packet public nullifier").toString("hex"),
    outputNoteLeaf: frBuffer(outputNoteLeaf, "packet output note leaf").toString("hex"),
  };
  const note = kind === "withdrawal"
    ? { root: Buffer.from(preState.noteRoot, "hex"), witness: undefined }
    : derivePersistentNoteAppendMutation(db, packet, { verifyPostRoot: false });
  const nullifier = kind === "deposit"
    ? { root: Buffer.from(preState.nullifierRoot, "hex"), witness: undefined }
    : derivePersistentNullifierInsertionMutation(db, packet, { verifyPostRoot: false });
  const denomination = BigInt(binding.denominationSats);
  const reserve = BigInt(preState.reserveSats) + (kind === "deposit"
    ? denomination : kind === "withdrawal" ? -denomination : 0n);
  if (reserve < 0n) fail("withdrawal exceeds the canonical pool reserve");
  const postState = Object.freeze({
    ...preState,
    noteRoot: note.root.toString("hex"),
    nullifierRoot: nullifier.root.toString("hex"),
    noteCount: (BigInt(preState.noteCount) + (kind === "withdrawal" ? 0n : 1n)).toString(),
    nullifierCount: (BigInt(preState.nullifierCount) + (kind === "deposit" ? 0n : 1n)).toString(),
    reserveSats: reserve.toString(),
    actionSequence: (BigInt(preState.actionSequence) + 1n).toString(),
  });
  let stateBytes;
  try {
    stateBytes = encodeStateNftCommitment(postState, {
      denominationSats: binding.denominationSats,
    });
  } catch (error) {
    fail(`derived packet post-state is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  return Object.freeze({ preState, postState, stateBytes, note, nullifier });
}

/** Encode the exact proving packet/public inputs once callers authenticate inputs. */
export function assemblePersistentProvingTransition({
  binding,
  derived,
  kind,
  publicNullifier,
  outputNoteLeaf,
  encryptedRecord,
  withdrawalLockingBytecodeHash,
  transactionContextHash,
  spend,
  expectedTip,
}) {
  const zero = Buffer.alloc(32);
  let packet;
  try {
    packet = encodeActionPacket({
      kind,
      networkId: binding.networkId,
      instanceId: binding.instanceId.toString("hex"),
      preState: derived.preState,
      postState: derived.postState,
      publicNullifier: (publicNullifier ?? zero).toString("hex"),
      outputNoteLeaf: (outputNoteLeaf ?? zero).toString("hex"),
      encryptedRecord: encryptedRecord ?? Buffer.alloc(128),
      withdrawalLockingBytecodeHash,
      transactionContextHash: transactionContextHash.toString("hex"),
    }, { denominationSats: binding.denominationSats });
  } catch (error) {
    fail(`proving transition packet construction failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  const context = { denominationSats: binding.denominationSats };
  return Object.freeze({
    packet,
    packetDigest: digestActionPacket(packet, context).toString("hex"),
    publicInputs: actionPacketPublicLimbs(packet, context),
    witness: Object.freeze({ note: derived.note.witness, nullifier: derived.nullifier.witness, spend }),
    expectedTip,
  });
}
