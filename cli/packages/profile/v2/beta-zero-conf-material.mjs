/**
 * Authenticated in-memory tree material for the explicitly unqualified V2 beta.
 *
 * This restores by replaying every note leaf and every historical nullifier
 * insertion. That is acceptable for the bounded 5-deposit/5-withdrawal beta
 * story, but is intentionally not scalable persistence or a production V2
 * design. Production requires persistent authenticated nodes/frontier or a
 * checkpointed incremental store.
 */
import {
  decodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  DIRECT_V2_NOTE_TREE_DEPTH,
  DIRECT_V2_NULLIFIER_TREE_DEPTH,
  createDirectV2PoolModel,
} from '../../action/v2/transition.mjs';
import {
  hashEmptyNoteLeaf,
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
  hashNoteTreeNode,
} from '../../action/v2/poseidon.mjs';
import {
  restore as restoreNoteTree,
  snapshot as snapshotNoteTree,
} from '../../action/v2/note-tree.mjs';
import {
  audit as auditNullifierTree,
  create as createNullifierTree,
  insert as insertNullifier,
} from '../../action/v2/indexed-nullifier-tree.mjs';

export const V2_BETA_ZERO_CONF_TREE_MATERIAL_SCHEMA =
  'shieldkit-v2-beta-zero-conf-tree-material-v1';

export class V2BetaZeroConfMaterialError extends Error {
  constructor(message, options = undefined) { super(message, options); this.name = 'V2BetaZeroConfMaterialError'; }
}
const fail = (message) => { throw new V2BetaZeroConfMaterialError(message); };
const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
  return value;
}
function hash(value, label) { if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be lowercase 32-byte hex`); return value; }
function capacity(value, label) { if (typeof value !== 'string' || !DECIMAL.test(value) || BigInt(value) < 1n || BigInt(value) > 0xffff_ffffn) fail(`${label} must be a nonzero u32 decimal`); return value; }

function nullifierTree(keys) {
  let tree = createNullifierTree({ depth: DIRECT_V2_NULLIFIER_TREE_DEPTH, hashLeaf: hashIndexedNullifierLeaf, hashNode: hashIndexedNullifierNode });
  for (const key of keys) tree = insertNullifier(tree, Buffer.from(key, 'hex')).tree;
  auditNullifierTree(tree);
  return tree;
}

/** Create authenticated empty trees for a just-accepted V2 beta genesis. */
export function createV2BetaZeroConfGenesisTreeMaterial({ profileId, maximumLiveNotes } = {}) {
  hash(profileId, 'profileId'); capacity(maximumLiveNotes, 'maximumLiveNotes');
  const model = createDirectV2PoolModel({ profileId, maximumLiveNotes });
  return Object.freeze({
    schema: V2_BETA_ZERO_CONF_TREE_MATERIAL_SCHEMA,
    maximumLiveNotes,
    noteTreeSnapshot: snapshotNoteTree(model.noteTree),
    nullifierInsertionKeys: Object.freeze([]),
  });
}

/** Restore snapshots and authenticate both roots/counts against an exact state NFT commitment. */
export function restoreV2BetaZeroConfTreeMaterial({ material, profileId, state } = {}) {
  const input = exact(material, ['maximumLiveNotes', 'noteTreeSnapshot', 'nullifierInsertionKeys', 'schema'], 'beta tree material');
  if (input.schema !== V2_BETA_ZERO_CONF_TREE_MATERIAL_SCHEMA) fail('beta tree material schema is unsupported');
  hash(profileId, 'profileId'); capacity(input.maximumLiveNotes, 'beta tree material.maximumLiveNotes');
  if (!Array.isArray(input.nullifierInsertionKeys)) fail('beta tree material.nullifierInsertionKeys must be an array');
  const keys = input.nullifierInsertionKeys.map((key, index) => hash(key, `beta tree material.nullifierInsertionKeys[${index}]`));
  if (new Set(keys).size !== keys.length) fail('beta tree material nullifier insertion keys must be unique');
  let decoded;
  try { decoded = decodeStateNftCommitment(state, { denominationSats: '10000000' }); }
  catch (error) { fail(`beta tree material state is invalid: ${error instanceof Error ? error.message : String(error)}`); }
  if (decoded.profileId !== profileId || decoded.maximumLiveNotes !== input.maximumLiveNotes) fail('beta tree material profile or capacity differs from state');
  let noteTree;
  try { noteTree = restoreNoteTree(input.noteTreeSnapshot, { emptyLeafHash: hashEmptyNoteLeaf(), hashNode: hashNoteTreeNode }); }
  catch (error) { fail(`beta note tree snapshot is not authenticated: ${error instanceof Error ? error.message : String(error)}`); }
  const nullifierTreeValue = nullifierTree(keys);
  const noteRoot = noteTree.root.toString(16).padStart(64, '0');
  const nullifierRoot = nullifierTreeValue.root.toString(16).padStart(64, '0');
  if (decoded.noteRoot !== noteRoot || decoded.nullifierRoot !== nullifierRoot
    || decoded.noteCount !== String(noteTree.nextIndex)
    || decoded.nullifierCount !== String(keys.length)) {
    fail('beta tree material does not authenticate the supplied state commitment');
  }
  return Object.freeze({ noteTree, nullifierTree: nullifierTreeValue, state: decoded });
}

/** Serialize exactly the two authenticated trees after a local transition. */
export function materializeV2BetaZeroConfTreeMaterial({ maximumLiveNotes, noteTree, nullifierTree: tree } = {}) {
  capacity(maximumLiveNotes, 'maximumLiveNotes');
  auditNullifierTree(tree);
  const keys = tree.leaves.filter((leaf) => leaf.type === 'normal').sort((left, right) => left.index - right.index).map((leaf) => leaf.key);
  return Object.freeze({
    schema: V2_BETA_ZERO_CONF_TREE_MATERIAL_SCHEMA,
    maximumLiveNotes,
    noteTreeSnapshot: snapshotNoteTree(noteTree),
    nullifierInsertionKeys: Object.freeze(keys),
  });
}
