/**
 * Build full Groth16 witness for PoolActionV2Direct (treeDepth=32).
 * Includes note Merkle, indexed-nullifier insert, record commitment, BabyJub encryption.
 */
import { DOMAIN, DENOMINATION_SATS, ZERO_32_HEX } from '../constants.mjs';
import { frFromHex, identifierLimbs, assertFr } from '../crypto/fr.mjs';
import { poseidon } from '../crypto/poseidon.mjs';
import { actionPacketPublicLimbsV2, decodeActionPacketV2 } from '../packet.mjs';
import {
  computeNoteCommitment,
  computeNullifier,
  recordCommitment,
  BABYJUB_BASE8,
  unpackBabyJubPoint,
} from '../crypto/note.mjs';

export const CIRCUIT_TREE_DEPTH = 32;

/** Base8 — valid on-curve dummy when encryption inactive. */
const BASE8_X = BABYJUB_BASE8[0];
const BASE8_Y = BABYJUB_BASE8[1];

function bitsLE(index, depth) {
  const idx = BigInt(index);
  const bits = [];
  for (let i = 0; i < depth; i += 1) {
    bits.push(String((idx >> BigInt(i)) & 1n));
  }
  return bits;
}

function zeroPath(depth) {
  return {
    elements: Array.from({ length: depth }, () => '0'),
    indices: Array.from({ length: depth }, () => '0'),
  };
}

function pathToSignals(path, depth, label) {
  if (!path || !path.siblings || path.siblings.length !== depth) {
    throw new Error(`${label}: path depth must be ${depth}`);
  }
  return {
    elements: path.siblings.map((s) => frFromHex(s, `${label}.sib`).toString()),
    indices: bitsLE(path.index, depth),
  };
}

function recordLimbsFromBytes(recordBytes) {
  const buf = Buffer.from(recordBytes);
  if (buf.length !== 128) throw new Error('encrypted record must be 128 bytes');
  const limbs = [];
  for (let i = 0; i < 8; i += 1) {
    limbs.push(BigInt(`0x${buf.subarray(i * 16, i * 16 + 16).toString('hex')}`).toString());
  }
  return limbs;
}

/**
 * @param {object} args
 * @param {Uint8Array} args.packetBytes
 * @param {object} args.note
 * @param {object} args.path — note tree path { index, siblings }
 * @param {object} [args.nullifierInsert] — from engine nullifierInsert on spend
 * @param {object} [args.encryption] — { esk, viewPoint:[x,y], encryptedRecord, encryptRho, encryptR }
 * @param {string} [args.recordCommitmentHex]
 * @param {string} [args.preNoteRoot]
 * @param {string} [args.postNoteRoot]
 * @param {string} [args.preNullifierRoot]
 * @param {string} [args.postNullifierRoot]
 */
export function buildExpandedCircuitInput({
  packetBytes,
  note,
  path,
  nullifierInsert,
  encryption,
  recordCommitmentHex,
  preNoteRoot,
  postNoteRoot,
  preNullifierRoot,
  postNullifierRoot,
}) {
  const decoded = decodeActionPacketV2(packetBytes);
  const limbs = actionPacketPublicLimbsV2(packetBytes);
  const kindCode = decoded.kind === 'deposit' ? 1 : decoded.kind === 'transfer' ? 2 : 3;
  const profileLimbs = identifierLimbs(decoded.preState.profileId, 'profileId');
  const instanceLimbs = identifierLimbs(decoded.instanceId, 'instanceId');

  const authority = frFromHex(note.authority, 'authority');
  const rho = frFromHex(note.rho, 'rho');
  const r = frFromHex(note.r, 'r');
  const sk = note.sk ? frFromHex(note.sk, 'sk') : 0n;
  const cm = note.cm
    ? frFromHex(note.cm, 'cm')
    : computeNoteCommitment({
      profileId: decoded.preState.profileId,
      instanceId: decoded.instanceId,
      authority,
      rho,
      r,
    });

  let createAuthority = 0n;
  let createRho = 0n;
  let createR = 0n;
  let createCm = 0n;
  if (kindCode === 1) {
    createCm = cm;
  } else if (kindCode === 2) {
    if (!note.create) throw new Error('transfer requires note.create { authority, rho, r, cm }');
    createAuthority = frFromHex(note.create.authority, 'create.authority');
    createRho = frFromHex(note.create.rho, 'create.rho');
    createR = frFromHex(note.create.r, 'create.r');
    createCm = note.create.cm
      ? frFromHex(note.create.cm, 'create.cm')
      : computeNoteCommitment({
        profileId: decoded.preState.profileId,
        instanceId: decoded.instanceId,
        authority: createAuthority,
        rho: createRho,
        r: createR,
      });
  }

  let nf = 0n;
  if (kindCode !== 1) {
    nf = computeNullifier({
      profileId: decoded.preState.profileId,
      instanceId: decoded.instanceId,
      sk,
      rho,
      cm,
    });
  }

  const rc = recordCommitmentHex
    ? frFromHex(recordCommitmentHex, 'recordCommitment')
    : (decoded.encryptedRecord && !decoded.encryptedRecord.equals(Buffer.alloc(128))
      ? recordCommitment(decoded.encryptedRecord)
      : 0n);

  let outputNoteLeaf = 0n;
  if (kindCode !== 3) {
    outputNoteLeaf = frFromHex(decoded.outputNoteLeaf, 'outputNoteLeaf');
  }

  const publicNullifier = kindCode === 1
    ? 0n
    : frFromHex(decoded.publicNullifier, 'publicNullifier');

  const spentOutputLeaf = note.spentOutputLeaf
    ? frFromHex(note.spentOutputLeaf, 'spentOutputLeaf')
    : 0n;

  const pathLeafFr = kindCode === 3
    ? poseidon(DOMAIN.NOTE_LEAF, assertFr(spentOutputLeaf))
    : poseidon(DOMAIN.NOTE_LEAF, assertFr(outputNoteLeaf));

  const notePath = pathToSignals(path, CIRCUIT_TREE_DEPTH, 'notePath');

  // --- nullifier insert signals ---
  const zPath = zeroPath(CIRCUIT_TREE_DEPTH);
  let nfPredType = 0n;
  let nfPredIndex = 0n;
  let nfPredKey = 0n;
  let nfPredSuccIndex = 0n;
  let nfPredSuccKey = 0n;
  let nfNewIndex = 0n;
  let nfNewSuccIndex = 0n;
  let nfNewSuccKey = 0n;
  let nfPredPath = zPath;
  let nfEmptyPath = zPath;

  if (kindCode !== 1) {
    if (!nullifierInsert) throw new Error('spend requires nullifierInsert proof material');
    const pred = nullifierInsert.predecessor.before;
    nfPredType = BigInt(pred.type);
    nfPredIndex = BigInt(pred.physicalIndex);
    nfPredKey = frFromHex(pred.key, 'pred.key');
    nfPredSuccIndex = BigInt(pred.successorIndex);
    nfPredSuccKey = frFromHex(pred.successorKey, 'pred.succKey');
    nfNewIndex = BigInt(nullifierInsert.insertedIndex);
    nfNewSuccIndex = BigInt(nullifierInsert.newLeaf.successorIndex);
    nfNewSuccKey = frFromHex(nullifierInsert.newLeaf.successorKey, 'new.succKey');
    nfPredPath = pathToSignals(nullifierInsert.predecessor.pathBefore, CIRCUIT_TREE_DEPTH, 'nfPred');
    const emptyPath = nullifierInsert.emptyPathAfterPred || nullifierInsert.emptyAppendPath;
    nfEmptyPath = pathToSignals(emptyPath, CIRCUIT_TREE_DEPTH, 'nfEmpty');
  }

  // --- encryption ---
  // Inactive: Base8 points + esk=1 so BabyCheck / BabyPbk stay well-formed.
  let esk = 1n;
  let Vx = BASE8_X;
  let Vy = BASE8_Y;
  let Ex = BASE8_X;
  let Ey = BASE8_Y;
  let encRho = 0n;
  let encR = 0n;
  let encTag = 0n;
  let encryptRho = 0n;
  let encryptR = 0n;
  let recordLimbs = Array.from({ length: 8 }, () => '0');

  if (kindCode !== 3) {
    if (!encryption) throw new Error('create requires encryption witness');
    esk = frFromHex(encryption.esk, 'esk');
    const V = encryption.viewPoint;
    Vx = typeof V[0] === 'bigint' ? V[0] : frFromHex(V[0], 'Vx');
    Vy = typeof V[1] === 'bigint' ? V[1] : frFromHex(V[1], 'Vy');
    const rec = Buffer.from(encryption.encryptedRecord);
    recordLimbs = recordLimbsFromBytes(rec);
    const E = unpackBabyJubPoint(rec.subarray(0, 32));
    Ex = E[0];
    Ey = E[1];
    encRho = BigInt(`0x${rec.subarray(32, 64).toString('hex')}`);
    encR = BigInt(`0x${rec.subarray(64, 96).toString('hex')}`);
    encTag = BigInt(`0x${rec.subarray(96, 128).toString('hex')}`);
    encryptRho = kindCode === 1 ? rho : createRho;
    encryptR = kindCode === 1 ? r : createR;
    if (encryption.encryptRho) encryptRho = frFromHex(encryption.encryptRho, 'encryptRho');
    if (encryption.encryptR) encryptR = frFromHex(encryption.encryptR, 'encryptR');
  }

  return {
    publicInput0: limbs[0],
    publicInput1: limbs[1],
    limb0: limbs[0],
    limb1: limbs[1],
    kind: String(kindCode),
    preNoteCount: decoded.preState.noteCount,
    preNullifierCount: decoded.preState.nullifierCount,
    preReserve: decoded.preState.reserveSats,
    preActionSequence: decoded.preState.actionSequence,
    preMaximumLiveNotes: decoded.preState.maximumLiveNotes,
    postNoteCount: decoded.postState.noteCount,
    postNullifierCount: decoded.postState.nullifierCount,
    postReserve: decoded.postState.reserveSats,
    postActionSequence: decoded.postState.actionSequence,
    profileIdLo: profileLimbs[0].toString(),
    profileIdHi: profileLimbs[1].toString(),
    instanceIdLo: instanceLimbs[0].toString(),
    instanceIdHi: instanceLimbs[1].toString(),
    denomination: DENOMINATION_SATS.toString(),
    authority: authority.toString(),
    rho: rho.toString(),
    r: r.toString(),
    sk: sk.toString(),
    cm: (typeof cm === 'bigint' ? cm : frFromHex(cm)).toString(),
    nf: nf.toString(),
    recordCommitment: rc.toString(),
    outputNoteLeaf: outputNoteLeaf.toString(),
    publicNullifier: publicNullifier.toString(),
    createAuthority: createAuthority.toString(),
    createRho: createRho.toString(),
    createR: createR.toString(),
    createCm: createCm.toString(),
    preNoteRoot: frFromHex(preNoteRoot || decoded.preState.noteRoot).toString(),
    postNoteRoot: frFromHex(postNoteRoot || decoded.postState.noteRoot).toString(),
    notePathElements: notePath.elements,
    notePathIndices: notePath.indices,
    noteLeafHash: pathLeafFr.toString(),
    spentOutputLeaf: spentOutputLeaf.toString(),
    preNullifierRoot: frFromHex(preNullifierRoot || decoded.preState.nullifierRoot).toString(),
    postNullifierRoot: frFromHex(postNullifierRoot || decoded.postState.nullifierRoot).toString(),
    nfPredType: nfPredType.toString(),
    nfPredIndex: nfPredIndex.toString(),
    nfPredKey: nfPredKey.toString(),
    nfPredSuccIndex: nfPredSuccIndex.toString(),
    nfPredSuccKey: nfPredSuccKey.toString(),
    nfPredPathElements: nfPredPath.elements,
    nfPredPathIndices: nfPredPath.indices,
    nfNewIndex: nfNewIndex.toString(),
    nfNewSuccIndex: nfNewSuccIndex.toString(),
    nfNewSuccKey: nfNewSuccKey.toString(),
    nfEmptyPathElements: nfEmptyPath.elements,
    nfEmptyPathIndices: nfEmptyPath.indices,
    recordLimbs,
    esk: esk.toString(),
    Vx: Vx.toString(),
    Vy: Vy.toString(),
    Ex: Ex.toString(),
    Ey: Ey.toString(),
    encRho: encRho.toString(),
    encR: encR.toString(),
    encTag: encTag.toString(),
    encryptRho: encryptRho.toString(),
    encryptR: encryptR.toString(),
  };
}
