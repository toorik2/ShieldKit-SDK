import {
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
} from 'poseidon-lite';

import {
  BN254_SCALAR_FIELD_MODULUS,
  V2_DOMAIN_SEPARATORS,
} from './domains.mjs';

const IMPLEMENTATIONS = Object.freeze([
  undefined,
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
]);

const HEX_32 = /^[0-9a-f]{64}$/;
const EMPTY_LEAF_TYPE = 0n;

export class V2PoseidonError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2PoseidonError';
  }
}

const fail = (message) => {
  throw new V2PoseidonError(message);
};

export function assertCanonicalFr(value, label = 'field element') {
  if (
    typeof value !== 'bigint'
    || value < 0n
    || value >= BN254_SCALAR_FIELD_MODULUS
  ) {
    fail(`${label} must be a canonical BN254 Fr bigint`);
  }
  return value;
}

export function frToCanonicalHex(value) {
  return assertCanonicalFr(value).toString(16).padStart(64, '0');
}

export function frFromCanonicalHex(value, label = 'field element') {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return assertCanonicalFr(BigInt(`0x${value}`), label);
}

export function identifierToU128Limbs(value, label = 'identifier') {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return Object.freeze([
    BigInt(`0x${value.slice(0, 32)}`),
    BigInt(`0x${value.slice(32)}`),
  ]);
}

export function poseidonHash(...inputs) {
  if (inputs.length < 1 || inputs.length > 16) {
    fail('Poseidon input arity must be between 1 and 16');
  }
  inputs.forEach((value, index) => assertCanonicalFr(value, `Poseidon input ${index}`));
  return assertCanonicalFr(IMPLEMENTATIONS[inputs.length](inputs), 'Poseidon output');
}

export function hashIndexedNullifierLeaf(inputs) {
  if (!Array.isArray(inputs) || inputs.length !== 5) {
    fail('indexed-nullifier leaf inputs must contain exactly five fields');
  }
  inputs.forEach((value, index) => assertCanonicalFr(value, `indexed-nullifier leaf input ${index}`));
  if (inputs[0] === EMPTY_LEAF_TYPE) {
    if (inputs.some((value) => value !== 0n)) {
      fail('empty indexed-nullifier leaf inputs must all be zero');
    }
    return poseidonHash(V2_DOMAIN_SEPARATORS.NULLIFIER_TREE_EMPTY.value, 0n);
  }
  return poseidonHash(V2_DOMAIN_SEPARATORS.NULLIFIER_TREE_LEAF.value, ...inputs);
}

export function hashIndexedNullifierNode(left, right) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.NULLIFIER_TREE_NODE.value,
    assertCanonicalFr(left, 'left nullifier-tree node'),
    assertCanonicalFr(right, 'right nullifier-tree node'),
  );
}

export function hashEmptyNoteLeaf() {
  return poseidonHash(V2_DOMAIN_SEPARATORS.NOTE_TREE_EMPTY.value, 0n);
}

export function hashNoteTreeNode(left, right) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.NOTE_TREE_NODE.value,
    assertCanonicalFr(left, 'left note-tree node'),
    assertCanonicalFr(right, 'right note-tree node'),
  );
}

export function hashOutputNoteLeaf(noteCommitment, recordTag) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.NOTE_LEAF.value,
    assertCanonicalFr(noteCommitment, 'note commitment'),
    assertCanonicalFr(recordTag, 'record tag'),
  );
}
