/**
 * Wallet-driven note secrets + Rust-compatible field hashing (production-randomness item 2).
 *
 * Note secrets (sk, rho, blind) are derived ONLY from wallet key material
 * (HMAC-SHA256 over the note master key + instance + index) — NEVER from a proof seed.
 * The field hash mirrors crates/fri-prover/src/poseidon2.rs hash_to_1 so statements
 * produced from wallet witnesses match the on-chain verifier exactly.
 */
import { createHash } from 'node:crypto';
import { GOLDILOCKS_P, fe } from '../core/crypto/field.mjs';
import { vendorHashTo1 } from './vendor-poseidon.mjs';

const P = GOLDILOCKS_P;
export const DOM_NF = 0x636173685f6e66n; // "cash_nf" (matches Rust DOM_NF)
export const POOL_NOTE_VALUE = 10_000_000n;

/** Vendor (Rust) compatible hash_to_1 — matches crates/fri-prover/src/poseidon2.rs. */
export function hashTo1(inputs) {
  return fe(vendorHashTo1(inputs));
}

function hmacSha256(keyBytes, ...parts) {
  const k = Buffer.isBuffer(keyBytes) ? keyBytes : Buffer.from(keyBytes, 'hex');
  const h = createHash('sha256');
  h.update(k);
  for (const part of parts) h.update(part);
  return h.digest();
}

function le64(v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v));
  return b;
}

function le32(v) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(Number(v) & 0xffffffff);
  return b;
}

/** Field element from the first 8 bytes (LE) of a 32-byte digest, mod P. */
function feFromDigest(digest) {
  return fe(BigInt('0x' + digest.subarray(0, 8).toString('hex')) % P);
}

/**
 * Derive a note's secrets from the wallet note-master key.
 * sk, rho, blind are independent HMAC-SHA256 derivations — unique per (instance, index).
 */
export function deriveNoteSecrets(masterKeyHex, instanceId32, index) {
  const inst = Buffer.from(instanceId32, 'hex');
  const idx = le32(index);
  const sk = feFromDigest(hmacSha256(masterKeyHex, Buffer.from('note-sk/v1'), inst, idx));
  const rho = feFromDigest(hmacSha256(masterKeyHex, Buffer.from('note-rho/v1'), inst, idx));
  const blind = feFromDigest(hmacSha256(masterKeyHex, Buffer.from('note-blind/v1'), inst, idx));
  return { sk, rho, blind };
}

export function ownerPubkey(sk) {
  return hashTo1([sk]);
}

export function noteCommitment(value, ownerPk, rho, blind) {
  return hashTo1([value, ownerPk, rho, blind]);
}

export function noteNullifier(sk, rho) {
  return hashTo1([sk, rho, DOM_NF]);
}

/** Canonical empty leaf for the client-side note tree (self-consistent; matches hashTo1). */
export const EMPTY_LEAF = hashTo1([0n, 0n]);
export const DOM_POOL = 0x534b4631n; // "SKF1" (matches Rust DOM_POOL)
export const KIND_ID = { deposit: 1, transfer: 2, withdrawal: 3 };

/**
 * Level-0 empty for a kind's tree: the AIR requires siblings[0] to carry the
 * DOM_POOL/kind domain tag (pool_prove: siblings[0] = hash_to_1([DOM_POOL, kind_id, sib0])).
 */
export function kindEmpty0(kindId) {
  return hashTo1([DOM_POOL, BigInt(kindId), EMPTY_LEAF]);
}

export function emptyTreeRoot(depth, kindId = 0) {
  let e = kindId ? kindEmpty0(kindId) : EMPTY_LEAF;
  for (let l = 0; l < depth; l += 1) e = hashTo1([e, e]);
  return e;
}

/**
 * Append-only client-side note tree (mirrors the pool's virtual note accounting).
 * Leaves are note commitments; compression = Rust merkle_compress (hashTo1([a,b]));
 * level-0 empties carry the DOM_POOL/kind domain tag when a kindId is given.
 */
export class ClientNoteTree {
  constructor(depth = 20, kindId = 0) {
    this.depth = depth;
    this.kindId = kindId;
    this.leaves = [];
    this.empties = [kindId ? kindEmpty0(kindId) : EMPTY_LEAF];
    for (let l = 0; l < depth; l += 1) this.empties.push(hashTo1([this.empties[l], this.empties[l]]));
    this.root = this.empties[depth];
  }
  append(leaf) {
    const i = this.leaves.length;
    this.leaves.push(fe(leaf));
    let node = this.leaves[i];
    const path = [];
    let idx = i;
    for (let l = 0; l < this.depth; l += 1) {
      const sibling = (idx ^ 1) < this.leaves.length ? this.leaves[idx ^ 1] : this.empties[l];
      path.push(sibling);
      node = hashTo1([idx % 2 === 0 ? node : sibling, idx % 2 === 0 ? sibling : node]);
      idx >>= 1;
    }
    this.root = node;
    return { root: this.root, path };
  }
  pathOf(index) {
    const idx0 = index;
    const path = [];
    let idx = idx0;
    for (let l = 0; l < this.depth; l += 1) {
      path.push((idx ^ 1) < this.leaves.length ? this.leaves[idx ^ 1] : this.empties[l]);
      idx >>= 1;
    }
    return path;
  }
}
