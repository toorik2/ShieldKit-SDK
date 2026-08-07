/**
 * Indexed nullifier tree (depth 20, AMENDED 2026-08-06) — append/insert of real nullifier leaves.
 * Physical leaf model: sequential append of REAL leaves (MIN handled as empty domain leaf).
 */
import { digest4ToHex, h4, h4Concat4, digest4FromHex } from '../crypto/h4.mjs';

export const NULLIFIER_TREE_DEPTH = 20;  // AMENDED 2026-08-06 from 32 (plan AMENDMENT-20260806)

function buildEmpties(depth) {
  const e = new Array(depth + 1);
  e[0] = h4('NULLIFIER_LEAF', [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  for (let level = 0; level < depth; level += 1) {
    e[level + 1] = h4Concat4(`NF_MERKLE_L${level}`, e[level], e[level]);
  }
  return e;
}

export class NullifierTree {
  constructor(depth = NULLIFIER_TREE_DEPTH) {
    this.depth = depth;
    this.nfCount = 0;
    this.empties = buildEmpties(depth);
    this.frontier = new Array(depth).fill(null);
    this.root = digest4ToHex(this.empties[depth]);
  }

  rootFromFrontier() {
    const peaks = [];
    for (let L = 0; L < this.depth; L += 1) {
      if (this.frontier[L] != null) peaks.push([L, this.frontier[L]]);
    }
    if (peaks.length === 0) return digest4ToHex(this.empties[this.depth]);
    let curL = peaks[0][0];
    let curN = peaks[0][1];
    for (let p = 1; p < peaks.length; p += 1) {
      const [L, N] = peaks[p];
      while (curL < L) {
        curN = h4Concat4(`NF_MERKLE_L${curL}`, curN, this.empties[curL]);
        curL += 1;
      }
      curN = h4Concat4(`NF_MERKLE_L${curL}`, curN, N);
      curL += 1;
    }
    while (curL < this.depth) {
      curN = h4Concat4(`NF_MERKLE_L${curL}`, curN, this.empties[curL]);
      curL += 1;
    }
    return digest4ToHex(curN);
  }

  insert(keyHex) {
    if (this.nfCount >= 0xfffffffe) throw new Error('nullifier tree full');
    const key = digest4FromHex(keyHex);
    const idx = BigInt(this.nfCount + 1);
    const leaf = h4('NULLIFIER_LEAF', [2n, idx, key[0], key[1], key[2], key[3], 0n, 0n]);

    let node = leaf;
    let i = this.nfCount;
    for (let level = 0; level < this.depth; level += 1) {
      if ((i & 1) === 0) {
        this.frontier[level] = node;
        this.nfCount += 1;
        this.root = this.rootFromFrontier();
        return { root: this.root, index: this.nfCount, physicalIndex: this.nfCount };
      }
      const left = this.frontier[level];
      if (left == null) throw new Error(`nullifier frontier missing at ${level}`);
      node = h4Concat4(`NF_MERKLE_L${level}`, left, node);
      this.frontier[level] = null;
      i >>= 1;
    }
    this.frontier[this.depth - 1] = node;
    this.nfCount += 1;
    this.root = this.rootFromFrontier();
    return { root: this.root, index: this.nfCount, physicalIndex: this.nfCount };
  }
}
