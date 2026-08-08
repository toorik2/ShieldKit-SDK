import { digest4ToHex, h4, h4Concat4, digest4FromHex } from '../crypto/h4.mjs';

export const NOTE_TREE_DEPTH = 20;  // AMENDED 2026-08-06 from 32 (plan AMENDMENT-20260806; 2^20 notes)

function buildEmpties(depth) {
  const e = new Array(depth + 1);
  e[0] = h4('EMPTY_NOTE_LEAF', [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  for (let level = 0; level < depth; level += 1) {
    e[level + 1] = h4Concat4(`NOTE_MERKLE_L${level}`, e[level], e[level]);
  }
  return e;
}

/**
 * Append-only depth-d Merkle tree.
 * frontier[level] = completed left-child subtree awaiting a right sibling.
 */
export class NoteTree {
  constructor(depth = NOTE_TREE_DEPTH) {
    this.depth = depth;
    this.count = 0;
    this.empties = buildEmpties(depth);
    /** @type {(bigint[]|null)[]} */
    this.frontier = new Array(depth).fill(null);
    this.root = digest4ToHex(this.empties[depth]);
  }

  rootFromFrontier() {
    // Peaks at levels where frontier[level] is set; combine with empties to full depth.
    // Represent count's binary decomposition: frontier[k] is the root of a 2^k-sized filled subtree.
    let node = null;
    let level = 0;
    // Find lowest peak
    const peaks = [];
    for (let L = 0; L < this.depth; L += 1) {
      if (this.frontier[L] != null) peaks.push([L, this.frontier[L]]);
    }
    if (peaks.length === 0) return digest4ToHex(this.empties[this.depth]);

    // Raise each peak to the next and merge when levels match (left-to-right).
    let curL = peaks[0][0];
    let curN = peaks[0][1];
    for (let p = 1; p < peaks.length; p += 1) {
      const [L, N] = peaks[p];
      while (curL < L) {
        curN = h4Concat4(`NOTE_MERKLE_L${curL}`, curN, this.empties[curL]);
        curL += 1;
      }
      // peaks are left-to-right: lower index is left
      // Actually binary frontier: higher level peaks are more significant left subtrees
      // Standard: process from low to high; when merging equal levels, left is previous.
      curN = h4Concat4(`NOTE_MERKLE_L${curL}`, curN, N);
      curL += 1;
    }
    while (curL < this.depth) {
      curN = h4Concat4(`NOTE_MERKLE_L${curL}`, curN, this.empties[curL]);
      curL += 1;
    }
    return digest4ToHex(curN);
  }

  /**
   * @param {string} leafHex Digest4 hex
   * @returns {{ root: string, index: number, path: string[] }}
   */
  append(leafHex) {
    if (this.count >= 2 ** this.depth) throw new Error('note tree full');
    let node = digest4FromHex(leafHex);
    let idx = this.count;
    const path = [];

    for (let level = 0; level < this.depth; level += 1) {
      if ((idx & 1) === 0) {
        // Insert as left child: record and stop.
        path.push(digest4ToHex(this.empties[level]));
        this.frontier[level] = node;
        this.count += 1;
        this.root = this.rootFromFrontier();
        while (path.length < this.depth) {
          path.push(digest4ToHex(this.empties[path.length]));
        }
        return { root: this.root, index: this.count - 1, path };
      }
      // Right child: combine with left sibling in frontier.
      const left = this.frontier[level];
      if (left == null) throw new Error(`invariant: missing frontier at ${level}`);
      path.push(digest4ToHex(left));
      node = h4Concat4(`NOTE_MERKLE_L${level}`, left, node);
      this.frontier[level] = null;
      idx >>= 1;
    }

    // Power-of-two fill: entire tree one peak at top (should not happen mid-depth-20 often)
    this.frontier[this.depth - 1] = node;
    this.count += 1;
    this.root = this.rootFromFrontier();
    while (path.length < this.depth) path.push(digest4ToHex(this.empties[path.length]));
    return { root: this.root, index: this.count - 1, path };
  }
}
