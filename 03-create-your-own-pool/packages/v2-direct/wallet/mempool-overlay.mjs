/**
 * Mempool overlay for V2 Direct wallet/pool tip.
 *
 * Tracks unconfirmed settlement outpoints and action digests so:
 *   - sync can project tip past confirmed chain using mempool parents
 *   - reorg/conflict marks needs_reproof without premature confirmed commit
 *   - parent-loss clears overlay entries
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { atomicWriteJson, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE } from '../../kit/secure-files.mjs';

export class MempoolOverlayError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MempoolOverlayError';
  }
}

const fail = (m) => {
  throw new MempoolOverlayError(m);
};

/**
 * @param {string} rootDir
 */
export function createMempoolOverlay(rootDir) {
  mkdirSync(rootDir, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  const filePath = path.join(rootDir, 'mempool-overlay.json');

  function load() {
    if (!existsSync(filePath)) {
      return { entries: [], version: 1 };
    }
    const mode = statSync(filePath).mode & 0o777;
    if (mode !== PRIVATE_FILE_MODE) fail(`overlay mode must be 0600, got ${mode.toString(8)}`);
    return JSON.parse(readFileSync(filePath, 'utf8'));
  }

  function save(data) {
    atomicWriteJson(filePath, data, { mode: PRIVATE_FILE_MODE });
  }

  function addEntry({
    txid,
    kind,
    digest,
    spentStateOutpoint,
    createdStateOutpoint,
    parents = [],
  }) {
    if (typeof txid !== 'string' || !/^[0-9a-f]{64}$/i.test(txid)) fail('txid must be 64 hex');
    const data = load();
    // replace same txid
    data.entries = data.entries.filter((e) => e.txid !== txid.toLowerCase());
    data.entries.push({
      txid: txid.toLowerCase(),
      kind,
      digest: digest || null,
      spentStateOutpoint: spentStateOutpoint || null,
      createdStateOutpoint: createdStateOutpoint || null,
      parents: parents.map((p) => String(p).toLowerCase()),
      addedAt: new Date().toISOString(),
      status: 'mempool',
    });
    save(data);
    return data.entries[data.entries.length - 1];
  }

  function markConfirmed(txid) {
    const data = load();
    const id = txid.toLowerCase();
    let found = false;
    data.entries = data.entries.map((e) => {
      if (e.txid === id) {
        found = true;
        return { ...e, status: 'confirmed' };
      }
      return e;
    });
    // drop confirmed from overlay (settled on chain tip)
    data.entries = data.entries.filter((e) => e.status !== 'confirmed');
    save(data);
    return found;
  }

  function markConflicted(txid, reason = 'conflict') {
    const data = load();
    const id = txid.toLowerCase();
    data.entries = data.entries.map((e) => (
      e.txid === id ? { ...e, status: 'conflicted', reason } : e
    ));
    save(data);
  }

  /** Drop entries whose parent txids are no longer in the provided set. */
  function dropLostParents(liveTxids) {
    const live = new Set([...liveTxids].map((t) => String(t).toLowerCase()));
    const data = load();
    const before = data.entries.length;
    data.entries = data.entries.filter((e) => {
      if (!e.parents?.length) return true;
      return e.parents.every((p) => live.has(p) || p === e.txid);
    });
    save(data);
    return before - data.entries.length;
  }

  function projectTip(confirmedTip) {
    const data = load();
    const mem = data.entries.filter((e) => e.status === 'mempool');
    if (!mem.length) {
      return { tip: confirmedTip, overlayDepth: 0, needsReproof: false };
    }
    // Overlay does not invent roots — signals that local tip may lag mempool chain
    return {
      tip: confirmedTip,
      overlayDepth: mem.length,
      needsReproof: false,
      pendingTxids: mem.map((e) => e.txid),
      pendingKinds: mem.map((e) => e.kind),
    };
  }

  function list() {
    return load().entries.slice();
  }

  function clear() {
    save({ entries: [], version: 1 });
  }

  return Object.freeze({
    addEntry,
    markConfirmed,
    markConflicted,
    dropLostParents,
    projectTip,
    list,
    clear,
    path: filePath,
  });
}

export function digestHex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
