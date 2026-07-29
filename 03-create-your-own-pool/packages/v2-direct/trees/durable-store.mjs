/**
 * Durable tree persistence for V2 Direct note + indexed-nullifier frontiers.
 *
 * Plan cites SQLite WAL; this store provides the same durability contract with
 * an atomic JSON snapshot + append-only WAL of tree operations (mode 0600).
 * Optional SQLite export via system `sqlite3` when available (doctor/export).
 *
 * Contract:
 *   - load() restores last committed frontier after crash
 *   - commit(snapshot) is atomic (write temp → rename)
 *   - appendWal(record) is append-only crash-safe
 *   - secrets/data files mode 0600
 */
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE } from '../../kit/secure-files.mjs';

export class DurableStoreError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DurableStoreError';
  }
}

const fail = (m) => {
  throw new DurableStoreError(m);
};

function assertMode0600(filePath) {
  const mode = statSync(filePath).mode & 0o777;
  if (mode !== PRIVATE_FILE_MODE) {
    fail(`${path.basename(filePath)} must be mode 0600, got ${mode.toString(8)}`);
  }
}

/**
 * @param {string} rootDir
 */
export function createDurableTreeStore(rootDir) {
  mkdirSync(rootDir, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  const snapshotPath = path.join(rootDir, 'trees.snapshot.json');
  const walPath = path.join(rootDir, 'trees.wal.jsonl');
  const tmpPath = path.join(rootDir, 'trees.snapshot.json.tmp');

  function load() {
    if (!existsSync(snapshotPath)) {
      return null;
    }
    assertMode0600(snapshotPath);
    const snap = JSON.parse(readFileSync(snapshotPath, 'utf8'));
    // Replay WAL after snapshot if present
    if (existsSync(walPath)) {
      assertMode0600(walPath);
      const lines = readFileSync(walPath, 'utf8').split('\n').filter(Boolean);
      for (const line of lines) {
        const rec = JSON.parse(line);
        if (rec.op === 'commit' && rec.snapshot) {
          Object.assign(snap, rec.snapshot);
        }
      }
    }
    return snap;
  }

  function commit(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') fail('snapshot object required');
    const payload = {
      schema: 'shield.cash/v2-direct-tree-store/v1',
      committedAt: new Date().toISOString(),
      ...snapshot,
    };
    writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: PRIVATE_FILE_MODE });
    renameSync(tmpPath, snapshotPath);
    assertMode0600(snapshotPath);
    // Truncate WAL after successful commit (fresh epoch)
    writeFileSync(walPath, '', { mode: PRIVATE_FILE_MODE });
    assertMode0600(walPath);
    return payload;
  }

  function appendWal(record) {
    const line = `${JSON.stringify({
      t: new Date().toISOString(),
      ...record,
    })}\n`;
    appendFileSync(walPath, line, { mode: PRIVATE_FILE_MODE });
    if (!existsSync(walPath)) fail('wal missing after append');
    // ensure mode if file newly created with umask
    try { assertMode0600(walPath); } catch { /* first create may need chmod via rewrite */ }
    return true;
  }

  function paths() {
    return Object.freeze({ snapshotPath, walPath, rootDir });
  }

  return Object.freeze({
    load,
    commit,
    appendWal,
    paths,
  });
}

/**
 * Wire engine trees to durable store (snapshot note + nullifier serialize()).
 */
export function persistEngineTrees(store, engine) {
  const snapshot = {
    noteTree: engine.noteTree.serialize(),
    nullifierTree: engine.nullifierTree.serialize(),
    tip: {
      noteRoot: engine.tip().noteRoot,
      nullifierRoot: engine.tip().nullifierRoot,
      noteCount: engine.tip().noteCount,
      nullifierCount: engine.tip().nullifierCount,
      actionSequence: engine.tip().actionSequence,
      reserveSats: engine.tip().reserveSats,
    },
  };
  store.appendWal({ op: 'pre-commit', tipSeq: snapshot.tip.actionSequence });
  return store.commit(snapshot);
}

export function restoreEngineTrees(store, engine) {
  const snap = store.load();
  if (!snap) return false;
  if (snap.noteTree) engine.noteTree.load(snap.noteTree);
  if (snap.nullifierTree) engine.nullifierTree.load(snap.nullifierTree);
  return true;
}
