/**
 * Crash-safe operation journal for V2 Direct.
 * States: draft → funding_selected → tip_synced → proving → proved →
 * needs_reproof | signed → broadcast → mempool → confirmed → settled
 * | conflicted | reorged | abandoned
 */
import {
  existsSync, mkdirSync, readFileSync, statSync,
} from 'node:fs';
import path from 'node:path';
import { atomicWriteJson, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE } from '../../kit/secure-files.mjs';

export const JOURNAL_STATES = Object.freeze([
  'draft',
  'funding_selected',
  'tip_synced',
  'proving',
  'proved',
  'needs_reproof',
  'signed',
  'broadcast',
  'mempool',
  'confirmed',
  'settled',
  'conflicted',
  'reorged',
  'abandoned',
]);

export class JournalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'JournalError';
  }
}

const fail = (m) => {
  throw new JournalError(m);
};

const TRANSITIONS = Object.freeze({
  draft: ['funding_selected', 'abandoned'],
  funding_selected: ['tip_synced', 'abandoned'],
  tip_synced: ['proving', 'abandoned'],
  proving: ['proved', 'needs_reproof', 'abandoned'],
  proved: ['signed', 'needs_reproof', 'abandoned'],
  needs_reproof: ['tip_synced', 'proving', 'abandoned'],
  signed: ['broadcast', 'needs_reproof', 'abandoned'],
  broadcast: ['mempool', 'conflicted', 'abandoned'],
  mempool: ['confirmed', 'conflicted', 'reorged'],
  confirmed: ['settled', 'reorged'],
  settled: [],
  conflicted: ['needs_reproof', 'abandoned'],
  reorged: ['needs_reproof', 'abandoned'],
  abandoned: [],
});

export function createJournal(rootDir) {
  mkdirSync(rootDir, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  const filePath = path.join(rootDir, 'operations.json');

  function load() {
    if (!existsSync(filePath)) return { operations: [] };
    return JSON.parse(readFileSync(filePath, 'utf8'));
  }

  function save(data) {
    atomicWriteJson(filePath, data, { mode: PRIVATE_FILE_MODE });
    const mode = statSync(filePath).mode & 0o777;
    if (mode !== PRIVATE_FILE_MODE) fail(`journal mode must be 0600, got ${mode.toString(8)}`);
  }

  function createOperation({ kind, noteId = null }) {
    const data = load();
    const op = {
      id: `op-${Date.now()}-${data.operations.length}`,
      kind,
      noteId,
      state: 'draft',
      createdAt: new Date().toISOString(),
      history: [{ state: 'draft', at: new Date().toISOString() }],
      fundingOutpoint: null,
      tipOutpoint: null,
      packetHex: null,
      proof: null,
      txid: null,
      confirmedStateCommitted: false,
    };
    data.operations.push(op);
    save(data);
    return op;
  }

  function transition(opId, nextState, patch = {}) {
    if (!JOURNAL_STATES.includes(nextState)) fail(`unknown state ${nextState}`);
    const data = load();
    const op = data.operations.find((o) => o.id === opId);
    if (!op) fail(`unknown operation ${opId}`);
    const allowed = TRANSITIONS[op.state] || [];
    if (!allowed.includes(nextState)) {
      fail(`illegal transition ${op.state} → ${nextState}`);
    }
    // Never commit confirmed state before confirmation
    if (patch.confirmedStateCommitted === true && nextState !== 'settled' && nextState !== 'confirmed') {
      fail('cannot mark confirmed state committed before confirmation');
    }
    if (nextState === 'settled') {
      op.confirmedStateCommitted = true;
    }
    Object.assign(op, patch, { state: nextState });
    op.history.push({ state: nextState, at: new Date().toISOString() });
    save(data);
    return op;
  }

  function get(opId) {
    return load().operations.find((o) => o.id === opId) || null;
  }

  function list() {
    return load().operations;
  }

  return Object.freeze({
    rootDir, filePath, createOperation, transition, get, list, load,
  });
}
