/**
 * Private note wallet — only *my* note secrets (full spend material).
 * Never stores global live set; never compares length to chain liveNoteCount.
 *
 * Each open note holds everything required for withdraw after tip rebuild:
 * noteIndex, domain-tagged leaf, key1, nfLeaf1, note1{sk,rho,r,recoveryPublicKey},
 * witnessSeed, depositDigest.
 */
import { createHash, randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';

export const NOTE_WALLET_SCHEMA = 'shieldkit/note-wallet/v1';
export const NOTE_WALLET_BACKUP_SCHEMA = 'shieldkit/note-wallet-backup/v1';

export class NoteWalletError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'NoteWalletError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new NoteWalletError(code, message);
};

const HEX32 = /^[0-9a-f]{64}$/;

function hex32(v, label) {
  if (typeof v !== 'string' || !HEX32.test(v)) fail('INVALID_HEX', `${label} must be 64 lowercase hex chars`);
  return v;
}

function normalizeLeafHex(leaf, label = 'leaf') {
  if (typeof leaf === 'bigint') {
    const h = leaf.toString(16).padStart(64, '0');
    if (h.length > 64) fail('INVALID_HEX', `${label} bigint does not fit 32 bytes`);
    return h;
  }
  if (typeof leaf === 'string' && HEX32.test(leaf)) return leaf;
  // decimal string form sometimes appears for Fr
  if (typeof leaf === 'string' && /^\d+$/.test(leaf)) {
    const h = BigInt(leaf).toString(16).padStart(64, '0');
    if (h.length > 64) fail('INVALID_HEX', `${label} decimal too large`);
    return h;
  }
  fail('INVALID_HEX', `${label} must be 64 lowercase hex chars or Fr bigint`);
}

function normalizeNote1(note1) {
  if (!note1 || typeof note1 !== 'object') fail('INVALID_NOTE1', 'note1 secrets required for spendable wallet note');
  return Object.freeze({
    sk: hex32(note1.sk, 'note1.sk'),
    recoveryPublicKey: hex32(note1.recoveryPublicKey, 'note1.recoveryPublicKey'),
    rho: hex32(note1.rho, 'note1.rho'),
    r: hex32(note1.r, 'note1.r'),
  });
}

/**
 * Build a wallet-owned note record from act residual openNoteMeta (deposit result).
 * Callers must pass the meta entry for *this* deposit only.
 *
 * @param {object} meta — openNoteMeta row from tipForest after deposit
 * @param {{ witnessSeed: string, depositDigest: string, createdSeq?: string }} extra
 */
export function ownedNoteFromOpenMeta(meta, extra) {
  if (!meta || typeof meta !== 'object') fail('INVALID_META', 'openNoteMeta required');
  if (!extra?.witnessSeed || !extra?.depositDigest) {
    fail('INVALID_META', 'witnessSeed and depositDigest required');
  }
  const leaf = normalizeLeafHex(meta.leaf, 'openNoteMeta.leaf');
  const nfLeaf1 = normalizeLeafHex(meta.nfLeaf1, 'openNoteMeta.nfLeaf1');
  const key1 = meta.key1 != null ? String(meta.key1) : fail('INVALID_META', 'openNoteMeta.key1 required');
  if (!/^\d+$/.test(key1)) fail('INVALID_META', 'openNoteMeta.key1 must be decimal string');
  return {
    noteIndex: Number(meta.noteIndex),
    leaf,
    key1,
    nfLeaf1,
    note1: normalizeNote1(meta.note1),
    witnessSeed: hex32(extra.witnessSeed, 'witnessSeed'),
    depositDigest: hex32(extra.depositDigest, 'depositDigest'),
    createdSeq: extra.createdSeq != null ? String(extra.createdSeq) : null,
    commitment: meta.commitment && HEX32.test(meta.commitment) ? meta.commitment : undefined,
  };
}

/**
 * @param {{ profileId: string, instanceId: string, network?: string }} identity
 */
export function createNoteWallet(identity = {}) {
  if (identity.profileId) hex32(identity.profileId, 'profileId');
  if (identity.instanceId) hex32(identity.instanceId, 'instanceId');
  /** @type {object[]} */
  let notes = [];
  const id = {
    profileId: identity.profileId || null,
    instanceId: identity.instanceId || null,
    network: identity.network || 'chipnet',
  };

  function freezeNote(n) {
    return Object.freeze({
      noteIndex: n.noteIndex,
      leaf: n.leaf,
      key1: n.key1,
      nfLeaf1: n.nfLeaf1,
      note1: n.note1 ? Object.freeze({ ...n.note1 }) : null,
      witnessSeed: n.witnessSeed,
      depositDigest: n.depositDigest,
      createdSeq: n.createdSeq,
      commitment: n.commitment || null,
      status: n.status,
    });
  }

  function snapshot() {
    return Object.freeze({
      schema: NOTE_WALLET_SCHEMA,
      profileId: id.profileId,
      instanceId: id.instanceId,
      network: id.network,
      notes: Object.freeze(notes.map((n) => freezeNote(n))),
    });
  }

  return {
    schema: NOTE_WALLET_SCHEMA,
    identity: () => ({ ...id }),
    /** @returns {object[]} open notes only (includes full spend secrets) */
    listOpen() {
      return notes.filter((n) => n.status === 'open').map((n) => freezeNote(n));
    },
    listAll() {
      return notes.map((n) => freezeNote(n));
    },
    /** Private balance = count of open notes (fixed denomination product). */
    privateBalanceNotes() {
      return notes.filter((n) => n.status === 'open').length;
    },
    /**
     * Add a spendable owned note. Full secrets required so backup+tip-replay
     * alone can withdraw without residual tipForest.
     *
     * @param {{
     *   noteIndex: number|string,
     *   leaf: string,
     *   key1: string|number|bigint,
     *   nfLeaf1: string,
     *   note1: { sk: string, recoveryPublicKey: string, rho: string, r: string },
     *   witnessSeed: string,
     *   depositDigest: string,
     *   createdSeq?: string,
     *   commitment?: string,
     * }} note
     */
    addOpenNote(note) {
      if (!note || typeof note !== 'object') fail('INVALID_NOTE', 'note object required');
      const leaf = normalizeLeafHex(note.leaf, 'leaf');
      const nfLeaf1 = normalizeLeafHex(note.nfLeaf1, 'nfLeaf1');
      const witnessSeed = hex32(note.witnessSeed, 'witnessSeed');
      const depositDigest = hex32(note.depositDigest, 'depositDigest');
      const note1 = normalizeNote1(note.note1);
      const key1 = note.key1 != null ? String(note.key1) : fail('INVALID_NOTE', 'key1 required');
      if (!/^\d+$/.test(key1)) fail('INVALID_NOTE', 'key1 must be non-negative decimal string');
      const noteIndex = Number(note.noteIndex);
      if (!Number.isSafeInteger(noteIndex) || noteIndex < 0) fail('INVALID_INDEX', 'noteIndex must be non-negative integer');
      if (notes.some((n) => n.status === 'open' && n.noteIndex === noteIndex)) {
        fail('DUPLICATE', `open note already exists at noteIndex=${noteIndex}`);
      }
      let commitment = null;
      if (note.commitment) commitment = hex32(note.commitment, 'commitment');
      notes.push({
        noteIndex,
        leaf,
        key1,
        nfLeaf1,
        note1,
        witnessSeed,
        depositDigest,
        createdSeq: note.createdSeq != null ? String(note.createdSeq) : null,
        commitment,
        status: 'open',
      });
      return snapshot();
    },
    markSpent(noteIndex) {
      const idx = Number(noteIndex);
      const n = notes.find((x) => x.noteIndex === idx && x.status === 'open');
      if (!n) fail('NOT_FOUND', `no open note at noteIndex=${idx}`);
      n.status = 'spent';
      return snapshot();
    },
    getOpen(noteIndex) {
      const idx = Number(noteIndex);
      const n = notes.find((x) => x.noteIndex === idx && x.status === 'open');
      if (!n) fail('NOT_FOUND', `no open note at noteIndex=${idx}`);
      return freezeNote(n);
    },
    /** LIFO helper among *my* open notes only (not global pool LIFO). */
    lastOpen() {
      const open = notes.filter((n) => n.status === 'open');
      if (!open.length) fail('EMPTY', 'no open notes in wallet');
      return freezeNote(open[open.length - 1]);
    },
    /**
     * openNoteMeta row for witness restore / mergeTipForestForAct (wallet only).
     */
    toOpenNoteMeta(noteIndex) {
      const n = this.getOpen(noteIndex);
      return Object.freeze({
        noteIndex: n.noteIndex,
        leaf: n.leaf,
        key1: n.key1,
        nfLeaf1: n.nfLeaf1,
        witnessSeed: n.witnessSeed,
        note1: { ...n.note1 },
      });
    },
    snapshot,
    /**
     * Encrypt wallet for backup (includes full spend secrets).
     * @param {string} passphrase
     */
    exportEncrypted(passphrase) {
      if (typeof passphrase !== 'string' || passphrase.length < 8) {
        fail('WEAK_PASSPHRASE', 'passphrase must be at least 8 characters');
      }
      const salt = randomBytes(16);
      const key = scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const plain = Buffer.from(JSON.stringify(snapshot()), 'utf8');
      const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
      const tag = cipher.getAuthTag();
      return Object.freeze({
        schema: NOTE_WALLET_BACKUP_SCHEMA,
        kdf: 'scrypt',
        cipher: 'aes-256-gcm',
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
        ciphertext: enc.toString('hex'),
      });
    },
  };
}

/**
 * @param {object} backup — exportEncrypted result
 * @param {string} passphrase
 */
export function importEncryptedNoteWallet(backup, passphrase) {
  if (!backup || backup.schema !== NOTE_WALLET_BACKUP_SCHEMA) {
    fail('INVALID_BACKUP', 'backup.schema must be shieldkit/note-wallet-backup/v1');
  }
  if (typeof passphrase !== 'string') fail('WEAK_PASSPHRASE', 'passphrase required');
  const salt = Buffer.from(backup.salt, 'hex');
  const iv = Buffer.from(backup.iv, 'hex');
  const tag = Buffer.from(backup.tag, 'hex');
  const key = scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let plain;
  try {
    plain = Buffer.concat([
      decipher.update(Buffer.from(backup.ciphertext, 'hex')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    fail('DECRYPT', 'backup decrypt failed (wrong passphrase or corrupt ciphertext)');
  }
  const data = JSON.parse(plain);
  if (data.schema !== NOTE_WALLET_SCHEMA) fail('INVALID_BACKUP', 'inner wallet schema mismatch');
  const w = createNoteWallet({
    profileId: data.profileId || undefined,
    instanceId: data.instanceId || undefined,
    network: data.network,
  });
  for (const n of data.notes || []) {
    // Full secrets required; legacy partial notes fail loudly (cannot spend).
    w.addOpenNote(n);
    if (n.status === 'spent') w.markSpent(n.noteIndex);
  }
  return w;
}

export function sha256Hex(s) {
  return createHash('sha256').update(s).digest('hex');
}
