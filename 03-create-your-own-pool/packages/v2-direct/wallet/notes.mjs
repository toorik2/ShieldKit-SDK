/**
 * Local note wallet + UTXO reservation for V2 Direct.
 */
import { existsSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { atomicWriteJson, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE } from '../../kit/secure-files.mjs';
import { createAccountKeys, shieldAddress } from '../crypto/note.mjs';
import { NETWORK_CHIPNET } from '../constants.mjs';

export class NoteWalletError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NoteWalletError';
  }
}

const fail = (m) => {
  throw new NoteWalletError(m);
};

export function createNoteWallet(rootDir, {
  networkId = NETWORK_CHIPNET,
  profileId,
  instanceId,
} = {}) {
  mkdirSync(rootDir, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
  const secretsPath = path.join(rootDir, 'secrets.json');
  const notesPath = path.join(rootDir, 'notes.json');
  const utxosPath = path.join(rootDir, 'utxos.json');

  function ensureSecrets() {
    if (existsSync(secretsPath)) {
      return JSON.parse(readFileSync(secretsPath, 'utf8'));
    }
    const account = createAccountKeys();
    const payload = {
      networkId,
      profileId,
      instanceId,
      account: {
        sk: account.sk,
        ivk: account.ivk,
        S: account.S,
        V: account.V,
      },
    };
    atomicWriteJson(secretsPath, payload, { mode: PRIVATE_FILE_MODE });
    const mode = statSync(secretsPath).mode & 0o777;
    if (mode !== 0o600) fail('secrets must be mode 0600');
    return payload;
  }

  function loadNotes() {
    if (!existsSync(notesPath)) return { notes: [] };
    return JSON.parse(readFileSync(notesPath, 'utf8'));
  }

  function saveNotes(data) {
    atomicWriteJson(notesPath, data, { mode: PRIVATE_FILE_MODE });
  }

  function loadUtxos() {
    if (!existsSync(utxosPath)) return { utxos: [], reserved: {} };
    return JSON.parse(readFileSync(utxosPath, 'utf8'));
  }

  function saveUtxos(data) {
    atomicWriteJson(utxosPath, data, { mode: PRIVATE_FILE_MODE });
  }

  const secrets = ensureSecrets();
  const address = shieldAddress({
    networkId: secrets.networkId,
    profileId: secrets.profileId || profileId,
    instanceId: secrets.instanceId || instanceId,
    account: secrets.account,
  });

  return Object.freeze({
    rootDir,
    address,
    secretsPath,
    getAccount: () => secrets.account,
    addNote(note) {
      const data = loadNotes();
      data.notes.push({
        ...note,
        status: note.status || 'unspent',
        reservedBy: null,
      });
      saveNotes(data);
      return note;
    },
    listNotes: () => loadNotes().notes,
    reserveNote(noteId, opId) {
      const data = loadNotes();
      const note = data.notes.find((n) => n.id === noteId);
      if (!note) fail('note not found');
      if (note.status !== 'unspent') fail('note not available');
      note.status = 'reserved';
      note.reservedBy = opId;
      saveNotes(data);
      return note;
    },
    markSpent(noteId) {
      const data = loadNotes();
      const note = data.notes.find((n) => n.id === noteId);
      if (!note) fail('note not found');
      note.status = 'spent';
      note.reservedBy = null;
      saveNotes(data);
    },
    setUtxos(utxos) {
      const data = loadUtxos();
      data.utxos = utxos;
      saveUtxos(data);
    },
    /**
     * Select exactly one tokenless P2PKH UTXO covering minValue.
     * Fails with FUNDING_UTXO_REQUIRED before proving.
     */
    selectFundingUtxo(minValue, opId) {
      const data = loadUtxos();
      const need = BigInt(minValue);
      const candidate = data.utxos.find((u) => (
        !data.reserved[u.outpoint]
        && BigInt(u.value) >= need
        && u.token === undefined
      ));
      if (!candidate) {
        const err = new NoteWalletError('FUNDING_UTXO_REQUIRED');
        err.code = 'FUNDING_UTXO_REQUIRED';
        throw err;
      }
      data.reserved[candidate.outpoint] = opId;
      saveUtxos(data);
      return candidate;
    },
    releaseFunding(outpoint) {
      const data = loadUtxos();
      delete data.reserved[outpoint];
      saveUtxos(data);
    },
  });
}
