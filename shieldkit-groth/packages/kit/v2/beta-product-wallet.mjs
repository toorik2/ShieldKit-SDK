import { createHash, randomBytes as systemRandomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
} from 'node:fs';
import { dirname, isAbsolute, parse, relative, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { secp256k1 } from '@bitauth/libauth';

import {
  constructDirectV2Output,
  deriveDirectV2Address,
  recoverDirectV2Output,
  validateDirectV2OutputConstruction,
} from '../../action/v2/notes.mjs';
import { BABYJUB_SUBGROUP_ORDER } from '../../recover/portable-core.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  deriveV2ChipnetFundingWallet,
  projectV2FundingWalletPublic,
} from './funding-wallet.mjs';

export const V2_BETA_PRODUCT_WALLET_SCHEMA =
  'shieldkit-v2-beta-product-wallet-v1';
export const V2_BETA_PRODUCT_WALLET_CRASH_STAGES = Object.freeze([
  'wallet.stage.after_insert',
  'wallet.attach.after_update',
  'wallet.orphan.after_update',
  'wallet.change.sent.after_update',
  'wallet.change.indeterminate.after_update',
  'wallet.action.send.after_change_update',
  'wallet.action.indeterminate.after_change_update',
  'wallet.action.abort.after_change_update',
  'wallet.note.stage.after_insert',
  'wallet.note.attach.after_update',
  'wallet.note.reserve.after_update',
  'wallet.note.sent.after_update',
  'wallet.note.indeterminate.after_update',
  'wallet.note.spent.after_update',
  'wallet.note.release.after_update',
]);

const VERSION = 5;
const HEX_32 = /^[0-9a-f]{64}$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const WALLET_BRAND = new WeakSet();
const SIDE_CARS = Object.freeze(['-wal', '-shm', '-journal']);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS wallet_metadata (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version INTEGER NOT NULL CHECK(schema_version=5),
  profile_id TEXT NOT NULL CHECK(length(profile_id)=64),
  instance_id TEXT NOT NULL CHECK(length(instance_id)=64),
  note_spend_secret TEXT NOT NULL CHECK(length(note_spend_secret)=64),
  note_incoming_view_secret TEXT NOT NULL CHECK(length(note_incoming_view_secret)=64),
  note_address_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64)
) STRICT;
CREATE TABLE IF NOT EXISTS funding_keyring (
  wallet_id TEXT PRIMARY KEY CHECK(length(wallet_id)=64),
  private_key_hex TEXT NOT NULL UNIQUE CHECK(length(private_key_hex)=64),
  compressed_public_key_hex TEXT NOT NULL UNIQUE CHECK(length(compressed_public_key_hex)=66),
  locking_bytecode_hex TEXT NOT NULL UNIQUE,
  cash_address TEXT NOT NULL UNIQUE,
  created_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS change_wallets (
  operation_id TEXT PRIMARY KEY,
  wallet_id TEXT NOT NULL UNIQUE CHECK(length(wallet_id)=64),
  private_key_hex TEXT NOT NULL UNIQUE CHECK(length(private_key_hex)=64),
  compressed_public_key_hex TEXT NOT NULL UNIQUE CHECK(length(compressed_public_key_hex)=66),
  locking_bytecode_hex TEXT NOT NULL UNIQUE,
  cash_address TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK(state IN ('prepared','sent','indeterminate','attached','orphan-recoverable')),
  attached_txid TEXT CHECK(attached_txid IS NULL OR length(attached_txid)=64),
  attached_vout INTEGER CHECK(attached_vout IS NULL OR attached_vout >= 0),
  attached_value_sats TEXT CHECK(attached_value_sats IS NULL OR attached_value_sats GLOB '[0-9]*'),
  orphan_reason TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(
    (state='attached' AND attached_txid IS NOT NULL AND attached_vout IS NOT NULL
      AND attached_value_sats IS NOT NULL AND orphan_reason IS NULL)
    OR
    (state IN ('prepared','sent','indeterminate') AND attached_txid IS NULL AND attached_vout IS NULL
      AND attached_value_sats IS NULL AND orphan_reason IS NULL)
    OR
    (state='orphan-recoverable' AND attached_txid IS NULL AND attached_vout IS NULL
      AND attached_value_sats IS NULL AND orphan_reason IS NOT NULL)
  )
) STRICT;
CREATE TABLE IF NOT EXISTS note_operations (
  operation_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL CHECK(length(profile_id)=64),
  instance_id TEXT NOT NULL CHECK(length(instance_id)=64),
  note_id TEXT NOT NULL CHECK(length(note_id)=64),
  kind TEXT NOT NULL CHECK(kind IN ('deposit','withdrawal')),
  state TEXT NOT NULL CHECK(state IN ('deposit-staged','deposit-rejected','deposit-attached','withdrawal-reserved','withdrawal-released','withdrawal-committed')),
  created_at_ms INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS owned_notes (
  note_id TEXT PRIMARY KEY CHECK(length(note_id)=64),
  profile_id TEXT NOT NULL CHECK(length(profile_id)=64),
  instance_id TEXT NOT NULL CHECK(length(instance_id)=64),
  deposit_operation_id TEXT NOT NULL UNIQUE,
  post_action_sequence TEXT NOT NULL,
  note_commitment TEXT NOT NULL UNIQUE CHECK(length(note_commitment)=64),
  output_note_leaf TEXT NOT NULL UNIQUE CHECK(length(output_note_leaf)=64),
  encrypted_record_hex TEXT NOT NULL CHECK(length(encrypted_record_hex)=256),
  rho TEXT NOT NULL CHECK(length(rho)=64),
  rho_blind TEXT NOT NULL CHECK(length(rho_blind)=64),
  randomness_r TEXT NOT NULL CHECK(length(randomness_r)=64),
  ephemeral_scalar TEXT NOT NULL CHECK(length(ephemeral_scalar)=64),
  nullifier TEXT NOT NULL UNIQUE CHECK(length(nullifier)=64),
  state TEXT NOT NULL CHECK(state IN ('deposit-staged','deposit-rejected','unspent','reserved','spent')),
  deposit_txid TEXT CHECK(deposit_txid IS NULL OR length(deposit_txid)=64),
  note_index INTEGER CHECK(note_index IS NULL OR note_index >= 0),
  reservation_operation_id TEXT UNIQUE,
  reservation_phase TEXT CHECK(reservation_phase IS NULL OR reservation_phase IN ('prepared','sent','indeterminate','committed')),
  spent_txid TEXT CHECK(spent_txid IS NULL OR length(spent_txid)=64),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  CHECK(
    (state='deposit-staged' AND deposit_txid IS NULL AND note_index IS NULL
      AND reservation_operation_id IS NULL AND reservation_phase IS NULL AND spent_txid IS NULL)
    OR
    (state='deposit-rejected' AND deposit_txid IS NULL AND note_index IS NULL
      AND reservation_operation_id IS NULL AND reservation_phase IS NULL AND spent_txid IS NULL)
    OR
    (state='unspent' AND deposit_txid IS NOT NULL AND note_index IS NOT NULL
      AND reservation_operation_id IS NULL AND reservation_phase IS NULL AND spent_txid IS NULL)
    OR
    (state='reserved' AND deposit_txid IS NOT NULL AND note_index IS NOT NULL
      AND reservation_operation_id IS NOT NULL AND reservation_phase IN ('prepared','sent','indeterminate')
      AND spent_txid IS NULL)
    OR
    (state='spent' AND deposit_txid IS NOT NULL AND note_index IS NOT NULL
      AND reservation_operation_id IS NOT NULL AND reservation_phase='committed' AND spent_txid IS NOT NULL)
  )
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS owned_notes_note_index_unique
  ON owned_notes(profile_id, instance_id, note_index) WHERE note_index IS NOT NULL;
`;

export class V2BetaProductWalletError extends Error {
  constructor(code, message, { cause = undefined } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2BetaProductWalletError';
    this.code = code;
  }
}

export class V2BetaProductWalletCrash extends Error {
  constructor(stage) {
    super(`injected V2 beta product wallet crash at ${stage}`);
    this.name = 'V2BetaProductWalletCrash';
    this.stage = stage;
  }
}

const fail = (code, message, options) => {
  throw new V2BetaProductWalletError(code, message, options);
};

const hash = value => createHash('sha256').update(value).digest('hex');
const now = () => Date.now();

function exactObject(value, keys, label) {
  if (
    value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) fail('INVALID_WALLET_ARGUMENT', `${label} must be a plain object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    fail('INVALID_WALLET_ARGUMENT', `${label} has missing or unknown fields`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail('INVALID_WALLET_IDENTITY', `${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function operationId(value) {
  if (typeof value !== 'string' || !OPERATION_ID.test(value)) {
    fail('INVALID_OPERATION_ID', 'operationId is invalid');
  }
  return value;
}

function actionKind(value) {
  if (value !== 'deposit' && value !== 'withdrawal') {
    fail('INVALID_ACTION_KIND', 'kind must be deposit or withdrawal');
  }
  return value;
}

function noteId(value) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail('INVALID_NOTE_ID', 'noteId must be lowercase 32-byte hex');
  }
  return value;
}

function postActionSequence(value) {
  if (typeof value !== 'string' || !/^(?:[1-9][0-9]*)$/.test(value)) {
    fail('INVALID_NOTE_SEQUENCE', 'postActionSequence must be a canonical positive integer');
  }
  const parsed = BigInt(value);
  if (parsed >= (1n << 33n)) {
    fail('INVALID_NOTE_SEQUENCE', 'postActionSequence must be below 2^33');
  }
  return value;
}

function txid(value) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail('INVALID_CHANGE_ATTACHMENT', 'txid must be lowercase 32-byte hex');
  }
  return value;
}

function valueSats(value) {
  if (typeof value === 'bigint') value = value.toString();
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    fail('INVALID_CHANGE_ATTACHMENT', 'valueSats must be a canonical nonnegative integer');
  }
  return value;
}

function crashStage(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !V2_BETA_PRODUCT_WALLET_CRASH_STAGES.includes(value)) {
    fail('INVALID_CRASH_STAGE', 'crashAt is unsupported');
  }
  return value;
}

function crash(requested, stage) {
  if (requested === stage) throw new V2BetaProductWalletCrash(stage);
}

function assertDedicatedPrivateParent(databasePath) {
  if (typeof databasePath !== 'string' || databasePath.length === 0 || databasePath.includes('\0')) {
    fail('UNSAFE_WALLET_PATH', 'databasePath must be a nonempty path');
  }
  const absolute = isAbsolute(databasePath) ? databasePath : resolve(databasePath);
  if (absolute !== resolve(absolute)) fail('UNSAFE_WALLET_PATH', 'databasePath is not normalized');
  const parent = dirname(absolute);
  const root = parse(parent).root;
  if (parent === root) fail('UNSAFE_WALLET_PATH', 'wallet requires a dedicated private parent');
  let current = root;
  for (const segment of relative(root, parent).split('/').filter(Boolean)) {
    current = `${current}${current.endsWith('/') ? '' : '/'}${segment}`;
    let stat;
    try { stat = lstatSync(current); } catch (error) {
      fail('UNSAFE_WALLET_PATH', 'wallet parent and every ancestor must already exist', { cause: error });
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      fail('UNSAFE_WALLET_PATH', 'wallet parent traversal contains a symlink or non-directory');
    }
  }
  const parentStat = lstatSync(parent);
  if ((parentStat.mode & 0o777) !== 0o700 || (process.getuid && parentStat.uid !== process.getuid())) {
    fail('UNSAFE_WALLET_PATH', 'wallet parent must be owner-controlled mode 0700');
  }
  return absolute;
}

function assertRegularPrivatePath(filename) {
  if (!existsSync(filename)) return;
  const stat = lstatSync(filename);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0) {
    fail('UNSAFE_WALLET_PATH', 'wallet database and sidecars must be unlinked regular private files');
  }
}

function secureFiles(databasePath) {
  for (const filename of [databasePath, ...SIDE_CARS.map(suffix => `${databasePath}${suffix}`)]) {
    if (existsSync(filename)) {
      const stat = lstatSync(filename);
      if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
        fail('UNSAFE_WALLET_PATH', 'wallet database and sidecars must be unlinked regular files');
      }
      chmodSync(filename, 0o600);
    }
  }
}

function freshBabyJubSecret() {
  for (let attempt = 0; attempt < 4096; attempt += 1) {
    const candidate = systemRandomBytes(32).toString('hex');
    const scalar = BigInt(`0x${candidate}`);
    if (scalar > 0n && scalar < BABYJUB_SUBGROUP_ORDER) return candidate;
  }
  fail('CSPRNG_FAILURE', 'could not sample a canonical BabyJubJub scalar');
}

function freshFundingWallet() {
  for (let attempt = 0; attempt < 4096; attempt += 1) {
    const bytes = systemRandomBytes(32);
    if (secp256k1.validatePrivateKey(bytes) === true) {
      return deriveV2ChipnetFundingWallet({ privateKeyHex: bytes.toString('hex') });
    }
  }
  fail('CSPRNG_FAILURE', 'could not sample a valid secp256k1 scalar');
}

function publicChange(row) {
  return Object.freeze({
    operationId: row.operation_id,
    walletId: row.wallet_id,
    compressedPublicKeyHex: row.compressed_public_key_hex,
    lockingBytecodeHex: row.locking_bytecode_hex,
    cashAddress: row.cash_address,
    state: row.state,
    attachedTxid: row.attached_txid,
    attachedVout: row.attached_vout,
    attachedValueSats: row.attached_value_sats,
  });
}

function publicNote(row) {
  return Object.freeze({
    noteId: row.note_id,
    depositOperationId: row.deposit_operation_id,
    postActionSequence: row.post_action_sequence,
    noteCommitment: row.note_commitment,
    outputNoteLeaf: row.output_note_leaf,
    encryptedRecord: Uint8Array.from(Buffer.from(row.encrypted_record_hex, 'hex')),
    state: row.state,
    noteIndex: row.note_index === null ? null : String(row.note_index),
    depositTxid: row.deposit_txid,
    reservationOperationId: row.reservation_operation_id,
    reservationPhase: row.reservation_phase,
    spentTxid: row.spent_txid,
  });
}

function noteOutput(row, address) {
  return Object.freeze({
    public: Object.freeze({
      noteCommitment: row.note_commitment,
      outputNoteLeaf: row.output_note_leaf,
      encryptedRecord: Uint8Array.from(Buffer.from(row.encrypted_record_hex, 'hex')),
    }),
    witness: Object.freeze({
      authority: address.authority,
      spendPublicKey: address.spendPublicKey,
      incomingViewPublicKey: address.incomingViewPublicKey,
      rho: row.rho,
      rhoBlind: row.rho_blind,
      r: row.randomness_r,
      ephemeralScalar: row.ephemeral_scalar,
    }),
  });
}

function depositNoteId(profileId, instanceId, operation) {
  return hash(canonicalizeJcs({
    schema: V2_BETA_PRODUCT_WALLET_SCHEMA,
    type: 'owned-deposit-note',
    profileId,
    instanceId,
    operationId: operation,
  }));
}

function ownedRecordId(row) {
  return hash(canonicalizeJcs({
    schema: V2_BETA_PRODUCT_WALLET_SCHEMA,
    type: 'owned-encrypted-note-record',
    profileId: row.profile_id,
    instanceId: row.instance_id,
    noteId: row.note_id,
    encryptedRecordSha256: hash(Buffer.from(row.encrypted_record_hex, 'hex')),
  }));
}

function walletId(wallet) {
  return hash(canonicalizeJcs(projectV2FundingWalletPublic(wallet)));
}

function metadataFingerprint({ profileId, instanceId, address }) {
  return hash(canonicalizeJcs({ schema: V2_BETA_PRODUCT_WALLET_SCHEMA, version: VERSION, profileId, instanceId, address }));
}

function parseStoredAddress(json) {
  try { return JSON.parse(json); } catch (error) {
    fail('WALLET_TAMPERED', 'stored note address is not valid JSON', { cause: error });
  }
}

export class V2BetaProductWallet {
  #db;
  #path;
  #crashAt;
  #closed = false;

  constructor({ databasePath, profileId, instanceId, fundingPrivateKeyHex = undefined, crashAt = undefined } = {}) {
    this.#path = assertDedicatedPrivateParent(databasePath);
    this.#crashAt = crashStage(crashAt);
    for (const file of [this.#path, ...SIDE_CARS.map(suffix => `${this.#path}${suffix}`)]) assertRegularPrivatePath(file);
    this.#db = new DatabaseSync(this.#path);
    try {
      this.#db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;');
      secureFiles(this.#path);
      this.#db.exec(SCHEMA);
      this.#initializeOrVerify(profileId, instanceId, fundingPrivateKeyHex);
      this.#verifyIntegrity();
      WALLET_BRAND.add(this);
    } catch (error) {
      try { this.#db.close(); } catch { /* best effort */ }
      throw error;
    }
  }

  #assertOpen() { if (this.#closed) fail('WALLET_CLOSED', 'wallet is closed'); }

  #account() {
    const metadata = this.#db.prepare('SELECT * FROM wallet_metadata WHERE singleton=1').get();
    if (!metadata) fail('WALLET_TAMPERED', 'wallet metadata is missing');
    this.#verifyMetadata(metadata);
    return Object.freeze({
      profileId: metadata.profile_id,
      instanceId: metadata.instance_id,
      address: Object.freeze(parseStoredAddress(metadata.note_address_json)),
      spendSecret: metadata.note_spend_secret,
      incomingViewSecret: metadata.note_incoming_view_secret,
    });
  }

  #initializeOrVerify(profileId, instanceId, fundingPrivateKeyHex) {
    const existing = this.#db.prepare('SELECT * FROM wallet_metadata WHERE singleton=1').get();
    if (!existing) {
      const p = identifier(profileId, 'profileId');
      const i = identifier(instanceId, 'instanceId');
      if (typeof fundingPrivateKeyHex !== 'string') {
        fail('FUNDING_KEY_REQUIRED', 'first wallet open requires a funding private key');
      }
      const spendSecret = freshBabyJubSecret();
      const incomingViewSecret = freshBabyJubSecret();
      const address = deriveDirectV2Address({ networkId: 2, profileId: p, instanceId: i, spendSecret, incomingViewSecret });
      const fingerprint = metadataFingerprint({ profileId: p, instanceId: i, address });
      const funding = deriveV2ChipnetFundingWallet({ privateKeyHex: fundingPrivateKeyHex });
      const stamp = now();
      this.#db.exec('BEGIN IMMEDIATE');
      try {
        this.#db.prepare('INSERT INTO wallet_metadata VALUES(1, ?, ?, ?, ?, ?, ?, ?)').run(
          VERSION, p, i, spendSecret, incomingViewSecret, canonicalizeJcs(address), fingerprint,
        );
        this.#insertFunding(funding, stamp);
        this.#db.exec('COMMIT');
      } catch (error) {
        this.#db.exec('ROLLBACK');
        throw error;
      }
      return;
    }
    if (profileId !== undefined && identifier(profileId, 'profileId') !== existing.profile_id) {
      fail('WALLET_IDENTITY_MISMATCH', 'profileId differs from the existing wallet');
    }
    if (instanceId !== undefined && identifier(instanceId, 'instanceId') !== existing.instance_id) {
      fail('WALLET_IDENTITY_MISMATCH', 'instanceId differs from the existing wallet');
    }
    this.#verifyMetadata(existing);
    if (fundingPrivateKeyHex !== undefined) {
      const funding = deriveV2ChipnetFundingWallet({ privateKeyHex: fundingPrivateKeyHex });
      this.#db.exec('BEGIN IMMEDIATE');
      try { this.#insertFunding(funding, now()); this.#db.exec('COMMIT'); }
      catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    }
  }

  #insertFunding(funding, stamp) {
    const publicWallet = projectV2FundingWalletPublic(funding);
    const id = walletId(funding);
    const old = this.#db.prepare('SELECT private_key_hex FROM funding_keyring WHERE wallet_id=?').get(id);
    if (old) {
      if (old.private_key_hex !== funding.privateKeyHex) fail('WALLET_TAMPERED', 'funding wallet identity collision');
      return;
    }
    this.#db.prepare(`INSERT INTO funding_keyring(
      wallet_id, private_key_hex, compressed_public_key_hex, locking_bytecode_hex, cash_address, created_at_ms
    ) VALUES(?, ?, ?, ?, ?, ?)`).run(
      id, funding.privateKeyHex, publicWallet.compressedPublicKeyHex, publicWallet.lockingBytecodeHex,
      publicWallet.cashAddress, stamp,
    );
  }

  #freshDistinctChangeWallet() {
    for (let attempt = 0; attempt < 128; attempt += 1) {
      const candidate = freshFundingWallet();
      const id = walletId(candidate);
      const funding = this.#db.prepare('SELECT 1 FROM funding_keyring WHERE wallet_id=?').get(id);
      const change = this.#db.prepare('SELECT 1 FROM change_wallets WHERE wallet_id=?').get(id);
      if (!funding && !change) return candidate;
    }
    fail('CSPRNG_FAILURE', 'could not sample a distinct change wallet identity');
  }

  #verifyMetadata(row) {
    if (row.schema_version !== VERSION || !HEX_32.test(row.profile_id) || !HEX_32.test(row.instance_id)
      || !HEX_32.test(row.note_spend_secret) || !HEX_32.test(row.note_incoming_view_secret) || !HEX_32.test(row.fingerprint)) {
      fail('WALLET_TAMPERED', 'wallet metadata has an invalid shape');
    }
    const address = deriveDirectV2Address({
      networkId: 2, profileId: row.profile_id, instanceId: row.instance_id,
      spendSecret: row.note_spend_secret, incomingViewSecret: row.note_incoming_view_secret,
    });
    if (canonicalizeJcs(address) !== canonicalizeJcs(parseStoredAddress(row.note_address_json))
      || metadataFingerprint({ profileId: row.profile_id, instanceId: row.instance_id, address }) !== row.fingerprint) {
      fail('WALLET_TAMPERED', 'wallet metadata fingerprint does not match its bound account');
    }
  }

  #verifyIntegrity() {
    const result = this.#db.prepare('PRAGMA integrity_check').all();
    if (result.length !== 1 || result[0].integrity_check !== 'ok') {
      fail('WALLET_INTEGRITY_FAILED', 'SQLite integrity_check did not return ok');
    }
    const account = this.#account();
    for (const row of this.#db.prepare('SELECT * FROM funding_keyring').all()) {
      const wallet = deriveV2ChipnetFundingWallet({ privateKeyHex: row.private_key_hex });
      const publicWallet = projectV2FundingWalletPublic(wallet);
      if (walletId(wallet) !== row.wallet_id || publicWallet.compressedPublicKeyHex !== row.compressed_public_key_hex
        || publicWallet.lockingBytecodeHex !== row.locking_bytecode_hex || publicWallet.cashAddress !== row.cash_address) {
        fail('WALLET_TAMPERED', 'funding keyring entry is inconsistent');
      }
    }
    for (const row of this.#db.prepare('SELECT * FROM change_wallets').all()) {
      const wallet = deriveV2ChipnetFundingWallet({ privateKeyHex: row.private_key_hex });
      const publicWallet = projectV2FundingWalletPublic(wallet);
      if (walletId(wallet) !== row.wallet_id || publicWallet.compressedPublicKeyHex !== row.compressed_public_key_hex
        || publicWallet.lockingBytecodeHex !== row.locking_bytecode_hex || publicWallet.cashAddress !== row.cash_address) {
        fail('WALLET_TAMPERED', 'change keyring entry is inconsistent');
      }
    }
    const notesById = new Map();
    for (const row of this.#db.prepare('SELECT * FROM owned_notes').all()) {
      this.#verifyOwnedNote(row, account);
      notesById.set(row.note_id, row);
    }
    const storedOperations = this.#db.prepare('SELECT * FROM note_operations').all();
    const operationsById = new Map(storedOperations.map(operation => [operation.operation_id, operation]));
    for (const operation of storedOperations) {
      const note = notesById.get(operation.note_id);
      if (!note || operation.profile_id !== account.profileId || operation.instance_id !== account.instanceId) {
        fail('WALLET_TAMPERED', 'owned-note operation registry is inconsistent');
      }
      if (operation.kind === 'deposit') {
        const expectedState = note.state === 'deposit-staged'
          ? 'deposit-staged'
          : note.state === 'deposit-rejected' ? 'deposit-rejected' : 'deposit-attached';
        if (operation.operation_id !== note.deposit_operation_id || operation.state !== expectedState) {
          fail('WALLET_TAMPERED', 'owned-note deposit operation registry is inconsistent');
        }
      } else if (operation.kind === 'withdrawal') {
        const current = operation.operation_id === note.reservation_operation_id;
        const expectedState = !current ? 'withdrawal-released'
          : note.state === 'spent' ? 'withdrawal-committed' : 'withdrawal-reserved';
        if (operation.state !== expectedState) {
          fail('WALLET_TAMPERED', 'owned-note withdrawal operation registry is inconsistent');
        }
      } else {
        fail('WALLET_TAMPERED', 'owned-note operation kind is invalid');
      }
    }
    for (const note of notesById.values()) {
      const deposit = operationsById.get(note.deposit_operation_id);
      const reservation = note.reservation_operation_id === null ? null : operationsById.get(note.reservation_operation_id);
      if (!deposit || deposit.kind !== 'deposit' || deposit.note_id !== note.note_id
        || (note.reservation_operation_id !== null && (!reservation || reservation.kind !== 'withdrawal' || reservation.note_id !== note.note_id))) {
        fail('WALLET_TAMPERED', 'owned note has no matching immutable operation registry row');
      }
    }
  }

  #verifyOwnedNote(row, account) {
    if (row.profile_id !== account.profileId || row.instance_id !== account.instanceId
      || depositNoteId(account.profileId, account.instanceId, row.deposit_operation_id) !== row.note_id
      || !HEX_32.test(row.note_commitment) || !HEX_32.test(row.output_note_leaf)
      || !/^[0-9a-f]{256}$/.test(row.encrypted_record_hex) || !HEX_32.test(row.rho)
      || !HEX_32.test(row.rho_blind) || !HEX_32.test(row.randomness_r)
      || !HEX_32.test(row.ephemeral_scalar) || !HEX_32.test(row.nullifier)) {
      fail('WALLET_TAMPERED', 'owned note has an invalid shape or binding');
    }
    postActionSequence(row.post_action_sequence);
    if (row.note_index !== null && (!Number.isSafeInteger(row.note_index) || row.note_index < 0)) {
      fail('WALLET_TAMPERED', 'owned note index is invalid');
    }
    const output = noteOutput(row, account.address);
    let validated;
    let recovered;
    try {
      validated = validateDirectV2OutputConstruction({
        address: account.address,
        postActionSequence: row.post_action_sequence,
        output,
      });
      recovered = recoverDirectV2Output({
        account: {
          address: account.address,
          spendSecret: account.spendSecret,
          incomingViewSecret: account.incomingViewSecret,
        },
        outputNoteLeaf: validated.public.outputNoteLeaf,
        encryptedRecord: validated.public.encryptedRecord,
      });
    } catch (error) {
      fail('WALLET_TAMPERED', 'owned note cannot be re-derived from private wallet material', { cause: error });
    }
    if (recovered.noteCommitment !== row.note_commitment || recovered.nullifier !== row.nullifier
      || recovered.rho !== row.rho || recovered.r !== row.randomness_r) {
      fail('WALLET_TAMPERED', 'owned note public or private material differs from its derivation');
    }
  }

  close() {
    if (!this.#closed) { this.#db.close(); this.#closed = true; }
  }

  publicSummary() {
    this.#assertOpen();
    const metadata = this.#db.prepare('SELECT * FROM wallet_metadata WHERE singleton=1').get();
    const counts = this.#db.prepare(`SELECT
      COUNT(*) AS all_count,
      SUM(state='prepared') AS prepared_count,
      SUM(state='sent') AS sent_count,
      SUM(state='indeterminate') AS indeterminate_count,
      SUM(state='attached') AS attached_count,
      SUM(state='orphan-recoverable') AS orphan_count
      FROM change_wallets`).get();
      const noteCounts = this.#db.prepare(`SELECT
      COUNT(*) AS all_count,
      SUM(state='deposit-staged') AS staged_count,
      SUM(state='deposit-rejected') AS rejected_count,
      SUM(state='unspent') AS unspent_count,
      SUM(state='reserved') AS reserved_count,
      SUM(state='spent') AS spent_count
      FROM owned_notes`).get();
    return Object.freeze({
      schema: V2_BETA_PRODUCT_WALLET_SCHEMA,
      profileId: metadata.profile_id,
      instanceId: metadata.instance_id,
      noteAddress: Object.freeze(parseStoredAddress(metadata.note_address_json)),
      fundingWalletCount: this.#db.prepare('SELECT COUNT(*) AS count FROM funding_keyring').get().count,
      changeWalletCount: counts.all_count,
      preparedChangeCount: counts.prepared_count ?? 0,
      sentChangeCount: counts.sent_count ?? 0,
      indeterminateChangeCount: counts.indeterminate_count ?? 0,
      attachedChangeCount: counts.attached_count ?? 0,
      orphanRecoverableChangeCount: counts.orphan_count ?? 0,
      ownedNoteCount: noteCounts.all_count,
      stagedDepositNoteCount: noteCounts.staged_count ?? 0,
      rejectedDepositNoteCount: noteCounts.rejected_count ?? 0,
      unspentOwnedNoteCount: noteCounts.unspent_count ?? 0,
      reservedOwnedNoteCount: noteCounts.reserved_count ?? 0,
      spentOwnedNoteCount: noteCounts.spent_count ?? 0,
    });
  }

  fundingWallets() {
    this.#assertOpen();
    return Object.freeze(this.#db.prepare(`SELECT wallet_id, compressed_public_key_hex, locking_bytecode_hex, cash_address
      FROM funding_keyring ORDER BY wallet_id`).all().map(row => Object.freeze({
      walletId: row.wallet_id, compressedPublicKeyHex: row.compressed_public_key_hex,
      lockingBytecodeHex: row.locking_bytecode_hex, cashAddress: row.cash_address,
    })));
  }

  spendableFundingWallets() {
    this.#assertOpen();
    const base = this.#db.prepare(`SELECT wallet_id, compressed_public_key_hex, locking_bytecode_hex, cash_address
      FROM funding_keyring ORDER BY wallet_id`).all().map(row => Object.freeze({
      source: 'funding-keyring',
      walletId: row.wallet_id,
      compressedPublicKeyHex: row.compressed_public_key_hex,
      lockingBytecodeHex: row.locking_bytecode_hex,
      cashAddress: row.cash_address,
      attachedOutpoint: null,
      attachedValueSats: null,
    }));
    const attached = this.#db.prepare(`SELECT wallet_id, compressed_public_key_hex, locking_bytecode_hex, cash_address,
      attached_txid, attached_vout, attached_value_sats FROM change_wallets WHERE state='attached'
      ORDER BY attached_txid, attached_vout, wallet_id`).all().map(row => Object.freeze({
      source: 'attached-change',
      walletId: row.wallet_id,
      compressedPublicKeyHex: row.compressed_public_key_hex,
      lockingBytecodeHex: row.locking_bytecode_hex,
      cashAddress: row.cash_address,
      attachedOutpoint: Object.freeze({ txid: row.attached_txid, vout: row.attached_vout }),
      attachedValueSats: row.attached_value_sats,
    }));
    return Object.freeze([...base, ...attached]);
  }

  addFundingWallet({ privateKeyHex } = {}) {
    this.#assertOpen();
    const funding = deriveV2ChipnetFundingWallet({ privateKeyHex });
    this.#db.exec('BEGIN IMMEDIATE');
    try { this.#insertFunding(funding, now()); this.#db.exec('COMMIT'); }
    catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return this.fundingWallets().find(value => value.walletId === walletId(funding));
  }

  signFunding({ walletId: requestedId, digestHex } = {}) {
    this.#assertOpen();
    if (typeof requestedId !== 'string' || !HEX_32.test(requestedId)
      || typeof digestHex !== 'string' || !HEX_32.test(digestHex)) {
      fail('INVALID_SIGNING_REQUEST', 'walletId and digestHex must be lowercase 32-byte hex');
    }
    let row = this.#db.prepare('SELECT private_key_hex FROM funding_keyring WHERE wallet_id=?').get(requestedId);
    if (!row) {
      const change = this.#db.prepare('SELECT private_key_hex, state FROM change_wallets WHERE wallet_id=?').get(requestedId);
      if (!change) fail('FUNDING_WALLET_UNKNOWN', 'funding wallet is not in this keyring');
      if (change.state !== 'attached') {
        fail('CHANGE_WALLET_NOT_SPENDABLE', 'only an exactly attached change wallet may authorize funding');
      }
      row = change;
    }
    const signature = secp256k1.signMessageHashSchnorr(Buffer.from(row.private_key_hex, 'hex'), Buffer.from(digestHex, 'hex'));
    if (!(signature instanceof Uint8Array) || signature.length !== 64) fail('FUNDING_SIGNING_FAILED', 'internal Schnorr signing failed');
    return Buffer.from(signature);
  }

  stageChangeWallet({ operationId: requestedOperationId } = {}) {
    this.#assertOpen();
    const op = operationId(requestedOperationId);
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      // The existence check and fresh-key selection must occur under the same
      // writer lock. Otherwise two live CLI processes can both observe no row,
      // generate independent change keys, and race toward the same operation.
      const existing = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op);
      if (existing) {
        this.#db.exec('COMMIT');
        return publicChange(existing);
      }
      const change = this.#freshDistinctChangeWallet();
      const projection = projectV2FundingWalletPublic(change);
      const stamp = now();
      this.#db.prepare(`INSERT INTO change_wallets(
        operation_id,wallet_id,private_key_hex,compressed_public_key_hex,locking_bytecode_hex,cash_address,
        state,attached_txid,attached_vout,attached_value_sats,orphan_reason,created_at_ms,updated_at_ms
      ) VALUES(?,?,?,?,?,?,'prepared',NULL,NULL,NULL,NULL,?,?)`).run(
        op, walletId(change), change.privateKeyHex, projection.compressedPublicKeyHex,
        projection.lockingBytecodeHex, projection.cashAddress, stamp, stamp,
      );
      crash(this.#crashAt, 'wallet.stage.after_insert');
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return publicChange(this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op));
  }

  attachChangeWallet({ operationId: requestedOperationId, txid: requestedTxid, vout, valueSats: requestedValueSats, acceptedCommit } = {}) {
    this.#assertOpen();
    const op = operationId(requestedOperationId);
    const transactionId = txid(requestedTxid);
    if (!Number.isSafeInteger(vout) || vout < 0) fail('INVALID_CHANGE_ATTACHMENT', 'vout must be a nonnegative safe integer');
    const amount = valueSats(requestedValueSats);
    if (acceptedCommit !== true) fail('UNACCEPTED_COMMIT', 'change may attach only after an accepted durable commit');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const current = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op);
      if (!current) fail('CHANGE_WALLET_UNKNOWN', 'change wallet was not staged');
      if (current.state === 'attached') {
        if (current.attached_txid === transactionId && current.attached_vout === vout && current.attached_value_sats === amount) {
          this.#db.exec('COMMIT'); return publicChange(current);
        }
        fail('CHANGE_WALLET_REUSE', 'change wallet already attached to a different exact outpoint');
      }
      if (!['sent', 'indeterminate'].includes(current.state)) {
        fail('CHANGE_WALLET_NOT_RECONCILABLE', 'change wallet must be sent or indeterminate before accepted attachment');
      }
      this.#db.prepare(`UPDATE change_wallets SET state='attached', attached_txid=?, attached_vout=?,
        attached_value_sats=?, updated_at_ms=? WHERE operation_id=?`).run(transactionId, vout, amount, now(), op);
      crash(this.#crashAt, 'wallet.attach.after_update');
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return publicChange(this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op));
  }

  #setChangeWalletState(operation, nextState, stage) {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const current = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(operation);
      if (!current) fail('CHANGE_WALLET_UNKNOWN', 'change wallet was not staged');
      if (current.state === nextState) { this.#db.exec('COMMIT'); return publicChange(current); }
      const allowed = nextState === 'sent'
        ? current.state === 'prepared'
        : current.state === 'prepared' || current.state === 'sent';
      if (!allowed) fail('CHANGE_WALLET_STATE', 'change wallet state transition is not allowed');
      this.#db.prepare('UPDATE change_wallets SET state=?, updated_at_ms=? WHERE operation_id=?').run(nextState, now(), operation);
      crash(this.#crashAt, stage);
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return publicChange(this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(operation));
  }

  markChangeWalletSent({ operationId: requestedOperationId } = {}) {
    this.#assertOpen();
    return this.#setChangeWalletState(operationId(requestedOperationId), 'sent', 'wallet.change.sent.after_update');
  }

  markChangeWalletIndeterminate({ operationId: requestedOperationId } = {}) {
    this.#assertOpen();
    return this.#setChangeWalletState(operationId(requestedOperationId), 'indeterminate', 'wallet.change.indeterminate.after_update');
  }

  #markActionResourceState(operation, kind, nextState, crashAfterChange) {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const change = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(operation);
      if (!change) fail('ACTION_CHANGE_UNKNOWN', 'action has no staged change wallet');
      const note = kind === 'withdrawal'
        ? this.#db.prepare('SELECT * FROM owned_notes WHERE reservation_operation_id=?').get(operation)
        : null;
      if (kind === 'withdrawal' && !note) {
        fail('ACTION_NOTE_UNKNOWN', 'withdrawal action has no reserved owned note');
      }
      const expectedChangeState = nextState === 'sent' ? 'prepared' : 'sent';
      const expectedNotePhase = nextState === 'sent' ? 'prepared' : 'sent';
      const alreadyChange = change.state === nextState;
      const alreadyNote = note === null || (note.state === 'reserved' && note.reservation_phase === nextState);
      if (alreadyChange && alreadyNote) {
        this.#db.exec('COMMIT');
        return Object.freeze({ change: publicChange(change), note: note === null ? null : publicNote(note) });
      }
      if (change.state !== expectedChangeState || (note !== null && (note.state !== 'reserved' || note.reservation_phase !== expectedNotePhase))) {
        fail('ACTION_RESOURCE_STATE', 'action change and owned-note resources are not jointly ready for this transition');
      }
      this.#db.prepare('UPDATE change_wallets SET state=?, updated_at_ms=? WHERE operation_id=?').run(nextState, now(), operation);
      crash(this.#crashAt, crashAfterChange);
      if (note !== null) {
        this.#db.prepare('UPDATE owned_notes SET reservation_phase=?, updated_at_ms=? WHERE note_id=?').run(nextState, now(), note.note_id);
      }
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    const changed = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(operation);
    const changedNote = kind === 'withdrawal'
      ? this.#db.prepare('SELECT * FROM owned_notes WHERE reservation_operation_id=?').get(operation)
      : null;
    return Object.freeze({ change: publicChange(changed), note: changedNote === null ? null : publicNote(changedNote) });
  }

  markActionSendAttempt(value = undefined) {
    exactObject(value, ['kind', 'operationId'], 'action send-attempt request');
    this.#assertOpen();
    return this.#markActionResourceState(
      operationId(value.operationId),
      actionKind(value.kind),
      'sent',
      'wallet.action.send.after_change_update',
    );
  }

  markActionIndeterminate(value = undefined) {
    exactObject(value, ['kind', 'operationId'], 'action indeterminate request');
    this.#assertOpen();
    return this.#markActionResourceState(
      operationId(value.operationId),
      actionKind(value.kind),
      'indeterminate',
      'wallet.action.indeterminate.after_change_update',
    );
  }

  abortSafePreSendAction(value = undefined) {
    exactObject(value, ['kind', 'operationId', 'reason'], 'pre-send action abort request');
    this.#assertOpen();
    const op = operationId(value.operationId);
    const kind = actionKind(value.kind);
    const reason = value.reason;
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) {
      fail('INVALID_ORPHAN_REASON', 'reason must be 1 to 256 printable characters');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const change = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op);
      if (!change) fail('ACTION_CHANGE_UNKNOWN', 'action has no staged change wallet');
      const note = kind === 'deposit'
        ? this.#db.prepare('SELECT * FROM owned_notes WHERE deposit_operation_id=?').get(op)
        : (() => {
          const operation = this.#db.prepare('SELECT * FROM note_operations WHERE operation_id=?').get(op);
          return operation?.kind === 'withdrawal'
            ? this.#db.prepare('SELECT * FROM owned_notes WHERE note_id=?').get(operation.note_id)
            : null;
        })();
      if (!note) fail('ACTION_NOTE_UNKNOWN', 'action has no matching owned-note resource');
      const alreadyAborted = change.state === 'orphan-recoverable';
      if (alreadyAborted) {
        const expected = kind === 'deposit'
          ? note.state === 'deposit-rejected'
          : note.state === 'unspent' && note.reservation_operation_id === null;
        const noteOperation = this.#db.prepare('SELECT state FROM note_operations WHERE operation_id=?').get(op);
        const expectedOperation = kind === 'deposit' ? 'deposit-rejected' : 'withdrawal-released';
        if (change.orphan_reason !== reason || !expected || noteOperation?.state !== expectedOperation) {
          fail('ACTION_ABORT_REPLAY_MISMATCH', 'pre-send abort replay differs from the immutable prior abort');
        }
        this.#db.exec('COMMIT');
        return Object.freeze({ change: publicChange(change), note: publicNote(note) });
      }
      if (change.state !== 'prepared') {
        fail('ACTION_ABORT_NOT_PRE_SEND', 'only a definitely pre-send prepared change wallet may be aborted');
      }
      const noteReady = kind === 'deposit'
        ? note.state === 'deposit-staged'
        : note.state === 'reserved' && note.reservation_operation_id === op && note.reservation_phase === 'prepared';
      if (!noteReady) {
        fail('ACTION_ABORT_NOT_PRE_SEND', 'owned-note resource is sent, indeterminate, attached, or otherwise not safely abortable');
      }
      this.#db.prepare(`UPDATE change_wallets SET state='orphan-recoverable', orphan_reason=?, updated_at_ms=?
        WHERE operation_id=?`).run(reason, now(), op);
      crash(this.#crashAt, 'wallet.action.abort.after_change_update');
      if (kind === 'deposit') {
        this.#db.prepare(`UPDATE owned_notes SET state='deposit-rejected', updated_at_ms=? WHERE note_id=?`).run(now(), note.note_id);
        this.#db.prepare(`UPDATE note_operations SET state='deposit-rejected'
          WHERE operation_id=? AND kind='deposit'`).run(op);
      } else {
        this.#db.prepare(`UPDATE owned_notes SET state='unspent', reservation_operation_id=NULL,
          reservation_phase=NULL, updated_at_ms=? WHERE note_id=?`).run(now(), note.note_id);
        this.#db.prepare(`UPDATE note_operations SET state='withdrawal-released'
          WHERE operation_id=? AND kind='withdrawal'`).run(op);
      }
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    const changed = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op);
    const changedNote = kind === 'deposit'
      ? this.#db.prepare('SELECT * FROM owned_notes WHERE deposit_operation_id=?').get(op)
      : (() => {
        const operation = this.#db.prepare('SELECT note_id FROM note_operations WHERE operation_id=?').get(op);
        return this.#db.prepare('SELECT * FROM owned_notes WHERE note_id=?').get(operation.note_id);
      })();
    return Object.freeze({ change: publicChange(changed), note: publicNote(changedNote) });
  }

  markChangeOrphanRecoverable({ operationId: requestedOperationId, reason } = {}) {
    this.#assertOpen();
    const op = operationId(requestedOperationId);
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) {
      fail('INVALID_ORPHAN_REASON', 'reason must be 1 to 256 printable characters');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const current = this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op);
      if (!current) fail('CHANGE_WALLET_UNKNOWN', 'change wallet was not staged');
      if (current.state !== 'prepared') fail('CHANGE_WALLET_NOT_PREPARED', 'only a definitely pre-send change wallet can be orphaned');
      if (current.state === 'prepared') this.#db.prepare(`UPDATE change_wallets SET state='orphan-recoverable', orphan_reason=?, updated_at_ms=? WHERE operation_id=?`).run(reason, now(), op);
      crash(this.#crashAt, 'wallet.orphan.after_update');
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return publicChange(this.#db.prepare('SELECT * FROM change_wallets WHERE operation_id=?').get(op));
  }

  recoverPreparedChanges({ reason = 'reopened-before-accepted-commit' } = {}) {
    this.#assertOpen();
    if (typeof reason !== 'string' || reason.length < 1 || reason.length > 256 || /[\u0000-\u001f\u007f]/.test(reason)) {
      fail('INVALID_ORPHAN_REASON', 'reason must be 1 to 256 printable characters');
    }
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result = this.#db.prepare(`UPDATE change_wallets SET state='orphan-recoverable', orphan_reason=?, updated_at_ms=?
        WHERE state='prepared'`).run(reason, now());
      this.#db.exec('COMMIT');
      return result.changes;
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }

  #depositStageMaterial(row, account) {
    const output = noteOutput(row, account.address);
    return Object.freeze({
      note: publicNote(row),
      publicOutput: Object.freeze({
        noteCommitment: output.public.noteCommitment,
        outputNoteLeaf: output.public.outputNoteLeaf,
        encryptedRecord: Uint8Array.from(output.public.encryptedRecord),
      }),
      circuitOutput: output,
      // Deliberately in-memory only: this is the exact handoff for the
      // private incremental store once the staged deposit is accepted.
      privateStoreMaterial: Object.freeze({
        noteId: row.note_id,
        recordId: ownedRecordId(row),
        nullifier: row.nullifier,
        encryptedRecord: Uint8Array.from(Buffer.from(row.encrypted_record_hex, 'hex')),
      }),
    });
  }

  #withdrawalSpendMaterial(row, account) {
    if (row.note_index === null) fail('OWNED_NOTE_NOT_ACCEPTED', 'owned note has no accepted note index');
    return Object.freeze({
      note: publicNote(row),
      publicSpend: Object.freeze({
        inputNoteLeaf: row.output_note_leaf,
        noteIndex: String(row.note_index),
        publicNullifier: row.nullifier,
      }),
      circuitSpend: Object.freeze({
        spendSecret: account.spendSecret,
        incomingViewPublicKey: account.address.incomingViewPublicKey,
        rho: row.rho,
        r: row.randomness_r,
        encryptedRecord: Uint8Array.from(Buffer.from(row.encrypted_record_hex, 'hex')),
      }),
    });
  }

  stageDepositNote(value = undefined) {
    exactObject(value, ['operationId', 'postActionSequence'], 'deposit note staging request');
    this.#assertOpen();
    const op = operationId(value.operationId);
    const sequence = postActionSequence(value.postActionSequence);
    const account = this.#account();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const prior = this.#db.prepare('SELECT * FROM note_operations WHERE operation_id=?').get(op);
      if (prior) {
        if (prior.kind !== 'deposit') fail('NOTE_OPERATION_REUSE', 'operationId was already used for a withdrawal');
        const existing = this.#db.prepare('SELECT * FROM owned_notes WHERE note_id=?').get(prior.note_id);
        if (!existing || existing.post_action_sequence !== sequence) {
          fail('NOTE_OPERATION_REUSE', 'deposit operation does not match its immutable staged note');
        }
        if (existing.state === 'deposit-rejected') {
          fail('NOTE_OPERATION_REJECTED', 'deposit operation was aborted before send and is permanently unusable');
        }
        this.#db.exec('COMMIT');
        return this.#depositStageMaterial(existing, account);
      }
      const output = constructDirectV2Output({
        address: account.address,
        postActionSequence: sequence,
        rng: Object.freeze({ bytes: length => new Uint8Array(systemRandomBytes(length)) }),
      });
      const recovered = recoverDirectV2Output({
        account: {
          address: account.address,
          spendSecret: account.spendSecret,
          incomingViewSecret: account.incomingViewSecret,
        },
        outputNoteLeaf: output.public.outputNoteLeaf,
        encryptedRecord: output.public.encryptedRecord,
      });
      const id = depositNoteId(account.profileId, account.instanceId, op);
      const stamp = now();
      this.#db.prepare(`INSERT INTO owned_notes(
        note_id,profile_id,instance_id,deposit_operation_id,post_action_sequence,note_commitment,
        output_note_leaf,encrypted_record_hex,rho,rho_blind,randomness_r,ephemeral_scalar,nullifier,
        state,deposit_txid,note_index,reservation_operation_id,reservation_phase,spent_txid,created_at_ms,updated_at_ms
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'deposit-staged',NULL,NULL,NULL,NULL,NULL,?,?)`).run(
        id, account.profileId, account.instanceId, op, sequence, output.public.noteCommitment,
        output.public.outputNoteLeaf, Buffer.from(output.public.encryptedRecord).toString('hex'),
        output.witness.rho, output.witness.rhoBlind, output.witness.r, output.witness.ephemeralScalar,
        recovered.nullifier, stamp, stamp,
      );
      this.#db.prepare('INSERT INTO note_operations VALUES(?,?,?,?,?,?,?)').run(
        op, account.profileId, account.instanceId, id, 'deposit', 'deposit-staged', stamp,
      );
      crash(this.#crashAt, 'wallet.note.stage.after_insert');
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return this.#depositStageMaterial(
      this.#db.prepare('SELECT * FROM owned_notes WHERE deposit_operation_id=?').get(op),
      account,
    );
  }

  attachAcceptedDeposit(value = undefined) {
    exactObject(value, ['acceptedCommit', 'noteIndex', 'operationId', 'txid'], 'accepted deposit request');
    this.#assertOpen();
    const op = operationId(value.operationId);
    const transactionId = txid(value.txid);
    if (!Number.isSafeInteger(value.noteIndex) || value.noteIndex < 0) {
      fail('INVALID_NOTE_INDEX', 'noteIndex must be a nonnegative safe integer');
    }
    if (value.acceptedCommit !== true) fail('UNACCEPTED_COMMIT', 'deposit note may attach only after an accepted durable commit');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM owned_notes WHERE deposit_operation_id=?').get(op);
      if (!row) fail('OWNED_NOTE_UNKNOWN', 'deposit note was not staged for this operation');
      if (row.state === 'unspent' || row.state === 'reserved' || row.state === 'spent') {
        if (row.deposit_txid === transactionId && row.note_index === value.noteIndex) {
          this.#db.exec('COMMIT'); return publicNote(row);
        }
        fail('OWNED_NOTE_REUSE', 'deposit note is already attached to a different exact index or transaction');
      }
      if (row.state !== 'deposit-staged') fail('OWNED_NOTE_STATE', 'deposit note cannot be attached from its current state');
      this.#db.prepare(`UPDATE owned_notes SET state='unspent', deposit_txid=?, note_index=?, updated_at_ms=?
        WHERE note_id=?`).run(transactionId, value.noteIndex, now(), row.note_id);
      this.#db.prepare(`UPDATE note_operations SET state='deposit-attached'
        WHERE operation_id=? AND kind='deposit'`).run(op);
      crash(this.#crashAt, 'wallet.note.attach.after_update');
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return publicNote(this.#db.prepare('SELECT * FROM owned_notes WHERE deposit_operation_id=?').get(op));
  }

  reserveOwnedNoteForWithdrawal(value = undefined) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      fail('INVALID_WALLET_ARGUMENT', 'withdrawal reservation request must be an object');
    }
    const keys = Object.keys(value).sort();
    const valid = keys.length === 1 && keys[0] === 'operationId'
      || keys.length === 2 && keys[0] === 'noteId' && keys[1] === 'operationId';
    if (!valid) fail('INVALID_WALLET_ARGUMENT', 'withdrawal reservation request has missing or unknown fields');
    this.#assertOpen();
    const op = operationId(value.operationId);
    const requestedNoteId = value.noteId === undefined ? undefined : noteId(value.noteId);
    const account = this.#account();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const prior = this.#db.prepare('SELECT * FROM note_operations WHERE operation_id=?').get(op);
      if (prior) {
        if (prior.kind !== 'withdrawal' || (requestedNoteId !== undefined && prior.note_id !== requestedNoteId)) {
          fail('NOTE_OPERATION_REUSE', 'operationId does not match its immutable withdrawal reservation');
        }
        const existing = this.#db.prepare('SELECT * FROM owned_notes WHERE note_id=?').get(prior.note_id);
        if (!existing || existing.reservation_operation_id !== op || existing.state !== 'reserved') {
          fail('WITHDRAWAL_OPERATION_COMPLETED', 'withdrawal reservation is no longer active');
        }
        this.#db.exec('COMMIT');
        return this.#withdrawalSpendMaterial(existing, account);
      }
      const selected = requestedNoteId === undefined
        ? this.#db.prepare(`SELECT * FROM owned_notes WHERE profile_id=? AND instance_id=? AND state='unspent'
          ORDER BY note_index, note_id LIMIT 1`).get(account.profileId, account.instanceId)
        : this.#db.prepare(`SELECT * FROM owned_notes WHERE note_id=? AND profile_id=? AND instance_id=?`).get(
          requestedNoteId, account.profileId, account.instanceId,
        );
      if (!selected || selected.state !== 'unspent') {
        fail('OWNED_NOTE_UNAVAILABLE', 'no requested unspent owned note is available');
      }
      const stamp = now();
      const update = this.#db.prepare(`UPDATE owned_notes SET state='reserved', reservation_operation_id=?,
        reservation_phase='prepared', updated_at_ms=? WHERE note_id=? AND state='unspent'`).run(op, stamp, selected.note_id);
      if (update.changes !== 1) fail('OWNED_NOTE_UNAVAILABLE', 'owned note reservation raced with another operation');
      this.#db.prepare('INSERT INTO note_operations VALUES(?,?,?,?,?,?,?)').run(
        op, account.profileId, account.instanceId, selected.note_id, 'withdrawal', 'withdrawal-reserved', stamp,
      );
      crash(this.#crashAt, 'wallet.note.reserve.after_update');
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return this.#withdrawalSpendMaterial(
      this.#db.prepare('SELECT * FROM owned_notes WHERE reservation_operation_id=?').get(op),
      account,
    );
  }

  #setWithdrawalReservationPhase(operation, phase, stage) {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM owned_notes WHERE reservation_operation_id=?').get(operation);
      if (!row) fail('WITHDRAWAL_RESERVATION_UNKNOWN', 'withdrawal reservation is unknown');
      if (row.state !== 'reserved') fail('WITHDRAWAL_OPERATION_COMPLETED', 'withdrawal reservation is no longer active');
      if (row.reservation_phase === phase) { this.#db.exec('COMMIT'); return publicNote(row); }
      const allowed = phase === 'sent'
        ? row.reservation_phase === 'prepared'
        : row.reservation_phase === 'prepared' || row.reservation_phase === 'sent';
      if (!allowed) fail('WITHDRAWAL_RESERVATION_STATE', 'withdrawal reservation phase cannot be changed');
      this.#db.prepare('UPDATE owned_notes SET reservation_phase=?, updated_at_ms=? WHERE note_id=?').run(phase, now(), row.note_id);
      crash(this.#crashAt, stage);
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return publicNote(this.#db.prepare('SELECT * FROM owned_notes WHERE reservation_operation_id=?').get(operation));
  }

  markWithdrawalReservationSent(value = undefined) {
    exactObject(value, ['operationId'], 'withdrawal sent request');
    this.#assertOpen();
    return this.#setWithdrawalReservationPhase(operationId(value.operationId), 'sent', 'wallet.note.sent.after_update');
  }

  markWithdrawalReservationIndeterminate(value = undefined) {
    exactObject(value, ['operationId'], 'withdrawal indeterminate request');
    this.#assertOpen();
    return this.#setWithdrawalReservationPhase(operationId(value.operationId), 'indeterminate', 'wallet.note.indeterminate.after_update');
  }

  commitAcceptedWithdrawalSpend(value = undefined) {
    exactObject(value, ['acceptedCommit', 'operationId', 'txid'], 'accepted withdrawal request');
    this.#assertOpen();
    const op = operationId(value.operationId);
    const transactionId = txid(value.txid);
    if (value.acceptedCommit !== true) fail('UNACCEPTED_COMMIT', 'owned note may be spent only after an accepted durable commit');
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM owned_notes WHERE reservation_operation_id=?').get(op);
      if (!row) fail('WITHDRAWAL_RESERVATION_UNKNOWN', 'withdrawal reservation is unknown');
      if (row.state === 'spent') {
        if (row.spent_txid === transactionId) { this.#db.exec('COMMIT'); return publicNote(row); }
        fail('OWNED_NOTE_REUSE', 'owned note was spent by a different exact transaction');
      }
      if (row.state !== 'reserved' || !['sent', 'indeterminate'].includes(row.reservation_phase)) {
        fail('WITHDRAWAL_RESERVATION_STATE', 'only a sent or indeterminate reservation may commit as spent');
      }
      this.#db.prepare(`UPDATE owned_notes SET state='spent', reservation_phase='committed', spent_txid=?, updated_at_ms=?
        WHERE note_id=?`).run(transactionId, now(), row.note_id);
      this.#db.prepare(`UPDATE note_operations SET state='withdrawal-committed'
        WHERE operation_id=? AND kind='withdrawal'`).run(op);
      crash(this.#crashAt, 'wallet.note.spent.after_update');
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    return publicNote(this.#db.prepare('SELECT * FROM owned_notes WHERE reservation_operation_id=?').get(op));
  }

  recoverSafePreSendWithdrawals() {
    this.#assertOpen();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result = this.#db.prepare(`UPDATE owned_notes SET state='unspent', reservation_operation_id=NULL,
        reservation_phase=NULL, updated_at_ms=? WHERE state='reserved' AND reservation_phase='prepared'`).run(now());
      this.#db.prepare(`UPDATE note_operations SET state='withdrawal-released'
        WHERE kind='withdrawal' AND state='withdrawal-reserved' AND operation_id NOT IN (
          SELECT reservation_operation_id FROM owned_notes WHERE reservation_operation_id IS NOT NULL
        )`).run();
      crash(this.#crashAt, 'wallet.note.release.after_update');
      this.#db.exec('COMMIT');
      return result.changes;
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }

  ownedNotesForWatch() {
    this.#assertOpen();
    return Object.freeze(this.#db.prepare('SELECT * FROM owned_notes ORDER BY created_at_ms, note_id').all().map(publicNote));
  }

  changeWalletsForWatch() {
    this.#assertOpen();
    return Object.freeze(this.#db.prepare('SELECT * FROM change_wallets ORDER BY created_at_ms, operation_id').all().map(publicChange));
  }
}

export function openV2BetaProductWallet(options = undefined) {
  return new V2BetaProductWallet(options);
}

export function assertV2BetaProductWallet(value) {
  if (!WALLET_BRAND.has(value) || typeof value.stageChangeWallet !== 'function'
    || typeof value.signFunding !== 'function' || typeof value.spendableFundingWallets !== 'function'
    || typeof value.stageDepositNote !== 'function'
    || typeof value.reserveOwnedNoteForWithdrawal !== 'function'
    || typeof value.commitAcceptedWithdrawalSpend !== 'function'
    || typeof value.markActionSendAttempt !== 'function'
    || typeof value.markActionIndeterminate !== 'function'
    || typeof value.abortSafePreSendAction !== 'function') {
    fail('WALLET_CAPABILITY_REQUIRED', 'a branded V2 beta product wallet capability is required');
  }
  return value;
}
