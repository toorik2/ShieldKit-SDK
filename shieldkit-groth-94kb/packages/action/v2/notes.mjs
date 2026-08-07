import {
  BABYJUB_BASE8,
  BABYJUB_SUBGROUP_ORDER,
  babyJubInSubgroup,
  babyJubMul,
  bytesToHex,
  hexToBytes,
  packBabyJubPoint,
  unpackBabyJubPoint,
} from '../../recover/portable-core.mjs';
import { isSupportedDirectV2NetworkId } from './network.mjs';
import {
  BN254_SCALAR_FIELD_MODULUS,
  V2_DOMAIN_SEPARATORS,
} from './domains.mjs';
import {
  assertCanonicalFr,
  frFromCanonicalHex,
  frToCanonicalHex,
  hashOutputNoteLeaf,
  identifierToU128Limbs,
  poseidonHash,
} from './poseidon.mjs';

export const DIRECT_V2_ADDRESS_SCHEMA = 'shieldkit-address-v2-direct';
export const DIRECT_V2_ENCRYPTED_RECORD_BYTES = 128;
export const DIRECT_V2_DENOMINATION_SATS = 10_000_000n;

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_ACTION_SEQUENCE_EXCLUSIVE = 1n << 33n;
const ADDRESS_KEYS = Object.freeze([
  'schema',
  'networkId',
  'profileId',
  'instanceId',
  'spendPublicKey',
  'incomingViewPublicKey',
  'authority',
]);
const ACCOUNT_KEYS = Object.freeze([
  'address',
  'spendSecret',
  'incomingViewSecret',
]);

export class DirectV2NoteError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DirectV2NoteError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new DirectV2NoteError(code, message);
};

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('INVALID_OBJECT', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
  }
}

function identifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail('INVALID_IDENTIFIER', `${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function scalar(value, label) {
  const parsed = frFromCanonicalHex(value, label);
  if (parsed === 0n || parsed >= BABYJUB_SUBGROUP_ORDER) {
    fail('INVALID_SCALAR', `${label} must be a nonzero canonical BabyJub subgroup scalar`);
  }
  return parsed;
}

function nonzeroFr(value, label) {
  const parsed = frFromCanonicalHex(value, label);
  if (parsed === 0n) fail('ZERO_FIELD', `${label} must be nonzero`);
  return parsed;
}

function canonicalPoint(value, label) {
  try {
    return unpackBabyJubPoint(hexToBytes(identifier(value, label)));
  } catch {
    fail('INVALID_POINT', `${label} must encode a nonidentity prime-subgroup BabyJub point`);
  }
}

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail('INVALID_BYTES', `${label} must contain exactly ${length} bytes`);
  }
  return new Uint8Array(value);
}

function parseSequence(value) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail('INVALID_SEQUENCE', 'postActionSequence must be a canonical unsigned decimal string');
  }
  const parsed = BigInt(value);
  if (parsed === 0n || parsed >= MAX_ACTION_SEQUENCE_EXCLUSIVE) {
    fail('INVALID_SEQUENCE', 'postActionSequence must be between 1 and 2^33-1');
  }
  return parsed;
}

function addFr(left, right) {
  return (left + right) % BN254_SCALAR_FIELD_MODULUS;
}

function subtractFr(left, right) {
  return (left - right + BN254_SCALAR_FIELD_MODULUS) % BN254_SCALAR_FIELD_MODULUS;
}

function randomBytes(rng, length) {
  if (rng === null || typeof rng !== 'object' || typeof rng.bytes !== 'function') {
    fail('INVALID_RNG', 'rng must expose bytes(length)');
  }
  let candidate;
  try {
    candidate = rng.bytes(length);
  } catch {
    fail('CSPRNG_FAILURE', 'CSPRNG failed');
  }
  if (!(candidate instanceof Uint8Array) || candidate.length !== length) {
    fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid byte string');
  }
  return new Uint8Array(candidate);
}

function randomCanonicalFr(rng, label) {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const value = BigInt(`0x${bytesToHex(randomBytes(rng, 32))}`);
    if (value > 0n && value < BN254_SCALAR_FIELD_MODULUS) return value;
  }
  fail('CSPRNG_FAILURE', `CSPRNG did not produce a canonical nonzero ${label}`);
}

function randomBabyJubScalar(rng) {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const value = BigInt(`0x${bytesToHex(randomBytes(rng, 32))}`);
    if (value > 0n && value < BABYJUB_SUBGROUP_ORDER) return value;
  }
  fail('CSPRNG_FAILURE', 'CSPRNG did not produce a canonical nonzero BabyJub scalar');
}

function cryptoContext(profileId, instanceId) {
  return Object.freeze([
    ...identifierToU128Limbs(identifier(profileId, 'profileId'), 'profileId'),
    ...identifierToU128Limbs(identifier(instanceId, 'instanceId'), 'instanceId'),
  ]);
}

function deriveAuthority(profileId, instanceId, spendPoint, incomingViewPoint) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.ADDRESS.value,
    ...cryptoContext(profileId, instanceId),
    spendPoint[0],
    spendPoint[1],
    incomingViewPoint[0],
    incomingViewPoint[1],
  );
}

function deriveMasks({
  profileId,
  instanceId,
  sharedPoint,
  ephemeralPoint,
}) {
  if (
    !babyJubInSubgroup(sharedPoint)
    || !babyJubInSubgroup(ephemeralPoint)
  ) {
    fail('INVALID_POINT', 'record ECDH points must be nonidentity prime-subgroup points');
  }
  const common = [
    ...cryptoContext(profileId, instanceId),
    sharedPoint[0],
    sharedPoint[1],
    ephemeralPoint[0],
    ephemeralPoint[1],
  ];
  return Object.freeze({
    rho: poseidonHash(V2_DOMAIN_SEPARATORS.RECORD_MASK_RHO.value, ...common),
    r: poseidonHash(V2_DOMAIN_SEPARATORS.RECORD_MASK_R.value, ...common),
  });
}

function deriveRecordTag({
  profileId,
  instanceId,
  sharedPoint,
  ephemeralPoint,
  noteCommitment,
  encryptedRho,
  encryptedR,
}) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.RECORD_TAG.value,
    ...cryptoContext(profileId, instanceId),
    sharedPoint[0],
    sharedPoint[1],
    ephemeralPoint[0],
    ephemeralPoint[1],
    assertCanonicalFr(noteCommitment, 'note commitment'),
    assertCanonicalFr(encryptedRho, 'encrypted rho'),
    assertCanonicalFr(encryptedR, 'encrypted r'),
  );
}

function encodeEncryptedRecord(ephemeralPoint, encryptedRho, encryptedR, tag) {
  const record = new Uint8Array(DIRECT_V2_ENCRYPTED_RECORD_BYTES);
  record.set(packBabyJubPoint(ephemeralPoint), 0);
  record.set(hexToBytes(frToCanonicalHex(encryptedRho)), 32);
  record.set(hexToBytes(frToCanonicalHex(encryptedR)), 64);
  record.set(hexToBytes(frToCanonicalHex(tag)), 96);
  return record;
}

function decodeEncryptedRecord(record) {
  const bytes = exactBytes(record, DIRECT_V2_ENCRYPTED_RECORD_BYTES, 'encrypted record');
  const ephemeralPoint = canonicalPoint(bytesToHex(bytes.subarray(0, 32)), 'record ephemeral point');
  let encryptedRho;
  let encryptedR;
  let tag;
  try {
    encryptedRho = frFromCanonicalHex(bytesToHex(bytes.subarray(32, 64)), 'record encrypted rho');
    encryptedR = frFromCanonicalHex(bytesToHex(bytes.subarray(64, 96)), 'record encrypted r');
    tag = frFromCanonicalHex(bytesToHex(bytes.subarray(96, 128)), 'record tag');
  } catch {
    fail('NONCANONICAL_RECORD', 'encrypted record contains a noncanonical field element');
  }
  return Object.freeze({ bytes, ephemeralPoint, encryptedRho, encryptedR, tag });
}

export function deriveDirectV2Address({
  networkId,
  profileId,
  instanceId,
  spendSecret,
  incomingViewSecret,
}) {
  if (!isSupportedDirectV2NetworkId(networkId)) fail('INVALID_NETWORK', 'address network is unsupported');
  const sk = scalar(spendSecret, 'spendSecret');
  const ivk = scalar(incomingViewSecret, 'incomingViewSecret');
  const spendPoint = babyJubMul(BABYJUB_BASE8, sk);
  const incomingViewPoint = babyJubMul(BABYJUB_BASE8, ivk);
  const authority = deriveAuthority(profileId, instanceId, spendPoint, incomingViewPoint);
  return Object.freeze({
    schema: DIRECT_V2_ADDRESS_SCHEMA,
    networkId,
    profileId: identifier(profileId, 'profileId'),
    instanceId: identifier(instanceId, 'instanceId'),
    spendPublicKey: bytesToHex(packBabyJubPoint(spendPoint)),
    incomingViewPublicKey: bytesToHex(packBabyJubPoint(incomingViewPoint)),
    authority: frToCanonicalHex(authority),
  });
}

export function validateDirectV2Address(value) {
  exactKeys(value, 'V2 address', ADDRESS_KEYS);
  if (value.schema !== DIRECT_V2_ADDRESS_SCHEMA) {
    fail('INVALID_ADDRESS_SCHEMA', 'V2 address schema is unsupported');
  }
  if (!isSupportedDirectV2NetworkId(value.networkId)) fail('INVALID_NETWORK', 'address network is unsupported');
  const profileId = identifier(value.profileId, 'address profileId');
  const instanceId = identifier(value.instanceId, 'address instanceId');
  const spendPoint = canonicalPoint(value.spendPublicKey, 'address spendPublicKey');
  const incomingViewPoint = canonicalPoint(value.incomingViewPublicKey, 'address incomingViewPublicKey');
  const authority = frFromCanonicalHex(value.authority, 'address authority');
  const expected = deriveAuthority(profileId, instanceId, spendPoint, incomingViewPoint);
  if (authority !== expected) fail('AUTHORITY_MISMATCH', 'address authority does not bind its public keys');
  return Object.freeze({
    schema: DIRECT_V2_ADDRESS_SCHEMA,
    networkId: value.networkId,
    profileId,
    instanceId,
    spendPublicKey: value.spendPublicKey,
    incomingViewPublicKey: value.incomingViewPublicKey,
    authority: frToCanonicalHex(authority),
  });
}

export function deriveDirectV2Rho({
  profileId,
  instanceId,
  postActionSequence,
  rhoBlind,
}) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.RHO.value,
    ...cryptoContext(profileId, instanceId),
    parseSequence(postActionSequence),
    nonzeroFr(rhoBlind, 'rhoBlind'),
  );
}

export function deriveDirectV2NoteCommitment({
  profileId,
  instanceId,
  authority,
  rho,
  r,
}) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.NOTE.value,
    ...cryptoContext(profileId, instanceId),
    DIRECT_V2_DENOMINATION_SATS,
    frFromCanonicalHex(authority, 'authority'),
    frFromCanonicalHex(rho, 'rho'),
    nonzeroFr(r, 'r'),
  );
}

export function deriveDirectV2Nullifier({
  profileId,
  instanceId,
  spendSecret,
  rho,
  noteCommitment,
}) {
  return poseidonHash(
    V2_DOMAIN_SEPARATORS.NULLIFIER.value,
    ...cryptoContext(profileId, instanceId),
    scalar(spendSecret, 'spendSecret'),
    frFromCanonicalHex(rho, 'rho'),
    frFromCanonicalHex(noteCommitment, 'noteCommitment'),
  );
}

export function constructDirectV2Output({
  address: untrustedAddress,
  postActionSequence,
  rng,
}) {
  const address = validateDirectV2Address(untrustedAddress);
  const rhoBlind = randomCanonicalFr(rng, 'rho blind');
  const r = randomCanonicalFr(rng, 'note randomness');
  const ephemeralScalar = randomBabyJubScalar(rng);
  const rho = deriveDirectV2Rho({
    profileId: address.profileId,
    instanceId: address.instanceId,
    postActionSequence,
    rhoBlind: frToCanonicalHex(rhoBlind),
  });
  const noteCommitment = deriveDirectV2NoteCommitment({
    profileId: address.profileId,
    instanceId: address.instanceId,
    authority: address.authority,
    rho: frToCanonicalHex(rho),
    r: frToCanonicalHex(r),
  });
  const incomingViewPoint = canonicalPoint(
    address.incomingViewPublicKey,
    'address incomingViewPublicKey',
  );
  const ephemeralPoint = babyJubMul(BABYJUB_BASE8, ephemeralScalar);
  const sharedPoint = babyJubMul(incomingViewPoint, ephemeralScalar);
  const masks = deriveMasks({
    profileId: address.profileId,
    instanceId: address.instanceId,
    sharedPoint,
    ephemeralPoint,
  });
  const encryptedRho = addFr(rho, masks.rho);
  const encryptedR = addFr(r, masks.r);
  const tag = deriveRecordTag({
    profileId: address.profileId,
    instanceId: address.instanceId,
    sharedPoint,
    ephemeralPoint,
    noteCommitment,
    encryptedRho,
    encryptedR,
  });
  const encryptedRecord = encodeEncryptedRecord(
    ephemeralPoint,
    encryptedRho,
    encryptedR,
    tag,
  );
  const outputNoteLeaf = hashOutputNoteLeaf(noteCommitment, tag);
  return Object.freeze({
    public: Object.freeze({
      noteCommitment: frToCanonicalHex(noteCommitment),
      outputNoteLeaf: frToCanonicalHex(outputNoteLeaf),
      encryptedRecord,
    }),
    witness: Object.freeze({
      authority: address.authority,
      spendPublicKey: address.spendPublicKey,
      incomingViewPublicKey: address.incomingViewPublicKey,
      rho: frToCanonicalHex(rho),
      rhoBlind: frToCanonicalHex(rhoBlind),
      r: frToCanonicalHex(r),
      ephemeralScalar: frToCanonicalHex(ephemeralScalar),
    }),
  });
}

/**
 * Re-derive every public and private output field for one exact successor
 * sequence. This is the prepare/rebase admission check: malformed or stale
 * output randomness is rejected before it can be committed to a durable
 * operation and before expensive proving begins.
 */
export function validateDirectV2OutputConstruction({
  address: untrustedAddress,
  postActionSequence,
  output,
}) {
  const address = validateDirectV2Address(untrustedAddress);
  exactKeys(
    output,
    'V2 output construction',
    ['public', 'witness'],
  );
  exactKeys(
    output.public,
    'V2 output construction public material',
    ['encryptedRecord', 'noteCommitment', 'outputNoteLeaf'],
  );
  exactKeys(
    output.witness,
    'V2 output construction witness',
    [
      'authority',
      'ephemeralScalar',
      'incomingViewPublicKey',
      'r',
      'rho',
      'rhoBlind',
      'spendPublicKey',
    ],
  );
  if (
    output.witness.authority !== address.authority
    || output.witness.spendPublicKey !== address.spendPublicKey
    || output.witness.incomingViewPublicKey
      !== address.incomingViewPublicKey
  ) {
    fail(
      'OUTPUT_RECIPIENT_MISMATCH',
      'output construction does not bind the supplied recipient address',
    );
  }
  const rhoBlind = nonzeroFr(output.witness.rhoBlind, 'rhoBlind');
  const r = nonzeroFr(output.witness.r, 'r');
  const ephemeralScalar =
    scalar(output.witness.ephemeralScalar, 'ephemeralScalar');
  const rho = deriveDirectV2Rho({
    profileId: address.profileId,
    instanceId: address.instanceId,
    postActionSequence,
    rhoBlind: frToCanonicalHex(rhoBlind),
  });
  if (output.witness.rho !== frToCanonicalHex(rho)) {
    fail(
      'OUTPUT_SEQUENCE_MISMATCH',
      'output rho does not bind the exact post-action sequence',
    );
  }
  const noteCommitment = deriveDirectV2NoteCommitment({
    profileId: address.profileId,
    instanceId: address.instanceId,
    authority: address.authority,
    rho: output.witness.rho,
    r: frToCanonicalHex(r),
  });
  if (output.public.noteCommitment !== frToCanonicalHex(noteCommitment)) {
    fail(
      'OUTPUT_COMMITMENT_MISMATCH',
      'output note commitment does not match its exact private witness',
    );
  }
  const incomingViewPoint = canonicalPoint(
    address.incomingViewPublicKey,
    'address incomingViewPublicKey',
  );
  const ephemeralPoint = babyJubMul(BABYJUB_BASE8, ephemeralScalar);
  const sharedPoint = babyJubMul(incomingViewPoint, ephemeralScalar);
  const masks = deriveMasks({
    profileId: address.profileId,
    instanceId: address.instanceId,
    sharedPoint,
    ephemeralPoint,
  });
  const encryptedRho = addFr(rho, masks.rho);
  const encryptedR = addFr(r, masks.r);
  const tag = deriveRecordTag({
    profileId: address.profileId,
    instanceId: address.instanceId,
    sharedPoint,
    ephemeralPoint,
    noteCommitment,
    encryptedRho,
    encryptedR,
  });
  const encryptedRecord = encodeEncryptedRecord(
    ephemeralPoint,
    encryptedRho,
    encryptedR,
    tag,
  );
  const suppliedRecord = exactBytes(
    output.public.encryptedRecord,
    DIRECT_V2_ENCRYPTED_RECORD_BYTES,
    'output encrypted record',
  );
  if (suppliedRecord.some(
    (byte, index) => byte !== encryptedRecord[index],
  )) {
    fail(
      'OUTPUT_RECORD_MISMATCH',
      'output encrypted record does not match its exact private witness',
    );
  }
  const outputNoteLeaf = hashOutputNoteLeaf(noteCommitment, tag);
  if (output.public.outputNoteLeaf !== frToCanonicalHex(outputNoteLeaf)) {
    fail(
      'OUTPUT_LEAF_MISMATCH',
      'output note leaf does not match its commitment and record tag',
    );
  }
  return Object.freeze({
    public: Object.freeze({
      encryptedRecord: new Uint8Array(encryptedRecord),
      noteCommitment: output.public.noteCommitment,
      outputNoteLeaf: output.public.outputNoteLeaf,
    }),
    witness: Object.freeze({ ...output.witness }),
  });
}

function validateAccount(value) {
  exactKeys(value, 'V2 account', ACCOUNT_KEYS);
  const address = validateDirectV2Address(value.address);
  const spendSecret = scalar(value.spendSecret, 'account spendSecret');
  const incomingViewSecret = scalar(value.incomingViewSecret, 'account incomingViewSecret');
  if (
    bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, spendSecret)))
      !== address.spendPublicKey
    || bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, incomingViewSecret)))
      !== address.incomingViewPublicKey
  ) {
    fail('ACCOUNT_MISMATCH', 'account secrets do not match the recipient address');
  }
  return Object.freeze({ address, spendSecret, incomingViewSecret });
}

export function recoverDirectV2Output({
  account: untrustedAccount,
  outputNoteLeaf,
  encryptedRecord,
}) {
  const account = validateAccount(untrustedAccount);
  const expectedLeaf = frFromCanonicalHex(outputNoteLeaf, 'outputNoteLeaf');
  const decoded = decodeEncryptedRecord(encryptedRecord);
  const sharedPoint = babyJubMul(decoded.ephemeralPoint, account.incomingViewSecret);
  const masks = deriveMasks({
    profileId: account.address.profileId,
    instanceId: account.address.instanceId,
    sharedPoint,
    ephemeralPoint: decoded.ephemeralPoint,
  });
  const rho = subtractFr(decoded.encryptedRho, masks.rho);
  const r = subtractFr(decoded.encryptedR, masks.r);
  if (r === 0n) fail('INVALID_PLAINTEXT', 'recovered note randomness is zero');
  const noteCommitment = deriveDirectV2NoteCommitment({
    profileId: account.address.profileId,
    instanceId: account.address.instanceId,
    authority: account.address.authority,
    rho: frToCanonicalHex(rho),
    r: frToCanonicalHex(r),
  });
  const expectedTag = deriveRecordTag({
    profileId: account.address.profileId,
    instanceId: account.address.instanceId,
    sharedPoint,
    ephemeralPoint: decoded.ephemeralPoint,
    noteCommitment,
    encryptedRho: decoded.encryptedRho,
    encryptedR: decoded.encryptedR,
  });
  if (expectedTag !== decoded.tag) {
    fail('RECORD_AUTHENTICATION_FAILED', 'encrypted record authentication failed');
  }
  const actualLeaf = hashOutputNoteLeaf(noteCommitment, decoded.tag);
  if (actualLeaf !== expectedLeaf) {
    fail('OUTPUT_LEAF_MISMATCH', 'encrypted record does not match outputNoteLeaf');
  }
  const nullifier = deriveDirectV2Nullifier({
    profileId: account.address.profileId,
    instanceId: account.address.instanceId,
    spendSecret: frToCanonicalHex(account.spendSecret),
    rho: frToCanonicalHex(rho),
    noteCommitment: frToCanonicalHex(noteCommitment),
  });
  return Object.freeze({
    authority: account.address.authority,
    rho: frToCanonicalHex(rho),
    r: frToCanonicalHex(r),
    noteCommitment: frToCanonicalHex(noteCommitment),
    nullifier: frToCanonicalHex(nullifier),
    outputNoteLeaf: frToCanonicalHex(actualLeaf),
    encryptedRecord: decoded.bytes,
  });
}

export const DIRECT_V2_INTERNALS = Object.freeze({
  decodeEncryptedRecord,
  deriveAuthority,
  deriveMasks,
  deriveRecordTag,
  subtractFr,
});
