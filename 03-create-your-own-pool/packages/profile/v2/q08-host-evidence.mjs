import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';

import { parseStrictJson } from '../load.mjs';
import { canonicalizeJcs } from './profile-core.mjs';
import { assertV2FinalReleaseRoot } from './release-bootstrap.mjs';

export const V2_Q08_HOST_STATEMENT_SCHEMA =
  'shieldkit-v2-direct-q08-clean-host-statement-v2';
export const V2_Q08_SIGNED_HOST_TRANSCRIPT_SCHEMA =
  'shieldkit-v2-direct-q08-signed-host-transcript-v1';
export const V2_Q08_HOST_SIGNATURE_DOMAIN =
  'shieldkit-v2-direct-q08-host-transcript-signature-v1\0';

const HASH = /^[0-9a-f]{64}$/;
const HOST_ROLES = Object.freeze(['clean-host-a', 'clean-host-b']);
const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
const PRIVATE_KEY_STABLE_FIELDS = Object.freeze([
  'dev',
  'ino',
  'size',
  'mode',
  'nlink',
  'uid',
  'mtimeNs',
  'ctimeNs',
]);

export class V2Q08HostEvidenceError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2Q08HostEvidenceError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new V2Q08HostEvidenceError(code, message, cause);
};
const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('Q08_HOST_SCHEMA_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(
      'Q08_HOST_SCHEMA_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
  return value;
}

function authority(value, label) {
  exact(value, [
    'independenceDomain',
    'organizationId',
    'publicKey',
    'role',
    'signerId',
  ], label);
  if (
    !HOST_ROLES.includes(value.role)
    || typeof value.signerId !== 'string'
    || typeof value.organizationId !== 'string'
    || typeof value.independenceDomain !== 'string'
    || typeof value.publicKey !== 'string'
  ) {
    fail('Q08_HOST_AUTHORITY_INVALID', `${label} is malformed`);
  }
  let key;
  try {
    key = createPublicKey(value.publicKey);
  } catch (error) {
    fail('Q08_HOST_AUTHORITY_INVALID', `${label} public key is invalid`, error);
  }
  if (
    key.asymmetricKeyType !== 'ed25519'
    || key.export({ format: 'pem', type: 'spki' }).toString()
      !== value.publicKey
  ) {
    fail(
      'Q08_HOST_AUTHORITY_INVALID',
      `${label} must use canonical Ed25519 SPKI PEM`,
    );
  }
  return Object.freeze({ ...value, key });
}

function statement(value) {
  plain(value, 'Q-08 host transcript statement');
  if (value.schema !== V2_Q08_HOST_STATEMENT_SCHEMA) {
    fail(
      'Q08_HOST_SCHEMA_INVALID',
      'Q-08 host transcript statement schema is unsupported',
    );
  }
  return value;
}

function signingBytes(role, statementBytes) {
  return Buffer.concat([
    Buffer.from(V2_Q08_HOST_SIGNATURE_DOMAIN, 'utf8'),
    Buffer.from(role, 'utf8'),
    Buffer.from([0]),
    statementBytes,
  ]);
}

function decodeSignature(value) {
  if (
    typeof value !== 'string'
    || value.length !== 88
    || !/^[A-Za-z0-9+/]{86}==$/.test(value)
  ) {
    fail(
      'Q08_HOST_SIGNATURE_INVALID',
      'Q-08 host signature must be canonical base64 for 64 bytes',
    );
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) {
    fail(
      'Q08_HOST_SIGNATURE_INVALID',
      'Q-08 host signature must be canonical base64 for 64 bytes',
    );
  }
  return bytes;
}

function parseCanonicalEnvelope(envelopeBytes) {
  if (!(envelopeBytes instanceof Uint8Array) || envelopeBytes.length === 0) {
    fail('Q08_HOST_SCHEMA_INVALID', 'Q-08 host envelope must be nonempty bytes');
  }
  let value;
  try {
    parseStrictJson(envelopeBytes);
    value = JSON.parse(Buffer.from(envelopeBytes).toString('utf8'));
  } catch (error) {
    fail('Q08_HOST_SCHEMA_INVALID', 'Q-08 host envelope is not strict JSON', error);
  }
  if (!Buffer.from(envelopeBytes).equals(canonicalBytes(value))) {
    fail(
      'Q08_HOST_SCHEMA_INVALID',
      'Q-08 host envelope must use exact RFC8785/JCS bytes',
    );
  }
  return value;
}

/**
 * Low-level signature constructor. It creates cryptographic evidence only and
 * never a Q-08 qualification result; release-root authorization is enforced
 * by the rooted wrapper below.
 */
export function createV2Q08HostSignatureEnvelope({
  authority: rawAuthority,
  privateKey,
  statement: rawStatement,
}) {
  const host = authority(rawAuthority, 'Q-08 host authority');
  const payload = statement(rawStatement);
  if (
    privateKey?.type !== 'private'
    || privateKey.asymmetricKeyType !== 'ed25519'
  ) {
    fail(
      'Q08_HOST_PRIVATE_KEY_INVALID',
      'Q-08 host private key must be an Ed25519 KeyObject',
    );
  }
  const derivedPublic = createPublicKey(privateKey)
    .export({ format: 'pem', type: 'spki' })
    .toString();
  if (derivedPublic !== host.publicKey) {
    fail(
      'Q08_HOST_PRIVATE_KEY_INVALID',
      'Q-08 host private key does not match its authority',
    );
  }
  const payloadBytes = canonicalBytes(payload);
  const signature = sign(
    null,
    signingBytes(host.role, payloadBytes),
    privateKey,
  );
  const envelope = Object.freeze({
    role: host.role,
    schema: V2_Q08_SIGNED_HOST_TRANSCRIPT_SCHEMA,
    signatureBase64: signature.toString('base64'),
    signerId: host.signerId,
    statement: payload,
    statementSha256: sha256(payloadBytes),
  });
  const bytes = canonicalBytes(envelope);
  return Object.freeze({
    bytes,
    envelope,
    envelopeSha256: sha256(bytes),
    qualification: false,
    scope: 'signature-envelope-only',
  });
}

/**
 * Low-level signature inspection. Authenticity against an arbitrary supplied
 * authority is not a release-root claim and always reports qualification false.
 */
export function inspectV2Q08HostSignatureEnvelope({
  authority: rawAuthority,
  envelopeBytes,
}) {
  const host = authority(rawAuthority, 'Q-08 host authority');
  const envelope = parseCanonicalEnvelope(envelopeBytes);
  exact(envelope, [
    'role',
    'schema',
    'signatureBase64',
    'signerId',
    'statement',
    'statementSha256',
  ], 'Q-08 signed host transcript');
  const payload = statement(envelope.statement);
  const payloadBytes = canonicalBytes(payload);
  if (
    envelope.schema !== V2_Q08_SIGNED_HOST_TRANSCRIPT_SCHEMA
    || envelope.role !== host.role
    || envelope.signerId !== host.signerId
    || typeof envelope.statementSha256 !== 'string'
    || !HASH.test(envelope.statementSha256)
    || envelope.statementSha256 !== sha256(payloadBytes)
    || !verify(
      null,
      signingBytes(host.role, payloadBytes),
      host.key,
      decodeSignature(envelope.signatureBase64),
    )
  ) {
    fail(
      'Q08_HOST_SIGNATURE_INVALID',
      'Q-08 signed host transcript is not authentic',
    );
  }
  return Object.freeze({
    authority: Object.freeze({
      role: host.role,
      signerId: host.signerId,
      organizationId: host.organizationId,
      independenceDomain: host.independenceDomain,
      publicKey: host.publicKey,
    }),
    envelopeSha256: sha256(Buffer.from(envelopeBytes)),
    qualification: false,
    scope: 'signature-inspection-only',
    statement: payload,
    statementSha256: envelope.statementSha256,
  });
}

function assertPrivateKeyFileMetadata(metadata, uid) {
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1n
    || metadata.size <= 0n
    || metadata.size > BigInt(MAX_PRIVATE_KEY_BYTES)
    || (metadata.mode & 0o7777n) !== 0o600n
    || (uid !== undefined && metadata.uid !== uid)
  ) {
    fail(
      'Q08_HOST_PRIVATE_KEY_INVALID',
      'Q-08 host private key must be one owner-held 0600 regular file',
    );
  }
}

function assertStablePrivateKeyMetadata(...metadata) {
  for (const entry of metadata) {
    for (const key of PRIVATE_KEY_STABLE_FIELDS) {
      if (entry[key] !== metadata[0][key]) {
        fail(
          'Q08_HOST_PRIVATE_KEY_CHANGED',
          'Q-08 host private key changed while it was read',
        );
      }
    }
  }
}

/**
 * Load a canonical Ed25519 key for signature construction only. This does not
 * authorize a release; release-root authorization remains in the wrapper.
 */
export async function loadV2Q08HostPrivateKeyForSignature(
  filename,
  expectedAuthority,
) {
  if (
    typeof filename !== 'string'
    || !path.isAbsolute(filename)
    || path.resolve(filename) !== filename
  ) {
    fail(
      'Q08_HOST_PRIVATE_KEY_INVALID',
      'Q-08 host private key path must be absolute and normalized',
    );
  }
  let pathMetadata;
  let canonical;
  try {
    pathMetadata = await lstat(filename, { bigint: true });
    canonical = await realpath(filename);
  } catch (error) {
    fail(
      'Q08_HOST_PRIVATE_KEY_INVALID',
      'Q-08 host private key file is unavailable',
      error,
    );
  }
  const uid = typeof process.getuid === 'function'
    ? BigInt(process.getuid())
    : undefined;
  if (canonical !== filename) {
    fail(
      'Q08_HOST_PRIVATE_KEY_INVALID',
      'Q-08 host private key must be one owner-held 0600 regular file',
    );
  }
  assertPrivateKeyFileMetadata(pathMetadata, uid);
  let handle;
  try {
    handle = await open(
      filename,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const before = await handle.stat({ bigint: true });
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const finalPath = await lstat(filename, { bigint: true });
    assertPrivateKeyFileMetadata(before, uid);
    assertPrivateKeyFileMetadata(after, uid);
    assertPrivateKeyFileMetadata(finalPath, uid);
    assertStablePrivateKeyMetadata(pathMetadata, before, after, finalPath);
    let key;
    try {
      key = createPrivateKey(bytes);
    } catch (error) {
      fail(
        'Q08_HOST_PRIVATE_KEY_INVALID',
        'Q-08 host private key is invalid',
        error,
      );
    }
    if (
      key.asymmetricKeyType !== 'ed25519'
      || key.export({ format: 'pem', type: 'pkcs8' }).toString()
        !== bytes.toString('utf8')
      || createPublicKey(key).export({ format: 'pem', type: 'spki' }).toString()
        !== expectedAuthority.publicKey
    ) {
      fail(
        'Q08_HOST_PRIVATE_KEY_INVALID',
        'Q-08 host private key is noncanonical or does not match its release authority',
      );
    }
    return key;
  } finally {
    await handle?.close();
  }
}

export async function signV2Q08HostTranscriptForRelease({
  privateKeyPath,
  releaseRoot,
  role,
  statement: rawStatement,
}) {
  const root = assertV2FinalReleaseRoot(releaseRoot);
  const host = root.cleanHosts.find((entry) => entry.role === role);
  if (host === undefined) {
    fail(
      'Q08_HOST_AUTHORITY_INVALID',
      'Q-08 host role is not approved by the release root',
    );
  }
  const privateKey = await loadV2Q08HostPrivateKeyForSignature(
    privateKeyPath,
    host,
  );
  return createV2Q08HostSignatureEnvelope({
    authority: host,
    privateKey,
    statement: rawStatement,
  });
}

export function verifyV2Q08HostTranscriptForRelease({
  envelopeBytes,
  releaseRoot,
}) {
  const root = assertV2FinalReleaseRoot(releaseRoot);
  const envelope = parseCanonicalEnvelope(envelopeBytes);
  const host = root.cleanHosts.find((entry) => entry.role === envelope.role);
  if (host === undefined) {
    fail(
      'Q08_HOST_AUTHORITY_INVALID',
      'Q-08 host role is not approved by the release root',
    );
  }
  return inspectV2Q08HostSignatureEnvelope({
    authority: host,
    envelopeBytes,
  });
}
