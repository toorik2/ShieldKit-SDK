import { createHash } from 'node:crypto';

import { canonicalizeJcs } from './profile-core.mjs';

export const RECOVERY_SCANNER_ARTIFACT_SCHEMA =
  'shieldkit-v2-recovery-scanner-artifact-v1';
export const RECOVERY_SCANNER_MANIFEST_ARTIFACT_ID =
  'recovery-scanner-manifest';
export const RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID =
  'recovery-scanner-linux-x64';
export const RECOVERY_SCANNER_TARGET = 'linux-x64';
export const RECOVERY_SCANNER_LINUX_X64_FILENAME =
  'shieldkit-v2-recovery-scanner';
export const RECOVERY_SCANNER_MANIFEST_FILENAME =
  'shieldkit-v2-recovery-scanner.manifest.json';
export const V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS = Object.freeze([
  'shieldkit-v2-recovery-authenticate-snapshot-stream-input-v2',
  'shieldkit-v2-recovery-authenticate-snapshot-v2',
  'shieldkit-v2-recovery-authenticated-material-v2',
  'shieldkit-v2-recovery-scan-result-v2',
  'shieldkit-v2-recovery-scan-v2',
  'shieldkit-v2-recovery-snapshot-v2',
  'shieldkit-v2-recovery-stream-input-v2',
  'shieldkit-v2-recovery-stream-output-v2',
  'shieldkit-v2-recovery-verify-v2',
]);

const HASH = /^[0-9a-f]{64}$/;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export class V2RecoveryScannerArtifactError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2RecoveryScannerArtifactError';
  }
}

const fail = (message) => {
  throw new V2RecoveryScannerArtifactError(message);
};

function exactKeys(value, label, expected) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function version(value, prefix, label) {
  if (
    typeof value !== 'string'
    || !value.startsWith(prefix)
    || value.length > 256
    || !/^[\x20-\x7e]+$/.test(value)
  ) {
    fail(`${label} is not a canonical printable version`);
  }
  return value;
}

export function validateV2RecoveryScannerArtifact(value) {
  exactKeys(value, 'recovery scanner manifest', [
    'binaryArtifactId',
    'binaryBytes',
    'binarySha256',
    'cargoLockSha256',
    'cargoVersion',
    'eligibility',
    'protocolSchemas',
    'rustcVersion',
    'schema',
    'sourceRevision',
    'target',
  ]);
  if (value.schema !== RECOVERY_SCANNER_ARTIFACT_SCHEMA) {
    fail('recovery scanner manifest schema is unsupported');
  }
  if (
    value.target !== RECOVERY_SCANNER_TARGET
    || value.binaryArtifactId !== RECOVERY_SCANNER_LINUX_X64_ARTIFACT_ID
    || !Number.isSafeInteger(value.binaryBytes)
    || value.binaryBytes <= 0
    || value.binaryBytes > 0xffff_ffff
  ) {
    fail(
      'recovery scanner manifest requires target linux-x64, the canonical binaryArtifactId, and a valid byte count',
    );
  }
  if (
    typeof value.sourceRevision !== 'string'
    || !REVISION.test(value.sourceRevision)
    || /^0+$/.test(value.sourceRevision)
  ) {
    fail('recovery scanner source revision is not an exact Git object ID');
  }
  if (
    ![
      'clean-source-build',
      'dirty-source-development-only',
    ].includes(value.eligibility)
  ) {
    fail('recovery scanner eligibility is unsupported');
  }
  if (
    !Array.isArray(value.protocolSchemas)
    || value.protocolSchemas.length
      !== V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS.length
    || value.protocolSchemas.some(
      (entry, index) =>
        entry !== V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS[index],
    )
  ) {
    fail(
      'recovery scanner protocol schemas do not exactly match the V2 native ABI',
    );
  }
  return Object.freeze({
    schema: RECOVERY_SCANNER_ARTIFACT_SCHEMA,
    target: value.target,
    binaryArtifactId: value.binaryArtifactId,
    binarySha256: hash(
      value.binarySha256,
      'recovery scanner binarySha256',
    ),
    binaryBytes: value.binaryBytes,
    cargoLockSha256: hash(
      value.cargoLockSha256,
      'recovery scanner cargoLockSha256',
    ),
    sourceRevision: value.sourceRevision,
    eligibility: value.eligibility,
    rustcVersion: version(
      value.rustcVersion,
      'rustc ',
      'recovery scanner rustcVersion',
    ),
    cargoVersion: version(
      value.cargoVersion,
      'cargo ',
      'recovery scanner cargoVersion',
    ),
    protocolSchemas: V2_RECOVERY_SCANNER_PROTOCOL_SCHEMAS,
  });
}

export function parseV2RecoveryScannerArtifact(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    fail('recovery scanner manifest must be nonempty bytes');
  }
  const input = Buffer.from(bytes);
  let value;
  try {
    value = JSON.parse(input.toString('utf8'));
  } catch {
    fail('recovery scanner manifest is not JSON');
  }
  const canonicalBytes = Buffer.from(canonicalizeJcs(value), 'utf8');
  if (!input.equals(canonicalBytes)) {
    fail(
      'recovery scanner manifest must use exact RFC8785/JCS canonical bytes',
    );
  }
  return Object.freeze({
    manifest: validateV2RecoveryScannerArtifact(value),
    canonicalBytes,
    sha256: createHash('sha256').update(canonicalBytes).digest('hex'),
  });
}
