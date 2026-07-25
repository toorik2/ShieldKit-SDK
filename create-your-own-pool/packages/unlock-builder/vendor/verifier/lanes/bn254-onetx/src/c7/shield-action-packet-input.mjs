import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute } from 'node:path';

export const SHIELD_ACTION_PACKET_BYTES = 752;
export const SHIELD_ACTION_PACKET_DIGEST_BYTES = 32;
export const SHIELD_ACTION_PACKET_PUSH_HEADER = Uint8Array.from([0x4d, 0xf0, 0x02]);
export const SHIELD_PROJECTION_SIGNAL_BYTES = 480;
export const SHIELD_PROJECTION_SIGNAL_PUSH_HEADER = Uint8Array.from([0x4d, 0xe0, 0x01]);

const SHA256 = /^[0-9a-f]{64}$/;
const SCAR = Uint8Array.from([0x53, 0x43, 0x41, 0x52]);
const fail = (message) => { throw new Error(`shield action packet input: ${message}`); };

export const sha256Bytes = (bytes) => createHash('sha256').update(bytes).digest();

export const actionDigestPublicInputs = (digest) => {
  if (!(digest instanceof Uint8Array) || digest.length !== SHIELD_ACTION_PACKET_DIGEST_BYTES) {
    fail(`digest must be exactly ${SHIELD_ACTION_PACKET_DIGEST_BYTES} bytes`);
  }
  return Object.freeze([
    BigInt(`0x${Buffer.from(digest.slice(0, 16)).toString('hex')}`),
    BigInt(`0x${Buffer.from(digest.slice(16, 32)).toString('hex')}`),
  ]);
};

export const assertActionDigestPublicInputs = (digest, publicInputs) => {
  if (!Array.isArray(publicInputs) || publicInputs.length !== 2) {
    fail('adapter must supply exactly two public inputs');
  }
  const observed = actionDigestPublicInputs(digest);
  const expected = publicInputs.map(BigInt);
  if (observed[0] !== expected[0] || observed[1] !== expected[1]) {
    fail(`digest limbs do not match adapter public inputs: packet=${observed.join(',')} adapter=${expected.join(',')}`);
  }
  return observed;
};

/**
 * Load one exact, immutable shield.cash SCAR action packet.
 *
 * This is build-time provenance only. Consumers must not embed the packet,
 * digest, or derived public inputs in verifier source locking bytecode.
 */
export const loadPinnedShieldActionPacket = ({ path, sha256 }) => {
  if (typeof path !== 'string' || !isAbsolute(path)) fail('path must be absolute');
  if (typeof sha256 !== 'string' || !SHA256.test(sha256)) fail('sha256 must be lowercase 64-hex');

  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink()) fail('path must name a regular non-symlink file');
  if (realpathSync(path) !== path) fail('path must be canonical and must not resolve through a symlink');

  const bytes = readFileSync(path);
  const after = lstatSync(path);
  if (!after.isFile() || after.isSymbolicLink()
      || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) {
    fail('file changed while reading');
  }
  if (bytes.length !== SHIELD_ACTION_PACKET_BYTES) {
    fail(`packet must be exactly ${SHIELD_ACTION_PACKET_BYTES} bytes, got ${bytes.length}`);
  }
  if (!bytes.subarray(0, SCAR.length).every((value, index) => value === SCAR[index])) {
    fail('packet must begin with the canonical SCAR domain');
  }
  const digest = sha256Bytes(bytes);
  const observed = Buffer.from(digest).toString('hex');
  if (observed !== sha256) fail(`SHA256 mismatch: expected ${sha256}, observed ${observed}`);

  return Object.freeze({
    bytes: Uint8Array.from(bytes),
    digest: Uint8Array.from(digest),
    sha256: observed,
  });
};
