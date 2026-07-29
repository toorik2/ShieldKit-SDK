import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute } from 'node:path';

export const SHIELD_DIRECT_V2_PACKET_BYTES = 552;
export const SHIELD_DIRECT_V2_PACKET_DIGEST_BYTES = 32;
export const SHIELD_DIRECT_V2_PACKET_PUSH_HEADER =
  Uint8Array.from([0x4d, 0x28, 0x02]);

const SHA256 = /^[0-9a-f]{64}$/;
const SDA2 = Uint8Array.from([0x53, 0x44, 0x41, 0x32]);
const fail = (message) => {
  throw new Error(`ShieldKit V2 Direct packet input: ${message}`);
};

export const sha256DirectV2Packet = (bytes) =>
  createHash('sha256').update(bytes).digest();

export const directV2PacketPublicInputs = (digest) => {
  if (
    !(digest instanceof Uint8Array)
    || digest.length !== SHIELD_DIRECT_V2_PACKET_DIGEST_BYTES
  ) {
    fail(
      `digest must be exactly ${SHIELD_DIRECT_V2_PACKET_DIGEST_BYTES} bytes`,
    );
  }
  return Object.freeze([
    BigInt(`0x${Buffer.from(digest.subarray(0, 16)).toString('hex')}`),
    BigInt(`0x${Buffer.from(digest.subarray(16, 32)).toString('hex')}`),
  ]);
};

export const assertDirectV2PacketPublicInputs = (digest, publicInputs) => {
  if (!Array.isArray(publicInputs) || publicInputs.length !== 2) {
    fail('adapter must supply exactly two public inputs');
  }
  const observed = directV2PacketPublicInputs(digest);
  let expected;
  try {
    expected = publicInputs.map(BigInt);
  } catch {
    fail('adapter public inputs must be canonical integers');
  }
  if (observed[0] !== expected[0] || observed[1] !== expected[1]) {
    fail(
      `digest limbs do not match adapter public inputs: packet=${observed.join(',')} adapter=${expected.join(',')}`,
    );
  }
  return observed;
};

/**
 * Load one exact immutable 552-byte SDA2 packet. This entrypoint deliberately
 * accepts no legacy packet ABI: callers must select V2 Direct explicitly.
 */
export const loadPinnedShieldDirectV2Packet = ({ path, sha256 }) => {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    fail('path must be absolute');
  }
  if (typeof sha256 !== 'string' || !SHA256.test(sha256)) {
    fail('sha256 must be lowercase 64-hex');
  }

  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink()) {
    fail('path must name a regular non-symlink file');
  }
  if (realpathSync(path) !== path) {
    fail('path must be canonical and must not resolve through a symlink');
  }

  const bytes = readFileSync(path);
  const after = lstatSync(path);
  if (
    !after.isFile()
    || after.isSymbolicLink()
    || after.dev !== before.dev
    || after.ino !== before.ino
    || after.size !== before.size
  ) {
    fail('file changed while reading');
  }
  if (bytes.length !== SHIELD_DIRECT_V2_PACKET_BYTES) {
    fail(
      `packet must be exactly ${SHIELD_DIRECT_V2_PACKET_BYTES} bytes, got ${bytes.length}`,
    );
  }
  if (!SDA2.every((value, index) => bytes[index] === value)) {
    fail('packet must begin with the canonical SDA2 domain');
  }

  const digest = sha256DirectV2Packet(bytes);
  const observed = Buffer.from(digest).toString('hex');
  if (observed !== sha256) {
    fail(`SHA256 mismatch: expected ${sha256}, observed ${observed}`);
  }
  return Object.freeze({
    bytes: Uint8Array.from(bytes),
    digest: Uint8Array.from(digest),
    sha256: observed,
  });
};
