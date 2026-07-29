import { randomBytes as systemRandomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';

import {
  hash160,
  lockingBytecodeToCashAddress,
  secp256k1,
} from '@bitauth/libauth';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { createV2SecretFile } from '../../profile/v2/instance-descriptor.mjs';

export const V2_FUNDING_WALLET_SCHEMA =
  'shieldkit-v2-cli-funding-wallet-v1';
export const V2_FUNDING_WALLET_PROTOCOL = 'v2-direct';
export const V2_FUNDING_WALLET_NETWORK_ID = 2;

const PRIVATE_KEY_HEX = /^[0-9a-f]{64}$/;
const PUBLIC_KEY_HEX = /^(?:02|03)[0-9a-f]{64}$/;
const P2PKH_HEX = /^76a914[0-9a-f]{40}88ac$/;
const MAX_FUNDING_WALLET_BYTES = 4 * 1024;
const WALLET_KEYS = Object.freeze([
  'cashAddress',
  'compressedPublicKeyHex',
  'lockingBytecodeHex',
  'networkId',
  'privateKeyHex',
  'protocol',
  'schema',
]);

export class V2FundingWalletError extends Error {
  constructor(code, message, { cause = undefined } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2FundingWalletError';
    this.code = code;
  }
}

const fail = (code, message, options) => {
  throw new V2FundingWalletError(code, message, options);
};

function exactKeys(value, expected, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('FUNDING_WALLET_INVALID', `${label} must be a plain JSON object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail('FUNDING_WALLET_INVALID', `${label} has missing or unknown fields`);
  }
}

function isPrivateMode(stat) {
  return (stat.mode & 0o077) === 0;
}

function assertOwnedPrivate(
  stat,
  label,
  code = 'FUNDING_WALLET_UNSAFE_PATH',
) {
  if (
    stat.isSymbolicLink()
    || !isPrivateMode(stat)
    || (process.getuid !== undefined && stat.uid !== process.getuid())
  ) {
    fail(
      code,
      `${label} must be owner-controlled and inaccessible to group and other users`,
    );
  }
}

async function assertPrivateParent(filename) {
  if (
    typeof filename !== 'string'
    || !path.isAbsolute(filename)
    || path.normalize(filename) !== filename
    || filename.includes('\0')
  ) {
    fail(
      'FUNDING_WALLET_PATH_INVALID',
      'funding wallet filename must be a normalized absolute path',
    );
  }
  const parent = path.dirname(filename);
  let stat;
  try {
    stat = await lstat(parent);
  } catch (error) {
    fail(
      'FUNDING_WALLET_UNSAFE_PATH',
      'funding wallet parent directory is unavailable',
      { cause: error },
    );
  }
  if (!stat.isDirectory()) {
    fail('FUNDING_WALLET_UNSAFE_PATH', 'funding wallet parent must be a directory');
  }
  assertOwnedPrivate(stat, 'funding wallet parent directory');
  if (await realpath(parent) !== parent) {
    fail(
      'FUNDING_WALLET_UNSAFE_PATH',
      'funding wallet parent must not resolve through a symlink',
    );
  }
}

function p2pkhLockingBytecode(publicKey) {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(hash160(publicKey)),
    Buffer.from([0x88, 0xac]),
  ]);
}

function privateKeyFromHex(value, label) {
  if (typeof value !== 'string' || !PRIVATE_KEY_HEX.test(value)) {
    fail('FUNDING_WALLET_INVALID', `${label} must be exactly 32 lowercase hex bytes`);
  }
  const privateKey = Buffer.from(value, 'hex');
  if (secp256k1.validatePrivateKey(privateKey) !== true) {
    fail('FUNDING_WALLET_INVALID', `${label} is not a valid secp256k1 scalar`);
  }
  return privateKey;
}

function derivedWallet(privateKey) {
  const derived = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof derived === 'string') {
    fail(
      'FUNDING_WALLET_INTERNAL',
      'could not derive the funding public key',
    );
  }
  const compressedPublicKey = Buffer.from(derived);
  const lockingBytecode = p2pkhLockingBytecode(compressedPublicKey);
  const encoded = lockingBytecodeToCashAddress({
    bytecode: lockingBytecode,
    prefix: 'bchtest',
  });
  if (typeof encoded === 'string') {
    fail('FUNDING_WALLET_INTERNAL', 'could not encode Chipnet P2PKH address');
  }
  return Object.freeze({
    compressedPublicKeyHex: compressedPublicKey.toString('hex'),
    lockingBytecodeHex: lockingBytecode.toString('hex'),
    cashAddress: encoded.address,
  });
}

/**
 * Derive the canonical local Chipnet P2PKH funding wallet record. The returned
 * record includes its secret and is intended only for private-file persistence.
 */
export function deriveV2ChipnetFundingWallet({ privateKeyHex } = {}) {
  const privateKey = privateKeyFromHex(privateKeyHex, 'privateKeyHex');
  return Object.freeze({
    schema: V2_FUNDING_WALLET_SCHEMA,
    protocol: V2_FUNDING_WALLET_PROTOCOL,
    networkId: V2_FUNDING_WALLET_NETWORK_ID,
    privateKeyHex: privateKey.toString('hex'),
    ...derivedWallet(privateKey),
  });
}

/** Return a deliberately secret-free funding address projection. */
export function projectV2FundingWalletPublic(value) {
  const wallet = validateV2ChipnetFundingWallet(value);
  return Object.freeze({
    schema: wallet.schema,
    protocol: wallet.protocol,
    networkId: wallet.networkId,
    compressedPublicKeyHex: wallet.compressedPublicKeyHex,
    lockingBytecodeHex: wallet.lockingBytecodeHex,
    cashAddress: wallet.cashAddress,
  });
}

export function validateV2ChipnetFundingWallet(value) {
  exactKeys(value, WALLET_KEYS, 'funding wallet');
  if (
    value.schema !== V2_FUNDING_WALLET_SCHEMA
    || value.protocol !== V2_FUNDING_WALLET_PROTOCOL
    || value.networkId !== V2_FUNDING_WALLET_NETWORK_ID
  ) {
    fail('FUNDING_WALLET_INVALID', 'funding wallet schema, protocol, or network differs');
  }
  if (
    typeof value.compressedPublicKeyHex !== 'string'
    || !PUBLIC_KEY_HEX.test(value.compressedPublicKeyHex)
    || typeof value.lockingBytecodeHex !== 'string'
    || !P2PKH_HEX.test(value.lockingBytecodeHex)
    || typeof value.cashAddress !== 'string'
  ) {
    fail('FUNDING_WALLET_INVALID', 'funding wallet public fields are malformed');
  }
  const expected = deriveV2ChipnetFundingWallet({
    privateKeyHex: value.privateKeyHex,
  });
  if (
    expected.compressedPublicKeyHex !== value.compressedPublicKeyHex
    || expected.lockingBytecodeHex !== value.lockingBytecodeHex
    || expected.cashAddress !== value.cashAddress
  ) {
    fail('FUNDING_WALLET_INVALID', 'funding wallet public fields do not match its private key');
  }
  return expected;
}

async function readExactPrivateKeyFile(filename) {
  if (
    typeof filename !== 'string'
    || !path.isAbsolute(filename)
    || path.normalize(filename) !== filename
    || filename.includes('\0')
  ) {
    fail(
      'FUNDING_KEY_FILE_INVALID',
      'funding key file must be a normalized absolute path',
    );
  }
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile()) {
      fail('FUNDING_KEY_FILE_UNSAFE', 'funding key file must be a regular file');
    }
    if (stat.size !== 64) {
      fail(
        'FUNDING_KEY_FILE_INVALID',
        'funding key file must contain exactly 64 lowercase hexadecimal characters',
      );
    }
    assertOwnedPrivate(stat, 'funding key file', 'FUNDING_KEY_FILE_UNSAFE');
    if (await realpath(filename) !== filename) {
      fail(
        'FUNDING_KEY_FILE_UNSAFE',
        'funding key file must not resolve through a symlink',
      );
    }
    const bytes = await handle.readFile();
    if (bytes.length !== 64 || !PRIVATE_KEY_HEX.test(bytes.toString('utf8'))) {
      fail(
        'FUNDING_KEY_FILE_INVALID',
        'funding key file must contain exactly 64 lowercase hexadecimal characters',
      );
    }
    return bytes.toString('utf8');
  } catch (error) {
    if (error instanceof V2FundingWalletError) throw error;
    fail('FUNDING_KEY_FILE_UNSAFE', 'funding key file cannot be read safely', {
      cause: error,
    });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function persistWallet(filename, wallet) {
  await assertPrivateParent(filename);
  const bytes = Buffer.from(canonicalizeJcs(wallet), 'utf8');
  try {
    await createV2SecretFile(filename, bytes);
  } catch (error) {
    fail(
      error?.message === 'secret file already exists'
        ? 'FUNDING_WALLET_EXISTS'
        : 'FUNDING_WALLET_WRITE_FAILED',
      error instanceof Error ? error.message : 'funding wallet creation failed',
      { cause: error },
    );
  }
  const stat = await lstat(filename);
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || (stat.mode & 0o777) !== 0o600
    || await realpath(filename) !== filename
  ) {
    fail('FUNDING_WALLET_WRITE_FAILED', 'published funding wallet has unsafe metadata');
  }
  assertOwnedPrivate(stat, 'published funding wallet');
  return wallet;
}

export async function createV2ChipnetFundingWallet(
  { filename } = {},
  { randomBytes = systemRandomBytes } = {},
) {
  if (typeof randomBytes !== 'function') {
    fail('FUNDING_WALLET_CSPRNG_FAILURE', 'randomBytes must be a function');
  }
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    let candidate;
    try {
      candidate = randomBytes(32);
    } catch (error) {
      fail('FUNDING_WALLET_CSPRNG_FAILURE', 'CSPRNG failed', { cause: error });
    }
    if (!(candidate instanceof Uint8Array) || candidate.length !== 32) {
      fail('FUNDING_WALLET_CSPRNG_FAILURE', 'CSPRNG returned invalid bytes');
    }
    const privateKeyHex = Buffer.from(candidate).toString('hex');
    if (secp256k1.validatePrivateKey(Buffer.from(candidate)) !== true) continue;
    return persistWallet(filename, deriveV2ChipnetFundingWallet({ privateKeyHex }));
  }
  fail('FUNDING_WALLET_CSPRNG_FAILURE', 'CSPRNG did not produce a valid secp256k1 scalar');
}

export async function importV2ChipnetFundingWallet({
  filename,
  keyFile,
} = {}) {
  const privateKeyHex = await readExactPrivateKeyFile(keyFile);
  return persistWallet(
    filename,
    deriveV2ChipnetFundingWallet({ privateKeyHex }),
  );
}

export async function loadV2ChipnetFundingWallet({ filename } = {}) {
  if (
    typeof filename !== 'string'
    || !path.isAbsolute(filename)
    || path.normalize(filename) !== filename
    || filename.includes('\0')
  ) {
    fail(
      'FUNDING_WALLET_PATH_INVALID',
      'funding wallet filename must be a normalized absolute path',
    );
  }
  await assertPrivateParent(filename);
  let handle;
  try {
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (
      !stat.isFile()
      || stat.size === 0
      || stat.size > MAX_FUNDING_WALLET_BYTES
      || (stat.mode & 0o777) !== 0o600
      || await realpath(filename) !== filename
    ) {
      fail('FUNDING_WALLET_UNSAFE_PATH', 'funding wallet must be a regular 0600 file');
    }
    assertOwnedPrivate(stat, 'funding wallet');
    const bytes = await handle.readFile();
    let parsed;
    try {
      parsed = JSON.parse(bytes.toString('utf8'));
    } catch (error) {
      fail('FUNDING_WALLET_INVALID', 'funding wallet is not valid JSON', { cause: error });
    }
    if (Buffer.from(canonicalizeJcs(parsed), 'utf8').compare(bytes) !== 0) {
      fail('FUNDING_WALLET_INVALID', 'funding wallet must use canonical JCS JSON');
    }
    return validateV2ChipnetFundingWallet(parsed);
  } catch (error) {
    if (error instanceof V2FundingWalletError) throw error;
    fail('FUNDING_WALLET_UNSAFE_PATH', 'funding wallet cannot be read safely', {
      cause: error,
    });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}
