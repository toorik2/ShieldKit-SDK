import {
  createHash,
  hkdfSync,
} from 'node:crypto';

import { canonicalJson } from '../load.mjs';

export const BETA_SINGLE_CONTRIBUTOR_ENTROPY_SCHEMA =
  'shieldkit/beta-single-contributor-entropy/v1';

export class BetaSingleContributorEntropyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BetaSingleContributorEntropyError';
  }
}

const DICE_ROLLS = 100;
const OS_RANDOM_BYTES = 64;
const HASH = /^sha256:[0-9a-f]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const REQUEST_SCHEMA =
  'shieldkit/v2-beta-single-contributor-contribution-request/v1';
const MIX_SALT_DOMAIN = 'shieldkit/v2/beta/phase2/mix-salt/v1\0';
const PROMPT_INFO_DOMAIN = 'shieldkit/v2/beta/phase2/snarkjs-prompt/v1\0';
const COMMITMENT_DOMAIN = 'shieldkit/v2/beta/phase2/entropy-commitment/v1\0';
const REQUEST_HASH_DOMAIN = 'shieldkit/v2/beta/phase2/request/v1\0';
const HEX_ASCII = Buffer.from('0123456789abcdef', 'ascii');

const fail = (message) => {
  throw new BetaSingleContributorEntropyError(message);
};

const sha256 = (bytes) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function sha256Parts(...parts) {
  const hasher = createHash('sha256');
  for (const part of parts) {
    if (typeof part === 'string') hasher.update(part, 'utf8');
    else hasher.update(part);
  }
  return `sha256:${hasher.digest('hex')}`;
}

function exactKeys(value, label, keys) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function validateRequest(request) {
  exactKeys(request, 'request', [
    'ceremonyId',
    'previousZkeySha256',
    'ptauSha256',
    'r1csSha256',
    'schema',
    'sequence',
  ]);
  if (request.schema !== REQUEST_SCHEMA) fail('request schema is invalid');
  if (!ID.test(request.ceremonyId) || !/^[1-9][0-9]*$/.test(request.sequence)) {
    fail('request identity or sequence is invalid');
  }
  for (const field of ['r1csSha256', 'ptauSha256', 'previousZkeySha256']) {
    if (!HASH.test(request[field])) fail(`request ${field} is invalid`);
  }
}

function validateDice(dice) {
  if (!(dice instanceof Uint8Array)
    || dice.byteLength !== DICE_ROLLS
    || dice.some((byte) => byte < 0x31 || byte > 0x36)) {
    fail('dice must be exactly 100 ASCII bytes from 1 through 6');
  }
}

function validateOsRandomBytes(osRandomBytes) {
  if (!(osRandomBytes instanceof Uint8Array) || osRandomBytes.byteLength !== OS_RANDOM_BYTES) {
    fail('osRandomBytes must be exactly 64 bytes');
  }
}

function u32be(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

/**
 * Derive the newline-free text supplied to the snarkjs Phase-2 entropy prompt.
 *
 * This is deliberately pure: it neither obtains OS randomness nor writes, logs,
 * or transports secrets. The caller owns the dice string, OS random bytes, and
 * returned non-enumerable promptBytes; temporary byte buffers are cleared on
 * return where possible. The caller must clear promptBytes after child input.
 */
export function deriveBetaSingleContributorEntropy(input) {
  exactKeys(input, 'derivation input', [
    'dice',
    'osRandomBytes',
    'request',
  ]);
  const { dice, osRandomBytes, request } = input;
  validateDice(dice);
  validateOsRandomBytes(osRandomBytes);
  validateRequest(request);

  let requestBytes;
  let salt;
  let diceBytes;
  let osBytes;
  let diceLength;
  let osLength;
  let ikm;
  let info;
  let seed;
  try {
    requestBytes = Buffer.from(canonicalJson(request), 'utf8');
    salt = Buffer.from(sha256Bytes(MIX_SALT_DOMAIN, requestBytes));
    diceBytes = Buffer.from(dice);
    osBytes = Buffer.from(osRandomBytes);
    diceLength = u32be(DICE_ROLLS);
    osLength = u32be(OS_RANDOM_BYTES);
    ikm = Buffer.concat([diceLength, diceBytes, osLength, osBytes]);
    info = Buffer.alloc(Buffer.byteLength(PROMPT_INFO_DOMAIN, 'utf8') + requestBytes.length);
    info.write(PROMPT_INFO_DOMAIN, 'utf8');
    requestBytes.copy(info, Buffer.byteLength(PROMPT_INFO_DOMAIN, 'utf8'));
    seed = Buffer.from(hkdfSync('sha256', ikm, salt, info, 64));
    // Encode the secret seed without first materializing an immutable JS
    // string: unlike a string, this prompt buffer can be explicitly cleared.
    const promptBytes = Buffer.alloc(7 + (seed.length * 2));
    promptBytes.write('SKV2P2:', 0, 'ascii');
    for (let index = 0; index < seed.length; index += 1) {
      promptBytes[7 + (index * 2)] = HEX_ASCII[seed[index] >>> 4];
      promptBytes[8 + (index * 2)] = HEX_ASCII[seed[index] & 0x0f];
    }
    const requestSha256 = sha256Parts(REQUEST_HASH_DOMAIN, requestBytes);
    const entropyCommitment = sha256Parts(COMMITMENT_DOMAIN, salt, seed);
    const result = {
      schema: BETA_SINGLE_CONTRIBUTOR_ENTROPY_SCHEMA,
      entropyCommitment,
      requestSha256,
      saltSha256: sha256(salt),
    };
    // The prompt is secret process memory. Keep it out of JSON, Object.keys,
    // logs, and receipts while making ownership/zeroization explicit to the
    // local operator wrapper.
    Object.defineProperty(result, 'promptBytes', {
      enumerable: false,
      value: promptBytes,
      writable: false,
    });
    return Object.freeze(result);
  } finally {
    requestBytes?.fill(0);
    salt?.fill(0);
    diceBytes?.fill(0);
    osBytes?.fill(0);
    diceLength?.fill(0);
    osLength?.fill(0);
    ikm?.fill(0);
    info?.fill(0);
    seed?.fill(0);
  }
}

function sha256Bytes(domain, value) {
  return createHash('sha256')
    .update(domain, 'utf8')
    .update(value)
    .digest();
}
