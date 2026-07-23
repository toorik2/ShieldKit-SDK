import { createHash } from 'node:crypto';

export const PF7_CARRIER_SOURCE_ENCODING = 'libauth-transaction-outputs-v1';
export const PF7_CARRIER_ROLES = Object.freeze([
  'exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal',
]);

const HASH_ID = /^sha256:[0-9a-f]{64}$/;
const LOWER_HEX = /^(?:[0-9a-f]{2})+$/;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export class Pf7AuthorityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'Pf7AuthorityError';
  }
}

const fail = (message) => {
  throw new Pf7AuthorityError(message);
};

const exactKeys = (value, label, keys) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
};

const sha256 = (value) => createHash('sha256').update(value).digest();
const sha256d = (value) => sha256(sha256(value));

function parseCarrier(script, index) {
  exactKeys(
    script,
    `PF7 carrier ${index}`,
    ['lockingBytecodeHex', 'name', 'redeemBytecodeHex', 'sourceValueSatoshis'],
  );
  if (script.name !== PF7_CARRIER_ROLES[index]) {
    fail(`PF7 carrier ${index} has the wrong role`);
  }
  if (
    typeof script.lockingBytecodeHex !== 'string'
    || !LOWER_HEX.test(script.lockingBytecodeHex)
  ) {
    fail(`PF7 carrier ${index} locking bytecode must be canonical lowercase hex`);
  }
  if (
    typeof script.redeemBytecodeHex !== 'string'
    || !LOWER_HEX.test(script.redeemBytecodeHex)
  ) {
    fail(`PF7 carrier ${index} redeem bytecode must be canonical lowercase hex`);
  }
  const lockingBytecode = Buffer.from(script.lockingBytecodeHex, 'hex');
  const redeemBytecode = Buffer.from(script.redeemBytecodeHex, 'hex');
  if (
    lockingBytecode.length !== 35
    || lockingBytecode[0] !== 0xaa
    || lockingBytecode[1] !== 0x20
    || lockingBytecode[34] !== 0x87
    || !sha256d(redeemBytecode).equals(lockingBytecode.subarray(2, 34))
  ) {
    fail(`PF7 carrier ${index} is not an exact P2SH32 source/redeem pair`);
  }
  if (
    typeof script.sourceValueSatoshis !== 'string'
    || !/^[1-9][0-9]*$/.test(script.sourceValueSatoshis)
  ) {
    fail(`PF7 carrier ${index} value must be a canonical positive decimal u64`);
  }
  const valueSatoshis = BigInt(script.sourceValueSatoshis);
  if (valueSatoshis > MAX_U64) {
    fail(`PF7 carrier ${index} value exceeds u64`);
  }
  return Object.freeze({
    role: script.name,
    lockingBytecode,
    redeemBytecode,
    valueSatoshis,
  });
}

/**
 * Serialize the exact tokenless PF7 carrier authority:
 * CompactSize(7) || (u64le(value) || CompactSize(35) || P2SH32) * 7.
 */
export function encodeCanonicalPf7CarrierSourceSet(carriers) {
  if (!Array.isArray(carriers) || carriers.length !== PF7_CARRIER_ROLES.length) {
    fail('PF7 carrier authority must contain exactly seven roles');
  }
  const outputs = carriers.map((carrier, index) => {
    const parsed = Object.hasOwn(carrier, 'role')
      ? carrier
      : parseCarrier(carrier, index);
    if (
      parsed.role !== PF7_CARRIER_ROLES[index]
      || typeof parsed.valueSatoshis !== 'bigint'
      || parsed.valueSatoshis <= 0n
      || parsed.valueSatoshis > MAX_U64
      || !(parsed.lockingBytecode instanceof Uint8Array)
      || parsed.lockingBytecode.length !== 35
    ) {
      fail(`PF7 carrier ${index} cannot be canonically serialized`);
    }
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(parsed.valueSatoshis);
    return Buffer.concat([value, Buffer.of(35), Buffer.from(parsed.lockingBytecode)]);
  });
  return Buffer.concat([Buffer.of(PF7_CARRIER_ROLES.length), ...outputs]);
}

/**
 * Validate and independently authenticate a profile's seven PF7 carriers.
 * Full ten-output verifier context artifacts are deliberately outside this
 * authority; only the canonical seven tokenless outputs are hashed here.
 */
export function parsePf7CarrierAuthority(record) {
  if (record === null || Array.isArray(record) || typeof record !== 'object') {
    fail('PF7 verifier-set artifact must be an object');
  }
  if (record.schema !== 'shield.cash/bch-verifier-set/v1') {
    fail('PF7 verifier-set schema is unsupported');
  }
  exactKeys(
    record.sourceSet,
    'PF7 sourceSet',
    ['carrierCount', 'encoding', 'sha256'],
  );
  if (
    record.sourceSet.encoding !== PF7_CARRIER_SOURCE_ENCODING
    || record.sourceSet.carrierCount !== PF7_CARRIER_ROLES.length
    || typeof record.sourceSet.sha256 !== 'string'
    || !HASH_ID.test(record.sourceSet.sha256)
  ) {
    fail('PF7 sourceSet authority is malformed');
  }
  if (!Array.isArray(record.scripts) || record.scripts.length !== PF7_CARRIER_ROLES.length) {
    fail('PF7 verifier-set must contain exactly seven carrier scripts');
  }
  const carriers = Object.freeze(record.scripts.map(parseCarrier));
  const serialization = encodeCanonicalPf7CarrierSourceSet(carriers);
  const sha256Identifier = `sha256:${sha256(serialization).toString('hex')}`;
  if (sha256Identifier !== record.sourceSet.sha256) {
    fail('PF7 sourceSet hash does not match canonical carrier outputs');
  }
  return Object.freeze({
    carriers,
    serialization,
    sha256: sha256Identifier,
  });
}
