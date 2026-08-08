/**
 * Deterministic selection over an already authenticated wallet-UTXO
 * observation. This module deliberately has no transport or wallet-key
 * dependency: callers must obtain `utxos` from V2ChipnetChainClient and bind
 * the expected P2PKH locking bytecode from the local funding wallet.
 */

const HEX_32 = /^[0-9a-f]{64}$/;
const P2PKH = /^76a914[0-9a-f]{40}88ac$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;
const INPUT_KEYS = Object.freeze([
  'fundingLockingBytecodeHex',
  'requiredSats',
  'utxos',
]);
const INSPECTION_INPUT_KEYS = Object.freeze([
  'fundingLockingBytecodeHex',
  'utxos',
]);
const UTXO_KEYS = Object.freeze([
  'lockingBytecodeHex',
  'token',
  'txid',
  'valueSats',
  'vout',
]);

export class V2FundingUtxoSelectionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2FundingUtxoSelectionError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new V2FundingUtxoSelectionError(code, message);
};

function exactDataObject(value, expected, label, { frozen = false } = {}) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || (frozen && !Object.isFrozen(value))
  ) {
    fail('FUNDING_UTXO_OBSERVATION_INVALID', `${label} must be a ${frozen ? 'frozen ' : ''}plain object`);
  }
  const names = Object.getOwnPropertyNames(value).sort();
  const wanted = [...expected].sort();
  if (
    names.length !== wanted.length
    || names.some((key, index) => key !== wanted[index])
    || Object.getOwnPropertySymbols(value).length !== 0
  ) {
    fail('FUNDING_UTXO_OBSERVATION_INVALID', `${label} has missing or unknown fields`);
  }
  for (const key of wanted) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      !descriptor
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
    ) {
      fail('FUNDING_UTXO_OBSERVATION_INVALID', `${label}.${key} must be an enumerable data field`);
    }
  }
  return value;
}

function exactFrozenArray(value, label) {
  if (
    !Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || !Object.isFrozen(value)
    || Object.getOwnPropertySymbols(value).length !== 0
  ) {
    fail('FUNDING_UTXO_OBSERVATION_INVALID', `${label} must be a frozen ordinary array`);
  }
  const names = Object.getOwnPropertyNames(value).sort();
  const wanted = [
    'length',
    ...Array.from({ length: value.length }, (_, index) => String(index)),
  ].sort();
  if (
    names.length !== wanted.length
    || names.some((key, index) => key !== wanted[index])
  ) {
    fail('FUNDING_UTXO_OBSERVATION_INVALID', `${label} has holes or unknown properties`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      fail('FUNDING_UTXO_OBSERVATION_INVALID', `${label}[${index}] must be an enumerable data entry`);
    }
  }
  return value;
}

function canonicalSats(value, label, { positive = false } = {}) {
  if (
    typeof value !== 'string'
    || !DECIMAL.test(value)
    || BigInt(value) > MAX_MONEY_SATS
    || (positive && value === '0')
  ) {
    fail('FUNDING_UTXO_OBSERVATION_INVALID', `${label} must be a canonical ${positive ? 'positive ' : ''}BCH satoshi amount`);
  }
  return BigInt(value);
}

function parseExpectedLock(value) {
  if (typeof value !== 'string' || !P2PKH.test(value)) {
    fail('FUNDING_UTXO_OBSERVATION_INVALID', 'fundingLockingBytecodeHex must be canonical lowercase P2PKH bytecode');
  }
  return value;
}

function parseUtxo(value, expectedLock, index) {
  exactDataObject(value, UTXO_KEYS, `utxos[${index}]`, { frozen: true });
  if (
    typeof value.txid !== 'string'
    || !HEX_32.test(value.txid)
    || !Number.isSafeInteger(value.vout)
    || value.vout < 0
    || value.vout > 0xffff_ffff
    || typeof value.lockingBytecodeHex !== 'string'
    || !P2PKH.test(value.lockingBytecodeHex)
    || value.lockingBytecodeHex !== expectedLock
    || value.token !== null
  ) {
    fail('FUNDING_UTXO_OBSERVATION_INVALID', `utxos[${index}] is not an exact tokenless output for the requested funding P2PKH lock`);
  }
  const valueSats = canonicalSats(value.valueSats, `utxos[${index}].valueSats`);
  return Object.freeze({
    lockingBytecodeHex: expectedLock,
    token: null,
    txid: value.txid,
    valueSats: value.valueSats,
    value: valueSats,
    vout: value.vout,
  });
}

function compareUtxos(left, right) {
  if (left.value < right.value) return -1;
  if (left.value > right.value) return 1;
  if (left.txid < right.txid) return -1;
  if (left.txid > right.txid) return 1;
  return left.vout - right.vout;
}

function publicUtxo(parsed) {
  return Object.freeze({
    lockingBytecodeHex: parsed.lockingBytecodeHex,
    token: null,
    txid: parsed.txid,
    valueSats: parsed.valueSats,
    vout: parsed.vout,
  });
}

/**
 * Strictly validate an authenticated wallet-UTXO observation and return a
 * canonical, immutable ordering. The input may arrive in arbitrary provider
 * order; callers must use this result for every subsequent funding decision.
 */
export function inspectV2FundingUtxos(value = {}) {
  exactDataObject(value, INSPECTION_INPUT_KEYS, 'funding UTXO inspection request');
  const expectedLock = parseExpectedLock(value.fundingLockingBytecodeHex);
  const utxos = exactFrozenArray(value.utxos, 'utxos');
  const seen = new Set();
  const inspected = [];
  for (let index = 0; index < utxos.length; index += 1) {
    const parsed = parseUtxo(utxos[index], expectedLock, index);
    const outpoint = `${parsed.txid}:${parsed.vout}`;
    if (seen.has(outpoint)) {
      fail('FUNDING_UTXO_OBSERVATION_INVALID', 'utxos contains a duplicate outpoint');
    }
    seen.add(outpoint);
    inspected.push(parsed);
  }
  inspected.sort(compareUtxos);
  return Object.freeze(inspected.map(publicUtxo));
}

/**
 * Select exactly one authenticated tokenless P2PKH funding UTXO. Every entry
 * is checked even when an earlier entry is sufficient: a malformed partial
 * observation must never be silently ignored.
 */
export function selectV2FundingUtxo(value = {}) {
  exactDataObject(value, INPUT_KEYS, 'funding UTXO selection request');
  const required = canonicalSats(value.requiredSats, 'requiredSats', { positive: true });
  const inspected = inspectV2FundingUtxos({
    fundingLockingBytecodeHex: value.fundingLockingBytecodeHex,
    utxos: value.utxos,
  });
  const sufficient = inspected.filter((utxo) => BigInt(utxo.valueSats) >= required);
  if (sufficient.length === 0) {
    fail('FUNDING_UTXO_INSUFFICIENT', 'no single authenticated funding UTXO meets requiredSats');
  }
  const selected = sufficient[0];
  return publicUtxo(selected);
}
