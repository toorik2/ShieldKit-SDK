import { createHash } from 'node:crypto';

export const MAX_MONEY_SATS = 2_100_000_000_000_000n;
export const DENOMINATION_SATS = '10000000';
export const PROFILE_CORE_SCHEMA = 'shieldkit-profile-core-v2-direct';
export const PROFILE_ID_PREFIX = 'SKP2';

const HASH = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const IDENTIFIER = /^[a-z][a-z0-9-]*$/;
const DOMAIN_HEX = Object.freeze({
  ADDRESS: '174c18c76e6b8e7e9035476f0419293d25aabb87220e613924e58345d11914df',
  RHO: '0d166c9d3f0e891e85bb4a502a6ec7303938d7bfc56f1b6e6e443fa8793f8a82',
  NOTE: '194fd66837e146a0a8dddfcc309eb8bc1a51deb31924e089b8960ae102c7c349',
  NULLIFIER: '23358847ffca5391ad471ef321c12099073bff6145a867d14700e8e976377460',
  RECORD_MASK_RHO: '0ddef22b3c03788145c0aed1bfba5a211f13466c813c0a5d9ed2e92ab173f966',
  RECORD_MASK_R: '1af24bc8a85aa4b05369756d4f60843ff6dc26f886999d215ed61e38a4ae2db0',
  RECORD_TAG: '03db9f4bbae24de0b96466001641dc5753651feaa55a8541ededbcaf2bb2da7e',
  NOTE_LEAF: '0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a',
  NOTE_TREE_EMPTY: '28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad',
  NOTE_TREE_NODE: '06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153',
  NULLIFIER_TREE_LEAF: '21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2',
  NULLIFIER_TREE_EMPTY: '2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb',
  NULLIFIER_TREE_NODE: '241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4',
});

export const V2_PROFILE_DOMAINS = DOMAIN_HEX;

export class ProfileCoreError extends Error {
  constructor(message) { super(message); this.name = 'ProfileCoreError'; }
}

const fail = (message) => { throw new ProfileCoreError(message); };

function validUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!Number.isInteger(next) || next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function dataProperties(value, label) {
  if (Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain JSON object`);
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) fail(`${label} must not contain symbol properties`);
  for (const name of names) {
    if (!validUnicode(name)) fail(`${label} has invalid Unicode property name`);
    if (name === 'toJSON') fail(`${label} must not contain toJSON`);
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail(`${label} must contain enumerable data properties only`);
  }
  return names;
}

function arrayValues(value, label) {
  if (Object.getPrototypeOf(value) !== Array.prototype) fail(`${label} must be a JSON array`);
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) fail(`${label} must not contain symbol properties`);
  if (names.length !== value.length + 1 || !names.includes('length')) fail(`${label} must be dense without extra properties`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) fail(`${label} must contain data elements only`);
  }
  return value;
}

/** RFC 8785 JSON Canonicalization Scheme for validated JSON data. */
export function canonicalizeJcs(value) {
  const visit = (current, label) => {
    if (current === null) return 'null';
    if (typeof current === 'string') {
      if (!validUnicode(current)) fail(`${label} contains invalid Unicode`);
      return JSON.stringify(current);
    }
    if (typeof current === 'boolean') return current ? 'true' : 'false';
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) fail(`${label} must be a finite JSON number`);
      return JSON.stringify(current);
    }
    if (Array.isArray(current)) return `[${arrayValues(current, label).map((entry, index) => visit(entry, `${label}[${index}]`)).join(',')}]`;
    if (typeof current !== 'object') fail(`${label} must be JSON data`);
    const keys = dataProperties(current, label).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${visit(current[key], `${label}.${key}`)}`).join(',')}}`;
  };
  return visit(value, 'value');
}

function exactKeys(value, label, keys) {
  const actual = dataProperties(value, label).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
}

function string(value, label) {
  if (typeof value !== 'string' || !validUnicode(value)) fail(`${label} must be valid Unicode string`);
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be lowercase SHA-256 hex without prefix`);
}

function identifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) fail(`${label} must be a canonical identifier`);
}

function sortedUnique(values, key, label) {
  if (!Array.isArray(values) || values.length === 0) fail(`${label} must be a nonempty array`);
  let previous;
  for (const entry of values) {
    const current = entry[key];
    if (previous !== undefined && previous >= current) fail(`${label} must be strictly ${key}-sorted without duplicates`);
    previous = current;
  }
}

function validateNetwork(value) {
  exactKeys(value, 'network', ['id', 'name']);
  if (!Number.isInteger(value.id) || !((value.id === 1 && value.name === 'mainnet') || (value.id === 2 && value.name === 'chipnet'))) {
    fail('network must pair 1/mainnet or 2/chipnet');
  }
}

function validateTrees(value) {
  exactKeys(value, 'trees', ['note', 'nullifier']);
  for (const [name, id] of [['note', 'shieldkit-note-tree-v2-depth32'], ['nullifier', 'shieldkit-indexed-nullifier-tree-v2-depth32']]) {
    const tree = value[name]; exactKeys(tree, `trees.${name}`, ['depth', 'id', 'leafSchemaId']);
    if (tree.id !== id || tree.depth !== 32) fail(`trees.${name} must use pinned id and depth 32`);
    identifier(tree.leafSchemaId, `trees.${name}.leafSchemaId`);
  }
}

function validateCrypto(value) {
  exactKeys(value, 'crypto', ['babyJubCurveId', 'domains', 'poseidonId']);
  if (value.babyJubCurveId !== 'circomlib-babyjub-base8' || value.poseidonId !== 'circomlib-poseidon-bn254') fail('crypto uses unsupported pinned identifiers');
  exactKeys(value.domains, 'crypto.domains', Object.keys(DOMAIN_HEX));
  for (const [label, expected] of Object.entries(DOMAIN_HEX)) if (value.domains[label] !== expected) fail(`crypto.domains.${label} differs from pinned value`);
}

function validateEncodings(value) {
  exactKeys(value, 'encodings', ['address', 'packet', 'record', 'state', 'unlock']);
  const pinned = {
    state: 'shieldkit-pool-state-sks2-native128', packet: 'shieldkit-direct-action-sda2-552',
    address: 'shieldkit-address-v2-direct', record: 'shieldkit-note-record-v2-direct-128',
    unlock: 'shieldkit-rolling-bundle-unlock-v2-direct',
  };
  for (const [key, expected] of Object.entries(pinned)) if (value[key] !== expected) fail(`encodings.${key} differs from pinned id`);
}

function validateArtifacts(value) {
  if (!Array.isArray(value)) fail('baseVerifierArtifacts must be an array');
  for (const entry of value) { exactKeys(entry, 'baseVerifierArtifacts entry', ['id', 'sha256']); identifier(entry.id, 'baseVerifierArtifacts.id'); hash(entry.sha256, 'baseVerifierArtifacts.sha256'); }
  sortedUnique(value, 'id', 'baseVerifierArtifacts');
}

function validateToolchain(value) {
  if (!Array.isArray(value)) fail('toolchain must be an array');
  for (const entry of value) { exactKeys(entry, 'toolchain entry', ['name', 'sha256', 'version']); identifier(entry.name, 'toolchain.name'); string(entry.version, 'toolchain.version'); if (entry.version.length === 0) fail('toolchain.version must be nonempty'); hash(entry.sha256, 'toolchain.sha256'); }
  sortedUnique(value, 'name', 'toolchain');
}

/** Validate the complete, hash-cycle-free V2 Direct profile core. */
export function validateProfileCore(value) {
  canonicalizeJcs(value);
  exactKeys(value, 'profile core', ['baseVerifierArtifacts', 'crypto', 'denominationSats', 'encodings', 'network', 'proof', 'publicInputAbi', 'schema', 'toolchain', 'trees']);
  if (value.schema !== PROFILE_CORE_SCHEMA) fail('profile core schema is unsupported');
  validateNetwork(value.network);
  if (typeof value.denominationSats !== 'string' || !DECIMAL.test(value.denominationSats) || value.denominationSats !== DENOMINATION_SATS) fail(`denominationSats must equal relation-pinned ${DENOMINATION_SATS} sats`);
  exactKeys(value.proof, 'proof', ['curve', 'r1csSha256', 'relationId', 'relationSha256', 'system', 'verificationKeySha256', 'witnessWasmSha256']);
  if (value.proof.system !== 'groth16' || value.proof.curve !== 'bn254' || value.proof.relationId !== 'shieldkit-pool-action-v2-direct') fail('proof uses unsupported pinned identifiers');
  for (const key of ['relationSha256', 'r1csSha256', 'verificationKeySha256', 'witnessWasmSha256']) hash(value.proof[key], `proof.${key}`);
  validateTrees(value.trees); validateCrypto(value.crypto); validateEncodings(value.encodings);
  exactKeys(value.publicInputAbi, 'publicInputAbi', ['count', 'digest', 'id', 'limbBits']);
  if (value.publicInputAbi.id !== 'shieldkit-sda2-sha256-be-u128x2' || value.publicInputAbi.count !== 2 || value.publicInputAbi.limbBits !== 128 || value.publicInputAbi.digest !== 'sha256') fail('publicInputAbi differs from pinned ABI');
  validateArtifacts(value.baseVerifierArtifacts); validateToolchain(value.toolchain);
  return value;
}

export function deriveProfileId(profileCore) {
  validateProfileCore(profileCore);
  return createHash('sha256').update(PROFILE_ID_PREFIX, 'ascii').update(canonicalizeJcs(profileCore), 'utf8').digest('hex');
}
