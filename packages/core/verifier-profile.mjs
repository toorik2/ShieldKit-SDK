import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

const HASH = /^sha256:[0-9a-f]{64}$/;
const LABEL = /^[a-z0-9][a-z0-9._-]*$/;
const REQUIRED_ARTIFACT_KINDS = new Set([
  'relation-definition', 'constraint-system', 'public-input-abi',
  'verification-key', 'proving-key', 'witness-generator', 'bch-verifier-set',
]);
const ARTIFACT_KINDS = new Set([...REQUIRED_ARTIFACT_KINDS, 'ceremony-transcript']);
const PROFILE_MATERIAL_KEYS = ['artifacts', 'network', 'profile', 'setup', 'standard', 'toolchain'];
const DENOMINATION_SATOSHIS = 10_000_000n;
const MAX_BCH_SUPPLY_SATOSHIS = 2_100_000_000_000_000n;

export class BundleValidationError extends Error {
  constructor(message) { super(message); this.name = 'BundleValidationError'; }
}

const fail = (message) => { throw new BundleValidationError(message); };
const object = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  return value;
};
const string = (value, label) => {
  if (typeof value !== 'string') fail(`${label} must be a string`);
  return value;
};
const hash = (value, label) => {
  string(value, label);
  if (!HASH.test(value)) fail(`${label} must be a lowercase sha256 identifier`);
  return value;
};
const exactKeys = (value, label, keys) => {
  object(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    fail(`${label} has missing or unknown properties`);
  }
};
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const MAX_MANIFEST_BYTES = 1024 * 1024;

async function hashFile(file) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(file)) digest.update(chunk);
  return `sha256:${digest.digest('hex')}`;
}

function compareDecimalSequence(left, right) {
  if (left.length !== right.length) return left.length - right.length;
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Strict JSON parser: rejects duplicate object names before canonicalization. */
export function parseStrictJson(bytes) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { fail('manifest is not valid UTF-8'); }
  if (text.charCodeAt(0) === 0xfeff) fail('manifest must not contain a UTF-8 BOM');
  let index = 0;
  const whitespace = () => { while (/[\u0009\u000a\u000d\u0020]/.test(text[index] ?? '')) index += 1; };
  const token = (source) => {
    if (text.slice(index, index + source.length) !== source) fail(`invalid JSON at byte ${index}`);
    index += source.length;
  };
  const value = () => {
    whitespace();
    const c = text[index];
    if (c === '{') return dictionary();
    if (c === '[') return array();
    if (c === '"') return quoted();
    if (c === 't') { token('true'); return true; }
    if (c === 'f') { token('false'); return false; }
    if (c === 'n') { token('null'); return null; }
    if (c === '-' || /[0-9]/.test(c ?? '')) return number();
    fail(`invalid JSON at byte ${index}`);
  };
  const quoted = () => {
    const start = index++;
    let escaped = false;
    while (index < text.length) {
      const c = text[index++];
      if (!escaped && c === '"') {
        const source = text.slice(start, index);
        try { return JSON.parse(source); } catch { fail(`invalid JSON string at byte ${start}`); }
      }
      if (!escaped && c.charCodeAt(0) < 0x20) fail(`control character in JSON string at byte ${index - 1}`);
      escaped = !escaped && c === '\\';
      if (escaped && c !== '\\') escaped = false;
    }
    fail(`unterminated JSON string at byte ${start}`);
  };
  const number = () => {
    const start = index;
    const match = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) fail(`invalid JSON number at byte ${index}`);
    index += match[0].length;
    const parsed = Number(match[0]);
    if (!Number.isFinite(parsed)) fail(`non-finite JSON number at byte ${start}`);
    return parsed;
  };
  const array = () => {
    index += 1; whitespace();
    const result = [];
    if (text[index] === ']') { index += 1; return result; }
    while (true) {
      result.push(value()); whitespace();
      if (text[index] === ']') { index += 1; return result; }
      if (text[index] !== ',') fail(`expected comma in array at byte ${index}`);
      index += 1;
    }
  };
  const dictionary = () => {
    index += 1; whitespace();
    const result = Object.create(null); const names = new Set();
    if (text[index] === '}') { index += 1; return result; }
    while (true) {
      whitespace();
      if (text[index] !== '"') fail(`expected object name at byte ${index}`);
      const name = quoted();
      if (names.has(name)) fail(`duplicate JSON object name: ${name}`);
      names.add(name); whitespace();
      if (text[index] !== ':') fail(`expected colon at byte ${index}`);
      index += 1; result[name] = value(); whitespace();
      if (text[index] === '}') { index += 1; return result; }
      if (text[index] !== ',') fail(`expected comma in object at byte ${index}`);
      index += 1;
    }
  };
  const result = value(); whitespace();
  if (index !== text.length) fail(`trailing JSON data at byte ${index}`);
  return result;
}

/** Canonical JSON as defined by spec/verifier-profile/manifest-v1.md. */
export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('canonical JSON cannot encode a non-finite number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  object(value, 'canonical JSON value');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

export function deriveProfileId(manifest) {
  object(manifest, 'manifest');
  const material = Object.fromEntries(PROFILE_MATERIAL_KEYS.map((key) => [key, manifest[key]]));
  return sha256(Buffer.concat([Buffer.from('shield.cash/verifier-profile-id/v1\0', 'utf8'), Buffer.from(canonicalJson(material), 'utf8')]));
}

export function deriveInstanceId(genesis) {
  object(genesis, 'genesis');
  const { instanceId: _ignored, ...material } = genesis;
  return sha256(Buffer.concat([Buffer.from('shield.cash/verifier-instance-id/v1\0', 'utf8'), Buffer.from(canonicalJson(material), 'utf8')]));
}

/** CashToken category ID for a category-creating input spending output 0. */
export function deriveStateNftCategory(categoryInputOutpoint) {
  exactKeys(categoryInputOutpoint, 'category input outpoint', ['txid', 'vout']);
  const txid = string(categoryInputOutpoint.txid, 'category input outpoint txid');
  if (!/^[0-9a-f]{64}$/.test(txid)) fail('category input outpoint txid is invalid');
  if (/^0+$/.test(txid)) fail('category input outpoint txid must be nonzero');
  if (categoryInputOutpoint.vout !== '0') fail('category input outpoint must spend output 0');
  return txid;
}

function safeArtifactPath(relativePath) {
  string(relativePath, 'artifact.path');
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(relativePath) || relativePath.includes('\\')) fail('artifact path is not a safe relative POSIX path');
  const parts = relativePath.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..')) fail('artifact path contains traversal');
  return relativePath;
}

function validateSetup(setup, artifactByPath) {
  object(setup, 'setup');
  const mode = setup.mode;
  if (mode === 'development-only') {
    exactKeys(setup, 'development setup', ['mode', 'provenance', 'material', 'transcript', 'contributions']);
    exactKeys(setup.provenance, 'development setup provenance', ['method', 'initializerCommitment']);
    if (setup.provenance.method !== 'local-initialization') fail('development setup requires local-initialization provenance');
    hash(setup.provenance.initializerCommitment, 'development initializer commitment');
    exactKeys(setup.transcript, 'development setup transcript', ['status']);
    if (setup.transcript.status !== 'not-applicable') fail('development setup transcript must be not-applicable');
    if (!Array.isArray(setup.contributions) || setup.contributions.length !== 0) fail('development setup must have no ceremony contributions');
    validateSetupMaterial(setup.material, 'development-only', artifactByPath);
    return;
  }
  if (mode !== 'ceremony-production') fail('setup.mode is unsupported');
  exactKeys(setup, 'ceremony setup', ['mode', 'provenance', 'material', 'transcript', 'contributions']);
  exactKeys(setup.provenance, 'ceremony setup provenance', ['method', 'initializerCommitment']);
  if (setup.provenance.method !== 'multi-party-randomness') fail('ceremony setup requires multi-party-randomness provenance');
  hash(setup.provenance.initializerCommitment, 'ceremony initializer commitment');
  exactKeys(setup.transcript, 'ceremony transcript', ['status', 'artifactPath', 'sha256', 'verifier']);
  if (setup.transcript.status !== 'complete') fail('ceremony transcript must be complete');
  const transcriptPath = safeArtifactPath(setup.transcript.artifactPath);
  const transcript = artifactByPath.get(transcriptPath);
  if (!transcript || transcript.kind !== 'ceremony-transcript') fail('ceremony transcript artifact is missing');
  if (transcript.sha256 !== hash(setup.transcript.sha256, 'ceremony transcript hash')) fail('ceremony transcript hash does not bind its artifact');
  validateVerifier(setup.transcript.verifier, 'ceremony transcript verifier');
  if (!Array.isArray(setup.contributions) || setup.contributions.length < 2) fail('ceremony setup requires at least two verified contributions');
  const participants = new Set(); let previousSequence;
  for (const [index, contribution] of setup.contributions.entries()) {
    exactKeys(contribution, `ceremony contribution ${index}`, ['sequence', 'participantCommitment', 'contributionHash', 'verification']);
    string(contribution.sequence, `ceremony contribution ${index} sequence`);
    if (!/^[1-9][0-9]*$/.test(contribution.sequence)) fail('ceremony contribution sequences must be positive decimal strings');
    if (previousSequence !== undefined && compareDecimalSequence(previousSequence, contribution.sequence) >= 0) fail('ceremony contributions must be strictly sorted by numeric sequence');
    previousSequence = contribution.sequence;
    const participant = hash(contribution.participantCommitment, `ceremony contribution ${index} participant commitment`);
    if (participants.has(participant)) fail('ceremony contribution participant commitments must be unique');
    participants.add(participant);
    hash(contribution.contributionHash, `ceremony contribution ${index} hash`);
    exactKeys(contribution.verification, `ceremony contribution ${index} verification`, ['status', 'verifier']);
    if (contribution.verification.status !== 'verified') fail('ceremony contribution must be verified');
    validateVerifier(contribution.verification.verifier, `ceremony contribution ${index} verifier`);
  }
  validateSetupMaterial(setup.material, 'ceremony-production', artifactByPath, setup.contributions);
}

function validateSetupCommand(command, label) {
  exactKeys(command, label, ['argv']);
  if (!Array.isArray(command.argv) || command.argv.length === 0) fail(`${label} argv must be a non-empty array`);
  for (const [index, argument] of command.argv.entries()) {
    string(argument, `${label} argv ${index}`);
    if (argument.length === 0 || argument.includes('\0')) fail(`${label} argv ${index} must be a non-empty argument without NUL`);
  }
}

/**
 * Binds phase-1 and circuit-specific phase-2 provenance without bundling the
 * potentially large ptau input as a runtime artifact. This is syntax/integrity
 * validation, not a cryptographic verification of either ceremony phase.
 */
function validateSetupMaterial(material, mode, artifactByPath, contributions = undefined) {
  exactKeys(material, 'setup material', ['phase1', 'phase2']);
  exactKeys(material.phase1, 'setup material phase1', ['ptauSource', 'ptauSha256']);
  const ptauSource = string(material.phase1.ptauSource, 'setup material ptau source');
  if (ptauSource.length === 0 || ptauSource.length > 1024 || ptauSource.includes('\0')) {
    fail('setup material ptau source must contain 1 to 1024 characters without NUL');
  }
  hash(material.phase1.ptauSha256, 'setup material ptau hash');
  const finalZkeyHash = [...artifactByPath.values()].find((artifact) => artifact.kind === 'proving-key')?.sha256;
  if (!finalZkeyHash) fail('setup material requires proving-key artifact');
  if (mode === 'development-only') {
    exactKeys(material.phase2, 'development setup material phase2', ['initializationCommand', 'contributionCommand', 'randomnessCommitment', 'finalZkeySha256']);
    validateSetupCommand(material.phase2.initializationCommand, 'development phase2 initialization command');
    validateSetupCommand(material.phase2.contributionCommand, 'development phase2 contribution command');
    hash(material.phase2.randomnessCommitment, 'development phase2 randomness commitment');
  } else {
    exactKeys(material.phase2, 'ceremony setup material phase2', ['initializationCommand', 'finalZkeySha256', 'finalZkeyVerification', 'contributionChainSha256']);
    validateSetupCommand(material.phase2.initializationCommand, 'ceremony phase2 initialization command');
    exactKeys(material.phase2.finalZkeyVerification, 'ceremony final zkey verification', ['status', 'verifier']);
    if (material.phase2.finalZkeyVerification.status !== 'verified') fail('ceremony final zkey must be verified');
    validateVerifier(material.phase2.finalZkeyVerification.verifier, 'ceremony final zkey verifier');
    const chainHash = hash(material.phase2.contributionChainSha256, 'ceremony contribution chain hash');
    const expectedChainHash = sha256(Buffer.from(canonicalJson(contributions), 'utf8'));
    if (chainHash !== expectedChainHash) fail('ceremony contribution chain hash does not bind contribution records');
  }
  if (hash(material.phase2.finalZkeySha256, 'setup material final zkey hash') !== finalZkeyHash) fail('setup material final zkey hash does not bind proving-key artifact');
}

function validateVerifier(verifier, label) {
  exactKeys(verifier, label, ['name', 'version', 'sha256']);
  if (!LABEL.test(string(verifier.name, `${label} name`))) fail(`${label} name is invalid`);
  string(verifier.version, `${label} version`); hash(verifier.sha256, `${label} hash`);
}

function validateManifest(manifest) {
  exactKeys(manifest, 'manifest', ['schema', 'standard', 'profile', 'setup', 'toolchain', 'network', 'artifacts', 'identity', 'genesis']);
  if (manifest.schema !== 'shield.cash/verifier-profile-manifest/v1') fail('unsupported manifest schema');
  exactKeys(manifest.standard, 'standard', ['id', 'version']);
  if (manifest.standard.id !== 'shield.cash' || manifest.standard.version !== '1') fail('unsupported standard');
  exactKeys(manifest.profile, 'profile', ['proofSystem', 'curve', 'relation', 'constraintSystemHash', 'publicInputAbi', 'bchVerifierSetHash']);
  if (manifest.profile.proofSystem !== 'groth16' || manifest.profile.curve !== 'bn254') fail('unsupported proof system or curve');
  for (const field of ['relation', 'publicInputAbi']) {
    exactKeys(manifest.profile[field], `profile.${field}`, ['id', 'sha256']);
    if (!LABEL.test(string(manifest.profile[field].id, `profile.${field}.id`))) fail(`profile.${field}.id is invalid`);
    hash(manifest.profile[field].sha256, `profile.${field}.sha256`);
  }
  hash(manifest.profile.constraintSystemHash, 'profile.constraintSystemHash');
  hash(manifest.profile.bchVerifierSetHash, 'profile.bchVerifierSetHash');
  exactKeys(manifest.toolchain, 'toolchain', ['compiler', 'generator']);
  validateVerifier(manifest.toolchain.compiler, 'toolchain compiler'); validateVerifier(manifest.toolchain.generator, 'toolchain generator');
  exactKeys(manifest.network, 'network', ['name']);
  if (manifest.network.name !== 'chipnet') fail('only chipnet is authorized by this interface');
  if (!Array.isArray(manifest.artifacts)) fail('artifacts must be an array');
  const ids = new Set(), paths = new Set(), kinds = new Set(), artifactByPath = new Map();
  let previousArtifactId;
  for (const [index, artifact] of manifest.artifacts.entries()) {
    exactKeys(artifact, `artifact ${index}`, ['id', 'kind', 'path', 'sha256']);
    if (!LABEL.test(string(artifact.id, `artifact ${index} id`)) || ids.has(artifact.id)) fail('artifact IDs must be unique labels');
    if (previousArtifactId !== undefined && previousArtifactId >= artifact.id) fail('artifacts must be strictly sorted by id');
    previousArtifactId = artifact.id;
    ids.add(artifact.id); if (!ARTIFACT_KINDS.has(artifact.kind) || kinds.has(artifact.kind)) fail('artifact kinds must be unique and supported');
    kinds.add(artifact.kind); const artifactPath = safeArtifactPath(artifact.path);
    if (paths.has(artifactPath)) fail('artifact paths must be unique'); paths.add(artifactPath);
    hash(artifact.sha256, `artifact ${index} hash`); artifactByPath.set(artifactPath, artifact);
  }
  for (const kind of REQUIRED_ARTIFACT_KINDS) if (!kinds.has(kind)) fail(`required artifact is missing: ${kind}`);
  const byKind = new Map(manifest.artifacts.map((artifact) => [artifact.kind, artifact]));
  if (byKind.get('relation-definition').sha256 !== manifest.profile.relation.sha256) fail('relation hash does not bind relation-definition artifact');
  if (byKind.get('constraint-system').sha256 !== manifest.profile.constraintSystemHash) fail('constraint hash does not bind constraint-system artifact');
  if (byKind.get('public-input-abi').sha256 !== manifest.profile.publicInputAbi.sha256) fail('public-input ABI hash does not bind public-input-abi artifact');
  if (byKind.get('bch-verifier-set').sha256 !== manifest.profile.bchVerifierSetHash) fail('BCH verifier-set hash does not bind bch-verifier-set artifact');
  validateSetup(manifest.setup, artifactByPath);
  exactKeys(manifest.identity, 'identity', ['profileId']); hash(manifest.identity.profileId, 'identity.profileId');
  exactKeys(manifest.genesis, 'genesis', ['profileId', 'instanceId', 'network', 'categoryInputOutpoint', 'stateNftCategory', 'reserveCapSatoshis']);
  hash(manifest.genesis.profileId, 'genesis.profileId'); hash(manifest.genesis.instanceId, 'genesis.instanceId');
  if (manifest.genesis.network !== manifest.network.name) fail('genesis network does not bind profile network');
  const categoryInputTxid = deriveStateNftCategory(manifest.genesis.categoryInputOutpoint);
  if (string(manifest.genesis.stateNftCategory, 'state NFT category') !== categoryInputTxid) fail('state NFT category must equal category input transaction hash in OP_HASH256 byte order');
  if (!/^(0|[1-9][0-9]{0,18})$/.test(string(manifest.genesis.reserveCapSatoshis, 'genesis reserve cap'))) fail('genesis reserve cap must be a canonical decimal string');
  const reserveCap = BigInt(manifest.genesis.reserveCapSatoshis);
  if (
    reserveCap < DENOMINATION_SATOSHIS
    || reserveCap > MAX_BCH_SUPPLY_SATOSHIS
    || reserveCap % DENOMINATION_SATOSHIS !== 0n
  ) {
    fail('genesis reserve cap must be a nonzero denomination multiple within BCH supply');
  }
  const profileId = deriveProfileId(manifest); const instanceId = deriveInstanceId(manifest.genesis);
  if (manifest.identity.profileId !== profileId || manifest.genesis.profileId !== profileId) fail('profile identity or genesis binding mismatch');
  if (manifest.genesis.instanceId !== instanceId) fail('genesis instance identity mismatch');
  return { profileId, instanceId };
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export async function loadVerifierProfileBundle(directory, expected = {}) {
  const requested = path.resolve(string(directory, 'bundle directory'));
  const directoryStats = await lstat(requested).catch(() => fail('bundle directory does not exist'));
  if (!directoryStats.isDirectory() || directoryStats.isSymbolicLink()) fail('bundle directory must be a real non-symlink directory');
  const root = await realpath(requested).catch(() => fail('bundle directory cannot be resolved'));
  if (root !== requested) fail('bundle directory path must not use symlinks');
  const manifestPath = path.join(root, 'manifest.json');
  const manifestStats = await lstat(manifestPath).catch(() => fail('bundle manifest is missing'));
  if (!manifestStats.isFile() || manifestStats.isSymbolicLink()) fail('bundle manifest must be a regular non-symlink file');
  if (manifestStats.size > MAX_MANIFEST_BYTES) fail('manifest exceeds the 1 MiB maximum size');
  const manifestBytes = await readFile(manifestPath);
  const manifest = parseStrictJson(manifestBytes);
  if (!Buffer.from(canonicalJson(manifest), 'utf8').equals(manifestBytes)) fail('manifest is not canonical JSON');
  const { profileId, instanceId } = validateManifest(manifest);
  for (const artifact of manifest.artifacts) {
    const candidate = path.resolve(root, ...artifact.path.split('/'));
    if (candidate !== root && !candidate.startsWith(`${root}${path.sep}`)) fail('artifact path escapes bundle root');
    const stats = await lstat(candidate).catch(() => fail(`artifact is missing: ${artifact.path}`));
    if (!stats.isFile() || stats.isSymbolicLink()) fail(`artifact must be a regular non-symlink file: ${artifact.path}`);
    const resolved = await realpath(candidate).catch(() => fail(`artifact cannot be resolved: ${artifact.path}`));
    if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) fail(`artifact resolves outside bundle root: ${artifact.path}`);
    if (resolved !== candidate) fail(`artifact path contains a symlink: ${artifact.path}`);
    if (await hashFile(resolved) !== artifact.sha256) fail(`artifact hash mismatch: ${artifact.path}`);
  }
  exactKeys(expected, 'expected bundle binding', ['network', 'profileId', 'instanceId'].filter((key) => expected[key] !== undefined));
  if (expected.profileId !== undefined && expected.profileId !== profileId) fail('expected profile binding mismatch: refusing hot swap');
  if (expected.instanceId !== undefined && expected.instanceId !== instanceId) fail('expected instance binding mismatch: refusing hot swap');
  if (expected.network !== undefined && expected.network !== manifest.network.name) fail('expected network binding mismatch');
  return deepFreeze({ root, manifest, profileId, instanceId });
}

function artifactHashByKind(manifest, kind) {
  const artifact = manifest.artifacts.find((candidate) => candidate.kind === kind);
  if (!artifact) fail(`replacement comparison requires ${kind} artifact`);
  return artifact.sha256;
}

function requireEqual(left, right, label) {
  if (left !== right) fail(`replacement comparison requires equal ${label}`);
}

function requireDistinct(left, right, label) {
  if (left === right) fail(`replacement comparison requires distinct ${label}`);
}

/**
 * Compare two completed local-development bundles for the narrow G1 setup
 * replacement property. This is read-only: it loads existing bundles only and
 * never initializes setup, creates a genesis transaction, or accepts caller
 * identity pins. The canonical result is returned only after every predicate
 * below has passed.
 */
export async function compareDevelopmentVerifierProfileBundles(input) {
  exactKeys(input, 'replacement comparison input', ['leftDirectory', 'rightDirectory']);
  const left = await loadVerifierProfileBundle(input.leftDirectory);
  const right = await loadVerifierProfileBundle(input.rightDirectory);
  if (left.root === right.root) fail('replacement comparison requires distinct bundle directories');

  const leftManifest = left.manifest; const rightManifest = right.manifest;
  for (const [label, manifest] of [['left', leftManifest], ['right', rightManifest]]) {
    if (manifest.network.name !== 'chipnet') fail(`replacement comparison requires ${label} Chipnet network`);
    if (manifest.setup.mode !== 'development-only') fail(`replacement comparison requires ${label} development-only setup`);
    if (manifest.setup.provenance.method !== 'local-initialization') fail(`replacement comparison requires ${label} local-initialization provenance`);
  }

  requireEqual(leftManifest.standard.id, rightManifest.standard.id, 'standard id');
  requireEqual(leftManifest.standard.version, rightManifest.standard.version, 'standard version');
  requireEqual(leftManifest.network.name, rightManifest.network.name, 'network');
  requireEqual(leftManifest.profile.proofSystem, rightManifest.profile.proofSystem, 'proof system');
  requireEqual(leftManifest.profile.curve, rightManifest.profile.curve, 'curve');
  requireEqual(leftManifest.profile.relation.id, rightManifest.profile.relation.id, 'relation id');
  requireEqual(leftManifest.profile.relation.sha256, rightManifest.profile.relation.sha256, 'relation hash');
  requireEqual(leftManifest.profile.constraintSystemHash, rightManifest.profile.constraintSystemHash, 'constraint-system hash');
  requireEqual(leftManifest.profile.publicInputAbi.id, rightManifest.profile.publicInputAbi.id, 'public-input ABI id');
  requireEqual(leftManifest.profile.publicInputAbi.sha256, rightManifest.profile.publicInputAbi.sha256, 'public-input ABI hash');
  requireEqual(artifactHashByKind(leftManifest, 'witness-generator'), artifactHashByKind(rightManifest, 'witness-generator'), 'witness-generator hash');
  requireEqual(leftManifest.setup.material.phase1.ptauSource, rightManifest.setup.material.phase1.ptauSource, 'Phase-1 ptau source');
  requireEqual(leftManifest.setup.material.phase1.ptauSha256, rightManifest.setup.material.phase1.ptauSha256, 'Phase-1 ptau hash');
  requireEqual(canonicalJson(leftManifest.toolchain.compiler), canonicalJson(rightManifest.toolchain.compiler), 'compiler toolchain record');
  requireEqual(canonicalJson(leftManifest.toolchain.generator), canonicalJson(rightManifest.toolchain.generator), 'generator toolchain record');
  requireEqual(leftManifest.genesis.reserveCapSatoshis, rightManifest.genesis.reserveCapSatoshis, 'denomination-relevant reserve-cap semantics');

  requireDistinct(leftManifest.setup.provenance.initializerCommitment, rightManifest.setup.provenance.initializerCommitment, 'initializer commitments');
  requireDistinct(leftManifest.setup.material.phase2.randomnessCommitment, rightManifest.setup.material.phase2.randomnessCommitment, 'setup randomness commitments');
  requireDistinct(leftManifest.setup.material.phase2.finalZkeySha256, rightManifest.setup.material.phase2.finalZkeySha256, 'final zkey hashes');
  requireDistinct(artifactHashByKind(leftManifest, 'verification-key'), artifactHashByKind(rightManifest, 'verification-key'), 'verification-key hashes');
  requireDistinct(leftManifest.profile.bchVerifierSetHash, rightManifest.profile.bchVerifierSetHash, 'BCH verifier-set hashes');
  requireDistinct(left.profileId, right.profileId, 'profile identifiers');
  requireDistinct(left.instanceId, right.instanceId, 'instance identifiers');
  requireDistinct(canonicalJson(leftManifest.genesis.categoryInputOutpoint), canonicalJson(rightManifest.genesis.categoryInputOutpoint), 'category input outpoints');

  return canonicalJson({
    schema: 'shield.cash/verifier-profile-replacement/v1',
    scope: 'interface-replacement-only',
    replacementProperty: 'satisfied',
    shared: {
      standard: leftManifest.standard,
      network: leftManifest.network,
      proofSystem: leftManifest.profile.proofSystem,
      curve: leftManifest.profile.curve,
      relation: leftManifest.profile.relation,
      constraintSystemHash: leftManifest.profile.constraintSystemHash,
      publicInputAbi: leftManifest.profile.publicInputAbi,
      witnessGeneratorHash: artifactHashByKind(leftManifest, 'witness-generator'),
      setupPhase1: leftManifest.setup.material.phase1,
      toolchain: leftManifest.toolchain,
      genesis: { reserveCapSatoshis: leftManifest.genesis.reserveCapSatoshis },
    },
    replacements: {
      left: {
        setupInitializerCommitment: leftManifest.setup.provenance.initializerCommitment,
        setupRandomnessCommitment: leftManifest.setup.material.phase2.randomnessCommitment,
        finalZkeySha256: leftManifest.setup.material.phase2.finalZkeySha256,
        verificationKeySha256: artifactHashByKind(leftManifest, 'verification-key'),
        bchVerifierSetSha256: leftManifest.profile.bchVerifierSetHash,
        profileId: left.profileId,
        instanceId: left.instanceId,
        categoryInputOutpoint: leftManifest.genesis.categoryInputOutpoint,
      },
      right: {
        setupInitializerCommitment: rightManifest.setup.provenance.initializerCommitment,
        setupRandomnessCommitment: rightManifest.setup.material.phase2.randomnessCommitment,
        finalZkeySha256: rightManifest.setup.material.phase2.finalZkeySha256,
        verificationKeySha256: artifactHashByKind(rightManifest, 'verification-key'),
        bchVerifierSetSha256: rightManifest.profile.bchVerifierSetHash,
        profileId: right.profileId,
        instanceId: right.instanceId,
        categoryInputOutpoint: rightManifest.genesis.categoryInputOutpoint,
      },
    },
  });
}
