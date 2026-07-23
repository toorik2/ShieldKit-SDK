import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

const HASH = /^sha256:[0-9a-f]{64}$/;
const LABEL = /^[a-z0-9][a-z0-9._-]*$/;
const REQUIRED_ARTIFACT_KINDS = new Set([
  'relation-definition', 'constraint-system', 'public-input-abi',
  'verification-key', 'proving-key', 'bch-verifier-script',
]);
const ARTIFACT_KINDS = new Set([...REQUIRED_ARTIFACT_KINDS, 'ceremony-transcript']);
const PROFILE_MATERIAL_KEYS = ['artifacts', 'network', 'profile', 'setup', 'standard', 'toolchain'];

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
    exactKeys(setup, 'development setup', ['mode', 'provenance', 'transcript', 'contributions']);
    exactKeys(setup.provenance, 'development setup provenance', ['method', 'initializerCommitment']);
    if (setup.provenance.method !== 'local-initialization') fail('development setup requires local-initialization provenance');
    hash(setup.provenance.initializerCommitment, 'development initializer commitment');
    exactKeys(setup.transcript, 'development setup transcript', ['status']);
    if (setup.transcript.status !== 'not-applicable') fail('development setup transcript must be not-applicable');
    if (!Array.isArray(setup.contributions) || setup.contributions.length !== 0) fail('development setup must have no ceremony contributions');
    return;
  }
  if (mode !== 'ceremony-production') fail('setup.mode is unsupported');
  exactKeys(setup, 'ceremony setup', ['mode', 'provenance', 'transcript', 'contributions']);
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
  const participants = new Set(); const sequences = new Set();
  for (const [index, contribution] of setup.contributions.entries()) {
    exactKeys(contribution, `ceremony contribution ${index}`, ['sequence', 'participantCommitment', 'contributionHash', 'verification']);
    string(contribution.sequence, `ceremony contribution ${index} sequence`);
    if (!/^[1-9][0-9]*$/.test(contribution.sequence) || sequences.has(contribution.sequence)) fail('ceremony contribution sequences must be unique positive decimal strings');
    sequences.add(contribution.sequence);
    const participant = hash(contribution.participantCommitment, `ceremony contribution ${index} participant commitment`);
    if (participants.has(participant)) fail('ceremony contribution participant commitments must be unique');
    participants.add(participant);
    hash(contribution.contributionHash, `ceremony contribution ${index} hash`);
    exactKeys(contribution.verification, `ceremony contribution ${index} verification`, ['status', 'verifier']);
    if (contribution.verification.status !== 'verified') fail('ceremony contribution must be verified');
    validateVerifier(contribution.verification.verifier, `ceremony contribution ${index} verifier`);
  }
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
  exactKeys(manifest.profile, 'profile', ['proofSystem', 'curve', 'relation', 'constraintSystemHash', 'publicInputAbi']);
  if (manifest.profile.proofSystem !== 'groth16' || manifest.profile.curve !== 'bn254') fail('unsupported proof system or curve');
  for (const field of ['relation', 'publicInputAbi']) {
    exactKeys(manifest.profile[field], `profile.${field}`, ['id', 'sha256']);
    if (!LABEL.test(string(manifest.profile[field].id, `profile.${field}.id`))) fail(`profile.${field}.id is invalid`);
    hash(manifest.profile[field].sha256, `profile.${field}.sha256`);
  }
  hash(manifest.profile.constraintSystemHash, 'profile.constraintSystemHash');
  exactKeys(manifest.toolchain, 'toolchain', ['compiler', 'generator']);
  validateVerifier(manifest.toolchain.compiler, 'toolchain compiler'); validateVerifier(manifest.toolchain.generator, 'toolchain generator');
  exactKeys(manifest.network, 'network', ['name']);
  if (manifest.network.name !== 'chipnet') fail('only chipnet is authorized by this interface');
  if (!Array.isArray(manifest.artifacts)) fail('artifacts must be an array');
  const ids = new Set(), paths = new Set(), kinds = new Set(), artifactByPath = new Map();
  for (const [index, artifact] of manifest.artifacts.entries()) {
    exactKeys(artifact, `artifact ${index}`, ['id', 'kind', 'path', 'sha256']);
    if (!LABEL.test(string(artifact.id, `artifact ${index} id`)) || ids.has(artifact.id)) fail('artifact IDs must be unique labels');
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
  validateSetup(manifest.setup, artifactByPath);
  exactKeys(manifest.identity, 'identity', ['profileId']); hash(manifest.identity.profileId, 'identity.profileId');
  exactKeys(manifest.genesis, 'genesis', ['profileId', 'instanceId', 'network', 'genesisOutpoint', 'reserveCapSatoshis']);
  hash(manifest.genesis.profileId, 'genesis.profileId'); hash(manifest.genesis.instanceId, 'genesis.instanceId');
  if (manifest.genesis.network !== manifest.network.name) fail('genesis network does not bind profile network');
  exactKeys(manifest.genesis.genesisOutpoint, 'genesis outpoint', ['txid', 'vout']);
  if (!/^[0-9a-f]{64}$/.test(string(manifest.genesis.genesisOutpoint.txid, 'genesis outpoint txid'))) fail('genesis outpoint txid is invalid');
  if (!/^(0|[1-9][0-9]{0,9})$/.test(string(manifest.genesis.genesisOutpoint.vout, 'genesis outpoint vout'))) fail('genesis outpoint vout is invalid');
  if (!/^(0|[1-9][0-9]{0,18})$/.test(string(manifest.genesis.reserveCapSatoshis, 'genesis reserve cap'))) fail('genesis reserve cap must be a canonical decimal string');
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
  const root = await realpath(directory).catch(() => fail('bundle directory does not exist'));
  const manifestPath = path.join(root, 'manifest.json');
  const manifestStats = await lstat(manifestPath).catch(() => fail('bundle manifest is missing'));
  if (!manifestStats.isFile() || manifestStats.isSymbolicLink()) fail('bundle manifest must be a regular non-symlink file');
  const manifestBytes = await readFile(manifestPath);
  const manifest = parseStrictJson(manifestBytes);
  if (!Buffer.from(canonicalJson(manifest), 'utf8').equals(manifestBytes)) fail('manifest is not canonical JSON');
  const { profileId, instanceId } = validateManifest(manifest);
  for (const artifact of manifest.artifacts) {
    const candidate = path.resolve(root, ...artifact.path.split('/'));
    if (candidate !== root && !candidate.startsWith(`${root}${path.sep}`)) fail('artifact path escapes bundle root');
    const stats = await lstat(candidate).catch(() => fail(`artifact is missing: ${artifact.path}`));
    if (!stats.isFile() || stats.isSymbolicLink()) fail(`artifact must be a regular non-symlink file: ${artifact.path}`);
    if (sha256(await readFile(candidate)) !== artifact.sha256) fail(`artifact hash mismatch: ${artifact.path}`);
  }
  exactKeys(expected, 'expected bundle binding', ['network', 'profileId', 'instanceId'].filter((key) => expected[key] !== undefined));
  if (expected.profileId !== undefined && expected.profileId !== profileId) fail('expected profile binding mismatch: refusing hot swap');
  if (expected.instanceId !== undefined && expected.instanceId !== instanceId) fail('expected instance binding mismatch: refusing hot swap');
  if (expected.network !== undefined && expected.network !== manifest.network.name) fail('expected network binding mismatch');
  return deepFreeze({ manifest, profileId, instanceId });
}
