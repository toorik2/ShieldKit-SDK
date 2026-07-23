import { createHash } from 'node:crypto';
import {
  lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import {
  BundleValidationError, canonicalJson, deriveInstanceId, deriveProfileId,
  loadVerifierProfileBundle,
} from '../core/verifier-profile.mjs';

const HASH = /^sha256:[0-9a-f]{64}$/;
const REQUIRED_ARTIFACT_KINDS = new Set([
  'relation-definition', 'constraint-system', 'public-input-abi',
  'verification-key', 'proving-key', 'witness-generator', 'bch-verifier-set',
]);
const ARTIFACT_KINDS = new Set([...REQUIRED_ARTIFACT_KINDS, 'ceremony-transcript']);

export class ProfileBuildError extends Error {
  constructor(message) { super(message); this.name = 'ProfileBuildError'; }
}

const fail = (message) => { throw new ProfileBuildError(message); };
const object = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  return value;
};
const string = (value, label) => {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`);
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
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown properties`);
  }
};
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function containsBytes(haystack, needle) {
  return haystack.indexOf(needle) !== -1;
}

/**
 * Reject direct final-identity embedding in profile-hashed verifier bytes.
 * This is a defense-in-depth byte scan, not a BCH-script semantic analysis.
 */
export function assertVerifierSetIsPreGenesis(verifierSetBytes, { profileId, instanceId }) {
  const bytes = Buffer.from(verifierSetBytes);
  for (const [label, identifier] of [['profileId', profileId], ['instanceId', instanceId]]) {
    hash(identifier, label);
    const hex = identifier.slice('sha256:'.length);
    if (
      containsBytes(bytes, Buffer.from(identifier, 'utf8'))
      || containsBytes(bytes, Buffer.from(hex, 'utf8'))
      || containsBytes(bytes, Buffer.from(hex, 'hex'))
    ) fail(`bch-verifier-set must not embed final ${label}`);
  }
}

function safeBundlePath(value, label) {
  string(value, label);
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value) || value.includes('\\')) fail(`${label} is not a safe relative POSIX path`);
  if (value.split('/').some((part) => !part || part === '.' || part === '..')) fail(`${label} contains traversal`);
  return value;
}

async function sourceBytes(source, label) {
  object(source, label);
  const hasPath = Object.hasOwn(source, 'sourcePath'); const hasBytes = Object.hasOwn(source, 'bytes');
  if (hasPath === hasBytes) fail(`${label} must contain exactly one of sourcePath or bytes`);
  exactKeys(source, label, hasPath ? ['sourcePath'] : ['bytes']);
  if (hasBytes) {
    if (!Buffer.isBuffer(source.bytes) && !(source.bytes instanceof Uint8Array)) fail(`${label}.bytes must be Buffer or Uint8Array`);
    return Buffer.from(source.bytes);
  }
  const requested = path.resolve(string(source.sourcePath, `${label}.sourcePath`));
  const stats = await lstat(requested).catch(() => fail(`${label}.sourcePath does not exist`));
  if (!stats.isFile() || stats.isSymbolicLink()) fail(`${label}.sourcePath must be a regular non-symlink file`);
  const resolved = await realpath(requested).catch(() => fail(`${label}.sourcePath cannot be resolved`));
  if (resolved !== requested) fail(`${label}.sourcePath must not use symlinks`);
  return readFile(resolved);
}

function normalizeArtifactInput(input) {
  object(input, 'artifact input');
  const keys = Object.hasOwn(input, 'expectedSha256')
    ? ['id', 'kind', 'path', 'source', 'expectedSha256']
    : ['id', 'kind', 'path', 'source'];
  exactKeys(input, 'artifact input', keys);
  string(input.id, 'artifact input id');
  if (!ARTIFACT_KINDS.has(input.kind)) fail('artifact input kind is unsupported');
  safeBundlePath(input.path, 'artifact input path');
  if (input.path === 'manifest.json') fail('artifact input path is reserved for manifest.json');
  if (input.expectedSha256 !== undefined) hash(input.expectedSha256, 'artifact input expectedSha256');
  return input;
}

async function materializeArtifacts(inputs) {
  if (!Array.isArray(inputs)) fail('artifacts must be an array');
  const artifacts = [];
  let previousId;
  const kinds = new Set(); const paths = new Set();
  for (const input of inputs) {
    normalizeArtifactInput(input);
    if (previousId !== undefined && previousId >= input.id) fail('artifact inputs must be strictly sorted by id');
    if (kinds.has(input.kind)) fail('artifact input kinds must be unique');
    if (paths.has(input.path)) fail('artifact input paths must be unique');
    previousId = input.id; kinds.add(input.kind); paths.add(input.path);
    const bytes = await sourceBytes(input.source, `artifact ${input.id}`);
    const actualHash = sha256(bytes);
    if (input.expectedSha256 !== undefined && input.expectedSha256 !== actualHash) fail(`artifact expected hash mismatch: ${input.id}`);
    artifacts.push({ id: input.id, kind: input.kind, path: input.path, sha256: actualHash, bytes });
  }
  for (const kind of REQUIRED_ARTIFACT_KINDS) if (!kinds.has(kind)) fail(`required artifact input is missing: ${kind}`);
  return artifacts;
}

async function materializeTool(tool, label) {
  exactKeys(tool, label, ['name', 'version', 'source']);
  const bytes = await sourceBytes(tool.source, `${label}.source`);
  return { name: string(tool.name, `${label}.name`), version: string(tool.version, `${label}.version`), sha256: sha256(bytes) };
}

function cloneTyped(value, label) {
  try { return JSON.parse(JSON.stringify(value)); }
  catch { fail(`${label} must be JSON-serializable`); }
}

function buildSetup(input, artifacts) {
  object(input, 'setup');
  if (input.mode === 'development-only') {
    exactKeys(input, 'development setup input', ['mode', 'provenance', 'material']);
    exactKeys(input.provenance, 'development setup provenance', ['method', 'initializerCommitment']);
    if (input.provenance.method !== 'local-initialization') fail('development setup requires local-initialization provenance');
    return {
      mode: 'development-only',
      provenance: cloneTyped(input.provenance, 'development setup provenance'),
      material: cloneTyped(input.material, 'development setup material'),
      transcript: { status: 'not-applicable' }, contributions: [],
    };
  }
  if (input.mode !== 'ceremony-production') fail('setup.mode is unsupported');
  exactKeys(input, 'ceremony setup input', ['mode', 'provenance', 'material', 'transcript', 'contributions']);
  exactKeys(input.provenance, 'ceremony setup provenance', ['method', 'initializerCommitment']);
  if (input.provenance.method !== 'multi-party-randomness') fail('ceremony setup requires multi-party-randomness provenance');
  exactKeys(input.transcript, 'ceremony transcript input', ['artifactPath', 'verifier']);
  const artifactPath = safeBundlePath(input.transcript.artifactPath, 'ceremony transcript input artifactPath');
  const transcript = artifacts.find((artifact) => artifact.path === artifactPath && artifact.kind === 'ceremony-transcript');
  if (!transcript) fail('ceremony transcript input must name a ceremony-transcript artifact');
  if (!Array.isArray(input.contributions)) fail('ceremony setup contributions must be an array');
  const material = cloneTyped(input.material, 'ceremony setup material');
  object(material, 'ceremony setup material'); object(material.phase2, 'ceremony setup material phase2');
  if (Object.hasOwn(material.phase2, 'contributionChainSha256')) fail('ceremony contributionChainSha256 is builder-derived');
  material.phase2.contributionChainSha256 = sha256(Buffer.from(canonicalJson(input.contributions), 'utf8'));
  return {
    mode: 'ceremony-production', provenance: cloneTyped(input.provenance, 'ceremony setup provenance'), material,
    transcript: { status: 'complete', artifactPath, sha256: transcript.sha256, verifier: cloneTyped(input.transcript.verifier, 'ceremony transcript verifier') },
    contributions: cloneTyped(input.contributions, 'ceremony setup contributions'),
  };
}

function makeManifest(input, artifacts, toolchain) {
  exactKeys(input.profile, 'profile input', ['proofSystem', 'curve', 'relation', 'publicInputAbi']);
  exactKeys(input.profile.relation, 'profile input relation', ['id']);
  exactKeys(input.profile.publicInputAbi, 'profile input publicInputAbi', ['id']);
  exactKeys(input.network, 'network input', ['name']);
  exactKeys(input.genesis, 'genesis input', ['categoryInputOutpoint', 'reserveCapSatoshis']);
  const byKind = new Map(artifacts.map((artifact) => [artifact.kind, artifact]));
  const setup = buildSetup(input.setup, artifacts);
  const manifest = {
    schema: 'shield.cash/verifier-profile-manifest/v1',
    standard: { id: 'shield.cash', version: '1' },
    profile: {
      proofSystem: input.profile.proofSystem, curve: input.profile.curve,
      relation: { id: input.profile.relation.id, sha256: byKind.get('relation-definition').sha256 },
      constraintSystemHash: byKind.get('constraint-system').sha256,
      publicInputAbi: { id: input.profile.publicInputAbi.id, sha256: byKind.get('public-input-abi').sha256 },
      bchVerifierSetHash: byKind.get('bch-verifier-set').sha256,
    },
    setup,
    toolchain,
    network: cloneTyped(input.network, 'network input'),
    artifacts: artifacts.map(({ bytes: _bytes, ...artifact }) => artifact),
    identity: { profileId: '' },
    genesis: {
      ...cloneTyped(input.genesis, 'genesis input'), profileId: '', instanceId: '', network: input.network.name,
      stateNftCategory: input.genesis.categoryInputOutpoint?.txid,
    },
  };
  manifest.identity.profileId = deriveProfileId(manifest);
  manifest.genesis.profileId = manifest.identity.profileId;
  manifest.genesis.instanceId = deriveInstanceId(manifest.genesis);
  assertVerifierSetIsPreGenesis(byKind.get('bch-verifier-set').bytes, {
    profileId: manifest.identity.profileId, instanceId: manifest.genesis.instanceId,
  });
  return manifest;
}

async function destinationPath(destination) {
  const requested = path.resolve(string(destination, 'destination'));
  const name = path.basename(requested);
  if (name === '.' || name === '..') fail('destination must name a new directory');
  const parent = await realpath(path.dirname(requested)).catch(() => fail('destination parent directory does not exist'));
  const target = path.join(parent, name);
  try {
    await lstat(target); fail('destination already exists; refusing overwrite');
  } catch (error) {
    if (error instanceof ProfileBuildError) throw error;
    if (error?.code !== 'ENOENT') fail('destination cannot be inspected safely');
  }
  return { parent, target };
}

async function writeBundle(directory, artifacts, manifestBytes) {
  for (const artifact of artifacts) {
    const target = path.join(directory, ...artifact.path.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, artifact.bytes, { flag: 'wx' });
  }
  await writeFile(path.join(directory, 'manifest.json'), manifestBytes, { flag: 'wx' });
}

/**
 * Build a new immutable verifier-profile bundle from caller-supplied bytes.
 * It never initializes a setup, creates a proof artifact, overwrites a
 * destination, or treats a caller-supplied hash as authoritative.
 */
export async function buildVerifierProfileBundle(input) {
  object(input, 'build input');
  exactKeys(input, 'build input', ['destination', 'profile', 'setup', 'toolchain', 'network', 'artifacts', 'genesis', ...(input.expected === undefined ? [] : ['expected'])]);
  const { parent, target } = await destinationPath(input.destination);
  exactKeys(input.toolchain, 'toolchain input', ['compiler', 'generator']);
  const artifacts = await materializeArtifacts(input.artifacts);
  const toolchain = {
    compiler: await materializeTool(input.toolchain.compiler, 'toolchain compiler input'),
    generator: await materializeTool(input.toolchain.generator, 'toolchain generator input'),
  };
  const manifest = makeManifest(input, artifacts, toolchain);
  const manifestBytes = Buffer.from(canonicalJson(manifest), 'utf8');
  let stage; let destinationCreated = false;
  try {
    stage = await mkdtemp(path.join(parent, '.shield-cash-profile-stage-'));
    await writeBundle(stage, artifacts, manifestBytes);
    const staged = await loadVerifierProfileBundle(stage, input.expected ?? {});
    if (staged.profileId !== manifest.identity.profileId || staged.instanceId !== manifest.genesis.instanceId) fail('core loader identity disagreement after staging');
    await mkdir(target); destinationCreated = true;
    await writeBundle(target, artifacts, manifestBytes);
    const promoted = await loadVerifierProfileBundle(target, input.expected ?? {});
    if (promoted.profileId !== staged.profileId || promoted.instanceId !== staged.instanceId) fail('core loader identity disagreement after promotion');
    return Object.freeze({ directory: target, profileId: promoted.profileId, instanceId: promoted.instanceId, manifest: promoted.manifest });
  } catch (error) {
    if (destinationCreated) await rm(target, { recursive: true, force: true });
    if (error instanceof ProfileBuildError || error instanceof BundleValidationError) throw error;
    throw new ProfileBuildError(error?.message ?? 'profile bundle build failed');
  } finally {
    if (stage) await rm(stage, { recursive: true, force: true });
  }
}
