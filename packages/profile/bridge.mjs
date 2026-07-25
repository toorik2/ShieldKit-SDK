import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { parseStrictJson } from './load.mjs';
import { ProfileBuildError, buildVerifierProfileBundle } from './build.mjs';

const HASH = /^sha256:[0-9a-f]{64}$/;
const CURRENT_RELATION_ID = 'shielded-action-v2';
const CURRENT_ABI_ID = 'shielded-action-public-input-v1';

export class SetupProfileBridgeError extends Error {
  constructor(message) { super(message); this.name = 'SetupProfileBridgeError'; }
}

const fail = (message) => { throw new SetupProfileBridgeError(message); };
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
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
};

async function regularFile(sourcePath, label) {
  const requested = path.resolve(string(sourcePath, label));
  const stats = await lstat(requested).catch(() => fail(`${label} does not exist`));
  if (!stats.isFile() || stats.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  const resolved = await realpath(requested).catch(() => fail(`${label} cannot be resolved`));
  if (resolved !== requested) fail(`${label} must not use symlinks`);
  return resolved;
}

async function digestFile(file) {
  return new Promise((resolve, reject) => {
    const hasher = createHash('sha256'); const stream = createReadStream(file, { highWaterMark: 64 * 1024 });
    stream.on('data', (chunk) => hasher.update(chunk));
    stream.on('error', () => reject(new SetupProfileBridgeError('artifact cannot be hashed')));
    stream.on('end', () => resolve(`sha256:${hasher.digest('hex')}`));
  });
}

async function sourceDigest(source, label) {
  object(source, label);
  const hasPath = Object.hasOwn(source, 'sourcePath'); const hasBytes = Object.hasOwn(source, 'bytes');
  if (hasPath === hasBytes) fail(`${label} must contain exactly one of sourcePath or bytes`);
  exactKeys(source, label, hasPath ? ['sourcePath'] : ['bytes']);
  if (hasBytes) {
    if (!Buffer.isBuffer(source.bytes) && !(source.bytes instanceof Uint8Array)) fail(`${label}.bytes must be Buffer or Uint8Array`);
    return `sha256:${createHash('sha256').update(source.bytes).digest('hex')}`;
  }
  return digestFile(await regularFile(source.sourcePath, `${label}.sourcePath`));
}

function safeLocalOutputPath(value, label) {
  string(value, label);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) fail(`${label} must be a simple relative filename`);
  return value;
}

async function metadataFile(input) {
  exactKeys(input.setupMetadata, 'setup metadata input', ['sourcePath', 'expectedSha256']);
  const sourcePath = await regularFile(input.setupMetadata.sourcePath, 'setup metadata sourcePath');
  const expectedSha256 = hash(input.setupMetadata.expectedSha256, 'setup metadata expectedSha256');
  if (await digestFile(sourcePath) !== expectedSha256) fail('setup metadata hash mismatch');
  const bytes = await readFile(sourcePath);
  if (`sha256:${createHash('sha256').update(bytes).digest('hex')}` !== expectedSha256) fail('setup metadata changed while reading');
  if (await digestFile(sourcePath) !== expectedSha256) fail('setup metadata changed after reading');
  let metadata;
  try { metadata = parseStrictJson(bytes); }
  catch (error) { if (error instanceof SetupProfileBridgeError) throw error; fail('setup metadata is invalid'); }
  return { sourcePath, metadata };
}

async function validateMetadata(metadataPath, metadata) {
  exactKeys(metadata, 'local setup metadata', ['schema', 'mode', 'inputs', 'outputs', 'setup', 'toolchain']);
  if (metadata.schema !== 'shield.cash/local-development-setup/v1') fail('unsupported local setup metadata schema');
  if (metadata.mode !== 'development-only') fail('local setup metadata must remain development-only');
  exactKeys(metadata.inputs, 'local setup metadata inputs', ['r1cs', 'ptau']);
  exactKeys(metadata.inputs.r1cs, 'local setup metadata r1cs', ['sha256', 'requiredPower', 'nConstraints', 'nPublicInputs', 'nOutputs']);
  hash(metadata.inputs.r1cs.sha256, 'local setup metadata r1cs hash');
  if (!Number.isInteger(metadata.inputs.r1cs.requiredPower) || !Number.isInteger(metadata.inputs.r1cs.nConstraints)) fail('local setup metadata r1cs counts are invalid');
  if (metadata.inputs.r1cs.nPublicInputs !== 2 || metadata.inputs.r1cs.nOutputs !== 0) fail('local setup metadata does not use the current shield.cash ABI');
  exactKeys(metadata.inputs.ptau, 'local setup metadata ptau', ['source', 'sha256', 'power', 'ceremonyPower']);
  string(metadata.inputs.ptau.source, 'local setup metadata ptau source'); hash(metadata.inputs.ptau.sha256, 'local setup metadata ptau hash');
  exactKeys(metadata.outputs, 'local setup metadata outputs', ['provingKey', 'verificationKey']);
  exactKeys(metadata.outputs.provingKey, 'local setup proving key output', ['path', 'sha256']);
  exactKeys(metadata.outputs.verificationKey, 'local setup verification key output', ['path', 'sha256']);
  if (safeLocalOutputPath(metadata.outputs.provingKey.path, 'local setup proving key path') !== 'final.zkey') fail('local setup proving key must be final.zkey');
  if (safeLocalOutputPath(metadata.outputs.verificationKey.path, 'local setup verification key path') !== 'verification_key.json') fail('local setup verification key must be verification_key.json');
  const provingKeyHash = hash(metadata.outputs.provingKey.sha256, 'local setup proving key hash');
  const verificationKeyHash = hash(metadata.outputs.verificationKey.sha256, 'local setup verification key hash');
  exactKeys(metadata.setup, 'local setup setup', ['mode', 'provenance', 'material', 'transcript', 'contributions']);
  if (metadata.setup.mode !== 'development-only') fail('local setup mode relabel is forbidden');
  exactKeys(metadata.setup.provenance, 'local setup provenance', ['method', 'initializerCommitment']);
  if (metadata.setup.provenance.method !== 'local-initialization') fail('local setup provenance must be local-initialization');
  hash(metadata.setup.provenance.initializerCommitment, 'local setup initializer commitment');
  exactKeys(metadata.setup.material, 'local setup material', ['phase1', 'phase2']);
  exactKeys(metadata.setup.material.phase1, 'local setup phase1', ['ptauSource', 'ptauSha256']);
  if (metadata.setup.material.phase1.ptauSource !== metadata.inputs.ptau.source || metadata.setup.material.phase1.ptauSha256 !== metadata.inputs.ptau.sha256) fail('local setup phase1 metadata mismatch');
  exactKeys(metadata.setup.material.phase2, 'local setup phase2', ['initializationCommand', 'contributionCommand', 'randomnessCommitment', 'finalZkeySha256']);
  hash(metadata.setup.material.phase2.randomnessCommitment, 'local setup randomness commitment');
  if (metadata.setup.material.phase2.finalZkeySha256 !== provingKeyHash) fail('local setup final zkey hash mismatch');
  exactKeys(metadata.setup.transcript, 'local setup transcript', ['status']);
  if (metadata.setup.transcript.status !== 'not-applicable' || !Array.isArray(metadata.setup.contributions) || metadata.setup.contributions.length !== 0) fail('local setup metadata must not contain ceremony records');
  exactKeys(metadata.toolchain, 'local setup toolchain', ['generator']);
  exactKeys(metadata.toolchain.generator, 'local setup generator', ['name', 'version', 'sha256']);
  string(metadata.toolchain.generator.name, 'local setup generator name'); string(metadata.toolchain.generator.version, 'local setup generator version'); hash(metadata.toolchain.generator.sha256, 'local setup generator hash');
  const base = path.dirname(metadataPath);
  const provingKeyPath = await regularFile(path.join(base, metadata.outputs.provingKey.path), 'local setup final.zkey');
  const verificationKeyPath = await regularFile(path.join(base, metadata.outputs.verificationKey.path), 'local setup verification_key.json');
  if (await digestFile(provingKeyPath) !== provingKeyHash) fail('local setup final.zkey hash mismatch');
  if (await digestFile(verificationKeyPath) !== verificationKeyHash) fail('local setup verification_key.json hash mismatch');
  return {
    provingKeyPath, verificationKeyPath, provingKeyHash, verificationKeyHash,
    setup: { mode: metadata.setup.mode, provenance: metadata.setup.provenance, material: metadata.setup.material },
    r1csHash: metadata.inputs.r1cs.sha256, generator: metadata.toolchain.generator,
  };
}

async function bridgeArtifacts(artifacts, local) {
  if (!Array.isArray(artifacts)) fail('artifacts must be an array');
  let constraintHash; let proving = 0; let verification = 0;
  const bridged = [];
  for (const artifact of artifacts) {
    object(artifact, 'bridge artifact'); string(artifact.kind, 'bridge artifact kind');
    if (artifact.kind === 'proving-key' || artifact.kind === 'verification-key') {
      exactKeys(artifact, 'bridge key artifact', ['id', 'kind', 'path']);
      if (artifact.kind === 'proving-key') { proving += 1; bridged.push({ ...artifact, source: { sourcePath: local.provingKeyPath }, expectedSha256: local.provingKeyHash }); }
      else { verification += 1; bridged.push({ ...artifact, source: { sourcePath: local.verificationKeyPath }, expectedSha256: local.verificationKeyHash }); }
      continue;
    }
    if (artifact.kind === 'constraint-system') constraintHash = await sourceDigest(artifact.source, 'constraint-system source');
    bridged.push(artifact);
  }
  if (proving !== 1 || verification !== 1) fail('bridge requires exactly one proving-key and one verification-key descriptor');
  if (constraintHash !== local.r1csHash) fail('constraint-system artifact does not bind local setup R1CS');
  return bridged;
}

/**
 * Package a hash-pinned, local-development setup as a new immutable profile.
 * Returned identifiers are derived pre-genesis identity inputs only: this
 * function never initializes setup, constructs, or broadcasts a BCH instance.
 */
export async function bridgeLocalSetupToProfile(input) {
  object(input, 'bridge input');
  exactKeys(input, 'bridge input', ['destination', 'setupMetadata', 'profile', 'toolchain', 'network', 'artifacts', 'genesis', ...(input.expected === undefined ? [] : ['expected'])]);
  const { sourcePath, metadata } = await metadataFile(input);
  const local = await validateMetadata(sourcePath, metadata);
  exactKeys(input.profile, 'profile input', ['proofSystem', 'curve', 'relation', 'publicInputAbi']);
  exactKeys(input.profile.relation, 'profile input relation', ['id']);
  exactKeys(input.profile.publicInputAbi, 'profile input publicInputAbi', ['id']);
  if (input.profile.relation.id !== CURRENT_RELATION_ID) fail(`profile relation must be ${CURRENT_RELATION_ID}`);
  if (input.profile.publicInputAbi.id !== CURRENT_ABI_ID) fail(`profile public-input ABI must be ${CURRENT_ABI_ID}`);
  exactKeys(input.toolchain, 'toolchain input', ['compiler', 'generator']);
  exactKeys(input.toolchain.generator, 'toolchain generator input', ['name', 'version', 'source']);
  if (input.toolchain.generator.name !== local.generator.name || input.toolchain.generator.version !== local.generator.version) fail('profile generator identity does not match local setup metadata');
  if (await sourceDigest(input.toolchain.generator.source, 'toolchain generator source') !== local.generator.sha256) fail('profile generator hash does not match local setup metadata');
  const artifacts = await bridgeArtifacts(input.artifacts, local);
  try {
    return await buildVerifierProfileBundle({
      destination: input.destination, profile: input.profile, setup: local.setup, toolchain: input.toolchain,
      network: input.network, artifacts, genesis: input.genesis, ...(input.expected === undefined ? {} : { expected: input.expected }),
    });
  } catch (error) {
    if (error instanceof SetupProfileBridgeError) throw error;
    if (error instanceof ProfileBuildError) fail(error.message);
    throw error;
  }
}
