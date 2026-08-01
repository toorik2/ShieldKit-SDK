#!/usr/bin/env node

/**
 * Build and independently revalidate a private, beta-only PF10 runtime
 * bundle. This is intentionally not an instance descriptor and cannot be
 * consumed by the ordinary development/final runtime path.
 */
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod, lstat, mkdir, mkdtemp, open, readdir, realpath, rename, rm,
} from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
} from '../packages/action/v2/topology.mjs';
import {
  canonicalizeJcs, deriveProfileId, validateProfileCore,
} from '../packages/profile/v2/profile-core.mjs';
import {
  validateV2BetaLocalProfilePackage,
  V2_BETA_LOCAL_ELIGIBILITY,
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../packages/profile/v2/beta-local-profile.mjs';
import {
  buildDirectV2Pf10BetaRuntime,
} from '../packages/unlock-builder/v2/pf10-development-runtime-builder.mjs';
import {
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
} from '../packages/unlock-builder/v2/pf10-action-witness.mjs';
import {
  V2_BETA_PROOF_EVIDENCE_CLASS,
  V2_BETA_PROOF_QUALIFICATION_SCHEMA,
  verifyBetaProofQualification,
} from './v2-beta-proof-qualification.mjs';

export const V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-local-runtime-bundle-v1';
export const V2_PF10_BETA_RUNTIME_MANIFEST = 'beta-runtime-manifest.json';

const ROOT = path.resolve(import.meta.dirname, '../..');
const HASH = /^[0-9a-f]{64}$/u;
const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const SOURCE_NAMES = Object.freeze([
  'profileCore', 'r1cs', 'wasm', 'betaProvingKey', 'verificationKey',
]);
const OPTIONS = Object.freeze({
  '--instance-id': ['instanceId', false],
  '--output': ['outputDirectory', true],
  '--profile-core': ['profileCorePath', true],
  '--profile-package': ['profilePackagePath', true],
  '--qualification-evidence': ['qualificationEvidencePath', true],
  '--temporary-root': ['temporaryRoot', true],
});
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');

export class V2Pf10BetaRuntimeError extends Error {
  constructor(message) { super(message); this.name = 'V2Pf10BetaRuntimeError'; }
}
const fail = (message) => { throw new V2Pf10BetaRuntimeError(message); };
function assertSafeRuntime() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 22 || (major === 22 && minor < 5)) {
    fail('beta runtime requires Node >=22.5.0');
  }
  const benignTestArgument = (entry) => entry === '--test'
    || entry === '--test-reporter=tap'
    || /^--test-concurrency=[1-9][0-9]*$/u.test(entry);
  if (process.execArgv.some((entry) => !benignTestArgument(entry))) {
    fail('beta runtime refuses Node preload, loader, inspector, or evaluator arguments');
  }
  const contaminated = Object.keys(process.env).filter((name) =>
    name === 'NODE_OPTIONS'
      || name === 'NODE_PATH'
      || name === 'NODE_V8_COVERAGE'
      || name.startsWith('LD_')
      || name.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(`beta runtime refuses ambient loader controls: ${contaminated.sort().join(',')}`);
  }
}
const plain = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} must be a plain object`);
  return value;
};
const exact = (value, keys, label) => {
  plain(value, label);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) fail(`${label} has missing or unknown properties`);
  return value;
};
const hash = (value, label) => {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be lowercase SHA-256`);
  return value;
};
const repoRelative = (filename, label) => {
  const relative = path.relative(ROOT, filename);
  if (relative.length === 0 || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) fail(`${label} must be repository-local`);
  return relative.split(path.sep).join('/');
};

export function parseV2Pf10BetaRuntimeArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv)) fail('CLI arguments must be an array');
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index]; const definition = OPTIONS[option];
    if (definition === undefined) fail(`unknown or positional CLI argument: ${String(option)}`);
    const [name, isPath] = definition;
    if (Object.hasOwn(parsed, name)) fail(`duplicate CLI option: ${option}`);
    const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) fail(`missing value for ${option}`);
    parsed[name] = isPath ? path.resolve(cwd, value) : value;
  }
  for (const [option, [name]] of Object.entries(OPTIONS)) if (!Object.hasOwn(parsed, name)) fail(`missing required CLI option: ${option}`);
  if (!HASH.test(parsed.instanceId)) fail('--instance-id must be 32 lowercase hexadecimal bytes');
  return Object.freeze(parsed);
}

export function parseV2Pf10BetaRuntimeVerifyArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length !== 4 || argv[0] !== '--verify' || argv[1] === '--temporary-root') fail('usage: --verify <beta-runtime-directory> --temporary-root <directory>');
  if (argv[2] !== '--temporary-root' || typeof argv[1] !== 'string' || typeof argv[3] !== 'string') fail('usage: --verify <beta-runtime-directory> --temporary-root <directory>');
  return Object.freeze({ outputDirectory: path.resolve(cwd, argv[1]), temporaryRoot: path.resolve(cwd, argv[3]) });
}

async function safeRead(filename, label, { canonicalJson = false, local = false } = {}) {
  const resolved = path.resolve(filename);
  if (local) repoRelative(resolved, label);
  let initial; let canonical;
  try { initial = await lstat(resolved, { bigint: true }); canonical = await realpath(resolved); } catch (error) { fail(`${label} is not readable: ${error.message}`); }
  if (!initial.isFile() || initial.isSymbolicLink() || initial.nlink !== 1n
      || initial.size === 0n || (initial.mode & 0o077n) !== 0n
      || canonical !== resolved
      || initial.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`${label} must be one private, nonempty, canonical, single-link regular file`);
  }
  const handle = await open(resolved, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true }); const bytes = await handle.readFile(); const after = await handle.stat({ bigint: true }); const afterPath = await lstat(resolved, { bigint: true });
    if (before.dev !== initial.dev || before.ino !== initial.ino || after.dev !== initial.dev || after.ino !== initial.ino || afterPath.dev !== initial.dev || afterPath.ino !== initial.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || bytes.length !== Number(before.size)) fail(`${label} changed while it was read`);
    let value;
    if (canonicalJson) {
      try { value = JSON.parse(bytes.toString('utf8')); } catch (error) { fail(`${label} is not JSON: ${error.message}`); }
      if (!bytes.equals(canonicalBytes(value))) fail(`${label} must use exact RFC8785/JCS bytes`);
    }
    return Object.freeze({ filename: resolved, bytes, sha256: sha256(bytes), ...(canonicalJson ? { value } : {}) });
  } finally { await handle.close(); }
}

async function outputStage(outputDirectory) {
  const output = path.resolve(outputDirectory); repoRelative(output, 'output directory');
  try { await lstat(output); fail('output directory must not already exist'); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  const parent = path.dirname(output); repoRelative(parent, 'output parent');
  const relative = repoRelative(parent, 'output parent'); let current = ROOT;
  for (const component of relative.split('/')) {
    current = path.join(current, component);
    let metadata;
    try { metadata = await lstat(current); } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await mkdir(current, { mode: 0o700 }); metadata = await lstat(current);
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || await realpath(current) !== current || (metadata.mode & 0o077) !== 0) fail('output parent must contain only private canonical directories');
  }
  const parentMeta = await lstat(parent);
  if (!parentMeta.isDirectory() || parentMeta.isSymbolicLink() || await realpath(parent) !== parent || (parentMeta.mode & 0o077) !== 0) fail('output parent must be a private canonical directory');
  const stage = await mkdtemp(path.join(parent, '.pf10-beta-runtime-stage-')); await chmod(stage, 0o700);
  return Object.freeze({ output, parent, stage });
}
async function writeExact(filename, bytes) {
  await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  const handle = await open(filename, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
async function copyArtifact(stage, artifacts, id, relative, source) {
  if (artifacts.some((entry) => entry.id === id || entry.path === relative)) fail(`duplicate emitted beta artifact: ${id}`);
  await writeExact(path.join(stage, relative), source.bytes);
  const entry = Object.freeze({ id, path: relative, bytes: source.bytes.length, sha256: sha256(source.bytes) }); artifacts.push(entry); return entry;
}
const artifactRef = (entry) => Object.freeze({ id: entry.id, path: entry.path, bytes: entry.bytes, sha256: entry.sha256 });
const actionFileNames = Object.freeze({ packet: 'packet.bin', input: 'input.json', witness: 'witness.wtns', proof: 'proof.json', publicSignals: 'public.json', v2DirectGroth16Adapter: 'v2-direct-groth16-adapter.json' });

function evidencePath(record, label) {
  exact(record, Object.hasOwn(record, 'pathScope') ? ['bytes', 'path', 'pathScope', 'sha256'] : ['bytes', 'path', 'sha256'], label);
  if (!Number.isSafeInteger(record.bytes) || record.bytes <= 0 || typeof record.path !== 'string' || record.path.length === 0) fail(`${label} file reference is invalid`);
  hash(record.sha256, `${label}.sha256`);
  if (record.pathScope === 'absolute') { if (!path.isAbsolute(record.path) || path.resolve(record.path) !== record.path) fail(`${label} absolute path is invalid`); return record.path; }
  if (record.pathScope !== undefined) fail(`${label} path scope is invalid`);
  const resolved = path.resolve(ROOT, record.path); repoRelative(resolved, label); return resolved;
}
async function evidenceArtifact(record, label) {
  const source = await safeRead(evidencePath(record, label), label, { local: record.pathScope !== 'absolute' });
  if (source.bytes.length !== record.bytes || source.sha256 !== record.sha256) fail(`${label} differs from beta proof evidence`);
  return source;
}
function cloneLocalEvidence(evidence, finalOutput) {
  const copy = structuredClone(evidence);
  const local = (record, relative) => ({ bytes: record.bytes, path: repoRelative(path.join(finalOutput, relative), 'beta runtime evidence'), sha256: record.sha256 });
  copy.sourceArtifacts.profileCore = local(evidence.sourceArtifacts.profileCore, 'profile/profile-core.json');
  copy.sourceArtifacts.r1cs = local(evidence.sourceArtifacts.r1cs, 'proof/main-chipnet.r1cs');
  copy.sourceArtifacts.wasm = local(evidence.sourceArtifacts.wasm, 'proof/main-chipnet.wasm');
  copy.sourceArtifacts.betaProvingKey = local(evidence.sourceArtifacts.betaProvingKey, 'proof/beta.zkey');
  copy.sourceArtifacts.verificationKey = local(evidence.sourceArtifacts.verificationKey, 'proof/verification_key.json');
  for (const action of ACTIONS) for (const [kind, filename] of Object.entries(actionFileNames)) copy.actions[action].files[kind] = local(evidence.actions[action].files[kind], `qualification/actions/${action}/${filename}`);
  return copy;
}

function validateInputBinding({ profile, profilePackage, evidence, instanceId }) {
  validateProfileCore(profile.value);
  const profileId = deriveProfileId(profile.value);
  const checkedPackage = validateV2BetaLocalProfilePackage(profilePackage.value, profile.value);
  if (checkedPackage.profileId !== profileId || checkedPackage.profileCoreSha256 !== profile.sha256) fail('beta profile package differs from supplied beta profile core');
  if (evidence.value.schema !== V2_BETA_PROOF_QUALIFICATION_SCHEMA || evidence.value.evidenceClass !== V2_BETA_PROOF_EVIDENCE_CLASS || evidence.value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY) fail('qualification evidence is not beta proof evidence');
  if (evidence.value.identity?.profileId !== profileId || evidence.value.identity?.instanceId !== instanceId || evidence.value.identity?.maximumLiveNotes !== '32' || evidence.value.identity?.denominationSats !== '10000000') fail('qualification evidence is not bound to this beta profile and instance');
  if (canonicalizeJcs(evidence.value.claims)
      !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)) {
    fail('qualification evidence claims differ from the beta boundary');
  }
  const expected = {
    r1cs: checkedPackage.artifacts.r1cs.sha256,
    wasm: checkedPackage.artifacts.witnessWasm.sha256,
    betaProvingKey: checkedPackage.artifacts.betaProvingKey.sha256,
    verificationKey: checkedPackage.artifacts.verificationKey.sha256,
  };
  for (const [name, expectedHash] of Object.entries(expected)) if (evidence.value.sourceArtifacts?.[name]?.sha256 !== expectedHash) fail(`qualification evidence ${name} differs from beta profile package`);
  if (evidence.value.sourceArtifacts?.profileCore?.sha256 !== profile.sha256) fail('qualification evidence profile core differs from beta profile package');
  return Object.freeze({ profileId, profilePackage: checkedPackage });
}

function claims() { return V2_BETA_LOCAL_FALSE_CLAIMS; }
function manifestValue({ profileId, instanceId, profile, profilePackage, sourceEvidence, localEvidence, artifacts, build, refs }) {
  return Object.freeze({
    schema: V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA,
    status: 'beta-local-runtime-built-unqualified',
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    assuranceClass: 'beta-single-contributor',
    claims: claims(),
    profile: Object.freeze({ profileId, profileCore: artifactRef(refs.profileCore), betaProfilePackage: artifactRef(refs.profilePackage), ceremonyResultSha256: profilePackage.ceremony.resultSha256 }),
    identity: Object.freeze({ instanceId, maximumLiveNotes: '32', denominationSats: '10000000' }),
    proofQualification: Object.freeze({ inputEvidence: artifactRef(refs.inputEvidence), inputEvidenceSha256: sourceEvidence.sha256, localEvidence: artifactRef(refs.localEvidence), betaProvenance: artifactRef(refs.betaProvenance), actionEvidence: Object.freeze(Object.fromEntries(ACTIONS.map((action) => [action, Object.freeze(Object.fromEntries(Object.keys(actionFileNames).map((kind) => [kind, artifactRef(refs.actionEvidence[action][kind])])))]))) }),
    proofArtifacts: Object.freeze(Object.fromEntries(Object.entries(refs.proof).map(([name, entry]) => [name, artifactRef(entry)]))),
    runtime: Object.freeze({ materialSha256: build.runtimeMaterial.materialSha256, material: artifactRef(refs.runtimeMaterial), artifacts: Object.freeze(Object.fromEntries(Object.entries(refs.runtime).map(([name, entry]) => [name, Array.isArray(entry) ? entry.map(artifactRef) : artifactRef(entry)]))), topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES, baseValues: build.baseValues, fixedTables: build.fixedTables, layout: build.layout, programs: build.programs && Object.freeze(Object.fromEntries(Object.entries(build.programs).map(([name, program]) => [name, Array.isArray(program) ? program.map((p) => p.hashes) : program.hashes]))), structural: Object.freeze(Object.fromEntries(Object.entries(refs.structural).map(([name, entry]) => [name, Array.isArray(entry) ? entry.map(artifactRef) : artifactRef(entry)]))), reproducibility: refs.repro }),
    artifacts: Object.freeze([...artifacts].sort((a, b) => a.id.localeCompare(b.id))),
  });
}

async function emitBuild(stage, artifacts, refs, build) {
  refs.runtime = {};
  const put = (id, relative, bytes) => copyArtifact(stage, artifacts, id, relative, { bytes });
  refs.runtimeMaterial = await put('beta-runtime-material', 'runtime/beta-runtime-material.json', canonicalBytes(build.runtimeMaterial));
  for (const [name, bytes] of Object.entries({ bindingLock: build.structural.bindingLock, bindingRedeem: build.structural.bindingRedeem, stateHelper: build.structural.stateHelper, stateUnlock: build.structural.stateUnlock, stateLock: build.structural.stateLock })) refs.structural[name] = await put(`structural-${name}`, `structural/${name}.bin`, bytes);
  refs.structural.verifierLocks = [];
  for (const [index, bytes] of build.structural.verifierLocks.entries()) refs.structural.verifierLocks.push(await put(`structural-verifier-lock-${index}`, `structural/verifier-lock-${index}.bin`, bytes));
  for (const [name, bytes] of Object.entries({ executorBody: build.runtimeMaterialInput.executorBody, fusedRedeem: build.runtimeMaterialInput.fusedRedeem, terminalRedeem: build.runtimeMaterialInput.terminalRedeem })) refs.runtime[name] = await put(`runtime-${name}`, `runtime/${name}.bin`, bytes);
  refs.runtime.exactMsmRedeems = [];
  for (const [index, bytes] of build.runtimeMaterialInput.exactMsmRedeems.entries()) refs.runtime.exactMsmRedeems.push(await put(`runtime-exact-msm-${index}`, `runtime/exact-msm-${index}.bin`, bytes));
  refs.runtime.fixedCarrierPads = [];
  for (const [index, bytes] of build.runtimeMaterialInput.fixedCarrierPads.entries()) refs.runtime.fixedCarrierPads.push(await put(`runtime-fixed-pad-${index}`, `runtime/fixed-carrier-pad-${index}.bin`, bytes));
  for (const [name, program] of Object.entries(build.programs).filter(([name]) => name !== 'fused')) {
    const programs = Array.isArray(program) ? program : [program];
    refs.repro[name] = [];
    for (const [index, entry] of programs.entries()) {
      const suffix = Array.isArray(program) ? `-${index}` : '';
      refs.repro[name].push(Object.freeze({ source: await put(`repro-${name}${suffix}-source`, `reproducibility/${name}${suffix}.cash`, Buffer.from(entry.source, 'utf8')), raw: await put(`repro-${name}${suffix}-raw`, `reproducibility/${name}${suffix}.raw.bin`, entry.raw) }));
    }
  }
  return refs;
}

export async function runV2Pf10BetaRuntime(argv, { cwd = process.cwd(), repositoryRoot = ROOT } = {}) {
  assertSafeRuntime();
  if (path.resolve(repositoryRoot) !== ROOT || await realpath(repositoryRoot) !== ROOT) fail('beta runtime repository root must be the canonical ShieldKit checkout');
  const options = parseV2Pf10BetaRuntimeArguments(argv, cwd);
  const [profile, profilePackage, evidence] = await Promise.all([
    safeRead(options.profileCorePath, 'beta profile core', { canonicalJson: true }),
    safeRead(options.profilePackagePath, 'beta profile package', { canonicalJson: true }),
    safeRead(options.qualificationEvidencePath, 'beta qualification evidence', { canonicalJson: true }),
  ]);
  const binding = validateInputBinding({ profile, profilePackage, evidence, instanceId: options.instanceId });
  // This is deliberately before copying: the candidate evidence must still be
  // independently rehashed and Groth16-verified at its original provenance.
  await verifyBetaProofQualification({ evidencePath: evidence.filename });
  const sources = Object.fromEntries(await Promise.all(SOURCE_NAMES.map(async (name) => [name, await evidenceArtifact(evidence.value.sourceArtifacts[name], `beta source ${name}`)])));
  const provenance = await safeRead(path.join(path.dirname(evidence.filename), evidence.value.betaProvenance?.file ?? ''), 'beta provenance', { canonicalJson: true });
  if (provenance.sha256 !== evidence.value.betaProvenance?.sha256 || provenance.bytes.length !== evidence.value.betaProvenance?.bytes) fail('beta provenance differs from beta proof evidence');
  const actionSources = {};
  for (const action of ACTIONS) { actionSources[action] = {}; for (const kind of Object.keys(actionFileNames)) actionSources[action][kind] = await evidenceArtifact(evidence.value.actions?.[action]?.files?.[kind], `${action}.${kind}`); }
  const target = await outputStage(options.outputDirectory);
  try {
    const artifacts = []; const refs = { proof: {}, actionEvidence: {}, repro: {}, structural: {} };
    refs.profileCore = await copyArtifact(target.stage, artifacts, 'profile-core', 'profile/profile-core.json', profile);
    refs.profilePackage = await copyArtifact(target.stage, artifacts, 'beta-profile-package', 'profile/beta-profile-package.json', profilePackage);
    refs.inputEvidence = await copyArtifact(target.stage, artifacts, 'input-beta-proof-evidence', 'qualification/input-beta-proof-evidence.json', evidence);
    refs.proof.r1cs = await copyArtifact(target.stage, artifacts, 'proof-r1cs', 'proof/main-chipnet.r1cs', sources.r1cs);
    refs.proof.wasm = await copyArtifact(target.stage, artifacts, 'proof-wasm', 'proof/main-chipnet.wasm', sources.wasm);
    refs.proof.provingKey = await copyArtifact(target.stage, artifacts, 'proof-beta-zkey', 'proof/beta.zkey', sources.betaProvingKey);
    refs.proof.verificationKey = await copyArtifact(target.stage, artifacts, 'proof-verification-key', 'proof/verification_key.json', sources.verificationKey);
    refs.betaProvenance = await copyArtifact(target.stage, artifacts, 'beta-provenance', 'qualification/beta-provenance.json', provenance);
    for (const action of ACTIONS) { refs.actionEvidence[action] = {}; for (const [kind, filename] of Object.entries(actionFileNames)) refs.actionEvidence[action][kind] = await copyArtifact(target.stage, artifacts, `qualification-${action}-${kind}`, `qualification/actions/${action}/${filename}`, actionSources[action][kind]); }
    const localEvidence = cloneLocalEvidence(evidence.value, target.output);
    refs.localEvidence = await copyArtifact(target.stage, artifacts, 'beta-proof-evidence', 'qualification/beta-proof-evidence.json', { bytes: canonicalBytes(localEvidence) });
    const build = await buildDirectV2Pf10BetaRuntime({ repositoryRoot: ROOT, temporaryRoot: options.temporaryRoot, profileId: binding.profileId, instanceId: options.instanceId, proofArtifacts: { provingKey: { path: path.join(target.stage, refs.proof.provingKey.path), sha256: refs.proof.provingKey.sha256 }, r1cs: { path: path.join(target.stage, refs.proof.r1cs.path), sha256: refs.proof.r1cs.sha256 }, verificationKey: { path: path.join(target.stage, refs.proof.verificationKey.path), sha256: refs.proof.verificationKey.sha256 }, wasm: { path: path.join(target.stage, refs.proof.wasm.path), sha256: refs.proof.wasm.sha256 } } });
    await emitBuild(target.stage, artifacts, refs, build);
    const manifest = manifestValue({ profileId: binding.profileId, instanceId: options.instanceId, profile, profilePackage: binding.profilePackage, sourceEvidence: evidence, localEvidence, artifacts, build, refs });
    const manifestBytes = canonicalBytes(manifest); await writeExact(path.join(target.stage, V2_PF10_BETA_RUNTIME_MANIFEST), manifestBytes);
    const handle = await open(target.stage, fsConstants.O_RDONLY); try { await handle.sync(); } finally { await handle.close(); }
    await rename(target.stage, target.output); const parent = await open(target.parent, fsConstants.O_RDONLY); try { await parent.sync(); } finally { await parent.close(); }
    return Object.freeze({ outputDirectory: target.output, buildManifestPath: path.join(target.output, V2_PF10_BETA_RUNTIME_MANIFEST), buildManifestSha256: sha256(manifestBytes), profileId: binding.profileId, instanceId: options.instanceId, runtimeMaterialSha256: build.runtimeMaterial.materialSha256, artifactCount: artifacts.length, eligibility: V2_BETA_LOCAL_ELIGIBILITY });
  } catch (error) { await rm(target.stage, { recursive: true, force: true }); throw error; }
}

async function walk(directory, prefix = '') {
  const entries = await readdir(directory, { withFileTypes: true }); const files = [];
  for (const entry of entries) { const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`; const filename = path.join(directory, entry.name); const metadata = await lstat(filename); if (entry.isDirectory()) { if (metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0 || await realpath(filename) !== filename) fail(`beta runtime directory is not private and canonical: ${relative}`); files.push(...await walk(filename, relative)); } else if (entry.isFile()) { if (metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o077) !== 0 || await realpath(filename) !== filename) fail(`beta runtime file is not private, canonical, and single-link: ${relative}`); files.push(relative); } else fail(`beta runtime bundle has unsafe entry: ${relative}`); }
  return files;
}
async function artifactByRef(output, ref, label) {
  exact(ref, ['bytes', 'id', 'path', 'sha256'], label); hash(ref.sha256, `${label}.sha256`);
  const filename = path.resolve(output, ref.path); const relative = path.relative(output, filename);
  if (relative === '' || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) fail(`${label} escapes bundle`);
  const source = await safeRead(filename, label, { local: true }); if (source.bytes.length !== ref.bytes || source.sha256 !== ref.sha256) fail(`${label} differs from beta runtime manifest`); return source;
}
function validateManifest(manifest) {
  exact(manifest, ['artifacts', 'assuranceClass', 'claims', 'eligibility', 'identity', 'profile', 'proofArtifacts', 'proofQualification', 'runtime', 'schema', 'status'], 'beta runtime manifest');
  if (manifest.schema !== V2_PF10_BETA_RUNTIME_BUNDLE_SCHEMA || manifest.status !== 'beta-local-runtime-built-unqualified' || manifest.eligibility !== V2_BETA_LOCAL_ELIGIBILITY || manifest.assuranceClass !== 'beta-single-contributor' || canonicalizeJcs(manifest.claims) !== canonicalizeJcs(claims())) fail('beta runtime manifest boundary is invalid');
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) fail('beta runtime manifest has no artifacts');
  const seen = new Set(); const paths = new Set(); for (const ref of manifest.artifacts) { exact(ref, ['bytes', 'id', 'path', 'sha256'], 'beta runtime artifact'); if (typeof ref.id !== 'string' || seen.has(ref.id) || typeof ref.path !== 'string' || paths.has(ref.path)) fail('beta runtime manifest artifacts are ambiguous'); seen.add(ref.id); paths.add(ref.path); }
  return manifest;
}

function assertManifestArtifactReferences(value, artifacts, label = 'manifest') {
  if (value === null || typeof value !== 'object') return;
  if (!Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === 'bytes,id,path,sha256') {
    const expected = artifacts.get(value.id);
    if (expected === undefined || canonicalizeJcs(expected) !== canonicalizeJcs(value)) fail(`${label} has an unbound artifact reference`);
    return;
  }
  for (const [key, entry] of Object.entries(value)) assertManifestArtifactReferences(entry, artifacts, `${label}.${key}`);
}

export async function verifyV2Pf10BetaRuntime({ outputDirectory, temporaryRoot }) {
  assertSafeRuntime();
  const output = path.resolve(outputDirectory); const rootMeta = await lstat(output); if (!rootMeta.isDirectory() || rootMeta.isSymbolicLink() || (rootMeta.mode & 0o077) !== 0 || await realpath(output) !== output) fail('beta runtime output must be a private canonical directory');
  const manifestFile = await safeRead(path.join(output, V2_PF10_BETA_RUNTIME_MANIFEST), 'beta runtime manifest', { canonicalJson: true, local: true }); const manifest = validateManifest(manifestFile.value);
  const expected = new Set([V2_PF10_BETA_RUNTIME_MANIFEST, ...manifest.artifacts.map((entry) => entry.path)]); const actual = new Set(await walk(output)); if (actual.size !== expected.size || [...actual].some((name) => !expected.has(name))) fail('beta runtime bundle has missing or unmanifested files');
  const artifactMap = new Map(); for (const entry of manifest.artifacts) artifactMap.set(entry.id, entry);
  assertManifestArtifactReferences(manifest, artifactMap);
  for (const entry of manifest.artifacts) await artifactByRef(output, entry, `artifact ${entry.id}`);
  const profile = await artifactByRef(output, manifest.profile.profileCore, 'profile core'); const profilePackage = await artifactByRef(output, manifest.profile.betaProfilePackage, 'beta profile package');
  const profileValue = JSON.parse(profile.bytes.toString('utf8')); validateProfileCore(profileValue); const profileId = deriveProfileId(profileValue); const packageValue = validateV2BetaLocalProfilePackage(JSON.parse(profilePackage.bytes.toString('utf8')), profileValue);
  if (profileId !== manifest.profile.profileId || packageValue.profileId !== profileId || manifest.identity.maximumLiveNotes !== '32' || manifest.identity.denominationSats !== '10000000') fail('beta runtime profile identity is invalid');
  const evidence = await artifactByRef(output, manifest.proofQualification.localEvidence, 'local beta proof evidence');
  const inputEvidence = await artifactByRef(output, manifest.proofQualification.inputEvidence, 'input beta proof evidence');
  if (inputEvidence.sha256 !== manifest.proofQualification.inputEvidenceSha256) fail('input beta proof evidence hash is not bound by the manifest');
  let originalEvidence; let localEvidence;
  try { originalEvidence = JSON.parse(inputEvidence.bytes.toString('utf8')); localEvidence = JSON.parse(evidence.bytes.toString('utf8')); } catch (error) { fail(`beta proof evidence is not JSON: ${error.message}`); }
  if (canonicalizeJcs(cloneLocalEvidence(originalEvidence, output)) !== canonicalizeJcs(localEvidence)) fail('local beta proof evidence is not an exact relocation of the input evidence');
  const verification = await verifyBetaProofQualification({ evidencePath: evidence.filename });
  if (verification.eligibility !== V2_BETA_LOCAL_ELIGIBILITY) fail('local beta proof evidence did not retain beta eligibility');
  const proof = Object.fromEntries(await Promise.all(Object.entries(manifest.proofArtifacts).map(async ([name, ref]) => [name, await artifactByRef(output, ref, `proof ${name}`)])));
  const build = await buildDirectV2Pf10BetaRuntime({ repositoryRoot: ROOT, temporaryRoot, profileId, instanceId: manifest.identity.instanceId, proofArtifacts: { provingKey: { path: proof.provingKey.filename, sha256: proof.provingKey.sha256 }, r1cs: { path: proof.r1cs.filename, sha256: proof.r1cs.sha256 }, verificationKey: { path: proof.verificationKey.filename, sha256: proof.verificationKey.sha256 }, wasm: { path: proof.wasm.filename, sha256: proof.wasm.sha256 } } });
  if (build.runtimeMaterial.materialSha256 !== manifest.runtime.materialSha256 || build.runtimeMaterial.schema !== DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA) fail('beta runtime material does not independently reproduce');
  for (const [name, expectedBytes] of Object.entries({ executorBody: build.runtimeMaterialInput.executorBody, fusedRedeem: build.runtimeMaterialInput.fusedRedeem, terminalRedeem: build.runtimeMaterialInput.terminalRedeem })) { const source = await artifactByRef(output, manifest.runtime.artifacts[name], `runtime ${name}`); if (!source.bytes.equals(Buffer.from(expectedBytes))) fail(`runtime ${name} does not reproduce`); }
  for (const [index, expectedBytes] of build.runtimeMaterialInput.exactMsmRedeems.entries()) { const source = await artifactByRef(output, manifest.runtime.artifacts.exactMsmRedeems[index], `exact MSM ${index}`); if (!source.bytes.equals(Buffer.from(expectedBytes))) fail(`exact MSM ${index} does not reproduce`); }
  for (const [index, expectedBytes] of build.runtimeMaterialInput.fixedCarrierPads.entries()) { const source = await artifactByRef(output, manifest.runtime.artifacts.fixedCarrierPads[index], `fixed carrier pad ${index}`); if (!source.bytes.equals(Buffer.from(expectedBytes))) fail(`fixed carrier pad ${index} does not reproduce`); }
  for (const [name, expectedBytes] of Object.entries({ bindingLock: build.structural.bindingLock, bindingRedeem: build.structural.bindingRedeem, stateHelper: build.structural.stateHelper, stateUnlock: build.structural.stateUnlock, stateLock: build.structural.stateLock })) { const source = await artifactByRef(output, manifest.runtime.structural[name], `structural ${name}`); if (!source.bytes.equals(Buffer.from(expectedBytes))) fail(`structural ${name} does not reproduce`); }
  for (const [index, expectedBytes] of build.structural.verifierLocks.entries()) { const source = await artifactByRef(output, manifest.runtime.structural.verifierLocks[index], `verifier lock ${index}`); if (!source.bytes.equals(Buffer.from(expectedBytes))) fail(`verifier lock ${index} does not reproduce`); }
  for (const [name, program] of Object.entries(build.programs).filter(([name]) => name !== 'fused')) {
    const programs = Array.isArray(program) ? program : [program];
    if (!Array.isArray(manifest.runtime.reproducibility[name]) || manifest.runtime.reproducibility[name].length !== programs.length) fail(`reproducibility ${name} is incomplete`);
    for (const [index, expectedProgram] of programs.entries()) {
      const retained = manifest.runtime.reproducibility[name][index];
      const source = await artifactByRef(output, retained.source, `reproducibility ${name} source ${index}`);
      const raw = await artifactByRef(output, retained.raw, `reproducibility ${name} raw ${index}`);
      if (!source.bytes.equals(Buffer.from(expectedProgram.source, 'utf8')) || !raw.bytes.equals(Buffer.from(expectedProgram.raw))) fail(`reproducibility ${name} does not reproduce`);
    }
  }
  return Object.freeze({ schema: 'shieldkit-v2-direct-pf10-beta-local-runtime-verification-v1', status: 'beta-runtime-reverified-unqualified', eligibility: V2_BETA_LOCAL_ELIGIBILITY, claims: claims(), manifestSha256: manifestFile.sha256, runtimeMaterialSha256: build.runtimeMaterial.materialSha256 });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = process.argv[2] === '--verify'
      ? await verifyV2Pf10BetaRuntime(
        parseV2Pf10BetaRuntimeVerifyArguments(process.argv.slice(2)),
      )
      : await runV2Pf10BetaRuntime(process.argv.slice(2));
    process.stdout.write(
      `${canonicalizeJcs(result)}\n`,
      () => process.exit(0),
    );
  } catch (error) {
    process.stderr.write(
      `V2 beta PF10 runtime failed: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
      () => process.exit(1),
    );
  }
}
