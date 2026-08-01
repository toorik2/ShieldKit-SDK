#!/usr/bin/env node

/**
 * Beta-only local proof evidence. This deliberately shares the real witness,
 * proving, verification, and pinned-adapter path with the development lane,
 * while using a non-interchangeable evidence schema and claim set.
 */
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  realpath,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import * as snarkjs from 'snarkjs';

import {
  createDevelopmentEvidenceManifest,
  DevelopmentProofQualificationError,
  fileEvidence,
  parseQualificationArguments,
  runProofQualification,
  stringifyJsonWithBigInts,
} from './v2-development-proof-qualification.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from '../packages/profile/v2/profile-core.mjs';
import {
  V2_BETA_LOCAL_ELIGIBILITY,
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../packages/profile/v2/beta-local-profile.mjs';
import {
  resolveV2BetaSingleContributorHistoricalCeremony,
} from './v2-beta-single-contributor-ceremony.mjs';

const PROJECT_ROOT = path.resolve(import.meta.dirname, '..');
const HASH = /^[0-9a-f]{64}$/;
const PREFIXED_HASH = /^sha256:[0-9a-f]{64}$/;
const GIT = /^[0-9a-f]{40}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);

export const V2_BETA_PROOF_QUALIFICATION_SCHEMA =
  'shieldkit-v2-direct-beta-groth16-qualification-v1';
export const V2_BETA_PROOF_EVIDENCE_CLASS =
  'deterministic-beta-single-contributor-groth16-integration-evidence';
export const V2_BETA_PROVENANCE_PIN_SCHEMA =
  'shieldkit-v2-beta-local-provenance-pin-v1';
export const V2_BETA_PROVENANCE_PIN_STATUS =
  'beta-local-provenance-cryptographically-reverified-unqualified';

export const V2_BETA_PROOF_CLAIMS = V2_BETA_LOCAL_FALSE_CLAIMS;

export class BetaProofQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BetaProofQualificationError';
  }
}

const fail = (message) => {
  throw new BetaProofQualificationError(message);
};
function assertSafeRuntime() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 22 || (major === 22 && minor < 5)) {
    fail('beta proof qualification requires Node >=22.5.0');
  }
  const benignTestArgument = (entry) => entry === '--test'
    || entry === '--test-reporter=tap'
    || /^--test-concurrency=[1-9][0-9]*$/u.test(entry);
  if (process.execArgv.some((entry) => !benignTestArgument(entry))) {
    fail('beta proof qualification refuses Node preload, loader, inspector, or evaluator arguments');
  }
  const contaminated = Object.keys(process.env).filter((name) =>
    name === 'NODE_OPTIONS'
      || name === 'NODE_PATH'
      || name === 'NODE_V8_COVERAGE'
      || name.startsWith('LD_')
      || name.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(`beta proof qualification refuses ambient loader controls: ${contaminated.sort().join(',')}`);
  }
}
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonicalBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) fail(`${label} must be a plain object`);
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) fail(`${label} has missing or unknown properties`);
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function prefixedHash(value, label) {
  if (typeof value !== 'string' || !PREFIXED_HASH.test(value)) {
    fail(`${label} must be sha256 followed by 32 lowercase hexadecimal bytes`);
  }
  return value;
}

export function serializeV2BetaCanonicalJson(value) {
  return canonicalizeJcs(JSON.parse(stringifyJsonWithBigInts(value)));
}

function repositoryRelative(filename, label) {
  const relative = path.relative(PROJECT_ROOT, filename);
  if (
    relative.length === 0
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) fail(`${label} must be repository-local`);
  return relative.split(path.sep).join('/');
}

async function stablePrivateFileEvidence(
  filename,
  label,
  { readData = false } = {},
) {
  const resolved = path.resolve(filename);
  const initial = await lstat(resolved, { bigint: true });
  if (
    !initial.isFile()
    || initial.isSymbolicLink()
    || initial.nlink !== 1n
    || initial.size <= 0n
    || (initial.mode & 0o077n) !== 0n
    || await realpath(resolved) !== resolved
    || initial.size > BigInt(Number.MAX_SAFE_INTEGER)
  ) fail(`${label} must be a private canonical single-link regular file`);
  const handle = await open(
    resolved,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  const digest = createHash('sha256');
  let bytes = 0;
  const chunks = readData ? [] : undefined;
  try {
    const before = await handle.stat({ bigint: true });
    if (
      before.dev !== initial.dev
      || before.ino !== initial.ino
      || before.size !== initial.size
      || before.mtimeNs !== initial.mtimeNs
      || before.ctimeNs !== initial.ctimeNs
    ) fail(`${label} changed before it was measured`);
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      digest.update(chunk);
      bytes += chunk.length;
      if (readData) chunks.push(Buffer.from(chunk));
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(resolved, { bigint: true });
    for (const current of [after, pathAfter]) {
      if (
        current.dev !== before.dev
        || current.ino !== before.ino
        || current.size !== before.size
        || current.mtimeNs !== before.mtimeNs
        || current.ctimeNs !== before.ctimeNs
      ) fail(`${label} changed while it was measured`);
    }
    if (BigInt(bytes) !== before.size || await realpath(resolved) !== resolved) {
      fail(`${label} byte length or canonical path changed while measured`);
    }
  } finally {
    await handle.close();
  }
  const relative = path.relative(PROJECT_ROOT, resolved);
  const external = relative.length === 0
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative);
  return Object.freeze({
    path: external ? resolved : relative.split(path.sep).join('/'),
    ...(external ? { pathScope: 'absolute' } : {}),
    bytes,
    sha256: digest.digest('hex'),
    ...(readData ? { data: Buffer.concat(chunks, bytes) } : {}),
  });
}

async function readCanonicalRegularJson(filename, label) {
  const resolved = path.resolve(filename);
  const measured = await stablePrivateFileEvidence(
    resolved,
    label,
    { readData: true },
  );
  const bytes = measured.data;
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  if (!bytes.equals(canonicalBytes(value))) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return Object.freeze({
    bytes,
    path: resolved,
    sha256: measured.sha256,
    value,
  });
}

export function validateV2BetaLocalProvenancePin(
  value,
  label = 'beta provenance pin',
) {
  exact(value, [
    'assuranceClass', 'b01ManifestSha256', 'betaProvingKeySha256',
    'ceremonyId', 'claims', 'eligibility', 'entropyPolicySha256',
    'implementationSha256', 'initialZkeySha256', 'powersOfTauSha256',
    'preparationSha256', 'r1csSha256', 'resultSha256',
    'schema', 'source', 'status', 'transcriptFileSha256',
    'transcriptSha256', 'verificationKeySha256',
  ], label);
  if (
    value.schema !== V2_BETA_PROVENANCE_PIN_SCHEMA
    || value.status !== V2_BETA_PROVENANCE_PIN_STATUS
    || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || value.assuranceClass !== 'beta-single-contributor'
    || typeof value.ceremonyId !== 'string'
    || !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(value.ceremonyId)
  ) fail(`${label} schema, status, or ceremony identity is invalid`);
  for (const name of [
    'b01ManifestSha256', 'betaProvingKeySha256', 'entropyPolicySha256',
    'implementationSha256', 'initialZkeySha256', 'powersOfTauSha256',
    'preparationSha256', 'r1csSha256', 'resultSha256',
    'transcriptFileSha256', 'transcriptSha256',
    'verificationKeySha256',
  ]) prefixedHash(value[name], `${label}.${name}`);
  exact(value.source, ['gitCommit', 'gitTree'], `${label}.source`);
  if (!GIT.test(value.source.gitCommit) || !GIT.test(value.source.gitTree)) {
    fail(`${label}.source is invalid`);
  }
  exact(
    value.claims,
    Object.keys(V2_BETA_PROOF_CLAIMS),
    `${label}.claims`,
  );
  if (canonicalizeJcs(value.claims)
      !== canonicalizeJcs(V2_BETA_PROOF_CLAIMS)) {
    fail(`${label}.claims are not the beta-only false qualification set`);
  }
  return Object.freeze({
    ...value,
    claims: V2_BETA_PROOF_CLAIMS,
    source: Object.freeze({ ...value.source }),
  });
}

/** Reduce a full historical ceremony resolution to a portable public pin. */
export function createV2BetaLocalProvenancePin(resolution) {
  exact(resolution, [
    'artifacts', 'assuranceClass', 'b01ManifestSha256',
    'betaProvingKeySha256', 'ceremonyId', 'claims',
    'entropyPolicySha256', 'implementationSha256', 'preparationSha256',
    'resultSha256', 'schema', 'source', 'status', 'transcriptFileSha256',
    'transcriptSha256', 'verificationKeySha256',
  ], 'historical beta ceremony resolution');
  if (
    resolution.schema
      !== 'shieldkit-v2-beta-single-contributor-historical-resolution-v1'
    || resolution.status
      !== 'beta-single-contributor-historical-source-reverified-unqualified'
    || resolution.assuranceClass !== 'beta-single-contributor'
  ) fail('historical beta ceremony resolution boundary is invalid');
  plain(resolution.artifacts, 'historical beta ceremony artifacts');
  if (
    resolution.artifacts.betaProvingKey?.sha256
      !== resolution.betaProvingKeySha256
    || resolution.artifacts.verificationKey?.sha256
      !== resolution.verificationKeySha256
  ) fail('historical beta ceremony artifacts differ from its public hashes');
  plain(resolution.claims, 'historical beta ceremony claims');
  for (const [name, actual] of Object.entries(resolution.claims)) {
    if (actual !== false || V2_BETA_PROOF_CLAIMS[name] !== false) {
      fail(`historical beta ceremony claim is not false: ${name}`);
    }
  }
  return validateV2BetaLocalProvenancePin({
    schema: V2_BETA_PROVENANCE_PIN_SCHEMA,
    status: V2_BETA_PROVENANCE_PIN_STATUS,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    assuranceClass: 'beta-single-contributor',
    claims: V2_BETA_PROOF_CLAIMS,
    ceremonyId: resolution.ceremonyId,
    source: resolution.source,
    b01ManifestSha256: resolution.b01ManifestSha256,
    preparationSha256: resolution.preparationSha256,
    resultSha256: resolution.resultSha256,
    betaProvingKeySha256: resolution.betaProvingKeySha256,
    verificationKeySha256: resolution.verificationKeySha256,
    entropyPolicySha256: resolution.entropyPolicySha256,
    implementationSha256: resolution.implementationSha256,
    initialZkeySha256: resolution.artifacts.initialZkey.sha256,
    powersOfTauSha256: resolution.artifacts.powersOfTau.sha256,
    r1csSha256: resolution.artifacts.r1cs.sha256,
    transcriptFileSha256: resolution.transcriptFileSha256,
    transcriptSha256: resolution.transcriptSha256,
  });
}

export function parseBetaProofQualificationArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv)) fail('CLI arguments must be an array');
  const parsed = {};
  let singleThread = false;
  for (let index = 0; index < argv.length;) {
    const option = argv[index];
    if (option === '--single-thread') {
      if (singleThread) fail('duplicate CLI option: --single-thread');
      singleThread = true;
      index += 1;
      continue;
    }
    const key = {
      '--profile-core': 'profileCore',
      '--r1cs': 'r1cs',
      '--wasm': 'wasm',
      '--beta-zkey': 'zkey',
      '--verification-key': 'verificationKey',
      '--ceremony-dir': 'ceremonyDirectory',
      '--output': 'outputDirectory',
      '--instance-id': 'instanceId',
      '--maximum-live-notes': 'maximumLiveNotes',
    }[option];
    if (key === undefined) fail(`unknown or positional argument: ${String(option)}`);
    if (Object.hasOwn(parsed, key)) fail(`duplicate CLI option: ${option}`);
    const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) {
      fail(`missing value for ${option}`);
    }
    parsed[key] = ['instanceId', 'maximumLiveNotes'].includes(key)
      ? value
      : path.resolve(cwd, value);
    index += 2;
  }
  for (const key of [
    'profileCore', 'r1cs', 'wasm', 'zkey', 'verificationKey',
    'ceremonyDirectory', 'outputDirectory', 'instanceId', 'maximumLiveNotes',
  ]) {
    if (!Object.hasOwn(parsed, key)) fail(`missing required CLI option: ${key}`);
  }
  if (!HASH.test(parsed.instanceId)) fail('--instance-id must be 32 lowercase hexadecimal bytes');
  if (
    !DECIMAL.test(parsed.maximumLiveNotes)
    || BigInt(parsed.maximumLiveNotes) === 0n
    || BigInt(parsed.maximumLiveNotes) > 210_000_000n
  ) fail('--maximum-live-notes must be canonical decimal in [1, 210000000]');
  return Object.freeze({ ...parsed, singleThread });
}

export function parseBetaProofVerificationArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== '--verify') {
    fail('usage: --verify <beta-qualification-evidence.json>');
  }
  if (typeof argv[1] !== 'string' || argv[1].length === 0 || argv[1].startsWith('--')) {
    fail('--verify requires an evidence path');
  }
  return Object.freeze({ evidencePath: path.resolve(cwd, argv[1]) });
}

export function createBetaProofEvidenceManifest({ betaProvenance: provenance, ...value }) {
  if (provenance === undefined) fail('beta provenance pin is required');
  exact(provenance, ['bytes', 'file', 'record', 'sha256'], 'beta provenance evidence');
  if (
    provenance.file !== 'beta-provenance.json'
    || !Number.isSafeInteger(provenance.bytes)
    || provenance.bytes <= 0
    || hash(provenance.sha256, 'beta provenance evidence.sha256') !== provenance.sha256
  ) fail('beta provenance evidence is invalid');
  const parsedProvenance = validateV2BetaLocalProvenancePin(
    provenance.record,
  );
  const developmentChecked = createDevelopmentEvidenceManifest({
    ...value,
    sourceArtifacts: Object.freeze({
      profileCore: value.sourceArtifacts.profileCore,
      r1cs: value.sourceArtifacts.r1cs,
      wasm: value.sourceArtifacts.wasm,
      developmentZkey: value.sourceArtifacts.betaProvingKey,
      verificationKey: value.sourceArtifacts.verificationKey,
    }),
  });
  if (
    parsedProvenance.betaProvingKeySha256.slice(7)
      !== value.sourceArtifacts.betaProvingKey.sha256
    || parsedProvenance.verificationKeySha256.slice(7)
      !== value.sourceArtifacts.verificationKey.sha256
    || parsedProvenance.r1csSha256.slice(7)
      !== value.sourceArtifacts.r1cs.sha256
  ) fail('beta provenance pin does not bind the supplied beta zkey and verification key');
  return Object.freeze({
    schema: V2_BETA_PROOF_QUALIFICATION_SCHEMA,
    evidenceClass: V2_BETA_PROOF_EVIDENCE_CLASS,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    claims: V2_BETA_PROOF_CLAIMS,
    fixture: developmentChecked.fixture,
    identity: developmentChecked.identity,
    versions: developmentChecked.versions,
    prover: developmentChecked.prover,
    sourceArtifacts: Object.freeze({
      profileCore: value.sourceArtifacts.profileCore,
      r1cs: value.sourceArtifacts.r1cs,
      wasm: value.sourceArtifacts.wasm,
      betaProvingKey: value.sourceArtifacts.betaProvingKey,
      verificationKey: value.sourceArtifacts.verificationKey,
    }),
    betaProvenance: Object.freeze({
      bytes: provenance.bytes,
      file: provenance.file,
      schema: parsedProvenance.schema,
      sha256: provenance.sha256,
    }),
    actions: developmentChecked.actions,
    measurements: developmentChecked.measurements,
  });
}

export async function runBetaProofQualification(configuration) {
  assertSafeRuntime();
  const resolution = await resolveV2BetaSingleContributorHistoricalCeremony({
    ceremonyDirectory: configuration.ceremonyDirectory,
  });
  const provenance = createV2BetaLocalProvenancePin(resolution);
  const provenanceBytes = canonicalBytes(provenance);
  const provenanceSha256 = sha256(provenanceBytes);
  const suppliedCeremonyArtifacts = Object.fromEntries(await Promise.all(
    [
      ['profileCore', configuration.profileCore],
      ['r1cs', configuration.r1cs],
      ['wasm', configuration.wasm],
      ['betaProvingKey', configuration.zkey],
      ['verificationKey', configuration.verificationKey],
    ].map(async ([name, filename]) => [
      name,
      await stablePrivateFileEvidence(filename, `beta source ${name}`),
    ]),
  ));
  if (
    suppliedCeremonyArtifacts.r1cs.sha256
      !== provenance.r1csSha256.slice(7)
    || suppliedCeremonyArtifacts.betaProvingKey.sha256
      !== provenance.betaProvingKeySha256.slice(7)
    || suppliedCeremonyArtifacts.verificationKey.sha256
      !== provenance.verificationKeySha256.slice(7)
  ) fail('supplied proof artifacts differ from the reverified beta ceremony');
  const betaProvenanceEvidence = Object.freeze({
    bytes: provenanceBytes.length,
    file: 'beta-provenance.json',
    record: provenance,
    sha256: provenanceSha256,
  });
  const result = await runProofQualification(configuration, {
    artifactFileEvidence: (filename) => fileEvidence(filename, {
      allowExternal: true,
    }),
    beforeEvidenceWrite: async ({ outputDirectory }) => {
      await writeFile(
        path.join(outputDirectory, betaProvenanceEvidence.file),
        provenanceBytes,
        { flag: 'wx', mode: 0o600 },
      );
    },
    createEvidenceManifest: (value) => createBetaProofEvidenceManifest({
      ...value,
      betaProvenance: betaProvenanceEvidence,
      sourceArtifacts: Object.freeze({
        profileCore: value.sourceArtifacts.profileCore,
        r1cs: value.sourceArtifacts.r1cs,
        wasm: value.sourceArtifacts.wasm,
        betaProvingKey: value.sourceArtifacts.developmentZkey,
        verificationKey: value.sourceArtifacts.verificationKey,
      }),
    }),
    serialize: serializeV2BetaCanonicalJson,
    sourceFileEvidence: (filename) => {
      const resolved = path.resolve(filename);
      const name = [
        ['profileCore', configuration.profileCore],
        ['r1cs', configuration.r1cs],
        ['wasm', configuration.wasm],
        ['betaProvingKey', configuration.zkey],
        ['verificationKey', configuration.verificationKey],
      ].find(([, candidate]) => path.resolve(candidate) === resolved)?.[0];
      if (name === undefined) fail('proof runner requested an unknown beta source');
      return suppliedCeremonyArtifacts[name];
    },
  });
  for (const [name, filename] of [
    ['profileCore', configuration.profileCore],
    ['r1cs', configuration.r1cs],
    ['wasm', configuration.wasm],
    ['betaProvingKey', configuration.zkey],
    ['verificationKey', configuration.verificationKey],
  ]) {
    const after = await stablePrivateFileEvidence(
      filename,
      `beta source ${name} after proving`,
    );
    if (
      after.bytes !== suppliedCeremonyArtifacts[name].bytes
      || after.sha256 !== suppliedCeremonyArtifacts[name].sha256
    ) fail(`beta ceremony artifact changed during proving: ${name}`);
  }
  return Object.freeze({
    ...result,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
  });
}

function evidenceFilePath(record, label) {
  const { path: relative, pathScope = 'repository' } = record;
  if (typeof relative !== 'string' || relative.length === 0) fail(`${label} path is invalid`);
  if (pathScope === 'absolute') {
    if (!path.isAbsolute(relative) || path.resolve(relative) !== relative) {
      fail(`${label} absolute path is invalid`);
    }
    return relative;
  }
  if (pathScope !== 'repository') fail(`${label} path scope is invalid`);
  const absolute = path.resolve(PROJECT_ROOT, relative);
  if (
    absolute === PROJECT_ROOT
    || !absolute.startsWith(`${PROJECT_ROOT}${path.sep}`)
  ) fail(`${label} escapes the repository`);
  return absolute;
}

async function rehashEvidenceFile(record, label) {
  plain(record, label);
  const keys = Object.keys(record).sort();
  const expected = Object.hasOwn(record, 'pathScope')
    ? ['bytes', 'path', 'pathScope', 'sha256']
    : ['bytes', 'path', 'sha256'];
  if (JSON.stringify(keys) !== JSON.stringify(expected)) {
    fail(`${label} has missing or unknown properties`);
  }
  if (
    !Number.isSafeInteger(record.bytes)
    || record.bytes <= 0
    || !HASH.test(record.sha256)
  ) fail(`${label} file evidence is invalid`);
  const filename = evidenceFilePath(record, label);
  const measured = await stablePrivateFileEvidence(
    filename,
    label,
    { readData: true },
  );
  if (measured.bytes !== record.bytes || measured.sha256 !== record.sha256) {
    fail(`${label} hash or byte length differs from evidence`);
  }
  return Object.freeze({ bytes: measured.data, filename });
}

function validateBetaEvidence(value) {
  exact(value, [
    'actions', 'betaProvenance', 'claims', 'evidenceClass', 'eligibility',
    'fixture', 'identity', 'measurements', 'prover', 'schema',
    'sourceArtifacts', 'versions',
  ], 'beta qualification evidence');
  if (
    value.schema !== V2_BETA_PROOF_QUALIFICATION_SCHEMA
    || value.evidenceClass !== V2_BETA_PROOF_EVIDENCE_CLASS
    || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
  ) fail('beta qualification evidence identity or claims are invalid');
  exact(
    value.claims,
    Object.keys(V2_BETA_PROOF_CLAIMS),
    'beta evidence claims',
  );
  for (const [name, expected] of Object.entries(V2_BETA_PROOF_CLAIMS)) {
    if (value.claims[name] !== expected) {
      fail(`beta evidence claims.${name} is invalid`);
    }
  }
  exact(value.identity, ['denominationSats', 'instanceId', 'maximumLiveNotes', 'profileId'], 'beta evidence identity');
  if (
    !HASH.test(value.identity.profileId)
    || !HASH.test(value.identity.instanceId)
    || !DECIMAL.test(value.identity.maximumLiveNotes)
    || value.identity.denominationSats !== '10000000'
  ) fail('beta evidence identity is invalid');
  exact(value.sourceArtifacts, [
    'betaProvingKey', 'profileCore', 'r1cs', 'verificationKey', 'wasm',
  ], 'beta evidence source artifacts');
  exact(value.betaProvenance, ['bytes', 'file', 'schema', 'sha256'], 'beta evidence provenance');
  if (
    value.betaProvenance.file !== 'beta-provenance.json'
    || value.betaProvenance.schema !== V2_BETA_PROVENANCE_PIN_SCHEMA
    || !Number.isSafeInteger(value.betaProvenance.bytes)
    || value.betaProvenance.bytes <= 0
    || !HASH.test(value.betaProvenance.sha256)
  ) fail('beta evidence provenance record is invalid');
  const actionNames = Object.keys(value.actions).sort();
  if (JSON.stringify(actionNames) !== JSON.stringify([...ACTIONS].sort())) {
    fail('beta evidence must contain deposit, transfer, and withdrawal');
  }
  return value;
}

/** Rehash every referenced artifact and re-run Groth16 verification offline. */
export async function verifyBetaProofQualification({ evidencePath }) {
  assertSafeRuntime();
  const evidenceFile = await readCanonicalRegularJson(
    evidencePath,
    'beta qualification evidence',
  );
  const evidence = validateBetaEvidence(evidenceFile.value);
  const sources = {};
  for (const [name, record] of Object.entries(evidence.sourceArtifacts)) {
    sources[name] = await rehashEvidenceFile(record, `sourceArtifacts.${name}`);
  }
  const profileCore = JSON.parse(sources.profileCore.bytes.toString('utf8'));
  try {
    validateProfileCore(profileCore);
  } catch (error) {
    fail(`profile core is invalid: ${error.message}`);
  }
  if (
    deriveProfileId(profileCore) !== evidence.identity.profileId
    || profileCore.proof.r1csSha256 !== evidence.sourceArtifacts.r1cs.sha256
    || profileCore.proof.witnessWasmSha256 !== evidence.sourceArtifacts.wasm.sha256
    || profileCore.proof.verificationKeySha256
      !== evidence.sourceArtifacts.verificationKey.sha256
  ) fail('profile core does not bind beta evidence identity and proof artifacts');
  const provenancePath = path.join(
    path.dirname(evidenceFile.path),
    evidence.betaProvenance.file,
  );
  const provenanceFile = await readCanonicalRegularJson(
    provenancePath,
    'copied beta provenance pin',
  );
  if (
    provenanceFile.bytes.length !== evidence.betaProvenance.bytes
    || provenanceFile.sha256 !== evidence.betaProvenance.sha256
  ) fail('copied beta provenance pin differs from evidence');
  const provenance = validateV2BetaLocalProvenancePin(provenanceFile.value);
  if (
    provenance.betaProvingKeySha256.slice(7)
      !== evidence.sourceArtifacts.betaProvingKey.sha256
    || provenance.verificationKeySha256.slice(7)
      !== evidence.sourceArtifacts.verificationKey.sha256
  ) fail('copied beta provenance pin differs from beta proof artifacts');
  let verificationKey;
  try {
    verificationKey = JSON.parse(sources.verificationKey.bytes.toString('utf8'));
  } catch (error) {
    fail(`verification key is not JSON: ${error.message}`);
  }
  for (const name of ACTIONS) {
    const action = evidence.actions[name];
    if (action?.witnessValid !== true || action?.proofVerified !== true) {
      fail(`${name} is not a fully verified beta proof`);
    }
    const files = {};
    for (const kind of [
      'packet', 'input', 'witness', 'proof', 'publicSignals',
      'v2DirectGroth16Adapter',
    ]) files[kind] = await rehashEvidenceFile(action.files?.[kind], `${name}.${kind}`);
    if (
      files.packet.bytes.length !== 552
      || sha256(files.packet.bytes) !== action.packetDigest
      || files.packet.bytes.length !== action.files.packet.bytes
    ) fail(`${name} packet differs from evidence`);
    let proof;
    let publicSignals;
    try {
      proof = JSON.parse(files.proof.bytes.toString('utf8'));
      publicSignals = JSON.parse(files.publicSignals.bytes.toString('utf8'));
    } catch (error) {
      fail(`${name} proof or public signals are not JSON: ${error.message}`);
    }
    if (
      !Array.isArray(publicSignals)
      || publicSignals.length !== 2
      || publicSignals.some((entry, index) => String(entry) !== action.publicInputs[index])
      || action.publicInputs.length !== 2
      || action.publicInputs.some((entry) => !DECIMAL.test(entry) || BigInt(entry) > MAX_U128)
    ) fail(`${name} public inputs are invalid or differ from evidence`);
    if (!(await snarkjs.groth16.verify(verificationKey, publicSignals, proof))) {
      fail(`${name} Groth16 verification returned false`);
    }
  }
  return Object.freeze({
    schema: 'shieldkit-v2-direct-beta-groth16-qualification-verification-v1',
    evidenceSha256: evidenceFile.sha256,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    profileId: evidence.identity.profileId,
    instanceId: evidence.identity.instanceId,
    maximumLiveNotes: evidence.identity.maximumLiveNotes,
    status: 'beta-proof-qualification-reverified-unqualified',
    claims: V2_BETA_PROOF_CLAIMS,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = process.argv[2] === '--verify'
      ? await verifyBetaProofQualification(
        parseBetaProofVerificationArguments(process.argv.slice(2)),
      )
      : await runBetaProofQualification(
        parseBetaProofQualificationArguments(process.argv.slice(2)),
      );
    process.stdout.write(`${canonicalizeJcs(result)}\n`);
  } catch (error) {
    process.stderr.write(
      `V2 beta proof qualification failed: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
      () => { process.exitCode = 1; },
    );
  }
}
