#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import {
  createReadStream,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import path from 'node:path';
import { chmod, mkdtemp, open, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const EXTERNAL_FIXTURE_TESTS = new Map([
  ['packages/action/assemble.profile-v2.test.mjs', 'authenticated profile-v2 bundle'],
  ['packages/action/witness.test.mjs', 'authenticated prover bundle/WASM/generator'],
  ['packages/kit/desktop.test.mjs', 'authenticated desktop profile bundle'],
  ['packages/kit/kit.test.mjs', 'local authenticated playground profile bundle'],
  ['packages/kit/pool-act-fail-closed.test.mjs', 'ticket10 live pool and wallet fixtures'],
  ['packages/profile/instance.test.mjs', 'local playground-matching profile bundle'],
  ['packages/prove/lab/verifier-generator.test.mjs', 'local hash-pinned PF7 provenance archive'],
]);
const SCRIPT_STYLE_TESTS = new Set([
  'packages/action/v2/typescript/parity.test.mjs',
]);
// These are deterministic, local-only campaigns. They deliberately remain
// runnable from a clean source checkout, but are opt-in rather than part of
// the portable CI latency budget. Their classification is explicit so they
// cannot be silently omitted or mistaken for an external/release gate.
const LOCAL_CAMPAIGN_TESTS = new Map([
  [
    'packages/action/v2/strict-codec-qualification.test.mjs',
    'exhaustively mutates all 128 state bytes and all 552 packet bytes',
  ],
  [
    'packages/action/v2/typescript/parity.test.mjs',
    'compiles the independent TypeScript codec and repeats the strict codec mutation corpus',
  ],
  [
    'packages/action/v2/tree-qualification-depth4.test.mjs',
    'runs the bounded 13,700-trace / 82,201-store-replay depth-4 structural campaign',
  ],
  [
    'packages/pool/v2/qualification/depth4-production-state-space.test.mjs',
    'exhaustively checks the production Poseidon depth-4 state space, including durable SQLite replay',
  ],
]);
// `node:test` gives the full production depth-4 state-space check five minutes.
// The process supervisor must permit that declared test timeout plus TAP/SQLite
// teardown; a blanket 180-second supervisor limit would kill a healthy test
// before node:test can report its own result. This is a test-class policy, not
// an opt-out: the corresponding CI job invokes the entire campaign suite.
const FILE_TIMEOUT_MS_BY_CLASSIFICATION = Object.freeze({
  'local-depth4-campaign': 360_000,
});
const VENDORED_VERIFIER_LANE_TEST_ROOT = 'packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/test';
const VENDORED_VERIFIER_EXTERNAL_TESTS = new Set([
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/legacy-c7-config.test.mjs`,
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/pairfold-8-plan.test.mjs`,
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/pf6-terminal-profile.test.mjs`,
  `${VENDORED_VERIFIER_LANE_TEST_ROOT}/shortlist-architectures.test.mjs`,
]);
const MATERIALIZED_UNLOCK_TOOLCHAIN = Object.freeze([
  'packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js',
]);
const DEVELOPMENT_ARTIFACT_ROOTS = Object.freeze([
  '../.codex-build/v2-circuit-model',
  '../.codex-build/v2-dev-groth16',
  '../.codex-build/v2-dev-proof-qualification',
  '../.codex-build/v2-dev-ptau',
  '../.codex-build/v2-development-profile',
  '../.codex-build/v2-pf10-development-runtime',
]);
const ARTIFACT_QUALIFICATION_TESTS = new Map([
  ['packages/unlock-builder/v2/pf10-withdrawal.test.mjs', Object.freeze([
    '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-dev-groth16/final.zkey',
    '../.codex-build/v2-dev-groth16/setup-metadata.json',
    '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '../.codex-build/v2-dev-proof-qualification/qualification-evidence.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/packet.bin',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/input.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/proof.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/public.json',
  ])],
  ['packages/unlock-builder/v2/total-pairfold.test.mjs', Object.freeze([
    '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-dev-groth16/final.zkey',
    '../.codex-build/v2-dev-groth16/setup-metadata.json',
    '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '../.codex-build/v2-dev-proof-qualification/qualification-evidence.json',
    '../.codex-build/v2-dev-proof-qualification/deposit/packet.bin',
    '../.codex-build/v2-dev-proof-qualification/deposit/input.json',
    '../.codex-build/v2-dev-proof-qualification/deposit/proof.json',
    '../.codex-build/v2-dev-proof-qualification/deposit/public.json',
  ])],
]);
const DEVELOPMENT_SETUP_SCHEMA = 'shield.cash/local-development-setup/v1';
const DEVELOPMENT_PROOF_EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-development-groth16-qualification-v4';
const DEVELOPMENT_PROOF_EVIDENCE_CLASS =
  'deterministic-development-key-proof-test-evidence';
const DEVELOPMENT_ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const SHA256 = /^[0-9a-f]{64}$/;
const SUITES = new Set([
  'portable',
  'external-fixtures',
  'external-verifier-source',
  'local-covenants',
  'local-verifier-lane',
  'local-strict-codec-campaign',
  'local-depth4-campaign',
]);
const SKIP_OR_TODO_SOURCE = /(?:\b(?:test|it|describe|suite|t)\s*\.\s*(?:skip|todo)\s*\(|\b(?:skip|todo)\s*:)/;
const NODE_TEST_DECLARATION = /\b(?:test|it|describe|suite)\s*\(/;
const DOMAIN_TEST_TEMP_PREFIX = 'domain-test-run-';
const managedDomainTestTemporaryDirectories = new Map();

export class DomainTestRunnerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DomainTestRunnerError';
  }
}
const fail = (message) => { throw new DomainTestRunnerError(message); };
const posix = (value) => value.split(path.sep).join('/');

function requiredObject(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  return value;
}

function requiredHash(value, label, { prefixed = false } = {}) {
  const expression = prefixed ? /^sha256:([0-9a-f]{64})$/ : SHA256;
  const match = typeof value === 'string' ? value.match(expression) : null;
  if (match === null) fail(`${label} must be a lowercase SHA-256 hash`);
  return prefixed ? match[1] : value;
}

function requiredBoolean(value, label) {
  if (typeof value !== 'boolean') fail(`${label} must be boolean`);
  return value;
}

function requiredPublicInputs(value, label) {
  if (
    !Array.isArray(value)
    || value.length !== 2
    || value.some((entry) => typeof entry !== 'string' || !/^(0|[1-9][0-9]*)$/.test(entry))
  ) {
    fail(`${label} must be exactly two canonical decimal public inputs`);
  }
  return value;
}

function readJson(filename, label) {
  let metadata;
  try {
    metadata = lstatSync(filename);
  } catch {
    fail(`${label} is missing`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) {
    fail(`${label} must be a nonempty regular non-symlink file`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(filename, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return requiredObject(parsed, label);
}

function artifactPathSet(projectRoot, overrides) {
  if (overrides !== undefined) {
    const expectedKeys = [
      'evidence',
      'evidenceRoot',
      'r1cs',
      'setupMetadata',
      'verificationKey',
      'wasm',
      'zkey',
    ];
    const actualKeys = Object.keys(requiredObject(
      overrides,
      'local verifier artifact path overrides',
    )).sort();
    if (
      actualKeys.length !== expectedKeys.length
      || actualKeys.some((key, index) => key !== expectedKeys[index])
    ) {
      fail('local verifier artifact path overrides have missing or unknown properties');
    }
    for (const key of expectedKeys) {
      if (
        typeof overrides[key] !== 'string'
        || !path.isAbsolute(overrides[key])
        || path.normalize(overrides[key]) !== overrides[key]
      ) {
        fail(`local verifier artifact path override ${key} must be an absolute normalized path`);
      }
    }
    return Object.freeze({
      r1cs: overrides.r1cs,
      wasm: overrides.wasm,
      setupMetadata: overrides.setupMetadata,
      zkey: overrides.zkey,
      verificationKey: overrides.verificationKey,
      evidence: overrides.evidence,
      action: (name, filename) => path.join(
        overrides.evidenceRoot,
        name,
        filename,
      ),
    });
  }
  const root = path.resolve(projectRoot, '..', '.codex-build');
  const model = path.join(root, 'v2-circuit-model');
  const setup = path.join(root, 'v2-dev-groth16');
  const evidence = path.join(root, 'v2-dev-proof-qualification');
  return Object.freeze({
    r1cs: path.join(model, 'main-chipnet.r1cs'),
    wasm: path.join(model, 'main-chipnet_js', 'main-chipnet.wasm'),
    setupMetadata: path.join(setup, 'setup-metadata.json'),
    zkey: path.join(setup, 'final.zkey'),
    verificationKey: path.join(setup, 'verification_key.json'),
    evidence: path.join(evidence, 'qualification-evidence.json'),
    action: (name, filename) => path.join(evidence, name, filename),
  });
}

async function sha256RegularFile(filename, label) {
  let metadata;
  try {
    metadata = lstatSync(filename);
  } catch {
    fail(`${label} is missing`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) {
    fail(`${label} must be a nonempty regular non-symlink file`);
  }
  const digest = await new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filename, { highWaterMark: 64 * 1024 });
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  }).catch(() => fail(`${label} cannot be hashed`));
  return Object.freeze({ bytes: metadata.size, sha256: digest });
}

async function assertEvidenceFile(filename, evidence, label) {
  const source = requiredObject(evidence, label);
  const expected = requiredHash(source.sha256, `${label}.sha256`);
  if (!Number.isSafeInteger(source.bytes) || source.bytes <= 0) {
    fail(`${label}.bytes must be a positive safe integer`);
  }
  const actual = await sha256RegularFile(filename, label);
  if (actual.bytes !== source.bytes || actual.sha256 !== expected) {
    fail(`${label} differs from the qualification evidence`);
  }
  return actual;
}

/**
 * Bind every artifact consumed by the local verifier lane to one current
 * circuit/setup/proof evidence set. This intentionally does not regenerate:
 * stale or partial generated state is BLOCKED for a clean explicit rebuild.
 */
async function inspectLocalVerifierArtifactCoherence({
  projectRoot = project,
  artifactPaths,
} = {}) {
  const files = artifactPathSet(projectRoot, artifactPaths);
  const [r1cs, wasm, zkey, verificationKey] = await Promise.all([
    sha256RegularFile(files.r1cs, 'local verifier R1CS'),
    sha256RegularFile(files.wasm, 'local verifier witness WASM'),
    sha256RegularFile(files.zkey, 'local verifier proving key'),
    sha256RegularFile(files.verificationKey, 'local verifier verification key'),
  ]);
  const setup = readJson(files.setupMetadata, 'local verifier setup metadata');
  if (setup.schema !== DEVELOPMENT_SETUP_SCHEMA || setup.mode !== 'development-only') {
    fail('local verifier setup metadata schema or mode is unsupported');
  }
  const setupR1cs = requiredObject(setup.inputs, 'local verifier setup metadata.inputs').r1cs;
  const setupOutputs = requiredObject(setup.outputs, 'local verifier setup metadata.outputs');
  if (
    requiredHash(requiredObject(setupR1cs, 'local verifier setup metadata.inputs.r1cs').sha256,
      'local verifier setup metadata.inputs.r1cs.sha256', { prefixed: true }) !== r1cs.sha256
    || requiredHash(requiredObject(setupOutputs.provingKey, 'local verifier setup metadata.outputs.provingKey').sha256,
      'local verifier setup metadata.outputs.provingKey.sha256', { prefixed: true }) !== zkey.sha256
    || requiredHash(requiredObject(setupOutputs.verificationKey, 'local verifier setup metadata.outputs.verificationKey').sha256,
      'local verifier setup metadata.outputs.verificationKey.sha256', { prefixed: true }) !== verificationKey.sha256
  ) {
    fail('local verifier setup metadata does not bind the current R1CS, zkey, and verification key');
  }
  const setupPhase2 = requiredObject(
    requiredObject(setup.setup, 'local verifier setup metadata.setup').material,
    'local verifier setup metadata.setup.material',
  ).phase2;
  if (
    requiredHash(requiredObject(setupPhase2, 'local verifier setup metadata.setup.material.phase2').finalZkeySha256,
      'local verifier setup metadata.setup.material.phase2.finalZkeySha256', { prefixed: true }) !== zkey.sha256
  ) {
    fail('local verifier setup phase2 record does not bind the current zkey');
  }

  const evidence = readJson(files.evidence, 'local verifier qualification evidence');
  if (
    evidence.schema !== DEVELOPMENT_PROOF_EVIDENCE_SCHEMA
    || evidence.evidenceClass !== DEVELOPMENT_PROOF_EVIDENCE_CLASS
  ) {
    fail('local verifier qualification evidence schema is unsupported; clean regeneration is required');
  }
  const source = requiredObject(evidence.sourceArtifacts, 'local verifier qualification evidence.sourceArtifacts');
  const expectedSources = Object.freeze({
    r1cs,
    wasm,
    developmentZkey: zkey,
    verificationKey,
  });
  for (const [name, actual] of Object.entries(expectedSources)) {
    await assertEvidenceFile(files[name === 'developmentZkey' ? 'zkey' : name], source[name],
      `local verifier qualification evidence.sourceArtifacts.${name}`);
    if (source[name].sha256 !== actual.sha256 || source[name].bytes !== actual.bytes) {
      fail(`local verifier qualification evidence source ${name} is incoherent`);
    }
  }
  const claims = requiredObject(evidence.claims, 'local verifier qualification evidence.claims');
  if (
    requiredBoolean(claims.developmentKey, 'local verifier qualification evidence.claims.developmentKey') !== true
    || requiredBoolean(claims.finalKey, 'local verifier qualification evidence.claims.finalKey') !== false
    || requiredBoolean(claims.bchVm, 'local verifier qualification evidence.claims.bchVm') !== false
    || requiredBoolean(claims.production, 'local verifier qualification evidence.claims.production') !== false
  ) {
    fail('local verifier qualification evidence claims are unsupported');
  }
  const actions = requiredObject(evidence.actions, 'local verifier qualification evidence.actions');
  if (
    Object.keys(actions).sort().join(',') !== DEVELOPMENT_ACTIONS.join(',')
  ) {
    fail('local verifier qualification evidence actions are incomplete');
  }
  for (const name of DEVELOPMENT_ACTIONS) {
    const action = requiredObject(actions[name], `local verifier qualification evidence.actions.${name}`);
    if (
      requiredBoolean(action.witnessValid, `local verifier qualification evidence.actions.${name}.witnessValid`) !== true
      || requiredBoolean(action.proofVerified, `local verifier qualification evidence.actions.${name}.proofVerified`) !== true
    ) {
      fail(`local verifier qualification evidence action ${name} is not verified`);
    }
    const publicInputs = requiredPublicInputs(action.publicInputs,
      `local verifier qualification evidence.actions.${name}.publicInputs`);
    const actionFiles = requiredObject(action.files,
      `local verifier qualification evidence.actions.${name}.files`);
    for (const [field, filename] of Object.entries({
      packet: 'packet.bin', input: 'input.json', witness: 'witness.wtns',
      proof: 'proof.json', publicSignals: 'public.json', v2DirectGroth16Adapter: 'v2-direct-groth16-adapter.json',
    })) {
      await assertEvidenceFile(files.action(name, filename), actionFiles[field],
        `local verifier qualification evidence.actions.${name}.files.${field}`);
    }
    if (actionFiles.packet.bytes !== 552) {
      fail(`local verifier qualification evidence action ${name} packet has the wrong byte length`);
    }
    if (requiredHash(action.packetDigest,
      `local verifier qualification evidence.actions.${name}.packetDigest`)
      !== actionFiles.packet.sha256) {
      fail(`local verifier qualification evidence action ${name} packet digest is incoherent`);
    }
    let input;
    let publicSignals;
    try {
      input = JSON.parse(readFileSync(files.action(name, 'input.json'), 'utf8'));
      publicSignals = JSON.parse(readFileSync(files.action(name, 'public.json'), 'utf8'));
    } catch {
      fail(`local verifier qualification action ${name} input/public JSON is invalid`);
    }
    if (
      !Array.isArray(publicSignals)
      || publicSignals.length !== 2
      || publicSignals.some((value, index) => String(value) !== publicInputs[index])
      || String(input?.publicInput0) !== publicInputs[0]
      || String(input?.publicInput1) !== publicInputs[1]
    ) {
      fail(`local verifier qualification action ${name} verifier inputs differ from the evidence`);
    }
  }
  return Object.freeze({ r1cs: r1cs.sha256, wasm: wasm.sha256, zkey: zkey.sha256, verificationKey: verificationKey.sha256 });
}

export async function assertLocalVerifierArtifactCoherence(options = {}) {
  try {
    return await inspectLocalVerifierArtifactCoherence(options);
  } catch (error) {
    if (error instanceof DomainTestRunnerError) {
      fail(
        `local verifier artifact coherence is BLOCKED: ${error.message}. `
        + 'Cleanly regenerate the complete circuit/setup/proof evidence set; do not mix artifacts.',
      );
    }
    throw error;
  }
}

function classify(relativePath) {
  const externalReason = EXTERNAL_FIXTURE_TESTS.get(relativePath);
  if (externalReason !== undefined) {
    return Object.freeze({
      classification: 'external-fixture',
      reason: `${externalReason}; run only via test:external:fixtures`,
    });
  }
  if (relativePath.startsWith('packages/prove/internal/covenants/')) {
    return Object.freeze({
      classification: 'local-covenant-qualification',
      reason: 'requires the explicitly materialized vendored qualification toolchain',
    });
  }
  if (VENDORED_VERIFIER_EXTERNAL_TESTS.has(relativePath)) {
    return Object.freeze({
      classification: 'external-verifier-source-qualification',
      reason: 'requires the omitted full verifier packages/build or packages/contracts source snapshot; test:external:verifier-source fails closed until that source is restored',
    });
  }
  if (relativePath.startsWith(`${VENDORED_VERIFIER_LANE_TEST_ROOT}/`)) {
    return Object.freeze({
      classification: 'local-verifier-lane-qualification',
      reason: 'tracked pinned BN254 verifier-lane test; requires the explicitly materialized vendored qualification toolchain',
    });
  }
  if (ARTIFACT_QUALIFICATION_TESTS.has(relativePath)) {
    return Object.freeze({
      classification: 'local-verifier-lane-qualification',
      reason: 'artifact-dependent local verifier qualification; requires the materialized vendored toolchain and explicit .codex-build proof artifacts',
    });
  }
  const campaignReason = LOCAL_CAMPAIGN_TESTS.get(relativePath);
  if (campaignReason !== undefined) {
    const classification = relativePath.includes('depth4')
      ? 'local-depth4-campaign'
      : 'local-strict-codec-campaign';
    return Object.freeze({
      classification,
      reason: `${campaignReason}; run via its explicit local campaign command and the mandatory matching CI campaign job`,
    });
  }
  return Object.freeze({
    classification: 'portable',
    reason: 'mandatory clean-clone unit/integration/security test',
  });
}

export async function assertQualificationPrerequisites(
  selected,
  { projectRoot = project, suite = 'portable' } = {},
) {
  if (!['local-covenants', 'local-verifier-lane'].includes(suite)) return;
  const required = new Set(MATERIALIZED_UNLOCK_TOOLCHAIN);
  for (const record of selected) {
    for (const artifact of ARTIFACT_QUALIFICATION_TESTS.get(record.relativePath) ?? []) {
      required.add(artifact);
    }
  }
  const missing = [...required].filter((relativePath) => !existsSync(
    path.join(projectRoot, relativePath),
  ));
  if (missing.length > 0) {
    fail(
      `qualification suite ${suite} is BLOCKED: required local artifacts are unavailable: ${JSON.stringify(missing)}. `
      + 'Do not treat this as portable coverage or a skipped qualification gate.',
    );
  }
  if (
    suite === 'local-verifier-lane'
    && selected.some((record) => ARTIFACT_QUALIFICATION_TESTS.has(record.relativePath))
  ) {
    await assertLocalVerifierArtifactCoherence({ projectRoot });
  }
}

function missingQualificationPrerequisites(selected, projectRoot) {
  const required = new Set(MATERIALIZED_UNLOCK_TOOLCHAIN);
  for (const record of selected) {
    for (const artifact of ARTIFACT_QUALIFICATION_TESTS.get(record.relativePath) ?? []) {
      required.add(artifact);
    }
  }
  return [...required].filter((relativePath) => !existsSync(
    path.join(projectRoot, relativePath),
  ));
}

function runProvisionCommand(command, args, { cwd, input } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    input,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error || result.status !== 0 || result.signal !== null) {
    fail(
      `local verifier artifact provisioning failed: ${command} ${args.join(' ')} `
      + `(exit=${result.status ?? 'none'} signal=${result.signal ?? 'none'}): `
      + `${result.error?.message ?? 'command failed'}`,
    );
  }
}

function assertNoPartialDevelopmentArtifacts(projectRoot) {
  const present = DEVELOPMENT_ARTIFACT_ROOTS.filter((relativePath) => existsSync(
    path.join(projectRoot, relativePath),
  ));
  if (present.length > 0) {
    fail(
      `local verifier artifact provisioning is BLOCKED by incomplete generated state: ${JSON.stringify(present)}. `
      + 'Refuse to mix a partial development circuit/proof set with a new qualification run.',
    );
  }
}

/**
 * Supply development setup entropy from one private, caller-owned fd. The
 * setup module accepts only stdin or a private fd; the entropy file is always
 * closed and removed before this helper resolves or rejects.
 */
export async function withPrivateSetupEntropyFd(
  consume,
  {
    directoryPrefix = path.join(tmpdir(), 'shieldkit-local-verifier-entropy-'),
    filesystem = { chmod, mkdtemp, open, rm },
    random = randomBytes,
  } = {},
) {
  if (typeof consume !== 'function') fail('private entropy consumer must be a function');
  const directory = await filesystem.mkdtemp(directoryPrefix);
  const filename = path.join(directory, 'phase2-entropy');
  let writer;
  let reader;
  let entropy;
  try {
    await filesystem.chmod(directory, 0o700);
    writer = await filesystem.open(filename, 'wx', 0o600);
    await filesystem.chmod(filename, 0o600);
    entropy = Buffer.from(random(64).toString('hex'), 'ascii');
    await writer.writeFile(entropy);
    await writer.sync();
    entropy.fill(0);
    entropy = undefined;
    await writer.close();
    writer = undefined;
    reader = await filesystem.open(filename, 'r');
    return await consume(Object.freeze({ kind: 'fd', fd: reader.fd }));
  } finally {
    if (entropy !== undefined) entropy.fill(0);
    try {
      if (reader !== undefined) await reader.close();
    } finally {
      try {
        if (writer !== undefined) await writer.close();
      } finally {
        await filesystem.rm(directory, { recursive: true, force: true, maxRetries: 1 });
      }
    }
  }
}

export function developmentProofQualificationArguments(
  projectRoot,
  { profileCore, instanceId, maximumLiveNotes },
) {
  return Object.freeze([
    path.join(projectRoot, 'scripts/v2-development-proof-qualification.mjs'),
    '--single-thread',
    '--profile-core', profileCore,
    '--r1cs', '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '--wasm', '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '--zkey', '../.codex-build/v2-dev-groth16/final.zkey',
    '--verification-key', '../.codex-build/v2-dev-groth16/verification_key.json',
    '--instance-id', instanceId,
    '--maximum-live-notes', maximumLiveNotes,
    '--output', '../.codex-build/v2-dev-proof-qualification',
  ]);
}

async function provisionMissingLocalVerifierArtifacts({ projectRoot, selected }) {
  const initialMissing = missingQualificationPrerequisites(selected, projectRoot);
  if (initialMissing.length === 0) return Object.freeze({ provisioned: false, missing: [] });
  assertNoPartialDevelopmentArtifacts(projectRoot);
  runProvisionCommand('npm', ['run', 'unlock-builder:setup'], { cwd: path.resolve(projectRoot, '..') });
  runProvisionCommand(process.execPath, [
    path.join(projectRoot, 'scripts/v2-circuit-model.mjs'),
  ], { cwd: projectRoot });

  const repositoryRoot = path.resolve(projectRoot, '..');
  const artifactRoot = path.resolve(projectRoot, '..', '.codex-build');
  const ptauDirectory = path.join(artifactRoot, 'v2-dev-ptau');
  const pot0 = path.join(ptauDirectory, 'pot19_0000.ptau');
  const pot1 = path.join(ptauDirectory, 'pot19_0001.ptau');
  const ptau = path.join(ptauDirectory, 'pot19_final.ptau');
  const snarkjsCli = path.join(
    repositoryRoot,
    'node_modules/snarkjs/build/cli.cjs',
  );
  mkdirSync(ptauDirectory, { recursive: true, mode: 0o700 });
  runProvisionCommand(process.execPath, [
    snarkjsCli, 'powersoftau', 'new', 'bn128', '19', pot0,
  ], {
    cwd: projectRoot,
  });
  runProvisionCommand(process.execPath, [
    snarkjsCli, 'powersoftau', 'contribute', pot0, pot1,
  ], { cwd: projectRoot, input: `${randomBytes(64).toString('hex')}\n` });
  runProvisionCommand(process.execPath, [
    snarkjsCli, 'powersoftau', 'prepare', 'phase2', pot1, ptau,
  ], { cwd: projectRoot });

  const setup = await import('../packages/profile/setup/development.mjs');
  const circuitBuild = path.join(artifactRoot, 'v2-circuit-model');
  const setupDirectory = path.join(artifactRoot, 'v2-dev-groth16');
  const profileDirectory = path.join(artifactRoot, 'v2-development-profile');
  const qualificationDirectory = path.join(
    artifactRoot,
    'v2-dev-proof-qualification',
  );
  const r1cs = path.join(circuitBuild, 'main-chipnet.r1cs');
  const wasm = path.join(circuitBuild, 'main-chipnet_js/main-chipnet.wasm');
  const circuitSymbols = path.join(circuitBuild, 'main-chipnet.sym');
  const buildAttestationPath = path.join(
    circuitBuild,
    'circuit-build-attestation.json',
  );
  const sourceManifestPath = path.join(
    circuitBuild,
    'relation-source-manifest.json',
  );
  const r1csSha256 = await setup.hashFileStreaming(r1cs);
  const ptauSha256 = await setup.hashFileStreaming(ptau);
  const pinnedSnarkjs = await setup.getPinnedSnarkjsInfo();
  await withPrivateSetupEntropyFd(async (entropySource) => {
    await setup.initializeDevelopmentGroth16({
      repositoryRoot: repositoryRoot,
      buildAttestationPath: buildAttestationPath,
      sourceManifestPath: sourceManifestPath,
      destination: setupDirectory,
      r1csPath: r1cs,
      ptauPath: ptau,
      ptauSource: 'locally generated development-only Powers of Tau transcript with non-production entropy',
      expectedR1csSha256: r1csSha256,
      expectedPtauSha256: ptauSha256,
      expectedPtauPower: 19,
      expectedSnarkjs: pinnedSnarkjs,
      entropySource,
      verifyPtau: true,
    });
  });
  runProvisionCommand(process.execPath, [
    path.join(projectRoot, 'scripts/v2-development-profile.mjs'),
    '--build-attestation', buildAttestationPath,
    '--circuit-symbols', circuitSymbols,
    '--initial-proving-key', path.join(setupDirectory, 'initial.zkey'),
    '--ptau', ptau,
    '--proving-key', path.join(setupDirectory, 'final.zkey'),
    '--r1cs', r1cs,
    '--setup-attestation', path.join(
      setupDirectory,
      'development-setup-attestation.json',
    ),
    '--verification-key', path.join(setupDirectory, 'verification_key.json'),
    '--wasm', wasm,
    '--output', profileDirectory,
  ], { cwd: projectRoot });
  const instanceId = createHash('sha256')
    .update('shieldkit-v2-direct-local-verifier-development-instance/v1')
    .digest('hex');
  const maximumLiveNotes = '32';
  const profileCore = path.join(profileDirectory, 'profile-core.json');
  runProvisionCommand(
    process.execPath,
    developmentProofQualificationArguments(projectRoot, {
      profileCore,
      instanceId,
      maximumLiveNotes,
    }),
    { cwd: projectRoot },
  );
  runProvisionCommand(process.execPath, [
    path.join(projectRoot, 'scripts/v2-pf10-development-runtime.mjs'),
    '--instance-id', instanceId,
    '--output', path.join(artifactRoot, 'v2-pf10-development-runtime'),
    '--profile-core', profileCore,
    '--profile-package', path.join(profileDirectory, 'profile-package.json'),
    '--qualification-evidence', path.join(
      qualificationDirectory,
      'qualification-evidence.json',
    ),
    '--temporary-root', path.join(artifactRoot, 'v2-pf10-runtime-tmp'),
  ], { cwd: projectRoot });
  return Object.freeze({ provisioned: true, missing: initialMissing });
}

export async function ensureLocalVerifierQualificationArtifacts(
  selected,
  { projectRoot = project, provision = provisionMissingLocalVerifierArtifacts } = {},
) {
  const result = await provision({ projectRoot, selected });
  await assertQualificationPrerequisites(selected, { projectRoot, suite: 'local-verifier-lane' });
  return result;
}

export function discoverDomainTests({ projectRoot = project } = {}) {
  const roots = [
    Object.freeze({ relativeRoot: 'packages', excludeVendor: true, required: true }),
    Object.freeze({ relativeRoot: 'scripts', excludeVendor: true, required: true }),
    Object.freeze({
      relativeRoot: VENDORED_VERIFIER_LANE_TEST_ROOT,
      excludeVendor: false,
      required: false,
    }),
  ];
  const records = [];
  const typecheckAssets = [];
  for (const { relativeRoot, excludeVendor, required } of roots) {
    const root = path.join(projectRoot, relativeRoot);
    if (!existsSync(root)) {
      if (required) fail(`test discovery root is missing: ${relativeRoot}`);
      continue;
    }
    const visit = (directory) => {
      const entries = readdirSync(directory, { withFileTypes: true })
        .sort((left, right) => left.name.localeCompare(right.name, 'en'));
      for (const entry of entries) {
        if (
          entry.name === 'node_modules'
          || (excludeVendor && entry.name === 'vendor')
          || entry.name.startsWith('.')
        ) continue;
        const full = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          visit(full);
          continue;
        }
        const relativePath = posix(path.relative(projectRoot, full));
        if (entry.isFile() && entry.name.endsWith('.test.mjs')) {
          records.push(Object.freeze({
            path: full,
            relativePath,
            ...classify(relativePath),
          }));
        } else if (entry.isFile() && entry.name.endsWith('.test.ts')) {
          typecheckAssets.push(Object.freeze({
            path: full,
            relativePath,
            classification: 'typescript-compile-asset',
            reason: 'compiled by check:type:v2 and exercised by the JavaScript parity test',
          }));
        }
      }
    };
    visit(root);
  }
  records.sort((left, right) => left.relativePath.localeCompare(right.relativePath, 'en'));
  typecheckAssets.sort((left, right) => left.relativePath.localeCompare(right.relativePath, 'en'));
  if (records.length === 0) fail('no domain test files discovered');
  return Object.freeze({
    tests: Object.freeze(records),
    typecheckAssets: Object.freeze(typecheckAssets),
    ignoredScopes: Object.freeze([
      Object.freeze({
        scope: 'packages/**/vendor/**',
        exception: `${VENDORED_VERIFIER_LANE_TEST_ROOT}/**/*.test.mjs`,
        classification: 'third-party-vendor-excluded',
        reason: 'bulk third-party trees and generated dependency/build caches are outside ShieldKit tests; the tracked pinned BN254 lane tests are explicitly discovered',
      }),
    ]),
  });
}

export function selectDomainTests(discovery, suite = 'portable') {
  if (!SUITES.has(suite)) fail(`unknown test suite: ${suite}`);
  const classification = {
    portable: 'portable',
    'external-fixtures': 'external-fixture',
    'external-verifier-source': 'external-verifier-source-qualification',
    'local-covenants': 'local-covenant-qualification',
    'local-verifier-lane': 'local-verifier-lane-qualification',
    'local-strict-codec-campaign': 'local-strict-codec-campaign',
    'local-depth4-campaign': 'local-depth4-campaign',
  }[suite];
  const selected = discovery.tests.filter((record) => record.classification === classification);
  if (selected.length === 0) fail(`test suite ${suite} selected no files`);
  return Object.freeze(selected);
}

export function assertCompleteSelection(discovery, selected, suite = 'portable') {
  const expected = selectDomainTests(discovery, suite).map((record) => record.relativePath);
  const actual = selected.map((record) => record.relativePath);
  if (
    actual.length !== expected.length
    || actual.some((relativePath, index) => relativePath !== expected[index])
  ) {
    const actualSet = new Set(actual);
    const expectedSet = new Set(expected);
    const omitted = expected.filter((relativePath) => !actualSet.has(relativePath));
    const unexpected = actual.filter((relativePath) => !expectedSet.has(relativePath));
    fail(`test selection is incomplete or contaminated: omitted=${JSON.stringify(omitted)} unexpected=${JSON.stringify(unexpected)}`);
  }
}

export function preflightTestSources(selected, { allowClassifiedFixtureGates = false } = {}) {
  for (const record of selected) {
    const source = readFileSync(record.path, 'utf8');
    const classifiedFixtureGate = allowClassifiedFixtureGates
      && record.classification === 'external-fixture';
    if (SKIP_OR_TODO_SOURCE.test(source) && !classifiedFixtureGate) {
      fail(`${record.relativePath} contains skip/todo fixture gating; move it to an explicit external suite`);
    }
    if (!source.includes('node:test')) {
      if (!SCRIPT_STYLE_TESTS.has(record.relativePath)) {
        fail(`${record.relativePath} is an empty or unregistered script-style test`);
      }
    } else if (!NODE_TEST_DECLARATION.test(source)) {
      fail(`${record.relativePath} imports node:test but declares no tests`);
    }
  }
}

function tapSummary(output) {
  const field = (name) => {
    const matches = [...output.matchAll(new RegExp(`^# ${name} (\\d+)$`, 'gm'))];
    return matches.length === 0 ? undefined : Number(matches.at(-1)[1]);
  };
  return Object.freeze({
    tests: field('tests'),
    pass: field('pass'),
    fail: field('fail'),
    cancelled: field('cancelled'),
    skipped: field('skipped'),
    todo: field('todo'),
  });
}

function domainTestTemporaryBuildRoot(cwd) {
  if (typeof cwd !== 'string' || !path.isAbsolute(cwd)) {
    fail('domain test cwd must be an absolute path');
  }
  const root = path.resolve(cwd, '..', '.codex-build');
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(root);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('domain test temporary build root must be a directory and not a symlink');
  }
  if (realpathSync(root) !== root) {
    fail('domain test temporary build root must be canonical');
  }
  return root;
}

function assertManagedDomainTestTemporaryDirectory(temporary) {
  if (temporary === null || typeof temporary !== 'object') {
    fail('domain test temporary directory must be an object');
  }
  const { root, directory } = temporary;
  if (
    typeof root !== 'string'
    || typeof directory !== 'string'
    || managedDomainTestTemporaryDirectories.get(directory) !== root
    || path.dirname(directory) !== root
    || !path.basename(directory).startsWith(DOMAIN_TEST_TEMP_PREFIX)
  ) {
    fail('refusing unmanaged domain test temporary directory');
  }
  const rootMetadata = lstatSync(root);
  const directoryMetadata = lstatSync(directory);
  if (
    !rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
    || !directoryMetadata.isDirectory()
    || directoryMetadata.isSymbolicLink()
    || realpathSync(root) !== root
    || realpathSync(directory) !== directory
    || (directoryMetadata.mode & 0o777) !== 0o700
  ) {
    fail('refusing unsafe domain test temporary directory');
  }
}

/** Create one private, repo-local temporary root for child domain-test processes. */
export function createDomainTestTemporaryDirectory(cwd = project) {
  const root = domainTestTemporaryBuildRoot(cwd);
  const directory = mkdtempSync(path.join(root, DOMAIN_TEST_TEMP_PREFIX));
  try {
    chmodSync(directory, 0o700);
    const temporary = Object.freeze({ root, directory });
    managedDomainTestTemporaryDirectories.set(directory, root);
    assertManagedDomainTestTemporaryDirectory(temporary);
    return temporary;
  } catch (error) {
    if (managedDomainTestTemporaryDirectories.get(directory) === root) {
      managedDomainTestTemporaryDirectories.delete(directory);
      rmSync(directory, { recursive: true, force: false });
    }
    throw error;
  }
}

/** Remove only the exact private directory created by this module. */
export function removeDomainTestTemporaryDirectory(temporary) {
  assertManagedDomainTestTemporaryDirectory(temporary);
  rmSync(temporary.directory, { recursive: true, force: false });
  managedDomainTestTemporaryDirectories.delete(temporary.directory);
}

/**
 * Return the process-supervisor deadline for one classified test file.
 *
 * The portable default deliberately remains short. Slow qualification tests
 * must be registered by exact path in LOCAL_CAMPAIGN_TESTS and selected by a
 * mandatory, named campaign suite before they can receive a longer deadline.
 */
export function fileTimeoutForDomainTest(record, { defaultTimeoutMs = 180_000 } = {}) {
  if (!Number.isSafeInteger(defaultTimeoutMs) || defaultTimeoutMs <= 0) {
    fail(`invalid default per-file timeout: ${defaultTimeoutMs}`);
  }
  if (record === null || typeof record !== 'object' || typeof record.classification !== 'string') {
    fail('test record must have a classification');
  }
  return FILE_TIMEOUT_MS_BY_CLASSIFICATION[record.classification] ?? defaultTimeoutMs;
}

export function runSelectedDomainTests(
  selected,
  {
    cwd = project,
    environment = process.env,
    fileTimeoutMs = 180_000,
  } = {},
) {
  if (!Number.isSafeInteger(fileTimeoutMs) || fileTimeoutMs <= 0) {
    fail(`invalid per-file timeout: ${fileTimeoutMs}`);
  }
  const childEnvironment = { ...environment };
  delete childEnvironment.NODE_TEST_CONTEXT;
  const temporary = createDomainTestTemporaryDirectory(cwd);
  childEnvironment.TMPDIR = temporary.directory;
  childEnvironment.TMP = temporary.directory;
  childEnvironment.TEMP = temporary.directory;
  const aggregate = {
    files: selected.length,
    tests: 0,
    pass: 0,
    fail: 0,
    cancelled: 0,
    skipped: 0,
    todo: 0,
  };
  try {
    for (const [index, record] of selected.entries()) {
      const timeoutMs = fileTimeoutForDomainTest(record, {
        defaultTimeoutMs: fileTimeoutMs,
      });
      process.stderr.write(`${JSON.stringify({
        phase: 'test-file',
        index: index + 1,
        total: selected.length,
        file: record.relativePath,
        timeoutMs,
      })}\n`);
      const result = spawnSync(process.execPath, [
        '--test',
        '--test-reporter=tap',
        '--test-concurrency=1',
        record.path,
      ], {
        cwd,
        env: childEnvironment,
        encoding: 'utf8',
        maxBuffer: 128 * 1024 * 1024,
        timeout: timeoutMs,
        killSignal: 'SIGKILL',
      });
      if (result.stdout) process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
      if (result.error) {
        const detail = result.error.code === 'ETIMEDOUT'
          ? `timed out after ${timeoutMs}ms`
          : `could not start: ${result.error.message}`;
        fail(`${record.relativePath}: node test runner ${detail}`);
      }
      const summary = tapSummary(`${result.stdout ?? ''}\n${result.stderr ?? ''}`);
      if (result.status !== 0 || result.signal !== null) {
        fail(`${record.relativePath}: node test runner failed: exit=${result.status ?? 'none'} signal=${result.signal ?? 'none'}`);
      }
      for (const field of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
        if (!Number.isSafeInteger(summary[field])) {
          fail(`${record.relativePath}: node test runner omitted TAP summary field ${field}`);
        }
      }
      if (summary.fail !== 0 || summary.cancelled !== 0 || summary.skipped !== 0 || summary.todo !== 0) {
        fail(`${record.relativePath}: node test runner was not fully executed: ${JSON.stringify(summary)}`);
      }
      if (summary.tests === 0 || summary.pass === 0) {
        fail(`${record.relativePath}: node test runner reported an empty suite`);
      }
      for (const field of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
        aggregate[field] += summary[field];
      }
    }
  } finally {
    removeDomainTestTemporaryDirectory(temporary);
  }
  process.stderr.write(`${JSON.stringify({ phase: 'test-complete', ...aggregate })}\n`);
  return Object.freeze(aggregate);
}

function parse(argv) {
  if (argv.length === 0) return Object.freeze({ suite: 'portable', provisionOnly: false });
  if (argv.length === 1 && argv[0] === '--provision-local-verifier-artifacts') {
    return Object.freeze({ suite: 'local-verifier-lane', provisionOnly: true });
  }
  if (argv.length === 2 && argv[0] === '--suite' && SUITES.has(argv[1])) {
    return Object.freeze({ suite: argv[1], provisionOnly: false });
  }
  fail('usage: node run-domain-tests.mjs [--suite portable|external-fixtures|external-verifier-source|local-covenants|local-verifier-lane|local-strict-codec-campaign|local-depth4-campaign] | --provision-local-verifier-artifacts');
}

export async function runDomainTests({ suite = 'portable', projectRoot = project, provisionOnly = false } = {}) {
  const discovery = discoverDomainTests({ projectRoot });
  const selected = selectDomainTests(discovery, suite);
  assertCompleteSelection(discovery, selected, suite);
  if (suite === 'local-verifier-lane') {
    await ensureLocalVerifierQualificationArtifacts(selected, { projectRoot });
    if (provisionOnly) return Object.freeze({ discovery, selected, summary: null });
  } else {
    await assertQualificationPrerequisites(selected, { projectRoot, suite });
  }
  preflightTestSources(selected, {
    allowClassifiedFixtureGates: suite === 'external-fixtures',
  });
  const selectedSet = new Set(selected.map((record) => record.relativePath));
  const excluded = discovery.tests
    .filter((record) => !selectedSet.has(record.relativePath))
    .map(({ relativePath, classification, reason }) => ({ file: relativePath, classification, reason }));
  process.stderr.write(`${JSON.stringify({
    phase: 'test-discovery',
    suite,
    selectedCount: selected.length,
    selected: selected.map((record) => record.relativePath),
    excludedCount: excluded.length + discovery.typecheckAssets.length,
    excluded: [
      ...excluded,
      ...discovery.typecheckAssets.map(({ relativePath, classification, reason }) => ({
        file: relativePath,
        classification,
        reason,
      })),
    ],
    ignoredScopes: discovery.ignoredScopes,
  }, null, 2)}\n`);
  return Object.freeze({
    discovery,
    selected,
    summary: runSelectedDomainTests(selected, { cwd: projectRoot }),
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const parsed = parse(process.argv.slice(2));
    await runDomainTests(parsed);
  } catch (error) {
    process.stderr.write(`mandatory domain test runner failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
