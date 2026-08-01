#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  V2_BETA_LOCAL_ELIGIBILITY,
} from '../packages/profile/v2/beta-local-profile.mjs';
import {
  V2_BETA_PROOF_QUALIFICATION_SCHEMA,
} from './v2-beta-proof-qualification.mjs';
import {
  actionPacketPublicLimbs,
  decodeActionPacket,
} from '../packages/action/v2/packet.mjs';
import {
  decodeDirectV2BindingUnlock,
} from '../packages/action/v2/binding-unlock.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  inspectV2LocalVmEvidence,
} from '../packages/kit/v2/vm-evidence.mjs';

const SCRIPT_SCHEMA =
  'shieldkit-v2-direct-pf10-local-libauth-qualification-v2';
const EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-pf10-local-libauth-evidence-v2';
export const PF10_BETA_LIBAUTH_EVIDENCE_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-local-libauth-evidence-v1';
export const PF10_BETA_LIBAUTH_QUALIFICATION_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-local-libauth-qualification-v1';
export const PF10_BETA_LIBAUTH_PUBLICATION_SCHEMA =
  'shieldkit-v2-direct-pf10-beta-libauth-publication-v1';
export const PF10_LIBAUTH_PUBLICATION_SCHEMA =
  'shieldkit-v2-direct-pf10-libauth-publication-v1';
export const PF10_LIBAUTH_PUBLICATION_FILE =
  'publication-complete.json';
const PF10_LIBAUTH_PUBLICATION_FILES = Object.freeze([
  'libauth.json',
  'qualification-summary.json',
  'stderr.txt',
  'stdout.txt',
]);
const projectRoot = path.resolve(import.meta.dirname, '..');
const repositoryRoot = path.resolve(projectRoot, '..');
const testPath = path.join(
  projectRoot,
  'packages/unlock-builder/v2/pf10-withdrawal.test.mjs',
);

export class QualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'QualificationError';
  }
}

export class QualificationPublicationCommittedError
  extends QualificationError {
  constructor(message, options = undefined) {
    super(message);
    this.name = 'QualificationPublicationCommittedError';
    this.committed = true;
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}

const fail = (message) => {
  throw new QualificationError(message);
};

const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');
const MAX_U128 = (1n << 128n) - 1n;

const hash256 = (bytes) => {
  const first = createHash('sha256').update(bytes).digest();
  return createHash('sha256').update(first).digest();
};

const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');

const exactObject = (value, label) => {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
  ) {
    fail(`${label} must be an object`);
  }
  return value;
};

const exactArray = (value, label) => {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return value;
};

const exactString = (value, expected, label) => {
  if (value !== expected) {
    fail(`${label} must equal ${JSON.stringify(expected)}`);
  }
};

const exactBoolean = (value, expected, label) => {
  if (value !== expected) {
    fail(`${label} must equal ${expected}`);
  }
};

const exactInteger = (value, label) => {
  if (!Number.isSafeInteger(value)) fail(`${label} must be a safe integer`);
  return value;
};

export const parseOptions = (argv) => {
  const optionNames = Object.freeze({
    '--output': 'output',
    '--profile-core': 'profileCore',
    '--qualification-root': 'qualificationRoot',
    '--r1cs': 'r1cs',
    '--setup-metadata': 'setupMetadata',
    '--temporary-root': 'temporaryRoot',
    '--verification-key': 'verificationKey',
    '--wasm': 'wasm',
    '--zkey': 'zkey',
  });
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const key = optionNames[option];
    if (key === undefined) fail(`unknown option: ${option}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      fail(`${option} requires a value`);
    }
    if (options[key] !== undefined) fail(`${option} may appear only once`);
    options[key] = value;
    index += 1;
  }
  for (const option of [
    '--output',
    '--profile-core',
    '--qualification-root',
    '--r1cs',
    '--setup-metadata',
    '--verification-key',
    '--wasm',
    '--zkey',
  ]) {
    if (options[optionNames[option]] === undefined) {
      fail(`${option} is required`);
    }
  }
  return Object.freeze({
    output: path.resolve(options.output),
    profileCore: path.resolve(options.profileCore),
    qualificationRoot: path.resolve(options.qualificationRoot),
    r1cs: path.resolve(options.r1cs),
    setupMetadata: path.resolve(options.setupMetadata),
    temporaryRoot: path.resolve(
      options.temporaryRoot
      ?? path.join(
        repositoryRoot,
        '.codex-build/v2-pf10-libauth-tmp',
      ),
    ),
    verificationKey: path.resolve(options.verificationKey),
    wasm: path.resolve(options.wasm),
    zkey: path.resolve(options.zkey),
  });
};

/** Parse the beta-only variant. It deliberately has no final/setup metadata. */
export const parseBetaOptions = (argv) => {
  const optionNames = Object.freeze({
    '--output': 'output',
    '--profile-core': 'profileCore',
    '--qualification-root': 'qualificationRoot',
    '--r1cs': 'r1cs',
    '--temporary-root': 'temporaryRoot',
    '--verification-key': 'verificationKey',
    '--wasm': 'wasm',
    '--beta-zkey': 'zkey',
  });
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const key = optionNames[option];
    if (key === undefined) fail(`unknown option: ${option}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      fail(`${option} requires a value`);
    }
    if (options[key] !== undefined) fail(`${option} may appear only once`);
    options[key] = value;
    index += 1;
  }
  for (const option of [
    '--output', '--profile-core', '--qualification-root', '--r1cs',
    '--verification-key', '--wasm', '--beta-zkey',
  ]) {
    if (options[optionNames[option]] === undefined) {
      fail(`${option} is required`);
    }
  }
  return Object.freeze({
    output: path.resolve(options.output),
    profileCore: path.resolve(options.profileCore),
    qualificationRoot: path.resolve(options.qualificationRoot),
    r1cs: path.resolve(options.r1cs),
    temporaryRoot: path.resolve(
      options.temporaryRoot
      ?? path.join(repositoryRoot, '.codex-build/v2-pf10-beta-libauth-tmp'),
    ),
    verificationKey: path.resolve(options.verificationKey),
    wasm: path.resolve(options.wasm),
    zkey: path.resolve(options.zkey),
  });
};

const assertAbsent = async (target) => {
  try {
    await access(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  fail(`refusing to overwrite existing output: ${target}`);
};

const isStrictDescendant = (root, target) =>
  target !== root && target.startsWith(`${root}${path.sep}`);

const fsyncPath = async (filename, label) => {
  let handle;
  try {
    handle = await open(filename, 'r');
    await handle.sync();
  } catch (error) {
    fail(`${label} cannot be synced: ${error.message}`);
  } finally {
    await handle?.close();
  }
};

const canonicalDirectory = async (
  directory,
  label,
  { create = false, privateMode = false } = {},
) => {
  if (!path.isAbsolute(directory)) fail(`${label} must be absolute`);
  if (create) await mkdir(directory, { recursive: true, mode: 0o700 });
  let metadata;
  try {
    metadata = await lstat(directory);
  } catch (error) {
    fail(`${label} is unavailable: ${error.message}`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail(`${label} must be a direct directory`);
  }
  const canonical = await realpath(directory);
  if (canonical !== directory) {
    fail(`${label} must be canonical and not resolve through a symlink`);
  }
  if (privateMode) await chmod(directory, 0o700);
  return canonical;
};

const privateBuildRoot = async (canonicalRepositoryRoot) => {
  const buildRoot = path.join(canonicalRepositoryRoot, '.codex-build');
  let created = false;
  try {
    await mkdir(buildRoot, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const canonical = await canonicalDirectory(
    buildRoot,
    'private build root',
  );
  const metadata = await lstat(canonical);
  if ((metadata.mode & 0o777) !== 0o700) {
    fail('private build root must have mode 0700');
  }
  if (created) await fsyncPath(canonicalRepositoryRoot, 'repository root');
  return canonical;
};

const privateDescendantDirectory = async (
  buildRoot,
  target,
  label,
) => {
  if (
    target !== buildRoot
    && !isStrictDescendant(buildRoot, target)
  ) {
    fail(`${label} must be contained by the private build root`);
  }
  let current = buildRoot;
  const relative = path.relative(buildRoot, target);
  if (relative.length === 0) return buildRoot;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    let created = false;
    try {
      await mkdir(current, { mode: 0o700 });
      created = true;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    await canonicalDirectory(current, label);
    const metadata = await lstat(current);
    if ((metadata.mode & 0o777) !== 0o700) {
      fail(`${label} must contain only mode-0700 directories`);
    }
    if (created) await fsyncPath(path.dirname(current), `${label} parent`);
  }
  return current;
};

const canonicalSingleLinkFile = async (
  filename,
  label,
  { allowEmpty = false } = {},
) => {
  let metadata;
  try {
    metadata = await lstat(filename);
  } catch (error) {
    fail(`${label} is unavailable: ${error.message}`);
  }
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || (!allowEmpty && metadata.size === 0)
    || metadata.nlink !== 1
  ) {
    fail(`${label} must be a ${allowEmpty ? '' : 'nonempty '}single-link regular non-symlink file`);
  }
  const canonical = await realpath(filename);
  if (canonical !== filename) {
    fail(`${label} must be canonical and not resolve through a symlink`);
  }
  return metadata;
};

export const writePrivateFile = async (filename, bytes, label) => {
  try {
    await writeFile(filename, bytes, { mode: 0o600, flag: 'wx' });
    await chmod(filename, 0o600);
    await canonicalSingleLinkFile(filename, label, { allowEmpty: true });
    await fsyncPath(filename, label);
  } catch (error) {
    if (error instanceof QualificationError) throw error;
    fail(`${label} cannot be written privately: ${error.message}`);
  }
};

export const preparePublicationPaths = async (options) => {
  if (
    options === null
    || Array.isArray(options)
    || typeof options !== 'object'
    || typeof options.output !== 'string'
    || typeof options.temporaryRoot !== 'string'
  ) {
    fail('publication options must include output and temporaryRoot paths');
  }
  const output = path.resolve(options.output);
  const requestedTemporaryRoot = path.resolve(options.temporaryRoot);
  const canonicalRepositoryRoot = await canonicalDirectory(
    repositoryRoot,
    'repository root',
  );
  if ((await stat(canonicalRepositoryRoot)).mode & 0o022) {
    fail('repository root must not be writable by group or other users');
  }
  const buildRoot = await privateBuildRoot(canonicalRepositoryRoot);
  const outputParent = path.dirname(output);
  if (
    !isStrictDescendant(buildRoot, output)
    || (
      outputParent !== buildRoot
      && !isStrictDescendant(buildRoot, outputParent)
    )
  ) {
    fail('output must be contained by the private build root');
  }
  await privateDescendantDirectory(buildRoot, outputParent, 'output parent');
  await assertAbsent(output);
  if (!isStrictDescendant(buildRoot, requestedTemporaryRoot)) {
    fail('temporary root must be contained by the private build root');
  }
  const temporaryRoot = await privateDescendantDirectory(
    buildRoot,
    requestedTemporaryRoot,
    'temporary root',
  );
  return Object.freeze({
    buildRoot,
    output,
    repositoryRoot: canonicalRepositoryRoot,
    outputParent,
    temporaryRoot,
  });
};

const publicationFileRecord = async (stage, filename) => {
  if (
    typeof filename !== 'string'
    || !/^[a-z0-9][a-z0-9.-]*$/u.test(filename)
    || path.basename(filename) !== filename
    || filename === PF10_LIBAUTH_PUBLICATION_FILE
  ) {
    fail(`publication file name is invalid: ${String(filename)}`);
  }
  const source = path.join(stage, filename);
  const before = await canonicalSingleLinkFile(
    source,
    `staged publication file ${filename}`,
    { allowEmpty: true },
  );
  const bytes = await readFile(source);
  const after = await lstat(source);
  if (
    before.dev !== after.dev
    || before.ino !== after.ino
    || before.size !== after.size
    || before.mtimeMs !== after.mtimeMs
    || before.ctimeMs !== after.ctimeMs
    || bytes.length !== before.size
  ) {
    fail(`staged publication file ${filename} changed while it was read`);
  }
  return Object.freeze({
    path: filename,
    bytes: bytes.length,
    sha256: sha256(bytes),
  });
};

const removeOwnedReservation = async (output, reservedIdentity) => {
  let current;
  try {
    current = await lstat(output);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  if (
    !current.isDirectory()
    || current.isSymbolicLink()
    || current.dev !== reservedIdentity.dev
    || current.ino !== reservedIdentity.ino
  ) {
    fail(
      'refusing to clean a publication path whose reserved directory identity changed',
    );
  }
  await rm(output, { recursive: true, force: false });
};

export const publishStage = async ({
  stage,
  output,
  outputParent,
  files = PF10_LIBAUTH_PUBLICATION_FILES,
  publicationSchema = PF10_LIBAUTH_PUBLICATION_SCHEMA,
  beforeReserve = undefined,
  beforeCommit = undefined,
  afterCommit = undefined,
}) => {
  if (
    publicationSchema !== PF10_LIBAUTH_PUBLICATION_SCHEMA
    && publicationSchema !== PF10_BETA_LIBAUTH_PUBLICATION_SCHEMA
  ) {
    fail('publication schema is not an approved PF10 evidence schema');
  }
  if (
    !Array.isArray(files)
    || files.length === 0
    || files.some((entry, index) =>
      typeof entry !== 'string'
      || (index > 0 && files[index - 1] >= entry))
  ) {
    fail('publication files must be a nonempty strictly sorted unique array');
  }
  const present = (await readdir(stage)).sort();
  if (
    present.length !== files.length
    || present.some((entry, index) => entry !== files[index])
  ) {
    fail('staged publication contains missing or unknown files');
  }
  const records = [];
  for (const filename of files) {
    records.push(await publicationFileRecord(stage, filename));
  }
  const completion = Object.freeze({
    schema: publicationSchema,
    files: Object.freeze(records),
  });
  await writePrivateFile(
    path.join(stage, PF10_LIBAUTH_PUBLICATION_FILE),
    canonicalBytes(completion),
    'publication completion record',
  );
  await assertAbsent(output);
  await fsyncPath(stage, 'staged publication directory');
  await fsyncPath(outputParent, 'output parent directory before publication');
  let reservedIdentity;
  let committed = false;
  try {
    await beforeReserve?.();
    try {
      await mkdir(output, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error?.code === 'EEXIST') {
        fail(`refusing to overwrite existing output: ${output}`);
      }
      throw error;
    }
    // Capture the directory identity immediately after the exclusive
    // reservation so every later pre-commit failure can clean only the
    // directory created by this publisher.
    reservedIdentity = await lstat(output);
    await canonicalDirectory(
      output,
      'reserved publication output directory',
      { privateMode: true },
    );
    for (const filename of files) {
      await rename(
        path.join(stage, filename),
        path.join(output, filename),
      );
    }
    await fsyncPath(output, 'reserved publication output directory');
    await beforeCommit?.();
    await rename(
      path.join(stage, PF10_LIBAUTH_PUBLICATION_FILE),
      path.join(output, PF10_LIBAUTH_PUBLICATION_FILE),
    );
    committed = true;
    await fsyncPath(output, 'committed publication output directory');
    await fsyncPath(outputParent, 'output parent directory after publication');
    await afterCommit?.();
    await rmdir(stage);
    return completion;
  } catch (error) {
    if (committed) {
      throw new QualificationPublicationCommittedError(
        `PF10 Libauth publication committed at ${output}, but post-commit durability or cleanup failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
        { cause: error },
      );
    }
    if (reservedIdentity !== undefined) {
      try {
        await removeOwnedReservation(output, reservedIdentity);
        await fsyncPath(
          outputParent,
          'output parent directory after failed publication cleanup',
        );
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          'PF10 Libauth publication failed and its owned reservation could not be cleaned',
          { cause: error },
        );
      }
    }
    throw error;
  }
};

const runChild = ({
  evidencePath,
  options,
  temporaryDirectory,
  betaLocal = false,
}) =>
  new Promise((resolve, reject) => {
    const temporaryFiles = path.join(temporaryDirectory, 'tmp');
    const child = spawn(
      process.execPath,
      ['--test', testPath],
      {
        cwd: repositoryRoot,
        env: {
          ...process.env,
          SHIELDKIT_PF10_LIBAUTH_EVIDENCE_OUTPUT: evidencePath,
          SHIELDKIT_PF10_PROFILE_CORE: options.profileCore,
          SHIELDKIT_PF10_QUALIFICATION_ROOT: options.qualificationRoot,
          SHIELDKIT_PF10_R1CS: options.r1cs,
          SHIELDKIT_PF10_VERIFICATION_KEY: options.verificationKey,
          SHIELDKIT_PF10_WASM: options.wasm,
          SHIELDKIT_PF10_ZKEY: options.zkey,
          ...(betaLocal ? {
            SHIELDKIT_PF10_BETA_LOCAL: '1',
          } : {
            SHIELDKIT_PF10_SETUP_METADATA: options.setupMetadata,
          }),
          TMPDIR: temporaryFiles,
          TMP: temporaryFiles,
          TEMP: temporaryFiles,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)));
    child.once('error', reject);
    child.once('close', (code, signal) => resolve(Object.freeze({
      code,
      signal,
      stdout: Buffer.concat(stdout),
      stderr: Buffer.concat(stderr),
    })));
  });

const canonicalHex = (value, label, { allowEmpty = false } = {}) => {
  if (
    typeof value !== 'string'
    || value.length % 2 !== 0
    || (!allowEmpty && value.length === 0)
    || !/^[0-9a-f]*$/.test(value)
  ) {
    fail(`${label} must be canonical lowercase hexadecimal`);
  }
  return value;
};

/**
 * Validate the beta transaction-specific packet/proof lineage. This helper is
 * intentionally not used by the development evidence path.
 */
export const validatePf10BetaActionProofBinding = ({
  action,
  expectedKind,
  instanceId,
  profileId,
}) => {
  exactObject(action, `beta action ${expectedKind}`);
  const expectedFields = [
    'construction', 'contextHash', 'feeRateSatsPerByte', 'feeSats',
    'inputCount', 'inputSources', 'kind', 'localVmEvidence',
    'mutationChecks', 'outputCount', 'packetHex', 'packetSha256', 'proof',
    'proofBindingSha256', 'proofGenerationMs', 'proofVerified',
    'publicInputs', 'rawTransactionHex', 'rawTransactionSha256', 'rows',
    'sourceOutputs', 'sourceParents', 'transactionBytes',
    'transactionHeadroomBytes', 'transactionId', 'transactionLimitBytes',
  ].sort();
  const actualFields = Object.keys(action).sort();
  if (
    actualFields.length !== expectedFields.length
    || actualFields.some((field, index) => field !== expectedFields[index])
  ) fail(`${expectedKind} beta action has missing or unknown properties`);
  if (
    typeof action.packetHex !== 'string'
    || action.packetHex.length !== 1104
    || !/^[0-9a-f]{1104}$/u.test(action.packetHex)
  ) fail(`${expectedKind}.packetHex must be exactly 552 canonical bytes`);
  const packet = Buffer.from(action.packetHex, 'hex');
  const packetSha256 = sha256(packet);
  exactString(action.packetSha256, packetSha256, `${expectedKind}.packetSha256`);
  const publicInputs = exactArray(action.publicInputs, `${expectedKind}.publicInputs`);
  if (
    publicInputs.length !== 2
    || publicInputs.some((entry) =>
      typeof entry !== 'string'
      || !/^(?:0|[1-9][0-9]*)$/u.test(entry)
      || BigInt(entry) > MAX_U128)
  ) fail(`${expectedKind}.publicInputs must be two canonical u128 decimals`);
  const decoded = decodeActionPacket(packet, {
    denominationSats: '10000000',
  });
  exactString(decoded.kind, expectedKind, `${expectedKind}.packet.kind`);
  exactString(decoded.instanceId, instanceId, `${expectedKind}.packet.instanceId`);
  exactString(decoded.preState.profileId, profileId, `${expectedKind}.packet.profileId`);
  exactString(decoded.postState.profileId, profileId, `${expectedKind}.packet.postProfileId`);
  exactString(
    decoded.transactionContextHash,
    action.contextHash,
    `${expectedKind}.packet.transactionContextHash`,
  );
  const calculatedPublicInputs = actionPacketPublicLimbs(packet, {
    denominationSats: '10000000',
  });
  if (calculatedPublicInputs.some((entry, index) => entry !== publicInputs[index])) {
    fail(`${expectedKind}.publicInputs differ from the exact packet digest`);
  }
  exactObject(action.proof, `${expectedKind}.proof`);
  let proofBindingSha256;
  try {
    proofBindingSha256 = sha256(Buffer.from(canonicalizeJcs({
      packetSha256,
      proof: action.proof,
      publicInputs,
    }), 'utf8'));
  } catch (error) {
    fail(`${expectedKind}.proof is not canonical JSON data: ${error.message}`);
  }
  exactString(
    action.proofBindingSha256,
    proofBindingSha256,
    `${expectedKind}.proofBindingSha256`,
  );
  return Object.freeze({
    decoded,
    packet,
    packetSha256,
    proofBindingSha256,
    publicInputs: Object.freeze([...publicInputs]),
  });
};

const validateSourceParent = (value, label) => {
  const parent = exactObject(value, label);
  const rawTransactionHex = canonicalHex(
    parent.rawTransactionHex,
    `${label}.rawTransactionHex`,
  );
  const raw = Buffer.from(rawTransactionHex, 'hex');
  const parsed = parseV2RawTransaction(rawTransactionHex);
  exactString(
    parent.rawTransactionSha256,
    sha256(raw),
    `${label}.rawTransactionSha256`,
  );
  exactString(
    parent.transactionId,
    parsed.txid,
    `${label}.transactionId`,
  );
  return Object.freeze({ parent, parsed });
};

const validateAction = (action, expectedKind) => {
  exactObject(action, `action ${expectedKind}`);
  exactString(action.kind, expectedKind, `${expectedKind}.kind`);
  exactInteger(action.inputCount, `${expectedKind}.inputCount`);
  exactInteger(action.outputCount, `${expectedKind}.outputCount`);
  if (action.inputCount !== 13) fail(`${expectedKind} must have 13 inputs`);
  const expectedOutputs = expectedKind === 'withdrawal' ? 14 : 13;
  if (action.outputCount !== expectedOutputs) {
    fail(`${expectedKind} must have ${expectedOutputs} outputs`);
  }
  const transactionBytes = exactInteger(
    action.transactionBytes,
    `${expectedKind}.transactionBytes`,
  );
  if (transactionBytes > 100_000) {
    fail(`${expectedKind} exceeds the 100000-byte transaction ceiling`);
  }
  exactBoolean(
    action.proofVerified,
    true,
    `${expectedKind}.proofVerified`,
  );
  if (
    typeof action.rawTransactionHex !== 'string'
    || !/^(?:[0-9a-f]{2})+$/.test(action.rawTransactionHex)
  ) {
    fail(`${expectedKind}.rawTransactionHex must be canonical lowercase hex`);
  }
  const raw = Buffer.from(action.rawTransactionHex, 'hex');
  if (raw.length !== transactionBytes) {
    fail(`${expectedKind} raw transaction length mismatch`);
  }
  exactString(
    action.rawTransactionSha256,
    sha256(raw),
    `${expectedKind}.rawTransactionSha256`,
  );
  exactString(
    action.transactionId,
    Buffer.from(hash256(raw)).reverse().toString('hex'),
    `${expectedKind}.transactionId`,
  );
  const parsedTransaction = parseV2RawTransaction(
    action.rawTransactionHex,
  );
  exactString(
    parsedTransaction.txid,
    action.transactionId,
    `${expectedKind}.parsedTransaction.txid`,
  );
  if (
    parsedTransaction.inputs.length !== 13
    || parsedTransaction.inputs.some((input) => input.sequence !== 0)
  ) {
    fail(`${expectedKind} must use sequence zero on all 13 inputs`);
  }
  exactString(
    action.feeRateSatsPerByte,
    '1',
    `${expectedKind}.feeRateSatsPerByte`,
  );
  exactString(
    action.feeSats,
    transactionBytes.toString(),
    `${expectedKind}.feeSats`,
  );
  const construction = exactObject(
    action.construction,
    `${expectedKind}.construction`,
  );
  const constructionPath = exactArray(
    construction.path,
    `${expectedKind}.construction.path`,
  );
  const expectedPath = [
    'prepareV2DirectSettlement',
    'assembleV2DirectSettlement',
    'signV2DirectSettlement',
  ];
  if (
    constructionPath.length !== expectedPath.length
    || constructionPath.some(
      (entry, index) => entry !== expectedPath[index],
    )
  ) {
    fail(`${expectedKind} did not use the exact production settlement path`);
  }
  for (const field of [
    'preparedPayloadHash',
    'assemblyHash',
    'localVmEvidenceHash',
  ]) {
    canonicalHex(
      construction[field],
      `${expectedKind}.construction.${field}`,
    );
    if (construction[field].length !== 64) {
      fail(`${expectedKind}.construction.${field} must be 32 bytes`);
    }
  }
  if (construction.inputSequence !== 0) {
    fail(`${expectedKind}.construction.inputSequence must be zero`);
  }

  const sourceParents = exactObject(
    action.sourceParents,
    `${expectedKind}.sourceParents`,
  );
  const previousBundle = validateSourceParent(
    sourceParents.previousBundle,
    `${expectedKind}.sourceParents.previousBundle`,
  );
  const funding = validateSourceParent(
    sourceParents.funding,
    `${expectedKind}.sourceParents.funding`,
  );
  if (previousBundle.parsed.txid === funding.parsed.txid) {
    fail(`${expectedKind} source parents must be distinct`);
  }
  const parents = new Map([
    ['previous-bundle', previousBundle],
    ['funding', funding],
  ]);

  const inputSources = exactArray(
    action.inputSources,
    `${expectedKind}.inputSources`,
  );
  if (inputSources.length !== 13) {
    fail(`${expectedKind} must record all 13 authenticated input sources`);
  }
  const sourceOutputs = exactArray(
    action.sourceOutputs,
    `${expectedKind}.sourceOutputs`,
  );
  if (sourceOutputs.length !== 13) {
    fail(`${expectedKind} must record all 13 source outputs`);
  }
  for (const [index, sourceOutput] of sourceOutputs.entries()) {
    const inputSource = exactObject(
      inputSources[index],
      `${expectedKind}.inputSources[${index}]`,
    );
    if (inputSource.inputIndex !== index) {
      fail(`${expectedKind}.inputSources[${index}] index mismatch`);
    }
    const expectedParentKind = index === 12
      ? 'funding'
      : 'previous-bundle';
    exactString(
      inputSource.parentKind,
      expectedParentKind,
      `${expectedKind}.inputSources[${index}].parentKind`,
    );
    const parent = parents.get(expectedParentKind);
    const expectedOutputIndex = index < 10
      ? index + 1
      : index === 10
        ? 11
        : 0;
    if (inputSource.outputIndex !== expectedOutputIndex) {
      fail(`${expectedKind}.inputSources[${index}] output index mismatch`);
    }
    exactString(
      inputSource.transactionId,
      parent.parsed.txid,
      `${expectedKind}.inputSources[${index}].transactionId`,
    );
    const transactionInput = parsedTransaction.inputs[index];
    if (
      transactionInput.outpoint.txid !== parent.parsed.txid
      || transactionInput.outpoint.vout !== expectedOutputIndex
    ) {
      fail(`${expectedKind} input ${index} does not spend its recorded parent`);
    }
    const serializedOutput =
      parent.parsed.outputs[expectedOutputIndex]?.serializedHex;
    if (serializedOutput === undefined) {
      fail(`${expectedKind} input ${index} source output is absent`);
    }
    const authenticatedOutput =
      parseSerializedSourceOutput(serializedOutput);
    exactString(
      inputSource.serializedOutputSha256,
      authenticatedOutput.sha256,
      `${expectedKind}.inputSources[${index}].serializedOutputSha256`,
    );
    exactObject(sourceOutput, `${expectedKind}.sourceOutputs[${index}]`);
    if (
      typeof sourceOutput.valueSats !== 'string'
      || !/^(?:0|[1-9][0-9]*)$/.test(sourceOutput.valueSats)
    ) {
      fail(`${expectedKind}.sourceOutputs[${index}].valueSats is invalid`);
    }
    for (const field of ['lockingBytecodeHex', 'tokenPrefixHex']) {
      if (
        typeof sourceOutput[field] !== 'string'
        || !/^(?:[0-9a-f]{2})*$/.test(sourceOutput[field])
      ) {
        fail(`${expectedKind}.sourceOutputs[${index}].${field} is invalid`);
      }
    }
    exactString(
      sourceOutput.valueSats,
      authenticatedOutput.valueSatoshis.toString(),
      `${expectedKind}.sourceOutputs[${index}].valueSats`,
    );
    exactString(
      sourceOutput.lockingBytecodeHex,
      authenticatedOutput.lockingBytecodeHex,
      `${expectedKind}.sourceOutputs[${index}].lockingBytecodeHex`,
    );
    exactString(
      sourceOutput.tokenPrefixHex,
      authenticatedOutput.tokenPrefixHex,
      `${expectedKind}.sourceOutputs[${index}].tokenPrefixHex`,
    );
  }
  const localVmEvidence = exactObject(
    action.localVmEvidence,
    `${expectedKind}.localVmEvidence`,
  );
  const localVmEvidenceHex = canonicalHex(
    localVmEvidence.hex,
    `${expectedKind}.localVmEvidence.hex`,
  );
  const localVmBytes = Buffer.from(localVmEvidenceHex, 'hex');
  exactString(
    localVmEvidence.sha256,
    sha256(localVmBytes),
    `${expectedKind}.localVmEvidence.sha256`,
  );
  exactString(
    localVmEvidence.evidenceHash,
    construction.localVmEvidenceHash,
    `${expectedKind}.localVmEvidence.evidenceHash`,
  );
  const inspectedVm = inspectV2LocalVmEvidence(localVmBytes);
  exactString(
    inspectedVm.evidenceHash,
    localVmEvidence.evidenceHash,
    `${expectedKind}.localVmEvidence inspected hash`,
  );
  exactString(
    inspectedVm.transaction.rawTransactionHex,
    action.rawTransactionHex,
    `${expectedKind}.localVmEvidence transaction`,
  );
  if (
    inspectedVm.inputs.length !== 13
    || inspectedVm.inputs.some((input, index) =>
      input.sourceTransaction.rawTransactionHex
      !== parents.get(index === 12 ? 'funding' : 'previous-bundle')
        .parent.rawTransactionHex)
  ) {
    fail(`${expectedKind} local VM evidence does not bind every parent byte`);
  }
  const rows = exactArray(action.rows, `${expectedKind}.rows`);
  if (rows.length !== 13) {
    fail(`${expectedKind} must record all 13 VM evaluations`);
  }
  for (const row of rows) {
    exactObject(row, `${expectedKind}.row`);
    const unlockBytes = exactInteger(
      row.unlockBytes,
      `${expectedKind}.${row.name}.unlockBytes`,
    );
    if (unlockBytes > 10_000) {
      fail(`${expectedKind}.${row.name} exceeds the 10000-byte unlock ceiling`);
    }
    exactBoolean(
      row.hardAccepted,
      true,
      `${expectedKind}.${row.name}.hardAccepted`,
    );
    exactBoolean(
      row.semanticAccepted,
      true,
      `${expectedKind}.${row.name}.semanticAccepted`,
    );
    const operationCost = exactInteger(
      row.operationCost,
      `${expectedKind}.${row.name}.operationCost`,
    );
    const maximumOperationCost = exactInteger(
      row.maximumOperationCost,
      `${expectedKind}.${row.name}.maximumOperationCost`,
    );
    const hashDigestIterations = exactInteger(
      row.hashDigestIterations,
      `${expectedKind}.${row.name}.hashDigestIterations`,
    );
    const maximumHashDigestIterations = exactInteger(
      row.maximumHashDigestIterations,
      `${expectedKind}.${row.name}.maximumHashDigestIterations`,
    );
    const signatureCheckCount = exactInteger(
      row.signatureCheckCount,
      `${expectedKind}.${row.name}.signatureCheckCount`,
    );
    const maximumSignatureChecks = exactInteger(
      row.maximumSignatureChecks,
      `${expectedKind}.${row.name}.maximumSignatureChecks`,
    );
    if (operationCost > maximumOperationCost) {
      fail(`${expectedKind}.${row.name} exceeds its operation budget`);
    }
    if (hashDigestIterations > maximumHashDigestIterations) {
      fail(`${expectedKind}.${row.name} exceeds its hash-iteration budget`);
    }
    if (signatureCheckCount > maximumSignatureChecks) {
      fail(`${expectedKind}.${row.name} exceeds its signature-check budget`);
    }
    if (
      typeof row.operationPercent !== 'number'
      || !Number.isFinite(row.operationPercent)
      || row.operationPercent < 0
      || row.operationPercent > 100
    ) {
      fail(`${expectedKind}.${row.name}.operationPercent is invalid`);
    }
  }
  return Object.freeze({
    kind: expectedKind,
    transactionBytes,
    transactionId: action.transactionId,
    maximumUnlockBytes: Math.max(...rows.map((row) => row.unlockBytes)),
    maximumOperationPercent: Math.max(
      ...rows.map((row) => row.operationPercent),
    ),
    feeSats: action.feeSats,
    proofGenerationMs: action.proofGenerationMs,
  });
};

const validateEvidence = (value) => {
  const evidence = exactObject(value, 'evidence');
  exactString(evidence.schema, EVIDENCE_SCHEMA, 'evidence.schema');
  exactString(
    evidence.eligibility,
    'development-only',
    'evidence.eligibility',
  );
  const claims = exactObject(evidence.claims, 'evidence.claims');
  exactBoolean(claims.finalKey, false, 'claims.finalKey');
  exactBoolean(claims.production, false, 'claims.production');
  exactBoolean(claims.releaseQualified, false, 'claims.releaseQualified');
  exactBoolean(claims.libauthBch2026, true, 'claims.libauthBch2026');
  for (const claim of [
    'bchnMempool',
    'bchnMined',
    'liveChainParentProvenance',
    'leanBch',
    'unmodifiedMaintainerBenchmark',
  ]) {
    exactBoolean(claims[claim], false, `claims.${claim}`);
  }
  exactBoolean(
    claims.productionSettlementBuilderPath,
    true,
    'claims.productionSettlementBuilderPath',
  );
  exactBoolean(
    claims.authenticatedSerializedParentOutputs,
    true,
    'claims.authenticatedSerializedParentOutputs',
  );
  const qualificationScope = exactObject(
    evidence.qualificationScope,
    'evidence.qualificationScope',
  );
  exactString(
    qualificationScope.settlementPath,
    'prepareV2DirectSettlement -> assembleV2DirectSettlement -> signV2DirectSettlement -> createV2LocalVmEvidence',
    'qualificationScope.settlementPath',
  );
  exactString(
    qualificationScope.feePolicy,
    'exact signed bytes at 1 satoshi per byte',
    'qualificationScope.feePolicy',
  );
  if (qualificationScope.inputSequence !== 0) {
    fail('qualificationScope.inputSequence must be zero');
  }
  if (
    typeof qualificationScope.parentTransactions !== 'string'
    || !qualificationScope.parentTransactions.includes(
      'no live-chain provenance is claimed',
    )
  ) {
    fail('qualificationScope must disclaim live-chain parent provenance');
  }
  const limits = exactObject(evidence.hardLimits, 'evidence.hardLimits');
  if (
    limits.transactionBytes !== 100_000
    || limits.unlockingBytecodeBytes !== 10_000
    || limits.standardVmResourcePercent !== 100
  ) {
    fail('evidence must use only the full BCH hard ceilings');
  }
  const bases = exactObject(evidence.exactDustBases, 'evidence.exactDustBases');
  const verifierBases = exactArray(
    bases.verifierSats,
    'exactDustBases.verifierSats',
  );
  if (
    verifierBases.length !== 10
    || verifierBases.some((value) => value !== '1200')
    || bases.bindingSats !== '1200'
    || bases.stateSats !== '2500'
    || bases.minimumChangeSats !== '546'
  ) {
    fail('evidence does not use the current exact PF10 dust-derived bases');
  }
  const result = exactObject(
    evidence.pf10FusedQGenesisActions,
    'pf10FusedQGenesisActions',
  );
  exactString(
    result.verdict,
    'production-builder-local-standard-pass-all-actions-precomputed-fixed-lines',
    'pf10FusedQGenesisActions.verdict',
  );
  const actions = exactArray(result.actions, 'pf10FusedQGenesisActions.actions');
  if (actions.length !== 3) fail('evidence must contain exactly three actions');
  const expectedKinds = ['deposit', 'transfer', 'withdrawal'];
  const summaries = expectedKinds.map((kind, index) =>
    validateAction(actions[index], kind));
  return Object.freeze({ evidence, summaries });
};

/**
 * Validate the beta lane without treating it as development or final evidence.
 * The transaction and VM rows have the exact same independently parsable shape
 * as the development lane, but the outer identity and every qualification claim
 * are beta-specific and fail closed.
 */
export const validatePf10BetaLibauthEvidence = (value) => {
  const evidence = exactObject(value, 'beta evidence');
  exactString(
    evidence.schema,
    PF10_BETA_LIBAUTH_EVIDENCE_SCHEMA,
    'beta evidence.schema',
  );
  exactString(
    evidence.eligibility,
    V2_BETA_LOCAL_ELIGIBILITY,
    'beta evidence.eligibility',
  );
  const expectedEvidenceFields = [
    'betaProofQualification', 'claims', 'eligibility', 'environment',
    'exactDustBases', 'generatedAt', 'hardLimits', 'identity',
    'pf10FusedQGenesisActions', 'qualificationScope', 'schema',
  ].sort();
  const actualEvidenceFields = Object.keys(evidence).sort();
  if (
    actualEvidenceFields.length !== expectedEvidenceFields.length
    || actualEvidenceFields.some(
      (field, index) => field !== expectedEvidenceFields[index],
    )
  ) fail('beta evidence has missing or unknown properties');
  const claims = exactObject(evidence.claims, 'beta evidence.claims');
  const expectedClaims = {
    authenticatedSerializedParentOutputs: true,
    b02Qualified: false,
    bchnMempool: false,
    bchnMined: false,
    betaSingleContributor: true,
    ceremonyQualified: false,
    d01Qualified: false,
    d02Qualified: false,
    developmentKey: false,
    finalKey: false,
    leanBch: false,
    libauthBch2026: true,
    liveChainParentProvenance: false,
    participantIndependenceEstablished: false,
    production: false,
    productionSettlementBuilderPath: true,
    q01FinalReplayQualified: false,
    q01Qualified: false,
    q02Qualified: false,
    q03Qualified: false,
    q04Qualified: false,
    q05Qualified: false,
    q06Qualified: false,
    q07Qualified: false,
    q08Qualified: false,
    q09Qualified: false,
    releaseQualified: false,
    unmodifiedMaintainerBenchmark: false,
  };
  const actualClaimNames = Object.keys(claims).sort();
  const expectedClaimNames = Object.keys(expectedClaims).sort();
  if (
    actualClaimNames.length !== expectedClaimNames.length
    || actualClaimNames.some((name, index) => name !== expectedClaimNames[index])
  ) fail('beta evidence.claims has missing or unknown properties');
  for (const [name, expected] of Object.entries(expectedClaims)) {
    exactBoolean(claims[name], expected, `beta evidence.claims.${name}`);
  }
  const actions = exactObject(
    evidence.pf10FusedQGenesisActions,
    'beta evidence.pf10FusedQGenesisActions',
  );
  const expectedActionSetFields = [
    'actionCount', 'actions', 'fixedLineDerivation', 'fixedPrograms',
    'identityExecutorRows', 'topologyId', 'verdict',
  ].sort();
  const actualActionSetFields = Object.keys(actions).sort();
  if (
    actualActionSetFields.length !== expectedActionSetFields.length
    || actualActionSetFields.some(
      (field, index) => field !== expectedActionSetFields[index],
    )
  ) fail('beta evidence action set has missing or unknown properties');
  exactString(
    actions.verdict,
    'beta-local-production-builder-standard-pass-all-actions-precomputed-fixed-lines',
    'beta evidence.pf10FusedQGenesisActions.verdict',
  );
  const proofQualification = exactObject(
    evidence.betaProofQualification,
    'beta evidence.betaProofQualification',
  );
  const proofQualificationFields = Object.keys(proofQualification).sort();
  const expectedProofQualificationFields = [
    'eligibility', 'instanceId', 'profileId', 'schema', 'sha256', 'status',
  ];
  if (
    proofQualificationFields.length !== expectedProofQualificationFields.length
    || proofQualificationFields.some(
      (field, index) => field !== expectedProofQualificationFields[index],
    )
  ) fail('beta evidence.betaProofQualification has missing or unknown properties');
  exactString(
    proofQualification.schema,
    V2_BETA_PROOF_QUALIFICATION_SCHEMA,
    'beta evidence.betaProofQualification.schema',
  );
  exactString(
    proofQualification.eligibility,
    V2_BETA_LOCAL_ELIGIBILITY,
    'beta evidence.betaProofQualification.eligibility',
  );
  exactString(
    proofQualification.status,
    'beta-proof-qualification-reverified-unqualified',
    'beta evidence.betaProofQualification.status',
  );
  canonicalHex(
    proofQualification.sha256,
    'beta evidence.betaProofQualification.sha256',
  );
  if (proofQualification.sha256.length !== 64) {
    fail('beta evidence.betaProofQualification.sha256 must be 32 bytes');
  }
  exactString(
    proofQualification.profileId,
    evidence.identity.profileId,
    'beta evidence.betaProofQualification.profileId',
  );
  exactString(
    proofQualification.instanceId,
    evidence.identity.instanceId,
    'beta evidence.betaProofQualification.instanceId',
  );
  // Reuse the byte, parent, fee, policy, and VM validation by translating only
  // the deliberately non-interchangeable outer beta labels.
  const translated = {
    ...evidence,
    schema: EVIDENCE_SCHEMA,
    eligibility: 'development-only',
    pf10FusedQGenesisActions: {
      ...actions,
      verdict:
        'production-builder-local-standard-pass-all-actions-precomputed-fixed-lines',
    },
  };
  const checked = validateEvidence(translated);
  const expectedKinds = ['deposit', 'transfer', 'withdrawal'];
  const actionBindings = expectedKinds.map((expectedKind, index) => {
    const action = actions.actions[index];
    const binding = validatePf10BetaActionProofBinding({
      action,
      expectedKind,
      instanceId: evidence.identity.instanceId,
      profileId: evidence.identity.profileId,
    });
    const parsed = parseV2RawTransaction(action.rawTransactionHex);
    decodeDirectV2BindingUnlock({
      expectedPacket: binding.packet,
      sourceLockingBytecode: Buffer.from(
        action.sourceOutputs[10].lockingBytecodeHex,
        'hex',
      ),
      unlockingBytecode: parsed.inputs[10].unlockingBytecode,
    });
    return Object.freeze({
      kind: expectedKind,
      packetSha256: binding.packetSha256,
      proofBindingSha256: binding.proofBindingSha256,
    });
  });
  return Object.freeze({
    evidence,
    summaries: checked.summaries,
    actionBindings: Object.freeze(actionBindings),
  });
};

export const runPf10LibauthQualification = async (
  options,
  {
    betaLocal = false,
    childRunner = runChild,
  } = {},
) => {
  const publication = await preparePublicationPaths(options);
  const stage = await mkdtemp(path.join(
    publication.outputParent,
    '.pf10-libauth-stage-',
  ));
  let childDirectory;
  let published = false;
  try {
    await canonicalDirectory(stage, 'staging directory', { privateMode: true });
    childDirectory = await mkdtemp(path.join(
      publication.temporaryRoot,
      '.pf10-libauth-child-',
    ));
    await canonicalDirectory(childDirectory, 'child temporary directory', { privateMode: true });
    const temporaryFiles = path.join(childDirectory, 'tmp');
    await mkdir(temporaryFiles, { mode: 0o700 });
    await canonicalDirectory(temporaryFiles, 'child temporary files', { privateMode: true });
    const childEvidencePath = path.join(childDirectory, 'libauth.json');
    const evidencePath = path.join(stage, 'libauth.json');
    const executed = await childRunner({
      evidencePath: childEvidencePath,
      betaLocal,
      options: Object.freeze({
        ...options,
        output: publication.output,
        temporaryRoot: publication.temporaryRoot,
      }),
      temporaryDirectory: childDirectory,
    });
    await writePrivateFile(
      path.join(stage, 'stdout.txt'),
      executed.stdout,
      'qualification stdout',
    );
    await writePrivateFile(
      path.join(stage, 'stderr.txt'),
      executed.stderr,
      'qualification stderr',
    );
    if (executed.code !== 0 || executed.signal !== null) {
      fail(
        `PF10 Libauth qualification test failed: code=${executed.code} signal=${executed.signal}`,
      );
    }
    await canonicalSingleLinkFile(childEvidencePath, 'child Libauth evidence');
    const parsed = JSON.parse(await readFile(childEvidencePath, 'utf8'));
    const validated = betaLocal
      ? validatePf10BetaLibauthEvidence(parsed)
      : validateEvidence(parsed);
    const evidenceBytes = canonicalBytes(validated.evidence);
    await writePrivateFile(evidencePath, evidenceBytes, 'canonical Libauth evidence');
    const summary = Object.freeze({
      schema: betaLocal
        ? PF10_BETA_LIBAUTH_QUALIFICATION_SCHEMA
        : SCRIPT_SCHEMA,
      eligibility: betaLocal
        ? V2_BETA_LOCAL_ELIGIBILITY
        : 'development-only',
      claims: validated.evidence.claims,
      identity: validated.evidence.identity,
      hardLimits: validated.evidence.hardLimits,
      exactDustBases: validated.evidence.exactDustBases,
      actions: validated.summaries,
      evidence: Object.freeze({
        path: 'libauth.json',
        bytes: evidenceBytes.length,
        sha256: sha256(evidenceBytes),
      }),
      command: Object.freeze({
        executable: process.execPath,
        arguments: Object.freeze(['--test', path.relative(
          repositoryRoot,
          testPath,
        )]),
        workingDirectory: '.',
      }),
    });
    const summaryBytes = canonicalBytes(summary);
    await writePrivateFile(
      path.join(stage, 'qualification-summary.json'),
      summaryBytes,
      'qualification summary',
    );
    await rm(temporaryFiles, { recursive: true, force: false });
    await publishStage({
      stage,
      output: publication.output,
      outputParent: publication.outputParent,
      ...(betaLocal ? {
        publicationSchema: PF10_BETA_LIBAUTH_PUBLICATION_SCHEMA,
      } : {}),
    });
    published = true;
    return Object.freeze({
      outputDirectory: publication.output,
      evidenceSha256: summary.evidence.sha256,
      actions: summary.actions,
      eligibility: summary.eligibility,
    });
  } finally {
    if (childDirectory !== undefined) {
      await rm(childDirectory, { recursive: true, force: true });
    }
    if (!published) {
      await rm(stage, { recursive: true, force: true });
    }
  }
};

export const main = async (argv = process.argv.slice(2)) => {
  const result = await runPf10LibauthQualification(parseOptions(argv));
  process.stdout.write(`${canonicalizeJcs(result)}\n`);
};

const directRun = process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === import.meta.filename;

if (directRun) {
  main().catch((error) => {
    process.stderr.write(`${error?.stack ?? error}\n`);
    process.exitCode = 1;
  });
}
