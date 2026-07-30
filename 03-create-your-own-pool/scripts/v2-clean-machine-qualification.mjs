#!/usr/bin/env node
/*
 * Q-08 clean-host driver. This is intentionally a one-shot evidence writer:
 * it does not create a development substitute, retry a failed action, or
 * interpret fixture output as chain evidence. The command plan is an
 * explicitly supplied, hash-recorded integration boundary for the final CLI.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, realpathSync, renameSync, writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { cashAddressToLockingBytecode } from '@bitauth/libauth';

import {
  deriveV2ManifestArtifactFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  signV2Q08HostTranscriptForRelease,
  V2_Q08_HOST_STATEMENT_SCHEMA,
} from '../packages/profile/v2/q08-host-evidence.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import {
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
} from '../packages/recover/raw-chain-recovery.mjs';
import {
  deriveV2Q02LaneAuthorityContextFromValidatedDescriptor,
} from './v2-q02-lane-evidence.mjs';
import {
  normalizeV2Q08LaneEvidenceReferences,
  verifyV2Q08ActionLaneEvidence,
} from './v2-q08-lane-evidence.mjs';
import { revalidateV2D02AuditClosure } from './v2-d02-audit-closure.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../..');
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const MAX_OUTPUT = 8 * 1024 * 1024;
const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdraw', 'recoveredSpend']);
const HOST_STATE_STEPS = Object.freeze(['wallet', 'sync', 'deleteLocalState', 'recover']);
const HOST_ROLES = Object.freeze(['clean-host-a', 'clean-host-b']);
const STEPS = Object.freeze([
  'npmCi', 'wallet', 'fundingAddress', 'sync', 'deposit', 'transfer', 'withdraw',
  'deleteLocalState', 'recover', 'recoveredSpend',
]);

export const V2_Q08_ATTEMPT_RECORD_SCHEMA = 'shieldkit-v2-direct-q08-attempt-record-v1';
export const V2_Q08_COMMAND_PLAN_SCHEMA = 'shieldkit-v2-direct-q08-command-plan-v1';
export const V2_Q08_FUNDING_CHECKPOINT_SCHEMA = 'shieldkit-v2-direct-q08-out-of-band-funding-v2';
export const V2_Q08_FUNDING_CHECKPOINT_FILE = 'q08-funding-checkpoint.json';
export const V2_Q08_HOST_STATE_EVIDENCE_SCHEMA = 'shieldkit-v2-direct-q08-host-state-evidence-v1';
export const V2_Q08_SOURCE_PIN_SCHEMA = 'shieldkit-v2-direct-q08-source-pin-v1';
export const V2_Q08_COMMAND_PLAN_ARTIFACT_ID = 'q08-command-plan';
export const V2_Q08_SOURCE_PIN_ARTIFACT_ID = 'q08-source-pin';

export class V2Q08CleanMachineQualificationError extends Error {
  constructor(message) { super(message); this.name = 'V2Q08CleanMachineQualificationError'; }
}
const fail = (message) => { throw new V2Q08CleanMachineQualificationError(message); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
const canonical = (value) => canonicalizeJcs(value);

function exactKeys(value, expected, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function absolute(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`);
  }
  return value;
}

function directRegularFile(path, label) {
  const entry = lstatSync(path, { throwIfNoEntry: false });
  if (entry === undefined || !entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    fail(`${label} must be one direct regular non-symlink file`);
  }
  if (realpathSync(path) !== path) {
    fail(`${label} must not traverse a symlink`);
  }
  return entry;
}

function privateNewDirectory(path) {
  absolute(path, 'Q-08 output directory');
  if (existsSync(path)) fail('Q-08 refuses a preexisting output directory');
  const parent = dirname(path);
  const parentEntry = lstatSync(parent, { throwIfNoEntry: false });
  if (
    parentEntry === undefined
    || !parentEntry.isDirectory()
    || parentEntry.isSymbolicLink()
    || realpathSync(parent) !== parent
  ) {
    fail('Q-08 output parent must be a direct canonical directory');
  }
  mkdirSync(path, { mode: 0o700 });
  const entry = lstatSync(path);
  if (
    !entry.isDirectory()
    || entry.isSymbolicLink()
    || realpathSync(path) !== path
  ) {
    fail('Q-08 output directory is not direct');
  }
  chmodSync(path, 0o700);
}

function writePrivateBytes(path, bytes) {
  if (existsSync(path)) fail(`Q-08 refuses to overwrite ${path}`);
  const parent = dirname(path); const parentEntry = lstatSync(parent);
  if (
    !parentEntry.isDirectory()
    || parentEntry.isSymbolicLink()
    || realpathSync(parent) !== parent
  ) {
    fail('Q-08 output parent is invalid');
  }
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) fail('Q-08 output bytes must be nonempty');
  const temporary = join(parent, `.${process.pid}.${Date.now()}.tmp`);
  const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { writeSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  const parentFd = openSync(parent, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try { fsyncSync(parentFd); } finally { closeSync(parentFd); }
  const written = lstatSync(path);
  if (
    !written.isFile()
    || written.isSymbolicLink()
    || written.nlink !== 1
    || (written.mode & 0o777) !== 0o600
  ) {
    fail('Q-08 output file is not one direct 0600 regular file');
  }
  return Object.freeze({ bytes: bytes.length, sha256: sha256(bytes), path });
}

function writePrivateJson(path, value) {
  return writePrivateBytes(path, Buffer.from(canonical(value), 'utf8'));
}

function readJson(path, label) {
  absolute(path, label); directRegularFile(path, label);
  const pathname = lstatSync(path, { bigint: true });
  let descriptor;
  let bytes;
  try {
    descriptor = openSync(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    const before = fstatSync(descriptor, { bigint: true });
    bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const finalPath = lstatSync(path, { bigint: true, throwIfNoEntry: false });
    const fields = [
      'dev', 'ino', 'size', 'mode', 'nlink', 'uid', 'mtimeNs', 'ctimeNs',
    ];
    if (
      !before.isFile()
      || before.nlink !== 1n
      || !after.isFile()
      || after.nlink !== 1n
      || finalPath === undefined
      || !finalPath.isFile()
      || finalPath.isSymbolicLink()
      || finalPath.nlink !== 1n
      || fields.some(
        (field) => pathname[field] !== before[field]
          || before[field] !== after[field]
          || after[field] !== finalPath[field],
      )
    ) {
      fail(`${label} changed while it was read`);
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`${label} is not JSON`); }
  return Object.freeze({ path, bytes, sha256: sha256(bytes), value });
}

function readCanonicalJson(path, label) {
  const parsed = readJson(path, label);
  if (!parsed.bytes.equals(Buffer.from(canonical(parsed.value), 'utf8'))) {
    fail(`${label} must use exact RFC8785/JCS canonical bytes`);
  }
  return parsed;
}

export function parseV2Q08Arguments(argv) {
  const fields = new Map();
  const names = new Set(['--output-dir', '--descriptor', '--final-manifest', '--profile-core', '--release-root', '--command-plan', '--d02-closure', '--funding-checkpoint', '--host-identity', '--host-role', '--host-signing-key', '--expected-commit', '--expected-tree']);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) fail('usage: v2-clean-machine-qualification.mjs --output-dir <absolute-new-dir> --descriptor <absolute> --final-manifest <absolute> --profile-core <absolute> --release-root <compiled-root-id> --command-plan <absolute> --d02-closure <absolute> --funding-checkpoint <absolute> --host-identity <absolute> --host-role <clean-host-a|clean-host-b> --host-signing-key <absolute-0600-ed25519-pkcs8> --expected-commit <sha1> --expected-tree <sha1>');
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index]; const value = argv[index + 1];
    if (!names.has(name) || fields.has(name) || typeof value !== 'string' || value.length === 0) fail('Q-08 arguments are malformed or duplicated');
    fields.set(name, value);
  }
  for (const required of names) if (!fields.has(required)) fail(`Q-08 requires ${required}`);
  const expectedCommit = fields.get('--expected-commit'); const expectedTree = fields.get('--expected-tree');
  if (!HEX_40.test(expectedCommit) || !HEX_40.test(expectedTree)) fail('Q-08 expected commit and tree must be lowercase SHA-1 values');
  const hostRole = fields.get('--host-role');
  if (!HOST_ROLES.includes(hostRole)) fail('Q-08 host role must be clean-host-a or clean-host-b');
  return Object.freeze({
    outputDirectory: absolute(fields.get('--output-dir'), 'Q-08 output directory'),
    descriptorPath: absolute(fields.get('--descriptor'), 'Q-08 descriptor'),
    finalManifestPath: absolute(fields.get('--final-manifest'), 'Q-08 final manifest'),
    profileCorePath: absolute(fields.get('--profile-core'), 'Q-08 profile core'),
    releaseRootId: fields.get('--release-root'),
    commandPlanPath: absolute(fields.get('--command-plan'), 'Q-08 command plan'),
    d02ClosurePath: absolute(fields.get('--d02-closure'), 'Q-08 D-02 closure'),
    fundingCheckpointPath: absolute(fields.get('--funding-checkpoint'), 'Q-08 funding checkpoint'),
    hostIdentityPath: absolute(fields.get('--host-identity'), 'Q-08 host identity'),
    hostRole,
    hostSigningKeyPath: absolute(fields.get('--host-signing-key'), 'Q-08 host signing key'),
    expectedCommit, expectedTree,
  });
}

async function capture(executable, arguments_, { cwd, env }) {
  const child = spawn(executable, arguments_, { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = ''; let spawnError;
  const append = (target, chunk) => {
    if (target.value.length + chunk.length > MAX_OUTPUT) { child.kill('SIGKILL'); return; }
    target.value += chunk;
  };
  const out = { value: stdout }; const err = { value: stderr };
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => append(out, chunk)); child.stderr.on('data', (chunk) => append(err, chunk));
  child.once('error', (error) => { spawnError = error; });
  const closed = await new Promise((done) => child.once('close', (exitCode, signal) => done({ exitCode, signal })));
  if (spawnError) fail(`Q-08 cannot spawn ${executable}: ${spawnError.message}`);
  return Object.freeze({ executable, arguments: Object.freeze([...arguments_]), exitCode: closed.exitCode, signal: closed.signal, stdout: out.value, stderr: err.value });
}

async function requireCommand(runner, executable, arguments_, options, label) {
  const result = await runner(executable, arguments_, options);
  if (result.exitCode !== 0 || result.signal !== null) fail(`Q-08 ${label} failed: exit=${result.exitCode} signal=${result.signal} stderr=${String(result.stderr ?? '').trim()}`);
  if (typeof result.stdout !== 'string' || typeof result.stderr !== 'string') fail(`Q-08 ${label} runner returned malformed output`);
  return result;
}

async function gitState(runner) {
  const run = (args) => requireCommand(runner, 'git', args, { cwd: workspaceRoot, env: process.env }, `git ${args.join(' ')}`);
  const [commit, tree, status] = await Promise.all([run(['rev-parse', 'HEAD^{commit}']), run(['rev-parse', 'HEAD^{tree}']), run(['status', '--porcelain=v1', '--untracked-files=all'])]);
  const value = { commit: commit.stdout.trim(), tree: tree.stdout.trim() };
  if (!HEX_40.test(value.commit) || !HEX_40.test(value.tree) || status.stdout !== '') fail('Q-08 requires an exact clean Git commit and tree');
  return Object.freeze(value);
}

function parsePlan(path) {
  const plan = readCanonicalJson(path, 'Q-08 command plan');
  exactKeys(plan.value, ['commands', 'schema'], 'Q-08 command plan');
  if (plan.value.schema !== V2_Q08_COMMAND_PLAN_SCHEMA) fail('Q-08 command plan schema is unsupported');
  exactKeys(plan.value.commands, STEPS, 'Q-08 command plan commands');
  for (const step of STEPS) {
    const command = plan.value.commands[step];
    exactKeys(command, ['arguments', 'executable'], `Q-08 command ${step}`);
    if (typeof command.executable !== 'string' || command.executable.length === 0 || !Array.isArray(command.arguments) || command.arguments.some((arg) => typeof arg !== 'string' || arg.length === 0)) fail(`Q-08 command ${step} is malformed`);
    if (/fixture|test-only|mock/i.test(`${command.executable}\u0000${command.arguments.join('\u0000')}`)) fail(`Q-08 command ${step} references test fixtures`);
  }
  const npm = plan.value.commands.npmCi;
  if (npm.executable !== 'npm' || canonical(npm.arguments) !== canonical(['ci', '--ignore-scripts', '--no-audit', '--no-fund'])) fail('Q-08 requires immutable npm ci --ignore-scripts --no-audit --no-fund');
  return plan;
}

function parseFundingCheckpoint(path, {
  expectedCheckpoint = undefined,
  testOnly = false,
} = {}) {
  const checkpoint = testOnly
    ? readJson(path, 'Q-08 test-only funding checkpoint')
    : readCanonicalJson(path, 'Q-08 out-of-band funding checkpoint');
  // Deliberately retain the legacy shape only for API-only test seams. A
  // production host must provide independently checkable transaction/output
  // and header/Merkle facts; an address string or signer assertion is never
  // evidence of funding by itself.
  if (testOnly) {
    exactKeys(checkpoint.value, ['fundedAt', 'fundingAddress', 'fundingTransactionHex', 'schema', 'status'], 'Q-08 test-only funding checkpoint');
    if (checkpoint.value.schema !== 'shieldkit-v2-direct-q08-out-of-band-funding-v1' || checkpoint.value.status !== 'funded-out-of-band') fail('Q-08 test-only funding checkpoint is malformed');
    try { parseV2RawTransaction(checkpoint.value.fundingTransactionHex); } catch { fail('Q-08 test-only funding transaction is invalid'); }
    return checkpoint;
  }
  exactKeys(checkpoint.value, ['chainEvidence', 'fundedAt', 'fundingAddress', 'fundingLockingBytecodeHex', 'fundingOutputIndex', 'fundingTransactionHex', 'fundingValueSatoshis', 'provenanceDeclaration', 'schema', 'status'], 'Q-08 out-of-band funding checkpoint');
  const value = checkpoint.value;
  const fundedAt = Date.parse(value.fundedAt);
  if (value.schema !== V2_Q08_FUNDING_CHECKPOINT_SCHEMA || value.status !== 'funded-out-of-band' || !Number.isSafeInteger(fundedAt) || new Date(fundedAt).toISOString() !== value.fundedAt || typeof value.fundingAddress !== 'string' || !/^[0-9a-f]+$/.test(value.fundingTransactionHex) || !Number.isSafeInteger(value.fundingOutputIndex) || value.fundingOutputIndex < 0 || typeof value.fundingValueSatoshis !== 'string' || !/^[1-9][0-9]*$/.test(value.fundingValueSatoshis) || typeof value.fundingLockingBytecodeHex !== 'string' || !/^[0-9a-f]+$/.test(value.fundingLockingBytecodeHex)) fail('Q-08 funding checkpoint fields are malformed');
  let transaction; try { transaction = parseV2RawTransaction(value.fundingTransactionHex); } catch { fail('Q-08 funding checkpoint does not contain an exact raw transaction'); }
  const output = transaction.outputs[value.fundingOutputIndex];
  if (output === undefined || output.valueSatoshis !== BigInt(value.fundingValueSatoshis) || output.lockingBytecode.toString('hex') !== value.fundingLockingBytecodeHex) fail('Q-08 funding checkpoint does not bind the declared funded output/value');
  const decodedAddress = cashAddressToLockingBytecode(value.fundingAddress);
  if (typeof decodedAddress === 'string' || Buffer.from(decodedAddress.bytecode).toString('hex') !== value.fundingLockingBytecodeHex) fail('Q-08 funding address does not cryptographically bind the funded output locking bytecode');
  exactKeys(value.provenanceDeclaration, ['classification', 'scope'], 'Q-08 funding provenance declaration');
  if (value.provenanceDeclaration.classification !== 'declared-non-faucet-non-sponsor' || value.provenanceDeclaration.scope !== 'signer-assertion-not-independently-verified') fail('Q-08 funding provenance must be explicitly labelled as a non-independent signer assertion');
  exactKeys(value.chainEvidence, ['blockHeight', 'checkpoint', 'merkleBranch', 'rawHeaders', 'tip', 'transactionCount', 'transactionIndex'], 'Q-08 funding chain evidence');
  const chain = value.chainEvidence;
  if (!Number.isSafeInteger(chain.blockHeight) || chain.blockHeight < 0 || !Array.isArray(chain.rawHeaders) || chain.rawHeaders.some((entry) => typeof entry !== 'string' || !/^[0-9a-f]{160}$/.test(entry)) || !Array.isArray(chain.merkleBranch) || chain.merkleBranch.some((entry) => !HEX_32.test(entry))) fail('Q-08 funding chain evidence is malformed');
  if (
    expectedCheckpoint !== undefined
    && canonical(chain.checkpoint) !== canonical(expectedCheckpoint)
  ) {
    fail('Q-08 funding chain evidence does not start at the signed-manifest Chipnet checkpoint');
  }
  let segment; try { segment = verifyRawHeaderSegment({ checkpoint: chain.checkpoint, rawHeaders: chain.rawHeaders.map((entry) => Buffer.from(entry, 'hex')), tip: chain.tip }); } catch (error) { fail(`Q-08 funding chain evidence is structurally invalid: ${error instanceof Error ? error.message : String(error)}`); }
  const header = segment.headers.find((entry) => entry.height === chain.blockHeight);
  if (header === undefined || segment.tip.height - chain.blockHeight + 1 < 6) fail('Q-08 funding transaction lacks six structurally linked confirmations');
  try { verifyBchTransactionMerkleProof({ rawTransaction: transaction.bytes, transactionIndex: chain.transactionIndex, transactionCount: chain.transactionCount, branch: chain.merkleBranch, headerMerkleRoot: header.merkleRoot }); } catch (error) { fail(`Q-08 funding transaction lacks a valid raw-header Merkle proof: ${error instanceof Error ? error.message : String(error)}`); }
  return checkpoint;
}

export function validateV2Q08FundingCheckpoint(path, options = {}) {
  return parseFundingCheckpoint(path, options);
}

export function normalizeV2Q08HostStateEvidenceReference(value) {
  exactKeys(value, ['path', 'sha256'], 'Q-08 host-state evidence reference');
  if (typeof value.path !== 'string' || value.path.length === 0 || isAbsolute(value.path) || value.path.split(/[\\/]/u).includes('..') || !HEX_32.test(value.sha256)) fail('Q-08 host-state evidence reference is unsafe or malformed');
  return Object.freeze({ path: value.path, sha256: value.sha256 });
}

export function verifyV2Q08HostStateEvidence({ evidenceRoot, reference, step, status, identity, stdoutSha256, stderrSha256, recoveredNoteId = null }) {
  if (!HOST_STATE_STEPS.includes(step)) fail('Q-08 host-state evidence step is unsupported');
  const normalized = normalizeV2Q08HostStateEvidenceReference(reference);
  const path = resolve(evidenceRoot, normalized.path);
  if (!path.startsWith(`${evidenceRoot}/`)) fail('Q-08 host-state evidence escapes its output directory');
  const evidence = readCanonicalJson(path, `Q-08 ${step} host-state evidence`);
  if (evidence.sha256 !== normalized.sha256) fail('Q-08 host-state evidence hash differs from its command result');
  exactKeys(evidence.value, ['commandStderrSha256', 'commandStdoutSha256', 'facts', 'instanceId', 'profileId', 'schema', 'status', 'step'], `Q-08 ${step} host-state evidence`);
  const value = evidence.value;
  if (value.schema !== V2_Q08_HOST_STATE_EVIDENCE_SCHEMA || value.step !== step || value.status !== status || value.profileId !== identity.profileId || value.instanceId !== identity.instanceId || value.commandStdoutSha256 !== stdoutSha256 || value.commandStderrSha256 !== stderrSha256) fail(`Q-08 ${step} host-state evidence does not bind the exact command result`);
  const facts = value.facts;
  if (step === 'wallet') { exactKeys(facts, ['walletPublicId'], 'Q-08 wallet host-state facts'); if (!HEX_32.test(facts.walletPublicId)) fail('Q-08 wallet host-state evidence lacks a public wallet identifier'); }
  if (step === 'sync') { exactKeys(facts, ['genesisBlockHash', 'tipBlockHash', 'tipHeight'], 'Q-08 sync host-state facts'); if (!HEX_32.test(facts.genesisBlockHash) || !HEX_32.test(facts.tipBlockHash) || !Number.isSafeInteger(facts.tipHeight) || facts.tipHeight < 0) fail('Q-08 sync host-state evidence is malformed'); }
  if (step === 'deleteLocalState') { exactKeys(facts, ['deletedStateSha256'], 'Q-08 deletion host-state facts'); if (!HEX_32.test(facts.deletedStateSha256)) fail('Q-08 deletion host-state evidence is malformed'); }
  if (step === 'recover') { exactKeys(facts, ['recoveredNoteId', 'recoveryJournalSha256'], 'Q-08 recovery host-state facts'); if (!HEX_32.test(facts.recoveredNoteId) || !HEX_32.test(facts.recoveryJournalSha256) || facts.recoveredNoteId !== recoveredNoteId) fail('Q-08 recovery host-state evidence does not bind the recovered note'); }
  return Object.freeze({ path: normalized.path, sha256: normalized.sha256 });
}

function parseHostIdentity(path) {
  const identity = readJson(path, 'Q-08 host identity');
  exactKeys(identity.value, ['hostIdentity', 'schema'], 'Q-08 host identity');
  if (identity.value.schema !== 'shieldkit-v2-direct-q08-host-identity-v1' || !HEX_32.test(identity.value.hostIdentity)) fail('Q-08 host identity is invalid');
  return Object.freeze({ ...identity, hostIdentity: identity.value.hostIdentity });
}

function assertFinalRuntime(runtime) {
  if (runtime?.eligibility !== 'final-qualified') fail('Q-08 refuses development-only runtime material');
  const claims = runtime.claims;
  if (
    claims === undefined
    || claims.finalKey !== true
    || claims.developmentKey !== false
    || claims.ceremonyQualified !== true
    || claims.production !== false
    || claims.releaseQualified !== false
  ) {
    fail('Q-08 requires a D-01-qualified final key without a premature production or release claim');
  }
}

function parseStepResult(
  step,
  result,
  identity,
  {
    authorityContext,
    evidenceRoot,
    testOnly,
  },
) {
  if (step === 'npmCi') return Object.freeze({ status: 'installed-immutable' });
  let value;
  try { value = JSON.parse(result.stdout); } catch { fail(`Q-08 ${step} did not emit one JSON result`); }
  const statusByStep = Object.freeze({ wallet: 'wallet-ready', fundingAddress: 'funding-address-displayed', sync: 'synced-from-genesis', deleteLocalState: 'local-state-deleted', recover: 'recovered-from-chain-history' });
  const action = ACTIONS.includes(step);
  const keys = ['instanceId', 'profileId', 'schema', 'status'];
  if (!testOnly && HOST_STATE_STEPS.includes(step)) keys.push('stateEvidence');
  if (action) keys.push('action', 'laneEvidence', 'rawTransactionHex', 'transactionId');
  if (step === 'fundingAddress') keys.push('fundingAddress');
  if (step === 'recover') keys.push('recoveredNoteId');
  if (step === 'recoveredSpend') keys.push('spentNoteId');
  exactKeys(value, keys, `Q-08 ${step} result`);
  if (value.schema !== 'shieldkit-v2-direct-q08-step-result-v2' || value.profileId !== identity.profileId || value.instanceId !== identity.instanceId || (action ? value.status !== 'confirmed' : value.status !== statusByStep[step])) fail(`Q-08 ${step} result identity or status is invalid`);
  const stateEvidence = !testOnly && HOST_STATE_STEPS.includes(step)
    ? normalizeV2Q08HostStateEvidenceReference(value.stateEvidence)
    : null;
  if (step === 'fundingAddress') {
    if (typeof value.fundingAddress !== 'string' || value.fundingAddress.length < 8) fail('Q-08 funding-address result is invalid');
    return Object.freeze({ status: value.status, fundingAddress: value.fundingAddress });
  }
  if (step === 'recover') {
    if (!HEX_32.test(value.recoveredNoteId)) fail('Q-08 recovery did not identify one recovered note');
    return Object.freeze({ status: value.status, recoveredNoteId: value.recoveredNoteId, ...(stateEvidence === null ? {} : { stateEvidence }) });
  }
  if (!action) return Object.freeze({ status: value.status, ...(stateEvidence === null ? {} : { stateEvidence }) });
  const expectedAction =
    step === 'withdraw' || step === 'recoveredSpend'
      ? 'withdrawal'
      : step;
  if (value.action !== expectedAction) fail(`Q-08 ${step} action evidence is mislabeled`);
  if (step === 'recoveredSpend' && !HEX_32.test(value.spentNoteId)) fail('Q-08 recovered spend does not identify its note');
  if (!HEX_32.test(value.transactionId) || typeof value.rawTransactionHex !== 'string' || !/^[0-9a-f]+$/.test(value.rawTransactionHex)) fail(`Q-08 ${step} raw transaction evidence is invalid`);
  let parsed; try { parsed = parseV2RawTransaction(value.rawTransactionHex); } catch { fail(`Q-08 ${step} raw transaction cannot be parsed`); }
  if (parsed.txid !== value.transactionId) fail(`Q-08 ${step} transaction ID does not bind raw bytes`);
  const laneEvidence =
    normalizeV2Q08LaneEvidenceReferences(value.laneEvidence);
  if (!testOnly) {
    verifyV2Q08ActionLaneEvidence({
      authorityContext,
      evidenceRoot,
      expected: {
        action: value.action,
        carrierCount: identity.carrierCount,
        instanceId: identity.instanceId,
        journeyStep: step,
        profileId: identity.profileId,
        profileSha256: identity.profileSha256,
        rawTransactionHex: value.rawTransactionHex,
        spentNoteId:
          step === 'recoveredSpend' ? value.spentNoteId : null,
        transactionId: value.transactionId,
      },
      laneEvidence,
    });
  }
  return Object.freeze({
    status: value.status,
    action: value.action,
    laneEvidence,
    rawTransactionHex: value.rawTransactionHex,
    transactionId: value.transactionId,
    ...(step === 'recoveredSpend'
      ? { spentNoteId: value.spentNoteId }
      : {}),
  });
}

export async function runV2Q08CleanMachineQualification(options, dependencies = {}) {
  exactKeys(
    dependencies,
    Object.keys(dependencies),
    'Q-08 injected dependencies',
  );
  const dependencyNames = Object.keys(dependencies);
  if (
    dependencyNames.some(
      (name) => !['runner', 'verifyFinalInputs'].includes(name),
    )
  ) {
    fail('Q-08 received an unsupported injected dependency');
  }
  const testOnly = options?.testOnly === true;
  if (dependencyNames.length > 0 && !testOnly) {
    fail(
      'Q-08 dependency injection is restricted to test-only nonqualifying mode',
    );
  }
  exactKeys(options, [
    'commandPlanPath', 'd02ClosurePath', 'descriptorPath',
    'expectedCommit', 'expectedTree',
    'finalManifestPath', 'fundingCheckpointPath', 'hostIdentityPath',
    'hostRole', 'outputDirectory', 'profileCorePath', 'releaseRootId',
    ...(!testOnly ? ['hostSigningKeyPath'] : []),
    ...(testOnly ? ['testOnly'] : []),
  ], 'Q-08 options');
  if (!HOST_ROLES.includes(options.hostRole)) {
    fail('Q-08 host role must be clean-host-a or clean-host-b');
  }
  const runner = dependencies.runner ?? capture;
  // This must happen before reading any caller-selected descriptor, profile,
  // or command-plan bytes. A release package cannot nominate its own trust
  // root or descriptor signer set.
  const releaseRoot = testOnly
    ? null
    : resolveV2FinalReleaseRoot(options?.releaseRootId);
  if (
    releaseRoot !== null
    && !releaseRoot.cleanHosts.some((entry) => entry.role === options.hostRole)
  ) {
    fail('Q-08 host role is not approved by the compiled release root');
  }
  const verifyFinalInputs = dependencies.verifyFinalInputs ?? (async (input) => {
    if (releaseRoot === null) {
      fail('Q-08 test-only input verification requires an injected verifier');
    }
    const profileCoreFile = readCanonicalJson(
      input.profileCorePath,
      'Q-08 profile core',
    );
    const release = verifyV2FinalReleaseProfileCore(
      releaseRoot,
      profileCoreFile.bytes,
      profileCoreFile.value,
    );
    const descriptor = await loadV2InstanceDescriptor({
      descriptorPath: input.descriptorPath,
      profileCore: profileCoreFile.value,
      trustedSigners: release.descriptorSigners,
    });
    if (
      descriptor.profileId !== releaseRoot.profileId
      || descriptor.finalLocks.topology.id !== releaseRoot.topology.id
      || descriptor.finalLocks.verifiers.length
        !== releaseRoot.topology.verifierRoles.length
      || descriptor.finalLocks.verifiers.some(
        (entry, index) => entry.role
          !== releaseRoot.topology.verifierRoles[index],
      )
    ) {
      fail('Q-08 descriptor identity or PF10 topology differs from its approved release root');
    }
    const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor);
    assertFinalRuntime(runtime);
    const settlementPins =
      deriveV2SettlementPinsFromValidatedDescriptor(descriptor);
    const laneAuthorityContext =
      deriveV2Q02LaneAuthorityContextFromValidatedDescriptor(descriptor);
    const commandPlanArtifact = descriptor.artifacts.get(
      V2_Q08_COMMAND_PLAN_ARTIFACT_ID,
    );
    const sourcePinArtifact = descriptor.artifacts.get(
      V2_Q08_SOURCE_PIN_ARTIFACT_ID,
    );
    if (
      commandPlanArtifact === undefined
      || sourcePinArtifact === undefined
      || commandPlanArtifact.filename !== input.commandPlanPath
      || descriptor.manifest.filename !== input.finalManifestPath
    ) {
      fail('Q-08 command plan and source pin must be signed-manifest artifacts');
    }
    const sourcePin = readCanonicalJson(
      resolve(sourcePinArtifact.filename),
      'Q-08 signed source pin',
    );
    exactKeys(
      sourcePin.value,
      ['commit', 'schema', 'tree'],
      'Q-08 signed source pin',
    );
    if (
      sourcePin.value.schema !== V2_Q08_SOURCE_PIN_SCHEMA
      || !HEX_40.test(sourcePin.value.commit)
      || !HEX_40.test(sourcePin.value.tree)
      || sourcePin.sha256 !== sourcePinArtifact.sha256
    ) {
      fail('Q-08 signed source pin is invalid');
    }
    const d02ClosureFile = readCanonicalJson(
      input.d02ClosurePath,
      'Q-08 D-02 audit closure',
    );
    const d02Closure = revalidateV2D02AuditClosure(d02ClosureFile.value);
    const d02AuditPolicy =
      deriveV2ManifestArtifactFromValidatedDescriptor(
        descriptor,
        'd02-audit-policy',
      );
    const expectedD02Hashes = {
      commit: sourcePin.value.commit,
      tree: sourcePin.value.tree,
      profileId: descriptor.profileId,
      descriptorSha256: descriptor.descriptor.sha256,
      manifestSha256: descriptor.manifest.sha256,
      runtimeMaterialSha256: runtime.runtimeMaterial.materialSha256,
    };
    if (
      canonical(d02Closure.expectedFinalHashes)
        !== canonical(expectedD02Hashes)
      || d02ClosureFile.value.policySha256 !== d02AuditPolicy.sha256
    ) {
      fail('Q-08 D-02 closure does not bind the exact final release and audit policy');
    }
    return Object.freeze({
      profileId: descriptor.profileId,
      profileSha256: release.profileCoreSha256,
      instanceId: descriptor.instanceId,
      carrierCount: settlementPins.verifierCarriers.length,
      descriptorSha256: descriptor.descriptor.sha256,
      manifestSha256: descriptor.manifest.sha256,
      runtimeMaterialSha256: runtime.runtimeMaterial.materialSha256,
      commandPlanSha256: commandPlanArtifact.sha256,
      d02AuditPolicySha256: d02AuditPolicy.sha256,
      d02ClosureSha256: d02ClosureFile.sha256,
      sourcePinSha256: sourcePinArtifact.sha256,
      sourceCommit: sourcePin.value.commit,
      sourceTree: sourcePin.value.tree,
      networkId: 2,
      releaseBootstrapSha256: release.releaseBootstrapSha256,
      releaseRootId: release.releaseRootId,
      laneAuthorityContext,
    });
  });
  const git = await gitState(runner);
  if (git.commit !== options.expectedCommit || git.tree !== options.expectedTree) fail('Q-08 live Git commit/tree differs from the exact requested clean source');
  const inputFiles = {
    descriptorPath: 'Q-08 descriptor',
    finalManifestPath: 'Q-08 final manifest',
    profileCorePath: 'Q-08 profile core',
    commandPlanPath: 'Q-08 command plan',
    d02ClosurePath: 'Q-08 D-02 closure',
    fundingCheckpointPath: 'Q-08 funding checkpoint',
    hostIdentityPath: 'Q-08 host identity',
    ...(!testOnly
      ? { hostSigningKeyPath: 'Q-08 host signing key' }
      : {}),
  };
  for (const [path, label] of Object.entries(inputFiles)) {
    directRegularFile(options[path], label);
  }
  const identity = await verifyFinalInputs(options);
  exactKeys(identity, [
    'carrierCount', 'commandPlanSha256', 'd02AuditPolicySha256',
    'd02ClosureSha256',
    'descriptorSha256', 'instanceId',
    'manifestSha256', 'networkId', 'profileId', 'releaseBootstrapSha256',
    'profileSha256', 'releaseRootId', 'runtimeMaterialSha256', 'sourceCommit',
    'sourcePinSha256', 'sourceTree',
    ...(!testOnly ? ['laneAuthorityContext'] : []),
  ], 'Q-08 final input verification result');
  if (
    !HEX_32.test(identity.profileId)
    || !HEX_32.test(identity.profileSha256)
    || !HEX_32.test(identity.instanceId)
    || !HEX_32.test(identity.descriptorSha256)
    || !HEX_32.test(identity.manifestSha256)
    || !HEX_32.test(identity.runtimeMaterialSha256)
    || !HEX_32.test(identity.commandPlanSha256)
    || !HEX_32.test(identity.d02AuditPolicySha256)
    || !HEX_32.test(identity.d02ClosureSha256)
    || !HEX_32.test(identity.sourcePinSha256)
    || !HEX_32.test(identity.releaseBootstrapSha256)
    || typeof identity.releaseRootId !== 'string'
    || !/^[a-z][a-z0-9-]*$/.test(identity.releaseRootId)
    || !HEX_40.test(identity.sourceCommit)
    || !HEX_40.test(identity.sourceTree)
    || !Number.isSafeInteger(identity.carrierCount)
    || identity.carrierCount < 1
    || identity.carrierCount > 255
    || identity.networkId !== 2
    || identity.sourceCommit !== options.expectedCommit
    || identity.sourceTree !== options.expectedTree
    || (!testOnly && identity.releaseRootId !== releaseRoot.rootId)
  ) fail('Q-08 final input verifier returned invalid or mismatched signed pins');
  if (sha256(readFileSync(options.finalManifestPath)) !== identity.manifestSha256) fail('Q-08 final manifest hash is not descriptor-pinned');
  if (
    readCanonicalJson(options.d02ClosurePath, 'Q-08 D-02 audit closure').sha256
      !== identity.d02ClosureSha256
  ) {
    fail('Q-08 D-02 closure hash changed after final input validation');
  }
  const plan = parsePlan(options.commandPlanPath); const funding = parseFundingCheckpoint(options.fundingCheckpointPath, { expectedCheckpoint: identity.laneAuthorityContext?.checkpoint, testOnly }); const host = parseHostIdentity(options.hostIdentityPath);
  if (identity.commandPlanSha256 !== plan.sha256) fail('Q-08 command plan hash is not descriptor-pinned');
  privateNewDirectory(options.outputDirectory);
  try {
    const bundledFundingPath = join(
      options.outputDirectory,
      V2_Q08_FUNDING_CHECKPOINT_FILE,
    );
    if (!testOnly) {
      const bundled = writePrivateBytes(bundledFundingPath, funding.bytes);
      if (bundled.sha256 !== funding.sha256) {
        fail('Q-08 bundled funding checkpoint changed during publication');
      }
    }
    const chain = []; let previousSha256 = null;
    let displayedFundingAddress = null;
    let recoveredNoteId = null;
    for (const step of STEPS) {
      if (step === 'fundingAddress') { /* command emits the address before the separately verified OOB checkpoint */ }
      const command = plan.value.commands[step];
      const result = await requireCommand(
        runner,
        command.executable,
        command.arguments,
        {
          cwd: workspaceRoot,
          env: {
            PATH: process.env.PATH,
            HOME: process.env.HOME,
            LANG: 'C',
            LC_ALL: 'C',
            SHIELDKIT_Q08_OUTPUT_DIR: options.outputDirectory,
          },
        },
        step,
      );
      const parsed = parseStepResult(step, result, identity, {
        authorityContext: identity.laneAuthorityContext,
        evidenceRoot: options.outputDirectory,
        testOnly,
      });
      if (step === 'fundingAddress') displayedFundingAddress = parsed.fundingAddress;
      if (step === 'recover') recoveredNoteId = parsed.recoveredNoteId;
      if (step === 'recoveredSpend' && (recoveredNoteId === null || parsed.spentNoteId !== recoveredNoteId)) fail('Q-08 recovered-note spend does not bind the note returned by chain-history recovery');
      const entry = Object.freeze({ sequence: chain.length, step, previousSha256, command: { executable: command.executable, arguments: command.arguments }, result: parsed, stdoutSha256: sha256(Buffer.from(result.stdout)), stderrSha256: sha256(Buffer.from(result.stderr)) });
      if (!testOnly && HOST_STATE_STEPS.includes(step)) {
        verifyV2Q08HostStateEvidence({ evidenceRoot: options.outputDirectory, reference: parsed.stateEvidence, step, status: parsed.status, identity, stdoutSha256: entry.stdoutSha256, stderrSha256: entry.stderrSha256, recoveredNoteId: step === 'recover' ? parsed.recoveredNoteId : null });
      }
      const entrySha256 = sha256(Buffer.from(canonical(entry)));
      chain.push(Object.freeze({ ...entry, entrySha256 })); previousSha256 = entrySha256;
    }
    if (displayedFundingAddress !== funding.value.fundingAddress) fail('Q-08 out-of-band funding checkpoint does not bind the displayed funding address');
    if (!testOnly) {
      const replayedFunding = parseFundingCheckpoint(bundledFundingPath, {
        expectedCheckpoint: identity.laneAuthorityContext.checkpoint,
      });
      if (replayedFunding.sha256 !== funding.sha256) {
        fail('Q-08 bundled funding checkpoint changed during the host journey');
      }
      for (const entry of chain) {
        if (!ACTIONS.includes(entry.step)) continue;
        verifyV2Q08ActionLaneEvidence({
          authorityContext: identity.laneAuthorityContext,
          evidenceRoot: options.outputDirectory,
          expected: {
            action: entry.result.action,
            carrierCount: identity.carrierCount,
            instanceId: identity.instanceId,
            journeyStep: entry.step,
            profileId: identity.profileId,
            profileSha256: identity.profileSha256,
            rawTransactionHex: entry.result.rawTransactionHex,
            spentNoteId:
              entry.step === 'recoveredSpend'
                ? entry.result.spentNoteId
                : null,
            transactionId: entry.result.transactionId,
          },
          laneEvidence: entry.result.laneEvidence,
        });
      }
    }
    if (testOnly) {
      // This API-only mode is deliberately unavailable from the CLI. It permits
      // bounded command doubles to exercise ordering without emitting a Q-08
      // transcript or a passing qualification claim.
      writePrivateJson(join(options.outputDirectory, 'test-only.json'), {
        schema: V2_Q08_ATTEMPT_RECORD_SCHEMA,
        status: 'test-only-nonqualifying',
        q08Qualified: false,
        exercisedSteps: chain.map((entry) => entry.step),
      });
      return Object.freeze({ schema: V2_Q08_ATTEMPT_RECORD_SCHEMA, status: 'test-only-nonqualifying', q08Qualified: false });
    }
    const statement = Object.freeze({
      schema: V2_Q08_HOST_STATEMENT_SCHEMA,
      status: 'host-journey-complete-awaiting-independent-pair-verification',
      profileId: identity.profileId,
      profileSha256: identity.profileSha256,
      instanceId: identity.instanceId,
      carrierCount: identity.carrierCount,
      descriptorSha256: identity.descriptorSha256,
      manifestSha256: identity.manifestSha256,
      runtimeMaterialSha256: identity.runtimeMaterialSha256,
      releaseRootId: identity.releaseRootId,
      releaseBootstrapSha256: identity.releaseBootstrapSha256,
      git,
      hostIdentity: host.hostIdentity,
      commandPlanSha256: plan.sha256,
      d02AuditPolicySha256: identity.d02AuditPolicySha256,
      d02ClosureSha256: identity.d02ClosureSha256,
      sourcePinSha256: identity.sourcePinSha256,
      fundingCheckpointSha256: funding.sha256,
      steps: chain,
    });
    const signed = await signV2Q08HostTranscriptForRelease({
      privateKeyPath: options.hostSigningKeyPath,
      releaseRoot,
      role: options.hostRole,
      statement,
    });
    const outputPath = join(
      options.outputDirectory,
      `q08-${options.hostRole}-signed-host-transcript.json`,
    );
    const written = writePrivateBytes(outputPath, signed.bytes);
    if (written.sha256 !== signed.envelopeSha256) {
      fail('Q-08 signed host transcript write did not preserve exact bytes');
    }
    return Object.freeze({
      schema: V2_Q08_ATTEMPT_RECORD_SCHEMA,
      status: 'host-journey-complete-awaiting-independent-pair-verification',
      hostRole: options.hostRole,
      envelopeSha256: signed.envelopeSha256,
      statementSha256: signed.envelope.statementSha256,
      outputPath,
      q08Qualified: false,
      production: false,
      releaseQualified: false,
    });
  } catch (error) {
    writePrivateJson(join(options.outputDirectory, 'failure.json'), { schema: V2_Q08_ATTEMPT_RECORD_SCHEMA, status: 'failed-preserved', message: error instanceof Error ? error.message : String(error), at: now() });
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await runV2Q08CleanMachineQualification(parseV2Q08Arguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`Q-08 clean-machine qualification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
