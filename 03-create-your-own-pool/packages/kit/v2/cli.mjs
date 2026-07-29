import { createHash, randomBytes as systemRandomBytes } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { decodeCashAddress } from '@bitauth/libauth';

import {
  decodeDirectV2Address,
  encodeDirectV2Address,
} from '../../action/v2/address.mjs';
import {
  verifyDirectV2BindingP2sh32Lock,
} from '../../action/v2/binding-unlock.mjs';
import {
  directV2NetworkNameFromId,
} from '../../action/v2/network.mjs';
import {
  constructDirectV2Output,
  deriveDirectV2Address,
  DirectV2NoteError,
  recoverDirectV2Output,
} from '../../action/v2/notes.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  resolveDirectV2VerifierTopology,
} from '../../action/v2/topology.mjs';
import {
  deriveV2RollingBaseSats,
} from '../../action/v2/dust-policy.mjs';
import {
  decodeStateNftCommitment,
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from '../../profile/v2/profile-core.mjs';
import {
  createV2SecretFile,
  deriveV2RecoveryScannerFromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2Pf10StoreRuntimeMaterialsSha256,
  deriveV2SettlementPinsFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../../profile/v2/instance-descriptor.mjs';
import {
  openExistingV2DirectStore,
  openV2DirectStore,
  V2_OPERATION_STATES,
} from '../../pool/v2/store.mjs';
import {
  BABYJUB_SUBGROUP_ORDER,
} from '../../recover/portable-core.mjs';
import {
  V2_MAX_TRANSACTION_BYTES,
  V2_MAX_UNLOCKING_BYTECODE_BYTES,
} from './transaction-policy.mjs';
import {
  loadV2ChainConfig,
  parseV2ChainConfig,
} from './chain-config.mjs';
import {
  createV2ChipnetChainClient,
  V2_CANONICAL_HISTORY_MAX_ACTIONS,
} from './chain-client.mjs';
import {
  createV2CanonicalHistorySynchronizer,
} from './canonical-history-sync.mjs';
import {
  createV2DirectActionLifecycle,
} from './action-lifecycle.mjs';
import {
  createV2PrivateActionStore,
} from './private-action-store.mjs';
import {
  openV2DeliveryJournal,
} from './delivery-journal.mjs';
import {
  inspectV2FundingUtxos,
} from './funding-utxo-selector.mjs';
import {
  deriveV2ChipnetFundingWallet,
  projectV2FundingWalletPublic,
  validateV2ChipnetFundingWallet,
} from './funding-wallet.mjs';
import {
  createV2HttpsTransport,
} from './https-transport.mjs';
import {
  broadcastAction as mandatoryBroadcastAction,
  V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT,
} from './network-gate.mjs';
import {
  parseV2RawTransaction,
} from './transaction-policy.mjs';

export const V2_CLI_PROTOCOL = 'v2-direct';
export const V1_LEGACY_PROTOCOL = 'v1-legacy';
export const V2_CLI_MATURITY = 'development-only-unqualified';
// Operational V2 Direct uses only the selected PF10 topology. PF11 remains
// available under explicitly oracle-named exports in the topology module.
export const V2_DIRECT_CARRIER_COUNT =
  DIRECT_V2_PF10_FUSED_VERIFIER_ROLES.length;

const POOL_SCHEMA = 'shieldkit-v2-cli-pool-v4';
const WALLET_SCHEMA = 'shieldkit-v2-cli-wallet-v3';
const RECOVERY_SCHEMA = 'shieldkit-v2-cli-recovery-v2';
const SHIELD_ADDRESS_PREFIX = 'shieldkit-v2:';
const HASH_HEX = /^[0-9a-f]{64}$/;
const BYTE_HEX = /^(?:[0-9a-f]{2})+$/;
const DECIMAL = /^[1-9][0-9]*$/;
const ARTIFACT_ID = /^[a-z][a-z0-9-]*$/;

function exactOrderedRoles(left, right) {
  return (
    Array.isArray(left)
    && left.length === right.length
    && left.every((role, index) => role === right[index])
  );
}

/**
 * The generic descriptor layer retains PF11 for semantic-oracle tooling, but
 * the CLI is an operational boundary: it may construct and reload only the
 * separately selected PF10 candidate. Keep this check before settlement pins
 * or runtime material are derived so an injected runtime resolver cannot turn
 * a signed PF11 descriptor into an operational pool.
 */
function requireOperationalPf10Topology({ topologyId, verifierRoles }, label) {
  if (topologyId === DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID) {
    fail(
      'PF11_SEMANTIC_ORACLE_ONLY',
      `${label} uses PF11, which is a semantic correctness oracle only and cannot be operational in the V2 Direct CLI`,
    );
  }
  if (
    topologyId !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    || !exactOrderedRoles(verifierRoles, DIRECT_V2_PF10_FUSED_VERIFIER_ROLES)
  ) {
    fail(
      'V2_OPERATIONAL_TOPOLOGY_REQUIRED',
      `${label} must use the exact PF10-FusedQGenesis topology and ordered verifier roles`,
    );
  }
}
const SIGNER_ID = /^[a-z][a-z0-9-]*$/;
const MAX_INPUT_JSON_BYTES = 256 * 1024 * 1024;
const MAX_LOCAL_JSON_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_RECOVERY_ACTIONS = 0xffff_ffff;
const ACTION_COMMANDS = new Set(['deposit', 'transfer', 'withdraw']);
const OPERATION_COMMANDS = new Set([
  'abandon',
  'confirm',
  'rebase',
  'rebroadcast',
  'reconcile',
  'resume',
]);
const V2_ONLY_COMMANDS = new Set([
  'operation',
  'pool',
  'status',
  'sync',
  'wallet',
]);
const VALUE_OPTIONS = new Set([
  'acknowledgement',
  'attempt-token',
  'binary',
  'binary-sha256',
  'actions',
  'chain-config',
  'data-dir',
  'note',
  'profile-core',
  'protocol',
  'request',
  'reason',
  'timeout-ms',
  'to',
  'trusted-signers',
]);
const BOOLEAN_OPTIONS = new Set(['broadcast']);
const COMMON_OPTIONS = new Set(['data-dir', 'protocol']);
const COMMAND_OPTIONS = Object.freeze({
  'wallet.create': new Set(COMMON_OPTIONS),
  'wallet.receive': new Set(COMMON_OPTIONS),
  'pool.add': new Set([
    ...COMMON_OPTIONS,
    'chain-config',
    'profile-core',
    'trusted-signers',
  ]),
  sync: new Set(COMMON_OPTIONS),
  recover: new Set(COMMON_OPTIONS),
  status: new Set(COMMON_OPTIONS),
  doctor: new Set(COMMON_OPTIONS),
  'operation.abandon': new Set([...COMMON_OPTIONS, 'reason']),
  'operation.confirm': new Set(COMMON_OPTIONS),
  'operation.rebase': new Set(COMMON_OPTIONS),
  'operation.rebroadcast': new Set([
    ...COMMON_OPTIONS,
    'acknowledgement',
    'attempt-token',
    'broadcast',
  ]),
  'operation.reconcile': new Set(COMMON_OPTIONS),
  'operation.resume': new Set([...COMMON_OPTIONS, 'broadcast']),
  deposit: new Set([...COMMON_OPTIONS, 'broadcast', 'to']),
  transfer: new Set([...COMMON_OPTIONS, 'broadcast', 'note', 'to']),
  withdraw: new Set([...COMMON_OPTIONS, 'broadcast', 'note', 'to']),
});

export class V2CliError extends Error {
  constructor(code, message, { details = undefined, exitCode = 2, cause } = {}) {
    super(message, { cause });
    this.name = 'V2CliError';
    this.code = code;
    this.details = details;
    this.exitCode = exitCode;
  }
}

const fail = (code, message, options) => {
  throw new V2CliError(code, message, options);
};

function exactKeys(value, expected, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('LOCAL_STATE_INVALID', `${label} must be a plain JSON object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(
      'LOCAL_STATE_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
}

function hashHex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parseOptionTokens(tokens) {
  const options = Object.create(null);
  const positionals = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }
    if (token === '--' || token.includes('=')) {
      fail(
        'INVALID_OPTION_SYNTAX',
        'options must use --name value syntax; -- and --name=value are unsupported',
      );
    }
    const name = token.slice(2);
    if (!VALUE_OPTIONS.has(name) && !BOOLEAN_OPTIONS.has(name)) {
      fail('UNKNOWN_OPTION', `unknown V2 CLI option: --${name}`);
    }
    if (Object.hasOwn(options, name)) {
      fail('DUPLICATE_OPTION', `option --${name} may be supplied only once`);
    }
    if (BOOLEAN_OPTIONS.has(name)) {
      options[name] = true;
      continue;
    }
    const value = tokens[index + 1];
    if (value === undefined || value.startsWith('--')) {
      fail('OPTION_VALUE_REQUIRED', `option --${name} requires one value`);
    }
    options[name] = value;
    index += 1;
  }
  return { options: Object.freeze({ ...options }), positionals };
}

function expectPositionals(parsed, count, usage) {
  if (parsed.positionals.length !== count) {
    fail('CLI_USAGE', `usage: ${usage}`);
  }
}

function assertAllowedOptions(command, options) {
  const allowed = COMMAND_OPTIONS[command];
  for (const name of Object.keys(options)) {
    if (!allowed.has(name)) {
      fail(
        'OPTION_NOT_ALLOWED',
        `option --${name} is not allowed for ${command}`,
      );
    }
  }
}

/**
 * Strict parser for the bounded V2 Direct command surface. It has no filesystem
 * or network side effects.
 */
export function parseV2CliArguments(argv) {
  if (!Array.isArray(argv) || argv.some((value) => typeof value !== 'string')) {
    fail('CLI_ARGUMENTS_INVALID', 'CLI arguments must be an array of strings');
  }
  if (argv.length === 0 || argv[0].startsWith('--')) {
    fail('CLI_USAGE', 'a V2 command is required');
  }
  const top = argv[0];
  let command;
  let rest;
  if (top === 'wallet') {
    if (!['create', 'receive'].includes(argv[1])) {
      fail('CLI_USAGE', 'usage: shieldkit wallet create|receive');
    }
    command = `wallet.${argv[1]}`;
    rest = argv.slice(2);
  } else if (top === 'pool') {
    if (argv[1] !== 'add') {
      fail('CLI_USAGE', 'usage: shieldkit pool add <descriptor>');
    }
    command = 'pool.add';
    rest = argv.slice(2);
  } else if (top === 'operation') {
    if (!OPERATION_COMMANDS.has(argv[1])) {
      fail(
        'CLI_USAGE',
        'usage: shieldkit operation abandon|confirm|rebase|rebroadcast|reconcile|resume <operation-id>',
      );
    }
    command = `operation.${argv[1]}`;
    rest = argv.slice(2);
  } else if (
    ['sync', 'recover', 'status', 'doctor', ...ACTION_COMMANDS].includes(top)
  ) {
    command = top;
    rest = argv.slice(1);
  } else {
    fail('UNKNOWN_COMMAND', `unknown V2 CLI command: ${top}`, {
      exitCode: 64,
    });
  }
  const parsed = parseOptionTokens(rest);
  assertAllowedOptions(command, parsed.options);
  if (command === 'pool.add') {
    expectPositionals(
      parsed,
      1,
      'shieldkit pool add <descriptor> --protocol v2-direct',
    );
  } else if (command.startsWith('operation.')) {
    expectPositionals(
      parsed,
      1,
      `shieldkit ${command.replace('.', ' ')} <operation-id>`,
    );
    if (!/^v2op:[0-9a-f]{64}$/.test(parsed.positionals[0])) {
      fail(
        'INVALID_OPERATION_ID',
        'operation ID must use v2op: followed by 64 lowercase hexadecimal characters',
      );
    }
  } else {
    expectPositionals(parsed, 0, `shieldkit ${command.replace('.', ' ')}`);
  }
  return Object.freeze({
    command,
    options: parsed.options,
    descriptor: command === 'pool.add' ? parsed.positionals[0] : undefined,
    operationId: command.startsWith('operation.')
      ? parsed.positionals[0]
      : undefined,
  });
}

/**
 * Identify commands which belong to the V2 surface. Mutation verbs are routed
 * here only with an explicit V2 protocol; the script separately guards V1.
 */
export function isV2CliInvocation(argv) {
  if (!Array.isArray(argv) || argv.length === 0) return false;
  const protocolIndex = argv.indexOf('--protocol');
  const protocol = protocolIndex === -1 ? undefined : argv[protocolIndex + 1];
  return (
    V2_ONLY_COMMANDS.has(argv[0])
    || protocol === V2_CLI_PROTOCOL
  );
}

function requireV2Protocol(options) {
  const protocol = options.protocol;
  if (protocol === undefined) {
    fail(
      'V2_DEFAULT_NOT_QUALIFIED',
      'V2 Direct is not the default because final qualification gates are not complete; pass --protocol v2-direct for this development-only local surface',
      {
        details: {
          defaultProtocol: null,
          qualification: 'blocked',
          requiredProtocol: V2_CLI_PROTOCOL,
        },
      },
    );
  }
  if (protocol === V1_LEGACY_PROTOCOL) {
    fail(
      'PROTOCOL_COMMAND_MISMATCH',
      'this command belongs to V2 Direct; V1 mutations are available only through their legacy commands',
    );
  }
  if (protocol !== V2_CLI_PROTOCOL) {
    fail('UNSUPPORTED_PROTOCOL', `unsupported protocol: ${protocol}`);
  }
}

function resolveDataDirectory(options, cwd, env) {
  const selected = options['data-dir']
    ?? env.SHIELDKIT_V2_HOME
    ?? path.join(os.homedir(), '.shieldkit', 'v2-direct');
  if (typeof selected !== 'string' || selected.length === 0) {
    fail('DATA_DIRECTORY_INVALID', 'V2 data directory must be nonempty');
  }
  return path.resolve(cwd, selected);
}

async function exists(filename) {
  try {
    return await lstat(filename);
  } catch (error) {
    if (error?.code === 'ENOENT') return undefined;
    throw error;
  }
}

async function inspectDirectoryAncestry(directory, { allowMissing }) {
  const parsed = path.parse(directory);
  const components = path.relative(parsed.root, directory)
    .split(path.sep)
    .filter((component) => component.length !== 0);
  let current = parsed.root;
  for (const component of components) {
    current = path.join(current, component);
    const metadata = await exists(current);
    if (metadata === undefined) {
      if (allowMissing) return false;
      fail('DATA_DIRECTORY_UNTRUSTED', 'V2 data directory does not exist');
    }
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      fail(
        'DATA_DIRECTORY_UNTRUSTED',
        'V2 data directory ancestry must contain only non-symlink directories',
      );
    }
    if ((metadata.mode & 0o022) !== 0) {
      fail(
        'DATA_DIRECTORY_UNTRUSTED',
        'V2 data directory ancestry must not be group/world writable',
      );
    }
    if (current === directory) {
      if (
        typeof process.getuid === 'function'
        && metadata.uid !== process.getuid()
      ) {
        fail(
          'DATA_DIRECTORY_UNTRUSTED',
          'V2 data directory must be owned by the current user',
        );
      }
      if ((metadata.mode & 0o077) !== 0) {
        fail(
          'DATA_DIRECTORY_PERMISSIONS',
          'V2 data directory must have mode 0700 or stricter',
        );
      }
    }
  }
  return true;
}

async function ensurePrivateDirectory(directory) {
  const alreadyExists = await inspectDirectoryAncestry(
    directory,
    { allowMissing: true },
  );
  await mkdir(directory, { recursive: true, mode: 0o700 });
  if (!alreadyExists) await chmod(directory, 0o700);
  await inspectDirectoryAncestry(directory, { allowMissing: false });
}

async function readCanonicalJson(filename, label, { optional = false } = {}) {
  const metadata = await exists(filename);
  if (metadata === undefined) {
    if (optional) return undefined;
    fail('LOCAL_STATE_MISSING', `${label} is not configured`);
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    fail('LOCAL_STATE_INVALID', `${label} must be a regular non-symlink file`);
  }
  if ((metadata.mode & 0o077) !== 0) {
    fail('LOCAL_STATE_PERMISSIONS', `${label} must not be group/world accessible`);
  }
  if (metadata.size > MAX_LOCAL_JSON_BYTES) {
    fail(
      'LOCAL_STATE_INVALID',
      `${label} exceeds ${MAX_LOCAL_JSON_BYTES} bytes`,
    );
  }
  const bytes = await readFile(filename);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('LOCAL_STATE_INVALID', `${label} is not valid JSON`);
  }
  if (!bytes.equals(Buffer.from(canonicalizeJcs(value), 'utf8'))) {
    fail('LOCAL_STATE_INVALID', `${label} must use exact RFC8785/JCS bytes`);
  }
  return value;
}

async function readInputJson(filename, label, cwd) {
  if (typeof filename !== 'string') {
    fail('INPUT_REQUIRED', `${label} is required`);
  }
  const absolute = path.resolve(cwd, filename);
  const metadata = await exists(absolute);
  if (
    metadata === undefined
    || metadata.isSymbolicLink()
    || !metadata.isFile()
  ) {
    fail('INPUT_UNREADABLE', `${label} must be a regular non-symlink file`);
  }
  if (metadata.size > MAX_INPUT_JSON_BYTES) {
    fail('INPUT_TOO_LARGE', `${label} exceeds ${MAX_INPUT_JSON_BYTES} bytes`);
  }
  let value;
  try {
    value = JSON.parse(await readFile(absolute, 'utf8'));
  } catch {
    fail('INPUT_JSON_INVALID', `${label} must contain one valid JSON value`);
  }
  return { absolute, value };
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, 'r');
    await handle.sync();
  } finally {
    await handle?.close();
  }
}

async function atomicReplaceSecret(filename, value, dependencies) {
  const directory = path.dirname(filename);
  await ensurePrivateDirectory(directory);
  const current = await exists(filename);
  if (current?.isSymbolicLink()) {
    fail('LOCAL_STATE_INVALID', 'refusing to replace a symlinked local state file');
  }
  let nonceBytes;
  try {
    nonceBytes = dependencies.randomBytes(16);
  } catch (error) {
    fail('CSPRNG_FAILURE', 'CSPRNG failed', { cause: error });
  }
  if (!(nonceBytes instanceof Uint8Array) || nonceBytes.length !== 16) {
    fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid temporary-file nonce');
  }
  const nonce = Buffer.from(nonceBytes).toString('hex');
  const temporary = path.join(directory, `.tmp-${path.basename(filename)}-${nonce}`);
  try {
    await dependencies.createSecretFile(
      temporary,
      Buffer.from(canonicalizeJcs(value), 'utf8'),
    );
    await rename(temporary, filename);
    await syncDirectory(directory);
  } finally {
    await unlink(temporary).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }
}

function poolPath(directory) {
  return path.join(directory, 'pool.json');
}

function walletPath(directory) {
  return path.join(directory, 'wallet.json');
}

function recoveryPath(directory) {
  return path.join(directory, 'recovery.json');
}

function storePath(directory) {
  return path.join(directory, 'pool.sqlite');
}

function deliveryJournalPath(directory) {
  return path.join(directory, 'delivery.sqlite');
}

function proofWorkspacePath(directory) {
  return path.join(directory, 'proof-workspace');
}

function privateActionDirectory(directory) {
  return path.join(directory, 'private-actions');
}

function validateStoredArtifact(value, label) {
  exactKeys(
    value,
    ['artifactId', 'bytesHex', 'sha256'],
    label,
  );
  if (
    typeof value.artifactId !== 'string'
    || !ARTIFACT_ID.test(value.artifactId)
    || typeof value.bytesHex !== 'string'
    || !BYTE_HEX.test(value.bytesHex)
    || typeof value.sha256 !== 'string'
    || !HASH_HEX.test(value.sha256)
  ) {
    fail('LOCAL_STATE_INVALID', `${label} is malformed`);
  }
  const bytes = Buffer.from(value.bytesHex, 'hex');
  if (hashHex(bytes) !== value.sha256) {
    fail('LOCAL_STATE_INVALID', `${label} SHA-256 pin mismatch`);
  }
  return bytes;
}

function validateStoredBaseSats(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(
      'LOCAL_STATE_INVALID',
      `${label} must be a nonzero canonical unsigned decimal string`,
    );
  }
  return value;
}

function validateStoredSettlementArtifacts(value, {
  denominationSats,
  initialStateHex,
  instanceId,
}) {
  exactKeys(
    value,
    ['binding', 'state', 'topologyId', 'verifiers'],
    'stored V2 settlement artifacts',
  );
  if (!Array.isArray(value.verifiers)) {
    fail(
      'LOCAL_STATE_INVALID',
      'stored V2 verifier artifacts must be an ordered array',
    );
  }
  requireOperationalPf10Topology({
    topologyId: value.topologyId,
    verifierRoles: value.verifiers.map((entry) => entry?.role),
  }, 'stored V2 settlement artifacts');
  let topology;
  try {
    topology = resolveDirectV2VerifierTopology({
      id: value.topologyId,
      verifierRoles: value.verifiers.map((entry) => entry?.role),
    });
  } catch (error) {
    fail(
      'LOCAL_STATE_INVALID',
      `stored V2 verifier topology is invalid: ${error.message}`,
      { cause: error },
    );
  }
  const seenRoles = new Set();
  const seenArtifactIds = new Set();
  for (const [index, verifier] of value.verifiers.entries()) {
    const label = `stored V2 verifier artifact ${index}`;
    exactKeys(
      verifier,
      ['baseSats', 'locking', 'role'],
      label,
    );
    const expectedRole = topology.verifierRoles[index];
    if (
      verifier.role !== expectedRole
      || seenRoles.has(verifier.role)
    ) {
      fail(
        'LOCAL_STATE_INVALID',
        'stored V2 verifier roles must be exact, ordered, and unique',
      );
    }
    seenRoles.add(verifier.role);
    const baseSats = validateStoredBaseSats(
      verifier.baseSats,
      `${label}.baseSats`,
    );
    const lockingBytecode = validateStoredArtifact(
      verifier.locking,
      `${label}.locking`,
    );
    const expected = deriveV2RollingBaseSats({ lockingBytecode });
    if (BigInt(baseSats) !== expected) {
      fail(
        'LOCAL_STATE_INVALID',
        `${label}.baseSats must equal the exact dust-derived value ${expected}`,
      );
    }
    if (seenArtifactIds.has(verifier.locking.artifactId)) {
      fail(
        'LOCAL_STATE_INVALID',
        'stored V2 verifier locking artifact IDs must be unique',
      );
    }
    seenArtifactIds.add(verifier.locking.artifactId);
  }
  exactKeys(
    value.binding,
    ['baseSats', 'locking', 'redeem'],
    'stored V2 binding artifacts',
  );
  const bindingBaseSats = validateStoredBaseSats(
    value.binding.baseSats,
    'stored V2 binding baseSats',
  );
  const bindingLock = validateStoredArtifact(
    value.binding.locking,
    'stored V2 binding locking artifact',
  );
  const bindingRedeem = validateStoredArtifact(
    value.binding.redeem,
    'stored V2 binding redeem artifact',
  );
  const bindingExpected = deriveV2RollingBaseSats({
    lockingBytecode: bindingLock,
  });
  if (BigInt(bindingBaseSats) !== bindingExpected) {
    fail(
      'LOCAL_STATE_INVALID',
      `stored V2 binding baseSats must equal the exact dust-derived value ${bindingExpected}`,
    );
  }
  try {
    verifyDirectV2BindingP2sh32Lock({
      redeemScript: bindingRedeem,
      sourceLockingBytecode: bindingLock,
    });
  } catch (error) {
    fail(
      'LOCAL_STATE_INVALID',
      'stored V2 binding locking and redeem artifacts do not form the exact P2SH32 pair',
      { cause: error },
    );
  }
  exactKeys(
    value.state,
    ['baseSats', 'helper', 'helperUnlock', 'locking'],
    'stored V2 state artifacts',
  );
  const stateBaseSats = validateStoredBaseSats(
    value.state.baseSats,
    'stored V2 state baseSats',
  );
  const stateLockingBytecode = validateStoredArtifact(
    value.state.locking,
    'stored V2 state locking artifact',
  );
  validateStoredArtifact(
    value.state.helper,
    'stored V2 state helper artifact',
  );
  validateStoredArtifact(
    value.state.helperUnlock,
    'stored V2 state helper-unlock artifact',
  );
  let initialState;
  try {
    initialState = decodeStateNftCommitment(
      Buffer.from(initialStateHex, 'hex'),
      { denominationSats },
    );
  } catch (error) {
    fail(
      'LOCAL_STATE_INVALID',
      `stored V2 initial state cannot encode the finalized state output: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const initialCommitment = encodeStateNftCommitment(initialState, {
    denominationSats,
  });
  if (!initialCommitment.equals(Buffer.from(initialStateHex, 'hex'))) {
    fail(
      'LOCAL_STATE_INVALID',
      'stored V2 initial state is not the canonical finalized state output commitment',
    );
  }
  const stateExpected = deriveV2RollingBaseSats({
    lockingBytecode: stateLockingBytecode,
    token: {
      category: Buffer.from(instanceId, 'hex'),
      amount: 0n,
      nft: {
        capability: 'mutable',
        commitment: initialCommitment,
      },
    },
  });
  if (BigInt(stateBaseSats) !== stateExpected) {
    fail(
      'LOCAL_STATE_INVALID',
      `stored V2 state baseSats must equal the exact dust-derived value ${stateExpected}`,
    );
  }
  return topology;
}

function validatePoolConfig(value) {
  exactKeys(
    value,
    [
      'carrierCount',
      'chainConfig',
      'descriptor',
      'profileCore',
      'protocol',
      'runtimeMaterialsSha256',
      'schema',
    ],
    'V2 pool configuration',
  );
  if (
    value.schema !== POOL_SCHEMA
    || value.protocol !== V2_CLI_PROTOCOL
    || !HASH_HEX.test(value.runtimeMaterialsSha256)
    || !Number.isSafeInteger(value.carrierCount)
    || value.carrierCount < 1
    || value.carrierCount > 0xff
  ) {
    fail('LOCAL_STATE_INVALID', 'V2 pool configuration version differs');
  }
  try {
    validateProfileCore(value.profileCore);
  } catch (error) {
    fail('LOCAL_STATE_INVALID', `stored profile core is invalid: ${error.message}`);
  }
  let chainConfig;
  try {
    chainConfig = parseV2ChainConfig(value.chainConfig);
  } catch (error) {
    fail(
      'LOCAL_STATE_INVALID',
      `stored chain configuration is invalid: ${error.message}`,
      { cause: error },
    );
  }
  if (
    canonicalizeJcs(chainConfig) !== canonicalizeJcs(value.chainConfig)
    || chainConfig.network !== value.profileCore.network.name
  ) {
    fail(
      'LOCAL_STATE_INVALID',
      'stored chain configuration differs from the exact profile network',
    );
  }
  if (value.profileCore.network.id !== 2) {
    fail(
      'V2_MAINNET_UNAVAILABLE',
      'V2 Direct mainnet operation is outside the current plan and is refused',
    );
  }
  exactKeys(
    value.descriptor,
    [
      'attestation',
      'descriptorSha256',
      'descriptorPath',
      'genesis',
      'initialStateHex',
      'instanceId',
      'manifestSha256',
      'profileId',
      'settlementArtifacts',
      'stateNftCategory',
    ],
    'stored instance descriptor binding',
  );
  exactKeys(
    value.descriptor.attestation,
    ['publicKey', 'publicKeySha256', 'signerId'],
    'stored descriptor attestation',
  );
  exactKeys(
    value.descriptor.genesis,
    ['outpointIndex', 'transactionId'],
    'stored genesis binding',
  );
  const derivedProfileId = deriveProfileId(value.profileCore);
  if (
    value.descriptor.profileId !== derivedProfileId
    || value.descriptor.instanceId !== value.descriptor.stateNftCategory
    || !HASH_HEX.test(value.descriptor.instanceId)
    || !HASH_HEX.test(value.descriptor.genesis.transactionId)
    || !HASH_HEX.test(value.descriptor.manifestSha256)
    || !HASH_HEX.test(value.descriptor.descriptorSha256)
    || typeof value.descriptor.initialStateHex !== 'string'
    || !/^[0-9a-f]{256}$/.test(value.descriptor.initialStateHex)
    || !path.isAbsolute(value.descriptor.descriptorPath)
    || typeof value.descriptor.attestation.signerId !== 'string'
    || !SIGNER_ID.test(value.descriptor.attestation.signerId)
    || typeof value.descriptor.attestation.publicKey !== 'string'
    || value.descriptor.attestation.publicKey.length === 0
    || value.descriptor.attestation.publicKey.length > 16 * 1024
    || !HASH_HEX.test(value.descriptor.attestation.publicKeySha256)
    || hashHex(Buffer.from(
      value.descriptor.attestation.publicKey,
      'utf8',
    )) !== value.descriptor.attestation.publicKeySha256
  ) {
    fail('LOCAL_STATE_INVALID', 'stored pool identity binding is invalid');
  }
  const topology = validateStoredSettlementArtifacts(
    value.descriptor.settlementArtifacts,
    {
      denominationSats: value.profileCore.denominationSats,
      initialStateHex: value.descriptor.initialStateHex,
      instanceId: value.descriptor.instanceId,
    },
  );
  if (value.carrierCount !== topology.carrierCount) {
    fail(
      'LOCAL_STATE_INVALID',
      'stored carrier count does not match the signed verifier topology',
    );
  }
  return value;
}

async function loadPool(directory, { optional = false } = {}) {
  const value = await readCanonicalJson(
    poolPath(directory),
    'V2 pool configuration',
    { optional },
  );
  return value === undefined ? undefined : validatePoolConfig(value);
}

function randomScalar(randomBytes) {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    let bytes;
    try {
      bytes = randomBytes(32);
    } catch (error) {
      fail('CSPRNG_FAILURE', 'CSPRNG failed', { cause: error });
    }
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
      fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid byte string');
    }
    const value = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
    if (value > 0n && value < BABYJUB_SUBGROUP_ORDER) {
      return value.toString(16).padStart(64, '0');
    }
  }
  fail('CSPRNG_FAILURE', 'CSPRNG did not produce a canonical account scalar');
}

function validateWalletConfig(value, pool) {
  exactKeys(
    value,
    [
      'addressHex',
      'changeWallets',
      'fundingWallet',
      'incomingViewSecret',
      'protocol',
      'schema',
      'spendSecret',
    ],
    'V2 wallet',
  );
  if (value.schema !== WALLET_SCHEMA || value.protocol !== V2_CLI_PROTOCOL) {
    fail('LOCAL_STATE_INVALID', 'V2 wallet version differs');
  }
  let address;
  let fundingWallet;
  const changeWallets = [];
  try {
    address = decodeDirectV2Address(Buffer.from(value.addressHex, 'hex'));
    const derived = deriveDirectV2Address({
      networkId: pool.profileCore.network.id,
      profileId: pool.descriptor.profileId,
      instanceId: pool.descriptor.instanceId,
      spendSecret: value.spendSecret,
      incomingViewSecret: value.incomingViewSecret,
    });
    if (
      !encodeDirectV2Address(derived).equals(
        encodeDirectV2Address(address),
      )
    ) {
      fail('LOCAL_STATE_INVALID', 'wallet secrets do not match its address');
    }
    fundingWallet = validateV2ChipnetFundingWallet(value.fundingWallet);
    if (fundingWallet.networkId !== pool.profileCore.network.id) {
      fail(
        'LOCAL_STATE_INVALID',
        'funding wallet network differs from the configured pool network',
      );
    }
    if (!Array.isArray(value.changeWallets) || value.changeWallets.length > 100_000) {
      fail(
        'LOCAL_STATE_INVALID',
        'wallet changeWallets must be a bounded array',
      );
    }
    const seenOperations = new Set();
    const seenLocks = new Set([fundingWallet.lockingBytecodeHex]);
    const seenAddresses = new Set([fundingWallet.cashAddress]);
    for (let index = 0; index < value.changeWallets.length; index += 1) {
      const entry = value.changeWallets[index];
      exactKeys(
        entry,
        ['operationId', 'wallet'],
        `wallet changeWallets[${index}]`,
      );
      if (
        typeof entry.operationId !== 'string'
        || !/^v2op:[0-9a-f]{64}$/.test(entry.operationId)
        || seenOperations.has(entry.operationId)
      ) {
        fail(
          'LOCAL_STATE_INVALID',
          'wallet change operation IDs must be unique canonical V2 operation IDs',
        );
      }
      const change = validateV2ChipnetFundingWallet(entry.wallet);
      if (
        change.networkId !== pool.profileCore.network.id
        || seenLocks.has(change.lockingBytecodeHex)
        || seenAddresses.has(change.cashAddress)
      ) {
        fail(
          'LOCAL_STATE_INVALID',
          'wallet change keys must be unique and match the configured pool network',
        );
      }
      seenOperations.add(entry.operationId);
      seenLocks.add(change.lockingBytecodeHex);
      seenAddresses.add(change.cashAddress);
      changeWallets.push(Object.freeze({
        operationId: entry.operationId,
        wallet: change,
      }));
    }
  } catch (error) {
    if (error instanceof V2CliError) throw error;
    fail('LOCAL_STATE_INVALID', `V2 wallet is invalid: ${error.message}`);
  }
  return Object.freeze({
    address,
    fundingWallet,
    changeWallets: Object.freeze(changeWallets),
    spendSecret: value.spendSecret,
    incomingViewSecret: value.incomingViewSecret,
  });
}

function fundingWalletKeyring(wallet) {
  return Object.freeze([
    wallet.fundingWallet,
    ...wallet.changeWallets.map((entry) => entry.wallet),
  ]);
}

function walletNoteAccount(wallet) {
  return Object.freeze({
    address: wallet.address,
    spendSecret: wallet.spendSecret,
    incomingViewSecret: wallet.incomingViewSecret,
  });
}

function randomFundingWallet(randomBytes) {
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    let candidate;
    try {
      candidate = randomBytes(32);
    } catch (error) {
      fail('CSPRNG_FAILURE', 'CSPRNG failed', { cause: error });
    }
    if (!(candidate instanceof Uint8Array) || candidate.length !== 32) {
      fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid byte string');
    }
    try {
      return deriveV2ChipnetFundingWallet({
        privateKeyHex: Buffer.from(candidate).toString('hex'),
      });
    } catch {
      // Rejection sampling is required because zero and out-of-range scalars
      // are not secp256k1 private keys.
    }
  }
  fail('CSPRNG_FAILURE', 'CSPRNG did not produce a canonical funding scalar');
}

function randomOperationId(randomBytes) {
  let bytes;
  try {
    bytes = randomBytes(32);
  } catch (error) {
    fail('CSPRNG_FAILURE', 'CSPRNG failed', { cause: error });
  }
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid operation nonce');
  }
  return `v2op:${Buffer.from(bytes).toString('hex')}`;
}

async function loadWallet(directory, pool, { optional = false } = {}) {
  const value = await readCanonicalJson(
    walletPath(directory),
    'V2 wallet',
    { optional },
  );
  return value === undefined ? undefined : validateWalletConfig(value, pool);
}

function storedWalletConfig(wallet) {
  return Object.freeze({
    schema: WALLET_SCHEMA,
    protocol: V2_CLI_PROTOCOL,
    addressHex: encodeDirectV2Address(wallet.address).toString('hex'),
    spendSecret: wallet.spendSecret,
    incomingViewSecret: wallet.incomingViewSecret,
    fundingWallet: wallet.fundingWallet,
    changeWallets: wallet.changeWallets.map((entry) => Object.freeze({
      operationId: entry.operationId,
      wallet: entry.wallet,
    })),
  });
}

async function persistChangeWallet(
  context,
  pool,
  wallet,
  operationId,
  changeWallet,
) {
  if (wallet.changeWallets.some(
    (entry) => entry.operationId === operationId,
  )) {
    fail(
      'LOCAL_STATE_INVALID',
      'operation ID already owns a persisted change key',
    );
  }
  const validatedChangeWallet =
    validateV2ChipnetFundingWallet(changeWallet);
  if (validatedChangeWallet.networkId !== pool.profileCore.network.id) {
    fail(
      'LOCAL_STATE_INVALID',
      'fresh change key network differs from the configured pool',
    );
  }
  const updated = Object.freeze({
    ...wallet,
    changeWallets: Object.freeze([
      ...wallet.changeWallets,
      Object.freeze({
        operationId,
        wallet: validatedChangeWallet,
      }),
    ]),
  });
  validateWalletConfig(storedWalletConfig(updated), pool);
  await atomicReplaceSecret(
    walletPath(context.dataDirectory),
    storedWalletConfig(updated),
    context.dependencies,
  );
  return Object.freeze({
    wallet: updated,
    changeWallet: validatedChangeWallet,
  });
}

export function formatV2ShieldAddress(address) {
  return `${SHIELD_ADDRESS_PREFIX}${encodeDirectV2Address(address).toString('hex')}`;
}

export function parseV2ShieldAddress(value, pool) {
  if (
    typeof value !== 'string'
    || !value.startsWith(SHIELD_ADDRESS_PREFIX)
    || !/^[0-9a-f]{336}$/.test(value.slice(SHIELD_ADDRESS_PREFIX.length))
  ) {
    fail(
      'SHIELD_ADDRESS_INVALID',
      `shield address must be ${SHIELD_ADDRESS_PREFIX}<336 lowercase hex characters>`,
    );
  }
  let address;
  try {
    address = decodeDirectV2Address(
      Buffer.from(value.slice(SHIELD_ADDRESS_PREFIX.length), 'hex'),
    );
  } catch (error) {
    fail('SHIELD_ADDRESS_INVALID', error.message, { cause: error });
  }
  if (
    address.profileId !== pool.descriptor.profileId
    || address.instanceId !== pool.descriptor.instanceId
    || address.networkId !== pool.profileCore.network.id
  ) {
    fail(
      'SHIELD_ADDRESS_POOL_MISMATCH',
      'shield address is bound to a different network, profile, or instance',
    );
  }
  return address;
}

function validateCashAddress(value, pool) {
  const decoded = decodeCashAddress(value);
  if (typeof decoded === 'string') {
    fail('CASH_ADDRESS_INVALID', `withdrawal address is invalid: ${decoded}`);
  }
  const expectedPrefix = pool.profileCore.network.id === 1
    ? 'bitcoincash'
    : 'bchtest';
  if (
    decoded.prefix !== expectedPrefix
    || decoded.type !== 'p2pkh'
    || decoded.payload.length !== 20
  ) {
    fail(
      'CASH_ADDRESS_INVALID',
      `withdrawal address must be a ${expectedPrefix} P2PKH cashaddr`,
    );
  }
  return value;
}

function validateSnapshotBinding(snapshot, pool) {
  if (
    snapshot === null
    || Array.isArray(snapshot)
    || typeof snapshot !== 'object'
  ) {
    fail(
      'RECOVERY_SNAPSHOT_POOL_MISMATCH',
      'native recovery snapshot does not exactly bind the configured V2 pool',
    );
  }
  exactKeys(
    snapshot,
    [
      'schema',
      'version',
      'networkId',
      'profileId',
      'instanceId',
      'denominationSats',
      'carrierCount',
      'runtimeMaterialsSha256',
      'poseidonProfile',
      'genesis',
      'tip',
      'actionCount',
      'historySha256',
      'stateHex',
      'noteTree',
      'nullifierTree',
      'externalAuthenticationBoundary',
      'contentSha256',
    ],
    'native recovery snapshot',
  );
  exactKeys(
    snapshot.noteTree,
    ['depth', 'count', 'root'],
    'native recovery snapshot.noteTree',
  );
  exactKeys(
    snapshot.nullifierTree,
    ['depth', 'count', 'root'],
    'native recovery snapshot.nullifierTree',
  );
  const actionCount = Number(snapshot.actionCount);
  if (
    snapshot.schema !== 'shieldkit-v2-recovery-snapshot-v2'
    || snapshot.version !== 2
    || snapshot.networkId !== pool.profileCore.network.id
    || snapshot.profileId !== pool.descriptor.profileId
    || snapshot.instanceId !== pool.descriptor.instanceId
    || snapshot.denominationSats !== pool.profileCore.denominationSats
    || snapshot.carrierCount !== pool.carrierCount
    || snapshot.runtimeMaterialsSha256 !== pool.runtimeMaterialsSha256
    || snapshot.genesis?.transactionId
      !== pool.descriptor.genesis.transactionId
    || snapshot.genesis?.outputIndex
      !== pool.descriptor.genesis.outpointIndex
    || snapshot.genesis?.stateHex !== pool.descriptor.initialStateHex
    || snapshot.tip?.stateHex !== snapshot.stateHex
    || !Number.isSafeInteger(actionCount)
    || actionCount < 0
    || actionCount > MAX_RECOVERY_ACTIONS
    || snapshot.noteTree?.depth !== 32
    || snapshot.nullifierTree?.depth !== 32
    || !/^(0|[1-9][0-9]*)$/.test(snapshot.noteTree?.count ?? '')
    || !/^(0|[1-9][0-9]*)$/.test(snapshot.nullifierTree?.count ?? '')
    || !HASH_HEX.test(snapshot.historySha256 ?? '')
    || !HASH_HEX.test(snapshot.contentSha256 ?? '')
  ) {
    fail(
      'RECOVERY_SNAPSHOT_POOL_MISMATCH',
      'native recovery snapshot does not exactly bind the configured V2 pool',
    );
  }
  return snapshot;
}

function validateRecoveryEnvelope(value, pool) {
  exactKeys(
    value,
    [
      'binarySha256',
      'protocol',
      'recoveryMode',
      'requestJcsSha256',
      'schema',
      'snapshot',
    ],
    'V2 recovery state',
  );
  if (
    value.schema !== RECOVERY_SCHEMA
    || value.protocol !== V2_CLI_PROTOCOL
    || !HASH_HEX.test(value.binarySha256)
    || !['raw-genesis', 'authenticated-snapshot'].includes(value.recoveryMode)
    || !HASH_HEX.test(value.requestJcsSha256)
  ) {
    fail('LOCAL_STATE_INVALID', 'V2 recovery state version or pins differ');
  }
  validateSnapshotBinding(value.snapshot, pool);
  return value;
}

async function loadRecovery(directory, pool, { optional = false } = {}) {
  const value = await readCanonicalJson(
    recoveryPath(directory),
    'V2 recovery state',
    { optional },
  );
  return value === undefined ? undefined : validateRecoveryEnvelope(value, pool);
}

function storeOpenOptions(pool, genesis) {
  return Object.freeze({
    path: null,
    profileId: Buffer.from(pool.descriptor.profileId, 'hex'),
    instanceId: Buffer.from(pool.descriptor.instanceId, 'hex'),
    networkId: pool.profileCore.network.id,
    denominationSats: pool.profileCore.denominationSats,
    carrierCount: pool.carrierCount,
    runtimeMaterialsSha256: Buffer.from(
      pool.runtimeMaterialsSha256,
      'hex',
    ),
    state: Buffer.from(pool.descriptor.initialStateHex, 'hex'),
    outpoint: {
      txid: Buffer.from(pool.descriptor.genesis.transactionId, 'hex'),
      vout: pool.descriptor.genesis.outpointIndex,
    },
    actionSequence: 0,
    height: genesis.height,
    blockHash: Buffer.from(genesis.blockHash, 'hex'),
  });
}

function existingStoreOpenOptions(pool, directory) {
  return Object.freeze({
    path: storePath(directory),
    profileId: Buffer.from(pool.descriptor.profileId, 'hex'),
    instanceId: Buffer.from(pool.descriptor.instanceId, 'hex'),
    networkId: pool.profileCore.network.id,
    denominationSats: pool.profileCore.denominationSats,
    carrierCount: pool.carrierCount,
    runtimeMaterialsSha256: Buffer.from(
      pool.runtimeMaterialsSha256,
      'hex',
    ),
    state: Buffer.from(pool.descriptor.initialStateHex, 'hex'),
    outpoint: {
      txid: Buffer.from(pool.descriptor.genesis.transactionId, 'hex'),
      vout: pool.descriptor.genesis.outpointIndex,
    },
    actionSequence: 0,
  });
}

function recoverStreamOwnedNote(pool, wallet, leaf) {
  let note;
  try {
    note = recoverDirectV2Output({
      account: walletNoteAccount(wallet),
      outputNoteLeaf: leaf.outputNoteLeaf.toString('hex'),
      encryptedRecord: leaf.encryptedRecord,
    });
  } catch (error) {
    if (
      error instanceof DirectV2NoteError
      && [
        'INVALID_PLAINTEXT',
        'RECORD_AUTHENTICATION_FAILED',
      ].includes(error.code)
    ) {
      return null;
    }
    throw error;
  }
  const nullifier = Buffer.from(note.nullifier, 'hex');
  const identity = Buffer.concat([
    Buffer.from('ShieldKit/V2Direct/LocalNoteId/v1\0', 'utf8'),
    Buffer.from(pool.descriptor.instanceId, 'hex'),
    leaf.outputNoteLeaf,
    nullifier,
  ]);
  return Object.freeze({
    noteId: `v2n:${hashHex(identity)}`,
    recordId: `v2r:${hashHex(Buffer.concat([
      Buffer.from('ShieldKit/V2Direct/LocalRecordId/v1\0', 'utf8'),
      leaf.transactionId,
      leaf.outputNoteLeaf,
    ]))}`,
    record: note.encryptedRecord,
    nullifier,
  });
}

async function localCanonicalStoreObservation(context, pool) {
  const filename = storePath(context.dataDirectory);
  let metadata;
  try {
    metadata = await lstat(filename);
  } catch (error) {
    if (error?.code === 'ENOENT') return undefined;
    fail(
      'LOCAL_STATE_INVALID',
      `cannot inspect the durable V2 store: ${error.message}`,
      { cause: error },
    );
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail(
      'LOCAL_STATE_INVALID',
      'durable V2 store path must be one regular non-symlink file',
    );
  }
  let store;
  try {
    store = context.dependencies.openExistingStore(
      existingStoreOpenOptions(pool, context.dataDirectory),
    );
    const canonical = store.canonicalState();
    const notes = store.ownedNoteStatistics();
    const checkpoint = store.recoveryCheckpoint();
    return Object.freeze({
      canonical,
      checkpoint,
      notes,
    });
  } catch (error) {
    fail(
      'LOCAL_STATE_INVALID',
      `cannot read the descriptor-bound durable V2 store: ${error.message}`,
      { cause: error },
    );
  } finally {
    store?.close();
  }
}

async function observedWalletBalance(
  context,
  pool,
  recovery,
  localObservation = undefined,
) {
  if (recovery === undefined) {
    const local = localObservation
      ?? await localCanonicalStoreObservation(context, pool);
    if (local !== undefined) {
      return Object.freeze({
        observedBalanceSats: (
          BigInt(pool.profileCore.denominationSats)
          * BigInt(local.notes.unspent)
        ).toString(),
        observedNoteCount: local.notes.unspent,
        observationStatus: 'local-authenticated-canonical-store',
      });
    }
    return Object.freeze({
      observedBalanceSats: null,
      observedNoteCount: null,
      observationStatus: 'not-synced',
    });
  }
  let store;
  try {
    store = context.dependencies.openStore({
      ...storeOpenOptions(pool, recovery.snapshot.genesis),
      path: storePath(context.dataDirectory),
    });
    const checkpoint = store.recoveryCheckpoint();
    const canonical = store.canonicalState();
    if (
      checkpoint === null
      || checkpoint.contentSha256.toString('hex')
        !== recovery.snapshot.contentSha256
      || canonical.state.toString('hex') !== recovery.snapshot.stateHex
      || canonical.outpoint.txid.toString('hex')
        !== recovery.snapshot.tip.transactionId
      || canonical.outpoint.vout !== recovery.snapshot.tip.outputIndex
      || canonical.actionSequence !== Number(recovery.snapshot.actionCount)
      || canonical.height !== recovery.snapshot.tip.height
      || canonical.blockHash.toString('hex')
        !== recovery.snapshot.tip.blockHash
    ) {
      fail(
        'LOCAL_STATE_INVALID',
        'recovery envelope differs from its atomically installed SQLite checkpoint',
      );
    }
    const notes = store.ownedNoteStatistics();
    return Object.freeze({
      observedBalanceSats: (
        BigInt(pool.profileCore.denominationSats) * BigInt(notes.unspent)
      ).toString(),
      observedNoteCount: notes.unspent,
      observationStatus: 'local-native-recovery-snapshot',
    });
  } catch (error) {
    if (error instanceof V2CliError) throw error;
    fail(
      'LOCAL_STATE_INVALID',
      `cannot read the authenticated recovery store: ${error.message}`,
      { cause: error },
    );
  } finally {
    store?.close();
  }
}

function poolSummary(pool) {
  return Object.freeze({
    network: directV2NetworkNameFromId(pool.profileCore.network.id),
    networkId: pool.profileCore.network.id,
    profileId: pool.descriptor.profileId,
    instanceId: pool.descriptor.instanceId,
    denominationSats: pool.profileCore.denominationSats,
    carrierCount: pool.carrierCount,
    runtimeMaterialsSha256: pool.runtimeMaterialsSha256,
    genesis: pool.descriptor.genesis,
  });
}

function storedDescriptorArtifact(loaded, artifactId, bytes) {
  const artifact = loaded.artifacts.get(artifactId);
  if (artifact === undefined) {
    fail(
      'INSTANCE_DESCRIPTOR_INVALID',
      `validated descriptor omitted artifact ${artifactId}`,
    );
  }
  const materialized = Buffer.from(bytes ?? artifact.data);
  if (
    artifact.sha256 !== hashHex(materialized)
    || artifact.sha256 !== hashHex(artifact.data)
  ) {
    fail(
      'INSTANCE_DESCRIPTOR_INVALID',
      `validated descriptor artifact ${artifactId} changed before persistence`,
    );
  }
  return Object.freeze({
    artifactId,
    sha256: artifact.sha256,
    bytesHex: materialized.toString('hex'),
  });
}

function storedSettlementArtifacts(loaded, pins) {
  return Object.freeze({
    topologyId: loaded.finalLocks.topology.id,
    verifiers: Object.freeze(loaded.finalLocks.verifiers.map(
      (entry, index) => Object.freeze({
        role: entry.role,
        baseSats: entry.baseSats,
        locking: storedDescriptorArtifact(
          loaded,
          entry.lockingArtifactId,
          pins.verifierCarriers[index].lockingBytecode,
        ),
      }),
    )),
    binding: Object.freeze({
      baseSats: loaded.finalLocks.binding.baseSats,
      locking: storedDescriptorArtifact(
        loaded,
        loaded.finalLocks.binding.lockingArtifactId,
        pins.bindingLockingBytecode,
      ),
      redeem: storedDescriptorArtifact(
        loaded,
        loaded.finalLocks.binding.redeemArtifactId,
        pins.bindingRedeemBytecode,
      ),
    }),
    state: Object.freeze({
      baseSats: loaded.finalLocks.state.baseSats,
      locking: storedDescriptorArtifact(
        loaded,
        loaded.finalLocks.state.lockingArtifactId,
        pins.stateLockingBytecode,
      ),
      helper: storedDescriptorArtifact(
        loaded,
        loaded.finalLocks.state.helperArtifactId,
      ),
      helperUnlock: storedDescriptorArtifact(
        loaded,
        loaded.finalLocks.state.helperUnlockArtifactId,
      ),
    }),
  });
}

async function reloadValidatedPoolRuntime(pool, dependencies) {
  let loaded;
  let settlementPins;
  let runtimeMaterialsSha256;
  try {
    loaded = await dependencies.loadDescriptor({
      descriptorPath: pool.descriptor.descriptorPath,
      profileCore: pool.profileCore,
      trustedSigners: [{
        signerId: pool.descriptor.attestation.signerId,
        publicKey: pool.descriptor.attestation.publicKey,
      }],
    });
    requireOperationalPf10Topology({
      topologyId: loaded.finalLocks.topology.id,
      verifierRoles: loaded.finalLocks.topology.verifierRoles,
    }, 'fresh signed instance descriptor');
    settlementPins =
      deriveV2SettlementPinsFromValidatedDescriptor(loaded);
    const runtimeDigest =
      await dependencies.resolveRuntimeMaterialsSha256(loaded);
    if (
      !(runtimeDigest instanceof Uint8Array)
      || runtimeDigest.length !== 32
    ) {
      throw new Error(
        'validated PF10 runtime resolver returned an invalid digest',
      );
    }
    runtimeMaterialsSha256 = Buffer.from(runtimeDigest).toString('hex');
  } catch (error) {
    if (
      error instanceof V2CliError
      && error.code === 'PF11_SEMANTIC_ORACLE_ONLY'
    ) {
      throw error;
    }
    fail(
      'INSTANCE_DESCRIPTOR_INVALID',
      `configured instance cannot be freshly revalidated: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const actualAttestation = {
    signerId: loaded.attestation.signerId,
    publicKey: loaded.attestation.publicKey,
    publicKeySha256: hashHex(
      Buffer.from(loaded.attestation.publicKey, 'utf8'),
    ),
  };
  const actualSettlementArtifacts = storedSettlementArtifacts(
    loaded,
    settlementPins,
  );
  if (
    loaded.profileId !== pool.descriptor.profileId
    || loaded.instanceId !== pool.descriptor.instanceId
    || loaded.stateNftCategory !== pool.descriptor.stateNftCategory
    || canonicalizeJcs(loaded.genesis)
      !== canonicalizeJcs(pool.descriptor.genesis)
    || loaded.initialState.toString('hex')
      !== pool.descriptor.initialStateHex
    || loaded.manifest.sha256 !== pool.descriptor.manifestSha256
    || loaded.descriptor.sha256 !== pool.descriptor.descriptorSha256
    || canonicalizeJcs(actualAttestation)
      !== canonicalizeJcs(pool.descriptor.attestation)
    || canonicalizeJcs(actualSettlementArtifacts)
      !== canonicalizeJcs(pool.descriptor.settlementArtifacts)
    || loaded.finalLocks.topology.carrierCount !== pool.carrierCount
    || runtimeMaterialsSha256 !== pool.runtimeMaterialsSha256
  ) {
    fail(
      'INSTANCE_DESCRIPTOR_DRIFT',
      'fresh signed descriptor, artifacts, signer, topology, or runtime digest differs from the persisted pool binding',
    );
  }
  return Object.freeze({
    descriptor: loaded,
    settlementPins,
    runtimeMaterialsSha256,
  });
}

async function commandPoolAdd(parsed, context) {
  const descriptorPath = path.resolve(context.cwd, parsed.descriptor);
  const chainConfigPath = path.resolve(
    context.cwd,
    parsed.options['chain-config']
      ?? path.join(path.dirname(descriptorPath), 'chain.json'),
  );
  const profileCorePath = path.resolve(
    context.cwd,
    parsed.options['profile-core']
      ?? path.join(path.dirname(descriptorPath), 'profile-core.json'),
  );
  const profileInput = await readInputJson(
    profileCorePath,
    '--profile-core',
    context.cwd,
  );
  if (
    !Buffer.from(canonicalizeJcs(profileInput.value), 'utf8').equals(
      await readFile(profileInput.absolute),
    )
  ) {
    fail(
      'PROFILE_CORE_INVALID',
      'profile core must use exact RFC8785/JCS canonical bytes',
    );
  }
  if (parsed.options['trusted-signers'] === undefined) {
    fail(
      'TRUSTED_SIGNERS_REQUIRED',
      'pool add requires --trusted-signers with at least one pinned Ed25519 public key',
    );
  }
  const trustedSignerInput = await readInputJson(
    parsed.options['trusted-signers'],
    '--trusted-signers',
    context.cwd,
  );
  if (!Array.isArray(trustedSignerInput.value)) {
    fail('TRUSTED_SIGNERS_INVALID', 'trusted signers must be a JSON array');
  }
  const trustedSigners = trustedSignerInput.value;
  let chainConfig;
  try {
    chainConfig = await context.dependencies.loadChainConfig(chainConfigPath);
  } catch (error) {
    fail(
      'CHAIN_CONFIG_INVALID',
      `pool add requires an exact pinned-TLS Chipnet chain configuration: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  let loaded;
  let settlementPins;
  let runtimeMaterialsSha256;
  try {
    loaded = await context.dependencies.loadDescriptor({
      descriptorPath,
      profileCore: profileInput.value,
      trustedSigners,
    });
    requireOperationalPf10Topology({
      topologyId: loaded.finalLocks.topology.id,
      verifierRoles: loaded.finalLocks.topology.verifierRoles,
    }, 'signed instance descriptor');
    settlementPins =
      deriveV2SettlementPinsFromValidatedDescriptor(loaded);
    const runtimeDigest =
      await context.dependencies.resolveRuntimeMaterialsSha256(loaded);
    if (
      !(runtimeDigest instanceof Uint8Array)
      || runtimeDigest.length !== 32
    ) {
      throw new Error(
        'validated PF10 runtime resolver returned an invalid digest',
      );
    }
    runtimeMaterialsSha256 = Buffer.from(runtimeDigest).toString('hex');
  } catch (error) {
    if (
      error instanceof V2CliError
      && error.code === 'PF11_SEMANTIC_ORACLE_ONLY'
    ) {
      throw error;
    }
    fail('INSTANCE_DESCRIPTOR_INVALID', error.message, { cause: error });
  }
  if (profileInput.value.network.id === 1) {
    fail(
      'V2_MAINNET_UNAVAILABLE',
      'V2 Direct mainnet operation is outside the current plan and is refused',
    );
  }
  const directory = context.dataDirectory;
  await ensurePrivateDirectory(directory);
  if (await exists(poolPath(directory))) {
    fail(
      'POOL_ALREADY_CONFIGURED',
      'a V2 pool is already configured; implicit profile/instance migration is forbidden',
    );
  }
  const config = {
    schema: POOL_SCHEMA,
    protocol: V2_CLI_PROTOCOL,
    carrierCount: loaded.finalLocks.topology.carrierCount,
    chainConfig,
    runtimeMaterialsSha256,
    profileCore: profileInput.value,
    descriptor: {
      descriptorPath,
      profileId: loaded.profileId,
      instanceId: loaded.instanceId,
      stateNftCategory: loaded.stateNftCategory,
      genesis: loaded.genesis,
      initialStateHex: loaded.initialState.toString('hex'),
      manifestSha256: loaded.manifest.sha256,
      descriptorSha256: loaded.descriptor.sha256,
      attestation: {
        signerId: loaded.attestation.signerId,
        publicKey: loaded.attestation.publicKey,
        publicKeySha256: hashHex(
          Buffer.from(loaded.attestation.publicKey, 'utf8'),
        ),
      },
      settlementArtifacts: storedSettlementArtifacts(
        loaded,
        settlementPins,
      ),
    },
  };
  validatePoolConfig(config);
  await context.dependencies.createSecretFile(
    poolPath(directory),
    Buffer.from(canonicalizeJcs(config), 'utf8'),
  );
  return Object.freeze({
    command: 'pool.add',
    pool: poolSummary(config),
    descriptorPinsValidated: true,
    descriptorSignatureValidated: true,
    qualification: 'blocked',
    networkActivity: false,
  });
}

async function commandWalletCreate(context) {
  const pool = await loadPool(context.dataDirectory);
  await ensurePrivateDirectory(context.dataDirectory);
  if (await exists(walletPath(context.dataDirectory))) {
    fail('WALLET_ALREADY_EXISTS', 'V2 wallet already exists; overwrite is refused');
  }
  const spendSecret = randomScalar(context.dependencies.randomBytes);
  const incomingViewSecret = randomScalar(context.dependencies.randomBytes);
  const fundingWallet = randomFundingWallet(context.dependencies.randomBytes);
  let address;
  try {
    address = deriveDirectV2Address({
      networkId: pool.profileCore.network.id,
      profileId: pool.descriptor.profileId,
      instanceId: pool.descriptor.instanceId,
      spendSecret,
      incomingViewSecret,
    });
  } catch (error) {
    fail('WALLET_CREATION_FAILED', error.message, { cause: error });
  }
  const encoded = encodeDirectV2Address(address).toString('hex');
  await context.dependencies.createSecretFile(
    walletPath(context.dataDirectory),
    Buffer.from(canonicalizeJcs({
      schema: WALLET_SCHEMA,
      protocol: V2_CLI_PROTOCOL,
      addressHex: encoded,
      spendSecret,
      incomingViewSecret,
      fundingWallet,
      changeWallets: [],
    }), 'utf8'),
  );
  const funding = projectV2FundingWalletPublic(fundingWallet);
  return Object.freeze({
    command: 'wallet.create',
    shieldAddress: formatV2ShieldAddress(address),
    fundingAddress: funding.cashAddress,
    secretFileCreated: true,
    secretFileMode: '0600',
    networkActivity: false,
  });
}

async function commandWalletReceive(context) {
  const pool = await loadPool(context.dataDirectory);
  const wallet = await loadWallet(context.dataDirectory, pool);
  const recovery = await loadRecovery(
    context.dataDirectory,
    pool,
    { optional: true },
  );
  const observed = await observedWalletBalance(context, pool, recovery);
  let funding;
  try {
    const chain = context.dependencies.createChainClient({
      chainConfig: pool.chainConfig,
    });
    const publicFundingWallets = fundingWalletKeyring(wallet).map(
      projectV2FundingWalletPublic,
    );
    const observations = [];
    for (const publicFunding of publicFundingWallets) {
      observations.push(await chain.queryWalletUtxos({
        cashAddress: publicFunding.cashAddress,
        instanceId: pool.descriptor.instanceId,
        lockingBytecodeHex: publicFunding.lockingBytecodeHex,
      }));
    }
    const canonicalTip = canonicalizeJcs(observations[0].canonicalTip);
    if (observations.some(
      (observation) =>
        canonicalizeJcs(observation.canonicalTip) !== canonicalTip,
    )) {
      fail(
        'FUNDING_BALANCE_QUERY_RACE',
        'funding addresses were not observed at one identical canonical pool tip',
      );
    }
    const utxos = observations.flatMap((observation) => observation.utxos);
    const seenOutpoints = new Set();
    for (const utxo of utxos) {
      const key = `${utxo.txid}:${utxo.vout}`;
      if (seenOutpoints.has(key)) {
        fail(
          'FUNDING_BALANCE_QUERY_INVALID',
          'one funding outpoint appeared under more than one wallet key',
        );
      }
      seenOutpoints.add(key);
    }
    const observedFundingSats = utxos.reduce(
      (total, utxo) => total + BigInt(utxo.valueSats),
      0n,
    );
    const receiveFunding = projectV2FundingWalletPublic(
      wallet.fundingWallet,
    );
    funding = Object.freeze({
      address: receiveFunding.cashAddress,
      observedBalanceSats: observedFundingSats.toString(),
      observedUtxoCount: utxos.length,
      watchedAddressCount: publicFundingWallets.length,
      observationStatus: 'authenticated-chipnet-query',
    });
  } catch (error) {
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'FUNDING_BALANCE_QUERY_FAILED',
      `cannot query the self-funded Chipnet wallet: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const guaranteedDepositFunding =
    BigInt(pool.profileCore.denominationSats)
    + BigInt(V2_MAX_TRANSACTION_BYTES)
    + 546n;
  return Object.freeze({
    command: 'wallet.receive',
    shieldAddress: formatV2ShieldAddress(wallet.address),
    funding,
    requiredUtxo: Object.freeze({
      denominationPrincipalSats: pool.profileCore.denominationSats,
      guaranteedSufficientValueSats: guaranteedDepositFunding.toString(),
      feeRateSatsPerByte: '1',
      changeDustFloorSats: '546',
      basis: '100000-byte hard-policy ceiling',
    }),
    ...observed,
    networkActivity: true,
  });
}

async function statusReport(context) {
  const pool = await loadPool(
    context.dataDirectory,
    { optional: true },
  );
  if (pool === undefined) {
    return Object.freeze({
      configured: false,
      pool: null,
      wallet: null,
      recovery: null,
      actionConstruction: 'unconfigured',
      networkActivity: false,
    });
  }
  const wallet = await loadWallet(
    context.dataDirectory,
    pool,
    { optional: true },
  );
  const recovery = await loadRecovery(
    context.dataDirectory,
    pool,
    { optional: true },
  );
  const localObservation = recovery === undefined
    ? await localCanonicalStoreObservation(context, pool)
    : undefined;
  return Object.freeze({
    configured: true,
    pool: poolSummary(pool),
    wallet: wallet === undefined
      ? Object.freeze({ configured: false })
      : Object.freeze({
        configured: true,
        shieldAddress: formatV2ShieldAddress(wallet.address),
        ...(await observedWalletBalance(
          context,
          pool,
          recovery,
          localObservation,
        )),
      }),
    recovery: recovery === undefined
      ? localObservation === undefined
        ? Object.freeze({ available: false })
        : Object.freeze({
          available: true,
          source: 'authenticated-canonical-store',
          contentSha256:
            localObservation.checkpoint?.contentSha256?.toString('hex')
            ?? null,
          actionCount: String(
            localObservation.canonical.actionSequence,
          ),
          tip: Object.freeze({
            transactionId:
              localObservation.canonical.outpoint.txid.toString('hex'),
            outputIndex: localObservation.canonical.outpoint.vout,
            height: localObservation.canonical.height,
            blockHash:
              localObservation.canonical.blockHash.toString('hex'),
            stateHex:
              localObservation.canonical.state.toString('hex'),
          }),
          externalAuthenticationBoundary:
            'descriptor-genesis active-best-chain reconstruction',
        })
      : Object.freeze({
        available: true,
        contentSha256: recovery.snapshot.contentSha256,
        actionCount: recovery.snapshot.actionCount,
        tip: recovery.snapshot.tip,
        externalAuthenticationBoundary:
          recovery.snapshot.externalAuthenticationBoundary,
      }),
    actionConstruction: 'available-development-only-unqualified',
    networkActivity: false,
  });
}

async function commandStatus(context) {
  return Object.freeze({
    command: 'status',
    ...(await statusReport(context)),
  });
}

async function commandDoctor(context) {
  const status = await statusReport(context);
  const blockers = [
    'final PoolActionV2Direct ceremony artifacts are not qualified',
    'BCHN, LeanBCH, and mined real-transaction evidence remains incomplete',
    'Q-06 durability and Q-07 hard-policy qualification evidence incomplete',
    'D-01 ceremony, D-02 audits, Q-08 clean-machine, and Q-09 rollout incomplete',
  ];
  if (!status.configured) blockers.unshift('no validated local V2 pool descriptor');
  if (status.configured && status.wallet?.configured !== true) {
    blockers.unshift('no local V2 wallet');
  }
  return Object.freeze({
    command: 'doctor',
    ready: false,
    maturity: V2_CLI_MATURITY,
    status,
    hardPolicyCeilings: Object.freeze({
      transactionBytes: V2_MAX_TRANSACTION_BYTES,
      eachUnlockingBytecodeBytes: V2_MAX_UNLOCKING_BYTECODE_BYTES,
      eachStandardVmResourcePercent: 100,
    }),
    mandatoryNetworkGate: Object.freeze({
      exported: typeof mandatoryBroadcastAction === 'function',
      invoked: false,
    }),
    qualification: Object.freeze({
      defaultActivation: false,
      state: 'blocked',
      blockers,
    }),
    networkActivity: false,
  });
}

function canonicalTipForSynchronizer(tip) {
  return Object.freeze({
    state: tip.state.toString('hex'),
    txid: tip.outpoint.txid.toString('hex'),
    vout: tip.outpoint.vout,
    actionSequence: tip.actionSequence,
    height: tip.height,
    blockHash: tip.blockHash.toString('hex'),
  });
}

function observationMatchesCanonical(observation, canonical) {
  return (
    observation.state === canonical.state.toString('hex')
    && observation.txid === canonical.outpoint.txid.toString('hex')
    && observation.vout === canonical.outpoint.vout
    && observation.actionSequence === canonical.actionSequence
    && observation.height === canonical.height
    && observation.blockHash === canonical.blockHash.toString('hex')
  );
}

async function openProductionV2Context(context) {
  const pool = await loadPool(context.dataDirectory);
  const wallet = await loadWallet(context.dataDirectory, pool);
  const runtime = await reloadValidatedPoolRuntime(
    pool,
    context.dependencies,
  );
  let recoveryScanner;
  try {
    recoveryScanner = await context.dependencies.deriveRecoveryScanner(
      runtime.descriptor,
    );
  } catch (error) {
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'RECOVERY_SCANNER_INVALID',
      `configured instance recovery scanner cannot be authenticated: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const chainClient = context.dependencies.createChainClient({
    chainConfig: pool.chainConfig,
  });
  let firstPage;
  try {
    firstPage = await chainClient.fetchCanonicalHistoryPage({
      instanceId: pool.descriptor.instanceId,
      genesisTransactionId: pool.descriptor.genesis.transactionId,
      cursor: null,
      maxActions: V2_CANONICAL_HISTORY_MAX_ACTIONS,
    });
  } catch (error) {
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'CANONICAL_HISTORY_UNAVAILABLE',
      `cannot authenticate the configured pool genesis: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (
    firstPage.genesis.transactionId
      !== pool.descriptor.genesis.transactionId
    || firstPage.genesis.outputIndex
      !== pool.descriptor.genesis.outpointIndex
    || firstPage.genesis.initialStateHex
      !== pool.descriptor.initialStateHex
  ) {
    fail(
      'CANONICAL_HISTORY_GENESIS_MISMATCH',
      'canonical history genesis differs from the signed instance descriptor',
    );
  }
  await ensurePrivateDirectory(context.dataDirectory);
  await ensurePrivateDirectory(proofWorkspacePath(context.dataDirectory));
  await ensurePrivateDirectory(privateActionDirectory(context.dataDirectory));
  let store;
  try {
    const privateActionStore =
      await context.dependencies.createPrivateActionStore({
        directory: privateActionDirectory(context.dataDirectory),
      });
    store = context.dependencies.openStore({
      ...storeOpenOptions(pool, firstPage.genesis),
      path: storePath(context.dataDirectory),
    });
    const publicFundingWallets = fundingWalletKeyring(wallet).map(
      (entry) => {
        const projected = projectV2FundingWalletPublic(entry);
        return Object.freeze({
          cashAddress: projected.cashAddress,
          lockingBytecodeHex: projected.lockingBytecodeHex,
        });
      },
    );
    const synchronizeCanonicalTip =
      context.dependencies.createCanonicalSynchronizer({
        binding: {
          profileId: pool.descriptor.profileId,
          instanceId: pool.descriptor.instanceId,
          networkId: pool.profileCore.network.id,
          denominationSats: pool.profileCore.denominationSats,
          carrierCount: pool.carrierCount,
          runtimeMaterialsSha256: pool.runtimeMaterialsSha256,
        },
        chainClient,
        fundingWallets: publicFundingWallets,
        genesis: {
          transactionId: pool.descriptor.genesis.transactionId,
          outputIndex: pool.descriptor.genesis.outpointIndex,
          initialStateHex: pool.descriptor.initialStateHex,
        },
        recoverOwnedNote: (leaf) =>
          recoverStreamOwnedNote(pool, wallet, leaf),
        recoveryScanner,
        store,
      });
    return Object.freeze({
      chainClient,
      pool,
      privateActionStore,
      recoveryScanner,
      runtime,
      store,
      synchronizeCanonicalTip,
      wallet,
    });
  } catch (error) {
    store?.close();
    if (error instanceof V2CliError) throw error;
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'ACTION_CONTEXT_INVALID',
      `cannot open the authenticated V2 action context: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
}

async function synchronizeWithoutPending(actionContext, phase) {
  const prior = actionContext.store.canonicalState();
  return actionContext.synchronizeCanonicalTip({
    operationId: null,
    phase,
    priorCanonicalTip: canonicalTipForSynchronizer(prior),
  });
}

function activeOperations(store) {
  return store.listOperations({
    states: V2_OPERATION_STATES.filter(
      (state) => !['settled', 'abandoned'].includes(state),
    ),
  });
}

async function authenticatedFundingCandidates(actionContext) {
  const canonical = actionContext.store.canonicalState();
  const keyring = fundingWalletKeyring(actionContext.wallet);
  const candidates = [];
  const inventory = [];
  const seen = new Set();
  for (const fundingWallet of keyring) {
    const projected = projectV2FundingWalletPublic(fundingWallet);
    const observation =
      await actionContext.chainClient.queryWalletUtxos({
        cashAddress: projected.cashAddress,
        instanceId: actionContext.pool.descriptor.instanceId,
        lockingBytecodeHex: projected.lockingBytecodeHex,
      });
    if (!observationMatchesCanonical(
      observation.canonicalTip,
      canonical,
    )) {
      fail(
        'CANONICAL_FUNDING_INVENTORY_RACE',
        'funding inventory was not observed at the exact durable canonical pool tip',
        { exitCode: 3 },
      );
    }
    const inspected = inspectV2FundingUtxos({
      fundingLockingBytecodeHex: projected.lockingBytecodeHex,
      utxos: observation.utxos,
    });
    for (const utxo of inspected) {
      const key = `${utxo.txid}:${utxo.vout}`;
      if (seen.has(key)) {
        fail(
          'FUNDING_UTXO_OBSERVATION_INVALID',
          'one funding outpoint appeared under multiple wallet keys',
        );
      }
      seen.add(key);
      inventory.push({
        txid: Buffer.from(utxo.txid, 'hex'),
        vout: utxo.vout,
        valueSats: utxo.valueSats,
      });
      candidates.push(Object.freeze({
        fundingWallet,
        utxo,
      }));
    }
  }
  actionContext.store.reconcileAuthenticatedFundingInventory({
    canonical,
    fundingInventory: inventory,
  });
  candidates.sort((left, right) => {
    const leftValue = BigInt(left.utxo.valueSats);
    const rightValue = BigInt(right.utxo.valueSats);
    if (leftValue < rightValue) return -1;
    if (leftValue > rightValue) return 1;
    if (left.utxo.txid < right.utxo.txid) return -1;
    if (left.utxo.txid > right.utxo.txid) return 1;
    return left.utxo.vout - right.utxo.vout;
  });
  return Object.freeze(candidates);
}

function withdrawalLockingBytecode(cashAddress, pool) {
  validateCashAddress(cashAddress, pool);
  const decoded = decodeCashAddress(cashAddress);
  if (typeof decoded === 'string') {
    fail('CASH_ADDRESS_INVALID', `withdrawal address is invalid: ${decoded}`);
  }
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(decoded.payload),
    Buffer.from([0x88, 0xac]),
  ]);
}

function spendMaterial(
  store,
  wallet,
  noteId,
  { operationId = null } = {},
) {
  const owned = store.ownedNote(noteId);
  if (owned === null) {
    fail('OWNED_NOTE_NOT_FOUND', `owned note ${noteId} does not exist`);
  }
  if (
    owned.spent
    || (
      owned.reservationOperationId !== null
      && owned.reservationOperationId !== operationId
    )
  ) {
    fail('OWNED_NOTE_UNAVAILABLE', `owned note ${noteId} is spent or reserved`);
  }
  const leaf = store.noteLeaf({ noteIndex: owned.noteIndex });
  const record = store.encryptedRecord(owned.recordId);
  if (
    leaf === null
    || record === null
    || !leaf.encryptedRecord.equals(record)
  ) {
    fail(
      'OWNED_NOTE_INVALID',
      `owned note ${noteId} is not backed by its authenticated note leaf`,
    );
  }
  let recovered;
  try {
    recovered = recoverDirectV2Output({
      account: walletNoteAccount(wallet),
      outputNoteLeaf: leaf.leafHash.toString('hex'),
      encryptedRecord: record,
    });
  } catch (error) {
    fail(
      'OWNED_NOTE_DECRYPTION_FAILED',
      `owned note ${noteId} cannot be authenticated: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (recovered.nullifier !== owned.nullifier.toString('hex')) {
    fail(
      'OWNED_NOTE_INVALID',
      `owned note ${noteId} nullifier differs from its authenticated record`,
    );
  }
  return Object.freeze({
    publicNullifier: recovered.nullifier,
    spend: Object.freeze({
      spendSecret: wallet.spendSecret,
      incomingViewPublicKey: wallet.address.incomingViewPublicKey,
      rho: recovered.rho,
      r: recovered.r,
      encryptedRecord: Buffer.from(recovered.encryptedRecord),
    }),
  });
}

function actionTarget(parsed, pool) {
  if (parsed.command === 'withdraw') {
    return Object.freeze({
      type: 'withdrawal_locking_bytecode',
      bytes: withdrawalLockingBytecode(parsed.options.to, pool),
    });
  }
  const address = parseV2ShieldAddress(parsed.options.to, pool);
  return Object.freeze({
    type: 'shield_address',
    bytes: encodeDirectV2Address(address),
  });
}

function actionKind(command) {
  return command === 'withdraw' ? 'withdrawal' : command;
}

function outputConstruction(
  parsed,
  pool,
  postActionSequence,
  randomBytes,
) {
  if (parsed.command === 'withdraw') return null;
  const address = parseV2ShieldAddress(parsed.options.to, pool);
  return constructDirectV2Output({
    address,
    postActionSequence: String(postActionSequence),
    rng: Object.freeze({
      bytes(length) {
        let value;
        try {
          value = randomBytes(length);
        } catch (error) {
          fail('CSPRNG_FAILURE', 'CSPRNG failed', { cause: error });
        }
        if (!(value instanceof Uint8Array) || value.length !== length) {
          fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid byte string');
        }
        return Buffer.from(value);
      },
    }),
  });
}

function lifecycleForFunding(
  context,
  actionContext,
  fundingWallet,
) {
  return context.dependencies.createActionLifecycle({
    allowDevelopmentOnly: true,
    descriptor: actionContext.runtime.descriptor,
    fundingWallet,
    loadRawTransaction: async ({ networkId, transactionId }) => {
      if (networkId !== actionContext.pool.profileCore.network.id) {
        fail(
          'CHAIN_READER_NETWORK_MISMATCH',
          'raw transaction request network differs from the configured pool',
        );
      }
      return actionContext.chainClient.fetchTransaction({
        transactionId,
      });
    },
    profileCore: actionContext.pool.profileCore,
    privateActionStore: actionContext.privateActionStore,
    proofWorkspaceDirectory:
      proofWorkspacePath(context.dataDirectory),
    store: actionContext.store,
    synchronizeCanonicalTip:
      actionContext.synchronizeCanonicalTip,
  });
}

async function commandAction(parsed, context) {
  const pool = await loadPool(context.dataDirectory);
  if (parsed.options.broadcast !== true) {
    fail(
      'BROADCAST_FLAG_REQUIRED',
      `${parsed.command} requires explicit --broadcast; no dry-run construction surface is available`,
    );
  }
  if (parsed.options.to === undefined) {
    fail('ACTION_TARGET_REQUIRED', `${parsed.command} requires --to`);
  }
  if (parsed.command === 'deposit' || parsed.command === 'transfer') {
    parseV2ShieldAddress(parsed.options.to, pool);
  } else {
    validateCashAddress(parsed.options.to, pool);
  }
  if (parsed.command === 'transfer' || parsed.command === 'withdraw') {
    if (
      typeof parsed.options.note !== 'string'
      || !/^[A-Za-z0-9._:-]{1,128}$/.test(parsed.options.note)
    ) {
      fail(
        'NOTE_ID_INVALID',
        `${parsed.command} requires --note with a 1-128 character canonical local note ID`,
      );
    }
  } else if (parsed.options.note !== undefined) {
    fail('OPTION_NOT_ALLOWED', '--note is not allowed for deposit');
  }
  let actionContext;
  let lifecycle;
  let delivery;
  try {
    actionContext = await openProductionV2Context(context);
    const pending = activeOperations(actionContext.store);
    if (pending.length !== 0) {
      fail(
        'PENDING_OPERATION_REQUIRES_RECOVERY',
        `operation ${pending[0].operationId} is ${pending[0].journalState}; resolve it before creating another action`,
        {
          details: {
            operationId: pending[0].operationId,
            journalState: pending[0].journalState,
          },
          exitCode: 3,
        },
      );
    }
    await synchronizeWithoutPending(
      actionContext,
      'cli-action-initial-sync',
    );
    const operationId = randomOperationId(
      context.dependencies.randomBytes,
    );
    const current = actionContext.store.canonicalState();
    const output = outputConstruction(
      parsed,
      actionContext.pool,
      current.actionSequence + 1,
      context.dependencies.randomBytes,
    );
    const spend = parsed.command === 'deposit'
      ? null
      : spendMaterial(
        actionContext.store,
        actionContext.wallet,
        parsed.options.note,
      );
    const target = actionTarget(parsed, actionContext.pool);
    const changeWallet = randomFundingWallet(
      context.dependencies.randomBytes,
    );
    const candidates = await authenticatedFundingCandidates(
      actionContext,
    );
    if (candidates.length === 0) {
      fail(
        'FUNDING_UTXO_REQUIRED',
        'no authenticated wallet-owned tokenless P2PKH funding UTXO is available',
        { exitCode: 3 },
      );
    }
    const kind = actionKind(parsed.command);
    let selected;
    let intent;
    let preflight;
    let lastFundingError;
    for (const candidate of candidates) {
      const principal = kind === 'deposit'
        ? BigInt(actionContext.pool.profileCore.denominationSats)
        : 0n;
      if (BigInt(candidate.utxo.valueSats) <= principal) continue;
      const rawSourceTransaction =
        await actionContext.chainClient.fetchTransaction({
          transactionId: candidate.utxo.txid,
        });
      const projectedInput = projectV2FundingWalletPublic(
        candidate.fundingWallet,
      );
      const projectedChange = projectV2FundingWalletPublic(
        changeWallet,
      );
      const preliminaryIntent = Object.freeze({
        kind,
        target,
        selectedNoteId:
          kind === 'deposit' ? null : parsed.options.note,
        funding: Object.freeze({
          rawSourceTransaction:
            Buffer.from(rawSourceTransaction, 'hex'),
          txid: Buffer.from(candidate.utxo.txid, 'hex'),
          vout: candidate.utxo.vout,
          valueSats: candidate.utxo.valueSats,
          lockingBytecode:
            Buffer.from(projectedInput.lockingBytecodeHex, 'hex'),
          compressedPublicKey:
            Buffer.from(projectedInput.compressedPublicKeyHex, 'hex'),
        }),
        changeLockingBytecode:
          Buffer.from(projectedChange.lockingBytecodeHex, 'hex'),
        feePolicy: Object.freeze({
          feeRateSatsPerByte: '1',
          maximumFeeSats: candidate.utxo.valueSats,
        }),
      });
      const candidateLifecycle = await lifecycleForFunding(
        context,
        actionContext,
        candidate.fundingWallet,
      );
      try {
        const quoted = await candidateLifecycle.quoteAction({
          operationId,
          intent: preliminaryIntent,
          output,
          publicNullifier: spend?.publicNullifier ?? null,
        });
        intent = Object.freeze({
          ...preliminaryIntent,
          feePolicy: Object.freeze({
            feeRateSatsPerByte: '1',
            maximumFeeSats: quoted.measurements.feeSats,
          }),
        });
        preflight = quoted;
        selected = candidate;
        lifecycle = candidateLifecycle;
        break;
      } catch (error) {
        candidateLifecycle.closeFundingSigner();
        if (['INSUFFICIENT_FUNDING', 'DUST_CHANGE'].includes(error?.code)) {
          lastFundingError = error;
          continue;
        }
        throw error;
      }
    }
    if (selected === undefined) {
      fail(
        'FUNDING_UTXO_REQUIRED',
        'no single authenticated funding UTXO can cover the exact action, fee, and dust-safe change',
        { cause: lastFundingError, exitCode: 3 },
      );
    }
    await persistChangeWallet(
      context,
      actionContext.pool,
      actionContext.wallet,
      operationId,
      changeWallet,
    );
    await lifecycle.prepareAction({
      operationId,
      intent,
      output,
      publicNullifier: spend?.publicNullifier ?? null,
      preflight,
      crashAt: null,
    });
    await lifecycle.proveAction({
      operationId,
      spend: spend?.spend ?? null,
      crashAt: null,
    });
    const signed = await lifecycle.signAction({
      operationId,
      crashAt: null,
    });
    delivery = context.dependencies.openDeliveryJournal(
      deliveryJournalPath(context.dataDirectory),
    );
    const transport = context.dependencies.createBroadcastTransport({
      timeoutMs: actionContext.pool.chainConfig.requestTimeoutMs,
    });
    if (transport.fixtureOnly === true) {
      fail(
        'FIXTURE_TRANSPORT_REFUSED',
        'the public CLI refuses fixture-only broadcast transports',
      );
    }
    const broadcast = await lifecycle.broadcastAction({
      operationId,
      delivery,
      transport,
      endpoint: actionContext.pool.chainConfig.endpoint,
    });
    const transaction = parseV2RawTransaction(
      signed.signedTx.toString('hex'),
      { carrierCount: actionContext.pool.carrierCount },
    );
    return Object.freeze({
      command: parsed.command,
      operation: Object.freeze({
        operationId,
        journalState: broadcast.status,
        transactionId: transaction.txid,
        transactionBytes: transaction.sizeBytes,
        feeSats: preflight.measurements.feeSats,
        fundingOutpoint: Object.freeze({
          transactionId: selected.utxo.txid,
          outputIndex: selected.utxo.vout,
        }),
      }),
      mandatoryNetworkGateInvoked: true,
      networkActivity: true,
    });
  } catch (error) {
    if (error instanceof V2CliError) throw error;
    fail(
      typeof error?.code === 'string' ? error.code : 'V2_ACTION_FAILED',
      error instanceof Error ? error.message : String(error),
      {
        cause: error,
        exitCode: error?.recoverable === true ? 3 : 2,
      },
    );
  } finally {
    lifecycle?.closeFundingSigner();
    delivery?.close();
    actionContext?.store.close();
  }
}

function fundingWalletForOperation(wallet, operation) {
  const expected = operation.intent.funding.compressedPublicKey
    .toString('hex');
  const selected = fundingWalletKeyring(wallet).find(
    (entry) => entry.compressedPublicKeyHex === expected,
  );
  if (selected === undefined) {
    fail(
      'FUNDING_WALLET_MISMATCH',
      `operation ${operation.operationId} funding key is absent from the authenticated local keyring`,
    );
  }
  return selected;
}

function outputConstructionForOperation(
  operation,
  postActionSequence,
  randomBytes,
) {
  if (operation.kind === 'withdrawal') return null;
  if (operation.intent.target.type !== 'shield_address') {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      'note-producing operation does not retain a shield-address target',
    );
  }
  let address;
  try {
    address = decodeDirectV2Address(operation.intent.target.bytes);
  } catch (error) {
    fail(
      'PRIVATE_ACTION_RECORD_INVALID',
      'stored operation shield target cannot be decoded',
      { cause: error },
    );
  }
  return constructDirectV2Output({
    address,
    postActionSequence: String(postActionSequence),
    rng: Object.freeze({
      bytes(length) {
        let value;
        try {
          value = randomBytes(length);
        } catch (error) {
          fail('CSPRNG_FAILURE', 'CSPRNG failed', { cause: error });
        }
        if (!(value instanceof Uint8Array) || value.length !== length) {
          fail('CSPRNG_FAILURE', 'CSPRNG returned an invalid byte string');
        }
        return Buffer.from(value);
      },
    }),
  });
}

async function rebaseWithFreshPrivateAction(
  context,
  actionContext,
  lifecycle,
  operation,
  explicitUserSelection,
) {
  return lifecycle.rebaseOperation({
    operationId: operation.operationId,
    explicitUserSelection,
    constructPrivateAction: async (challenge) => {
      if (
        challenge.operationId !== operation.operationId
        || challenge.kind !== operation.kind
        || challenge.postActionSequence
          !== challenge.expectedActionSequence + 1
      ) {
        fail(
          'PRIVATE_ACTION_RECORD_MISMATCH',
          'lifecycle rebase challenge differs from the selected operation',
        );
      }
      const currentOperation =
        actionContext.store.operation(operation.operationId);
      const spend = currentOperation.kind === 'deposit'
        ? null
        : spendMaterial(
          actionContext.store,
          actionContext.wallet,
          currentOperation.intent.selectedNoteId,
          { operationId: currentOperation.operationId },
        );
      const output = outputConstructionForOperation(
        currentOperation,
        challenge.postActionSequence,
        context.dependencies.randomBytes,
      );
      return Object.freeze({
        output,
        publicNullifier: spend?.publicNullifier ?? null,
      });
    },
  });
}

async function proveDurableOperation(
  actionContext,
  lifecycle,
  operation,
) {
  const spend = operation.kind === 'deposit'
    ? null
    : spendMaterial(
      actionContext.store,
      actionContext.wallet,
      operation.intent.selectedNoteId,
      { operationId: operation.operationId },
    );
  return lifecycle.proveAction({
    operationId: operation.operationId,
    spend: spend?.spend ?? null,
    crashAt: null,
  });
}

function operationResult(operation, next, extras = {}) {
  let transactionId = null;
  let transactionBytes = null;
  if (operation.signedTx !== null) {
    const parsed = parseV2RawTransaction(operation.signedTx.toString('hex'));
    transactionId = parsed.txid;
    transactionBytes = parsed.sizeBytes;
  }
  return Object.freeze({
    operationId: operation.operationId,
    kind: operation.kind,
    journalState: operation.journalState,
    retryCount: operation.retryCount,
    next,
    transactionId,
    transactionBytes,
    ...extras,
  });
}

function createPublicBroadcastTransport(context, actionContext) {
  const transport = context.dependencies.createBroadcastTransport({
    timeoutMs: actionContext.pool.chainConfig.requestTimeoutMs,
  });
  if (transport.fixtureOnly === true) {
    fail(
      'FIXTURE_TRANSPORT_REFUSED',
      'the public CLI refuses fixture-only broadcast transports',
    );
  }
  return transport;
}

async function broadcastDurableOperation(
  context,
  actionContext,
  lifecycle,
  operationId,
) {
  const delivery = context.dependencies.openDeliveryJournal(
    deliveryJournalPath(context.dataDirectory),
  );
  try {
    return await lifecycle.broadcastAction({
      operationId,
      delivery,
      transport: createPublicBroadcastTransport(context, actionContext),
      endpoint: actionContext.pool.chainConfig.endpoint,
    });
  } finally {
    delivery.close();
  }
}

function validateOperationInvocation(parsed) {
  const subcommand = parsed.command.slice('operation.'.length);
  if (subcommand === 'abandon') {
    const reason = parsed.options.reason;
    if (
      typeof reason !== 'string'
      || reason.length < 1
      || reason.length > 256
      || /[\u0000-\u001f\u007f]/.test(reason)
    ) {
      fail(
        'ABANDON_REASON_INVALID',
        'operation abandon requires --reason with 1-256 printable characters',
      );
    }
  }
  if (subcommand === 'rebroadcast') {
    if (parsed.options.broadcast !== true) {
      fail(
        'BROADCAST_FLAG_REQUIRED',
        'exact rebroadcast requires explicit --broadcast',
      );
    }
    if (
      parsed.options.acknowledgement
        !== V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT
    ) {
      fail(
        'EXACT_RESUBMISSION_ACKNOWLEDGEMENT_REQUIRED',
        `--acknowledgement must exactly equal ${V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT}`,
      );
    }
    if (
      typeof parsed.options['attempt-token'] !== 'string'
      || parsed.options['attempt-token'].length === 0
    ) {
      fail(
        'DELIVERY_ATTEMPT_TOKEN_REQUIRED',
        'exact rebroadcast requires --attempt-token from the durable delivery record',
      );
    }
  }
  return subcommand;
}

async function commandOperation(parsed, context) {
  const subcommand = validateOperationInvocation(parsed);
  let actionContext;
  let lifecycle;
  let delivery;
  try {
    actionContext = await openProductionV2Context(context);
    let operation =
      actionContext.store.operation(parsed.operationId);
    lifecycle = await lifecycleForFunding(
      context,
      actionContext,
      fundingWalletForOperation(actionContext.wallet, operation),
    );

    if (subcommand === 'abandon') {
      operation = lifecycle.abandonOperation({
        operationId: operation.operationId,
        reason: parsed.options.reason,
      });
      return Object.freeze({
        command: parsed.command,
        operation: operationResult(operation, 'terminal'),
        mandatoryNetworkGateInvoked: false,
        networkActivity: false,
      });
    }

    if (subcommand === 'rebase') {
      operation = await rebaseWithFreshPrivateAction(
        context,
        actionContext,
        lifecycle,
        operation,
        true,
      );
      return Object.freeze({
        command: parsed.command,
        operation: operationResult(operation, 'prove'),
        mandatoryNetworkGateInvoked: false,
        networkActivity: true,
      });
    }

    if (subcommand === 'confirm') {
      operation = await lifecycle.confirmAction({
        operationId: operation.operationId,
      });
      return Object.freeze({
        command: parsed.command,
        operation: operationResult(
          operation,
          operation.journalState === 'settled' ? 'complete' : 'confirm',
        ),
        mandatoryNetworkGateInvoked: false,
        networkActivity: true,
      });
    }

    if (subcommand === 'reconcile') {
      delivery = context.dependencies.openDeliveryJournal(
        deliveryJournalPath(context.dataDirectory),
      );
      let observed;
      try {
        observed = await lifecycle.recoverBroadcastAction({
          operationId: operation.operationId,
          delivery,
        });
      } catch (error) {
        if (
          ['TRANSACTION_NOT_OBSERVED', 'TRANSACTION_OBSERVATION_FAILED']
            .includes(error?.code)
        ) {
          const record = delivery.record(operation.operationId);
          fail(
            error.code,
            error.message,
            {
              cause: error,
              details: record === null
                ? undefined
                : {
                    deliveryState: record.state,
                    attemptToken: record.attemptToken,
                    attemptCount: record.attemptCount,
                    exactResubmissionAcknowledgement:
                      V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT,
                  },
              exitCode: 3,
            },
          );
        }
        throw error;
      }
      operation = actionContext.store.operation(operation.operationId);
      let next = 'confirm';
      try {
        operation = await lifecycle.confirmAction({
          operationId: operation.operationId,
        });
        next = operation.journalState === 'settled'
          ? 'complete'
          : 'confirm';
      } catch (error) {
        if (error?.code !== 'CONFIRMATION_PENDING') throw error;
      }
      return Object.freeze({
        command: parsed.command,
        operation: operationResult(operation, next, {
          observationStatus: observed.status,
        }),
        mandatoryNetworkGateInvoked: false,
        networkActivity: true,
      });
    }

    if (subcommand === 'rebroadcast') {
      delivery = context.dependencies.openDeliveryJournal(
        deliveryJournalPath(context.dataDirectory),
      );
      const result = await lifecycle.rebroadcastExactAction({
        operationId: operation.operationId,
        delivery,
        transport: createPublicBroadcastTransport(context, actionContext),
        endpoint: actionContext.pool.chainConfig.endpoint,
        priorAttemptToken: parsed.options['attempt-token'],
        acknowledgement: parsed.options.acknowledgement,
      });
      operation = actionContext.store.operation(operation.operationId);
      return Object.freeze({
        command: parsed.command,
        operation: operationResult(operation, 'chain-reconcile-no-resend', {
          replayed: result.replayed,
        }),
        mandatoryNetworkGateInvoked: true,
        networkActivity: true,
      });
    }

    let resumed = await lifecycle.resumeOperation({
      operationId: operation.operationId,
    });
    operation = resumed.operation;
    if (['needs_reproof', 'reorged'].includes(operation.journalState)) {
      operation = await rebaseWithFreshPrivateAction(
        context,
        actionContext,
        lifecycle,
        operation,
        false,
      );
    }
    if (['tip_synced', 'proving'].includes(operation.journalState)) {
      operation = await proveDurableOperation(
        actionContext,
        lifecycle,
        operation,
      );
    }
    if (operation.journalState === 'proved') {
      operation = await lifecycle.signAction({
        operationId: operation.operationId,
        crashAt: null,
      });
    }
    let gateInvoked = false;
    let networkActivity = true;
    if (
      operation.journalState === 'signed'
      && parsed.options.broadcast === true
    ) {
      await broadcastDurableOperation(
        context,
        actionContext,
        lifecycle,
        operation.operationId,
      );
      gateInvoked = true;
      operation = actionContext.store.operation(operation.operationId);
    }
    resumed = await lifecycle.resumeOperation({
      operationId: operation.operationId,
    });
    operation = resumed.operation;
    return Object.freeze({
      command: parsed.command,
      operation: operationResult(operation, resumed.next),
      mandatoryNetworkGateInvoked: gateInvoked,
      networkActivity,
    });
  } catch (error) {
    if (error instanceof V2CliError) throw error;
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'V2_OPERATION_FAILED',
      error instanceof Error ? error.message : String(error),
      {
        cause: error,
        exitCode: error?.recoverable === true ? 3 : 2,
      },
    );
  } finally {
    lifecycle?.closeFundingSigner();
    delivery?.close();
    actionContext?.store.close();
  }
}

async function commandOnlineSync(context, command = 'sync') {
  let actionContext;
  const lifecycles = [];
  try {
    actionContext = await openProductionV2Context(context);
    let pending = activeOperations(actionContext.store);
    const operationResults = [];
    if (pending.length === 0) {
      await synchronizeWithoutPending(actionContext, `cli-${command}`);
      await authenticatedFundingCandidates(actionContext);
    } else {
      for (const operation of pending) {
        const lifecycle = await lifecycleForFunding(
          context,
          actionContext,
          fundingWalletForOperation(actionContext.wallet, operation),
        );
        lifecycles.push(lifecycle);
        if (
          ['broadcast', 'mempool', 'confirmed'].includes(
            operation.journalState,
          )
        ) {
          try {
            const settled = await lifecycle.confirmAction({
              operationId: operation.operationId,
            });
            operationResults.push(Object.freeze({
              operationId: settled.operationId,
              journalState: settled.journalState,
              next: settled.journalState === 'settled'
                ? 'complete'
                : 'confirm',
            }));
          } catch (error) {
            if (error?.code !== 'CONFIRMATION_PENDING') throw error;
            const resumed = await lifecycle.resumeOperation({
              operationId: operation.operationId,
            });
            operationResults.push(Object.freeze({
              operationId: operation.operationId,
              journalState: resumed.operation.journalState,
              next: resumed.next,
            }));
          }
        } else {
          const resumed = await lifecycle.resumeOperation({
            operationId: operation.operationId,
          });
          operationResults.push(Object.freeze({
            operationId: operation.operationId,
            journalState: resumed.operation.journalState,
            next: resumed.next,
          }));
        }
      }
      pending = activeOperations(actionContext.store);
      if (pending.length === 0) {
        await authenticatedFundingCandidates(actionContext);
      }
    }
    const canonical = actionContext.store.canonicalState();
    return Object.freeze({
      command,
      canonical: Object.freeze({
        transactionId: canonical.outpoint.txid.toString('hex'),
        outputIndex: canonical.outpoint.vout,
        actionSequence: canonical.actionSequence,
        height: canonical.height,
        blockHash: canonical.blockHash.toString('hex'),
        stateHex: canonical.state.toString('hex'),
      }),
      operations: Object.freeze(operationResults),
      pendingOperationCount: pending.length,
      networkActivity: true,
    });
  } catch (error) {
    if (error instanceof V2CliError) throw error;
    fail(
      typeof error?.code === 'string' ? error.code : 'V2_SYNC_FAILED',
      error instanceof Error ? error.message : String(error),
      {
        cause: error,
        exitCode: error?.recoverable === true ? 3 : 2,
      },
    );
  } finally {
    for (const lifecycle of lifecycles) lifecycle.closeFundingSigner();
    actionContext?.store.close();
  }
}

const DEFAULT_DEPENDENCIES = Object.freeze({
  createActionLifecycle: createV2DirectActionLifecycle,
  createBroadcastTransport: createV2HttpsTransport,
  createCanonicalSynchronizer: createV2CanonicalHistorySynchronizer,
  createChainClient: createV2ChipnetChainClient,
  createPrivateActionStore: createV2PrivateActionStore,
  createSecretFile: createV2SecretFile,
  deriveRecoveryScanner:
    deriveV2RecoveryScannerFromValidatedDescriptor,
  loadChainConfig: loadV2ChainConfig,
  loadDescriptor: loadV2InstanceDescriptor,
  openDeliveryJournal: openV2DeliveryJournal,
  randomBytes: systemRandomBytes,
  resolveRuntimeMaterialsSha256: async (descriptor) => {
    const resolution =
      await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor);
    return deriveV2Pf10StoreRuntimeMaterialsSha256(resolution);
  },
  openStore: openV2DirectStore,
  openExistingStore: openExistingV2DirectStore,
});

/**
 * Execute one V2 CLI command. Read-only status/doctor remain offline; sync and
 * mutation commands use only the descriptor-bound read client, and every send
 * crosses the mandatory durable network gate.
 */
export async function executeV2Cli(
  argv,
  {
    cwd = process.cwd(),
    env = process.env,
    dependencies = {},
  } = {},
) {
  const parsed = parseV2CliArguments(argv);
  requireV2Protocol(parsed.options);
  const context = Object.freeze({
    cwd: path.resolve(cwd),
    env,
    dataDirectory: resolveDataDirectory(parsed.options, cwd, env),
    dependencies: Object.freeze({
      ...DEFAULT_DEPENDENCIES,
      ...dependencies,
    }),
  });
  await inspectDirectoryAncestry(
    context.dataDirectory,
    { allowMissing: true },
  );
  let result;
  if (parsed.command === 'pool.add') {
    result = await commandPoolAdd(parsed, context);
  } else if (parsed.command === 'wallet.create') {
    result = await commandWalletCreate(context);
  } else if (parsed.command === 'wallet.receive') {
    result = await commandWalletReceive(context);
  } else if (
    parsed.command === 'recover'
    || parsed.command === 'sync'
  ) {
    result = await commandOnlineSync(context, parsed.command);
  } else if (parsed.command === 'status') {
    result = await commandStatus(context);
  } else if (parsed.command === 'doctor') {
    result = await commandDoctor(context);
  } else if (parsed.command.startsWith('operation.')) {
    result = await commandOperation(parsed, context);
  } else {
    result = await commandAction(parsed, context);
  }
  return Object.freeze({
    ok: true,
    protocol: V2_CLI_PROTOCOL,
    maturity: V2_CLI_MATURITY,
    qualification: 'blocked',
    ...result,
  });
}

export function v2CliErrorResult(error) {
  const normalized = error instanceof V2CliError
    ? error
    : new V2CliError(
      'V2_CLI_UNEXPECTED',
      error instanceof Error ? error.message : String(error),
      { exitCode: 1, cause: error },
    );
  return Object.freeze({
    exitCode: normalized.exitCode,
    body: Object.freeze({
      ok: false,
      protocol: V2_CLI_PROTOCOL,
      maturity: V2_CLI_MATURITY,
      qualification: 'blocked',
      error: Object.freeze({
        code: normalized.code,
        message: normalized.message,
        ...(normalized.details === undefined
          ? {}
          : { details: normalized.details }),
      }),
    }),
  });
}
