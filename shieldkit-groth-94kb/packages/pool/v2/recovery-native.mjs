import { createHash, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { spawn } from 'node:child_process';

const SHA256_HEX = /^[0-9a-f]{64}$/;
const SCAN_RESULT_SCHEMA = 'shieldkit-v2-recovery-scan-result-v2';
const SNAPSHOT_SCHEMA = 'shieldkit-v2-recovery-snapshot-v2';
const AUTHENTICATED_MATERIAL_SCHEMA =
  'shieldkit-v2-recovery-authenticated-material-v2';
const MAX_U32 = 0xffff_ffff;
const MAX_ACTION_SEQUENCE = 0x1_ffff_ffff;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;
const COMMANDS = new Set([
  'scan',
  'authenticate-snapshot',
  'verify-snapshot',
]);
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 2 * 60 * 60 * 1000;
const MAX_TIMEOUT_MS = 24 * 60 * 60 * 1000;
const STREAM_MAGIC = Buffer.from('SKR2F001', 'ascii');
const STREAM_INPUT_SCHEMA = 'shieldkit-v2-recovery-stream-input-v2';
const AUTHENTICATE_STREAM_INPUT_SCHEMA =
  'shieldkit-v2-recovery-authenticate-snapshot-stream-input-v2';
const STREAM_OUTPUT_SCHEMA = 'shieldkit-v2-recovery-stream-output-v2';
const MAX_STREAM_FRAME_BYTES = 512 * 1024;
const MAX_STREAM_ACTIONS = 0xffff_fffd;
const MAX_STREAM_OUTPUT_RECORDS = 0x2_0000_0020;
const MAX_STREAM_STDERR_BYTES = 64 * 1024;
const STREAM_INPUT_DOMAIN = Buffer.from(
  'ShieldKit V2 recovery stream input v2\0',
  'utf8',
);
const AUTHENTICATE_STREAM_INPUT_DOMAIN = Buffer.from(
  'ShieldKit V2 recovery authenticate snapshot stream input v2\0',
  'utf8',
);
const STREAM_OUTPUT_DOMAIN = Buffer.from(
  'ShieldKit V2 recovery stream output v2\0',
  'utf8',
);

export class NativeRecoveryError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'NativeRecoveryError';
  }
}

const fail = (message, options) => {
  throw new NativeRecoveryError(message, options);
};

function exactObject(value, expected, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
}

function safeInteger(value, minimum, maximum, label) {
  if (
    !Number.isSafeInteger(value)
    || value < minimum
    || value > maximum
  ) {
    fail(`${label} is outside its safe integer range`);
  }
  return value;
}

function hexBytes(value, length, label) {
  if (
    typeof value !== 'string'
    || value.length !== length * 2
    || !/^[0-9a-f]+$/.test(value)
  ) {
    fail(`${label} must be exactly ${length} lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function canonicalMoney(value, label) {
  if (
    typeof value !== 'string'
    || !/^(0|[1-9][0-9]*)$/.test(value)
    || BigInt(value) === 0n
    || BigInt(value) > MAX_MONEY_SATS
  ) {
    fail(`${label} must be nonzero canonical money`);
  }
  return value;
}

function convertedArray(value, converter, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return Object.freeze(
    value.map((entry, index) => converter(entry, `${label}[${index}]`)),
  );
}

function convertBinding(value) {
  const input = exactObject(value, [
    'profileId',
    'instanceId',
    'networkId',
    'denominationSats',
    'carrierCount',
    'runtimeMaterialsSha256',
  ], 'native recovery material.binding');
  return Object.freeze({
    profileId: hexBytes(
      input.profileId,
      32,
      'native recovery material.binding.profileId',
    ),
    instanceId: hexBytes(
      input.instanceId,
      32,
      'native recovery material.binding.instanceId',
    ),
    networkId: safeInteger(
      input.networkId,
      1,
      2,
      'native recovery material.binding.networkId',
    ),
    denominationSats: canonicalMoney(
      input.denominationSats,
      'native recovery material.binding.denominationSats',
    ),
    carrierCount: safeInteger(
      input.carrierCount,
      1,
      0xff,
      'native recovery material.binding.carrierCount',
    ),
    runtimeMaterialsSha256: hexBytes(
      input.runtimeMaterialsSha256,
      32,
      'native recovery material.binding.runtimeMaterialsSha256',
    ),
  });
}

function convertOutpoint(value) {
  const input = exactObject(
    value,
    ['txid', 'vout'],
    'native recovery material.canonical.outpoint',
  );
  return Object.freeze({
    txid: hexBytes(
      input.txid,
      32,
      'native recovery material.canonical.outpoint.txid',
    ),
    vout: safeInteger(
      input.vout,
      0,
      MAX_U32,
      'native recovery material.canonical.outpoint.vout',
    ),
  });
}

function convertCanonical(value) {
  const input = exactObject(value, [
    'state',
    'outpoint',
    'actionSequence',
    'height',
    'blockHash',
  ], 'native recovery material.canonical');
  return Object.freeze({
    state: hexBytes(
      input.state,
      128,
      'native recovery material.canonical.state',
    ),
    outpoint: convertOutpoint(input.outpoint),
    actionSequence: safeInteger(
      input.actionSequence,
      0,
      MAX_ACTION_SEQUENCE,
      'native recovery material.canonical.actionSequence',
    ),
    height: safeInteger(
      input.height,
      0,
      MAX_U32,
      'native recovery material.canonical.height',
    ),
    blockHash: hexBytes(
      input.blockHash,
      32,
      'native recovery material.canonical.blockHash',
    ),
  });
}

function convertTreeNode(value, label) {
  const input = exactObject(
    value,
    ['depth', 'nodeIndex', 'nodeHash'],
    label,
  );
  const depth = safeInteger(input.depth, 0, 32, `${label}.depth`);
  return Object.freeze({
    depth,
    nodeIndex: safeInteger(
      input.nodeIndex,
      0,
      (2 ** (32 - depth)) - 1,
      `${label}.nodeIndex`,
    ),
    nodeHash: hexBytes(input.nodeHash, 32, `${label}.nodeHash`),
  });
}

function convertFrontier(value, label) {
  const input = exactObject(value, ['depth', 'nodeHash'], label);
  return Object.freeze({
    depth: safeInteger(input.depth, 0, 31, `${label}.depth`),
    nodeHash: hexBytes(input.nodeHash, 32, `${label}.nodeHash`),
  });
}

function convertNoteLeaf(value, label) {
  const input = exactObject(value, [
    'noteIndex',
    'leafHash',
    'encryptedRecord',
    'actionSequence',
    'transactionId',
  ], label);
  return Object.freeze({
    noteIndex: safeInteger(
      input.noteIndex,
      0,
      MAX_U32,
      `${label}.noteIndex`,
    ),
    leafHash: hexBytes(input.leafHash, 32, `${label}.leafHash`),
    encryptedRecord: hexBytes(
      input.encryptedRecord,
      128,
      `${label}.encryptedRecord`,
    ),
    actionSequence: safeInteger(
      input.actionSequence,
      1,
      MAX_ACTION_SEQUENCE,
      `${label}.actionSequence`,
    ),
    transactionId: hexBytes(
      input.transactionId,
      32,
      `${label}.transactionId`,
    ),
  });
}

function convertNullifierLeaf(value, label) {
  const input = exactObject(value, [
    'physicalIndex',
    'leafType',
    'leafHash',
    'key',
    'successorIndex',
    'successorKey',
  ], label);
  return Object.freeze({
    physicalIndex: safeInteger(
      input.physicalIndex,
      0,
      MAX_U32,
      `${label}.physicalIndex`,
    ),
    leafType: safeInteger(input.leafType, 1, 3, `${label}.leafType`),
    leafHash: hexBytes(input.leafHash, 32, `${label}.leafHash`),
    key: hexBytes(input.key, 32, `${label}.key`),
    successorIndex: safeInteger(
      input.successorIndex,
      0,
      MAX_U32,
      `${label}.successorIndex`,
    ),
    successorKey: hexBytes(
      input.successorKey,
      32,
      `${label}.successorKey`,
    ),
  });
}

function canonicalCount(value, maximum, label) {
  if (
    typeof value !== 'string'
    || !/^(0|[1-9][0-9]*)$/.test(value)
  ) {
    fail(`${label} must be a canonical unsigned decimal integer`);
  }
  const count = Number(value);
  if (
    !Number.isSafeInteger(count)
    || count < 0
    || count > maximum
  ) {
    fail(`${label} exceeds its protocol range`);
  }
  return count;
}

function convertActionSnapshot(value, label) {
  const input = exactObject(value, [
    'transactionId',
    'height',
    'blockHash',
    'kind',
    'packetHex',
    'transactionContextHash',
  ], label);
  if (!['deposit', 'transfer', 'withdrawal'].includes(input.kind)) {
    fail(`${label}.kind is unsupported`);
  }
  return Object.freeze({
    transactionId: hexBytes(
      input.transactionId,
      32,
      `${label}.transactionId`,
    ),
    height: safeInteger(input.height, 0, MAX_U32, `${label}.height`),
    blockHash: hexBytes(input.blockHash, 32, `${label}.blockHash`),
    kind: input.kind,
    packet: hexBytes(input.packetHex, 552, `${label}.packetHex`),
    transactionContextHash: hexBytes(
      input.transactionContextHash,
      32,
      `${label}.transactionContextHash`,
    ),
  });
}

function validateCompactSnapshot(value) {
  const snapshot = exactObject(value, [
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
  ], 'native recovery stream snapshot');
  if (snapshot.schema !== SNAPSHOT_SCHEMA || snapshot.version !== 2) {
    fail('native recovery stream snapshot schema or version is unsupported');
  }
  safeInteger(snapshot.networkId, 1, 2, 'native recovery stream snapshot.networkId');
  hexBytes(snapshot.profileId, 32, 'native recovery stream snapshot.profileId');
  hexBytes(snapshot.instanceId, 32, 'native recovery stream snapshot.instanceId');
  canonicalMoney(
    snapshot.denominationSats,
    'native recovery stream snapshot.denominationSats',
  );
  safeInteger(
    snapshot.carrierCount,
    1,
    0xff,
    'native recovery stream snapshot.carrierCount',
  );
  hexBytes(
    snapshot.runtimeMaterialsSha256,
    32,
    'native recovery stream snapshot.runtimeMaterialsSha256',
  );
  if (
    snapshot.poseidonProfile
    !== 'shieldkit-pool-action-v2-direct-poseidon-v1'
  ) {
    fail('native recovery stream snapshot Poseidon profile is unsupported');
  }
  const point = (candidate, label) => {
    const input = exactObject(candidate, [
      'transactionId',
      'outputIndex',
      'height',
      'blockHash',
      'stateHex',
    ], label);
    hexBytes(input.transactionId, 32, `${label}.transactionId`);
    safeInteger(input.outputIndex, 0, MAX_U32, `${label}.outputIndex`);
    safeInteger(input.height, 0, MAX_U32, `${label}.height`);
    hexBytes(input.blockHash, 32, `${label}.blockHash`);
    hexBytes(input.stateHex, 128, `${label}.stateHex`);
  };
  point(snapshot.genesis, 'native recovery stream snapshot.genesis');
  point(snapshot.tip, 'native recovery stream snapshot.tip');
  canonicalCount(
    snapshot.actionCount,
    MAX_STREAM_ACTIONS,
    'native recovery stream snapshot.actionCount',
  );
  hexBytes(
    snapshot.historySha256,
    32,
    'native recovery stream snapshot.historySha256',
  );
  hexBytes(snapshot.stateHex, 128, 'native recovery stream snapshot.stateHex');
  const tree = (candidate, label) => {
    const input = exactObject(candidate, ['depth', 'count', 'root'], label);
    if (input.depth !== 32) fail(`${label}.depth must be 32`);
    canonicalCount(input.count, MAX_U32, `${label}.count`);
    hexBytes(input.root, 32, `${label}.root`);
  };
  tree(snapshot.noteTree, 'native recovery stream snapshot.noteTree');
  tree(
    snapshot.nullifierTree,
    'native recovery stream snapshot.nullifierTree',
  );
  if (typeof snapshot.externalAuthenticationBoundary !== 'string') {
    fail(
      'native recovery stream snapshot.externalAuthenticationBoundary must be a string',
    );
  }
  hexBytes(
    snapshot.contentSha256,
    32,
    'native recovery stream snapshot.contentSha256',
  );
  return snapshot;
}

function validateSnapshotEnvelope(value) {
  const snapshot = exactObject(value, [
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
    'actions',
    'externalAuthenticationBoundary',
    'contentSha256',
  ], 'native recovery scan result.snapshot');
  if (snapshot.schema !== SNAPSHOT_SCHEMA || snapshot.version !== 2) {
    fail('native recovery scan result snapshot schema or version is unsupported');
  }
  if (
    typeof snapshot.contentSha256 !== 'string'
    || !SHA256_HEX.test(snapshot.contentSha256)
  ) {
    fail(
      'native recovery scan result.snapshot.contentSha256 must be exactly 32 lowercase hexadecimal bytes',
    );
  }
  hexBytes(
    snapshot.runtimeMaterialsSha256,
    32,
    'native recovery scan result.snapshot.runtimeMaterialsSha256',
  );
  return snapshot;
}

function validateAuthenticatedMaterial(value) {
  const material = exactObject(value, [
    'schema',
    'contentSha256',
    'binding',
    'canonical',
    'noteNodes',
    'noteFrontier',
    'noteLeaves',
    'nullifierNodes',
    'nullifierLeaves',
  ], 'native recovery authenticated material');
  if (material.schema !== AUTHENTICATED_MATERIAL_SCHEMA) {
    fail('native recovery authenticated material schema is unsupported');
  }
  if (
    typeof material.contentSha256 !== 'string'
    || !SHA256_HEX.test(material.contentSha256)
  ) {
    fail(
      'native recovery material.contentSha256 must be exactly 32 lowercase hexadecimal bytes',
    );
  }
  return material;
}

function convertValidatedAuthenticatedMaterial(material) {
  return Object.freeze({
    binding: convertBinding(material.binding),
    canonical: convertCanonical(material.canonical),
    noteNodes: convertedArray(
      material.noteNodes,
      convertTreeNode,
      'native recovery material.noteNodes',
    ),
    noteFrontier: convertedArray(
      material.noteFrontier,
      convertFrontier,
      'native recovery material.noteFrontier',
    ),
    noteLeaves: convertedArray(
      material.noteLeaves,
      convertNoteLeaf,
      'native recovery material.noteLeaves',
    ),
    nullifierNodes: convertedArray(
      material.nullifierNodes,
      convertTreeNode,
      'native recovery material.nullifierNodes',
    ),
    nullifierLeaves: convertedArray(
      material.nullifierLeaves,
      convertNullifierLeaf,
      'native recovery material.nullifierLeaves',
    ),
    crashAt: null,
  });
}

function convertAuthenticatedMaterial(value) {
  return convertValidatedAuthenticatedMaterial(
    validateAuthenticatedMaterial(value),
  );
}

/**
 * Convert strict Rust recovery wire output into the exact
 * V2DirectStore.installAuthenticatedSnapshot input. This conversion does not
 * authenticate chain inclusion, an unspent tip, or internal tree relations.
 */
export function nativeRecoveryResultToStoreInstall(value) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('native recovery result must be an object');
  }
  if (value.schema === SCAN_RESULT_SCHEMA) {
    const result = exactObject(
      value,
      ['schema', 'snapshot', 'material'],
      'native recovery scan result',
    );
    const snapshot = validateSnapshotEnvelope(result.snapshot);
    const material = validateAuthenticatedMaterial(result.material);
    if (material.contentSha256 !== snapshot.contentSha256) {
      fail(
        'native recovery scan result material.contentSha256 differs from snapshot.contentSha256',
      );
    }
    const binding = convertBinding(material.binding);
    if (!binding.runtimeMaterialsSha256.equals(
      Buffer.from(snapshot.runtimeMaterialsSha256, 'hex'),
    )) {
      fail(
        'native recovery scan result material.binding.runtimeMaterialsSha256 differs from snapshot.runtimeMaterialsSha256',
      );
    }
    return convertValidatedAuthenticatedMaterial(material);
  }
  if (value.schema === AUTHENTICATED_MATERIAL_SCHEMA) {
    return convertAuthenticatedMaterial(value);
  }
  fail('native recovery result schema is unsupported');
}

function exactOptions(value) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail('native recovery options must be an object');
  }
  const expected = [
    'binaryPath',
    'binarySha256',
    'command',
    'request',
    'timeoutMs',
  ];
  const actual = Object.keys(value).sort();
  const allowed = new Set(expected);
  if (actual.some((key) => !allowed.has(key))) {
    fail('native recovery options contain an unknown property');
  }
  for (const required of expected.slice(0, 4)) {
    if (!Object.hasOwn(value, required)) {
      fail(`native recovery options are missing ${required}`);
    }
  }
}

function validateOptions(value) {
  exactOptions(value);
  if (typeof value.binaryPath !== 'string' || !isAbsolute(value.binaryPath)) {
    fail('binaryPath must be an absolute path');
  }
  if (
    typeof value.binarySha256 !== 'string'
    || !SHA256_HEX.test(value.binarySha256)
  ) {
    fail('binarySha256 must be exactly 32 lowercase hexadecimal bytes');
  }
  if (!COMMANDS.has(value.command)) {
    fail('command must be scan, authenticate-snapshot, or verify-snapshot');
  }
  if (
    value.request === null
    || Array.isArray(value.request)
    || typeof value.request !== 'object'
  ) {
    fail('request must be a JSON object');
  }
  const timeoutMs = value.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1
    || timeoutMs > MAX_TIMEOUT_MS
  ) {
    fail(`timeoutMs must be an integer from 1 to ${MAX_TIMEOUT_MS}`);
  }
  return { ...value, timeoutMs };
}

async function digestHandle(handle) {
  const digest = createHash('sha256');
  const chunk = Buffer.allocUnsafe(64 * 1024);
  let position = 0;
  while (true) {
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, position);
    if (bytesRead === 0) break;
    digest.update(chunk.subarray(0, bytesRead));
    position += bytesRead;
  }
  return digest.digest();
}

function sameFile(left, right) {
  return (
    left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
  );
}

async function openPinnedBinary(binaryPath, expectedHex) {
  const before = await lstat(binaryPath, { bigint: true });
  if (before.isSymbolicLink() || !before.isFile()) {
    fail('native recovery binary must be a regular, non-symlink file');
  }
  if ((before.mode & 0o111n) === 0n) {
    fail('native recovery binary is not executable');
  }
  let handle;
  try {
    handle = await open(
      binaryPath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameFile(before, opened)) {
      fail('native recovery binary changed while it was opened');
    }
    const actual = await digestHandle(handle);
    const expected = Buffer.from(expectedHex, 'hex');
    if (!timingSafeEqual(actual, expected)) {
      fail('native recovery binary SHA-256 pin mismatch');
    }
    return { handle, stat: opened, digest: actual };
  } catch (error) {
    await handle?.close();
    throw error;
  }
}

function collect(stream, label, child) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    stream.on('data', (chunk) => {
      length += chunk.length;
      if (length > MAX_OUTPUT_BYTES) {
        child.kill('SIGKILL');
        reject(new NativeRecoveryError(
          `native recovery ${label} exceeds ${MAX_OUTPUT_BYTES} bytes`,
        ));
        return;
      }
      chunks.push(chunk);
    });
    stream.once('error', (error) => reject(new NativeRecoveryError(
      `cannot read native recovery ${label}`,
      { cause: error },
    )));
    stream.once('end', () => resolve(Buffer.concat(chunks, length)));
  });
}

async function executeOpened({
  handle,
  stat,
  digest,
  command,
  requestBytes,
  timeoutMs,
}) {
  if (process.platform !== 'linux') {
    fail('descriptor-pinned native recovery execution currently requires Linux /proc');
  }
  const executableFd = 3;
  const child = spawn(`/proc/self/fd/${executableFd}`, [command], {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe', handle.fd],
    windowsHide: true,
  });
  const stdoutPromise = collect(child.stdout, 'stdout', child);
  const stderrPromise = collect(child.stderr, 'stderr', child);
  const exitPromise = new Promise((resolve, reject) => {
    child.once('error', (error) => reject(new NativeRecoveryError(
      'cannot execute descriptor-pinned native recovery binary',
      { cause: error },
    )));
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const timeout = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
  timeout.unref();
  try {
    const stdinPromise = new Promise((resolve, reject) => {
      child.stdin.once('error', (error) => reject(new NativeRecoveryError(
        'cannot write the native recovery request',
        { cause: error },
      )));
      child.stdin.end(requestBytes, resolve);
    });
    const [{ code, signal }, stdout, stderr] = await Promise.all([
      exitPromise,
      stdoutPromise,
      stderrPromise,
      stdinPromise,
    ]);
    const after = await handle.stat({ bigint: true });
    const afterDigest = await digestHandle(handle);
    if (!sameFile(stat, after) || !timingSafeEqual(digest, afterDigest)) {
      fail('native recovery binary changed during execution');
    }
    if (code !== 0) {
      const detail = stderr.toString('utf8').trim();
      fail(
        `native recovery exited unsuccessfully (${signal ?? code})${
          detail === '' ? '' : `: ${detail}`
        }`,
      );
    }
    if (stderr.length !== 0) {
      fail('native recovery emitted stderr on a successful execution');
    }
    try {
      const parsed = JSON.parse(stdout.toString('utf8'));
      if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
        fail('native recovery output must be a JSON object');
      }
      return parsed;
    } catch (error) {
      if (error instanceof NativeRecoveryError) throw error;
      fail('native recovery output is not one complete JSON value', {
        cause: error,
      });
    }
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Execute the exact SHA-256-pinned native scanner through an inherited file
 * descriptor. No shell, PATH lookup, symlink target, or post-hash pathname
 * re-open participates in execution.
 */
export async function runNativeRecovery(options) {
  const normalized = validateOptions(options);
  let requestBytes;
  try {
    const serialized = JSON.stringify(normalized.request);
    if (serialized === undefined) {
      fail('request JSON serialization returned undefined');
    }
    requestBytes = Buffer.from(`${serialized}\n`, 'utf8');
  } catch (error) {
    fail('request is not deterministically JSON-serializable', { cause: error });
  }
  const opened = await openPinnedBinary(
    normalized.binaryPath,
    normalized.binarySha256,
  );
  try {
    return await executeOpened({ ...opened, ...normalized, requestBytes });
  } finally {
    await opened.handle.close();
  }
}

export function scanNativeRecovery(options) {
  return runNativeRecovery({ ...options, command: 'scan' });
}

export function authenticateNativeRecoverySnapshot(options) {
  return runNativeRecovery({ ...options, command: 'authenticate-snapshot' });
}

export function verifyNativeRecoverySnapshot(options) {
  return runNativeRecovery({ ...options, command: 'verify-snapshot' });
}

function validateStreamOptions(value) {
  const input = exactObject(value, [
    'binaryPath',
    'binarySha256',
    'requestHeader',
    'actionCount',
    'steps',
    ...(Object.hasOwn(value ?? {}, 'timeoutMs') ? ['timeoutMs'] : []),
  ], 'native recovery stream options');
  if (typeof input.binaryPath !== 'string' || !isAbsolute(input.binaryPath)) {
    fail('binaryPath must be an absolute path');
  }
  if (
    typeof input.binarySha256 !== 'string'
    || !SHA256_HEX.test(input.binarySha256)
  ) {
    fail('binarySha256 must be exactly 32 lowercase hexadecimal bytes');
  }
  exactObject(input.requestHeader, [
    'networkId',
    'profileId',
    'instanceId',
    'denominationSats',
    'carrierCount',
    'runtimeMaterialsSha256',
    'genesis',
    'genesisOutpoint',
    'initialStateHex',
    'expectedTip',
  ], 'native recovery stream requestHeader');
  hexBytes(
    input.requestHeader.runtimeMaterialsSha256,
    32,
    'native recovery stream requestHeader.runtimeMaterialsSha256',
  );
  const actionCount = safeInteger(
    input.actionCount,
    0,
    MAX_STREAM_ACTIONS,
    'native recovery stream actionCount',
  );
  const iterable = input.steps?.[Symbol.asyncIterator]
    ?? input.steps?.[Symbol.iterator];
  if (typeof iterable !== 'function') {
    fail('native recovery stream steps must be an iterable or async iterable');
  }
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  safeInteger(
    timeoutMs,
    1,
    MAX_TIMEOUT_MS,
    'native recovery stream timeoutMs',
  );
  return { ...input, actionCount, timeoutMs };
}

function validateAuthenticateStreamOptions(value) {
  const input = exactObject(value, [
    'binaryPath',
    'binarySha256',
    'requestHeader',
    'actionCount',
    'actions',
    ...(Object.hasOwn(value ?? {}, 'timeoutMs') ? ['timeoutMs'] : []),
  ], 'native recovery authenticate snapshot stream options');
  if (typeof input.binaryPath !== 'string' || !isAbsolute(input.binaryPath)) {
    fail('binaryPath must be an absolute path');
  }
  if (
    typeof input.binarySha256 !== 'string'
    || !SHA256_HEX.test(input.binarySha256)
  ) {
    fail('binarySha256 must be exactly 32 lowercase hexadecimal bytes');
  }
  const requestHeader = exactObject(input.requestHeader, [
    'networkId',
    'profileId',
    'instanceId',
    'denominationSats',
    'carrierCount',
    'runtimeMaterialsSha256',
    'genesis',
    'tip',
    'snapshot',
  ], 'native recovery authenticate snapshot stream requestHeader');
  const snapshot = validateCompactSnapshot(requestHeader.snapshot);
  hexBytes(
    requestHeader.runtimeMaterialsSha256,
    32,
    'native recovery authenticate snapshot stream requestHeader.runtimeMaterialsSha256',
  );
  if (
    requestHeader.runtimeMaterialsSha256
    !== snapshot.runtimeMaterialsSha256
  ) {
    fail(
      'native recovery authenticate snapshot stream requestHeader.runtimeMaterialsSha256 differs from snapshot.runtimeMaterialsSha256',
    );
  }
  const actionCount = safeInteger(
    input.actionCount,
    0,
    MAX_STREAM_ACTIONS,
    'native recovery authenticate snapshot stream actionCount',
  );
  if (
    canonicalCount(
      snapshot.actionCount,
      MAX_STREAM_ACTIONS,
      'native recovery authenticate snapshot stream snapshot.actionCount',
    ) !== actionCount
  ) {
    fail(
      'native recovery authenticate snapshot stream actionCount differs from its compact snapshot',
    );
  }
  const iterable = input.actions?.[Symbol.asyncIterator]
    ?? input.actions?.[Symbol.iterator];
  if (typeof iterable !== 'function') {
    fail(
      'native recovery authenticate snapshot stream actions must be an iterable or async iterable',
    );
  }
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  safeInteger(
    timeoutMs,
    1,
    MAX_TIMEOUT_MS,
    'native recovery authenticate snapshot stream timeoutMs',
  );
  return { ...input, requestHeader, actionCount, timeoutMs };
}

function encodeStreamFrame(value, label) {
  let payload;
  try {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) {
      fail(`${label} JSON serialization returned undefined`);
    }
    payload = Buffer.from(encoded, 'utf8');
  } catch (error) {
    if (error instanceof NativeRecoveryError) throw error;
    fail(`${label} is not deterministically JSON-serializable`, {
      cause: error,
    });
  }
  if (
    payload.length === 0
    || payload.length > MAX_STREAM_FRAME_BYTES
  ) {
    fail(
      `${label} length must be from 1 to ${MAX_STREAM_FRAME_BYTES} bytes`,
    );
  }
  const frame = Buffer.allocUnsafe(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function writeBytes(stream, bytes, label) {
  return new Promise((resolveWrite, rejectWrite) => {
    stream.write(bytes, (error) => {
      if (error) {
        rejectWrite(new NativeRecoveryError(`cannot write ${label}`, {
          cause: error,
        }));
      } else {
        resolveWrite();
      }
    });
  });
}

function abortable(promise, signal, label) {
  return new Promise((resolveAbortable, rejectAbortable) => {
    const aborted = () => {
      rejectAbortable(new NativeRecoveryError(`${label} was aborted`));
    };
    if (signal.aborted) {
      aborted();
    } else {
      signal.addEventListener('abort', aborted, { once: true });
    }
    Promise.resolve(promise).then(
      (value) => {
        signal.removeEventListener('abort', aborted);
        resolveAbortable(value);
      },
      (error) => {
        signal.removeEventListener('abort', aborted);
        rejectAbortable(error);
      },
    );
  });
}

async function writeStreamInput(stream, options, signal) {
  const iterator = options.steps[Symbol.asyncIterator]?.()
    ?? options.steps[Symbol.iterator]();
  const digest = createHash('sha256').update(STREAM_INPUT_DOMAIN);
  try {
    await writeBytes(stream, STREAM_MAGIC, 'native recovery stream magic');
    const header = encodeStreamFrame({
      schema: STREAM_INPUT_SCHEMA,
      type: 'header',
      actionCount: String(options.actionCount),
      request: options.requestHeader,
    }, 'native recovery stream header');
    digest.update(header);
    await writeBytes(stream, header, 'native recovery stream header');
    for (let index = 0; index < options.actionCount; index += 1) {
      const next = await abortable(
        iterator.next(),
        signal,
        `native recovery stream step ${index}`,
      );
      if (next.done) {
        fail(
          `native recovery stream steps ended at ${index}; expected ${options.actionCount}`,
        );
      }
      const step = exactObject(
        next.value,
        ['action', 'fundingPrevout'],
        `native recovery stream step ${index}`,
      );
      const frame = encodeStreamFrame({
        schema: STREAM_INPUT_SCHEMA,
        type: 'action',
        index: String(index),
        action: step.action,
        fundingPrevout: step.fundingPrevout,
      }, `native recovery stream action ${index}`);
      digest.update(frame);
      await writeBytes(
        stream,
        frame,
        `native recovery stream action ${index}`,
      );
    }
    const extra = await abortable(
      iterator.next(),
      signal,
      'native recovery stream terminal step check',
    );
    if (!extra.done) {
      fail(
        `native recovery stream steps exceed declared actionCount ${options.actionCount}`,
      );
    }
    const end = encodeStreamFrame({
      schema: STREAM_INPUT_SCHEMA,
      type: 'end',
      actionCount: String(options.actionCount),
      frameCount: String(options.actionCount + 1),
      digest: digest.digest('hex'),
    }, 'native recovery stream end');
    await writeBytes(stream, end, 'native recovery stream end');
    await new Promise((resolveEnd, rejectEnd) => {
      stream.end((error) => {
        if (error) {
          rejectEnd(new NativeRecoveryError(
            'cannot finish native recovery stream input',
            { cause: error },
          ));
        } else {
          resolveEnd();
        }
      });
    });
  } finally {
    const returned = iterator.return?.();
    if (returned !== undefined) {
      await abortable(
        returned,
        signal,
        'native recovery stream iterator cleanup',
      ).catch(() => {});
    }
  }
}

async function writeAuthenticateSnapshotStreamInput(stream, options, signal) {
  const iterator = options.actions[Symbol.asyncIterator]?.()
    ?? options.actions[Symbol.iterator]();
  const digest = createHash('sha256').update(
    AUTHENTICATE_STREAM_INPUT_DOMAIN,
  );
  try {
    await writeBytes(
      stream,
      STREAM_MAGIC,
      'native recovery authenticate snapshot stream magic',
    );
    const header = encodeStreamFrame({
      schema: AUTHENTICATE_STREAM_INPUT_SCHEMA,
      type: 'header',
      actionCount: String(options.actionCount),
      request: options.requestHeader,
    }, 'native recovery authenticate snapshot stream header');
    digest.update(header);
    await writeBytes(
      stream,
      header,
      'native recovery authenticate snapshot stream header',
    );
    for (let index = 0; index < options.actionCount; index += 1) {
      const next = await abortable(
        iterator.next(),
        signal,
        `native recovery authenticate snapshot stream action ${index}`,
      );
      if (next.done) {
        fail(
          `native recovery authenticate snapshot stream actions ended at ${index}; expected ${options.actionCount}`,
        );
      }
      convertActionSnapshot(
        next.value,
        `native recovery authenticate snapshot stream action ${index}`,
      );
      const frame = encodeStreamFrame({
        schema: AUTHENTICATE_STREAM_INPUT_SCHEMA,
        type: 'action',
        index: String(index),
        action: next.value,
      }, `native recovery authenticate snapshot stream action ${index}`);
      digest.update(frame);
      await writeBytes(
        stream,
        frame,
        `native recovery authenticate snapshot stream action ${index}`,
      );
    }
    const extra = await abortable(
      iterator.next(),
      signal,
      'native recovery authenticate snapshot stream terminal action check',
    );
    if (!extra.done) {
      fail(
        `native recovery authenticate snapshot stream actions exceed declared actionCount ${options.actionCount}`,
      );
    }
    const end = encodeStreamFrame({
      schema: AUTHENTICATE_STREAM_INPUT_SCHEMA,
      type: 'end',
      actionCount: String(options.actionCount),
      frameCount: String(options.actionCount + 1),
      digest: digest.digest('hex'),
    }, 'native recovery authenticate snapshot stream end');
    await writeBytes(
      stream,
      end,
      'native recovery authenticate snapshot stream end',
    );
    await new Promise((resolveEnd, rejectEnd) => {
      stream.end((error) => {
        if (error) {
          rejectEnd(new NativeRecoveryError(
            'cannot finish native recovery authenticate snapshot stream input',
            { cause: error },
          ));
        } else {
          resolveEnd();
        }
      });
    });
  } finally {
    const returned = iterator.return?.();
    if (returned !== undefined) {
      await abortable(
        returned,
        signal,
        'native recovery authenticate snapshot stream iterator cleanup',
      ).catch(() => {});
    }
  }
}

async function* decodeFramedStream(stream) {
  let magicOffset = 0;
  const lengthBytes = Buffer.alloc(4);
  let lengthOffset = 0;
  let payload = null;
  let payloadOffset = 0;
  for await (const original of stream) {
    const chunk = Buffer.isBuffer(original) ? original : Buffer.from(original);
    let offset = 0;
    while (offset < chunk.length) {
      if (magicOffset < STREAM_MAGIC.length) {
        const take = Math.min(
          STREAM_MAGIC.length - magicOffset,
          chunk.length - offset,
        );
        if (!chunk.subarray(offset, offset + take).equals(
          STREAM_MAGIC.subarray(magicOffset, magicOffset + take),
        )) {
          fail('native recovery stream magic or framing version is unsupported');
        }
        magicOffset += take;
        offset += take;
        continue;
      }
      if (payload === null) {
        const take = Math.min(4 - lengthOffset, chunk.length - offset);
        chunk.copy(lengthBytes, lengthOffset, offset, offset + take);
        lengthOffset += take;
        offset += take;
        if (lengthOffset !== 4) continue;
        const length = lengthBytes.readUInt32BE(0);
        if (length === 0 || length > MAX_STREAM_FRAME_BYTES) {
          fail(
            `native recovery output frame length must be from 1 to ${MAX_STREAM_FRAME_BYTES} bytes`,
          );
        }
        payload = Buffer.allocUnsafe(length);
        payloadOffset = 0;
        lengthOffset = 0;
        continue;
      }
      const take = Math.min(
        payload.length - payloadOffset,
        chunk.length - offset,
      );
      chunk.copy(payload, payloadOffset, offset, offset + take);
      payloadOffset += take;
      offset += take;
      if (payloadOffset === payload.length) {
        const complete = payload;
        payload = null;
        payloadOffset = 0;
        yield complete;
      }
    }
  }
  if (
    magicOffset !== STREAM_MAGIC.length
    || lengthOffset !== 0
    || payload !== null
  ) {
    fail('native recovery output stream is truncated');
  }
}

function boundedCollect(stream, maximum, label, child) {
  return new Promise((resolveCollect, rejectCollect) => {
    const chunks = [];
    let length = 0;
    stream.on('data', (chunk) => {
      length += chunk.length;
      if (length > maximum) {
        child.kill('SIGKILL');
        rejectCollect(new NativeRecoveryError(
          `native recovery ${label} exceeds ${maximum} bytes`,
        ));
        return;
      }
      chunks.push(chunk);
    });
    stream.once('error', (error) => rejectCollect(new NativeRecoveryError(
      `cannot read native recovery ${label}`,
      { cause: error },
    )));
    stream.once('end', () => resolveCollect(Buffer.concat(chunks, length)));
  });
}

function parseStreamJson(payload) {
  try {
    const parsed = JSON.parse(payload.toString('utf8'));
    if (
      parsed === null
      || Array.isArray(parsed)
      || typeof parsed !== 'object'
    ) {
      fail('native recovery output frame must be a JSON object');
    }
    return parsed;
  } catch (error) {
    if (error instanceof NativeRecoveryError) throw error;
    fail('native recovery output frame is not one complete JSON object', {
      cause: error,
    });
  }
}

function streamCounts(value, label) {
  return Object.freeze({
    action: canonicalCount(
      value.actionCount,
      MAX_STREAM_ACTIONS,
      `${label}.actionCount`,
    ),
    noteNode: canonicalCount(
      value.noteNodeCount,
      MAX_STREAM_OUTPUT_RECORDS,
      `${label}.noteNodeCount`,
    ),
    noteFrontier: canonicalCount(
      value.noteFrontierCount,
      32,
      `${label}.noteFrontierCount`,
    ),
    noteLeaf: canonicalCount(
      value.noteLeafCount,
      MAX_U32,
      `${label}.noteLeafCount`,
    ),
    nullifierNode: canonicalCount(
      value.nullifierNodeCount,
      MAX_STREAM_OUTPUT_RECORDS,
      `${label}.nullifierNodeCount`,
    ),
    nullifierLeaf: canonicalCount(
      value.nullifierLeafCount,
      MAX_STREAM_OUTPUT_RECORDS,
      `${label}.nullifierLeafCount`,
    ),
  });
}

function sameCounts(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function streamState() {
  return {
    phase: 'header',
    counts: null,
    positions: {
      action: 0,
      noteNode: 0,
      noteFrontier: 0,
      noteLeaf: 0,
      nullifierNode: 0,
      nullifierLeaf: 0,
    },
    snapshot: null,
    material: null,
    lastNode: {
      noteNode: null,
      nullifierNode: null,
    },
    frameCount: 0,
  };
}

const STREAM_PHASES = Object.freeze([
  ['action', 'action', convertActionSnapshot],
  ['note-node', 'noteNode', convertTreeNode],
  ['note-frontier', 'noteFrontier', convertFrontier],
  ['note-leaf', 'noteLeaf', convertNoteLeaf],
  ['nullifier-node', 'nullifierNode', convertTreeNode],
  ['nullifier-leaf', 'nullifierLeaf', convertNullifierLeaf],
]);

function nextStreamPhase(state) {
  while (state.phase !== 'end') {
    const index = STREAM_PHASES.findIndex(([type]) => type === state.phase);
    if (index === -1) return;
    const [, countKey] = STREAM_PHASES[index];
    if (state.positions[countKey] < state.counts[countKey]) return;
    state.phase = STREAM_PHASES[index + 1]?.[0] ?? 'end';
  }
}

function validateOutputHeader(value, state) {
  const input = exactObject(value, [
    'schema',
    'type',
    'actionCount',
    'noteNodeCount',
    'noteFrontierCount',
    'noteLeafCount',
    'nullifierNodeCount',
    'nullifierLeafCount',
  ], 'native recovery stream output header');
  if (
    input.schema !== STREAM_OUTPUT_SCHEMA
    || input.type !== 'header'
  ) {
    fail('native recovery stream output header schema or type is unsupported');
  }
  state.counts = streamCounts(input, 'native recovery stream output header');
  state.phase = 'snapshot';
  state.frameCount += 1;
  return Object.freeze({
    type: 'header',
    counts: state.counts,
  });
}

function validateOutputSnapshot(value, state) {
  const input = exactObject(value, [
    'schema',
    'type',
    'snapshot',
    'material',
  ], 'native recovery stream snapshot frame');
  if (
    input.schema !== STREAM_OUTPUT_SCHEMA
    || input.type !== 'snapshot'
  ) {
    fail('native recovery stream snapshot frame schema or type is unsupported');
  }
  const snapshot = validateCompactSnapshot(input.snapshot);
  const material = exactObject(input.material, [
    'schema',
    'contentSha256',
    'binding',
    'canonical',
  ], 'native recovery stream material header');
  if (material.schema !== AUTHENTICATED_MATERIAL_SCHEMA) {
    fail('native recovery stream material schema is unsupported');
  }
  hexBytes(
    material.contentSha256,
    32,
    'native recovery stream material.contentSha256',
  );
  if (material.contentSha256 !== snapshot.contentSha256) {
    fail('native recovery stream snapshot and material content hashes differ');
  }
  const binding = convertBinding(material.binding);
  const canonical = convertCanonical(material.canonical);
  if (
    state.counts.action
      !== canonicalCount(
        snapshot.actionCount,
        MAX_STREAM_ACTIONS,
        'native recovery stream snapshot.actionCount',
      )
    || state.counts.noteLeaf
      !== canonicalCount(
        snapshot.noteTree.count,
        MAX_U32,
        'native recovery stream snapshot.noteTree.count',
      )
    || state.counts.nullifierLeaf
      !== canonicalCount(
        snapshot.nullifierTree.count,
        MAX_U32,
        'native recovery stream snapshot.nullifierTree.count',
      ) + 2
  ) {
    fail('native recovery stream output counts differ from its snapshot');
  }
  if (
    !binding.profileId.equals(Buffer.from(snapshot.profileId, 'hex'))
    || !binding.instanceId.equals(Buffer.from(snapshot.instanceId, 'hex'))
    || binding.networkId !== snapshot.networkId
    || binding.denominationSats !== snapshot.denominationSats
    || binding.carrierCount !== snapshot.carrierCount
    || !binding.runtimeMaterialsSha256.equals(
      Buffer.from(snapshot.runtimeMaterialsSha256, 'hex'),
    )
    || !canonical.state.equals(Buffer.from(snapshot.stateHex, 'hex'))
    || !canonical.outpoint.txid.equals(
      Buffer.from(snapshot.tip.transactionId, 'hex'),
    )
    || canonical.outpoint.vout !== snapshot.tip.outputIndex
    || canonical.height !== snapshot.tip.height
    || !canonical.blockHash.equals(Buffer.from(snapshot.tip.blockHash, 'hex'))
  ) {
    fail('native recovery stream material header differs from its snapshot');
  }
  state.snapshot = snapshot;
  state.material = Object.freeze({
    schema: material.schema,
    contentSha256: material.contentSha256,
    binding,
    canonical,
  });
  state.phase = STREAM_PHASES[0][0];
  nextStreamPhase(state);
  state.frameCount += 1;
  return Object.freeze({
    type: 'snapshot',
    snapshot,
    material: state.material,
  });
}

function validateRecordOrder(type, countKey, converted, state) {
  if (countKey === 'noteNode' || countKey === 'nullifierNode') {
    const previous = state.lastNode[countKey];
    if (
      previous !== null
      && (
        converted.depth < previous.depth
        || (
          converted.depth === previous.depth
          && converted.nodeIndex <= previous.nodeIndex
        )
      )
    ) {
      fail(`native recovery stream ${type} records are not strictly ordered`);
    }
    state.lastNode[countKey] = converted;
  } else if (
    countKey === 'noteFrontier'
    && state.positions[countKey] > 0
    && converted.depth <= state.lastFrontierDepth
  ) {
    fail('native recovery stream note-frontier records are not ordered');
  } else if (
    countKey === 'noteLeaf'
    && converted.noteIndex !== state.positions[countKey]
  ) {
    fail('native recovery stream note-leaf indices are not contiguous');
  } else if (
    countKey === 'nullifierLeaf'
    && converted.physicalIndex !== state.positions[countKey]
  ) {
    fail('native recovery stream nullifier-leaf indices are not contiguous');
  }
  if (countKey === 'noteFrontier') {
    state.lastFrontierDepth = converted.depth;
  }
}

function validateOutputRecord(value, state) {
  nextStreamPhase(state);
  if (state.phase === 'end') {
    fail('native recovery stream has more records than declared');
  }
  const [expectedType, countKey, converter] = STREAM_PHASES.find(
    ([type]) => type === state.phase,
  );
  const input = exactObject(value, [
    'schema',
    'type',
    'index',
    'value',
  ], `native recovery stream ${expectedType} frame`);
  if (
    input.schema !== STREAM_OUTPUT_SCHEMA
    || input.type !== expectedType
  ) {
    fail(
      `native recovery stream expected ${expectedType} frame, received ${String(input.type)}`,
    );
  }
  const index = canonicalCount(
    input.index,
    state.counts[countKey],
    `native recovery stream ${expectedType} index`,
  );
  if (index !== state.positions[countKey]) {
    fail(
      `native recovery stream ${expectedType} index ${index} is reordered or duplicated`,
    );
  }
  const converted = converter(
    input.value,
    `native recovery stream ${expectedType}[${index}]`,
  );
  validateRecordOrder(expectedType, countKey, converted, state);
  state.positions[countKey] += 1;
  state.frameCount += 1;
  nextStreamPhase(state);
  return Object.freeze({
    type: expectedType,
    index,
    value: converted,
  });
}

function validateOutputEnd(value, state, digestHex) {
  nextStreamPhase(state);
  if (state.phase !== 'end') {
    fail(`native recovery stream ended before all ${state.phase} records`);
  }
  const input = exactObject(value, [
    'schema',
    'type',
    'actionCount',
    'noteNodeCount',
    'noteFrontierCount',
    'noteLeafCount',
    'nullifierNodeCount',
    'nullifierLeafCount',
    'frameCount',
    'digest',
  ], 'native recovery stream end frame');
  if (
    input.schema !== STREAM_OUTPUT_SCHEMA
    || input.type !== 'end'
  ) {
    fail('native recovery stream end frame schema or type is unsupported');
  }
  const counts = streamCounts(input, 'native recovery stream end frame');
  if (!sameCounts(counts, state.counts)) {
    fail('native recovery stream end counts differ from its header');
  }
  const frameCount = canonicalCount(
    input.frameCount,
    Number.MAX_SAFE_INTEGER,
    'native recovery stream end frameCount',
  );
  if (frameCount !== state.frameCount) {
    fail('native recovery stream end frameCount differs from consumed frames');
  }
  if (typeof input.digest !== 'string' || !SHA256_HEX.test(input.digest)) {
    fail(
      'native recovery stream end digest must be exactly 32 lowercase hexadecimal bytes',
    );
  }
  if (!timingSafeEqual(
    Buffer.from(input.digest, 'hex'),
    Buffer.from(digestHex, 'hex'),
  )) {
    fail('native recovery stream output transcript digest differs');
  }
  const noteRoot = state.lastNode.noteNode;
  const nullifierRoot = state.lastNode.nullifierNode;
  if (
    noteRoot?.depth !== 32
    || noteRoot.nodeIndex !== 0
    || !noteRoot.nodeHash.equals(
      Buffer.from(state.snapshot.noteTree.root, 'hex'),
    )
    || nullifierRoot?.depth !== 32
    || nullifierRoot.nodeIndex !== 0
    || !nullifierRoot.nodeHash.equals(
      Buffer.from(state.snapshot.nullifierTree.root, 'hex'),
    )
  ) {
    fail('native recovery stream terminal root nodes differ from its snapshot');
  }
  return Object.freeze({
    type: 'end',
    counts,
    frameCount,
    digest: input.digest,
  });
}

/**
 * Execute the exact SHA-256-pinned scanner in bounded framed mode. Each yielded
 * data frame is strictly validated but remains provisional: callers must stage
 * rows and commit only after the yielded `end` frame. Breaking iteration,
 * timeout, nonzero exit, stderr, binary mutation, truncation, extra data, count
 * mismatch, or transcript mismatch closes the process without an `end` frame.
 */
async function* executeNativeRecoveryStream({
  normalized,
  command,
  writeInput,
}) {
  const opened = await openPinnedBinary(
    normalized.binaryPath,
    normalized.binarySha256,
  );
  if (process.platform !== 'linux') {
    await opened.handle.close();
    fail(
      'descriptor-pinned native recovery execution currently requires Linux /proc',
    );
  }
  const executableFd = 3;
  const child = spawn(`/proc/self/fd/${executableFd}`, [command], {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe', opened.handle.fd],
    windowsHide: true,
  });
  const exitPromise = new Promise((resolveExit, rejectExit) => {
    child.once('error', (error) => rejectExit(new NativeRecoveryError(
      'cannot execute descriptor-pinned native recovery binary',
      { cause: error },
    )));
    child.once('close', (code, signal) => resolveExit({ code, signal }));
  });
  const stderrPromise = boundedCollect(
    child.stderr,
    MAX_STREAM_STDERR_BYTES,
    'stream stderr',
    child,
  );
  const inputAbort = new AbortController();
  const inputPromise = writeInput(
    child.stdin,
    normalized,
    inputAbort.signal,
  );
  let inputFailure = null;
  inputPromise.catch((error) => {
    inputFailure = error;
    child.kill('SIGKILL');
  });
  stderrPromise.catch(() => child.kill('SIGKILL'));
  const timeout = setTimeout(() => child.kill('SIGKILL'), normalized.timeoutMs);
  timeout.unref();
  let terminal = null;
  let sawEnd = false;
  const state = streamState();
  const digest = createHash('sha256').update(STREAM_OUTPUT_DOMAIN);
  try {
    for await (const payload of decodeFramedStream(child.stdout)) {
      const parsed = parseStreamJson(payload);
      if (sawEnd) {
        fail('native recovery output has trailing frames after its end frame');
      }
      if (parsed.type === 'end') {
        terminal = validateOutputEnd(parsed, state, digest.digest('hex'));
        sawEnd = true;
        continue;
      }
      const framed = Buffer.allocUnsafe(4 + payload.length);
      framed.writeUInt32BE(payload.length, 0);
      payload.copy(framed, 4);
      digest.update(framed);
      let converted;
      if (state.phase === 'header') {
        converted = validateOutputHeader(parsed, state);
      } else if (state.phase === 'snapshot') {
        converted = validateOutputSnapshot(parsed, state);
      } else {
        converted = validateOutputRecord(parsed, state);
      }
      yield converted;
    }
    const [{ code, signal }, stderr] = await Promise.all([
      exitPromise,
      stderrPromise,
      inputPromise,
    ]);
    const after = await opened.handle.stat({ bigint: true });
    const afterDigest = await digestHandle(opened.handle);
    if (
      !sameFile(opened.stat, after)
      || !timingSafeEqual(opened.digest, afterDigest)
    ) {
      fail('native recovery binary changed during execution');
    }
    if (code !== 0) {
      const detail = stderr.toString('utf8').trim();
      fail(
        `native recovery exited unsuccessfully (${signal ?? code})${
          detail === '' ? '' : `: ${detail}`
        }`,
      );
    }
    if (stderr.length !== 0) {
      fail('native recovery emitted stderr on a successful execution');
    }
    if (!sawEnd || terminal === null) {
      fail('native recovery output stream is missing its end frame');
    }
    yield terminal;
  } catch (error) {
    if (inputFailure !== null) throw inputFailure;
    throw error;
  } finally {
    clearTimeout(timeout);
    inputAbort.abort();
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
    }
    await Promise.allSettled([exitPromise, stderrPromise, inputPromise]);
    await opened.handle.close();
  }
}

export async function* runNativeRecoveryStream(options) {
  const normalized = validateStreamOptions(options);
  yield* executeNativeRecoveryStream({
    normalized,
    command: 'scan-stream',
    writeInput: writeStreamInput,
  });
}

export function scanNativeRecoveryStream(options) {
  return runNativeRecoveryStream(options);
}

/**
 * Authenticate a compact snapshot stream against independently authenticated
 * profile/genesis/tip bindings. `actions` is an iterable of raw snapshot action
 * records, not raw BCH transactions. This is a separate wire schema and native
 * command from raw `scanNativeRecoveryStream`.
 */
export async function* authenticateNativeRecoverySnapshotStream(options) {
  const normalized = validateAuthenticateStreamOptions(options);
  yield* executeNativeRecoveryStream({
    normalized,
    command: 'authenticate-snapshot-stream',
    writeInput: writeAuthenticateSnapshotStreamInput,
  });
}
