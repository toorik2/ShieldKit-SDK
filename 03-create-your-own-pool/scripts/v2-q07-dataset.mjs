/*
 * Q-07's single-history key stream is deliberately separate from Q-04's
 * four-history campaign. It is a deterministic input dataset for later
 * published-machine measurements, not performance qualification by itself.
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fsyncSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import { parseStrictJson } from '../packages/profile/load.mjs';

export const V2_Q07_DATASET_SCHEMA =
  'shieldkit-v2-direct/q07-single-history-key-stream/v1';
export const V2_Q07_MAIN_HISTORY_COUNT = 100_000;
export const V2_Q07_WARM_SAMPLE_ORDINAL = V2_Q07_MAIN_HISTORY_COUNT + 1;
export const V2_Q07_TOTAL_KEY_COUNT = V2_Q07_WARM_SAMPLE_ORDINAL;
export const V2_Q07_BN254_FR_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
export const V2_Q07_DATASET_FILENAME = 'q07-single-history-keys.ndjson';

const KEY_DOMAIN = 'ShieldKit/PoolActionV2Direct/Q07/single-history-key/v1\0';
const TRANSCRIPT_DOMAIN =
  'ShieldKit/PoolActionV2Direct/Q07/single-history-key-transcript/v1\0';
const HEX_64 = /^[0-9a-f]{64}$/u;
const MAX_NDJSON_LINE_BYTES = 1024;
const READ_CHUNK_BYTES = 64 * 1024;

export class V2Q07DatasetError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q07DatasetError';
  }
}

const fail = (message) => { throw new V2Q07DatasetError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function exactKeys(value, keys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
}

function canonicalAbsolutePath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || resolve(value) !== value) {
    fail(`${label} must be an absolute normalized path`);
  }
  return value;
}

function uint64be(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${label} must be a non-negative safe integer`);
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function uint32be(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail(`${label} must be a uint32`);
  }
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function frHex(value) {
  if (typeof value !== 'bigint' || value < 0n || value >= V2_Q07_BN254_FR_MODULUS) {
    fail('Q-07 key must be a canonical BN254 Fr element');
  }
  return value.toString(16).padStart(64, '0');
}

function canonicalKeyHex(value, label) {
  if (typeof value !== 'string' || !HEX_64.test(value)) {
    fail(`${label} must be exactly 32 lowercase hexadecimal bytes`);
  }
  const parsed = BigInt(`0x${value}`);
  if (parsed >= V2_Q07_BN254_FR_MODULUS) fail(`${label} is not canonical BN254 Fr`);
  return value;
}

function resolveMainCount({ testOnlyMainCount = undefined } = {}) {
  if (testOnlyMainCount === undefined) return V2_Q07_MAIN_HISTORY_COUNT;
  if (
    !Number.isSafeInteger(testOnlyMainCount) ||
    testOnlyMainCount < 2 ||
    testOnlyMainCount >= V2_Q07_MAIN_HISTORY_COUNT
  ) {
    fail(`testOnlyMainCount must be an integer from 2 through ${V2_Q07_MAIN_HISTORY_COUNT - 1}`);
  }
  return testOnlyMainCount;
}

function qualifyingShape(mainCount) {
  return mainCount === V2_Q07_MAIN_HISTORY_COUNT;
}

function assertPrivateDirectory(path, { create = false } = {}) {
  if (create) mkdirSync(path, { recursive: true, mode: 0o700 });
  const observed = lstatSync(path);
  if (
    !observed.isDirectory() ||
    observed.isSymbolicLink() ||
    (observed.mode & 0o777) !== 0o700 ||
    (typeof process.getuid === 'function' && observed.uid !== process.getuid())
  ) fail(`Q-07 output directory must be a direct user-owned mode-0700 directory: ${path}`);
  if (realpathSync(path) !== path) fail(`Q-07 output directory is not canonical or traverses a symlink: ${path}`);
}

function assertDirectOutputPath(outputDirectory, filename) {
  canonicalAbsolutePath(outputDirectory, 'Q-07 output directory');
  if (typeof filename !== 'string' || basename(filename) !== filename || filename.length === 0) {
    fail('Q-07 output filename must be one direct filename');
  }
  const pathname = join(outputDirectory, filename);
  if (dirname(pathname) !== outputDirectory) fail('Q-07 output file escapes its directory');
  return pathname;
}

function assertSingleLinkFileDescriptor(descriptor, pathname, label) {
  const observed = fstatSync(descriptor);
  if (
    !observed.isFile() ||
    observed.nlink !== 1 ||
    (observed.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === 'function' && observed.uid !== process.getuid())
  ) fail(`${label} must be a single-link user-owned mode-0600 regular file`);
  const named = lstatSync(pathname);
  if (
    named.isSymbolicLink() ||
    named.dev !== observed.dev ||
    named.ino !== observed.ino ||
    named.nlink !== 1 ||
    realpathSync(pathname) !== pathname
  ) fail(`${label} path changed, is linked, or traverses a symlink`);
  return observed;
}

function writeFully(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(descriptor, bytes, offset, bytes.length - offset);
    if (written <= 0) fail('Q-07 dataset write made no progress');
    offset += written;
  }
}

function openReadOnlyNoFollow(pathname, label) {
  try {
    return openSync(pathname, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    fail(`${label} cannot be opened as a direct regular file: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function createQ07SingleHistoryKeyStream(options = {}) {
  const mainCount = resolveMainCount(options);
  const totalCount = mainCount + 1;
  const used = new Set();
  let ordinal = 0;
  return Object.freeze({
    mainCount,
    totalCount,
    next() {
      if (ordinal >= totalCount) return null;
      ordinal += 1;
      let key;
      if (ordinal === 1) key = 0n;
      else if (ordinal === 2) key = V2_Q07_BN254_FR_MODULUS - 1n;
      else {
        for (let attempt = 0; attempt <= 0xffffffff; attempt += 1) {
          const candidate = BigInt(`0x${createHash('sha256')
            .update(KEY_DOMAIN, 'ascii')
            .update(uint64be(ordinal, 'Q-07 key ordinal'))
            .update(uint32be(attempt, 'Q-07 key attempt'))
            .digest('hex')}`);
          if (candidate < V2_Q07_BN254_FR_MODULUS && !used.has(frHex(candidate))) {
            key = candidate;
            break;
          }
        }
        if (key === undefined) fail(`Q-07 rejection sampling exhausted at ordinal ${ordinal}`);
      }
      const keyHex = frHex(key);
      if (used.has(keyHex)) fail(`Q-07 deterministic key stream repeated a key at ordinal ${ordinal}`);
      used.add(keyHex);
      return Object.freeze({ ordinal, key: keyHex });
    },
  });
}

function updateTranscript(transcript, ordinal, key) {
  transcript.update(uint64be(ordinal, 'Q-07 transcript ordinal'));
  transcript.update(Buffer.from(key, 'hex'));
}

function datasetResult({ path, mainCount, count, sha256: fileSha256, transcriptSha256 }) {
  const isQualifyingShape = qualifyingShape(mainCount);
  return Object.freeze({
    schema: V2_Q07_DATASET_SCHEMA,
    ...(path === undefined ? {} : { path }),
    mainCount,
    count,
    warmSampleOrdinal: mainCount + 1,
    sha256: fileSha256,
    transcriptSha256,
    edgeEvidence: Object.freeze({
      zeroOrdinal: 1,
      zeroKey: frHex(0n),
      frMinusOneOrdinal: 2,
      frMinusOneKey: frHex(V2_Q07_BN254_FR_MODULUS - 1n),
    }),
    qualifyingShape: isQualifyingShape,
    qualification: isQualifyingShape
      ? 'dataset-shape-only-not-q07-performance-qualified'
      : 'test-only-nonqualifying',
  });
}

/** Stream the deterministic main history plus its one reserved warm-sample key. */
export function writeQ07SingleHistoryDataset({
  outputDirectory,
  filename = V2_Q07_DATASET_FILENAME,
  testOnlyMainCount = undefined,
} = {}) {
  const mainCount = resolveMainCount({ testOnlyMainCount });
  assertPrivateDirectory(canonicalAbsolutePath(outputDirectory, 'Q-07 output directory'), { create: true });
  const outputPath = assertDirectOutputPath(outputDirectory, filename);
  if (lstatSync(outputPath, { throwIfNoEntry: false }) !== undefined) {
    fail(`Q-07 refuses to overwrite an existing dataset: ${outputPath}`);
  }
  const temporaryPath = join(
    outputDirectory,
    `.${filename}.${randomBytes(16).toString('hex')}.tmp`,
  );
  const descriptor = openSync(
    temporaryPath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  let result;
  let published = false;
  try {
    const stream = createQ07SingleHistoryKeyStream({ testOnlyMainCount });
    const digest = createHash('sha256');
    const transcript = createHash('sha256').update(TRANSCRIPT_DOMAIN, 'ascii');
    let count = 0;
    for (let entry = stream.next(); entry !== null; entry = stream.next()) {
      const record = { schema: V2_Q07_DATASET_SCHEMA, ordinal: entry.ordinal, key: entry.key };
      const bytes = Buffer.from(`${JSON.stringify(record)}\n`, 'utf8');
      writeFully(descriptor, bytes);
      digest.update(bytes);
      updateTranscript(transcript, entry.ordinal, entry.key);
      count += 1;
    }
    fsyncSync(descriptor);
    assertSingleLinkFileDescriptor(descriptor, temporaryPath, 'Q-07 temporary dataset');
    result = datasetResult({
      path: outputPath,
      mainCount,
      count,
      sha256: digest.digest('hex'),
      transcriptSha256: transcript.digest('hex'),
    });
  } finally {
    closeSync(descriptor);
  }
  try {
    // link(2) is a no-replace publication primitive. The private parent keeps
    // the brief two-link interval inaccessible to other users, and unlinking
    // the staged name restores the required single-link invariant.
    linkSync(temporaryPath, outputPath);
    unlinkSync(temporaryPath);
    published = true;
    chmodSync(outputPath, 0o600);
    const publishedDescriptor = openReadOnlyNoFollow(outputPath, 'Q-07 published dataset');
    try {
      assertSingleLinkFileDescriptor(publishedDescriptor, outputPath, 'Q-07 published dataset');
    } finally {
      closeSync(publishedDescriptor);
    }
  } finally {
    if (!published && lstatSync(temporaryPath, { throwIfNoEntry: false }) !== undefined) {
      unlinkSync(temporaryPath);
    }
  }
  const directoryDescriptor = openSync(outputDirectory, constants.O_RDONLY);
  try {
    fsyncSync(directoryDescriptor);
  } finally {
    closeSync(directoryDescriptor);
  }
  return result;
}

function validateRecord(bytes, expected, lineNumber) {
  let record;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    record = parseStrictJson(bytes);
  } catch (error) {
    fail(`Q-07 dataset line ${lineNumber} is not strict UTF-8 JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  exactKeys(record, ['key', 'ordinal', 'schema'], `Q-07 dataset line ${lineNumber}`);
  if (record.schema !== V2_Q07_DATASET_SCHEMA) fail(`Q-07 dataset line ${lineNumber} schema differs`);
  if (!Number.isSafeInteger(record.ordinal) || record.ordinal !== expected.ordinal) {
    fail(`Q-07 dataset line ${lineNumber} ordinal is not the exact sequence`);
  }
  const key = canonicalKeyHex(record.key, `Q-07 dataset line ${lineNumber}.key`);
  if (key !== expected.key) fail(`Q-07 dataset line ${lineNumber} key differs from deterministic stream`);
  const canonical = JSON.stringify({ schema: record.schema, ordinal: record.ordinal, key });
  if (text !== canonical) fail(`Q-07 dataset line ${lineNumber} is not canonical NDJSON`);
  return key;
}

/**
 * Fail-closed streaming verifier. It retains only a bounded input buffer and
 * deterministic-stream state; it never reads the NDJSON file as one value.
 */
export function verifyQ07SingleHistoryDataset({
  path,
  testOnlyMainCount = undefined,
} = {}) {
  const mainCount = resolveMainCount({ testOnlyMainCount });
  const pathname = canonicalAbsolutePath(path, 'Q-07 dataset path');
  const descriptor = openReadOnlyNoFollow(pathname, 'Q-07 dataset');
  let initial;
  try {
    initial = assertSingleLinkFileDescriptor(descriptor, pathname, 'Q-07 dataset');
    const stream = createQ07SingleHistoryKeyStream({ testOnlyMainCount });
    const digest = createHash('sha256');
    const transcript = createHash('sha256').update(TRANSCRIPT_DOMAIN, 'ascii');
    const chunk = Buffer.alloc(READ_CHUNK_BYTES);
    let carry = Buffer.alloc(0);
    let lineNumber = 0;
    let count = 0;
    for (;;) {
      const read = readSync(descriptor, chunk, 0, chunk.length, null);
      if (read === 0) break;
      const combined = carry.length === 0 ? chunk.subarray(0, read) : Buffer.concat([carry, chunk.subarray(0, read)]);
      let start = 0;
      for (;;) {
        const ending = combined.indexOf(0x0a, start);
        if (ending === -1) break;
        const line = combined.subarray(start, ending);
        if (line.length === 0 || line.length > MAX_NDJSON_LINE_BYTES) {
          fail(`Q-07 dataset line ${lineNumber + 1} is empty or oversized`);
        }
        const expected = stream.next();
        if (expected === null) fail('Q-07 dataset contains an extra line');
        lineNumber += 1;
        const raw = combined.subarray(start, ending + 1);
        digest.update(raw);
        const key = validateRecord(line, expected, lineNumber);
        updateTranscript(transcript, expected.ordinal, key);
        count += 1;
        start = ending + 1;
      }
      carry = Buffer.from(combined.subarray(start));
      if (carry.length > MAX_NDJSON_LINE_BYTES) fail('Q-07 dataset has an oversized unterminated line');
    }
    if (carry.length !== 0) fail('Q-07 dataset must end with one newline per record');
    if (stream.next() !== null) fail('Q-07 dataset is truncated');
    const final = fstatSync(descriptor);
    if (
      final.dev !== initial.dev ||
      final.ino !== initial.ino ||
      final.size !== initial.size ||
      final.mtimeMs !== initial.mtimeMs ||
      final.ctimeMs !== initial.ctimeMs ||
      final.nlink !== 1
    ) fail('Q-07 dataset changed while being read');
    return datasetResult({
      path: pathname,
      mainCount,
      count,
      sha256: digest.digest('hex'),
      transcriptSha256: transcript.digest('hex'),
    });
  } finally {
    closeSync(descriptor);
  }
}
