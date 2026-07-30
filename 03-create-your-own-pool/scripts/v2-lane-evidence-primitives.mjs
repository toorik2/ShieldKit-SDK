/*
 * Shared, fail-closed primitives for replaying signed V2 lane evidence.
 *
 * Callers supply their policy-specific schemas, authority roots, and failure
 * type. This module intentionally supplies no trust root or qualification
 * decision of its own.
 */
import {
  constants as fsConstants,
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { createHash, verify as verifySignature } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';

const HASH = /^[0-9a-f]{64}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/**
 * Brand a caller-owned public context while retaining private authority
 * material in a closure. `get` is deliberately only available to the module
 * that created the brand; consumers can only present the opaque context.
 */
export function createV2LaneEvidenceContextBrand({ fail, label = 'lane evidence context' }) {
  const privateContexts = new WeakMap();
  return Object.freeze({
    create(publicContext, privateContext) {
      const context = Object.freeze({ ...publicContext });
      privateContexts.set(context, Object.freeze({ ...privateContext }));
      return context;
    },
    assert(context) {
      if (!privateContexts.has(context)) fail(`${label} is not a branded context`);
      return context;
    },
    get(context) {
      if (!privateContexts.has(context)) fail(`${label} is not a branded context`);
      return privateContexts.get(context);
    },
  });
}

/**
 * Construct shared evidence readers and lane validators. The caller-owned
 * `fail` function keeps policy errors in the caller's public error domain.
 */
export function createV2LaneEvidencePrimitives({
  canonicalizeJcs,
  fail,
  maximumClockSkewMs = 5 * 60 * 1000,
  maximumEvidenceFileBytes = 256 * 1024 * 1024,
  parseRawTransaction,
  parseSerializedSourceOutput,
  verifyBchTransactionMerkleProof,
  verifyRawHeaderSegment,
}) {
  const sha256 = (value) => createHash('sha256').update(value).digest('hex');
  const canonicalBytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
  const plain = (value, label) => {
    if (value === null || Array.isArray(value) || typeof value !== 'object'
      || Object.getPrototypeOf(value) !== Object.prototype) {
      fail(`${label} must be a plain object`);
    }
    return value;
  };
  const exact = (value, keys, label) => {
    plain(value, label);
    const actual = Object.keys(value).sort();
    const expected = [...keys].sort();
    if (actual.length !== expected.length
      || actual.some((entry, index) => entry !== expected[index])) {
      fail(`${label} has missing or unknown properties`);
    }
    return value;
  };
  const hash = (value, label) => {
    if (typeof value !== 'string' || !HASH.test(value)) {
      fail(`${label} must be 32 lowercase hexadecimal bytes`);
    }
    return value;
  };
  const integer = (value, low, high, label) => {
    if (!Number.isSafeInteger(value) || value < low || value > high) {
      fail(`${label} is outside its integer range`);
    }
    return value;
  };
  /** Optional caller-supplied closure count; undefined preserves legacy APIs. */
  const assertExactInputCount = (actual, expected, label) => {
    integer(actual, 1, 258, `${label} actual input count`);
    if (expected !== undefined) {
      integer(expected, 1, 258, `${label} expected input count`);
      if (actual !== expected) fail(`${label} differs from the exact expected closure`);
    }
    return actual;
  };
  const text = (value, label, maximum = 4096) => {
    if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
      fail(`${label} must be a bounded nonempty string`);
    }
    return value;
  };
  const canonicalTimestamp = (value, label) => {
    text(value, label, 64);
    const milliseconds = Date.parse(value);
    if (!Number.isSafeInteger(milliseconds) || new Date(milliseconds).toISOString() !== value) {
      fail(`${label} must be canonical ISO-8601 UTC with milliseconds`);
    }
    return milliseconds;
  };
  const sameFile = (before, after) => before.dev === after.dev
    && before.ino === after.ino && before.mode === after.mode
    && before.nlink === after.nlink && before.size === after.size
    && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;

  const readStableDirectFile = (filename, label, {
    allowEmpty = false,
    maximumBytes = maximumEvidenceFileBytes,
  } = {}) => {
    if (typeof filename !== 'string' || !isAbsolute(filename) || resolve(filename) !== filename) {
      fail(`${label} must be an absolute normalized path`);
    }
    const pathname = lstatSync(filename, { bigint: true, throwIfNoEntry: false });
    if (pathname === undefined || !pathname.isFile() || pathname.isSymbolicLink() || pathname.nlink !== 1n) {
      fail(`${label} must be a direct single-link regular file`);
    }
    if (realpathSync(filename) !== filename) fail(`${label} may not traverse a symlinked ancestor`);
    let descriptor;
    try {
      descriptor = openSync(filename, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
      const before = fstatSync(descriptor, { bigint: true });
      if (!before.isFile() || before.nlink !== 1n || (!allowEmpty && before.size === 0n)
        || before.size > BigInt(maximumBytes) || before.dev !== pathname.dev || before.ino !== pathname.ino) {
        fail(`${label} has unsafe type, link count, or byte size`);
      }
      const bytes = readFileSync(descriptor);
      const after = fstatSync(descriptor, { bigint: true });
      const finalPath = lstatSync(filename, { bigint: true, throwIfNoEntry: false });
      if (finalPath === undefined || !sameFile(before, after)
        || finalPath.dev !== after.dev || finalPath.ino !== after.ino) {
        fail(`${label} changed while it was read`);
      }
      return Buffer.from(bytes);
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
  };

  const relativeReference = (value, root, label, options = {}) => {
    exact(value, ['path', 'sha256'], label);
    hash(value.sha256, `${label}.sha256`);
    if (typeof value.path !== 'string' || value.path.length === 0 || isAbsolute(value.path)
      || value.path.split(/[\\/]/u).includes('..')) {
      fail(`${label}.path must be a safe relative path`);
    }
    const filename = resolve(root, value.path);
    if (!filename.startsWith(`${root}/`)) fail(`${label}.path escapes the envelope directory`);
    const bytes = readStableDirectFile(filename, label, options);
    if (sha256(bytes) !== value.sha256) fail(`${label} SHA-256 pin mismatch`);
    return Object.freeze({ bytes, filename, sha256: value.sha256 });
  };

  const jcsReference = (value, root, label) => {
    const artifact = relativeReference(value, root, label);
    let parsed;
    try { parsed = JSON.parse(artifact.bytes); } catch { fail(`${label} is not JSON`); }
    if (!artifact.bytes.equals(canonicalBytes(parsed))) fail(`${label} must contain exact RFC8785/JCS bytes`);
    return Object.freeze({ ...artifact, value: parsed });
  };

  const verifyEd25519AuthorityEnvelope = ({ authorityKey, attestationBytes, signature, label }) => {
    exact(signature, ['algorithm', 'signatureBase64'], label);
    let bytes;
    try { bytes = Buffer.from(signature.signatureBase64, 'base64'); } catch { fail(`${label} is not canonical base64`); }
    if (signature.algorithm !== 'ed25519' || bytes.length !== 64
      || bytes.toString('base64') !== signature.signatureBase64
      || !verifySignature(null, attestationBytes, authorityKey, bytes)) {
      fail(`${label} does not cover the complete envelope`);
    }
  };

  /**
   * Verify the common signed-envelope bindings without selecting a trust root.
   * The caller supplies its authoritative key/tool/command and validates the
   * policy-specific subject (for example, a Q-02 corpus case or Q-08 journey).
   */
  const verifySignedLaneEnvelope = ({
    attestationDomain,
    attestationVersion,
    authority,
    envelope,
    envelopeKeys,
    envelopeSchema,
    expectedAuthoritySetSha256,
    expectedDescriptor,
    subjectValidator,
    window,
  }) => {
    exact(envelope, envelopeKeys, 'lane envelope');
    if (envelope.schema !== envelopeSchema || envelope.authoritySetSha256 !== expectedAuthoritySetSha256) {
      fail('lane envelope schema or authority set is invalid');
    }
    if (!canonicalBytes(envelope.tool).equals(canonicalBytes(authority.tool))
      || !canonicalBytes(envelope.command).equals(canonicalBytes(authority.command))) {
      fail('lane envelope tool or command differs from its signed pin');
    }
    if (!canonicalBytes(envelope.descriptor).equals(canonicalBytes(expectedDescriptor))) {
      fail('lane envelope does not bind its expected descriptor');
    }
    subjectValidator(envelope);
    const startedAt = canonicalTimestamp(envelope.startedAt, 'lane startedAt');
    const completedAt = canonicalTimestamp(envelope.completedAt, 'lane completedAt');
    if (completedAt < startedAt || startedAt < window.notBefore || completedAt > window.notAfter) {
      fail('lane run is outside its signed evidence window');
    }
    verifyEd25519AuthorityEnvelope({
      authorityKey: authority.key,
      attestationBytes: canonicalBytes({
        domain: attestationDomain,
        envelope: { ...envelope, signature: null },
        version: attestationVersion,
      }),
      label: 'lane signature',
      signature: envelope.signature,
    });
    return Object.freeze({ completedAt, startedAt });
  };

  const transactionFromHex = (rawTransactionHex, expected, label) => {
    let transaction;
    try { transaction = parseRawTransaction(rawTransactionHex); } catch (error) {
      fail(`${label} raw transaction is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (sha256(transaction.bytes) !== expected.rawTransactionSha256 || transaction.txid !== expected.transactionId) {
      fail(`${label} does not bind the exact corpus transaction`);
    }
    return transaction;
  };
  const sourceOutputBytes = (value, label) => {
    if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(value)) {
      fail(`${label} must be nonempty lowercase even-length hex`);
    }
    try { parseSerializedSourceOutput(value); } catch (error) {
      fail(`${label} is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    return Buffer.from(value, 'hex');
  };

  const validateExternalPerInputLane = ({ stdin, stdout, context, expected, role, stdinSchema, stdoutSchema }) => {
    exact(stdin, ['rawTransactionHex', 'schema', 'sourceOutputs'], `${role} stdin`);
    if (stdin.schema !== stdinSchema || !Array.isArray(stdin.sourceOutputs)) fail(`${role} stdin schema or source outputs are invalid`);
    const transaction = transactionFromHex(stdin.rawTransactionHex, expected, `${role} stdin`);
    if (transaction.inputs.length !== context.topology.inputCount || stdin.sourceOutputs.length !== transaction.inputs.length) {
      fail(`${role} stdin does not contain every selected-topology input`);
    }
    const sourceHashes = stdin.sourceOutputs.map((entry, index) => sha256(sourceOutputBytes(entry, `${role} source output ${index}`)));
    exact(stdout, ['inputCount', 'inputs', 'rawTransactionSha256', 'schema', 'transactionId'], `${role} stdout`);
    if (stdout.schema !== stdoutSchema || stdout.inputCount !== transaction.inputs.length
      || stdout.rawTransactionSha256 !== expected.rawTransactionSha256 || stdout.transactionId !== expected.transactionId
      || !Array.isArray(stdout.inputs) || stdout.inputs.length !== transaction.inputs.length) {
      fail(`${role} stdout is incomplete or bound to another transaction`);
    }
    const seen = new Set();
    for (const row of stdout.inputs) {
      exact(row, ['accepted', 'error', 'hashDigestIterations', 'inputIndex', 'maximumHashDigestIterations',
        'maximumOperationCost', 'maximumSignatureCheckCount', 'operationCost', 'signatureCheckCount',
        'sourceOutputSha256', 'unlockingBytecodeSha256'], `${role} input result`);
      integer(row.inputIndex, 0, transaction.inputs.length - 1, `${role} inputIndex`);
      if (seen.has(row.inputIndex) || typeof row.accepted !== 'boolean') fail(`${role} input indices or acceptance values are invalid`);
      seen.add(row.inputIndex);
      const input = transaction.inputs[row.inputIndex];
      if (row.unlockingBytecodeSha256 !== sha256(input.unlockingBytecode) || row.sourceOutputSha256 !== sourceHashes[row.inputIndex]) {
        fail(`${role} input result is not bound to exact transaction bytes`);
      }
      for (const key of ['hashDigestIterations', 'maximumHashDigestIterations', 'maximumOperationCost',
        'maximumSignatureCheckCount', 'operationCost', 'signatureCheckCount']) {
        integer(row[key], 0, Number.MAX_SAFE_INTEGER, `${role} input result.${key}`);
      }
      if (row.operationCost > row.maximumOperationCost || row.hashDigestIterations > row.maximumHashDigestIterations
        || row.signatureCheckCount > row.maximumSignatureCheckCount) fail(`${role} input result exceeds its reported legal maximum`);
      if ((row.accepted && row.error !== null) || (!row.accepted && (typeof row.error !== 'string'
        || row.error.length === 0 || row.error.length > 16_384))) fail(`${role} input result has inconsistent error evidence`);
    }
    return stdout.inputs.every((row) => row.accepted);
  };

  const rpcEnvelope = (value, label) => {
    plain(value, label);
    const allowedKeys = new Set(['error', 'id', 'jsonrpc', 'result']);
    if (Object.keys(value).some((key) => !allowedKeys.has(key)) || !Object.hasOwn(value, 'id')
      || !Object.hasOwn(value, 'result') || !Object.hasOwn(value, 'error') || value.error !== null
      || (Object.hasOwn(value, 'jsonrpc') && !['1.0', '2.0'].includes(value.jsonrpc))) {
      fail(`${label} is not an exact successful BCHN JSON-RPC envelope`);
    }
    return value;
  };
  const validateBchnMempoolLane = ({ stdin, stdout, expected }) => {
    exact(stdin, ['id', 'jsonrpc', 'method', 'params'], 'BCHN mempool request');
    if (!['1.0', '2.0'].includes(stdin.jsonrpc) || stdin.method !== 'testmempoolaccept'
      || !Array.isArray(stdin.params) || stdin.params.length < 1 || stdin.params.length > 2
      || !Array.isArray(stdin.params[0]) || stdin.params[0].length !== 1
      || (stdin.params.length === 2 && stdin.params[1] !== false)) fail('BCHN testmempoolaccept request shape is invalid');
    const transaction = transactionFromHex(stdin.params[0][0], expected, 'BCHN mempool request');
    const response = rpcEnvelope(stdout, 'BCHN mempool response');
    if (response.id !== stdin.id || !Array.isArray(response.result) || response.result.length !== 1) {
      fail('BCHN mempool response does not match its exact request');
    }
    const row = plain(response.result[0], 'BCHN mempool result');
    if (row.txid !== transaction.txid || typeof row.allowed !== 'boolean') fail('BCHN mempool result lacks exact txid/allowed binding');
    if (row.allowed) {
      exact(row, ['allowed', 'fees', 'size', 'txid', 'vsize'], 'accepted BCHN mempool result');
      exact(row.fees, ['base', 'effective-feerate'], 'accepted BCHN mempool fees');
      if (row.size !== transaction.sizeBytes || !Number.isSafeInteger(row.vsize) || row.vsize < transaction.sizeBytes
        || typeof row.fees.base !== 'number' || !Number.isFinite(row.fees.base) || row.fees.base < 0
        || typeof row.fees['effective-feerate'] !== 'number' || !Number.isFinite(row.fees['effective-feerate'])
        || row.fees['effective-feerate'] < 0) fail('accepted BCHN mempool resource/fee result is invalid');
    } else {
      const allowed = new Set(['allowed', 'reject-details', 'reject-reason', 'txid']);
      if (Object.keys(row).some((key) => !allowed.has(key)) || typeof row['reject-reason'] !== 'string'
        || row['reject-reason'].length === 0 || (Object.hasOwn(row, 'reject-details')
        && (typeof row['reject-details'] !== 'string' || row['reject-details'].length === 0))) {
        fail('rejected BCHN mempool result lacks a concrete rejection');
      }
    }
    return row.allowed;
  };

  const validateBchnMinedLane = ({ stdin, stdout, context, expected, stdinSchema, stdoutSchema }) => {
    if (expected.expectation !== 'accept') fail('BCHN mined inclusion cannot be used as rejection evidence');
    exact(stdin, ['rawTransactionHex', 'schema'], 'BCHN mined stdin');
    if (stdin.schema !== stdinSchema) fail('BCHN mined stdin schema is invalid');
    const transaction = transactionFromHex(stdin.rawTransactionHex, expected, 'BCHN mined stdin');
    exact(stdout, ['headerSegment', 'nodeObservation', 'schema', 'transactionBlock'], 'BCHN mined stdout');
    if (stdout.schema !== stdoutSchema) fail('BCHN mined stdout schema is invalid');
    exact(stdout.headerSegment, ['rawHeadersHex', 'tip'], 'BCHN mined header segment');
    if (!Array.isArray(stdout.headerSegment.rawHeadersHex) || stdout.headerSegment.rawHeadersHex.some(
      (entry) => typeof entry !== 'string' || !/^[0-9a-f]{160}$/u.test(entry))) fail('BCHN mined raw header list is invalid');
    const segment = verifyRawHeaderSegment({ checkpoint: context.checkpoint,
      rawHeaders: stdout.headerSegment.rawHeadersHex.map((entry) => Buffer.from(entry, 'hex')),
      tip: stdout.headerSegment.tip });
    exact(stdout.transactionBlock, ['headerIndex', 'merkleBranch', 'transactionCount', 'transactionIndex'], 'BCHN mined transaction block');
    const headerIndex = integer(stdout.transactionBlock.headerIndex, 0, segment.headers.length - 1, 'BCHN mined transaction headerIndex');
    const transactionHeader = segment.headers[headerIndex];
    verifyBchTransactionMerkleProof({ branch: stdout.transactionBlock.merkleBranch,
      headerMerkleRoot: transactionHeader.merkleRoot, rawTransaction: transaction.bytes,
      transactionCount: stdout.transactionBlock.transactionCount, transactionIndex: stdout.transactionBlock.transactionIndex });
    const confirmations = segment.tip.height - transactionHeader.height + 1;
    if (confirmations < context.minimumConfirmations) fail('BCHN mined transaction lacks the pinned confirmation depth');
    exact(stdout.nodeObservation, ['blockHash', 'chain', 'confirmations', 'initialBlockDownload', 'transactionId', 'version'], 'BCHN mined node observation');
    if (stdout.nodeObservation.blockHash !== transactionHeader.id || stdout.nodeObservation.transactionId !== transaction.txid
      || stdout.nodeObservation.confirmations !== confirmations || stdout.nodeObservation.initialBlockDownload !== false
      || stdout.nodeObservation.chain !== 'chipnet' || typeof stdout.nodeObservation.version !== 'string'
      || !SEMVER.test(stdout.nodeObservation.version)) fail('BCHN mined node observation contradicts raw chain evidence');
    return true;
  };

  const validateMachineManifest = (value, startedAt, completedAt, { schema, label = 'Q-02 machine manifest' }) => {
    exact(value, ['architecture', 'capturedAt', 'cpuModel', 'kernel', 'machineIdSha256', 'memoryBytes', 'operatingSystem', 'schema'], label);
    if (value.schema !== schema) fail(`${label} schema is invalid`);
    for (const key of ['architecture', 'cpuModel', 'kernel', 'operatingSystem']) text(value[key], `${label}.${key}`, 1024);
    hash(value.machineIdSha256, `${label}.machineIdSha256`);
    if (typeof value.memoryBytes !== 'string' || !/^[1-9][0-9]*$/u.test(value.memoryBytes)) fail(`${label}.memoryBytes must be positive canonical decimal`);
    const capturedAt = canonicalTimestamp(value.capturedAt, `${label}.capturedAt`);
    if (capturedAt < startedAt - maximumClockSkewMs || capturedAt > completedAt + maximumClockSkewMs) fail(`${label} timestamp is outside its signed run`);
  };

  return Object.freeze({ assertExactInputCount, canonicalBytes, canonicalTimestamp, exact, hash, integer, jcsReference,
    loadStableCanonicalJsonReference: jcsReference, plain, readStableDirectFile, relativeReference, sha256, text, validateBchnMempoolLane,
    validateBchnMinedLane, validateExternalPerInputLane, validateMachineManifest,
    verifyEd25519AuthorityEnvelope, verifySignedLaneEnvelope });
}
