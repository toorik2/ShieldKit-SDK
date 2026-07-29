import { performance } from 'node:perf_hooks';
import {
  chmod,
  lstat,
  open,
  readFile,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import * as snarkjs from 'snarkjs';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  parseStrictJson,
  sha256Bytes,
  sha256File,
} from '../groth16.mjs';

export const V2_GROTH16_PROOF_REQUEST_SCHEMA =
  'shieldkit-v2-direct-groth16-proof-request-v1';
export const V2_GROTH16_PROOF_RESULT_SCHEMA =
  'shieldkit-v2-direct-groth16-proof-result-v1';

const HASH = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const ARTIFACT_NAMES = Object.freeze([
  'r1cs',
  'wasm',
  'provingKey',
  'verificationKey',
]);

export class V2Groth16ProofChildError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2Groth16ProofChildError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new V2Groth16ProofChildError(code, message, cause);
};

function plainObject(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    fail('PROVER_REQUEST_INVALID', `${label} must be an object`);
  }
  return value;
}

function exactKeys(value, keys, label) {
  plainObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(
      'PROVER_REQUEST_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
  return value;
}

function absolutePath(value, label) {
  if (
    typeof value !== 'string'
    || !path.isAbsolute(value)
    || path.normalize(value) !== value
    || value.includes('\0')
  ) {
    fail('PROVER_REQUEST_INVALID', `${label} must be a normalized absolute path`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('PROVER_REQUEST_INVALID', `${label} must be lowercase SHA-256`);
  }
  return value;
}

function publicInputs(value) {
  if (
    !Array.isArray(value)
    || value.length !== 2
    || value.some(
      (entry) =>
        typeof entry !== 'string'
        || !DECIMAL.test(entry)
        || BigInt(entry) > MAX_U128,
    )
  ) {
    fail(
      'PROVER_REQUEST_INVALID',
      'expectedPublicInputs must contain exactly two canonical u128 strings',
    );
  }
  return Object.freeze([...value]);
}

async function regularFile(filename, label) {
  let metadata;
  try {
    metadata = await lstat(filename, { bigint: true });
  } catch (error) {
    fail('PROVER_ARTIFACT_UNAVAILABLE', `${label} is unavailable`, error);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    fail(
      'PROVER_ARTIFACT_UNAVAILABLE',
      `${label} must be a regular non-symlink file`,
    );
  }
  if (await realpath(filename) !== filename) {
    fail(
      'PROVER_ARTIFACT_UNAVAILABLE',
      `${label} resolves through a symlink`,
    );
  }
  return Object.freeze({
    dev: metadata.dev.toString(),
    ino: metadata.ino.toString(),
    size: metadata.size.toString(),
  });
}

async function pinnedArtifact(record, label) {
  exactKeys(record, ['path', 'sha256'], label);
  const filename = absolutePath(record.path, `${label}.path`);
  const expectedHash = hash(record.sha256, `${label}.sha256`);
  const identity = await regularFile(filename, label);
  const measured = await sha256File(filename);
  if (measured !== expectedHash) {
    fail(
      'PROVER_ARTIFACT_HASH_MISMATCH',
      `${label} SHA-256 mismatch`,
    );
  }
  if (
    canonicalizeJcs(await regularFile(filename, label))
    !== canonicalizeJcs(identity)
  ) {
    fail('PROVER_ARTIFACT_CHANGED', `${label} changed while hashing`);
  }
  return Object.freeze({
    path: filename,
    sha256: measured,
    identity,
  });
}

async function assertArtifactUnchanged(artifact, label) {
  const identity = await regularFile(artifact.path, label);
  if (
    canonicalizeJcs(identity) !== canonicalizeJcs(artifact.identity)
    || await sha256File(artifact.path) !== artifact.sha256
  ) {
    fail('PROVER_ARTIFACT_CHANGED', `${label} changed during proving`);
  }
}

function normalizeRequest(value) {
  exactKeys(value, [
    'artifacts',
    'expectedPublicInputs',
    'failurePath',
    'input',
    'outputPath',
    'schema',
    'witnessPath',
  ], 'proof request');
  if (value.schema !== V2_GROTH16_PROOF_REQUEST_SCHEMA) {
    fail('PROVER_REQUEST_INVALID', 'proof request schema is unsupported');
  }
  exactKeys(value.artifacts, ARTIFACT_NAMES, 'proof request.artifacts');
  exactKeys(value.input, ['path', 'sha256'], 'proof request.input');
  const artifacts = Object.freeze(Object.fromEntries(
    ARTIFACT_NAMES.map((name) => {
      const record = value.artifacts[name];
      exactKeys(record, ['path', 'sha256'], `proof request.artifacts.${name}`);
      return [name, Object.freeze({
        path: absolutePath(
          record.path,
          `proof request.artifacts.${name}.path`,
        ),
        sha256: hash(
          record.sha256,
          `proof request.artifacts.${name}.sha256`,
        ),
      })];
    }),
  ));
  return Object.freeze({
    schema: value.schema,
    artifacts,
    expectedPublicInputs: publicInputs(value.expectedPublicInputs),
    input: Object.freeze({
      path: absolutePath(value.input.path, 'proof request.input.path'),
      sha256: hash(value.input.sha256, 'proof request.input.sha256'),
    }),
    witnessPath: absolutePath(value.witnessPath, 'proof request.witnessPath'),
    outputPath: absolutePath(value.outputPath, 'proof request.outputPath'),
    failurePath: absolutePath(value.failurePath, 'proof request.failurePath'),
  });
}

async function writeExclusive(filename, value) {
  const bytes = Buffer.from(canonicalizeJcs(value), 'utf8');
  const handle = await open(filename, 'wx', 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.chmod(0o600);
    await handle.sync();
  } finally {
    await handle.close();
  }
  return Object.freeze({
    bytes: bytes.length,
    sha256: sha256Bytes(bytes),
  });
}

export async function executeV2Groth16ProofRequest(value) {
  const request = normalizeRequest(value);
  const artifacts = Object.freeze(Object.fromEntries(
    await Promise.all(ARTIFACT_NAMES.map(async (name) => [
      name,
      await pinnedArtifact(
        request.artifacts[name],
        `proof request artifact ${name}`,
      ),
    ])),
  ));
  const inputIdentity = await regularFile(
    request.input.path,
    'proof request circuit input',
  );
  const inputBytes = await readFile(request.input.path);
  if (sha256Bytes(inputBytes) !== request.input.sha256) {
    fail(
      'PROVER_INPUT_HASH_MISMATCH',
      'proof request circuit input SHA-256 mismatch',
    );
  }
  if (
    canonicalizeJcs(await regularFile(
      request.input.path,
      'proof request circuit input',
    )) !== canonicalizeJcs(inputIdentity)
  ) {
    fail('PROVER_INPUT_CHANGED', 'proof request circuit input changed while reading');
  }
  const circuitInput = parseStrictJson(inputBytes, 'proof request circuit input');
  const verificationKeyBytes = await readFile(
    artifacts.verificationKey.path,
  );
  if (
    sha256Bytes(verificationKeyBytes)
    !== artifacts.verificationKey.sha256
  ) {
    fail(
      'PROVER_ARTIFACT_CHANGED',
      'verification key changed while reading',
    );
  }
  const verificationKey = parseStrictJson(
    verificationKeyBytes,
    'verification key',
  );

  const started = performance.now();
  const witnessStarted = performance.now();
  await snarkjs.wtns.calculate(
    circuitInput,
    artifacts.wasm.path,
    request.witnessPath,
  );
  await chmod(request.witnessPath, 0o600);
  const witnessCalculationMs = performance.now() - witnessStarted;
  const witnessCheckStarted = performance.now();
  if (!await snarkjs.wtns.check(artifacts.r1cs.path, request.witnessPath)) {
    fail('PROVER_WITNESS_INVALID', 'generated witness does not satisfy the R1CS');
  }
  const witnessCheckMs = performance.now() - witnessCheckStarted;
  const provingStarted = performance.now();
  const generated = await snarkjs.groth16.prove(
    artifacts.provingKey.path,
    request.witnessPath,
    undefined,
    { singleThread: true },
  );
  const proofGenerationMs = performance.now() - provingStarted;
  const generatedPublicInputs = publicInputs(
    generated.publicSignals.map(String),
  );
  if (
    generatedPublicInputs.some(
      (entry, index) => entry !== request.expectedPublicInputs[index],
    )
  ) {
    fail(
      'PROVER_PUBLIC_INPUT_MISMATCH',
      'proof public inputs differ from the exact packet digest limbs',
    );
  }
  const verificationStarted = performance.now();
  if (
    !await snarkjs.groth16.verify(
      verificationKey,
      generatedPublicInputs,
      generated.proof,
    )
  ) {
    fail(
      'PROVER_PROOF_INVALID',
      'generated proof does not verify under the pinned verification key',
    );
  }
  const proofVerificationMs = performance.now() - verificationStarted;
  for (const name of ARTIFACT_NAMES) {
    await assertArtifactUnchanged(
      artifacts[name],
      `proof request artifact ${name}`,
    );
  }
  if (
    await sha256File(request.input.path) !== request.input.sha256
    || canonicalizeJcs(await regularFile(
      request.input.path,
      'proof request circuit input',
    )) !== canonicalizeJcs(inputIdentity)
  ) {
    fail('PROVER_INPUT_CHANGED', 'proof request circuit input changed during proving');
  }
  const result = {
    schema: V2_GROTH16_PROOF_RESULT_SCHEMA,
    claims: {
      proofVerified: true,
      singleThread: true,
      witnessValid: true,
    },
    sourceHashes: Object.fromEntries(
      ARTIFACT_NAMES.map((name) => [name, artifacts[name].sha256]),
    ),
    inputSha256: request.input.sha256,
    proof: generated.proof,
    publicInputs: generatedPublicInputs,
    timingsMs: {
      proofGeneration: proofGenerationMs,
      proofVerification: proofVerificationMs,
      total: performance.now() - started,
      witnessCalculation: witnessCalculationMs,
      witnessCheck: witnessCheckMs,
    },
  };
  const written = await writeExclusive(request.outputPath, result);
  return Object.freeze({ result, written });
}

async function writeFailure(filename, error) {
  try {
    await writeExclusive(filename, {
      schema: 'shieldkit-v2-direct-groth16-proof-failure-v1',
      code: typeof error?.code === 'string'
        ? error.code
        : 'PROVER_CHILD_FAILED',
      message: error instanceof Error ? error.message : String(error),
    });
  } catch {}
}

async function main() {
  const requestPath = absolutePath(
    process.argv[2],
    'proof request filename',
  );
  const bytes = await readFile(requestPath);
  const request = normalizeRequest(
    parseStrictJson(bytes, 'proof request'),
  );
  try {
    await executeV2Groth16ProofRequest(request);
  } catch (error) {
    await writeFailure(request.failurePath, error);
    throw error;
  }
}

if (
  typeof process.argv[1] === 'string'
  && import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().then(
    () => process.exit(0),
    (error) => {
      process.stderr.write(
        `${typeof error?.code === 'string'
          ? error.code
          : 'PROVER_CHILD_FAILED'}: `
        + `${error instanceof Error ? error.message : String(error)}\n`,
      );
      process.exit(1);
    },
  );
}
