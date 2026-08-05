import {
  chmod,
  lstat,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  parseStrictJson,
  sha256Bytes,
  sha256File,
} from '../groth16.mjs';
import {
  runLinuxCgroupV2ProofWorker,
} from './linux-cgroup-v2-worker.mjs';
import {
  V2_GROTH16_PROOF_REQUEST_SCHEMA,
  V2_GROTH16_PROOF_RESULT_SCHEMA,
} from './groth16-proof-child.mjs';

const CHILD_ENTRYPOINT = fileURLToPath(
  new URL('./groth16-proof-child.mjs', import.meta.url),
);
const HASH = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const ARTIFACT_NAMES = Object.freeze([
  'r1cs',
  'wasm',
  'provingKey',
  'verificationKey',
]);

export class V2Groth16ProofWorkerError extends Error {
  constructor(code, message, cause = undefined, evidence = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2Groth16ProofWorkerError';
    this.code = code;
    this.evidence = evidence;
  }
}

const fail = (code, message, cause, evidence) => {
  throw new V2Groth16ProofWorkerError(code, message, cause, evidence);
};

function plainObject(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('PROVER_INPUT_INVALID', `${label} must be a plain object`);
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
    fail('PROVER_INPUT_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function resultExactKeys(value, keys, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    fail('PROVER_RESULT_INVALID', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail('PROVER_RESULT_INVALID', `${label} has missing or unknown properties`);
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
    fail('PROVER_INPUT_INVALID', `${label} must be a normalized absolute path`);
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
      'PROVER_INPUT_INVALID',
      'expectedPublicInputs must contain exactly two canonical u128 strings',
    );
  }
  return Object.freeze([...value]);
}

async function trustedDirectory(filename) {
  const directory = absolutePath(filename, 'workspaceDirectory');
  const metadata = await lstat(directory).catch((error) =>
    fail('PROVER_WORKSPACE_UNAVAILABLE', 'workspaceDirectory is unavailable', error)
  );
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || await realpath(directory) !== directory
    || (process.getuid !== undefined && metadata.uid !== process.getuid())
    || (metadata.mode & 0o077) !== 0
  ) {
    fail(
      'PROVER_WORKSPACE_UNTRUSTED',
      'workspaceDirectory must be a private owner-controlled non-symlink directory',
    );
  }
  return directory;
}

async function pinnedArtifacts(value) {
  exactKeys(value, ARTIFACT_NAMES, 'artifacts');
  return Object.freeze(Object.fromEntries(
    await Promise.all(ARTIFACT_NAMES.map(async (name) => {
      const record = value[name];
      exactKeys(record, ['path', 'sha256'], `artifacts.${name}`);
      const filename = absolutePath(record.path, `artifacts.${name}.path`);
      if (typeof record.sha256 !== 'string' || !HASH.test(record.sha256)) {
        fail(
          'PROVER_INPUT_INVALID',
          `artifacts.${name}.sha256 must be lowercase SHA-256`,
        );
      }
      const metadata = await lstat(filename).catch((error) =>
        fail(
          'PROVER_ARTIFACT_UNAVAILABLE',
          `artifacts.${name} is unavailable`,
          error,
        )
      );
      if (
        !metadata.isFile()
        || metadata.isSymbolicLink()
        || await realpath(filename) !== filename
        || await sha256File(filename) !== record.sha256
      ) {
        fail(
          'PROVER_ARTIFACT_HASH_MISMATCH',
          `artifacts.${name} is not the exact pinned regular file`,
        );
      }
      return [name, Object.freeze({
        path: filename,
        sha256: record.sha256,
      })];
    })),
  ));
}

async function artifactIdentity(filename, code, label) {
  const metadata = await lstat(filename, { bigint: true }).catch((error) =>
    fail(code, `${label} is unavailable`, error)
  );
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || await realpath(filename) !== filename
  ) {
    fail(code, `${label} is not the original regular file`);
  }
  return Object.freeze({
    dev: metadata.dev.toString(),
    ino: metadata.ino.toString(),
    size: metadata.size.toString(),
  });
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size;
}

async function pinnedArtifactIdentities(artifacts) {
  return Object.freeze(Object.fromEntries(await Promise.all(
    ARTIFACT_NAMES.map(async (name) => [
      name,
      await artifactIdentity(
        artifacts[name].path,
        'PROVER_ARTIFACT_UNAVAILABLE',
        `artifacts.${name}`,
      ),
    ]),
  )));
}

async function assertPinnedArtifactsUnchanged(artifacts, identities) {
  await Promise.all(ARTIFACT_NAMES.map(async (name) => {
    const artifact = artifacts[name];
    const identity = await artifactIdentity(
      artifact.path,
      'PROVER_ARTIFACT_CHANGED',
      `artifacts.${name}`,
    );
    if (
      !sameIdentity(identity, identities[name])
      || await sha256File(artifact.path) !== artifact.sha256
    ) {
      fail(
        'PROVER_ARTIFACT_CHANGED',
        `artifacts.${name} changed while the proof worker ran`,
      );
    }
  }));
}

async function writePrivate(filename, value) {
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
    bytes,
    sha256: sha256Bytes(bytes),
  });
}

function validateResult(value, request, resultSha256) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    fail('PROVER_RESULT_INVALID', 'proof worker result must be an object');
  }
  resultExactKeys(
    value.claims,
    ['proofVerified', 'singleThread', 'witnessValid'],
    'proof worker result.claims',
  );
  resultExactKeys(
    value.sourceHashes,
    ARTIFACT_NAMES,
    'proof worker result.sourceHashes',
  );
  resultExactKeys(
    value.timingsMs,
    ['proofGeneration', 'proofVerification', 'total', 'witnessCalculation', 'witnessCheck'],
    'proof worker result.timingsMs',
  );
  const expectedKeys = [
    'claims',
    'inputSha256',
    'proof',
    'publicInputs',
    'schema',
    'sourceHashes',
    'timingsMs',
  ].sort();
  const actualKeys = Object.keys(value).sort();
  if (
    actualKeys.length !== expectedKeys.length
    || actualKeys.some((key, index) => key !== expectedKeys[index])
    || value.schema !== V2_GROTH16_PROOF_RESULT_SCHEMA
    || value.claims?.witnessValid !== true
    || value.claims?.proofVerified !== true
    || value.claims?.singleThread !== true
    || !Array.isArray(value.publicInputs)
    || value.publicInputs.length !== 2
    || value.publicInputs.some(
      (entry, index) => entry !== request.expectedPublicInputs[index],
    )
    || value.inputSha256 !== request.input.sha256
    || ARTIFACT_NAMES.some(
      (name) => value.sourceHashes?.[name] !== request.artifacts[name].sha256,
    )
  ) {
    fail(
      'PROVER_RESULT_INVALID',
      'proof worker result is not bound to its exact request',
    );
  }
  if (
    value.proof === null
    || Array.isArray(value.proof)
    || typeof value.proof !== 'object'
  ) {
    fail('PROVER_RESULT_INVALID', 'proof worker result has no proof object');
  }
  for (const name of [
    'proofGeneration',
    'proofVerification',
    'total',
    'witnessCalculation',
    'witnessCheck',
  ]) {
    if (
      typeof value.timingsMs?.[name] !== 'number'
      || !Number.isFinite(value.timingsMs[name])
      || value.timingsMs[name] < 0
    ) {
      fail('PROVER_RESULT_INVALID', `proof worker timing ${name} is invalid`);
    }
  }
  const proof = JSON.parse(JSON.stringify(value.proof));
  return Object.freeze({
    schema: value.schema,
    proof,
    publicInputs: Object.freeze([...value.publicInputs]),
    claims: Object.freeze({ ...value.claims }),
    sourceHashes: Object.freeze({ ...value.sourceHashes }),
    inputSha256: value.inputSha256,
    resultSha256,
    timingsMs: Object.freeze({ ...value.timingsMs }),
  });
}

async function readFailure(filename) {
  try {
    const value = parseStrictJson(await readFile(filename), 'proof failure');
    if (
      typeof value?.code === 'string'
      && typeof value?.message === 'string'
    ) {
      return Object.freeze({ code: value.code, message: value.message });
    }
  } catch {}
  return undefined;
}

/**
 * Generate and locally verify exactly one V2 Groth16 proof inside a hard
 * 4-GiB/zero-swap cgroup. All private transient files are removed in finally.
 */
export async function proveV2DirectGroth16(value, dependencies = {}) {
  exactKeys(value, [
    'artifacts',
    'circuitInput',
    'expectedPublicInputs',
    'workspaceDirectory',
  ], 'V2 proof input');
  exactKeys(dependencies, ['runContainedWorker'], 'V2 proof dependencies');
  if (typeof dependencies.runContainedWorker !== 'function') {
    fail(
      'PROVER_INPUT_INVALID',
      'runContainedWorker dependency must be a function',
    );
  }
  plainObject(value.circuitInput, 'circuitInput');
  const workspace = await trustedDirectory(value.workspaceDirectory);
  const artifacts = await pinnedArtifacts(value.artifacts);
  const artifactIdentities = await pinnedArtifactIdentities(artifacts);
  const expected = publicInputs(value.expectedPublicInputs);
  const temporary = await mkdtemp(
    path.join(workspace, '.shieldkit-v2-proof-'),
  );
  await chmod(temporary, 0o700);
  const inputPath = path.join(temporary, 'input.json');
  const requestPath = path.join(temporary, 'request.json');
  const witnessPath = path.join(temporary, 'witness.wtns');
  const outputPath = path.join(temporary, 'result.json');
  const failurePath = path.join(temporary, 'failure.json');
  try {
    const input = await writePrivate(inputPath, value.circuitInput);
    const request = Object.freeze({
      schema: V2_GROTH16_PROOF_REQUEST_SCHEMA,
      artifacts,
      expectedPublicInputs: expected,
      input: Object.freeze({
        path: inputPath,
        sha256: input.sha256,
      }),
      witnessPath,
      outputPath,
      failurePath,
    });
    await writePrivate(requestPath, request);
    let containment;
    try {
      containment = await dependencies.runContainedWorker({
        command: process.execPath,
        arguments: [CHILD_ENTRYPOINT, requestPath],
      });
    } catch (error) {
      const childFailure = await readFailure(failurePath);
      fail(
        childFailure?.code ?? error?.code ?? 'PROVER_WORKER_FAILED',
        childFailure?.message
          ?? (error instanceof Error ? error.message : String(error)),
        error,
        error?.evidence,
      );
    }
    await assertPinnedArtifactsUnchanged(artifacts, artifactIdentities);
    const outputBytes = await readFile(outputPath).catch((error) =>
      fail('PROVER_RESULT_MISSING', 'proof worker produced no result', error)
    );
    const result = validateResult(
      parseStrictJson(outputBytes, 'proof result'),
      request,
      sha256Bytes(outputBytes),
    );
    const proofBytes = Buffer.from(canonicalizeJcs({
      proof: result.proof,
      publicInputs: result.publicInputs,
    }), 'utf8');
    return Object.freeze({
      ...result,
      proofBytes,
      containment,
    });
  } finally {
    await rm(temporary, { recursive: true, force: false });
  }
}

export async function proveV2DirectGroth16Default(value) {
  return proveV2DirectGroth16(value, {
    runContainedWorker: runLinuxCgroupV2ProofWorker,
  });
}
