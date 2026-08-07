import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  realpath,
  rm,
} from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { readBinFile } from '@iden3/binfileutils';
import { readR1csHeader } from 'r1csfile';

import {
  BN254_SCALAR_FIELD_MODULUS,
} from '../../action/v2/domains.mjs';
import {
  PINNED_CIRCOM2_PACKAGE_VERSION,
  PINNED_CIRCOM_COMPILER_VERSION,
  V2_BUILD_R1CS_PATH,
  V2_BUILD_SYM_PATH,
  V2_BUILD_WASM_PATH,
  verifyCircuitBuildAttestationAgainstRepository,
} from './build-attestation.mjs';
import {
  parseV2RelationSourceManifest,
} from './relation-source-manifest.mjs';

const MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024;

export class CircuitBuildReproductionError extends Error {
  constructor(code, message, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'CircuitBuildReproductionError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new CircuitBuildReproductionError(code, message, cause);
};

const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');

function sameIdentity(left, right) {
  return (
    left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
  );
}

async function canonicalRepositoryRoot(repositoryRoot) {
  if (
    typeof repositoryRoot !== 'string'
    || !path.isAbsolute(repositoryRoot)
  ) {
    fail(
      'BUILD_REPRODUCTION_ROOT_INVALID',
      'repositoryRoot must be an absolute path',
    );
  }
  const resolved = await realpath(repositoryRoot).catch((error) =>
    fail(
      'BUILD_REPRODUCTION_ROOT_INVALID',
      'repositoryRoot cannot be resolved',
      error,
    ));
  const metadata = await lstat(repositoryRoot, { bigint: true }).catch(
    (error) =>
      fail(
        'BUILD_REPRODUCTION_ROOT_INVALID',
        'repositoryRoot cannot be inspected',
        error,
      ),
  );
  if (
    resolved !== repositoryRoot
    || !metadata.isDirectory()
    || metadata.isSymbolicLink()
  ) {
    fail(
      'BUILD_REPRODUCTION_ROOT_INVALID',
      'repositoryRoot must be a canonical non-symlink directory',
    );
  }
  return resolved;
}

async function stableFile(filename, label, { capture = false } = {}) {
  const beforePath = await lstat(filename, { bigint: true }).catch((error) =>
    fail(
      'BUILD_REPRODUCTION_ARTIFACT_INVALID',
      `${label} cannot be inspected`,
      error,
    ));
  if (
    !beforePath.isFile()
    || beforePath.isSymbolicLink()
    || beforePath.nlink !== 1n
  ) {
    fail(
      'BUILD_REPRODUCTION_ARTIFACT_INVALID',
      `${label} must be a unique regular non-symlink file`,
    );
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(filename, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n) {
      fail(
        'BUILD_REPRODUCTION_ARTIFACT_INVALID',
        `${label} has an unsafe file identity`,
      );
    }
    const hasher = createHash('sha256');
    const chunks = capture ? [] : undefined;
    for await (const chunk of handle.createReadStream({
      autoClose: false,
      highWaterMark: 64 * 1024,
    })) {
      hasher.update(chunk);
      chunks?.push(Buffer.from(chunk));
    }
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(filename, { bigint: true });
    if (
      !sameIdentity(beforePath, before)
      || !sameIdentity(before, after)
      || !sameIdentity(after, afterPath)
    ) {
      fail(
        'BUILD_REPRODUCTION_ARTIFACT_CHANGED',
        `${label} changed while it was measured`,
      );
    }
    const bytes = Number(after.size);
    if (!Number.isSafeInteger(bytes) || bytes <= 0) {
      fail(
        'BUILD_REPRODUCTION_ARTIFACT_INVALID',
        `${label} has an invalid size`,
      );
    }
    const result = {
      bytes,
      sha256: hasher.digest('hex'),
    };
    if (capture) result.data = Buffer.concat(chunks, bytes);
    return Object.freeze(result);
  } finally {
    await handle?.close();
  }
}

async function writePrivateFile(filename, bytes) {
  let handle;
  try {
    handle = await open(filename, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle?.close();
  }
  await chmod(filename, 0o600);
}

async function copyExactSourceSnapshot(
  repositoryRoot,
  sourceManifest,
  snapshotRoot,
) {
  for (const source of sourceManifest.sources) {
    const sourcePath = path.join(
      repositoryRoot,
      ...source.path.split('/'),
    );
    const measured = await stableFile(
      sourcePath,
      `relation source ${source.path}`,
      { capture: true },
    );
    if (
      measured.bytes !== source.bytes
      || measured.sha256 !== source.sha256
    ) {
      fail(
        'BUILD_REPRODUCTION_SOURCE_DRIFT',
        `relation source differs from its manifest: ${source.path}`,
      );
    }
    const destination = path.join(
      snapshotRoot,
      ...source.path.split('/'),
    );
    await mkdir(path.dirname(destination), {
      recursive: true,
      mode: 0o700,
    });
    await writePrivateFile(destination, measured.data);
  }
}

async function runPinnedNode(argv, { cwd, label }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, argv, {
      cwd,
      env: {},
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const collect = (chunks, kind) => (chunk) => {
      const bytes = Buffer.from(chunk);
      if (kind === 'stdout') stdoutBytes += bytes.byteLength;
      else stderrBytes += bytes.byteLength;
      if (stdoutBytes + stderrBytes > MAX_COMMAND_OUTPUT_BYTES) {
        child.kill('SIGKILL');
        reject(new CircuitBuildReproductionError(
          'BUILD_REPRODUCTION_COMMAND_OUTPUT_LIMIT',
          `${label} exceeded the command-output limit`,
        ));
        return;
      }
      chunks.push(bytes);
    };
    child.stdout.on('data', collect(stdout, 'stdout'));
    child.stderr.on('data', collect(stderr, 'stderr'));
    child.once('error', (error) =>
      reject(new CircuitBuildReproductionError(
        'BUILD_REPRODUCTION_COMMAND_FAILED',
        `${label} could not be started`,
        error,
      )));
    child.once('close', (code, signal) => {
      if (code !== 0 || signal !== null) {
        reject(new CircuitBuildReproductionError(
          'BUILD_REPRODUCTION_COMMAND_FAILED',
          `${label} failed with code ${String(code)} and signal ${
            String(signal)
          }: ${Buffer.concat(stderr).toString('utf8').slice(-4096)}`,
        ));
        return;
      }
      resolve(Object.freeze({
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      }));
    });
  });
}

async function readReproducedR1csAbi(filename) {
  const { fd, sections } = await readBinFile(
    filename,
    'r1cs',
    1,
    1 << 22,
    1 << 24,
  );
  try {
    const header = await readR1csHeader(fd, sections, true);
    if (
      BigInt(header.prime) !== BN254_SCALAR_FIELD_MODULUS
      || header.useCustomGates !== false
    ) {
      fail(
        'BUILD_REPRODUCTION_R1CS_INVALID',
        'reproduced R1CS has an unexpected field or custom gates',
      );
    }
    return Object.freeze({
      field: 'bn254',
      publicInputs: header.nPubInputs,
      publicOutputs: header.nOutputs,
      privateInputs: header.nPrvInputs,
      constraints: header.nConstraints,
      wires: header.nVars,
    });
  } finally {
    await fd.close();
  }
}

function assertArtifactMatches(record, measured, label) {
  if (
    record.bytes !== measured.bytes
    || record.sha256 !== measured.sha256
  ) {
    fail(
      'BUILD_REPRODUCTION_MISMATCH',
      `${label} differs from a clean independent recompilation`,
    );
  }
}

function assertAbiMatches(expected, actual) {
  for (const field of [
    'field',
    'publicInputs',
    'publicOutputs',
    'privateInputs',
    'constraints',
    'wires',
  ]) {
    if (expected[field] !== actual[field]) {
      fail(
        'BUILD_REPRODUCTION_MISMATCH',
        `R1CS ABI field ${field} differs from a clean independent recompilation`,
      );
    }
  }
}

/**
 * Independently recompile the exact manifest-pinned V2 relation from a private
 * source snapshot, then byte/hash compare every declared output. A canonical
 * attestation alone is only a claim; successful reproduction is the evidence
 * that the claimed sources and pinned compiler actually produce the artifacts.
 */
export async function reproduceV2CircuitBuild({
  buildAttestationBytes,
  repositoryRoot,
  requireTrustedSigner = false,
  sourceManifestBytes,
  trustedDevelopmentSigners,
} = {}) {
  if (!(buildAttestationBytes instanceof Uint8Array)) {
    fail(
      'BUILD_REPRODUCTION_INPUT_INVALID',
      'buildAttestationBytes must be canonical UTF-8 bytes',
    );
  }
  if (!(sourceManifestBytes instanceof Uint8Array)) {
    fail(
      'BUILD_REPRODUCTION_INPUT_INVALID',
      'sourceManifestBytes must be canonical UTF-8 bytes',
    );
  }
  const root = await canonicalRepositoryRoot(repositoryRoot);
  const attestation =
    await verifyCircuitBuildAttestationAgainstRepository(
      buildAttestationBytes,
      {
        repositoryRoot: root,
        requireTrustedSigner,
        sourceManifestBytes,
        trustedDevelopmentSigners,
      },
    );
  const sourceManifest = parseV2RelationSourceManifest(
    sourceManifestBytes,
  );
  if (
    attestation.compilation.node.version !== process.versions.node
    || attestation.compilation.node.modulesAbi !== process.versions.modules
  ) {
    fail(
      'BUILD_REPRODUCTION_RUNTIME_MISMATCH',
      'current Node runtime differs from the attested compiler runtime',
    );
  }

  const temporaryParent = path.join(root, '.codex-build', 'test-tmp');
  await mkdir(temporaryParent, { recursive: true, mode: 0o700 });
  await chmod(temporaryParent, 0o700);
  if (await realpath(temporaryParent) !== temporaryParent) {
    fail(
      'BUILD_REPRODUCTION_ROOT_INVALID',
      'reproduction temporary directory must not use symlink traversal',
    );
  }
  const temporary = await mkdtemp(path.join(
    temporaryParent,
    'v2-build-reproduction-',
  ));
  await chmod(temporary, 0o700);
  try {
    const snapshotRoot = path.join(temporary, 'source-snapshot');
    const outputRoot = path.join(temporary, 'output');
    await mkdir(snapshotRoot, { mode: 0o700 });
    await mkdir(outputRoot, { mode: 0o700 });
    await copyExactSourceSnapshot(
      root,
      sourceManifest,
      snapshotRoot,
    );

    const circomCli = path.join(root, 'node_modules', 'circom2', 'cli.js');
    const cliBefore = await stableFile(circomCli, 'pinned Circom CLI');
    assertArtifactMatches(
      attestation.compilation.cli,
      cliBefore,
      'pinned Circom CLI',
    );
    const version = await runPinnedNode(
      [circomCli, '--version'],
      { cwd: temporary, label: 'pinned Circom version check' },
    );
    const versionOutput = `${version.stdout}${version.stderr}`;
    if (
      !versionOutput.includes(
        `circom2 npm package ${PINNED_CIRCOM2_PACKAGE_VERSION}`,
      )
      || !versionOutput.includes(
        `circom compiler ${PINNED_CIRCOM_COMPILER_VERSION}`,
      )
    ) {
      fail(
        'BUILD_REPRODUCTION_COMPILER_MISMATCH',
        'pinned Circom runtime reports an unexpected version',
      );
    }

    const snapshotEntrypoint = path.join(
      snapshotRoot,
      ...sourceManifest.entrypoint.split('/'),
    );
    const started = performance.now();
    await runPinnedNode([
      circomCli,
      snapshotEntrypoint,
      '--r1cs',
      '--wasm',
      '--sym',
      '--O1',
      '--sanity_check',
      '2',
      '--output',
      outputRoot,
    ], {
      cwd: temporary,
      label: 'independent V2 Circom reproduction',
    });
    const elapsedMs = performance.now() - started;

    const reproduced = Object.freeze({
      r1cs: await stableFile(
        path.join(outputRoot, ...V2_BUILD_R1CS_PATH.split('/')),
        'reproduced R1CS',
      ),
      sym: await stableFile(
        path.join(outputRoot, ...V2_BUILD_SYM_PATH.split('/')),
        'reproduced symbol file',
      ),
      wasm: await stableFile(
        path.join(outputRoot, ...V2_BUILD_WASM_PATH.split('/')),
        'reproduced witness WASM',
      ),
    });
    assertArtifactMatches(
      attestation.artifacts.r1cs,
      reproduced.r1cs,
      'R1CS',
    );
    assertArtifactMatches(
      attestation.artifacts.sym,
      reproduced.sym,
      'symbol file',
    );
    assertArtifactMatches(
      attestation.artifacts.wasm,
      reproduced.wasm,
      'witness WASM',
    );
    const reproducedAbi = await readReproducedR1csAbi(
      path.join(outputRoot, ...V2_BUILD_R1CS_PATH.split('/')),
    );
    assertAbiMatches(attestation.r1csAbi, reproducedAbi);

    const cliAfter = await stableFile(circomCli, 'pinned Circom CLI');
    if (
      cliAfter.bytes !== cliBefore.bytes
      || cliAfter.sha256 !== cliBefore.sha256
    ) {
      fail(
        'BUILD_REPRODUCTION_ARTIFACT_CHANGED',
        'pinned Circom CLI changed during reproduction',
      );
    }
    await verifyCircuitBuildAttestationAgainstRepository(
      buildAttestationBytes,
      {
        repositoryRoot: root,
        requireTrustedSigner,
        sourceManifestBytes,
        trustedDevelopmentSigners,
      },
    );
    return Object.freeze({
      attestation,
      elapsedMs,
      reproduced,
      r1csAbi: reproducedAbi,
      sourceManifestSha256: sha256(sourceManifestBytes),
    });
  } finally {
    await rm(temporary, {
      recursive: true,
      force: true,
      maxRetries: 1,
    });
  }
}
