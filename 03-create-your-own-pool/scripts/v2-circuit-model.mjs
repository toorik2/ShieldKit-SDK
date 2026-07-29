import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rename,
  rm,
} from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { readBinFile } from '@iden3/binfileutils';
import { readR1csHeader } from 'r1csfile';

import { buildDirectV2CircuitInput } from '../packages/action/v2/circuit-witness.mjs';
import { BN254_SCALAR_FIELD_MODULUS } from '../packages/action/v2/domains.mjs';
import {
  constructDirectV2Output,
  deriveDirectV2Address,
  recoverDirectV2Output,
} from '../packages/action/v2/notes.mjs';
import {
  applyDirectV2Transition,
  createDirectV2PoolModel,
  DIRECT_V2_DENOMINATION_SATS,
} from '../packages/action/v2/transition.mjs';
import {
  canonicalCircuitBuildAttestation,
  CIRCUIT_BUILD_ATTESTATION_SCHEMA,
  PINNED_CIRCOM2_PACKAGE_VERSION,
  PINNED_CIRCOM_COMPILER_VERSION,
} from '../packages/profile/v2/build-attestation.mjs';
import {
  collectNpmBuildClosure,
  verifyNpmBuildClosure,
} from '../packages/profile/v2/npm-closure.mjs';
import {
  canonicalV2RelationSourceManifest,
  collectV2RelationSourceManifest,
  verifyV2RelationSourceManifest,
} from '../packages/profile/v2/relation-source-manifest.mjs';
import {
  reproduceV2CircuitBuild,
} from '../packages/profile/v2/circuit-build-reproduction.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(SCRIPT_DIRECTORY, '../..');
export const DEFAULT_BUILD_DIRECTORY = path.join(
  PROJECT_ROOT,
  '.codex-build/v2-circuit-model',
);
export const CIRCOM2_PACKAGE_VERSION = PINNED_CIRCOM2_PACKAGE_VERSION;
export const CIRCOM_COMPILER_VERSION = PINNED_CIRCOM_COMPILER_VERSION;

const digest = (value) => createHash('sha256').update(value).digest('hex');
const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAXIMUM_LIVE_NOTES = 210_000_000n;

function mutatePacketAndRebind(input, mutate) {
  const packet = Buffer.from(input.packet);
  mutate(packet);
  const packetDigest = createHash('sha256').update(packet).digest();
  return {
    ...input,
    packet: Object.freeze([...packet]),
    publicInput0: BigInt(`0x${packetDigest.subarray(0, 16).toString('hex')}`)
      .toString(),
    publicInput1: BigInt(`0x${packetDigest.subarray(16).toString('hex')}`)
      .toString(),
  };
}

function deterministicRng(start) {
  let next = BigInt(start);
  return Object.freeze({
    bytes() {
      const value = next;
      next += 1n;
      return Uint8Array.from(Buffer.from(fr(value), 'hex'));
    },
  });
}

function spendMaterial(address, recovered) {
  return Object.freeze({
    spendSecret: fr(3),
    incomingViewPublicKey: address.incomingViewPublicKey,
    rho: recovered.rho,
    r: recovered.r,
    encryptedRecord: recovered.encryptedRecord,
  });
}

/**
 * Construct the deterministic in-memory deposit -> transfer -> withdrawal
 * fixture. This is circuit-model test evidence only: it uses no proving key,
 * BCH VM, transaction, or deployment artifact.
 */
export function buildDeterministicDirectV2Chain({
  profileId = digest('shieldkit-v2-circuit-model-profile'),
  instanceId = digest('shieldkit-v2-circuit-model-instance'),
  maximumLiveNotes = '4',
} = {}) {
  if (typeof profileId !== 'string' || !HEX_32.test(profileId)) {
    throw new TypeError('profileId must be 32 lowercase hexadecimal bytes');
  }
  if (typeof instanceId !== 'string' || !HEX_32.test(instanceId)) {
    throw new TypeError('instanceId must be 32 lowercase hexadecimal bytes');
  }
  if (
    typeof maximumLiveNotes !== 'string'
    || !DECIMAL.test(maximumLiveNotes)
    || BigInt(maximumLiveNotes) === 0n
    || BigInt(maximumLiveNotes) > MAXIMUM_LIVE_NOTES
  ) {
    throw new TypeError(
      'maximumLiveNotes must be canonical decimal in [1, 210000000]',
    );
  }
  const spendSecret = fr(3);
  const incomingViewSecret = fr(4);
  const denominationSats = DIRECT_V2_DENOMINATION_SATS.toString();
  const pool = createDirectV2PoolModel({
    profileId,
    maximumLiveNotes,
    denominationSats,
  });
  const address = deriveDirectV2Address({
    networkId: 2,
    profileId,
    instanceId,
    spendSecret,
    incomingViewSecret,
  });

  const firstOutput = constructDirectV2Output({
    address,
    postActionSequence: '1',
    rng: deterministicRng(5),
  });
  const deposit = applyDirectV2Transition({
    kind: 'deposit',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats,
    preState: pool.state,
    noteTree: pool.noteTree,
    nullifierTree: pool.nullifierTree,
    output: {
      outputNoteLeaf: firstOutput.public.outputNoteLeaf,
      encryptedRecord: firstOutput.public.encryptedRecord,
    },
    transactionContextHash: digest('shieldkit-v2-circuit-model-deposit-context'),
  });
  const depositInput = buildDirectV2CircuitInput({
    denominationSats,
    transition: deposit,
    output: firstOutput,
  });

  const firstNote = recoverDirectV2Output({
    account: { address, spendSecret, incomingViewSecret },
    outputNoteLeaf: firstOutput.public.outputNoteLeaf,
    encryptedRecord: firstOutput.public.encryptedRecord,
  });
  const secondOutput = constructDirectV2Output({
    address,
    postActionSequence: '2',
    rng: deterministicRng(8),
  });
  const transfer = applyDirectV2Transition({
    kind: 'transfer',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats,
    preState: deposit.state,
    noteTree: deposit.noteTree,
    nullifierTree: deposit.nullifierTree,
    spend: {
      inputNoteLeaf: firstOutput.public.outputNoteLeaf,
      noteIndex: '0',
      publicNullifier: firstNote.nullifier,
    },
    output: {
      outputNoteLeaf: secondOutput.public.outputNoteLeaf,
      encryptedRecord: secondOutput.public.encryptedRecord,
    },
    transactionContextHash: digest('shieldkit-v2-circuit-model-transfer-context'),
  });
  const transferInput = buildDirectV2CircuitInput({
    denominationSats,
    transition: transfer,
    spend: spendMaterial(address, firstNote),
    output: secondOutput,
  });

  const secondNote = recoverDirectV2Output({
    account: { address, spendSecret, incomingViewSecret },
    outputNoteLeaf: secondOutput.public.outputNoteLeaf,
    encryptedRecord: secondOutput.public.encryptedRecord,
  });
  const withdrawal = applyDirectV2Transition({
    kind: 'withdrawal',
    networkId: 2,
    profileId,
    instanceId,
    denominationSats,
    preState: transfer.state,
    noteTree: transfer.noteTree,
    nullifierTree: transfer.nullifierTree,
    spend: {
      inputNoteLeaf: secondOutput.public.outputNoteLeaf,
      noteIndex: '1',
      publicNullifier: secondNote.nullifier,
    },
    withdrawalLockingBytecodeHash: digest(
      'shieldkit-v2-circuit-model-withdrawal-lock',
    ),
    transactionContextHash: digest(
      'shieldkit-v2-circuit-model-withdrawal-context',
    ),
  });
  const withdrawalInput = buildDirectV2CircuitInput({
    denominationSats,
    transition: withdrawal,
    spend: spendMaterial(address, secondNote),
  });

  return Object.freeze({
    fixtureClass: 'deterministic-circuit-model-test-evidence',
    profileId,
    instanceId,
    maximumLiveNotes,
    actions: Object.freeze({
      deposit: Object.freeze({ transition: deposit, circuitInput: depositInput }),
      transfer: Object.freeze({ transition: transfer, circuitInput: transferInput }),
      withdrawal: Object.freeze({
        transition: withdrawal,
        circuitInput: withdrawalInput,
      }),
    }),
  });
}

function run(command, args, { cwd = PROJECT_ROOT } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: {},
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code, signal) => {
      const result = {
        code,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      if (code !== 0) {
        reject(new Error(
          `${command} failed (${code ?? signal}):\n${result.stdout}${result.stderr}`,
        ));
      } else {
        resolve(result);
      }
    });
  });
}

function metric(output, label) {
  const match = output.match(new RegExp(`^${label}:\\s*([0-9]+)(?:\\s|$)`, 'm'));
  if (match === null) throw new Error(`circom2 output omitted ${label}`);
  return Number(match[1]);
}

function sameFileIdentity(left, right) {
  return (
    left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
  );
}

async function stableArtifactEvidence(
  filename,
  logicalPath,
  { capture = false } = {},
) {
  const beforePath = await lstat(filename, { bigint: true });
  if (
    !beforePath.isFile()
    || beforePath.isSymbolicLink()
    || beforePath.nlink !== 1n
  ) {
    throw new Error(`${logicalPath} must be a unique regular non-symlink file`);
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(filename, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n) {
      throw new Error(`${logicalPath} has an unsafe file identity`);
    }
    const hasher = createHash('sha256');
    const chunks = capture ? [] : undefined;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hasher.update(chunk);
      chunks?.push(Buffer.from(chunk));
    }
    const after = await handle.stat({ bigint: true });
    const afterPath = await lstat(filename, { bigint: true });
    if (
      !sameFileIdentity(beforePath, before)
      || !sameFileIdentity(before, after)
      || !sameFileIdentity(after, afterPath)
    ) {
      throw new Error(`${logicalPath} changed while it was measured`);
    }
    const bytes = Number(after.size);
    if (!Number.isSafeInteger(bytes) || bytes <= 0) {
      throw new Error(`${logicalPath} has an invalid size`);
    }
    const result = {
      bytes,
      path: logicalPath,
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

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, fsConstants.O_RDONLY);
    await handle.sync();
  } finally {
    await handle?.close();
  }
}

async function newBuildStage(buildDirectory) {
  const repositoryRoot = await realpath(PROJECT_ROOT);
  if (repositoryRoot !== PROJECT_ROOT) {
    throw new Error('project root must be a canonical non-symlink directory');
  }
  const target = path.resolve(buildDirectory);
  if (
    target === repositoryRoot
    || !target.startsWith(`${repositoryRoot}${path.sep}`)
  ) {
    throw new Error('buildDirectory must be a child of the project root');
  }
  const parent = path.dirname(target);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  if (await realpath(parent) !== parent) {
    throw new Error('buildDirectory parent must not use symlink traversal');
  }
  try {
    await lstat(target);
    throw new Error('buildDirectory already exists; refusing stale overwrite');
  } catch (error) {
    if (
      error instanceof Error
      && error.message ===
        'buildDirectory already exists; refusing stale overwrite'
    ) {
      throw error;
    }
    if (error?.code !== 'ENOENT') throw error;
  }
  const stageRoot = await mkdtemp(path.join(parent, '.v2-circuit-stage-'));
  await chmod(stageRoot, 0o700);
  const output = path.join(stageRoot, 'output');
  const sources = path.join(stageRoot, 'source-snapshot');
  await mkdir(output, { mode: 0o700 });
  await mkdir(sources, { mode: 0o700 });
  return Object.freeze({
    output,
    parent,
    sources,
    stageRoot,
    target,
  });
}

async function copyRelationSnapshot(manifest, snapshotRoot) {
  for (const source of manifest.sources) {
    const sourcePath = path.join(PROJECT_ROOT, ...source.path.split('/'));
    const evidence = await stableArtifactEvidence(
      sourcePath,
      source.path,
      { capture: true },
    );
    if (
      evidence.bytes !== source.bytes
      || evidence.sha256 !== source.sha256
    ) {
      throw new Error(`relation source changed before snapshot: ${source.path}`);
    }
    const destination = path.join(snapshotRoot, ...source.path.split('/'));
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await writePrivateFile(destination, evidence.data);
  }
}

async function r1csAbi(filename) {
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
      || header.nPubInputs !== 2
      || header.nOutputs !== 0
      || header.useCustomGates !== false
    ) {
      throw new Error('compiled R1CS has an unexpected field or public ABI');
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

export async function compileDirectV2Circuit({
  buildDirectory = DEFAULT_BUILD_DIRECTORY,
} = {}) {
  const stage = await newBuildStage(buildDirectory);
  let published = false;
  try {
    const npmClosure = await collectNpmBuildClosure({
      repositoryRoot: PROJECT_ROOT,
      roots: ['node_modules/circom2'],
    });
    const circomPackage = npmClosure.packages.find(
      (entry) => entry.packagePath === 'node_modules/circom2',
    );
    const cliFile = circomPackage?.installed.files.find(
      (entry) => entry.path === 'cli.js',
    );
    const packageFile = circomPackage?.installed.files.find(
      (entry) => entry.path === 'package.json',
    );
    if (
      circomPackage?.lock.version !== CIRCOM2_PACKAGE_VERSION
      || cliFile === undefined
      || packageFile === undefined
    ) {
      throw new Error('pinned Circom package is absent from its npm closure');
    }
    const circomCli = path.join(PROJECT_ROOT, 'node_modules/circom2/cli.js');
    const circomPackageJson = path.join(
      PROJECT_ROOT,
      'node_modules/circom2/package.json',
    );
    const cliEvidence = await stableArtifactEvidence(
      circomCli,
      'node_modules/circom2/cli.js',
    );
    const packageEvidence = await stableArtifactEvidence(
      circomPackageJson,
      'node_modules/circom2/package.json',
      { capture: true },
    );
    if (
      cliEvidence.bytes !== cliFile.bytes
      || cliEvidence.sha256 !== cliFile.sha256
      || packageEvidence.bytes !== packageFile.bytes
      || packageEvidence.sha256 !== packageFile.sha256
    ) {
      throw new Error('Circom executable files differ from their npm closure');
    }
    let packageMetadata;
    try {
      packageMetadata = JSON.parse(packageEvidence.data.toString('utf8'));
    } catch {
      throw new Error('Circom package metadata is not JSON');
    }
    if (
      packageMetadata.name !== 'circom2'
      || packageMetadata.version !== CIRCOM2_PACKAGE_VERSION
    ) {
      throw new Error('Circom package metadata version is not pinned');
    }
    const relationManifest = await collectV2RelationSourceManifest({
      repositoryRoot: PROJECT_ROOT,
    });
    const canonicalRelation = canonicalV2RelationSourceManifest(
      relationManifest,
    );
    await copyRelationSnapshot(relationManifest, stage.sources);
    const snapshotCircuit = path.join(
      stage.sources,
      ...relationManifest.entrypoint.split('/'),
    );
    const version = await run(process.execPath, [
      circomCli,
      '--version',
    ]);
    const versionOutput = `${version.stdout}${version.stderr}`;
    if (
      !versionOutput.includes(`circom2 npm package ${CIRCOM2_PACKAGE_VERSION}`)
      || !versionOutput.includes(`circom compiler ${CIRCOM_COMPILER_VERSION}`)
    ) {
      throw new Error(`unexpected pinned circom2 version:\n${versionOutput}`);
    }
    const physicalArgs = [
      circomCli,
      snapshotCircuit,
      '--r1cs',
      '--wasm',
      '--sym',
      '--O1',
      '--sanity_check',
      '2',
      '--output',
      stage.output,
    ];
    const started = performance.now();
    const compiled = await run(process.execPath, physicalArgs);
    const elapsedMs = performance.now() - started;
    const output = `${compiled.stdout}${compiled.stderr}`;
    const constraints = Object.freeze({
      nonlinear: metric(output, 'non-linear constraints'),
      linear: metric(output, 'linear constraints'),
      total: (
        metric(output, 'non-linear constraints')
        + metric(output, 'linear constraints')
      ),
      publicInputs: metric(output, 'public inputs'),
      privateInputs: metric(output, 'private inputs'),
      publicOutputs: metric(output, 'public outputs'),
      wires: metric(output, 'wires'),
      labels: metric(output, 'labels'),
    });
    const r1csPath = path.join(stage.output, 'main-chipnet.r1cs');
    const wasmPath = path.join(
      stage.output,
      'main-chipnet_js/main-chipnet.wasm',
    );
    const symPath = path.join(stage.output, 'main-chipnet.sym');
    const abi = await r1csAbi(r1csPath);
    if (
      constraints.total !== abi.constraints
      || constraints.publicInputs !== abi.publicInputs
      || constraints.privateInputs !== abi.privateInputs
      || constraints.publicOutputs !== abi.publicOutputs
      || constraints.wires !== abi.wires
    ) {
      throw new Error('Circom report differs from the emitted R1CS header');
    }
    const artifacts = Object.freeze({
      r1cs: await stableArtifactEvidence(
        r1csPath,
        'main-chipnet.r1cs',
      ),
      sym: await stableArtifactEvidence(symPath, 'main-chipnet.sym'),
      wasm: await stableArtifactEvidence(
        wasmPath,
        'main-chipnet_js/main-chipnet.wasm',
      ),
    });
    const sourceManifestPath = path.join(
      stage.output,
      'relation-source-manifest.json',
    );
    await writePrivateFile(sourceManifestPath, canonicalRelation.bytes);
    const sourceManifest = await stableArtifactEvidence(
      sourceManifestPath,
      'relation-source-manifest.json',
    );
    if (
      sourceManifest.bytes !== canonicalRelation.bytes.byteLength
      || sourceManifest.sha256 !== canonicalRelation.sha256
    ) {
      throw new Error('written relation source manifest changed');
    }
    await verifyNpmBuildClosure(npmClosure, {
      repositoryRoot: PROJECT_ROOT,
    });
    await verifyV2RelationSourceManifest(relationManifest, {
      repositoryRoot: PROJECT_ROOT,
    });
    const logicalArgv = [
      'node_modules/circom2/cli.js',
      relationManifest.entrypoint,
      '--r1cs',
      '--wasm',
      '--sym',
      '--O1',
      '--sanity_check',
      '2',
      '--output',
      '$BUILD_OUTPUT',
    ];
    const attestation = canonicalCircuitBuildAttestation({
      schema: CIRCUIT_BUILD_ATTESTATION_SCHEMA,
      claims: Object.freeze({
        developmentOnly: true,
        production: false,
        release: false,
      }),
      compilation: Object.freeze({
        executable: 'process.execPath',
        node: Object.freeze({
          version: process.versions.node,
          modulesAbi: process.versions.modules,
        }),
        cli: cliEvidence,
        packageMetadata: Object.freeze({
          bytes: packageEvidence.bytes,
          path: packageEvidence.path,
          sha256: packageEvidence.sha256,
        }),
        circomPackageVersion: CIRCOM2_PACKAGE_VERSION,
        circomCompilerVersion: CIRCOM_COMPILER_VERSION,
        optimization: 'O1',
        sanityCheck: 2,
        argv: Object.freeze(logicalArgv),
      }),
      npmClosure,
      sourceManifest,
      artifacts,
      r1csAbi: abi,
    });
    const reproduction = await reproduceV2CircuitBuild({
      buildAttestationBytes: attestation.bytes,
      repositoryRoot: PROJECT_ROOT,
      sourceManifestBytes: canonicalRelation.bytes,
    });
    const attestationPath = path.join(
      stage.output,
      'circuit-build-attestation.json',
    );
    await writePrivateFile(attestationPath, attestation.bytes);
    const attestationEvidence = await stableArtifactEvidence(
      attestationPath,
      'circuit-build-attestation.json',
    );
    if (
      attestationEvidence.bytes !== attestation.bytes.byteLength
      || attestationEvidence.sha256 !== attestation.sha256
    ) {
      throw new Error('written circuit build attestation changed');
    }
    await syncDirectory(stage.output);
    try {
      await lstat(stage.target);
      throw new Error('buildDirectory appeared before atomic publication');
    } catch (error) {
      if (
        error instanceof Error
        && error.message ===
          'buildDirectory appeared before atomic publication'
      ) {
        throw error;
      }
      if (error?.code !== 'ENOENT') throw error;
    }
    await rename(stage.output, stage.target);
    published = true;
    await syncDirectory(stage.parent);
    return Object.freeze({
      command: Object.freeze({
        executable: 'process.execPath',
        argv: Object.freeze(logicalArgv),
        resolver: 'direct-pinned-npm-closure',
      }),
      compiler: Object.freeze({
        npmPackage: CIRCOM2_PACKAGE_VERSION,
        circom: CIRCOM_COMPILER_VERSION,
        optimization: 'O1',
        sanityCheck: 2,
      }),
      constraints,
      elapsedMs,
      buildDirectory: stage.target,
      r1cs: path.join(stage.target, 'main-chipnet.r1cs'),
      sym: path.join(stage.target, 'main-chipnet.sym'),
      wasm: path.join(
        stage.target,
        'main-chipnet_js/main-chipnet.wasm',
      ),
      witnessCalculator: path.join(
        stage.target,
        'main-chipnet_js/witness_calculator.js',
      ),
      relationSourceManifest: Object.freeze({
        ...sourceManifest,
        path: path.join(stage.target, sourceManifest.path),
      }),
      buildAttestation: Object.freeze({
        ...attestationEvidence,
        path: path.join(stage.target, attestationEvidence.path),
      }),
      reproduction: Object.freeze({
        elapsedMs: reproduction.elapsedMs,
        reproduced: reproduction.reproduced,
        r1csAbi: reproduction.r1csAbi,
        sourceManifestSha256: reproduction.sourceManifestSha256,
      }),
    });
  } finally {
    await rm(stage.stageRoot, {
      recursive: true,
      force: true,
      maxRetries: 1,
    });
    if (!published) {
      // `stage.target` is intentionally never removed here: if it appeared
      // concurrently, it is not owned by this invocation.
    }
  }
}

async function loadWitnessCalculator(compilation) {
  const temporaryParent = path.join(
    PROJECT_ROOT,
    '.codex-build/test-tmp',
  );
  await mkdir(temporaryParent, { recursive: true, mode: 0o700 });
  await chmod(temporaryParent, 0o700);
  const temporary = await mkdtemp(path.join(
    temporaryParent,
    'v2-witness-calculator-',
  ));
  try {
    const commonJsCalculator = path.join(
      temporary,
      'witness_calculator.cjs',
    );
    await copyFile(compilation.witnessCalculator, commonJsCalculator);
    const require = createRequire(import.meta.url);
    const builder = require(commonJsCalculator);
    return builder(await readFile(compilation.wasm));
  } finally {
    await rm(temporary, { recursive: true, force: true, maxRetries: 1 });
  }
}

async function calculate(calculator, name, input) {
  const started = performance.now();
  const witness = await calculator.calculateWitness(input, true);
  const elapsedMs = performance.now() - started;
  if (
    witness[0] !== 1n
    || witness[1] !== BigInt(input.publicInput0)
    || witness[2] !== BigInt(input.publicInput1)
  ) {
    throw new Error(`${name} witness public signals do not match its inputs`);
  }
  return Object.freeze({
    name,
    elapsedMs,
    witnessSignals: witness.length,
    publicInputs: Object.freeze([input.publicInput0, input.publicInput1]),
  });
}

async function expectMutationFailure(calculator, name, input) {
  const started = performance.now();
  try {
    await calculator.calculateWitness(input, true);
  } catch (error) {
    return Object.freeze({
      name,
      rejected: true,
      elapsedMs: performance.now() - started,
      error: error instanceof Error ? error.message.split('\n')[0] : String(error),
    });
  }
  throw new Error(`${name} unexpectedly produced a witness`);
}

export async function runDirectV2CircuitModelQualification(options) {
  const totalStarted = performance.now();
  const chain = buildDeterministicDirectV2Chain();
  const compilation = await compileDirectV2Circuit(options);
  const calculator = await loadWitnessCalculator(compilation);
  const witnesses = [];
  for (const [name, action] of Object.entries(chain.actions)) {
    witnesses.push(await calculate(calculator, name, action.circuitInput));
  }
  const mutations = [
    await expectMutationFailure(calculator, 'deposit-output-rho-blind', {
      ...chain.actions.deposit.circuitInput,
      outputRhoBlind: (
        BigInt(chain.actions.deposit.circuitInput.outputRhoBlind) + 1n
      ).toString(),
    }),
    await expectMutationFailure(calculator, 'transfer-spend-secret', {
      ...chain.actions.transfer.circuitInput,
      spendSk: (
        BigInt(chain.actions.transfer.circuitInput.spendSk) + 1n
      ).toString(),
    }),
    await expectMutationFailure(calculator, 'transfer-spend-record-tag', {
      ...chain.actions.transfer.circuitInput,
      spendRecordTag: (
        BigInt(chain.actions.transfer.circuitInput.spendRecordTag) + 1n
      ).toString(),
    }),
    await expectMutationFailure(
      calculator,
      'transfer-nullifier-successor-index-fr-alias',
      {
        ...chain.actions.transfer.circuitInput,
        nullifierSuccessorIndex: (
          BN254_SCALAR_FIELD_MODULUS - (1n << 32n) + 2n
        ).toString(),
      },
    ),
    await expectMutationFailure(calculator, 'withdrawal-public-input', {
      ...chain.actions.withdrawal.circuitInput,
      publicInput0: (
        BigInt(chain.actions.withdrawal.circuitInput.publicInput0) + 1n
      ).toString(),
    }),
    await expectMutationFailure(
      calculator,
      'deposit-noncanonical-pre-note-root-with-rebound-digest',
      mutatePacketAndRebind(chain.actions.deposit.circuitInput, (packet) => {
        Buffer.from(
          BN254_SCALAR_FIELD_MODULUS.toString(16).padStart(64, '0'),
          'hex',
        ).copy(packet, 76);
      }),
    ),
    await expectMutationFailure(
      calculator,
      'deposit-noncanonical-output-leaf-with-rebound-digest',
      mutatePacketAndRebind(chain.actions.deposit.circuitInput, (packet) => {
        Buffer.from(
          BN254_SCALAR_FIELD_MODULUS.toString(16).padStart(64, '0'),
          'hex',
        ).copy(packet, 328);
      }),
    ),
    await expectMutationFailure(
      calculator,
      'deposit-ephemeral-byte-with-rebound-digest',
      mutatePacketAndRebind(chain.actions.deposit.circuitInput, (packet) => {
        packet[360] ^= 1;
      }),
    ),
    await expectMutationFailure(
      calculator,
      'deposit-record-tag-byte-with-rebound-digest',
      mutatePacketAndRebind(chain.actions.deposit.circuitInput, (packet) => {
        packet[487] ^= 1;
      }),
    ),
  ];
  return Object.freeze({
    evidenceClass: 'deterministic-circuit-model-test-evidence-only',
    qualificationClaims: Object.freeze({
      finalKey: false,
      bchVm: false,
      production: false,
    }),
    compilation,
    chain: Object.freeze(Object.fromEntries(
      Object.entries(chain.actions).map(([name, action]) => [name, Object.freeze({
        packetDigest: action.transition.packetDigest,
        postState: action.transition.state,
      })]),
    )),
    witnesses: Object.freeze(witnesses),
    mutations: Object.freeze(mutations),
    totalElapsedMs: performance.now() - totalStarted,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const result = await runDirectV2CircuitModelQualification();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
