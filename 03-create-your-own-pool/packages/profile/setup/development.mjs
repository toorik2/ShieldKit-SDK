import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants as fsConstants, fstat, readSync } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rename,
  rm,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { readBinFile } from '@iden3/binfileutils';
import { readR1csHeader } from 'r1csfile';
import { canonicalJson } from '../load.mjs';
import {
  canonicalDevelopmentSetupAttestation,
  DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
  verifyCircuitBuildAttestationAgainstRepository,
  verifyDevelopmentSetupAttestationPair,
} from '../v2/build-attestation.mjs';
import {
  collectNpmBuildClosure,
  verifyNpmBuildClosure,
} from '../v2/npm-closure.mjs';
import {
  reproduceV2CircuitBuild,
} from '../v2/circuit-build-reproduction.mjs';

export const SNARKJS_VERSION = '0.7.6';
export const ENTROPY_DOMAIN =
  DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN;
const INITIALIZER_DOMAIN = 'shield.cash/local-development-initializer/v1\0';
const MAX_ENTROPY_BYTES = 4096;
const MIN_ENTROPY_BYTES = 32;
const HASH = /^sha256:[0-9a-f]{64}$/;
const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const snarkjsRoot = path.dirname(fileURLToPath(import.meta.resolve('snarkjs')));
const snarkjsCliPath = path.join(snarkjsRoot, 'build', 'cli.cjs');
const snarkjsPackagePath = path.join(snarkjsRoot, 'package.json');
const fstatAsync = promisify(fstat);

/**
 * Well-known Phase-1 ptau pins for development-only.
 * The policy helper can classify a hash-only development pin, but the V2
 * setup producer below always runs full `snarkjs powersoftau verify`.
 */
export const TRUSTED_DEVELOPMENT_PTAU = Object.freeze({
  'hermez-powersOfTau28_hez_final_20': Object.freeze({
    source: 'hermez-powersOfTau28_hez_final_20',
    sha256: 'sha256:159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd',
    power: 20,
    note: 'Hermez / Perpetual Powers of Tau final_20 (community-distributed). Not a ShieldKit ceremony.',
  }),
});

export class LocalSetupError extends Error {
  constructor(message) { super(message); this.name = 'LocalSetupError'; }
}

const fail = (message) => { throw new LocalSetupError(message); };
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const sha256Parts = (...parts) => {
  const hasher = createHash('sha256');
  for (const part of parts) hasher.update(part);
  return `sha256:${hasher.digest('hex')}`;
};
const hash = (value, label) => {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} must be a lowercase sha256 identifier`);
  return value;
};
const text = (value, label) => {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`);
  return value;
};
const exactKeys = (value, label, keys) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown properties`);
};

async function regularFile(sourcePath, label) {
  const requested = path.resolve(text(sourcePath, label));
  const details = await lstat(requested).catch(() => fail(`${label} does not exist`));
  if (!details.isFile() || details.isSymbolicLink() || details.nlink !== 1) {
    fail(`${label} must be a unique regular non-symlink file`);
  }
  const resolved = await realpath(requested).catch(() => fail(`${label} cannot be resolved`));
  if (resolved !== requested) fail(`${label} must not use symlinks`);
  return resolved;
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
  );
}

async function measureFile(file, label, { capture = false } = {}) {
  const requested = path.resolve(file);
  const beforePath = await lstat(requested, { bigint: true }).catch(() =>
    fail(`${label} does not exist`));
  if (
    !beforePath.isFile()
    || beforePath.isSymbolicLink()
    || beforePath.nlink !== 1n
  ) {
    fail(`${label} must be a unique regular non-symlink file`);
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(requested, flags);
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n) {
      fail(`${label} has an unsafe file identity`);
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
    const afterPath = await lstat(requested, { bigint: true });
    if (
      !sameIdentity(beforePath, before)
      || !sameIdentity(before, after)
      || !sameIdentity(after, afterPath)
    ) {
      fail(`${label} changed while it was measured`);
    }
    const bytes = Number(after.size);
    if (!Number.isSafeInteger(bytes) || bytes <= 0) {
      fail(`${label} has an invalid size`);
    }
    const evidence = {
      bytes,
      sha256: `sha256:${hasher.digest('hex')}`,
    };
    if (capture) evidence.data = Buffer.concat(chunks, bytes);
    return Object.freeze(evidence);
  } finally {
    await handle?.close();
  }
}

/** Stream artifact hashes: ptau and zkey files are deliberately not buffered. */
export async function hashFileStreaming(file) {
  return (await measureFile(file, 'artifact')).sha256;
}

const digestFile = hashFileStreaming;

async function readPtauCapacity(ptauPath) {
  const { fd, sections } = await readBinFile(ptauPath, 'ptau', 1, 1 << 22, 1 << 24);
  try {
    if (!sections[1] || sections[1].length !== 1) fail('ptau has no unique header section');
    const section = sections[1][0]; fd.pos = section.p;
    const fieldBytes = await fd.readULE32(); await fd.read(fieldBytes);
    const power = await fd.readULE32(); const ceremonyPower = await fd.readULE32();
    if (fd.pos - section.p !== section.size) fail('ptau header length is invalid');
    return { power, ceremonyPower };
  } finally {
    await fd.close();
  }
}

async function readR1csCapacity(r1csPath) {
  const { fd, sections } = await readBinFile(r1csPath, 'r1cs', 1, 1 << 22, 1 << 24);
  try {
    // Header inspection does not use curve arithmetic. Keep ffjavascript in
    // single-thread mode so a metadata read cannot leave a worker pool alive.
    const header = await readR1csHeader(fd, sections, true);
    const terms = header.nConstraints + header.nPubInputs + header.nOutputs;
    const requiredPower = Math.ceil(Math.log2(terms + 1));
    return {
      nConstraints: header.nConstraints,
      nPrivateInputs: header.nPrvInputs,
      nPublicInputs: header.nPubInputs,
      nOutputs: header.nOutputs,
      nWires: header.nVars,
      requiredPower,
    };
  } finally {
    await fd.close();
  }
}

function commandLabel(args) {
  return args.slice(0, 2).join(' ');
}

function phase(message) {
  process.stderr.write(`[shieldkit setup] ${message}\n`);
}

/**
 * Resolve ptau verification policy for development-only setup.
 * @returns {{ mode: 'hash-only'|'full', trusted: object|null, reason: string }}
 */
export function resolveDevelopmentPtauVerification({
  ptauSource,
  ptauSha256,
  expectedPtauPower,
  verifyPtau,
}) {
  const trusted = TRUSTED_DEVELOPMENT_PTAU[ptauSource] ?? null;
  const pinEligible = Boolean(
    trusted
    && trusted.sha256 === ptauSha256
    && trusted.power === expectedPtauPower,
  );

  if (verifyPtau === true) {
    return {
      mode: 'full',
      trusted,
      reason: pinEligible
        ? 'verifyPtau=true: full snarkjs powersoftau verify forced despite trusted pin'
        : 'verifyPtau=true: full snarkjs powersoftau verify required',
    };
  }
  if (verifyPtau === false) {
    if (!pinEligible) {
      fail(
        'verifyPtau=false (hash-only) requires ptauSource + expectedPtauSha256 + power '
          + 'to match a TRUSTED_DEVELOPMENT_PTAU pin (e.g. hermez-powersOfTau28_hez_final_20); '
          + 'unknown ptau must use full verify (omit verifyPtau or set verifyPtau=true)',
      );
    }
    return {
      mode: 'hash-only',
      trusted,
      reason: 'verifyPtau=false: hash-only against trusted development pin',
    };
  }
  // default: hash-only when pin-eligible, else full verify
  if (pinEligible) {
    return {
      mode: 'hash-only',
      trusted,
      reason: 'default: trusted Hermez/final pin + SHA-256 match → skip multi-hour powersoftau verify',
    };
  }
  return {
    mode: 'full',
    trusted: null,
    reason: 'default: ptau is not a known development pin → full snarkjs powersoftau verify',
  };
}

async function runPinnedSnarkjs(args, { cwd, entropy = undefined, capture = false, label = undefined } = {}) {
  const options = { cwd, env: {}, windowsHide: true, maxBuffer: 1024 * 1024 };
  if (capture && entropy !== undefined) fail('captured snarkjs commands cannot receive entropy');
  if (capture) {
    return new Promise((resolve, reject) => {
      execFile(process.execPath, [snarkjsCliPath, ...args], options, (error, stdout) => {
        // snarkjs 0.7.6 prints its version then usage and exits 99. This is
        // its documented CLI behavior, not a successful setup command.
        if (error && !(args.length === 1 && args[0] === '--version' && error.code === 99)) reject(new LocalSetupError(`snarkjs command failed: ${commandLabel(args)}`));
        else resolve(String(stdout));
      });
    });
  }
  const started = Date.now();
  phase(`start snarkjs ${label ?? commandLabel(args)} …`);
  await new Promise((resolve, reject) => {
    const child = execFile(process.execPath, [snarkjsCliPath, ...args], options);
    let settled = false; let suppliedEntropy = false; let output = ''; let entropyTransport;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      entropyTransport?.fill(0);
      if (error) reject(error); else resolve();
    };
    // Stream snarkjs output so multi-minute/hour work is visible (progress honesty).
    child.stdout?.on('data', (chunk) => {
      process.stderr.write(chunk);
      if (entropy === undefined || suppliedEntropy) return;
      output = `${output}${String(chunk)}`.slice(-512);
      if (output.includes('Enter a random text. (Entropy):')) {
        suppliedEntropy = true;
        // The newline is a readline transport delimiter, not part of entropy.
        entropyTransport = Buffer.allocUnsafe(entropy.length + 1);
        entropy.copy(entropyTransport); entropyTransport[entropy.length] = 0x0a;
        child.stdin.end(entropyTransport);
      }
    });
    child.stderr?.on('data', (chunk) => {
      process.stderr.write(chunk);
    });
    child.on('error', () => finish(new LocalSetupError(`snarkjs command failed: ${commandLabel(args)}`)));
    child.on('close', (code) => {
      if (code !== 0) finish(new LocalSetupError(`snarkjs command failed: ${commandLabel(args)}`));
      else if (entropy !== undefined && !suppliedEntropy) finish(new LocalSetupError(`snarkjs contribution did not request entropy: ${commandLabel(args)}`));
      else finish();
    });
    if (entropy === undefined) child.stdin.end();
  });
  phase(`done snarkjs ${label ?? commandLabel(args)} (${((Date.now() - started) / 1000).toFixed(1)}s)`);
}

async function pinnedSnarkjsInfo(expected) {
  exactKeys(expected, 'expected snarkjs', ['cliSha256', 'version']);
  if (expected.version !== SNARKJS_VERSION) fail(`expected snarkjs version must be ${SNARKJS_VERSION}`);
  const cli = await regularFile(snarkjsCliPath, 'pinned snarkjs CLI');
  const cliSha256 = await digestFile(cli);
  if (hash(expected.cliSha256, 'expected snarkjs CLI hash') !== cliSha256) fail('pinned snarkjs CLI hash mismatch');
  const packagePath = await regularFile(snarkjsPackagePath, 'pinned snarkjs package metadata');
  const packageData = JSON.parse(await readFile(packagePath, 'utf8'));
  if (packageData.version !== SNARKJS_VERSION) fail('pinned snarkjs package version drift');
  const versionOutput = await runPinnedSnarkjs(['--version'], { capture: true });
  if (!versionOutput.includes(`snarkjs@${SNARKJS_VERSION}`)) fail('pinned snarkjs command version drift');
  return { name: 'snarkjs', version: SNARKJS_VERSION, sha256: cliSha256 };
}

async function collectEntropy(source) {
  if (source === null || Array.isArray(source) || typeof source !== 'object') fail('entropy source must be an object');
  exactKeys(source, 'entropy source', ['kind', ...(source.kind === 'fd' ? ['fd'] : [])]);
  let readable;
  if (source.kind === 'stdin') {
    readable = process.stdin;
  } else if (source.kind === 'fd') {
    if (!Number.isInteger(source.fd) || source.fd < 0) fail('entropy fd must be a non-negative integer');
    const details = await fstatAsync(source.fd).catch(() => fail('entropy fd cannot be inspected'));
    if (!details.isFile() || (details.mode & 0o077) !== 0) fail('entropy fd must reference a private regular file');
    // The fd is caller-owned. A temporary ReadStream either retains an active
    // event-loop handle or closes the fd when explicitly destroyed. Entropy is
    // bounded to 4096 bytes, so read it synchronously without creating a
    // libuv-backed handle and leave ownership unchanged.
    const scratch = Buffer.allocUnsafe(MAX_ENTROPY_BYTES + 1); let size = 0;
    try {
      while (size < scratch.length) {
        const bytesRead = readSync(source.fd, scratch, size, scratch.length - size, null);
        if (bytesRead === 0) break;
        size += bytesRead;
      }
      if (size > MAX_ENTROPY_BYTES) fail(`entropy exceeds ${MAX_ENTROPY_BYTES} bytes`);
      const entropy = Buffer.allocUnsafe(size);
      scratch.copy(entropy, 0, 0, size);
      return validateEntropy(entropy);
    } catch (error) {
      throw error instanceof LocalSetupError ? error : new LocalSetupError('entropy fd cannot be read');
    } finally {
      scratch.fill(0);
    }
  } else {
    fail('entropy source kind must be stdin or fd');
  }
  const chunks = []; let size = 0;
  try {
    for await (const chunk of readable) {
      const bytes = Buffer.from(chunk); size += bytes.length;
      if (size > MAX_ENTROPY_BYTES) { bytes.fill(0); fail(`entropy exceeds ${MAX_ENTROPY_BYTES} bytes`); }
      chunks.push(bytes);
    }
  } catch (error) {
    for (const chunk of chunks) chunk.fill(0);
    throw error;
  }
  const entropy = Buffer.allocUnsafe(size); let offset = 0;
  for (const chunk of chunks) { chunk.copy(entropy, offset); offset += chunk.length; chunk.fill(0); }
  return validateEntropy(entropy);
}

function validateEntropy(entropy) {
  if (entropy.length < MIN_ENTROPY_BYTES) { entropy.fill(0); fail(`entropy must contain at least ${MIN_ENTROPY_BYTES} bytes`); }
  try { new TextDecoder('utf-8', { fatal: true }).decode(entropy); }
  catch { entropy.fill(0); fail('entropy must be UTF-8 text'); }
  if (entropy.includes(0x0a) || entropy.includes(0x0d)) { entropy.fill(0); fail('entropy must not contain line breaks'); }
  return entropy;
}

function safeDestination(destination) {
  return path.resolve(text(destination, 'destination'));
}

async function assertNewDestination(destination) {
  const requestedParent = path.dirname(destination);
  const parent = await realpath(requestedParent).catch(() => fail('destination parent directory does not exist'));
  if (parent !== requestedParent) fail('destination parent directory must not use symlinks');
  const target = path.join(parent, path.basename(destination));
  try { await lstat(target); fail('destination already exists; refusing overwrite'); }
  catch (error) {
    if (error instanceof LocalSetupError) throw error;
    if (error?.code !== 'ENOENT') fail('destination cannot be inspected safely');
  }
  return target;
}

async function createSetupStage(destination) {
  const target = await assertNewDestination(destination);
  const parent = path.dirname(target);
  const stage = await mkdtemp(path.join(parent, '.shieldkit-setup-stage-'));
  await chmod(stage, 0o700);
  return Object.freeze({ parent, stage, target });
}

async function writePrivateBytes(filename, bytes) {
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

function bareHash(value, label) {
  return hash(value, label).slice('sha256:'.length);
}

function attestationArtifact(pathname, evidence) {
  return Object.freeze({
    bytes: evidence.bytes,
    path: pathname,
    sha256: bareHash(evidence.sha256, `${pathname} hash`),
  });
}

/** Recheck direct-file identity and hashes before publishing setup metadata. */
export async function assertUnchangedSetupInputs({ r1csPath, ptauPath, r1csSha256, ptauSha256 }) {
  const currentR1csPath = await regularFile(r1csPath, 'r1cs path');
  const currentPtauPath = await regularFile(ptauPath, 'ptau path');
  if (currentR1csPath !== r1csPath || currentPtauPath !== ptauPath) fail('setup input path drift detected');
  if (await digestFile(currentR1csPath) !== r1csSha256) fail('r1cs changed during setup');
  if (await digestFile(currentPtauPath) !== ptauSha256) fail('ptau changed during setup');
}

function logicalCommandRecord(args) {
  return Object.freeze({
    executable: 'process.execPath',
    argv: Object.freeze([
      'node_modules/snarkjs/build/cli.cjs',
      ...args,
    ]),
  });
}

/**
 * Execute one fully attested, development-only Groth16 Phase-2 contribution.
 * The entropy is supplied only through inherited stdin or an already-open
 * private fd and is never placed in argv, metadata, logs, or an environment
 * dump. This path always performs full PTau and final-zkey verification.
 */
export async function initializeDevelopmentGroth16(input) {
  if (input === null || Array.isArray(input) || typeof input !== 'object') fail('local setup input must be an object');
  const required = [
    'buildAttestationPath', 'destination', 'entropySource',
    'expectedPtauPower', 'expectedPtauSha256', 'expectedR1csSha256',
    'expectedSnarkjs', 'ptauPath', 'ptauSource', 'repositoryRoot', 'r1csPath',
    'sourceManifestPath',
  ];
  for (const key of required) {
    if (!Object.hasOwn(input, key)) fail(`local setup input missing ${key}`);
  }
  for (const key of Object.keys(input)) {
    if (!required.includes(key) && key !== 'verifyPtau') {
      fail(`local setup input has unknown property: ${key}`);
    }
  }
  if (Object.hasOwn(input, 'verifyPtau') && input.verifyPtau !== true) {
    fail('the attested V2 setup path requires verifyPtau=true');
  }
  if (!Number.isInteger(input.expectedPtauPower) || input.expectedPtauPower < 1 || input.expectedPtauPower > 28) fail('expected ptau power must be an integer from 1 to 28');
  const ptauSource = text(input.ptauSource, 'ptau source');
  const requestedRoot = path.resolve(text(input.repositoryRoot, 'repository root'));
  const repositoryRoot = await realpath(requestedRoot).catch(() =>
    fail('repository root cannot be resolved'));
  const rootMetadata = await lstat(requestedRoot);
  if (
    repositoryRoot !== requestedRoot
    || !rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
  ) {
    fail('repository root must be a canonical non-symlink directory');
  }
  const buildAttestationPath = await regularFile(
    input.buildAttestationPath,
    'circuit build attestation',
  );
  const buildAttestationEvidence = await measureFile(
    buildAttestationPath,
    'circuit build attestation',
    { capture: true },
  );
  const sourceManifestPath = await regularFile(
    input.sourceManifestPath,
    'relation source manifest',
  );
  const sourceManifestEvidence = await measureFile(
    sourceManifestPath,
    'relation source manifest',
    { capture: true },
  );
  let buildAttestation;
  try {
    buildAttestation =
      await verifyCircuitBuildAttestationAgainstRepository(
        buildAttestationEvidence.data,
        {
          repositoryRoot,
          sourceManifestBytes: sourceManifestEvidence.data,
        },
      );
  } catch (error) {
    fail(`circuit build attestation is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  try {
    await reproduceV2CircuitBuild({
      buildAttestationBytes: buildAttestationEvidence.data,
      repositoryRoot,
      sourceManifestBytes: sourceManifestEvidence.data,
    });
  } catch (error) {
    fail(`circuit build cannot be independently reproduced: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  phase('hashing r1cs + ptau (streaming) …');
  const r1csPath = await regularFile(input.r1csPath, 'r1cs path'); const ptauPath = await regularFile(input.ptauPath, 'ptau path');
  const r1cs = await readR1csCapacity(r1csPath);
  if (r1cs.nPublicInputs !== 2 || r1cs.nOutputs !== 0) fail('r1cs must use the shield.cash ABI: exactly 2 public inputs and 0 outputs');
  const r1csEvidence = await measureFile(r1csPath, 'r1cs');
  const ptauEvidence = await measureFile(ptauPath, 'ptau');
  const r1csSha256 = r1csEvidence.sha256;
  const ptauSha256 = ptauEvidence.sha256;
  phase(`r1cs sha256 ${r1csSha256}`);
  phase(`ptau sha256 ${ptauSha256}`);
  if (hash(input.expectedR1csSha256, 'expected r1cs hash') !== r1csSha256) fail('r1cs hash mismatch');
  if (hash(input.expectedPtauSha256, 'expected ptau hash') !== ptauSha256) fail('ptau hash mismatch');
  if (
    buildAttestation.artifacts.r1cs.bytes !== r1csEvidence.bytes
    || buildAttestation.artifacts.r1cs.sha256
      !== bareHash(r1csSha256, 'r1cs hash')
    || buildAttestation.r1csAbi.constraints !== r1cs.nConstraints
    || buildAttestation.r1csAbi.privateInputs !== r1cs.nPrivateInputs
    || buildAttestation.r1csAbi.publicInputs !== r1cs.nPublicInputs
    || buildAttestation.r1csAbi.publicOutputs !== r1cs.nOutputs
    || buildAttestation.r1csAbi.wires !== r1cs.nWires
  ) {
    fail('r1cs or its ABI differs from the circuit build attestation');
  }
  const ptau = await readPtauCapacity(ptauPath);
  if (ptau.power !== input.expectedPtauPower) fail('ptau power mismatch');
  if (ptau.power < r1cs.requiredPower) fail('ptau power is insufficient for r1cs capacity');
  const snarkjs = await pinnedSnarkjsInfo(input.expectedSnarkjs);
  const snarkjsClosure = await collectNpmBuildClosure({
    repositoryRoot,
    roots: ['node_modules/snarkjs'],
  });
  const snarkjsPackage = snarkjsClosure.packages.find(
    (entry) => entry.packagePath === 'node_modules/snarkjs',
  );
  const closureCli = snarkjsPackage?.installed.files.find(
    (entry) => entry.path === 'build/cli.cjs',
  );
  const closurePackage = snarkjsPackage?.installed.files.find(
    (entry) => entry.path === 'package.json',
  );
  const snarkjsCliEvidence = await measureFile(
    snarkjsCliPath,
    'pinned snarkjs CLI',
  );
  const snarkjsPackageEvidence = await measureFile(
    snarkjsPackagePath,
    'pinned snarkjs package metadata',
    { capture: true },
  );
  let snarkjsPackageMetadata;
  try {
    snarkjsPackageMetadata = JSON.parse(
      snarkjsPackageEvidence.data.toString('utf8'),
    );
  } catch {
    fail('pinned snarkjs package metadata is not JSON');
  }
  if (
    snarkjsPackage?.lock.version !== SNARKJS_VERSION
    || snarkjsPackageMetadata.name !== 'snarkjs'
    || snarkjsPackageMetadata.version !== SNARKJS_VERSION
    || closureCli?.bytes !== snarkjsCliEvidence.bytes
    || closureCli?.sha256 !== bareHash(
      snarkjsCliEvidence.sha256,
      'snarkjs CLI hash',
    )
    || closurePackage?.bytes !== snarkjsPackageEvidence.bytes
    || closurePackage?.sha256 !== bareHash(
      snarkjsPackageEvidence.sha256,
      'snarkjs package metadata hash',
    )
    || snarkjs.sha256 !== snarkjsCliEvidence.sha256
  ) {
    fail('pinned snarkjs files differ from their complete npm closure');
  }
  const destination = safeDestination(input.destination);
  await assertNewDestination(destination);
  phase('ptau: full snarkjs powersoftau verify …');
  await runPinnedSnarkjs(
    ['powersoftau', 'verify', ptauPath],
    { label: 'powersoftau verify' },
  );
  const ptauVerificationRecord = Object.freeze({
    mode: 'full',
    snarkjsPowersoftauVerify: true,
    measuredSha256: ptauSha256,
    reason: 'mandatory full verification for V2 setup attestation',
  });

  let entropy;
  let stage;
  let published = false;
  try {
    stage = await createSetupStage(destination);
    entropy = await collectEntropy(input.entropySource);
    const randomnessCommitment = sha256Parts(ENTROPY_DOMAIN, entropy);
    const initializerCommitment = sha256(Buffer.from(`${INITIALIZER_DOMAIN}${r1csSha256}\0${ptauSha256}\0${randomnessCommitment}`, 'utf8'));
    const initialZkey = path.join(stage.stage, 'initial.zkey');
    const finalZkey = path.join(stage.stage, 'final.zkey');
    const verificationKey = path.join(stage.stage, 'verification_key.json');
    const setupArgs = ['groth16', 'setup', r1csPath, ptauPath, initialZkey];
    const contributeArgs = ['zkey', 'contribute', initialZkey, finalZkey];
    await runPinnedSnarkjs(setupArgs, {
      cwd: stage.stage,
      label: 'groth16 setup',
    });
    await chmod(initialZkey, 0o600);
    const initialZkeyEvidence = await measureFile(
      initialZkey,
      'initial zkey',
    );
    await runPinnedSnarkjs(contributeArgs, {
      cwd: stage.stage,
      entropy,
      label: 'zkey contribute',
    });
    await chmod(finalZkey, 0o600);
    const finalZkeyEvidence = await measureFile(finalZkey, 'final zkey');
    if (initialZkeyEvidence.sha256 === finalZkeyEvidence.sha256) {
      fail('snarkjs contribution did not change the zkey');
    }
    await runPinnedSnarkjs(
      ['zkey', 'verify', r1csPath, ptauPath, finalZkey],
      { cwd: stage.stage, label: 'zkey verify' },
    );
    await runPinnedSnarkjs(
      [
        'zkey',
        'export',
        'verificationkey',
        finalZkey,
        verificationKey,
      ],
      { cwd: stage.stage, label: 'export verification key' },
    );
    await chmod(verificationKey, 0o600);
    const verificationKeyEvidence = await measureFile(
      verificationKey,
      'verification key',
    );
    const finalZkeySha256 = finalZkeyEvidence.sha256;
    const verificationKeySha256 = verificationKeyEvidence.sha256;
    await assertUnchangedSetupInputs({ r1csPath, ptauPath, r1csSha256, ptauSha256 });
    const finalBuildEvidence = await measureFile(
      buildAttestationPath,
      'circuit build attestation',
      { capture: true },
    );
    const finalSourceManifestEvidence = await measureFile(
      sourceManifestPath,
      'relation source manifest',
      { capture: true },
    );
    if (
      finalBuildEvidence.bytes !== buildAttestationEvidence.bytes
      || finalBuildEvidence.sha256 !== buildAttestationEvidence.sha256
      || !finalBuildEvidence.data.equals(buildAttestationEvidence.data)
    ) {
      fail('circuit build attestation changed during setup');
    }
    if (
      finalSourceManifestEvidence.bytes !== sourceManifestEvidence.bytes
      || finalSourceManifestEvidence.sha256 !== sourceManifestEvidence.sha256
      || !finalSourceManifestEvidence.data.equals(sourceManifestEvidence.data)
    ) {
      fail('relation source manifest changed during setup');
    }
    await verifyCircuitBuildAttestationAgainstRepository(
      finalBuildEvidence.data,
      {
        repositoryRoot,
        sourceManifestBytes: finalSourceManifestEvidence.data,
      },
    );
    await verifyNpmBuildClosure(snarkjsClosure, { repositoryRoot });
    const developmentAttestation =
      canonicalDevelopmentSetupAttestation({
        schema: DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
        claims: Object.freeze({
          contributionIndependence: 'not-established',
          developmentOnly: true,
          externalTranscript: false,
          finalCeremony: false,
          production: false,
          release: false,
        }),
        buildAttestation: attestationArtifact(
          'circuit-build-attestation.json',
          finalBuildEvidence,
        ),
        r1cs: attestationArtifact(
          buildAttestation.artifacts.r1cs.path,
          r1csEvidence,
        ),
        ptau: Object.freeze({
          source: ptauSource,
          artifact: attestationArtifact(
            'powers-of-tau.ptau',
            ptauEvidence,
          ),
          power: ptau.power,
          ceremonyPower: ptau.ceremonyPower,
          verified: true,
        }),
        snarkjs: Object.freeze({
          version: SNARKJS_VERSION,
          node: Object.freeze({
            version: process.versions.node,
            modulesAbi: process.versions.modules,
          }),
          cli: attestationArtifact(
            'node_modules/snarkjs/build/cli.cjs',
            snarkjsCliEvidence,
          ),
          packageMetadata: attestationArtifact(
            'node_modules/snarkjs/package.json',
            snarkjsPackageEvidence,
          ),
          npmClosure: snarkjsClosure,
        }),
        commands: Object.freeze({
          powersOfTauVerify: Object.freeze([
            'node_modules/snarkjs/build/cli.cjs',
            'powersoftau',
            'verify',
            '$PTAU',
          ]),
          setup: Object.freeze([
            'node_modules/snarkjs/build/cli.cjs',
            'groth16',
            'setup',
            '$R1CS',
            '$PTAU',
            '$INITIAL_ZKEY',
          ]),
          contribute: Object.freeze([
            'node_modules/snarkjs/build/cli.cjs',
            'zkey',
            'contribute',
            '$INPUT_ZKEY',
            '$OUTPUT_ZKEY',
          ]),
          verifyFinalZkey: Object.freeze([
            'node_modules/snarkjs/build/cli.cjs',
            'zkey',
            'verify',
            '$R1CS',
            '$PTAU',
            '$FINAL_ZKEY',
          ]),
          exportVerificationKey: Object.freeze([
            'node_modules/snarkjs/build/cli.cjs',
            'zkey',
            'export',
            'verificationkey',
            '$FINAL_ZKEY',
            '$VERIFICATION_KEY',
          ]),
        }),
        zkeyChain: Object.freeze({
          initial: attestationArtifact(
            'initial.zkey',
            initialZkeyEvidence,
          ),
          contributions: Object.freeze([
            Object.freeze({
              sequence: 1,
              inputZkeySha256: bareHash(
                initialZkeyEvidence.sha256,
                'initial zkey hash',
              ),
              output: attestationArtifact(
                'final.zkey',
                finalZkeyEvidence,
              ),
              entropyCommitmentDomain: ENTROPY_DOMAIN,
              entropyCommitment: bareHash(
                randomnessCommitment,
                'entropy commitment',
              ),
            }),
          ]),
        }),
        finalEvidence: Object.freeze({
          finalZkeySha256: bareHash(
            finalZkeySha256,
            'final zkey hash',
          ),
          finalZkeyVerified: true,
          verificationKeyExported: true,
          verificationKey: attestationArtifact(
            'verification_key.json',
            verificationKeyEvidence,
          ),
        }),
      });
    await writePrivateBytes(
      path.join(stage.stage, 'circuit-build-attestation.json'),
      finalBuildEvidence.data,
    );
    await writePrivateBytes(
      path.join(stage.stage, 'relation-source-manifest.json'),
      finalSourceManifestEvidence.data,
    );
    await writePrivateBytes(
      path.join(stage.stage, 'development-setup-attestation.json'),
      developmentAttestation.bytes,
    );
    const setup = {
      mode: 'development-only',
      provenance: { method: 'local-initialization', initializerCommitment },
      material: {
        phase1: { ptauSource, ptauSha256, verification: ptauVerificationRecord },
        phase2: {
          initializationCommand: logicalCommandRecord([
            'groth16',
            'setup',
            '$R1CS',
            '$PTAU',
            '$INITIAL_ZKEY',
          ]),
          contributionCommand: logicalCommandRecord([
            'zkey',
            'contribute',
            '$INPUT_ZKEY',
            '$OUTPUT_ZKEY',
          ]),
          randomnessCommitment,
          finalZkeySha256,
        },
      },
      transcript: { status: 'not-applicable' }, contributions: [],
    };
    const metadata = {
      schema: 'shield.cash/local-development-setup/v1', mode: 'development-only',
      inputs: {
        buildAttestation: {
          path: 'circuit-build-attestation.json',
          sha256: buildAttestationEvidence.sha256,
        },
        sourceManifest: {
          path: 'relation-source-manifest.json',
          sha256: sourceManifestEvidence.sha256,
        },
        r1cs: {
          sha256: r1csSha256, requiredPower: r1cs.requiredPower,
          nConstraints: r1cs.nConstraints,
          nPrivateInputs: r1cs.nPrivateInputs,
          nPublicInputs: r1cs.nPublicInputs,
          nOutputs: r1cs.nOutputs,
          nWires: r1cs.nWires,
        },
        ptau: {
          source: ptauSource, sha256: ptauSha256, power: ptau.power, ceremonyPower: ptau.ceremonyPower,
          verification: ptauVerificationRecord,
        },
      },
      outputs: {
        initialProvingKey: {
          path: 'initial.zkey',
          sha256: initialZkeyEvidence.sha256,
        },
        provingKey: { path: 'final.zkey', sha256: finalZkeySha256 },
        verificationKey: {
          path: 'verification_key.json',
          sha256: verificationKeySha256,
        },
        setupAttestation: {
          path: 'development-setup-attestation.json',
          sha256: `sha256:${developmentAttestation.sha256}`,
        },
      },
      setup, toolchain: { generator: snarkjs },
    };
    await writePrivateBytes(
      path.join(stage.stage, 'setup-metadata.json'),
      Buffer.from(`${canonicalJson(metadata)}\n`, 'utf8'),
    );
    await assertNewDestination(stage.target);
    await syncDirectory(stage.stage);
    await rename(stage.stage, stage.target);
    published = true;
    await syncDirectory(stage.parent);
    phase(`setup complete → ${destination}`);
    return Object.freeze({
      directory: destination,
      metadata: Object.freeze(metadata),
      setupAttestation: Object.freeze({
        path: path.join(destination, 'development-setup-attestation.json'),
        sha256: developmentAttestation.sha256,
      }),
    });
  } catch (error) {
    if (error instanceof LocalSetupError) throw error;
    throw new LocalSetupError(error?.message ?? 'local setup failed');
  } finally {
    entropy?.fill(0);
    if (!published && stage !== undefined) {
      await rm(stage.stage, {
        recursive: true,
        force: true,
        maxRetries: 1,
      });
    }
  }
}

export async function getPinnedSnarkjsInfo() {
  const cli = await regularFile(snarkjsCliPath, 'pinned snarkjs CLI');
  return { version: SNARKJS_VERSION, cliSha256: await digestFile(cli) };
}

function assertAttestedArtifact(record, evidence, label) {
  if (
    record.bytes !== evidence.bytes
    || record.sha256 !== bareHash(evidence.sha256, `${label} hash`)
  ) {
    fail(`${label} differs from the setup attestation`);
  }
}

/**
 * Independently consume a development setup record: re-verify both npm
 * closures, every referenced setup artifact, the full PTau transcript, the
 * final zkey, and a freshly exported verification key.
 */
export async function verifyDevelopmentGroth16Artifacts({
  repositoryRoot,
  buildAttestationBytes,
  sourceManifestBytes,
  setupAttestationBytes,
  initialZkeyPath,
  provingKeyPath,
  ptauPath,
  r1csPath,
  verificationKeyPath,
} = {}) {
  const requestedRoot = path.resolve(text(repositoryRoot, 'repository root'));
  const root = await realpath(requestedRoot).catch(() =>
    fail('repository root cannot be resolved'));
  if (root !== requestedRoot) {
    fail('repository root must not use symlink traversal');
  }
  let pair;
  try {
    pair = await verifyDevelopmentSetupAttestationPair(
      setupAttestationBytes,
      {
        buildAttestationBytes,
        repositoryRoot: root,
        sourceManifestBytes,
      },
    );
  } catch (error) {
    fail(`development setup attestation pair is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  try {
    await reproduceV2CircuitBuild({
      buildAttestationBytes,
      repositoryRoot: root,
      sourceManifestBytes,
    });
  } catch (error) {
    fail(`circuit build cannot be independently reproduced: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  const paths = {
    initialZkey: await regularFile(initialZkeyPath, 'initial zkey'),
    provingKey: await regularFile(provingKeyPath, 'final zkey'),
    ptau: await regularFile(ptauPath, 'ptau'),
    r1cs: await regularFile(r1csPath, 'r1cs'),
    verificationKey: await regularFile(
      verificationKeyPath,
      'verification key',
    ),
  };
  const evidence = {
    initialZkey: await measureFile(paths.initialZkey, 'initial zkey'),
    provingKey: await measureFile(paths.provingKey, 'final zkey'),
    ptau: await measureFile(paths.ptau, 'ptau'),
    r1cs: await measureFile(paths.r1cs, 'r1cs'),
    verificationKey: await measureFile(
      paths.verificationKey,
      'verification key',
    ),
  };
  assertAttestedArtifact(
    pair.setup.zkeyChain.initial,
    evidence.initialZkey,
    'initial zkey',
  );
  assertAttestedArtifact(
    pair.setup.zkeyChain.contributions[0].output,
    evidence.provingKey,
    'final zkey',
  );
  assertAttestedArtifact(
    pair.setup.ptau.artifact,
    evidence.ptau,
    'ptau',
  );
  assertAttestedArtifact(pair.setup.r1cs, evidence.r1cs, 'r1cs');
  assertAttestedArtifact(
    pair.setup.finalEvidence.verificationKey,
    evidence.verificationKey,
    'verification key',
  );
  phase('independent consumer: full powersoftau verify …');
  await runPinnedSnarkjs(
    ['powersoftau', 'verify', paths.ptau],
    { label: 'independent powersoftau verify' },
  );
  phase('independent consumer: final zkey verify …');
  await runPinnedSnarkjs(
    [
      'zkey',
      'verify',
      paths.r1cs,
      paths.ptau,
      paths.provingKey,
    ],
    { label: 'independent zkey verify' },
  );
  const temporaryParent = path.join(root, '.codex-build/test-tmp');
  await mkdir(temporaryParent, { recursive: true, mode: 0o700 });
  if (await realpath(temporaryParent) !== temporaryParent) {
    fail('verification temporary directory must not use symlink traversal');
  }
  await chmod(temporaryParent, 0o700);
  const temporary = await mkdtemp(path.join(
    temporaryParent,
    'v2-vk-export-',
  ));
  try {
    const exported = path.join(temporary, 'verification_key.json');
    await runPinnedSnarkjs(
      [
        'zkey',
        'export',
        'verificationkey',
        paths.provingKey,
        exported,
      ],
      {
        cwd: temporary,
        label: 'independent verification-key export',
      },
    );
    const exportedEvidence = await measureFile(
      exported,
      'independently exported verification key',
    );
    assertAttestedArtifact(
      pair.setup.finalEvidence.verificationKey,
      exportedEvidence,
      'independently exported verification key',
    );
    if (
      exportedEvidence.sha256 !== evidence.verificationKey.sha256
      || exportedEvidence.bytes !== evidence.verificationKey.bytes
    ) {
      fail('verification key differs from a fresh final-zkey export');
    }
  } finally {
    await rm(temporary, {
      recursive: true,
      force: true,
      maxRetries: 1,
    });
  }
  const finalEvidence = {
    initialZkey: await measureFile(paths.initialZkey, 'initial zkey'),
    provingKey: await measureFile(paths.provingKey, 'final zkey'),
    ptau: await measureFile(paths.ptau, 'ptau'),
    r1cs: await measureFile(paths.r1cs, 'r1cs'),
    verificationKey: await measureFile(
      paths.verificationKey,
      'verification key',
    ),
  };
  for (const name of Object.keys(evidence)) {
    if (
      evidence[name].bytes !== finalEvidence[name].bytes
      || evidence[name].sha256 !== finalEvidence[name].sha256
    ) {
      fail(`${name} changed during independent setup verification`);
    }
  }
  return Object.freeze({
    build: pair.build,
    setup: pair.setup,
    evidence: Object.freeze(evidence),
  });
}
