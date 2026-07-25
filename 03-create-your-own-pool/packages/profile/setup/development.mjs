import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createReadStream, fstat, readSync } from 'node:fs';
import {
  lstat, mkdir, readFile, realpath, rm, writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { readBinFile } from '@iden3/binfileutils';
import { readR1csHeader } from 'r1csfile';
import { canonicalJson } from '../load.mjs';

export const SNARKJS_VERSION = '0.7.6';
export const ENTROPY_DOMAIN = 'shield.cash/local-development-phase2-entropy/v1\0';
const INITIALIZER_DOMAIN = 'shield.cash/local-development-initializer/v1\0';
const MAX_ENTROPY_BYTES = 4096;
const MIN_ENTROPY_BYTES = 32;
const HASH = /^sha256:[0-9a-f]{64}$/;
const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const snarkjsRoot = path.join(packageDirectory, '..', 'node_modules', 'snarkjs');
const snarkjsCliPath = path.join(snarkjsRoot, 'build', 'cli.cjs');
const snarkjsPackagePath = path.join(snarkjsRoot, 'package.json');
const fstatAsync = promisify(fstat);

/**
 * Well-known Phase-1 ptau pins for development-only.
 * Hash match is the integrity check; full `snarkjs powersoftau verify` is optional (hours for power 20).
 * Ceremony/production path always runs full verify (see ceremony.mjs).
 */
export const TRUSTED_DEVELOPMENT_PTAU = Object.freeze({
  'hermez-powersOfTau28_hez_final_20': Object.freeze({
    source: 'hermez-powersOfTau28_hez_final_20',
    sha256: 'sha256:159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd',
    power: 20,
    note: 'Hermez / Perpetual Powers of Tau final_20 (community-distributed). Not a ShieldKit ceremony.',
  }),
});

const PTAU_HASH_ONLY_IMPLICATIONS = Object.freeze([
  'development-only: snarkjs powersoftau verify was skipped after SHA-256 pin match',
  'you trust the pin identity (e.g. Hermez final_20) and that the file bytes match that pin',
  'hash-only does NOT re-check the multi-party Phase-1 transcript or contribution chain',
  'hash-only is NOT ceremony-production or mainnet qualification evidence',
  'a wrong pin (or malicious pin) would accept a bad ptau without full verify',
  'pass setup.verifyPtau=true or CLI --verify-ptau to force full snarkjs powersoftau verify',
]);

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
  if (!details.isFile() || details.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  const resolved = await realpath(requested).catch(() => fail(`${label} cannot be resolved`));
  if (resolved !== requested) fail(`${label} must not use symlinks`);
  return resolved;
}

/** Stream artifact hashes: ptau and zkey files are deliberately not buffered. */
export async function hashFileStreaming(file) {
  return new Promise((resolve, reject) => {
    const hasher = createHash('sha256');
    const stream = createReadStream(file, { highWaterMark: 64 * 1024 });
    stream.on('data', (chunk) => hasher.update(chunk));
    stream.on('error', () => reject(new LocalSetupError('artifact cannot be hashed')));
    stream.on('end', () => resolve(`sha256:${hasher.digest('hex')}`));
  });
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
    return { nConstraints: header.nConstraints, nPublicInputs: header.nPubInputs, nOutputs: header.nOutputs, requiredPower };
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

function warnPtauHashOnly(policy, ptauSha256) {
  process.stderr.write(
    [
      '',
      '╔══════════════════════════════════════════════════════════════════════╗',
      '║  WARNING: development-only ptau check is HASH-ONLY                   ║',
      '╚══════════════════════════════════════════════════════════════════════╝',
      `  mode:        hash-only (snarkjs powersoftau verify SKIPPED)`,
      `  ptau sha256: ${ptauSha256}`,
      `  pin source:  ${policy.trusted?.source ?? '(none)'}`,
      `  reason:      ${policy.reason}`,
      '  Implications:',
      ...PTAU_HASH_ONLY_IMPLICATIONS.map((line) => `    • ${line}`),
      '  This setup remains development-only. It is not production privacy.',
      '',
    ].join('\n'),
  );
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

async function ensureNewDestination(destination) {
  const target = await assertNewDestination(destination);
  await mkdir(target, { mode: 0o700 });
  return target;
}

/** Recheck direct-file identity and hashes before publishing setup metadata. */
export async function assertUnchangedSetupInputs({ r1csPath, ptauPath, r1csSha256, ptauSha256 }) {
  const currentR1csPath = await regularFile(r1csPath, 'r1cs path');
  const currentPtauPath = await regularFile(ptauPath, 'ptau path');
  if (currentR1csPath !== r1csPath || currentPtauPath !== ptauPath) fail('setup input path drift detected');
  if (await digestFile(currentR1csPath) !== r1csSha256) fail('r1cs changed during setup');
  if (await digestFile(currentPtauPath) !== ptauSha256) fail('ptau changed during setup');
}

function commandRecord(args) {
  return { argv: [process.execPath, snarkjsCliPath, ...args] };
}

/**
 * Execute exactly one local Groth16 Phase-2 contribution. The entropy is
 * supplied only through inherited stdin or an already-open private fd and is
 * never placed in argv, metadata, logs, or an environment dump.
 *
 * Optional input fields:
 * - verifyPtau: true  → always run snarkjs powersoftau verify
 * - verifyPtau: false → hash-only (requires TRUSTED_DEVELOPMENT_PTAU pin match)
 * - omit verifyPtau   → hash-only if pin-eligible, else full verify
 *
 * Hash-only is development convenience only. Ceremony path never skips verify.
 */
export async function initializeDevelopmentGroth16(input) {
  if (input === null || Array.isArray(input) || typeof input !== 'object') fail('local setup input must be an object');
  const required = [
    'destination', 'r1csPath', 'ptauPath', 'ptauSource', 'expectedR1csSha256',
    'expectedPtauSha256', 'expectedPtauPower', 'expectedSnarkjs', 'entropySource',
  ];
  for (const key of required) {
    if (!Object.hasOwn(input, key)) fail(`local setup input missing ${key}`);
  }
  for (const key of Object.keys(input)) {
    if (!required.includes(key) && key !== 'verifyPtau') {
      fail(`local setup input has unknown property: ${key}`);
    }
  }
  if (Object.hasOwn(input, 'verifyPtau') && typeof input.verifyPtau !== 'boolean') {
    fail('verifyPtau must be a boolean when set');
  }
  if (!Number.isInteger(input.expectedPtauPower) || input.expectedPtauPower < 1 || input.expectedPtauPower > 28) fail('expected ptau power must be an integer from 1 to 28');
  const ptauSource = text(input.ptauSource, 'ptau source');
  phase('hashing r1cs + ptau (streaming) …');
  const r1csPath = await regularFile(input.r1csPath, 'r1cs path'); const ptauPath = await regularFile(input.ptauPath, 'ptau path');
  const r1cs = await readR1csCapacity(r1csPath);
  if (r1cs.nPublicInputs !== 2 || r1cs.nOutputs !== 0) fail('r1cs must use the shield.cash ABI: exactly 2 public inputs and 0 outputs');
  const r1csSha256 = await digestFile(r1csPath); const ptauSha256 = await digestFile(ptauPath);
  phase(`r1cs sha256 ${r1csSha256}`);
  phase(`ptau sha256 ${ptauSha256}`);
  if (hash(input.expectedR1csSha256, 'expected r1cs hash') !== r1csSha256) fail('r1cs hash mismatch');
  if (hash(input.expectedPtauSha256, 'expected ptau hash') !== ptauSha256) fail('ptau hash mismatch');
  const ptau = await readPtauCapacity(ptauPath);
  if (ptau.power !== input.expectedPtauPower) fail('ptau power mismatch');
  if (ptau.power < r1cs.requiredPower) fail('ptau power is insufficient for r1cs capacity');
  const snarkjs = await pinnedSnarkjsInfo(input.expectedSnarkjs);
  const destination = safeDestination(input.destination);
  // Refuse collision before costly validation or any output creation.
  await assertNewDestination(destination);

  const ptauPolicy = resolveDevelopmentPtauVerification({
    ptauSource,
    ptauSha256,
    expectedPtauPower: input.expectedPtauPower,
    verifyPtau: input.verifyPtau,
  });
  let ptauVerificationRecord;
  if (ptauPolicy.mode === 'hash-only') {
    warnPtauHashOnly(ptauPolicy, ptauSha256);
    ptauVerificationRecord = Object.freeze({
      mode: 'hash-only',
      snarkjsPowersoftauVerify: false,
      trustedSource: ptauPolicy.trusted.source,
      trustedSha256: ptauPolicy.trusted.sha256,
      measuredSha256: ptauSha256,
      reason: ptauPolicy.reason,
      implications: PTAU_HASH_ONLY_IMPLICATIONS,
    });
    phase('ptau: hash-only (full powersoftau verify skipped)');
  } else {
    phase('ptau: full snarkjs powersoftau verify (can take a long time for high power) …');
    await runPinnedSnarkjs(['powersoftau', 'verify', ptauPath], { label: 'powersoftau verify' });
    ptauVerificationRecord = Object.freeze({
      mode: 'full',
      snarkjsPowersoftauVerify: true,
      trustedSource: ptauPolicy.trusted?.source ?? null,
      measuredSha256: ptauSha256,
      reason: ptauPolicy.reason,
    });
  }

  let created = false; let entropy;
  try {
    await ensureNewDestination(destination); created = true;
    entropy = await collectEntropy(input.entropySource);
    const randomnessCommitment = sha256Parts(ENTROPY_DOMAIN, entropy);
    const initializerCommitment = sha256(Buffer.from(`${INITIALIZER_DOMAIN}${r1csSha256}\0${ptauSha256}\0${randomnessCommitment}`, 'utf8'));
    const initialZkey = path.join(destination, 'initial.zkey'); const finalZkey = path.join(destination, 'final.zkey'); const verificationKey = path.join(destination, 'verification_key.json');
    const setupArgs = ['groth16', 'setup', r1csPath, ptauPath, initialZkey];
    const contributeArgs = ['zkey', 'contribute', initialZkey, finalZkey];
    // Multi-thread MSM remains enabled inside snarkjs/ffjavascript (do not force singleThread).
    await runPinnedSnarkjs(setupArgs, { cwd: destination, label: 'groth16 setup' });
    await runPinnedSnarkjs(contributeArgs, { cwd: destination, entropy, label: 'zkey contribute' });
    await runPinnedSnarkjs(['zkey', 'verify', r1csPath, ptauPath, finalZkey], { cwd: destination, label: 'zkey verify' });
    await runPinnedSnarkjs(['zkey', 'export', 'verificationkey', finalZkey, verificationKey], { cwd: destination, label: 'export verification key' });
    await rm(initialZkey, { force: false });
    const finalZkeySha256 = await digestFile(finalZkey); const verificationKeySha256 = await digestFile(verificationKey);
    await assertUnchangedSetupInputs({ r1csPath, ptauPath, r1csSha256, ptauSha256 });
    const setup = {
      mode: 'development-only',
      provenance: { method: 'local-initialization', initializerCommitment },
      material: {
        phase1: { ptauSource, ptauSha256, verification: ptauVerificationRecord },
        phase2: { initializationCommand: commandRecord(setupArgs), contributionCommand: commandRecord(contributeArgs), randomnessCommitment, finalZkeySha256 },
      },
      transcript: { status: 'not-applicable' }, contributions: [],
    };
    const metadata = {
      schema: 'shield.cash/local-development-setup/v1', mode: 'development-only',
      inputs: {
        r1cs: {
          sha256: r1csSha256, requiredPower: r1cs.requiredPower,
          nConstraints: r1cs.nConstraints, nPublicInputs: r1cs.nPublicInputs, nOutputs: r1cs.nOutputs,
        },
        ptau: {
          source: ptauSource, sha256: ptauSha256, power: ptau.power, ceremonyPower: ptau.ceremonyPower,
          verification: ptauVerificationRecord,
        },
      },
      outputs: { provingKey: { path: 'final.zkey', sha256: finalZkeySha256 }, verificationKey: { path: 'verification_key.json', sha256: verificationKeySha256 } },
      setup, toolchain: { generator: snarkjs },
    };
    await writeFile(path.join(destination, 'setup-metadata.json'), `${canonicalJson(metadata)}\n`, { mode: 0o600, flag: 'wx' });
    phase(`setup complete → ${destination}`);
    return Object.freeze({ directory: destination, metadata: Object.freeze(metadata) });
  } catch (error) {
    if (created) await rm(destination, { recursive: true, force: true });
    if (error instanceof LocalSetupError) throw error;
    throw new LocalSetupError(error?.message ?? 'local setup failed');
  } finally {
    entropy?.fill(0);
  }
}

export async function getPinnedSnarkjsInfo() {
  const cli = await regularFile(snarkjsCliPath, 'pinned snarkjs CLI');
  return { version: SNARKJS_VERSION, cliSha256: await digestFile(cli) };
}
