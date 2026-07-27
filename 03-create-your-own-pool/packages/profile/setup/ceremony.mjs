import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  lstat, mkdir, readFile, realpath, rm, writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  LocalSetupError,
  SNARKJS_VERSION,
  getPinnedSnarkjsInfo,
  // reuse validation helpers via re-import of private path — call development primitives carefully
} from './development.mjs';
import { canonicalJson } from '../load.mjs';

// This local runner reuses the same pinned snarkjs + entropy FD discipline as
// development setup. Because one process sees every entropy source, its output is
// explicitly a local contribution simulation, never a production ceremony claim.

import { createHash as ch } from 'node:crypto';
import { execFile } from 'node:child_process';
import { fstat, readSync } from 'node:fs';
import { promisify } from 'node:util';
import { readBinFile } from '@iden3/binfileutils';
import { readR1csHeader } from 'r1csfile';

export class CeremonyError extends Error {
  constructor(message) { super(message); this.name = 'CeremonyError'; }
}
const fail = (message) => { throw new CeremonyError(message); };
const HASH = /^sha256:[0-9a-f]{64}$/;
const ENTROPY_DOMAIN = 'shield.cash/ceremony-phase2-entropy/v1\0';
const PARTICIPANT_DOMAIN = 'shield.cash/ceremony-participant/v1\0';
const INITIALIZER_DOMAIN = 'shield.cash/ceremony-initializer/v1\0';
const MAX_ENTROPY_BYTES = 4096;
const MIN_ENTROPY_BYTES = 32;
const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const snarkjsRoot = path.dirname(fileURLToPath(import.meta.resolve('snarkjs')));
const snarkjsCliPath = path.join(snarkjsRoot, 'build', 'cli.cjs');
const snarkjsPackagePath = path.join(snarkjsRoot, 'package.json');
const fstatAsync = promisify(fstat);
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

async function digestFile(file) {
  return new Promise((resolve, reject) => {
    const hasher = createHash('sha256');
    const stream = createReadStream(file, { highWaterMark: 64 * 1024 });
    stream.on('data', (chunk) => hasher.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(`sha256:${hasher.digest('hex')}`));
  });
}

async function regularFile(sourcePath, label) {
  const requested = path.resolve(String(sourcePath));
  const stats = await lstat(requested).catch(() => fail(`${label} does not exist`));
  if (!stats.isFile() || stats.isSymbolicLink()) fail(`${label} must be a regular non-symlink file`);
  const resolved = await realpath(requested).catch(() => fail(`${label} cannot be resolved`));
  if (resolved !== requested) fail(`${label} must not use symlinks`);
  return resolved;
}

function exactKeys(value, label, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((k, i) => k !== expected[i])) fail(`${label} has missing or unknown properties`);
}

function text(value, label) {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a non-empty string`);
  return value;
}

function hash(value, label) {
  text(value, label);
  if (!HASH.test(value)) fail(`${label} must be a lowercase sha256 identifier`);
  return value;
}

async function collectEntropy(entropySource) {
  if (entropySource === null || typeof entropySource !== 'object') fail('entropySource must be an object');
  if (entropySource.kind === 'bytes') {
    const buf = Buffer.from(entropySource.bytes);
    if (buf.length < MIN_ENTROPY_BYTES || buf.length > MAX_ENTROPY_BYTES) fail(`entropy must contain ${MIN_ENTROPY_BYTES}–${MAX_ENTROPY_BYTES} bytes`);
    if (buf.includes(0x0a) || buf.includes(0x0d)) fail('entropy must not contain line breaks');
    return buf;
  }
  if (entropySource.kind !== 'fd') fail('entropySource.kind must be fd or bytes');
  const fd = entropySource.fd;
  if (!Number.isInteger(fd) || fd < 0) fail('entropy fd must be a non-negative integer');
  const stats = await fstatAsync(fd).catch(() => fail('entropy fd is not readable'));
  if (!stats.isFile()) fail('entropy fd must refer to a regular file');
  const size = Number(stats.size);
  if (size < MIN_ENTROPY_BYTES || size > MAX_ENTROPY_BYTES) fail(`entropy must contain ${MIN_ENTROPY_BYTES}–${MAX_ENTROPY_BYTES} bytes`);
  const buf = Buffer.alloc(size);
  const n = readSync(fd, buf, 0, size, 0);
  if (n !== size) fail('entropy fd read incomplete');
  if (buf.includes(0x0a) || buf.includes(0x0d)) fail('entropy must not contain line breaks');
  return buf;
}

async function runPinnedSnarkjs(args, { cwd, entropy } = {}) {
  const child = execFile(process.execPath, [snarkjsCliPath, ...args], { cwd, env: {}, windowsHide: true });
  let output = ''; let supplied = false;
  child.stdout.on('data', (chunk) => {
    if (entropy === undefined || supplied) return;
    output = `${output}${String(chunk)}`.slice(-512);
    if (output.includes('Enter a random text. (Entropy):')) {
      supplied = true;
      child.stdin.end(Buffer.concat([entropy, Buffer.from('\n')]));
    }
  });
  child.stderr.resume();
  if (entropy === undefined) child.stdin.end();
  await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new CeremonyError(`snarkjs failed: ${args.join(' ')}`));
      else if (entropy !== undefined && !supplied) reject(new CeremonyError(`snarkjs did not request entropy: ${args.join(' ')}`));
      else resolve();
    });
  });
}

async function pinnedSnarkjsInfo(expected) {
  exactKeys(expected, 'expectedSnarkjs', ['version', 'cliSha256']);
  if (expected.version !== SNARKJS_VERSION) fail(`expected snarkjs version ${SNARKJS_VERSION}`);
  const pkg = JSON.parse(await readFile(snarkjsPackagePath, 'utf8'));
  if (pkg.version !== SNARKJS_VERSION) fail('pinned snarkjs package version mismatch');
  const cliSha = await digestFile(snarkjsCliPath);
  if (hash(expected.cliSha256, 'cliSha256') !== cliSha) fail('snarkjs cli hash mismatch');
  return Object.freeze({ name: 'snarkjs', version: SNARKJS_VERSION, sha256: cliSha, path: snarkjsCliPath });
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

function commandRecord(args) {
  return { argv: [process.execPath, snarkjsCliPath, ...args] };
}

/**
 * Local phase-2 contribution simulation (≥2 sequential contributions).
 * Offline, coordinator-visible entropy, and never a release gate.
 * @param {object} input
 * @param {string} input.destination
 * @param {Array<{entropySource: object, participantLabel?: string}>} input.participants — min 2
 */
export async function initializeLocalContributionSimulationGroth16(input) {
  exactKeys(input, 'ceremony setup input', [
    'destination', 'r1csPath', 'ptauPath', 'ptauSource', 'expectedR1csSha256',
    'expectedPtauSha256', 'expectedPtauPower', 'expectedSnarkjs', 'participants',
  ]);
  if (!Array.isArray(input.participants) || input.participants.length < 2) {
    fail('ceremony requires at least two participants');
  }
  if (!Number.isInteger(input.expectedPtauPower) || input.expectedPtauPower < 1 || input.expectedPtauPower > 28) {
    fail('expected ptau power must be an integer from 1 to 28');
  }
  const ptauSource = text(input.ptauSource, 'ptau source');
  const r1csPath = await regularFile(input.r1csPath, 'r1cs path');
  const ptauPath = await regularFile(input.ptauPath, 'ptau path');
  const r1cs = await readR1csCapacity(r1csPath);
  if (r1cs.nPublicInputs !== 2 || r1cs.nOutputs !== 0) fail('r1cs must use the shield.cash ABI: exactly 2 public inputs and 0 outputs');
  const r1csSha256 = await digestFile(r1csPath);
  const ptauSha256 = await digestFile(ptauPath);
  if (hash(input.expectedR1csSha256, 'expected r1cs hash') !== r1csSha256) fail('r1cs hash mismatch');
  if (hash(input.expectedPtauSha256, 'expected ptau hash') !== ptauSha256) fail('ptau hash mismatch');
  const ptau = await readPtauCapacity(ptauPath);
  if (ptau.power !== input.expectedPtauPower) fail('ptau power mismatch');
  if (ptau.power < r1cs.requiredPower) fail('ptau power is insufficient for r1cs capacity');
  const snarkjs = await pinnedSnarkjsInfo(input.expectedSnarkjs);

  const destination = path.resolve(input.destination);
  if (destination !== path.normalize(destination)) fail('destination path invalid');
  try {
    await lstat(destination);
    fail('destination must not already exist');
  } catch (e) {
    if (e?.name === 'CeremonyError') throw e;
  }

  await runPinnedSnarkjs(['powersoftau', 'verify', ptauPath]);
  let created = false;
  const entropies = [];
  try {
    await mkdir(destination, { recursive: false });
    created = true;
    const initialZkey = path.join(destination, 'initial.zkey');
    const setupArgs = ['groth16', 'setup', r1csPath, ptauPath, initialZkey];
    await runPinnedSnarkjs(setupArgs, { cwd: destination });

    const contributions = [];
    let prevZkey = initialZkey;
    for (let i = 0; i < input.participants.length; i += 1) {
      const p = input.participants[i];
      if (p === null || typeof p !== 'object' || !p.entropySource) fail(`participant ${i} requires entropySource`);
      const entropy = await collectEntropy(p.entropySource);
      entropies.push(entropy);
      const randomnessCommitment = sha256(Buffer.concat([Buffer.from(ENTROPY_DOMAIN, 'utf8'), entropy]));
      const participantCommitment = sha256(Buffer.concat([
        Buffer.from(PARTICIPANT_DOMAIN, 'utf8'),
        Buffer.from(String(i + 1), 'utf8'),
        Buffer.from(randomnessCommitment, 'utf8'),
      ]));
      const nextZkey = path.join(destination, i === input.participants.length - 1 ? 'final.zkey' : `contrib-${i + 1}.zkey`);
      const contributeArgs = ['zkey', 'contribute', prevZkey, nextZkey];
      await runPinnedSnarkjs(contributeArgs, { cwd: destination, entropy });
      const contributionHash = await digestFile(nextZkey);
      contributions.push({
        sequence: String(i + 1),
        participantCommitment,
        contributionHash,
        verification: {
          status: 'verified',
          verifier: { name: snarkjs.name, version: snarkjs.version, sha256: snarkjs.sha256 },
        },
      });
      if (prevZkey !== initialZkey) await rm(prevZkey, { force: true });
      prevZkey = nextZkey;
    }
    await rm(initialZkey, { force: true });
    const finalZkey = path.join(destination, 'final.zkey');
    const verificationKey = path.join(destination, 'verification_key.json');
    await runPinnedSnarkjs(['zkey', 'verify', r1csPath, ptauPath, finalZkey], { cwd: destination });
    await runPinnedSnarkjs(['zkey', 'export', 'verificationkey', finalZkey, verificationKey], { cwd: destination });
    const finalZkeySha256 = await digestFile(finalZkey);
    const verificationKeySha256 = await digestFile(verificationKey);
    if ((await digestFile(r1csPath)) !== r1csSha256) fail('r1cs changed during ceremony');
    if ((await digestFile(ptauPath)) !== ptauSha256) fail('ptau changed during ceremony');

    const contributionChainSha256 = sha256(Buffer.from(canonicalJson(contributions), 'utf8'));
    const transcriptBody = {
      schema: 'shieldkit/local-contribution-transcript/v1',
      mode: 'local-contribution-simulation',
      phase1: { ptauSource, ptauSha256 },
      phase2: {
        initializationCommand: commandRecord(setupArgs),
        contributionChainSha256,
        finalZkeySha256,
      },
      contributions,
    };
    const transcriptPath = path.join(destination, 'ceremony-transcript.json');
    const transcriptJson = `${canonicalJson(transcriptBody)}\n`;
    await writeFile(transcriptPath, transcriptJson, { mode: 0o600, flag: 'wx' });
    const transcriptSha256 = sha256(Buffer.from(transcriptJson, 'utf8'));

    const randomnessParts = contributions.map((c) => c.participantCommitment).join('\0');
    const initializerCommitment = sha256(Buffer.from(
      `${INITIALIZER_DOMAIN}${r1csSha256}\0${ptauSha256}\0${randomnessParts}`,
      'utf8',
    ));

    const setup = {
      mode: 'local-contribution-simulation',
      provenance: { method: 'single-coordinator-sequential-contributions', initializerCommitment },
      material: {
        phase1: { ptauSource, ptauSha256 },
        phase2: {
          initializationCommand: commandRecord(setupArgs),
          finalZkeySha256,
          finalZkeyVerification: {
            status: 'verified',
            verifier: { name: snarkjs.name, version: snarkjs.version, sha256: snarkjs.sha256 },
          },
          contributionChainSha256,
        },
      },
      transcript: {
        status: 'complete',
        artifactPath: 'ceremony-transcript.json',
        sha256: transcriptSha256,
        verifier: { name: snarkjs.name, version: snarkjs.version, sha256: snarkjs.sha256 },
      },
      contributions,
    };

    if (setup.mode !== 'local-contribution-simulation') fail('mode laundering refused');

    const metadata = {
      schema: 'shieldkit/local-contribution-setup/v1',
      mode: 'local-contribution-simulation',
      inputs: {
        r1cs: {
          sha256: r1csSha256,
          requiredPower: r1cs.requiredPower,
          nConstraints: r1cs.nConstraints,
          nPublicInputs: r1cs.nPublicInputs,
          nOutputs: r1cs.nOutputs,
        },
        ptau: { source: ptauSource, sha256: ptauSha256, power: ptau.power, ceremonyPower: ptau.ceremonyPower },
      },
      outputs: {
        provingKey: { path: 'final.zkey', sha256: finalZkeySha256 },
        verificationKey: { path: 'verification_key.json', sha256: verificationKeySha256 },
        transcript: { path: 'ceremony-transcript.json', sha256: transcriptSha256 },
      },
      setup,
      toolchain: { generator: snarkjs },
    };
    await writeFile(path.join(destination, 'setup-metadata.json'), `${canonicalJson(metadata)}\n`, { mode: 0o600, flag: 'wx' });
    return Object.freeze({ directory: destination, metadata: Object.freeze(metadata) });
  } catch (error) {
    if (created) await rm(destination, { recursive: true, force: true });
    if (error instanceof CeremonyError) throw error;
    throw new CeremonyError(error?.message ?? 'ceremony failed');
  } finally {
    for (const e of entropies) e.fill?.(0);
  }
}

/** Validate the local simulation label and refuse production-ceremony laundering. */
export function assertLocalContributionSimulationMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') fail('metadata must be an object');
  if (metadata.mode === 'ceremony-production' || metadata.setup?.mode === 'ceremony-production') {
    fail('ceremony-production is unsupported: local entropy collection cannot establish independence');
  }
  if (metadata.mode !== 'local-contribution-simulation'
    || metadata.setup?.mode !== 'local-contribution-simulation') {
    fail('metadata must use local-contribution-simulation mode');
  }
  if (metadata.setup?.provenance?.method !== 'single-coordinator-sequential-contributions') {
    fail('local simulation provenance is invalid');
  }
  if (!Array.isArray(metadata.setup?.contributions) || metadata.setup.contributions.length < 2) {
    fail('local simulation requires at least two sequential contributions');
  }
  return metadata;
}

/**
 * Compatibility name retained for callers, but it now produces honestly labelled
 * local-contribution-simulation metadata.
 */
export const initializeCeremonyGroth16 = initializeLocalContributionSimulationGroth16;

/** @deprecated use assertLocalContributionSimulationMetadata */
export const assertCeremonyMetadata = assertLocalContributionSimulationMetadata;
