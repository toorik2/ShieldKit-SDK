import { createHash } from 'node:crypto';
import {
  chmod,
  mkdir,
  open,
  readFile,
  readdir,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

import * as snarkjs from 'snarkjs';

import { ACTION_PACKET_BYTES } from '../packages/action/v2/packet.mjs';
import {
  canonicalizeJcs,
  deriveProfileId,
  validateProfileCore,
} from '../packages/profile/v2/profile-core.mjs';
import {
  adaptV2DirectGroth16,
} from '../packages/prove/v2-direct-groth16-adapter.mjs';
import {
  loadPinnedV2DirectGroth16AdapterResult,
} from '../packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/src/c7/v2-direct-groth16-adapter-input.mjs';
import { buildDeterministicDirectV2Chain } from './v2-circuit-model.mjs';

const PROJECT_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../..',
);
const REQUIRED_OPTIONS = Object.freeze({
  '--profile-core': 'profileCore',
  '--r1cs': 'r1cs',
  '--wasm': 'wasm',
  '--zkey': 'zkey',
  '--verification-key': 'verificationKey',
  '--output': 'outputDirectory',
});
const REQUIRED_VALUE_OPTIONS = Object.freeze({
  '--instance-id': 'instanceId',
  '--maximum-live-notes': 'maximumLiveNotes',
});
const FLAG_OPTIONS = Object.freeze({
  '--single-thread': 'singleThread',
});
const ACTION_NAMES = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const SHA256 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;

export class DevelopmentProofQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DevelopmentProofQualificationError';
  }
}

const fail = (message) => {
  throw new DevelopmentProofQualificationError(message);
};

export function parseQualificationArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv)) fail('CLI arguments must be an array');
  const parsed = { singleThread: false };
  for (let index = 0; index < argv.length;) {
    const option = argv[index];
    const flag = FLAG_OPTIONS[option];
    if (flag !== undefined) {
      if (parsed[flag]) fail(`duplicate CLI option: ${option}`);
      parsed[flag] = true;
      index += 1;
      continue;
    }
    const pathKey = REQUIRED_OPTIONS[option];
    const valueKey = REQUIRED_VALUE_OPTIONS[option];
    const key = pathKey ?? valueKey;
    if (key === undefined) fail(`unknown or positional argument: ${String(option)}`);
    if (Object.hasOwn(parsed, key)) fail(`duplicate CLI option: ${option}`);
    const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0 || value.startsWith('--')) {
      fail(`missing path for ${option}`);
    }
    parsed[key] = pathKey === undefined ? value : path.resolve(cwd, value);
    index += 2;
  }
  for (const [option, key] of Object.entries(REQUIRED_OPTIONS)) {
    if (!Object.hasOwn(parsed, key)) fail(`missing required CLI option: ${option}`);
  }
  for (const [option, key] of Object.entries(REQUIRED_VALUE_OPTIONS)) {
    if (!Object.hasOwn(parsed, key)) fail(`missing required CLI option: ${option}`);
  }
  if (!SHA256.test(parsed.instanceId)) {
    fail('--instance-id must be 32 lowercase hexadecimal bytes');
  }
  if (
    !DECIMAL.test(parsed.maximumLiveNotes)
    || BigInt(parsed.maximumLiveNotes) === 0n
    || BigInt(parsed.maximumLiveNotes) > 210_000_000n
  ) {
    fail('--maximum-live-notes must be canonical decimal in [1, 210000000]');
  }
  return Object.freeze(parsed);
}

/**
 * Keep snarkjs' single-thread mode an explicit, observable invocation shape.
 * In particular, do not retry without the option if that mode fails.
 */
export function snarkjsGroth16ProveArguments(zkey, witness, singleThread) {
  if (typeof singleThread !== 'boolean') fail('singleThread must be a boolean');
  return singleThread
    ? Object.freeze([zkey, witness, undefined, Object.freeze({ singleThread: true })])
    : Object.freeze([zkey, witness]);
}

export function proverEvidence(singleThread) {
  if (typeof singleThread !== 'boolean') fail('singleThread must be a boolean');
  return Object.freeze({
    backend: 'snarkjs',
    provingSystem: 'groth16',
    mode: singleThread ? 'single-thread' : 'default',
  });
}

export function stringifyJsonWithBigInts(value) {
  const active = new WeakSet();
  const normalize = (current) => {
    if (current === null) return null;
    if (typeof current === 'bigint') return current.toString();
    if (
      typeof current === 'string'
      || typeof current === 'boolean'
    ) {
      return current;
    }
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) fail('JSON value contains a non-finite number');
      return current;
    }
    if (
      current === undefined
      || typeof current === 'function'
      || typeof current === 'symbol'
    ) {
      fail('JSON value contains a non-serializable value');
    }
    if (active.has(current)) fail('JSON value contains a cycle');
    active.add(current);
    let normalized;
    if (Array.isArray(current)) {
      const keys = Object.keys(current);
      if (
        keys.length !== current.length
        || keys.some((key, index) => key !== String(index))
        || Object.getOwnPropertyNames(current).length !== current.length + 1
        || Object.getOwnPropertySymbols(current).length !== 0
      ) {
        fail('JSON array must be dense without extra properties');
      }
      normalized = [];
      for (let index = 0; index < current.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(current, String(index));
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
          fail('JSON array must contain enumerable data elements only');
        }
        normalized.push(normalize(descriptor.value));
      }
    } else {
      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        fail('JSON object has an unsupported prototype');
      }
      if (Object.getOwnPropertySymbols(current).length !== 0) {
        fail('JSON object contains symbol properties');
      }
      normalized = Object.create(null);
      for (const key of Object.getOwnPropertyNames(current)) {
        const descriptor = Object.getOwnPropertyDescriptor(current, key);
        if (
          key === 'toJSON'
          || !descriptor?.enumerable
          || !Object.hasOwn(descriptor, 'value')
        ) {
          fail('JSON object must contain enumerable data properties only');
        }
        normalized[key] = normalize(descriptor.value);
      }
    }
    active.delete(current);
    return normalized;
  };
  return `${JSON.stringify(normalize(value), null, 2)}\n`;
}

async function assertReadableArtifact(filename, label) {
  let metadata;
  try {
    metadata = await stat(filename);
  } catch (error) {
    fail(`${label} is not readable: ${error.message}`);
  }
  if (!metadata.isFile() || metadata.size === 0) {
    fail(`${label} must be a nonempty regular file`);
  }
}

async function prepareOutputDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const entries = await readdir(directory);
  if (entries.length !== 0) {
    fail('output directory must be empty');
  }
}

async function sha256File(filename) {
  const handle = await open(filename, 'r');
  try {
    const hash = createHash('sha256');
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk);
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

async function fileEvidence(filename) {
  const metadata = await stat(filename);
  const relative = path.relative(PROJECT_ROOT, path.resolve(filename));
  if (
    relative.length === 0
    || relative === '..'
    || relative.startsWith(`..${path.sep}`)
    || path.isAbsolute(relative)
  ) {
    fail(`evidence file is outside the repository: ${filename}`);
  }
  return Object.freeze({
    path: relative.split(path.sep).join('/'),
    bytes: metadata.size,
    sha256: await sha256File(filename),
  });
}

async function writeJson(filename, value) {
  await writeFile(filename, stringifyJsonWithBigInts(value), {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
}

export async function snarkjsVersion() {
  const resolved = fileURLToPath(import.meta.resolve('snarkjs'));
  const packageJson = path.resolve(path.dirname(resolved), 'package.json');
  const parsed = JSON.parse(await readFile(packageJson, 'utf8'));
  if (typeof parsed.version !== 'string' || parsed.version.length === 0) {
    fail('installed snarkjs package has no version');
  }
  return parsed.version;
}

function peakRssEvidence() {
  if (process.platform !== 'linux') {
    return Object.freeze({
      available: false,
      reason: 'process.resourceUsage().maxRSS units are only recorded here on Linux',
    });
  }
  return Object.freeze({
    available: true,
    bytes: process.resourceUsage().maxRSS * 1024,
    source: 'process.resourceUsage().maxRSS-kibibytes',
  });
}

function assertHashEvidence(value, label) {
  if (
    value === null
    || typeof value !== 'object'
    || !Number.isSafeInteger(value.bytes)
    || value.bytes <= 0
    || typeof value.path !== 'string'
    || !SHA256.test(value.sha256)
  ) {
    fail(`${label} has invalid file evidence`);
  }
}

export function createDevelopmentEvidenceManifest({
  identity,
  sourceArtifacts,
  actions,
  versions,
  prover,
  totalWallMs,
  peakRss,
}) {
  for (const name of [
    'profileCore',
    'r1cs',
    'wasm',
    'developmentZkey',
    'verificationKey',
  ]) {
    assertHashEvidence(sourceArtifacts?.[name], `sourceArtifacts.${name}`);
  }
  if (
    identity === null
    || Array.isArray(identity)
    || typeof identity !== 'object'
    || !SHA256.test(identity.profileId)
    || !SHA256.test(identity.instanceId)
    || typeof identity.maximumLiveNotes !== 'string'
    || !DECIMAL.test(identity.maximumLiveNotes)
    || BigInt(identity.maximumLiveNotes) === 0n
    || BigInt(identity.maximumLiveNotes) > 210_000_000n
    || identity.denominationSats !== '10000000'
  ) {
    fail('evidence identity is invalid');
  }
  const actualActions = Object.keys(actions ?? {}).sort();
  const expectedActions = [...ACTION_NAMES].sort();
  if (
    actualActions.length !== expectedActions.length
    || actualActions.some((name, index) => name !== expectedActions[index])
  ) {
    fail('evidence must contain exactly deposit, transfer, and withdrawal');
  }
  for (const name of ACTION_NAMES) {
    const action = actions[name];
    if (action?.witnessValid !== true || action?.proofVerified !== true) {
      fail(`${name} is not fully verified`);
    }
    for (const file of [
      'packet',
      'input',
      'witness',
      'proof',
      'publicSignals',
      'v2DirectGroth16Adapter',
    ]) {
      assertHashEvidence(action.files?.[file], `actions.${name}.files.${file}`);
    }
    if (
      !SHA256.test(action.packetDigest)
      || action.files.packet.bytes !== ACTION_PACKET_BYTES
      || action.files.packet.sha256 !== action.packetDigest
    ) {
      fail(`${name} packet evidence does not match its SHA-256 digest`);
    }
    if (
      !Array.isArray(action.publicInputs)
      || action.publicInputs.length !== 2
      || action.publicInputs.some(
        (value) => (
          typeof value !== 'string'
          || !DECIMAL.test(value)
          || BigInt(value) > MAX_U128
        ),
      )
    ) {
      fail(`${name} public inputs do not match the u128x2 ABI`);
    }
  }
  if (
    versions === null
    || typeof versions !== 'object'
    || typeof versions.node !== 'string'
    || typeof versions.snarkjs !== 'string'
    || !Number.isFinite(totalWallMs)
    || totalWallMs < 0
  ) {
    fail('evidence versions or total timing are invalid');
  }
  if (
    prover === null
    || typeof prover !== 'object'
    || prover.backend !== 'snarkjs'
    || prover.provingSystem !== 'groth16'
    || (prover.mode !== 'default' && prover.mode !== 'single-thread')
  ) {
    fail('evidence prover backend or mode is invalid');
  }
  return Object.freeze({
    schema: 'shieldkit-v2-direct-development-groth16-qualification-v4',
    evidenceClass: 'deterministic-development-key-proof-test-evidence',
    claims: Object.freeze({
      developmentKey: true,
      finalKey: false,
      bchVm: false,
      production: false,
    }),
    fixture: 'deterministic-deposit-transfer-withdrawal-chain',
    identity,
    versions,
    prover,
    sourceArtifacts,
    actions,
    measurements: Object.freeze({
      totalWallMs,
      peakRss,
    }),
  });
}

function exactPublicSignals(action, publicSignals) {
  const expected = [
    action.circuitInput.publicInput0,
    action.circuitInput.publicInput1,
  ];
  if (
    !Array.isArray(publicSignals)
    || publicSignals.length !== 2
    || publicSignals.some((value, index) => String(value) !== expected[index])
  ) {
    fail('Groth16 public signals do not match the deterministic circuit input');
  }
}

async function qualifyAction({
  name,
  action,
  outputDirectory,
  r1cs,
  wasm,
  zkey,
  verificationKey,
  verificationKeyPath,
  verificationKeyEvidence,
  singleThread,
}) {
  const actionStarted = performance.now();
  const directory = path.join(outputDirectory, name);
  await mkdir(directory, { mode: 0o700 });
  await chmod(directory, 0o700);
  const packet = path.join(directory, 'packet.bin');
  const input = path.join(directory, 'input.json');
  const witness = path.join(directory, 'witness.wtns');
  const proof = path.join(directory, 'proof.json');
  const publicSignalsFile = path.join(directory, 'public.json');
  const adapterFile = path.join(directory, 'v2-direct-groth16-adapter.json');
  await writeFile(packet, action.transition.packet, { flag: 'wx', mode: 0o600 });
  await writeJson(input, action.circuitInput);

  const witnessStarted = performance.now();
  await snarkjs.wtns.calculate(action.circuitInput, wasm, witness);
  await chmod(witness, 0o600);
  const witnessCalculationMs = performance.now() - witnessStarted;
  const witnessCheckStarted = performance.now();
  if (!(await snarkjs.wtns.check(r1cs, witness))) {
    fail(`${name} witness failed the supplied R1CS`);
  }
  const witnessCheckMs = performance.now() - witnessCheckStarted;

  const proofStarted = performance.now();
  const generated = await snarkjs.groth16.prove(
    ...snarkjsGroth16ProveArguments(zkey, witness, singleThread),
  );
  const proofGenerationMs = performance.now() - proofStarted;
  exactPublicSignals(action, generated.publicSignals);
  await writeJson(proof, generated.proof);
  await writeJson(publicSignalsFile, generated.publicSignals);

  const verifyStarted = performance.now();
  const proofVerified = await snarkjs.groth16.verify(
    verificationKey,
    generated.publicSignals,
    generated.proof,
  );
  const proofVerificationMs = performance.now() - verifyStarted;
  if (!proofVerified) fail(`${name} Groth16 verification returned false`);

  const proofEvidence = await fileEvidence(proof);
  const publicSignalsEvidence = await fileEvidence(publicSignalsFile);
  const adapter = await adaptV2DirectGroth16({
    verificationKey: {
      path: verificationKeyPath,
      sha256: verificationKeyEvidence.sha256,
    },
    proof: { path: proof, sha256: proofEvidence.sha256 },
    publicSignals: {
      path: publicSignalsFile,
      sha256: publicSignalsEvidence.sha256,
    },
  });
  // The in-process adapter keeps inode/device identity as non-enumerable
  // properties for TOCTOU checks. The published adapter schema intentionally
  // contains only its enumerable transport fields; the pinned verifier loader
  // below revalidates the exact emitted bytes and complete public schema.
  const adapterDocument = JSON.parse(JSON.stringify(adapter));
  await writeJson(adapterFile, adapterDocument);
  const adapterEvidence = await fileEvidence(adapterFile);
  const loadedAdapter = await loadPinnedV2DirectGroth16AdapterResult({
    path: adapterFile,
    sha256: adapterEvidence.sha256,
  });
  if (
    loadedAdapter.fixture.in0 !== action.circuitInput.publicInput0
    || loadedAdapter.fixture.in1 !== action.circuitInput.publicInput1
  ) {
    fail(`${name} V2 Direct Groth16 adapter public inputs do not match the circuit`);
  }

  return Object.freeze({
    packetDigest: action.transition.packetDigest,
    publicInputs: Object.freeze([
      action.circuitInput.publicInput0,
      action.circuitInput.publicInput1,
    ]),
    witnessValid: true,
    proofVerified: true,
    timingsMs: Object.freeze({
      witnessCalculation: witnessCalculationMs,
      witnessCheck: witnessCheckMs,
      proofGeneration: proofGenerationMs,
      proofVerification: proofVerificationMs,
      total: performance.now() - actionStarted,
    }),
    files: Object.freeze({
      packet: await fileEvidence(packet),
      input: await fileEvidence(input),
      witness: await fileEvidence(witness),
      proof: proofEvidence,
      publicSignals: publicSignalsEvidence,
      v2DirectGroth16Adapter: adapterEvidence,
    }),
  });
}

export async function runDevelopmentProofQualification(configuration) {
  const totalStarted = performance.now();
  const {
    r1cs,
    wasm,
    zkey,
    verificationKey: verificationKeyPath,
    profileCore: profileCorePath,
    instanceId,
    maximumLiveNotes,
    outputDirectory,
    singleThread = false,
  } = configuration;
  for (const [label, filename] of [
    ['R1CS', r1cs],
    ['WASM', wasm],
    ['development zkey', zkey],
    ['verification key', verificationKeyPath],
    ['profile core', profileCorePath],
  ]) {
    await assertReadableArtifact(filename, label);
  }
  await prepareOutputDirectory(outputDirectory);

  let verificationKey;
  let profileCore;
  let profileCoreBytes;
  try {
    verificationKey = JSON.parse(await readFile(verificationKeyPath, 'utf8'));
  } catch (error) {
    fail(`verification key is not valid JSON: ${error.message}`);
  }
  if (
    verificationKey === null
    || Array.isArray(verificationKey)
    || typeof verificationKey !== 'object'
  ) {
    fail('verification key JSON must be an object');
  }
  try {
    profileCoreBytes = await readFile(profileCorePath);
    profileCore = JSON.parse(profileCoreBytes.toString('utf8'));
    validateProfileCore(profileCore);
  } catch (error) {
    fail(`profile core is invalid: ${error.message}`);
  }
  const canonicalProfileCore = Buffer.from(
    canonicalizeJcs(profileCore),
    'utf8',
  );
  if (!profileCoreBytes.equals(canonicalProfileCore)) {
    fail('profile core must use exact RFC8785/JCS bytes');
  }
  if (
    profileCore.network.id !== 2
    || profileCore.network.name !== 'chipnet'
    || profileCore.denominationSats !== '10000000'
  ) {
    fail('development qualification requires the exact Chipnet profile');
  }

  const sourceArtifacts = Object.freeze({
    profileCore: await fileEvidence(profileCorePath),
    r1cs: await fileEvidence(r1cs),
    wasm: await fileEvidence(wasm),
    developmentZkey: await fileEvidence(zkey),
    verificationKey: await fileEvidence(verificationKeyPath),
  });
  if (
    sourceArtifacts.r1cs.sha256 !== profileCore.proof.r1csSha256
    || sourceArtifacts.wasm.sha256 !== profileCore.proof.witnessWasmSha256
    || sourceArtifacts.verificationKey.sha256
      !== profileCore.proof.verificationKeySha256
  ) {
    fail('proof artifacts differ from the supplied profile core');
  }
  if (
    typeof instanceId !== 'string'
    || !SHA256.test(instanceId)
    || typeof maximumLiveNotes !== 'string'
    || !DECIMAL.test(maximumLiveNotes)
    || BigInt(maximumLiveNotes) === 0n
    || BigInt(maximumLiveNotes) > 210_000_000n
  ) {
    fail('instance identity or maximumLiveNotes is invalid');
  }
  const profileId = deriveProfileId(profileCore);
  const identity = Object.freeze({
    profileId,
    instanceId,
    maximumLiveNotes,
    denominationSats: profileCore.denominationSats,
  });
  const chain = buildDeterministicDirectV2Chain(identity);
  const actions = {};
  for (const name of ACTION_NAMES) {
    actions[name] = await qualifyAction({
      name,
      action: chain.actions[name],
      outputDirectory,
      r1cs,
      wasm,
      zkey,
      verificationKey,
      verificationKeyPath,
      verificationKeyEvidence: sourceArtifacts.verificationKey,
      singleThread,
    });
  }
  const manifest = createDevelopmentEvidenceManifest({
    identity,
    sourceArtifacts,
    actions: Object.freeze(actions),
    versions: Object.freeze({
      node: process.version,
      snarkjs: await snarkjsVersion(),
    }),
    prover: proverEvidence(singleThread),
    totalWallMs: performance.now() - totalStarted,
    peakRss: peakRssEvidence(),
  });
  const evidencePath = path.join(
    outputDirectory,
    'qualification-evidence.json',
  );
  await writeJson(evidencePath, manifest);
  return Object.freeze({
    evidencePath,
    evidence: manifest,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const configuration = parseQualificationArguments(process.argv.slice(2));
    const result = await runDevelopmentProofQualification(configuration);
    process.stdout.write(stringifyJsonWithBigInts(result), () => {
      // snarkjs/ffjavascript may retain worker-pool handles after all awaited
      // proof work has completed. Exit only after the evidence JSON is flushed.
      process.exit(0);
    });
  } catch (error) {
    process.stderr.write(
      `V2 development proof qualification failed: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
      () => process.exit(1),
    );
  }
}
