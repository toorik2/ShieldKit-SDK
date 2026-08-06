/**
 * Shared helpers: run the shipped native Groth16 prove path using an installed
 * product data-home (receipt-bound artifacts + linked runtime + native prover).
 */
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { loadV2BetaProductArtifactInstallation } from '../../packages/profile/v2/beta-product-artifact-installation.mjs';
import {
  deriveV2BetaChipnetNativeProofArtifacts,
  loadV2BetaProductLinkedRuntimeCache,
} from '../../packages/profile/v2/beta-chipnet-runtime.mjs';
import { loadV2NativeGroth16ProverInstallation } from '../../packages/prove/v2/native-groth16-prover-installation.mjs';
import { proveV2DirectNativeGroth16Default } from '../../packages/prove/v2/native-groth16-proof-worker.mjs';
import {
  DIRECT_V2_PF10_MAX_UNLOCK_BYTES,
  DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES,
} from '../../packages/unlock-builder/v2/pf10-action-witness.mjs';

export class BenchProductProveError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'BenchProductProveError';
    this.code = code;
  }
}

const fail = (code, message, cause) => {
  throw new BenchProductProveError(code, message, cause === undefined ? undefined : { cause });
};

/**
 * Env-only data-home (no author/machine defaults).
 * Prefer requireProductDataHome from ../data-home.mjs for path validation.
 */
export function resolveBenchDataHome() {
  if (typeof process.env.SHIELDKIT_BENCH_DATA_HOME === 'string'
    && process.env.SHIELDKIT_BENCH_DATA_HOME.length > 0) {
    return path.resolve(process.env.SHIELDKIT_BENCH_DATA_HOME);
  }
  if (typeof process.env.SHIELDKIT_DATA_HOME === 'string'
    && process.env.SHIELDKIT_DATA_HOME.length > 0) {
    return path.resolve(process.env.SHIELDKIT_DATA_HOME);
  }
  return null;
}

export async function loadProductSession(dataDirectory) {
  const productDataDirectory = path.resolve(dataDirectory);
  let install;
  try {
    install = await loadV2BetaProductArtifactInstallation({ productDataDirectory });
  } catch (error) {
    fail(
      'BENCH_ARTIFACTS_REQUIRED',
      'product artifact installation missing; set SHIELDKIT_BENCH_DATA_HOME to a data-home with offline pin install',
      error,
    );
  }
  const sessionPath = path.join(productDataDirectory, 'session.json');
  let session;
  try {
    session = JSON.parse(await readFile(sessionPath, 'utf8'));
  } catch (error) {
    fail('BENCH_SESSION_REQUIRED', `cannot read session.json under ${productDataDirectory}`, error);
  }
  // Instance id from wallet DB is preferred; fall back to runtime-cache sole entry.
  const cacheRoot = session.runtimeCacheRoot
    || path.join(productDataDirectory, 'runtime-cache');
  let instanceId = process.env.SHIELDKIT_BENCH_INSTANCE_ID;
  if (typeof instanceId !== 'string' || !/^[0-9a-f]{64}$/u.test(instanceId)) {
    const { readdir } = await import('node:fs/promises');
    const entries = await readdir(cacheRoot).catch(() => []);
    // Linked cache dirs are 64-hex generation ids, not instance ids — load fails without instance.
    // Read from store/wallet if present.
    try {
      const DatabaseSync = (await import('node:sqlite')).DatabaseSync;
      const walletPath = session.walletDatabasePath
        || path.join(productDataDirectory, 'wallet/wallet.sqlite');
      const db = new DatabaseSync(walletPath, { readOnly: true });
      const row = db.prepare(
        'SELECT instance_id FROM wallet_metadata WHERE singleton = 1',
      ).get();
      db.close();
      instanceId = row?.instance_id;
    } catch {
      // fall through
    }
  }
  if (typeof instanceId !== 'string' || !/^[0-9a-f]{64}$/u.test(instanceId)) {
    fail(
      'BENCH_INSTANCE_REQUIRED',
      'set SHIELDKIT_BENCH_INSTANCE_ID to the 64-hex instance id for this data-home',
    );
  }
  const resolution = await loadV2BetaProductLinkedRuntimeCache({
    artifactInstallation: install,
    cacheRoot,
    instanceId,
  });
  const artifacts = deriveV2BetaChipnetNativeProofArtifacts(resolution);
  const nativeDir = session.nativeProverDirectory
    || path.join(productDataDirectory, 'v2-beta-product-artifacts', 'native');
  const nativeProverInstallation = await loadV2NativeGroth16ProverInstallation({
    installationDirectory: nativeDir,
  });
  const workspaceDirectory = session.proofWorkspaceDirectory
    || path.join(productDataDirectory, 'proof-workspace');
  await mkdir(workspaceDirectory, { recursive: true, mode: 0o700 });
  await chmod(workspaceDirectory, 0o700);
  const depositInputPath = path.join(
    productDataDirectory,
    'v2-beta-product-artifacts/runtime/qualification/actions/deposit/input.json',
  );
  const depositPublicPath = path.join(
    productDataDirectory,
    'v2-beta-product-artifacts/runtime/qualification/actions/deposit/public.json',
  );
  let circuitInput;
  let expectedPublicInputs;
  try {
    circuitInput = JSON.parse(await readFile(depositInputPath, 'utf8'));
    expectedPublicInputs = JSON.parse(await readFile(depositPublicPath, 'utf8'));
  } catch (error) {
    fail(
      'BENCH_QUAL_INPUT_REQUIRED',
      'deposit qualification input/public missing under v2-beta-product-artifacts/runtime/qualification',
      error,
    );
  }
  return Object.freeze({
    productDataDirectory,
    instanceId,
    install,
    artifacts,
    nativeProverInstallation,
    workspaceDirectory,
    circuitInput,
    expectedPublicInputs,
  });
}

/** One deposit-shaped native prove via shipped worker (first try only). */
export async function proveDepositOnce(session) {
  const started = performance.now();
  const result = await proveV2DirectNativeGroth16Default({
    artifacts: session.artifacts,
    circuitInput: session.circuitInput,
    expectedPublicInputs: session.expectedPublicInputs,
    nativeProverInstallation: session.nativeProverInstallation,
    workspaceDirectory: session.workspaceDirectory,
  });
  const wallMs = performance.now() - started;
  return Object.freeze({
    proofGenerationMs: result.timingsMs.proofGeneration,
    witnessCalculationMs: result.timingsMs.witnessCalculation,
    proofVerificationMs: result.timingsMs.proofVerification,
    proofTotalMs: result.timingsMs.total,
    wallMs,
  });
}

/** Designed PF10 max verifier unlock length (product assembly budget, real constant). */
export function designedMaxUnlockBytes() {
  const maxVerifier = Math.max(...DIRECT_V2_PF10_VERIFIER_UNLOCK_BYTES);
  if (maxVerifier > DIRECT_V2_PF10_MAX_UNLOCK_BYTES) {
    fail(
      'BENCH_UNLOCK_BUDGET',
      `designed unlock ${maxVerifier} exceeds product max ${DIRECT_V2_PF10_MAX_UNLOCK_BYTES}`,
    );
  }
  return maxVerifier;
}

export function productRootFromBench() {
  // .../shieldkit-groth/bench/pf10-baseline → monorepo root (package.json + .git)
  return path.resolve(import.meta.dirname, '../../..');
}

export async function resolveFirstUsableDataHome() {
  const home = resolveBenchDataHome();
  if (home === null) {
    fail(
      'BENCH_DATA_HOME_REQUIRED',
      'set SHIELDKIT_BENCH_DATA_HOME (or SHIELDKIT_DATA_HOME) to an absolute product data-home with session.json',
    );
  }
  try {
    return await loadProductSession(home);
  } catch (error) {
    fail(
      'BENCH_DATA_HOME_UNAVAILABLE',
      `no usable product data-home at ${home}: ${error.code || error.message}`,
      error,
    );
  }
}

export async function writeJson(filename, value) {
  await mkdir(path.dirname(filename), { recursive: true });
  await writeFile(filename, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}
