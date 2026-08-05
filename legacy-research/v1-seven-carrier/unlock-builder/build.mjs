import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, mkdtempSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  PIN_LENS, ROLE_NAMES, assertPinLens, buildLiveUnlockEnv,
} from './env.mjs';
import { UnlockBuilderError } from './errors.mjs';
import { assertEcipWithinPinBudget } from './ecip-pin-gate.mjs';
import { resolveLeanRoot, resolveTsxBin, resolveUnlockRoot } from './resolve.mjs';
import { assertSafeReplaceDirectory } from '../kit/safe-paths.mjs';

export { UnlockBuilderError };
const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
);

function sha256File(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

function ensureAbsFile(filePath, label) {
  const resolved = path.resolve(filePath);
  if (!existsSync(resolved)) {
    throw new UnlockBuilderError('MISSING_INPUT', `${label} not found: ${resolved}`);
  }
  return resolved;
}

/**
 * Build 7 verifier unlocks for one proof+packet under the live densFuel pin.
 *
 * Preflights ECIP nfail ≤ pin maxTry (2) before densFuel spawn. On ECIP_NFAIL
 * the proof's public inputs are outside the pin envelope — re-prove with
 * different public inputs; never retry unlock on the same adapter.
 *
 * @param {{
 *   adapterPath: string,
 *   packetPath: string,
 *   outDir: string,
 *   unlockRoot?: string,
 *   leanRoot?: string,
 *   expectedLocksHex?: string[],
 *   requirePinLens?: boolean,
 *   keepStage?: boolean,
 *   skipEcipGate?: boolean,
 * }} input
 */
export async function buildVerifierUnlocks(input) {
  if (!input || typeof input !== 'object') {
    throw new UnlockBuilderError('INVALID_INPUT', 'buildVerifierUnlocks requires an object');
  }
  const adapterPath = ensureAbsFile(input.adapterPath, 'adapterPath');
  const packetPath = ensureAbsFile(input.packetPath, 'packetPath');
  if (!input.outDir || typeof input.outDir !== 'string') {
    throw new UnlockBuilderError('INVALID_INPUT', 'outDir is required');
  }
  const outDir = assertSafeReplaceDirectory(input.outDir, {
    repositoryRoot: REPOSITORY_ROOT,
  });
  const requirePinLens = input.requirePinLens !== false;

  // Quiet by default (product path). Verbose only when explicitly requested:
  //   input.quiet === false | SHIELDKIT_VERBOSE=1 | SHIELDKIT_UNLOCK_VERBOSE=1 | --verbose
  const verboseEnv = process.env.SHIELDKIT_VERBOSE === '1'
    || process.env.SHIELDKIT_UNLOCK_VERBOSE === '1'
    || (Array.isArray(process.argv) && process.argv.includes('--verbose'));
  const quiet = input.quiet === true
    || (input.quiet !== false && process.env.SHIELDKIT_UNLOCK_QUIET !== '0' && !verboseEnv);
  const log = (obj) => {
    if (!quiet) console.error(JSON.stringify(obj));
  };

  // Fundamental gate: pin genesis require(nfail<=2). Fail in ~1s, not 30s×retries.
  if (input.skipEcipGate !== true) {
    const tEcip = Date.now();
    const budget = await assertEcipWithinPinBudget({ adapterPath });
    log({
      phase: 'ecip-pin-gate',
      nfail: budget.nfail,
      maxTry: budget.maxTry,
      retry0: budget.retry0,
      ms: Date.now() - tEcip,
    });
  }

  const unlockRoot = resolveUnlockRoot({ unlockRoot: input.unlockRoot });
  const leanRoot = resolveLeanRoot({ leanRoot: input.leanRoot });
  const tsxBin = resolveTsxBin(unlockRoot);

  rmSync(outDir, { recursive: true, force: true });
  const buildDir = path.join(outDir, 'build');
  const genDir = path.join(outDir, 'generated');
  // tsx IPC uses unix sockets under TMPDIR; AF_UNIX sun_path ~108 bytes.
  // Deep outDir paths (…/pool/runs/…/unlocks-…/tmp-…) overflow → EADDRINUSE/ENOENT.
  // Always use a short system temp dir for the compile subprocess.
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), `sk-ul-${process.pid}-`));
  mkdirSync(buildDir, { recursive: true });
  mkdirSync(genDir, { recursive: true });

  const adapterSha256 = sha256File(adapterPath);
  const packetSha256 = sha256File(packetPath);

  const pathPrefix = [
    path.join(unlockRoot, 'harness/node_modules/.bin'),
    path.dirname(tsxBin) !== '.' ? path.dirname(tsxBin) : null,
  ].filter(Boolean).join(':');

  const nodePath = [
    path.join(unlockRoot, 'vendor/cashc-resched/node_modules'),
    path.join(unlockRoot, 'node_modules'),
    path.join(unlockRoot, 'harness/node_modules'),
  ].filter((p) => existsSync(p)).join(':');

  const env = buildLiveUnlockEnv({
    unlockRoot,
    leanRoot,
    adapterPath,
    adapterSha256,
    packetPath,
    packetSha256,
    buildDir,
    genDir,
    tmpDir,
    pathPrefix,
    nodePath,
  });

  log({
    phase: 'unlock-build-start',
    unlockRoot,
    leanRoot,
    adapterSha256: adapterSha256.slice(0, 16),
    packetSha256: packetSha256.slice(0, 16),
    note: 'densFuel pin compile typically 25–40s',
  });

  const t0 = Date.now();
  // Heartbeat while compile runs (tsx is opaque; tick every 5s).
  let heartbeat;
  if (!quiet) {
    heartbeat = setInterval(() => {
      log({ phase: 'unlock-build-progress', elapsedMs: Date.now() - t0 });
    }, 5000);
  }
  let r;
  try {
    r = spawnSync(tsxBin, ['lanes/bn254-onetx/src/c7/build.ts'], {
      cwd: unlockRoot,
      env,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    // Best-effort cleanup of short-lived TMPDIR (do not fail the build on rm).
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  const ms = Date.now() - t0;
  const logText = `${r.stdout || ''}${r.stderr || ''}`;
  writeFileSync(path.join(outDir, 'build.log'), logText);
  log({
    phase: 'unlock-build-spawn-done',
    ms,
    status: r.status,
    signal: r.signal ?? null,
    error: r.error ? { code: r.error.code, message: r.error.message } : null,
    logBytes: logText.length,
    tsxBin,
  });

  // spawnSync: missing binary → status null + error ENOENT (was reported as "exit null")
  if (r.error) {
    throw new UnlockBuilderError(
      'SPAWN_FAIL',
      `unlock build spawn failed: ${r.error.message}`
        + (r.error.code === 'ENOENT'
          ? ' — run root `npm ci`, then `npm run unlock-builder:setup`'
          : ''),
      {
        status: r.status,
        signal: r.signal,
        errno: r.error.code,
        ms,
        tsxBin,
        unlockRoot,
        logTail: logText.slice(-4000),
      },
    );
  }
  if (r.status !== 0) {
    throw new UnlockBuilderError('BUILD_EXIT', `unlock build exit ${r.status}${r.signal ? ` signal=${r.signal}` : ''}`, {
      status: r.status,
      signal: r.signal,
      ms,
      logTail: logText.slice(-4000),
      unlockRoot,
      tsxBin,
    });
  }

  const resultPath = path.join(buildDir, 'result.json');
  const dumpPath = path.join(buildDir, 'inputs_dump.json');
  if (!existsSync(resultPath) || !existsSync(dumpPath)) {
    throw new UnlockBuilderError('MISSING_OUTPUT', 'result.json or inputs_dump.json missing', { ms, unlockRoot });
  }

  const result = JSON.parse(readFileSync(resultPath, 'utf8'));
  const dump = JSON.parse(readFileSync(dumpPath, 'utf8'));

  if (result.gateOk !== true) {
    const gen = (result.manual || []).find((row) => row.name === 'genesis' || row.i === 5);
    throw new UnlockBuilderError(
      'GATE_FAIL',
      `gateOk false genesis.accepts=${gen?.accepts} err=${String(gen?.error || '').slice(0, 120)}`,
      { ms, result },
    );
  }

  if (!Array.isArray(dump) || dump.length < 7) {
    throw new UnlockBuilderError('BAD_DUMP', `inputs_dump expected ≥7 rows, got ${dump?.length}`, { ms });
  }

  const roles = dump.slice(0, 7).map((row, i) => {
    const unlockHex = row.unlock;
    const lockHex = row.lock;
    if (typeof unlockHex !== 'string' || typeof lockHex !== 'string') {
      throw new UnlockBuilderError('BAD_DUMP', `row ${i} missing lock/unlock hex`);
    }
    return {
      name: ROLE_NAMES[i],
      lockHex,
      unlockHex,
      unlockLen: unlockHex.length / 2,
      lockingBytecode: Buffer.from(lockHex, 'hex'),
      unlockingBytecode: Buffer.from(unlockHex, 'hex'),
    };
  });

  const lens = roles.map((role) => role.unlockLen);
  if (requirePinLens) assertPinLens(lens);

  if (input.expectedLocksHex) {
    if (!Array.isArray(input.expectedLocksHex) || input.expectedLocksHex.length !== 7) {
      throw new UnlockBuilderError('INVALID_INPUT', 'expectedLocksHex must be length-7');
    }
    for (let i = 0; i < 7; i++) {
      if (roles[i].lockHex !== input.expectedLocksHex[i]) {
        throw new UnlockBuilderError(
          'LOCK_MISMATCH',
          `lock mismatch role ${ROLE_NAMES[i]} index ${i}`,
          { got: roles[i].lockHex, want: input.expectedLocksHex[i] },
        );
      }
    }
  }

  log({
    phase: 'unlock-build-ok',
    ms,
    lens,
    wire: result.wire,
    gateOk: true,
  });

  return {
    ok: true,
    roles,
    lens,
    pinLens: [...PIN_LENS],
    gateOk: true,
    wire: result.wire,
    ms,
    unlockRoot,
    leanRoot,
    result,
    dump,
    outDir,
    buildDir,
  };
}
