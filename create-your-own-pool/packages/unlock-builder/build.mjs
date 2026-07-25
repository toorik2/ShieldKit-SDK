import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  PIN_LENS, ROLE_NAMES, assertPinLens, buildLiveUnlockEnv,
} from './env.mjs';
import { resolveLeanRoot, resolveTsxBin, resolveUnlockRoot } from './resolve.mjs';

export class UnlockBuilderError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = 'UnlockBuilderError';
    this.code = code;
    Object.assign(this, extra);
  }
}

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
 * @param {{
 *   adapterPath: string,
 *   packetPath: string,
 *   outDir: string,
 *   unlockRoot?: string,
 *   leanRoot?: string,
 *   expectedLocksHex?: string[],
 *   requirePinLens?: boolean,
 *   keepStage?: boolean,
 * }} input
 */
export function buildVerifierUnlocks(input) {
  if (!input || typeof input !== 'object') {
    throw new UnlockBuilderError('INVALID_INPUT', 'buildVerifierUnlocks requires an object');
  }
  const adapterPath = ensureAbsFile(input.adapterPath, 'adapterPath');
  const packetPath = ensureAbsFile(input.packetPath, 'packetPath');
  if (!input.outDir || typeof input.outDir !== 'string') {
    throw new UnlockBuilderError('INVALID_INPUT', 'outDir is required');
  }
  const outDir = path.resolve(input.outDir);
  const requirePinLens = input.requirePinLens !== false;

  const unlockRoot = resolveUnlockRoot({ unlockRoot: input.unlockRoot });
  const leanRoot = resolveLeanRoot({ leanRoot: input.leanRoot });
  const tsxBin = resolveTsxBin(unlockRoot);

  rmSync(outDir, { recursive: true, force: true });
  const buildDir = path.join(outDir, 'build');
  const genDir = path.join(outDir, 'generated');
  const tmpDir = path.join(
    outDir,
    `tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
  );
  mkdirSync(buildDir, { recursive: true });
  mkdirSync(genDir, { recursive: true });
  mkdirSync(tmpDir, { recursive: true });

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

  const t0 = Date.now();
  const r = spawnSync(tsxBin, ['lanes/bn254-onetx/src/c7/build.ts'], {
    cwd: unlockRoot,
    env,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const ms = Date.now() - t0;
  const logText = `${r.stdout || ''}${r.stderr || ''}`;
  writeFileSync(path.join(outDir, 'build.log'), logText);

  if (r.status !== 0) {
    throw new UnlockBuilderError('BUILD_EXIT', `unlock build exit ${r.status}`, {
      status: r.status,
      ms,
      logTail: logText.slice(-4000),
      unlockRoot,
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
