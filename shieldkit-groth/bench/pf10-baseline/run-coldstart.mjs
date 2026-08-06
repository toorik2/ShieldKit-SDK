#!/usr/bin/env node
/**
 * Optional blank-machine cold-start story.
 *
 * Modes:
 *   (default)           Inventory + disk sizes of current tree / live data-home
 *   --sandbox DIR       Temporary clean sandbox: git clone + npm ci, then
 *                       optional proves against the **live** data-home (no pool setup)
 *   --time-npm-ci       Legacy: npm ci into --work-root without full clone
 *   --time-prove        Two deposit-shaped proves against --data-home (live pool)
 *
 * Live pool (default if unset):
 *   SHIELDKIT_BENCH_DATA_HOME or packed-live / final-ready candidates
 *
 * Cleanup: sandbox removed unless SHIELDKIT_BENCH_KEEP_COLDSTART=1
 */
import { spawnSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { mkdir, readdir, rm, writeFile, cp } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  DESIGN_PF10_BASELINE,
  resolveGitCommit,
} from '../scorecard.mjs';
import {
  buildColdstartReport,
  formatColdstartTable,
} from '../coldstart.mjs';
import {
  productRootFromBench,
  proveDepositOnce,
  resolveFirstUsableDataHome,
  resolveBenchDataHome,
  loadProductSession,
} from './product-prove.mjs';

const DEFAULT_LIVE_DATA_HOMES = Object.freeze([
  '/home/toorik/.local/share/shieldkit-packed-live-d06632c/shieldkit/v2-beta-product',
  '/home/toorik/.local/share/shieldkit-final-ready-140c183/shieldkit/v2-beta-product',
]);

function parseArgs(argv) {
  const out = {
    dataHome: process.env.SHIELDKIT_BENCH_DATA_HOME || null,
    timeNpmCi: false,
    timeProve: false,
    workRoot: null,
    sandbox: null,
    keep: process.env.SHIELDKIT_BENCH_KEEP_COLDSTART === '1',
    jsonOut: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--data-home') out.dataHome = path.resolve(argv[++i] ?? '');
    else if (a === '--time-npm-ci') out.timeNpmCi = true;
    else if (a === '--time-prove') out.timeProve = true;
    else if (a === '--work-root') out.workRoot = path.resolve(argv[++i] ?? '');
    else if (a === '--sandbox') out.sandbox = path.resolve(argv[++i] ?? '');
    else if (a === '--keep') out.keep = true;
    else if (a === '--json-out') out.jsonOut = path.resolve(argv[++i] ?? '');
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  if (out.sandbox) {
    // Sandbox mode implies clone + npm ci + prove against live pool
    out.timeProve = true;
  }
  return out;
}

function normalizeProductDataHome(home) {
  if (typeof home !== 'string' || home.length === 0) return null;
  const abs = path.resolve(home);
  if (abs.endsWith(`${path.sep}v2-beta-product`)) return abs;
  const nested = path.join(abs, 'shieldkit', 'v2-beta-product');
  if (existsSync(path.join(nested, 'session.json'))) return nested;
  if (existsSync(path.join(abs, 'session.json'))) return abs;
  return abs;
}

function resolveLiveDataHome(explicit) {
  if (explicit) return normalizeProductDataHome(explicit);
  if (process.env.SHIELDKIT_BENCH_DATA_HOME) {
    return normalizeProductDataHome(process.env.SHIELDKIT_BENCH_DATA_HOME);
  }
  for (const c of DEFAULT_LIVE_DATA_HOMES) {
    if (existsSync(path.join(c, 'session.json'))) return c;
  }
  const list = resolveBenchDataHome();
  const arr = Array.isArray(list) ? list : [list];
  for (const c of arr) {
    const n = normalizeProductDataHome(c);
    if (n && existsSync(path.join(n, 'session.json'))) return n;
  }
  return null;
}

async function dirBytes(root) {
  if (!existsSync(root)) return null;
  let total = 0;
  async function walk(dir) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      const p = path.join(dir, ent.name);
      try {
        if (ent.isDirectory() && !ent.isSymbolicLink()) await walk(p);
        else if (ent.isFile()) total += statSync(p).size;
        else if (ent.isSymbolicLink()) {
          total += statSync(p, { throwIfNoEntry: false })?.size ?? 0;
        }
      } catch {
        // ignore
      }
    }
  }
  await walk(root);
  return total;
}

function timeCommand(cmd, args, cwd, env = process.env) {
  const started = performance.now();
  const result = spawnSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    env: { ...env },
    maxBuffer: 64 * 1024 * 1024,
  });
  const ms = performance.now() - started;
  return {
    ms,
    status: result.status,
    stderr: result.stderr || '',
    stdout: result.stdout || '',
  };
}

async function measureProves(session) {
  const cold = await proveDepositOnce(session);
  const warm = await proveDepositOnce(session);
  return { cold, warm };
}

/** Prove using modules loaded from a sandbox repo (sandbox node_modules). */
async function measureProvesFromSandbox(sandboxRepo, liveDataHome) {
  const proveUrl = pathToFileURL(
    path.join(sandboxRepo, 'shieldkit-groth/bench/pf10-baseline/product-prove.mjs'),
  ).href;
  const mod = await import(proveUrl);
  const session = await mod.loadProductSession(liveDataHome);
  const cold = await mod.proveDepositOnce(session);
  const warm = await mod.proveDepositOnce(session);
  return { cold, warm, instanceId: session.instanceId };
}

async function runSandboxMode(args, root, commit) {
  const liveHome = resolveLiveDataHome(args.dataHome);
  if (!liveHome) {
    throw new Error(
      'sandbox mode needs a live pool data-home '
      + '(--data-home …/v2-beta-product or SHIELDKIT_BENCH_DATA_HOME)',
    );
  }

  const sandboxRoot = args.sandbox;
  await mkdir(sandboxRoot, { recursive: true });
  const repoDir = path.join(sandboxRoot, 'repo');
  if (existsSync(repoDir)) {
    await rm(repoDir, { recursive: true, force: true });
  }

  const steps = [];
  let timedMs = 0;

  // 1) clone
  const clone = timeCommand(
    'git',
    ['clone', '--depth', '1', '--single-branch', root, repoDir],
    sandboxRoot,
  );
  const cloneBytes = await dirBytes(repoDir);
  steps.push({
    id: 'clone',
    ms: clone.ms,
    bytes: cloneBytes,
    ok: clone.status === 0,
    detail: clone.status === 0
      ? `git clone --depth 1 → ${repoDir}`
      : `git clone failed: ${clone.stderr.slice(0, 240)}`,
  });
  if (clone.status === 0) timedMs += clone.ms;
  else {
    return finishReport({
      commit, steps, timedMs, diskBytes: cloneBytes || 0, args, liveHome,
      notes: 'sandbox aborted after clone failure',
    });
  }

  // 2) npm ci (full postinstall — real first-build)
  const npmEnv = { ...process.env };
  delete npmEnv.NODE_OPTIONS;
  delete npmEnv.NODE_PATH;
  const npmResult = timeCommand('npm', ['ci'], repoDir, npmEnv);

  const nmBytes = await dirBytes(path.join(repoDir, 'node_modules'));
  steps.push({
    id: 'npm_ci',
    ms: npmResult.ms,
    bytes: nmBytes,
    ok: npmResult.status === 0,
    detail: npmResult.status === 0
      ? 'npm ci in sandbox repo (full postinstall)'
      : `npm ci failed exit=${npmResult.status}: ${npmResult.stderr.slice(0, 300)}`,
  });
  if (npmResult.status === 0) timedMs += npmResult.ms;

  // 3–5 live pool footprints (not reinstalled — by design)
  const nativeDir = path.join(liveHome, 'v2-beta-product-artifacts', 'native');
  const artDir = path.join(liveHome, 'v2-beta-product-artifacts');
  const cacheDir = path.join(liveHome, 'runtime-cache');
  const nativeBytes = await dirBytes(nativeDir);
  const artBytes = await dirBytes(artDir);
  const cacheBytes = await dirBytes(cacheDir);

  steps.push({
    id: 'native_prover',
    ms: null,
    bytes: nativeBytes,
    ok: existsSync(path.join(nativeDir, 'bin', 'prover')),
    detail: `live pool (not reinstalled): ${nativeDir}`,
  });
  steps.push({
    id: 'artifact_install',
    ms: null,
    bytes: artBytes,
    ok: existsSync(artDir),
    detail: `live pool artifacts (not reinstalled): ${artDir}`,
  });
  steps.push({
    id: 'runtime_link',
    ms: null,
    bytes: cacheBytes,
    ok: existsSync(cacheDir),
    detail: `live pool runtime-cache: ${cacheDir}`,
  });

  // 6–7 prove from sandbox code against live pool
  if (npmResult.status === 0 && args.timeProve) {
    try {
      const { cold, warm, instanceId } = await measureProvesFromSandbox(repoDir, liveHome);
      steps.push({
        id: 'first_prove_cold',
        ms: cold.wallMs,
        ok: true,
        detail: `sandbox code + live pool instance=${instanceId}; proofGen=${Math.round(cold.proofGenerationMs)}ms`,
      });
      steps.push({
        id: 'second_prove_warm',
        ms: warm.wallMs,
        ok: true,
        detail: `proofGen=${Math.round(warm.proofGenerationMs)}ms`,
      });
      timedMs += cold.wallMs + warm.wallMs;
    } catch (error) {
      steps.push({
        id: 'first_prove_cold',
        ms: null,
        ok: false,
        detail: `${error.code || 'ERROR'}: ${error.message}`,
      });
      steps.push({
        id: 'second_prove_warm',
        ms: null,
        ok: false,
        detail: 'skipped after cold prove failure',
      });
    }
  } else {
    steps.push({
      id: 'first_prove_cold',
      ms: null,
      ok: null,
      detail: npmResult.status === 0 ? 'prove skipped' : 'skipped (npm ci failed)',
    });
    steps.push({
      id: 'second_prove_warm',
      ms: null,
      ok: null,
      detail: 'skipped',
    });
  }

  const sandboxBytes = await dirBytes(sandboxRoot);
  // Avoid double-counting live artifacts inside sandbox total: report sandbox + live art
  const diskBytes = (sandboxBytes || 0) + (artBytes || 0);
  steps.push({
    id: 'disk_footprint',
    ms: null,
    bytes: diskBytes,
    ok: true,
    detail: `sandbox=${formatShortBytes(sandboxBytes)} + live artifacts=${formatShortBytes(artBytes)}`,
  });

  const report = await finishReport({
    commit,
    steps,
    timedMs,
    diskBytes,
    args,
    liveHome,
    notes: `sandbox at ${sandboxRoot}; live pool ${liveHome}; pool setup not performed`,
  });

  if (!args.keep) {
    await rm(sandboxRoot, { recursive: true, force: true }).catch(() => undefined);
  } else {
    process.stdout.write(`\n(kept sandbox: ${sandboxRoot})\n`);
  }
  return report;
}

function formatShortBytes(n) {
  if (n == null) return 'n/a';
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}

async function finishReport({
  commit, steps, timedMs, diskBytes, args, liveHome, notes,
}) {
  const report = buildColdstartReport({
    design: DESIGN_PF10_BASELINE,
    commit,
    steps,
    totals: {
      timedMs: timedMs || null,
      diskBytes: diskBytes || null,
    },
    notes: notes
      + (liveHome ? `; liveDataHome=${liveHome}` : ''),
  });
  process.stdout.write(`${formatColdstartTable(report)}\n`);
  if (args.jsonOut) {
    await mkdir(path.dirname(args.jsonOut), { recursive: true });
    await writeFile(args.jsonOut, `${JSON.stringify(report, null, 2)}\n`);
  }
  return report;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(
      'usage:\n'
      + '  # temporary clean sandbox (clone + npm ci + prove vs live pool)\n'
      + '  node run-coldstart.mjs --sandbox /abs/empty/dir \\\n'
      + '    [--data-home /abs/.../v2-beta-product] [--json-out file] [--keep]\n'
      + '\n'
      + '  # inventory only\n'
      + '  node run-coldstart.mjs [--data-home ABS] [--json-out file]\n'
      + '\n'
      + '  # opt-in pieces without full sandbox\n'
      + '  node run-coldstart.mjs --time-prove --data-home ABS\n'
      + '  node run-coldstart.mjs --time-npm-ci --work-root ABS\n'
      + '\n'
      + 'Sandbox does NOT create a pool; it uses the default/live data-home for prove.\n'
      + 'Keep sandbox: --keep or SHIELDKIT_BENCH_KEEP_COLDSTART=1\n',
    );
    return;
  }

  const root = productRootFromBench();
  const commit = resolveGitCommit(root);

  if (args.sandbox) {
    await runSandboxMode(args, root, commit);
    return;
  }

  // ── inventory / partial timer mode (original) ─────────────────────
  const steps = [];
  let timedMs = 0;
  let diskBytes = 0;
  const liveHome = resolveLiveDataHome(args.dataHome);

  const gitDir = path.join(root, '.git');
  const repoBytes = await dirBytes(root);
  steps.push({
    id: 'clone',
    ms: null,
    bytes: repoBytes,
    ok: existsSync(gitDir),
    detail: existsSync(gitDir)
      ? 'existing checkout (use --sandbox DIR for timed git clone)'
      : 'no .git',
  });
  if (repoBytes) diskBytes += repoBytes;

  const nm = path.join(root, 'node_modules');
  const nmBytes = await dirBytes(nm);
  if (args.timeNpmCi) {
    if (!args.workRoot) throw new Error('--time-npm-ci requires --work-root ABS');
    await mkdir(args.workRoot, { recursive: true });
    const dest = path.join(args.workRoot, `npm-ci-${Date.now()}`);
    await mkdir(dest, { recursive: true });
    for (const name of ['package.json', 'package-lock.json', '.npmrc', '.npmignore']) {
      const src = path.join(root, name);
      if (existsSync(src)) await cp(src, path.join(dest, name));
    }
    const rsync = timeCommand(
      'rsync',
      ['-a', '--exclude', 'node_modules', '--exclude', '.git',
        `${root}/shieldkit-groth/`, `${dest}/shieldkit-groth/`],
      root,
    );
    if (rsync.status !== 0) {
      steps.push({
        id: 'npm_ci',
        ms: rsync.ms,
        ok: false,
        detail: `rsync failed: ${rsync.stderr?.slice(0, 200)}`,
      });
    } else {
      const npmEnv = { ...process.env };
      delete npmEnv.NODE_OPTIONS;
      delete npmEnv.NODE_PATH;
      const ci = timeCommand('npm', ['ci'], dest, npmEnv);
      const ms = ci.ms;
      timedMs += ms;
      const bytes = await dirBytes(path.join(dest, 'node_modules'));
      steps.push({
        id: 'npm_ci',
        ms,
        bytes,
        ok: ci.status === 0,
        detail: `npm ci exit=${ci.status}`,
      });
      if (!args.keep) await rm(dest, { recursive: true, force: true });
    }
  } else {
    steps.push({
      id: 'npm_ci',
      ms: null,
      bytes: nmBytes,
      ok: existsSync(nm),
      detail: existsSync(nm)
        ? 'node_modules present (use --sandbox or --time-npm-ci to time install)'
        : 'node_modules missing',
    });
    if (nmBytes) diskBytes += nmBytes;
  }

  const productDir = liveHome;
  if (productDir) {
    const nativeDir = path.join(productDir, 'v2-beta-product-artifacts', 'native');
    const artDir = path.join(productDir, 'v2-beta-product-artifacts');
    const cacheDir = path.join(productDir, 'runtime-cache');
    const nativeBytes = await dirBytes(nativeDir);
    const artBytes = await dirBytes(artDir);
    const cacheBytes = await dirBytes(cacheDir);
    steps.push({
      id: 'native_prover',
      ms: null,
      bytes: nativeBytes,
      ok: existsSync(path.join(nativeDir, 'bin', 'prover')),
      detail: nativeDir,
    });
    steps.push({
      id: 'artifact_install',
      ms: null,
      bytes: artBytes,
      ok: existsSync(artDir),
      detail: artDir,
    });
    steps.push({
      id: 'runtime_link',
      ms: null,
      bytes: cacheBytes,
      ok: existsSync(cacheDir),
      detail: cacheDir || 'none',
    });
    if (artBytes) diskBytes += artBytes;
    else if (nativeBytes) diskBytes += nativeBytes;
    if (cacheBytes) diskBytes += cacheBytes;
  } else {
    steps.push({ id: 'native_prover', ms: null, ok: false, detail: 'no live data-home' });
    steps.push({ id: 'artifact_install', ms: null, ok: false, detail: 'no live data-home' });
    steps.push({ id: 'runtime_link', ms: null, ok: false, detail: 'no live data-home' });
  }

  if (args.timeProve) {
    try {
      if (args.dataHome) process.env.SHIELDKIT_BENCH_DATA_HOME = normalizeProductDataHome(args.dataHome);
      const session = liveHome
        ? await loadProductSession(liveHome)
        : await resolveFirstUsableDataHome();
      const { cold, warm } = await measureProves(session);
      steps.push({
        id: 'first_prove_cold',
        ms: cold.wallMs,
        ok: true,
        detail: `proofGen=${Math.round(cold.proofGenerationMs)}ms`,
      });
      steps.push({
        id: 'second_prove_warm',
        ms: warm.wallMs,
        ok: true,
        detail: `proofGen=${Math.round(warm.proofGenerationMs)}ms`,
      });
      timedMs += cold.wallMs + warm.wallMs;
    } catch (error) {
      steps.push({
        id: 'first_prove_cold',
        ms: null,
        ok: false,
        detail: error.message,
      });
      steps.push({
        id: 'second_prove_warm',
        ms: null,
        ok: false,
        detail: 'skipped after cold prove failure',
      });
    }
  } else {
    steps.push({
      id: 'first_prove_cold',
      ms: null,
      ok: null,
      detail: 'pass --time-prove or --sandbox to measure',
    });
    steps.push({
      id: 'second_prove_warm',
      ms: null,
      ok: null,
      detail: 'pass --time-prove or --sandbox to measure',
    });
  }

  steps.push({
    id: 'disk_footprint',
    ms: null,
    bytes: diskBytes,
    ok: diskBytes > 0,
    detail: 'approx sum of measured roots',
  });

  await finishReport({
    commit,
    steps,
    timedMs,
    diskBytes,
    args,
    liveHome,
    notes: args.timeNpmCi || args.timeProve
      ? 'includes opt-in timers'
      : 'inventory-only; use --sandbox DIR for clean temporary install',
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack || error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
