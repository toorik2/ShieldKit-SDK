#!/usr/bin/env node
/**
 * Optional blank-machine cold-start story.
 *
 * Default: inventory + disk sizes (safe, no reinstall).
 * Optional timers (destructive/expensive — opt-in):
 *   --time-npm-ci          run npm ci in a fresh worktree under --work-root
 *   --time-prove           run two deposit proves (cold + warm) via product path
 *
 * Always safe:
 *   --data-home ABS        measure artifact install footprint
 *   --json-out file
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
} from './product-prove.mjs';

function parseArgs(argv) {
  const out = {
    dataHome: process.env.SHIELDKIT_BENCH_DATA_HOME || null,
    timeNpmCi: false,
    timeProve: false,
    workRoot: null,
    jsonOut: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--data-home') out.dataHome = path.resolve(argv[++i] ?? '');
    else if (a === '--time-npm-ci') out.timeNpmCi = true;
    else if (a === '--time-prove') out.timeProve = true;
    else if (a === '--work-root') out.workRoot = path.resolve(argv[++i] ?? '');
    else if (a === '--json-out') out.jsonOut = path.resolve(argv[++i] ?? '');
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
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
          // count link itself only
          total += statSync(p, { throwIfNoEntry: false })?.size ?? 0;
        }
      } catch {
        // ignore permission races
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
  return { ms, status: result.status, stderr: result.stderr, stdout: result.stdout };
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(
      'usage: node run-coldstart.mjs [--data-home ABS] [--time-npm-ci --work-root ABS]\n'
      + '                            [--time-prove] [--json-out file]\n'
      + 'Default is inventory-only (disk sizes). Opt-in timers may reinstall deps.\n',
    );
    return;
  }

  const root = productRootFromBench();
  const commit = resolveGitCommit(root);
  const steps = [];
  let timedMs = 0;
  let diskBytes = 0;

  // 1) clone — inventory only (do not re-clone by default)
  const gitDir = path.join(root, '.git');
  const repoBytes = await dirBytes(root);
  steps.push({
    id: 'clone',
    ms: null,
    bytes: repoBytes,
    ok: existsSync(gitDir),
    detail: existsSync(gitDir)
      ? 'existing checkout (clone not re-timed; use external timed git clone for first download)'
      : 'no .git',
  });
  if (repoBytes) diskBytes += repoBytes;

  // 2) npm ci
  const nm = path.join(root, 'node_modules');
  const nmBytes = await dirBytes(nm);
  if (args.timeNpmCi) {
    if (!args.workRoot) throw new Error('--time-npm-ci requires --work-root ABS');
    await mkdir(args.workRoot, { recursive: true });
    const dest = path.join(args.workRoot, `npm-ci-${Date.now()}`);
    // Copy package manifests only + lock, then npm ci
    await mkdir(dest, { recursive: true });
    for (const name of ['package.json', 'package-lock.json', '.npmrc', '.npmignore']) {
      const src = path.join(root, name);
      if (existsSync(src)) await cp(src, path.join(dest, name));
    }
    // Need shieldkit-groth sources for postinstall workspaces — rsync light tree
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
      const ci = timeCommand('npm', ['ci', '--ignore-scripts'], dest);
      // run postinstall scripts explicitly for fair build timing
      const post = timeCommand('npm', ['run', 'build:vendored-cashc'], dest);
      const installDeps = timeCommand(
        'node',
        ['shieldkit-groth/scripts/install-deps.mjs'],
        dest,
      );
      const ms = ci.ms + post.ms + installDeps.ms;
      timedMs += ms;
      const bytes = await dirBytes(path.join(dest, 'node_modules'));
      steps.push({
        id: 'npm_ci',
        ms,
        bytes,
        ok: ci.status === 0,
        detail: `npm ci --ignore-scripts + build:vendored-cashc + install-deps; exit=${ci.status}/${post.status}/${installDeps.status}`,
      });
      // cleanup work tree to save disk unless KEEP
      if (process.env.SHIELDKIT_BENCH_KEEP_COLDSTART !== '1') {
        await rm(dest, { recursive: true, force: true });
      }
    }
  } else {
    steps.push({
      id: 'npm_ci',
      ms: null,
      bytes: nmBytes,
      ok: existsSync(nm),
      detail: existsSync(nm)
        ? 'node_modules present (not re-timed; pass --time-npm-ci --work-root …)'
        : 'node_modules missing',
    });
    if (nmBytes) diskBytes += nmBytes;
  }

  // 3) native prover — footprint under data-home or monorepo build cache
  let nativeBytes = null;
  let nativeOk = null;
  let nativeDetail = 'not measured';
  const dataCandidates = args.dataHome
    ? [path.resolve(args.dataHome)]
    : (Array.isArray(resolveBenchDataHome())
      ? resolveBenchDataHome()
      : [resolveBenchDataHome()]);
  for (const home of dataCandidates) {
    const productDir = home.endsWith(`${path.sep}v2-beta-product`)
      ? home
      : path.join(home, 'shieldkit', 'v2-beta-product');
    const nativeDir = path.join(productDir, 'v2-beta-product-artifacts', 'native');
    if (existsSync(nativeDir)) {
      nativeBytes = await dirBytes(nativeDir);
      nativeOk = existsSync(path.join(nativeDir, 'bin', 'prover'));
      nativeDetail = nativeDir;
      break;
    }
  }
  steps.push({
    id: 'native_prover',
    ms: null,
    bytes: nativeBytes,
    ok: nativeOk,
    detail: nativeDetail,
  });
  if (nativeBytes) diskBytes += nativeBytes;

  // 4) artifact install footprint
  let artBytes = null;
  let artOk = null;
  let artDetail = 'not measured';
  for (const home of dataCandidates) {
    const productDir = home.endsWith(`${path.sep}v2-beta-product`)
      ? home
      : path.join(home, 'shieldkit', 'v2-beta-product');
    const art = path.join(productDir, 'v2-beta-product-artifacts');
    if (existsSync(art)) {
      artBytes = await dirBytes(art);
      artOk = true;
      artDetail = art;
      // native already counted separately if nested — subtract if nested
      if (nativeBytes && art.includes(path.dirname(nativeDetail || ''))) {
        // artifacts dir includes native; avoid double-count in total
        diskBytes -= nativeBytes;
      }
      break;
    }
  }
  steps.push({
    id: 'artifact_install',
    ms: null,
    bytes: artBytes,
    ok: artOk,
    detail: artOk
      ? `${artDetail} (install time: run offline installer separately to time)`
      : 'no v2-beta-product-artifacts found',
  });
  if (artBytes) diskBytes += artBytes;

  // 5) runtime link cache
  let cacheBytes = null;
  for (const home of dataCandidates) {
    const productDir = home.endsWith(`${path.sep}v2-beta-product`)
      ? home
      : path.join(home, 'shieldkit', 'v2-beta-product');
    const cache = path.join(productDir, 'runtime-cache');
    if (existsSync(cache)) {
      cacheBytes = await dirBytes(cache);
      steps.push({
        id: 'runtime_link',
        ms: null,
        bytes: cacheBytes,
        ok: true,
        detail: cache,
      });
      diskBytes += cacheBytes;
      break;
    }
  }
  if (!steps.find((s) => s.id === 'runtime_link')) {
    steps.push({
      id: 'runtime_link',
      ms: null,
      bytes: null,
      ok: false,
      detail: 'no runtime-cache yet (appears after first specialized instance)',
    });
  }

  // 6–7) prove cold/warm
  if (args.timeProve) {
    try {
      process.env.SHIELDKIT_BENCH_DATA_HOME = args.dataHome
        || process.env.SHIELDKIT_BENCH_DATA_HOME
        || '';
      const session = await resolveFirstUsableDataHome();
      const cold = await proveDepositOnce(session);
      const warm = await proveDepositOnce(session);
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
      detail: 'pass --time-prove to measure',
    });
    steps.push({
      id: 'second_prove_warm',
      ms: null,
      ok: null,
      detail: 'pass --time-prove to measure',
    });
  }

  // 8) disk footprint summary row
  steps.push({
    id: 'disk_footprint',
    ms: null,
    bytes: diskBytes,
    ok: diskBytes > 0,
    detail: 'sum of measured roots (approx; nested dirs adjusted when possible)',
  });

  const report = buildColdstartReport({
    design: DESIGN_PF10_BASELINE,
    commit,
    steps,
    totals: { timedMs: timedMs || null, diskBytes },
    notes: args.timeNpmCi || args.timeProve
      ? 'includes opt-in timers'
      : 'inventory-only; opt-in --time-npm-ci / --time-prove for wall clocks',
  });

  process.stdout.write(`${formatColdstartTable(report)}\n`);
  if (args.jsonOut) {
    await mkdir(path.dirname(args.jsonOut), { recursive: true });
    await writeFile(args.jsonOut, `${JSON.stringify(report, null, 2)}\n`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
