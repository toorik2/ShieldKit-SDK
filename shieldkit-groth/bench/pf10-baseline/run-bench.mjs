#!/usr/bin/env node
/**
 * ShieldKit bench — two modes only.
 *
 *   (default)       Pipeline: one live deposit act tip → mempool admit → commit
 *   --cold-start    Machine cold-start: CDN + native + empty install + cold prove
 *
 * Shared:
 *   --data-home ABS   (or SHIELDKIT_BENCH_DATA_HOME / default live installs)
 *   --json-out FILE
 *   --help
 *
 * Cold-start only:
 *   --sandbox DIR   (default: ~/.cache/shieldkit-bench)
 *   --keep          keep sandbox after run
 *
 * Pipeline only:
 *   --kind deposit|transfer|withdraw   (default deposit)
 *   --to / --note   (withdraw / transfer)
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.resolve(HERE, '../results');
const DEFAULT_SANDBOX = path.join(homedir(), '.cache/shieldkit-bench');
const DEFAULT_DATA_HOMES = Object.freeze([
  '/home/toorik/.local/share/shieldkit-packed-live-d06632c/shieldkit/v2-beta-product',
  '/home/toorik/.local/share/shieldkit-final-ready-140c183/shieldkit/v2-beta-product',
]);

function parseArgs(argv) {
  const out = {
    coldStart: false,
    dataHome: process.env.SHIELDKIT_BENCH_DATA_HOME
      || process.env.SHIELDKIT_DATA_HOME
      || null,
    jsonOut: null,
    sandbox: DEFAULT_SANDBOX,
    keep: process.env.SHIELDKIT_BENCH_KEEP_COLDSTART === '1',
    kind: 'deposit',
    to: process.env.SHIELDKIT_BENCH_PAYOUT || null,
    note: process.env.SHIELDKIT_BENCH_NOTE_ID || null,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--cold-start' || a === '--coldstart') out.coldStart = true;
    else if (a === '--data-home') out.dataHome = path.resolve(argv[++i] ?? '');
    else if (a === '--json-out') out.jsonOut = path.resolve(argv[++i] ?? '');
    else if (a === '--sandbox') out.sandbox = path.resolve(argv[++i] ?? '');
    else if (a === '--keep') out.keep = true;
    else if (a === '--kind') out.kind = argv[++i];
    else if (a === '--to') out.to = argv[++i];
    else if (a === '--note') out.note = argv[++i];
    else if (a === '--help' || a === '-h') out.help = true;
    else throw new Error(`unknown argument: ${a} (only default pipeline or --cold-start)`);
  }
  return out;
}

/**
 * Product session dir (…/v2-beta-product) — used by cold-start prove path.
 * CLI --data-home is often the outer private root (…/shieldkit-packed-…), not nested.
 */
function normalizeProductDataHome(home) {
  if (typeof home !== 'string' || home.length === 0) return null;
  const abs = path.resolve(home);
  if (abs.endsWith(`${path.sep}v2-beta-product`)
    && existsSync(path.join(abs, 'session.json'))) {
    return abs;
  }
  const nested = path.join(abs, 'shieldkit', 'v2-beta-product');
  if (existsSync(path.join(nested, 'session.json'))) return nested;
  if (existsSync(path.join(abs, 'session.json'))) return abs;
  return null;
}

/** Outer data-home for product CLI (parent of shieldkit/v2-beta-product when nested). */
function cliDataHomeFromProduct(productHome) {
  const abs = path.resolve(productHome);
  if (abs.endsWith(`${path.sep}shieldkit${path.sep}v2-beta-product`)) {
    return path.dirname(path.dirname(abs));
  }
  if (path.basename(abs) === 'v2-beta-product'
    && path.basename(path.dirname(abs)) === 'shieldkit') {
    return path.dirname(path.dirname(abs));
  }
  return abs;
}

function resolveDataHome(explicit) {
  if (explicit) {
    const n = normalizeProductDataHome(explicit);
    if (!n) {
      throw new Error(`--data-home must point at a product data-home with session.json (got ${explicit})`);
    }
    return n;
  }
  if (process.env.SHIELDKIT_BENCH_DATA_HOME) {
    return resolveDataHome(process.env.SHIELDKIT_BENCH_DATA_HOME);
  }
  for (const c of DEFAULT_DATA_HOMES) {
    if (existsSync(path.join(c, 'session.json'))) return c;
  }
  // also accept outer packed roots in the default list parents
  for (const c of DEFAULT_DATA_HOMES) {
    const outer = cliDataHomeFromProduct(c);
    const n = normalizeProductDataHome(outer);
    if (n) return n;
  }
  throw new Error(
    'no data-home: pass --data-home …/v2-beta-product (or outer packed root) or set SHIELDKIT_BENCH_DATA_HOME',
  );
}

function runNode(script, args) {
  const result = spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8',
    stdio: 'inherit',
    env: { ...process.env },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) {
    process.exitCode = result.status === null ? 1 : result.status;
  }
  return result.status === 0;
}

function printHelp() {
  process.stdout.write(
    'ShieldKit bench — two modes only\n'
    + '\n'
    + '  (default)       Pipeline: live deposit tip → prove → mempool admit → commit\n'
    + '  --cold-start    Machine cold-start: CDN + native + empty install + cold prove\n'
    + '\n'
    + 'usage:\n'
    + '  node run-bench.mjs [--data-home ABS] [--json-out file] [--kind deposit]\n'
    + '  node run-bench.mjs --cold-start [--data-home ABS] [--sandbox DIR] [--json-out file] [--keep]\n'
    + '\n'
    + 'defaults:\n'
    + `  data-home   first usable live install (or SHIELDKIT_BENCH_DATA_HOME)\n`
    + `  sandbox     ${DEFAULT_SANDBOX}  (cold-start only)\n`
    + `  json-out    ${path.join(RESULTS, 'pipeline.json')}  |  ${path.join(RESULTS, 'coldstart.json')}\n`
    + '\n'
    + 'pipeline is a real live act (spends/broadcasts). cold-start never creates a pool.\n',
  );
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return;
  }

  const dataHome = resolveDataHome(args.dataHome);

  if (args.coldStart) {
    const jsonOut = args.jsonOut || path.join(RESULTS, 'coldstart.json');
    const script = path.join(HERE, 'run-coldstart.mjs');
    // cold-start prove loaders want …/v2-beta-product
    const childArgs = [
      '--sandbox', args.sandbox,
      '--machine',
      '--data-home', dataHome,
      '--json-out', jsonOut,
    ];
    if (args.keep) childArgs.push('--keep');
    process.stdout.write(
      `bench mode=cold-start data-home=${dataHome} sandbox=${args.sandbox}\n\n`,
    );
    runNode(script, childArgs);
    return;
  }

  // default: pipeline (live act → mempool)
  // product CLI wants the outer private root when session lives under shieldkit/v2-beta-product
  const cliHome = cliDataHomeFromProduct(dataHome);
  const jsonOut = args.jsonOut || path.join(RESULTS, 'pipeline.json');
  const script = path.join(HERE, 'run-pipeline.mjs');
  const childArgs = [
    '--live',
    '--data-home', cliHome,
    '--kind', args.kind,
    '--json-out', jsonOut,
  ];
  if (args.to) childArgs.push('--to', args.to);
  if (args.note) childArgs.push('--note', args.note);
  process.stdout.write(
    `bench mode=pipeline (live ${args.kind} → mempool) data-home=${cliHome}\n\n`,
  );
  runNode(script, childArgs);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
