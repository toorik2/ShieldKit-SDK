#!/usr/bin/env node
/**
 * ShieldKit public bench — two modes only.
 *
 *   (default)       Pipeline: live deposit tip → prove → mempool admit → commit
 *   --cold-start    Machine cold-start: CDN + native + empty install + cold prove
 *
 * Requires an absolute product data-home (--data-home or SHIELDKIT_BENCH_DATA_HOME).
 * No author-specific default paths.
 */
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  BenchDataHomeError,
  cliDataHomeFromProduct,
  requireProductDataHome,
} from '../data-home.mjs';
import { formatSubjectHeader, resolveBenchSubject } from '../identity.mjs';
import { resolveGitCommit } from '../scorecard.mjs';
import { productRootFromBench } from './product-prove.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.resolve(HERE, '../results');
const DEFAULT_SANDBOX = path.join(homedir(), '.cache', 'shieldkit-bench');
const KINDS = new Set(['deposit', 'transfer', 'withdraw']);

export function parseBenchArgs(argv) {
  const out = {
    coldStart: false,
    dataHome: null,
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
    else if (a === '--data-home') {
      const v = argv[++i];
      if (v === undefined || v.startsWith('-')) {
        throw new Error('--data-home requires an absolute path argument');
      }
      out.dataHome = path.resolve(v);
    } else if (a === '--json-out') {
      const v = argv[++i];
      if (v === undefined || v.startsWith('-')) {
        throw new Error('--json-out requires a path argument');
      }
      out.jsonOut = path.resolve(v);
    } else if (a === '--sandbox') {
      const v = argv[++i];
      if (v === undefined || v.startsWith('-')) {
        throw new Error('--sandbox requires an absolute path argument');
      }
      out.sandbox = path.resolve(v);
    } else if (a === '--keep') out.keep = true;
    else if (a === '--kind') {
      const v = argv[++i];
      if (v === undefined || !KINDS.has(v)) {
        throw new Error('--kind must be deposit|transfer|withdraw');
      }
      out.kind = v;
    } else if (a === '--to') {
      const v = argv[++i];
      if (v === undefined) throw new Error('--to requires an address');
      out.to = v;
    } else if (a === '--note') {
      const v = argv[++i];
      if (v === undefined) throw new Error('--note requires a 64-hex note id');
      out.note = v;
    } else if (a === '--help' || a === '-h') out.help = true;
    else {
      throw new Error(
        `unknown argument: ${a}\n`
        + 'public surface is only: (default pipeline) or --cold-start\n'
        + 'try: node run-bench.mjs --help',
      );
    }
  }
  if (out.kind === 'withdraw' && !out.help && !out.coldStart && !out.to) {
    throw new Error('withdraw requires --to (or SHIELDKIT_BENCH_PAYOUT)');
  }
  if (out.kind === 'transfer' && !out.help && !out.coldStart && !out.note) {
    throw new Error('transfer requires --note (or SHIELDKIT_BENCH_NOTE_ID)');
  }
  return out;
}

function runNode(script, args) {
  const result = spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8',
    stdio: 'inherit',
    env: { ...process.env },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) {
    process.stderr.write(`${result.error.message}\n`);
    process.exitCode = 1;
    return false;
  }
  if (result.status !== 0) {
    process.exitCode = result.status === null ? 1 : result.status;
    return false;
  }
  return true;
}

export function printHelp(stream = process.stdout) {
  let subjectLine = '';
  try {
    const commit = resolveGitCommit(productRootFromBench());
    subjectLine = `${formatSubjectHeader(resolveBenchSubject({ commit }))}\n\n`;
  } catch {
    subjectLine = `${formatSubjectHeader(resolveBenchSubject())}\n\n`;
  }

  stream.write(
    'ShieldKit bench — two modes only\n'
    + '\n'
    + subjectLine
    + '  (default)       Pipeline: live deposit tip → prove → mempool admit → commit\n'
    + '  --cold-start    Machine cold-start: CDN pin + native + empty install + cold prove\n'
    + '\n'
    + 'usage:\n'
    + '  npm run bench -- --data-home /abs/path/to/install-or-v2-beta-product\n'
    + '  npm run bench:cold-start -- --data-home /abs/path/to/install-or-v2-beta-product\n'
    + '\n'
    + '  node shieldkit-groth/bench/pf10-baseline/run-bench.mjs --data-home ABS [options]\n'
    + '  node shieldkit-groth/bench/pf10-baseline/run-bench.mjs --cold-start --data-home ABS [options]\n'
    + '\n'
    + 'required:\n'
    + '  --data-home ABS   product install root or …/v2-beta-product (session.json required)\n'
    + '                    or set SHIELDKIT_BENCH_DATA_HOME\n'
    + '\n'
    + 'shared options:\n'
    + '  --json-out FILE   default: bench/results/pipeline.json | coldstart.json\n'
    + '  --help\n'
    + '\n'
    + 'pipeline options:\n'
    + '  --kind deposit|transfer|withdraw   (default deposit)\n'
    + '  --to ADDRESS                       (withdraw)\n'
    + '  --note 64hex                       (transfer)\n'
    + '\n'
    + 'cold-start options:\n'
    + `  --sandbox DIR     default: ${DEFAULT_SANDBOX}\n`
    + '  --keep            keep sandbox after run (default: delete)\n'
    + '\n'
    + 'notes:\n'
    + '  • pipeline is a real Chipnet act (spends/broadcasts). Fund the pool first.\n'
    + '  • cold-start never creates a pool; cold prove uses the live session.\n'
    + '  • results include subject (product version, DIRECT_V2_PF10, commit).\n'
    + '  • refuse ambient NODE_OPTIONS / NODE_PATH for native prover policy.\n'
    + '  • see shieldkit-groth/bench/README.md and USER_GUIDE for pool setup.\n',
  );
}

export async function runBench(argv, deps = {}) {
  const args = parseBenchArgs(argv);
  if (args.help) {
    printHelp(deps.stdout ?? process.stdout);
    return { ok: true, mode: 'help' };
  }

  const productHome = requireProductDataHome(args.dataHome, {
    env: deps.env ?? process.env,
    existsSync: deps.existsSync,
  });

  if (args.coldStart) {
    const jsonOut = args.jsonOut || path.join(RESULTS, 'coldstart.json');
    const script = path.join(HERE, 'run-coldstart.mjs');
    const childArgs = [
      '--sandbox', args.sandbox,
      '--machine',
      '--data-home', productHome,
      '--json-out', jsonOut,
    ];
    if (args.keep) childArgs.push('--keep');
    const banner = deps.stdout ?? process.stdout;
    banner.write(
      `bench mode=cold-start\n`
      + `product-home=${productHome}\n`
      + `sandbox=${args.sandbox}\n`
      + `json-out=${jsonOut}\n\n`,
    );
    const ok = (deps.runNode ?? runNode)(script, childArgs);
    return { ok, mode: 'cold-start', productHome, jsonOut };
  }

  const cliHome = cliDataHomeFromProduct(productHome);
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
  const banner = deps.stdout ?? process.stdout;
  banner.write(
    `bench mode=pipeline (live ${args.kind} → mempool)\n`
    + `cli-data-home=${cliHome}\n`
    + `product-home=${productHome}\n`
    + `json-out=${jsonOut}\n\n`,
  );
  const ok = (deps.runNode ?? runNode)(script, childArgs);
  return { ok, mode: 'pipeline', productHome, cliHome, jsonOut };
}

async function main(argv) {
  try {
    await runBench(argv);
  } catch (error) {
    if (error instanceof BenchDataHomeError) {
      process.stderr.write(`${error.code}: ${error.message}\n`);
    } else {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    }
    process.exitCode = 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
}
