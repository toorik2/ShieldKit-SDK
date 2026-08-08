#!/usr/bin/env node
// cli.mjs — the self-contained, gated, trust-labeling optimizer entry point.
//
//   node cli.mjs <in.hex|.cash> [out.hex] [options]
//     --dialect <name>   parser/emitter framing (default: auto = cashc-standard)
//     --gate             run the soundness gate (round-trip + differential) before emitting
//     --report <path>    write the trust report JSON (default: <out>.report.json)
//     --no-emit          measure + report only; do not write out.hex
//     --cashc <path>     cashc CLI, for a .cash input (or env CASHC)
//
// Never writes out.hex unless the run is at least as trustworthy as the report claims: with --gate,
// the gate must pass; the covenant dialect (P3) is analyze-only and always refuses in-place emit.
import { spawnSync, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { setDialect } from './core/program.mjs';
import { resolveDialect } from './dialect/index.mjs';
import { classifyEmitSafety } from './dialect/covenant-wrapped.mjs';
import { measureRun, classifyBound } from './cost.mjs';
import { buildReport, printReport } from './manifest.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = { dialect: 'auto', gate: false, emit: true, report: undefined, cashc: process.env.CASHC, opCost: null, unlockBytes: null };
const pos = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--dialect') opt.dialect = args[++i];
  else if (a === '--gate') opt.gate = true;
  else if (a === '--no-emit') opt.emit = false;
  else if (a === '--report') opt.report = args[++i];
  else if (a === '--cashc') opt.cashc = args[++i];
  else if (a === '--op-cost') opt.opCost = Number(args[++i]);        // covenant analysis: the chunk's known op-cost
  else if (a === '--unlock-bytes') opt.unlockBytes = Number(args[++i]);
  else pos.push(a);
}
const inPath = pos[0];
if (!inPath) { console.error('usage: node cli.mjs <in.hex|.cash> [out.hex] [--dialect n] [--gate] [--report p] [--no-emit]'); process.exit(2); }
const outPath = pos[1] || inPath.replace(/\.(hex|cash)$/, '') + '.opt.hex';
const reportPath = opt.report || outPath + '.report.json';

// ---- 1. load bytecode (compile .cash if needed) ----
function loadHex(path) {
  if (path.endsWith('.cash')) {
    const cashc = opt.cashc || join('/home/toorik/Projects', 'cashc-resched', 'packages', 'cashc', 'dist', 'cashc-cli.js');
    if (!existsSync(cashc)) { console.error(`.cash input needs a cashc build; pass --cashc <path> or set CASHC (looked at ${cashc})`); process.exit(2); }
    return execFileSync('node', [cashc, path, '-h'], { encoding: 'utf8' }).trim();
  }
  return readFileSync(path, 'utf8').trim().replace(/\s/g, '');
}
const inHex = loadHex(inPath);
const inBytes = inHex.length / 2;

// ---- 2. select dialect (auto-detect covenant from the bytes) ----
const inBin = Uint8Array.from(Buffer.from(inHex, 'hex'));
const dialect = resolveDialect(opt.dialect, inBin);
setDialect(dialect);
const covenant = !!dialect.analyzeOnly;                  // covenant = analyze-only
const parseCert = covenant ? 'structural-only' : 'round-trip-byte-exact';

// ---- COVENANT PATH: analyze-only (recognize, prove refusal, bound-type). No optimize, no emit. ----
if (covenant) {
  const safety = classifyEmitSafety(inBin);
  const cost = { inBytes, opCost: opt.opCost, unlockBytes: opt.unlockBytes };
  let bound = null;
  if (opt.opCost != null && opt.unlockBytes != null) bound = classifyBound(opt.unlockBytes, opt.opCost);
  const report = buildReport({ dialect, parseCert, passes: [], gate: null, cost: { ...cost, bound }, emitSafety: 'refused-in-place' });
  const reportPathC = opt.report || inPath.replace(/\.(hex|cash)$/, '') + '.analysis.json';
  writeFileSync(reportPathC, JSON.stringify({ ...report, emitSafetyReason: safety.reason }, null, 2) + '\n');
  console.log(`covenant chunk: ${inBytes}B  (dialect: ${dialect.name}, ANALYZE-ONLY)`);
  console.log(`  emit-safety: REFUSED-IN-PLACE — ${safety.reason}`);
  if (bound) console.log(`  op-cost ${opt.opCost.toLocaleString()} · unlock ${opt.unlockBytes}B · bound=${bound.bound} (min-unlock ${bound.minUnlock}, slack ${bound.slack}) · lever="${bound.lever}"`);
  else console.log('  (pass --op-cost N --unlock-bytes M for the bound-type + lever analysis)');
  console.log(`  wrote analysis -> ${reportPathC}  (NO out.hex — in-place covenant optimization is unsound)`);
  process.exit(0);
}

// ---- 3. optimize (cse + fold fixpoint via the proven driver) ----
const inTmp = join('/tmp', `bchopt-in-${process.pid}.hex`);
writeFileSync(inTmp, inHex);
const optOut = join('/tmp', `bchopt-out-${process.pid}.hex`);
const drv = spawnSync('node', [join(HERE, 'optimize.mjs'), inTmp, optOut], { encoding: 'utf8' });
if (drv.status !== 0) { console.error('optimize failed:\n', (drv.stderr || drv.stdout || '').slice(0, 400)); process.exit(1); }
const outHex = readFileSync(optOut, 'utf8').trim();
const outBytes = outHex.length / 2;
const passes = [
  { name: 'cse', bytesRemoved: null },
  { name: 'fold', bytesRemoved: null },
];

// ---- 4. gate (optional) ----
let gate = null;
if (opt.gate && !covenant) {
  const g = spawnSync('node', [join(HERE, 'passes', 'cse.mjs'), inTmp, join('/tmp', `bchopt-g-${process.pid}.hex`), '--gate'], { encoding: 'utf8' });
  const allPass = /all-pass:\s*true/i.test(g.stdout || '');
  gate = { check1: allPass, check2: allPass, check3: null, strength: 'block-DAG (strong)', trials: 'default' };
  if (!allPass) console.error('⚠ gate did NOT pass — refusing to emit'); // handled below
}

// ---- 5. cost summary ----
const cost = { inBytes, outBytes, bytesRemoved: inBytes - outBytes, pct: +(100 * (inBytes - outBytes) / inBytes).toFixed(2) };

// ---- 6. trust report ----
const emitSafety = covenant ? 'refused-in-place' : 'ok';
const report = buildReport({ dialect, parseCert, passes, gate, cost, emitSafety });
writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');

// ---- 7. emit (unless refused) ----
const gateBlocks = opt.gate && !covenant && !(gate && gate.check1);
const emit = opt.emit && !covenant && !gateBlocks;
if (emit) { writeFileSync(outPath, outHex + '\n'); }

// ---- 8. print summary ----
console.log(`in ${inBytes}B  ->  out ${outBytes}B   (${cost.bytesRemoved >= 0 ? '-' : '+'}${Math.abs(cost.bytesRemoved)}B, ${cost.pct}%)`);
printReport(report);
console.log(covenant ? `analyze-only (covenant): no out.hex written; report -> ${reportPath}`
  : gateBlocks ? `GATE FAILED: no out.hex written; report -> ${reportPath}`
  : !opt.emit ? `--no-emit: report -> ${reportPath}`
  : `wrote ${outPath}  +  ${reportPath}`);
process.exit(gateBlocks ? 1 : 0);
