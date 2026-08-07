// difftest_composed.mjs -- per-subroutine DIFFERENTIAL TEST on the COMPOSED opts (same
// label + nodeOrders + body search budget as buildcomposed.mjs), so each body it checks is
// byte-for-byte the one shipped in optimized.hex. Runs orig vs optimized on random Fp; requires
// bit-identical output stacks. Budget env matches buildcomposed CAP_BODY/TRIALS_BODY.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect, probeArity, runSubroutine } from './program.mjs';
import { optimizeItems } from './optimize.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const NODEORDERS = JSON.parse(readFileSync(join(here, 'nodeorders.json'), 'utf8'));
const CAP_BODY = +(process.env.CAP_BODY || 30000), TRIALS_BODY = +(process.env.TRIALS_BODY || 8000);

const arityPath = join(here, 'arity.json');
let arity;
if (existsSync(arityPath)) { arity = JSON.parse(readFileSync(arityPath, 'utf8')); }
else { arity = probeArity(d); writeFileSync(arityPath, JSON.stringify(arity)); }

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function mkrng(seed) { let x = BigInt(seed) * 6364136223846793005n + 1n; return () => { x = (x * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); let z = x; z = (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n & ((1n << 64n) - 1n); z = (z ^ (z >> 27n)) * 0x94d049bb133111ebn & ((1n << 64n) - 1n); return (z ^ (z >> 31n)) & ((1n << 64n) - 1n); }; }
function randFp(rng) { let v = 0n; for (let i = 0; i < 4; i++) v = (v << 64n) | rng(); return v % P; }

const NTRIAL = 8;
const eqStacks = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

let totOrig = 0, totOpt = 0, totSchedBlocks = 0, totBlocks = 0;
const fails = [];
const rows = [];
for (const id of d.order) {
  const items = decompile(d.bodies.get(id), arity, arity[id].in, { label: 'def#' + id });
  const { bytes: optBytes, chosen } = optimizeItems(items, arity, 'sched', {
    peephole: true, label: 'def#' + id, nodeOrders: NODEORDERS, search: { cap: CAP_BODY, trials: TRIALS_BODY },
  });
  const origLen = d.bodies.get(id).length;
  totOrig += origLen; totOpt += optBytes.length; totSchedBlocks += chosen.sched; totBlocks += chosen.blocks;
  const override = new Map([[id, optBytes]]);

  let clean = 0, match = 0, errBoth = 0, errMismatch = 0;
  for (let s = 0; s < NTRIAL; s++) {
    const rng = mkrng(s * 1009 + id * 7 + 1);
    const inputs = Array.from({ length: arity[id].in }, () => randFp(rng));
    const ro = runSubroutine(d, id, inputs);
    const rs = runSubroutine(d, id, inputs, override);
    if (ro.error) { if (rs.error) errBoth++; else errMismatch++; continue; }
    clean++;
    if (!rs.error && eqStacks(ro.stack, rs.stack)) match++;
    else errMismatch++;
  }
  const verdict = errMismatch > 0 ? 'FAIL' : (clean > 0 ? 'PASS(' + match + '/' + clean + ')' : 'NOCLEAN(errBoth=' + errBoth + ')');
  if (errMismatch > 0) fails.push(id);
  rows.push(`def#${String(id).padStart(2)}  ${String(origLen).padStart(4)}->${String(optBytes.length).padStart(4)}B  sched ${chosen.sched}/${chosen.blocks}  ${verdict}`);
}

for (const r of rows) console.log(r);
console.log(`\nBODIES total: ${totOrig} -> ${totOpt} B  (saved ${totOrig - totOpt} B)`);
console.log(`blocks scheduled: ${totSchedBlocks}/${totBlocks}`);
console.log(fails.length ? `DIFF-TEST FAILURES: def#${fails.join(', def#')}` : 'DIFF-TEST: all bodies PASS (no output mismatch)');
process.exit(fails.length ? 1 : 0);
