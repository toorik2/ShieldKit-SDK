// enumerate.mjs -- parse the 5613 richpeep artifact into per-body opcode streams,
// enumerate adjacent op PAIRS and TRIPLES + frequencies across all bodies + main.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse } from './asm.mjs';
import { dissect } from './program.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const ART = join(here, 'singleton-richpeep-locking.hex');
const bytes = Uint8Array.from(Buffer.from(readFileSync(ART, 'utf8').trim(), 'hex'));
console.log(`artifact ${ART}  ${bytes.length} B`);

const d = dissect(bytes);
console.log(`bodies=${d.order.length}  mainOps=${d.mainOps.length}`);

// opcode name map (BCH stack + push + define/invoke + a few we care about)
const NAME = {
  0x00: '<0>', 0x4f: '<-1>',
  0x6d: '2DROP', 0x6e: '2DUP', 0x6f: '3DUP', 0x70: '2OVER', 0x71: '2ROT', 0x72: '2SWAP',
  0x73: 'IFDUP', 0x74: 'DEPTH', 0x75: 'DROP', 0x76: 'DUP', 0x77: 'NIP', 0x78: 'OVER',
  0x79: 'PICK', 0x7a: 'ROLL', 0x7b: 'ROT', 0x7c: 'SWAP', 0x7d: 'TUCK',
  0x6b: 'TOALT', 0x6c: 'FROMALT', 0x89: 'DEFINE', 0x8a: 'INVOKE',
};
function opName(o) {
  if (o.data !== undefined) {
    // small-int / short numeric push
    if (o.data.length <= 2) { let v = 0; for (let i = o.data.length - 1; i >= 0; i--) v = (v << 8) | o.data[i]; return `PUSH<${v}>(${o.data.length}B)`; }
    return `PUSH[${o.data.length}B]`;
  }
  if (o.op >= 0x51 && o.op <= 0x60) return `<${o.op - 0x50}>`;
  return NAME[o.op] || `op${o.op.toString(16)}`;
}
// token used for pair/triple counting: for pushes, collapse to a class so we see
// <0>/<1>/<2> constants (relevant for PICK/ROLL folds) but lump big pushes.
function token(o) {
  if (o.data !== undefined) {
    if (o.data.length <= 2) { let v = 0; for (let i = o.data.length - 1; i >= 0; i--) v = (v << 8) | o.data[i]; if (v <= 16) return `<${v}>`; return 'PUSHn'; }
    return 'PUSH';
  }
  if (o.op >= 0x51 && o.op <= 0x60) return `<${o.op - 0x50}>`;
  if (o.op === 0x00) return '<0>';
  return NAME[o.op] || `op${o.op.toString(16)}`;
}

const pairFreq = new Map();
const tripleFreq = new Map();
const opFreq = new Map();
let totalOps = 0;

function scan(ops, label) {
  const toks = ops.map(token);
  for (const t of toks) { opFreq.set(t, (opFreq.get(t) || 0) + 1); totalOps++; }
  for (let i = 0; i + 1 < toks.length; i++) {
    const k = toks[i] + ' ' + toks[i + 1];
    pairFreq.set(k, (pairFreq.get(k) || 0) + 1);
  }
  for (let i = 0; i + 2 < toks.length; i++) {
    const k = toks[i] + ' ' + toks[i + 1] + ' ' + toks[i + 2];
    tripleFreq.set(k, (tripleFreq.get(k) || 0) + 1);
  }
}

for (const id of d.order) scan(parse(d.bodies.get(id)), 'def#' + id);
scan(d.mainOps, 'main');

console.log(`\ntotal ops across all bodies+main: ${totalOps}`);
console.log('\n== opcode frequencies (stack ops & pushes) ==');
[...opFreq.entries()].sort((a, b) => b[1] - a[1]).forEach(([k, v]) => console.log(`  ${String(v).padStart(5)}  ${k}`));

console.log('\n== adjacent PAIR frequencies (top 60) ==');
[...pairFreq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 60).forEach(([k, v]) => console.log(`  ${String(v).padStart(5)}  ${k}`));

console.log('\n== adjacent TRIPLE frequencies (top 40) ==');
[...tripleFreq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).forEach(([k, v]) => console.log(`  ${String(v).padStart(5)}  ${k}`));

// Highlight pairs/triples that are fold candidates
console.log('\n== FOLD-CANDIDATE pairs present (per the stack-op grammar) ==');
const candPairs = ['OVER OVER','SWAP OVER','DROP DROP','SWAP DROP','DUP DROP','OVER DROP','SWAP SWAP',
  '<0> PICK','<1> PICK','<0> ROLL','<1> ROLL','<2> ROLL','DROP DUP','NIP','ROT ROT','DUP DUP',
  'TUCK DROP','OVER SWAP','SWAP NIP','2DUP DROP','DUP NIP','ROT ROT'];
for (const c of candPairs) {
  const v = pairFreq.get(c);
  if (v) console.log(`  ${String(v).padStart(5)}  ${c}   <-- candidate`);
}
