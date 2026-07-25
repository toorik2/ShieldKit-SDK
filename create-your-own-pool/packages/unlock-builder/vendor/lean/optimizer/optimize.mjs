#!/usr/bin/env node
// -----------------------------------------------------------------------------
// optimize.mjs — the unified VERIFIED DETERMINISTIC OPTIMIZER driver.
//
// Alternates the two productized, theorem-backed passes to a COMBINED FIXPOINT:
//   passes/cse.mjs   (sound by Stackcert.InvokeCSE.invoke_cse)
//   passes/fold.mjs (sound by Stackcert.FoldTable + Peephole)
// Each sub-pass already runs to its OWN fixpoint; this driver alternates them
// (CSE can expose folds and vice-versa) until a full round removes no bytes.
//
// NO search. Every byte removed carries a machine-checked soundness proof.
// See VERIFIED-OPTIMIZER.md for the pass↔theorem manifest.
//
//   node optimize.mjs <in.hex> <out.hex>
//
// (const-derivation passes — E/inv2/b2/p-pool — are source-level splices applied
//  earlier in the pipeline, not part of this bytecode-level driver.)
// -----------------------------------------------------------------------------
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const [, , inPath, outPath] = process.argv;
if (!inPath || !outPath) {
  console.error('usage: node optimize.mjs <in.hex> <out.hex>');
  process.exit(2);
}

const bytesOf = (p) => Math.floor(readFileSync(p, 'utf8').trim().replace(/\s/g, '').length / 2);
const runTool = (tool, inp, outp) => {
  const r = spawnSync('node', [join(HERE, tool), inp, outp], { encoding: 'utf8' });
  if (r.status !== 0) { console.error(`  ${tool} FAILED:\n`, (r.stderr || r.stdout || '').slice(0, 300)); process.exit(1); }
  return bytesOf(outp);
};

copyFileSync(inPath, outPath);
const start0 = bytesOf(outPath);
let cur = start0;
const tmpC = outPath + '.cse.tmp', tmpF = outPath + '.fold.tmp';

console.log(`verified optimizer: ${start0} B in`);
for (let round = 1; ; round++) {
  const roundStart = cur;
  const c = runTool('passes/cse.mjs', outPath, tmpC);
  if (c < cur) { copyFileSync(tmpC, outPath); cur = c; }
  const f = runTool('passes/fold.mjs', outPath, tmpF);
  if (f < cur) { copyFileSync(tmpF, outPath); cur = f; }
  console.log(`  round ${round}: CSE->${c}  fold->${f}  =>  ${cur} B`);
  if (cur >= roundStart) break;   // a full round removed nothing -> combined fixpoint
}
console.log(`combined fixpoint: ${start0} B -> ${cur} B  (net ${cur - start0} B); wrote ${outPath}`);
