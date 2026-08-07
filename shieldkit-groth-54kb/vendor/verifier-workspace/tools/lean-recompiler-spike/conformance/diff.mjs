// Differ: compares Lean-side vs libauth-side results case-by-case.
// PASS for a case iff:  (Lean.fail === libauth.fail)  AND  (if both ok, main & alt sentinel
// sequences are identical on both sides).
// Usage: node diff.mjs [leanResultsFile]   (default lean_results.json)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url'; import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));

const leanFile = process.argv[2] || 'lean_results.json';
const cases  = JSON.parse(readFileSync(join(here,'cases.json'),'utf8')).cases;
const lean   = JSON.parse(readFileSync(join(here,leanFile),'utf8'));
const libauth= JSON.parse(readFileSync(join(here,'libauth_results.json'),'utf8'));

const byId = arr => Object.fromEntries(arr.map(r => [r.id, r]));
const L = byId(lean), A = byId(libauth), C = byId(cases);
const eq = (x,y) => JSON.stringify(x||[]) === JSON.stringify(y||[]);

let pass=0, mismatches=[];
const perOp = {};
for (const c of cases){
  const l = L[c.id], a = A[c.id];
  perOp[c.op] ??= { pass:0, fail:0 };
  let ok;
  if (!l || !a) ok = false;
  else if (l.fail !== a.fail) ok = false;
  else if (l.fail === true) ok = true;              // both underflow
  else ok = eq(l.main, a.main) && eq(l.alt, a.alt);  // both ok: sequences match
  if (ok){ pass++; perOp[c.op].pass++; }
  else { perOp[c.op].fail++; mismatches.push({ c, lean:l, libauth:a }); }
}

console.log(`\n=== conformance diff (${leanFile}) ===`);
console.log(`cases: ${cases.length}  PASS: ${pass}  MISMATCH: ${mismatches.length}`);
console.log('per-op:', Object.entries(perOp).map(([o,v])=>`${o}:${v.pass}/${v.pass+v.fail}`).join(' '));
if (mismatches.length){
  console.log(`\n--- first ${Math.min(15,mismatches.length)} mismatches ---`);
  for (const m of mismatches.slice(0,15)){
    console.log(`#${m.c.id} ${m.c.op}${m.c.n!==undefined?'('+m.c.n+')':''} in main=${JSON.stringify(m.c.main)} alt=${JSON.stringify(m.c.alt)}`);
    console.log(`    lean   : ${JSON.stringify(m.lean)}`);
    console.log(`    libauth: ${JSON.stringify(m.libauth)}`);
  }
}
console.log('\nCONFORMANCE:', mismatches.length===0 ? 'PASS' : 'FAIL');
process.exit(mismatches.length===0 ? 0 : 1);
