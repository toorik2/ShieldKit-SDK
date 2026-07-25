// CONTROL differ: Lean runProg vs libauth flat-control execution, case-by-case.
// PASS iff (lean.fail === libauth.fail) AND (if both ok, main & alt sequences identical).
// Usage: node ctrl_diff.mjs [leanResultsFile]
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url'; import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));

const leanFile = process.argv[2] || 'ctrl_lean_results.json';
const libFile  = process.argv[3] || 'ctrl_libauth_results.json';
const cases  = JSON.parse(readFileSync(join(here,'ctrl_cases.json'),'utf8')).cases;
const lean   = JSON.parse(readFileSync(join(here,leanFile),'utf8'));
const libauth= JSON.parse(readFileSync(join(here,libFile),'utf8'));

const byId = arr => Object.fromEntries(arr.map(r => [r.id, r]));
const L = byId(lean), A = byId(libauth);
const eq = (x,y) => JSON.stringify(x||[]) === JSON.stringify(y||[]);

let pass=0, mismatches=[];
for (const c of cases){
  const l = L[c.id], a = A[c.id];
  let ok;
  if (!l || !a) ok = false;
  else if (l.fail !== a.fail) ok = false;
  else if (l.fail === true) ok = true;
  else ok = eq(l.main, a.main) && eq(l.alt, a.alt);
  if (ok) pass++; else mismatches.push({ c, lean:l, libauth:a });
}

console.log(`\n=== CONTROL conformance diff (${leanFile}) ===`);
console.log(`cases: ${cases.length}  PASS: ${pass}  MISMATCH: ${mismatches.length}`);
if (mismatches.length){
  console.log(`\n--- first ${Math.min(20,mismatches.length)} mismatches ---`);
  for (const m of mismatches.slice(0,20)){
    console.log(`#${m.c.id} ${m.c.desc} main=${JSON.stringify(m.c.main)} alt=${JSON.stringify(m.c.alt)}`);
    console.log(`    prog   : ${JSON.stringify(m.c.prog)}`);
    console.log(`    lean   : ${JSON.stringify(m.lean)}`);
    console.log(`    libauth: ${JSON.stringify(m.libauth)}`);
  }
}
console.log('\nCONTROL CONFORMANCE:', mismatches.length===0 ? 'PASS' : 'FAIL');
process.exit(mismatches.length===0 ? 0 : 1);
