// Generator: emits cases.json consumed by BOTH the Lean side and the libauth side.
// Convention (matches Lean State): main/alt are TOP-FIRST integer lists (head = top of stack).
// Sentinels are DISTINCT small ints in [17..250] (avoiding 129 = -1 and <=16 which
// would violate libauth minimal-push) so any WIRING mismatch is detected; stack ops are
// value-agnostic so sentinels suffice.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url'; import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));

const OPS = ['DUP','DROP','OVER','SWAP','ROT','NIP','TUCK','PICK','ROLL',
  'TOALT','FROMALT','2DROP','2DUP','3DUP','2OVER','2ROT','2SWAP'];
const TAKES_N = new Set(['PICK','ROLL']);

// deterministic PRNG (mulberry32) for reproducibility
let seed = 0xC0FFEE;
function rnd(){ seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }
const ri = (lo,hi) => lo + Math.floor(rnd()*(hi-lo+1)); // inclusive

// distinct sentinel pool for a case: sample `count` distinct values from [17..250]\{129}
function sentinels(count){
  const pool = [];
  for (let v=17; v<=250; v++) if (v!==129) pool.push(v);
  // Fisher-Yates partial shuffle
  for (let i=0;i<count;i++){ const j = i + Math.floor(rnd()*(pool.length-i)); [pool[i],pool[j]]=[pool[j],pool[i]]; }
  return pool.slice(0,count);
}

const cases = [];
let id = 0;
function push(op, mainDepth, altDepth, n){
  const s = sentinels(mainDepth+altDepth);
  const main = s.slice(0, mainDepth);      // top-first
  const alt  = s.slice(mainDepth);         // top-first
  const c = { id: id++, op, main, alt };
  if (TAKES_N.has(op)) c.n = n;
  cases.push(c);
}

// (1) Random coverage: for every op, many random main depths 0..20 and alt depths 0..6.
const PER_OP_RANDOM = 130;
for (const op of OPS){
  for (let k=0;k<PER_OP_RANDOM;k++){
    const mainDepth = ri(0,20);
    const altDepth  = ri(0,6);
    let n = 0;
    if (TAKES_N.has(op)) n = ri(0, mainDepth+2); // include out-of-range (n>=mainDepth => underflow)
    push(op, mainDepth, altDepth, n);
  }
}

// (2) Deliberate underflow sweep: each op at EVERY main depth 0..(arity+1), alt depth 0..2.
const MINARITY = { DUP:1,DROP:1,OVER:2,SWAP:2,ROT:3,NIP:2,TUCK:2,PICK:1,ROLL:1,
  TOALT:1,FROMALT:0,'2DROP':2,'2DUP':2,'3DUP':3,'2OVER':4,'2ROT':6,'2SWAP':4 };
for (const op of OPS){
  const maxD = (MINARITY[op]||0)+2;
  for (let d=0; d<=maxD; d++){
    for (let a=0; a<=2; a++){
      if (TAKES_N.has(op)){
        // vary n around depth incl exact-out-of-range
        for (const n of [0, Math.max(0,d-1), d, d+1]) push(op, d, a, n);
      } else {
        push(op, d, a, 0);
      }
    }
  }
}

// (3) PICK/ROLL n-range exhaustive at a couple depths (0-index-from-top, incl out-of-range)
for (const op of ['PICK','ROLL']){
  for (const d of [3, 8, 15]){
    for (let n=0; n<=d+2; n++) push(op, d, 1, n);
  }
}

writeFileSync(join(here,'cases.json'), JSON.stringify({ cases }, null, 0));
console.log('wrote', cases.length, 'cases to cases.json');
