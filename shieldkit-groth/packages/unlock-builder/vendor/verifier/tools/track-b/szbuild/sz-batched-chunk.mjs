import { repoPath as vcRepoPath } from '#repo-paths';
// STEP 2: a REALISTIC batched SZ Miller chunk measured on the VM — marginal per-mul cost
// in the BATCH (shared z, c0-power RLC, incremental transcript absorb), + the byte outcome
// under the project's scored-unlock model. This decides ship / no-ship (byte-positive?).
//
// Models M f-muls in one chunk: f_{k}=f_{k-1}*B_k (B_k = sparse line operand, committed).
// On-chain per mul: absorb R_k into the rolling transcript (state=HASH256(state||R_k_limbs)),
// eval B_k(z) + R_k(z) (A_k(z)=prev R eval, REUSED), accumulate LHS=Σc0^k A_k(z)B_k(z),
// RHS=Σc0^k R_k(z). z,c0 derived ONLY after the transcript closes (here: emulated by feeding
// a precomputed z to measure the per-mul Horner+absorb cost; the z-derivation is a one-time
// tail cost measured separately in sz-onchain-fs).
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { push, measure, P } from '../asm-measure.mjs';
import { hexToBin } from '../../../node_modules/@bitauth/libauth/build/index.js';

const CLI = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');
const mod = (x) => ((x % P) + P) % P;
const rng = (() => { let s = 0x77abn; return () => { s = (s * 6364136223846793005n + 1n) & ((1n << 64n) - 1n); return mod(s * 0x2545F4914F6CDD1Dn); }; })();
const compile = (src) => { const F = vcRepoPath('tools/track-b/szbuild/_batch.cash'); writeFileSync(F, src); return hexToBin(execFileSync('node', [CLI, F, '-h'], { encoding: 'utf8' }).trim()); };

const params = (names) => names.map((n) => `int ${n}`).join(',');
// per-mul block (CHAINED + transcript absorb): given z, c0pow (w), prev az (reused), the
// operand B_k (12 limbs) and result R_k (12 limbs):
//   bz = Horner(B_k, z); rz = Horner(R_k, z)
//   lhs += w * az * bz ; rhs += w * rz ; w *= c0
//   transcript-absorb: state = HASH256(state || R_k limbs)   [INCREMENTAL FS]
//   (az for next mul = rz)
function perMul(k) {
  const bn = Array.from({ length: 12 }, (_, i) => `b${k}_${i}`);
  const rn = Array.from({ length: 12 }, (_, i) => `r${k}_${i}`);
  let s = '';
  // Horner B_k(z)
  s += `        int bz${k} = ${bn[11]};\n`;
  for (let i = 10; i >= 0; i--) s += `        bz${k} = (bz${k} * z + ${bn[i]}) % P;\n`;
  // Horner R_k(z)
  s += `        int rz${k} = ${rn[11]};\n`;
  for (let i = 10; i >= 0; i--) s += `        rz${k} = (rz${k} * z + ${rn[i]}) % P;\n`;
  // accumulate: lhs += w * az * bz ; rhs += w * rz
  s += `        accL = (accL + (w * ((az * bz${k}) % P)) % P) % P;\n`;
  s += `        accR = (accR + (w * rz${k}) % P) % P;\n`;
  s += `        w = (w * c0) % P;\n`;
  s += `        az = rz${k};\n`;
  // INCREMENTAL transcript absorb of R_k (12 limbs, packed into one hash256 of state||R_k)
  s += `        state = hash256(state + ${rn.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ')});\n`;
  return { src: s, bn, rn };
}

function buildChunk(M) {
  const blocks = Array.from({ length: M }, (_, k) => perMul(k));
  const allParams = ['z', 'c0', 'az'].concat(blocks.flatMap((b) => [...b.bn, ...b.rn]));
  let body = `        int P = ${P};\n        int w = 1; int accL = 0; int accR = 0;\n        bytes32 state = 0x${'00'.repeat(32)};\n`;
  for (const b of blocks) body += b.src;
  // final: state is the rolling transcript; require it's nonzero (consume), accs consumed.
  body += '        require(accL + accR + int(state) >= 0 - P);\n';
  const src = `pragma cashscript ^0.13.0;\ncontract SZBatch() {\n    function spend(${params(allParams)}) {\n${body}    }\n}\n`;
  // unlocking values
  const z = rng(), c0 = rng(), az = rng();
  const vals = [z, c0, az];
  for (const b of blocks) { for (let i = 0; i < 12; i++) vals.push(rng()); for (let i = 0; i < 12; i++) vals.push(rng()); }
  return { src, vals, allParams };
}

console.log('M\topCost\tperMul\targBytes\tunlock=max(op/800,arg)\tbytes/mul');
const rows = [];
for (const M of [1, 4, 8, 13, 21, 40]) {
  const { src, vals } = buildChunk(M);
  const tpl = compile(src);
  const unlocking = Uint8Array.from(vals.slice().reverse().flatMap((x) => push(x)));
  const res = measure(tpl, unlocking);
  const argBytes = unlocking.length;
  const opPad = Math.ceil(res.opCost / 800);
  const scoredUnlock = Math.max(opPad, argBytes);
  const perMul = M > 1 ? res.opCost / M : res.opCost;
  rows.push({ M, op: res.opCost, perMul: Math.round(perMul), argBytes, lockBytes: tpl.length, scoredUnlock, accepted: res.accepted });
  console.log(`${M}\t${res.opCost}\t${Math.round(perMul)}\t${argBytes}\t${scoredUnlock}\t${(scoredUnlock / M).toFixed(0)}  acc=${res.accepted}`);
}
// marginal per-mul (from the slope between two large M)
const big = rows[rows.length - 1], mid = rows[rows.length - 2];
const marginalOp = (big.op - mid.op) / (big.M - mid.M);
const marginalArg = (big.argBytes - mid.argBytes) / (big.M - mid.M);
console.log(`\nMARGINAL per-mul: op=${Math.round(marginalOp)}  argBytes=${Math.round(marginalArg)}`);
console.log(`marginal op/800 = ${(marginalOp / 800).toFixed(1)} B/mul of op-padding  vs  ${Math.round(marginalArg)} B/mul of witness`);
console.log(`=> witness ${marginalArg > marginalOp / 800 ? 'EXCEEDS' : 'is ABSORBED by'} op-padding (per-mul). ${marginalArg > marginalOp / 800 ? 'WITNESS-BOUND (byte floor = witness)' : 'OP-BOUND (witness free)'}`);
