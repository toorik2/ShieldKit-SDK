import { repoPath as vcRepoPath } from '#repo-paths';
// DECISIVE measurement: SZ chunk with a REUSABLE szEval function (defined once, invoked per mul).
// If locking stays small (function shared) AND op-cost ~same, the SZ Miller is byte-POSITIVE.
// This is the architecture that makes scenario B real.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { push, measure, P } from '../asm-measure.mjs';
import { hexToBin } from '../../../node_modules/@bitauth/libauth/build/index.js';

const CLI = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');
const mod = (x) => ((x % P) + P) % P;
const rng = (() => { let s = 0x77abn; return () => { s = (s * 6364136223846793005n + 1n) & ((1n << 64n) - 1n); return mod(s * 0x2545F4914F6CDD1Dn); }; })();
const compile = (src) => { const F = vcRepoPath('tools/track-b/szbuild/_reuse.cash'); writeFileSync(F, src); return hexToBin(execFileSync('node', [CLI, F, '-h'], { encoding: 'utf8' }).trim()); };

// szEval12(z, c0..c11) -> Horner eval of a deg-11 poly at z. Reusable function.
// szStep(z, w, c0, accL, accR, az, B0..B11, R0..R11) -> updates (accL,accR,w,az) for one mul,
//   returns the new az (=R(z)). But cashscript internal functions can't return tuples easily across
//   re-use; model szEval as the reusable core + inline the small accumulate.
function buildChunk(M, useReusable) {
  const horner12 = (zname, prefix) => {
    let s = `        int ${prefix}z = ${prefix}11;\n`;
    for (let i = 10; i >= 0; i--) s += `        ${prefix}z = (${prefix}z * ${zname} + ${prefix}${i}) % P;\n`;
    return s;
  };
  const args = Array.from({ length: 12 }, (_, i) => `int q${i}`).join(', ');
  const fnDef = `    internal function szEval(int z, ${args}) returns (int) {
        int P = ${P};
        int acc = q11;
        acc = (acc * z + q10) % P; acc = (acc * z + q9) % P; acc = (acc * z + q8) % P;
        acc = (acc * z + q7) % P; acc = (acc * z + q6) % P; acc = (acc * z + q5) % P;
        acc = (acc * z + q4) % P; acc = (acc * z + q3) % P; acc = (acc * z + q2) % P;
        acc = (acc * z + q1) % P; acc = (acc * z + q0) % P;
        return acc;
    }`;
  const blocks = [];
  const allParams = ['z', 'c0', 'az'];
  let body = '';
  for (let k = 0; k < M; k++) {
    const bn = Array.from({ length: 12 }, (_, i) => `b${k}_${i}`);
    const rn = Array.from({ length: 12 }, (_, i) => `r${k}_${i}`);
    allParams.push(...bn, ...rn);
    if (useReusable) {
      body += `        int bz${k} = szEval(z, ${bn.join(', ')});\n`;
      body += `        int rz${k} = szEval(z, ${rn.join(', ')});\n`;
    } else {
      body += horner12('z', `b${k}_`).replace(new RegExp(`b${k}_z`, 'g'), `bz${k}`).replace(/^/, '').replace(new RegExp(`int bz${k}`), `int bz${k}`);
      // fallback inline (not used in the reusable path)
    }
    body += `        accL = (accL + (w * ((az * bz${k}) % P)) % P) % P;\n`;
    body += `        accR = (accR + (w * rz${k}) % P) % P;\n`;
    body += `        w = (w * c0) % P; az = rz${k};\n`;
    body += `        state = hash256(state + ${rn.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ')});\n`;
  }
  body += '        require(accL + accR + int(state) >= 0 - P);\n';
  const src = `pragma cashscript ^0.13.0;
contract SZReuse() {
${useReusable ? fnDef + '\n' : ''}    function spend(${allParams.map((p, i) => i < 3 ? `int ${p}` : `int ${p}`).join(', ')}) {
        int P = ${P};
        int w = 1; int accL = 0; int accR = 0;
        bytes32 state = 0x${'00'.repeat(32)};
${body}    }
}
`;
  const z = rng(), c0 = rng(), az = rng();
  const vals = [z, c0, az];
  for (let k = 0; k < M; k++) { for (let i = 0; i < 12; i++) vals.push(rng()); for (let i = 0; i < 12; i++) vals.push(rng()); }
  return { src, vals };
}

console.log('M\tlock(B)\tlock/mul\topCost\tperMul\tacc');
for (const M of [1, 8, 13, 21, 40, 80]) {
  const { src, vals } = buildChunk(M, true);
  let tpl;
  try { tpl = compile(src); } catch (e) { console.log(`${M}\tCOMPILE ERROR: ${String(e).slice(0, 80)}`); continue; }
  const unlocking = Uint8Array.from(vals.slice().reverse().flatMap((x) => push(x)));
  const res = measure(tpl, unlocking);
  console.log(`${M}\t${tpl.length}\t${(tpl.length / M).toFixed(0)}\t${res.opCost}\t${Math.round(res.opCost / M)}\t${res.accepted}`);
}
