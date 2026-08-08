import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber } from '@bitauth/libauth';
import { writeFileSync } from 'node:fs';
import { measureRun, decompose } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const RESCHED = process.env.RESCHEDULE === 'off' ? {} : { rescheduleStacks: true };
const src = `pragma cashscript ^0.14.0;
import "../../../singleton/bn254/lib/lazy/Bn254Lazy.cash";
contract Bench() {
  function run(int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11) {
    int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11 = fp12Sqr(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11);
    int s = (b0+b1+b2+b3+b4+b5+b6+b7+b8+b9+b10+b11) % ${P};
    require(s == 12345678901234567890123456789012345678901234567890123456789012345678901234567);
  }
}`;
writeFileSync('generated/fp12bench.cash', src);
const bc = utils.asmToBytecode(compileFile('generated/fp12bench.cash', RESCHED).bytecode);
const a = Array.from({length:12},(_,i)=> P - BigInt(1+i*7));
const push = (n)=>{const d=bigIntToVmNumber(n); return Uint8Array.from([d.length,...d]);};
const unlock = Uint8Array.from([...a].reverse().flatMap(x=> [...push(x)]));
const r = measureRun(bc, unlock); const d = decompose(r);
console.log(`fp12Sqr (RESCHEDULE=${process.env.RESCHEDULE||'on'}) via LeanBCH cost.mjs: redeem ${bc.length}B  opCost=${r.opCost}  instr=${r.instr}`);
console.log(`  arith ${d.arithPct}%  base(glue) ${d.basePct}%  push ${d.pushPct}%   (${r.error? 'ran through sqr, require-failed(expected)':'accepted'})`);
