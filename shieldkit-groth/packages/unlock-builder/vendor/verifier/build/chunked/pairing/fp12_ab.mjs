// Head-to-head: cashc rescheduleStacks vs LeanBCH move-arrange, on the fp12Sqr body.
import { compileFile, utils } from 'cashc';
import { writeFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { bigIntToVmNumber } from '@bitauth/libauth';
import { measureRun, decompose } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
// call fp12Sqr TWICE so cashc keeps it as an OP_DEFINE function (LeanBCH move-arrange needs the table)
const src = `pragma cashscript ^0.14.0;
import "../../../singleton/bn254/lib/lazy/Bn254Lazy.cash";
contract Bench() {
  function run(int a0,int a1,int a2,int a3,int a4,int a5,int a6,int a7,int a8,int a9,int a10,int a11) {
    int b0,int b1,int b2,int b3,int b4,int b5,int b6,int b7,int b8,int b9,int b10,int b11 = fp12Sqr(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11);
    int c0,int c1,int c2,int c3,int c4,int c5,int c6,int c7,int c8,int c9,int c10,int c11 = fp12Sqr(b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11);
    require((c0+c1+c2+c3+c4+c5+c6+c7+c8+c9+c10+c11) % ${P} == 1234567890);
  }
}`;
writeFileSync('generated/fp12ab.cash', src);
const bcResched = utils.asmToBytecode(compileFile('generated/fp12ab.cash', { rescheduleStacks: true }).bytecode);
const bcRaw = utils.asmToBytecode(compileFile('generated/fp12ab.cash', {}).bytecode);
const hex = (b)=>Buffer.from(b).toString('hex');
writeFileSync('/tmp/fp12raw.hex', hex(bcRaw));
// LeanBCH optimizer on the raw compile
const OPT='/home/toorik/Projects/LeanBCH/optimizer';
const r = spawnSync('node',[OPT+'/optimize.mjs','/tmp/fp12raw.hex','/tmp/fp12lean.hex'],{encoding:'utf8'});
process.stderr.write((r.stdout||'')+ (r.stderr||''));
const bcLean = Uint8Array.from(Buffer.from(readFileSync('/tmp/fp12lean.hex','utf8').trim(),'hex'));
const a = Array.from({length:12},(_,i)=> P - BigInt(1+i*7));
const push=(n)=>{const d=bigIntToVmNumber(n);return Uint8Array.from([d.length,...d]);};
const unlock=Uint8Array.from([...a].reverse().flatMap(x=>[...push(x)]));
for (const [tag,bc] of [['cashc-raw',bcRaw],['cashc-rescheduleStacks',bcResched],['LeanBCH-optimize(on raw)',bcLean]]) {
  const m=measureRun(bc,unlock);
  console.log(`  ${tag.padEnd(24)} bytes=${String(bc.length).padStart(4)}  opCost=${String(m.opCost).padStart(7)}  instr=${m.instr}`);
}
