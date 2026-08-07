import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
const { asmToBytecode } = utils;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const lib = readFileSync('variants/V3_millerres_lib.cash','utf8');
function extract(name){ const src=lib.split('\n'); const out=[]; let p=false,depth=0;
  for(const ln of src){ if(!p && ln.startsWith(`function ${name}(`)) p=true;
    if(p){ out.push(ln); depth += (ln.match(/\{/g)||[]).length-(ln.match(/\}/g)||[]).length; if(depth===0&&ln.includes('}')) break; } } return out.join('\n'); }
const need = ['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale','fp2MulByB','fp2Half','fp2MulXi','pointDouble','pointAdd'];
const libtext = need.map(extract).join('\n\n');
const OP_PUSHDATA2=0x4d, OP_DROP=0x75;
function measure(bodySrc, nargs){
  const src = `pragma cashscript ^0.14.0;\ncontract T() {\n  function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(', ')}, bytes unused pad) {\n${bodySrc}\n  }\n}\n${libtext}`;
  let raw; try { raw = asmToBytecode(compileString(src, { rescheduleStacks: true }).bytecode); } catch(e){ return {err:String(e?.message??e)}; }
  const locking = Uint8Array.from(raw);
  const args = Array.from({length:nargs},(_,i)=> P - BigInt(1+i*7));
  const pushInt=(n)=> encodeDataPush(bigIntToVmNumber(n));
  // big pad first (the trailing 'pad' bytes param), then args reversed
  const padN = 9000;
  const pad = Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(padN), ...new Uint8Array(padN)]);
  const argBytes = Uint8Array.from([...args].reverse().flatMap(c=>[...pushInt(c)]));
  const unlocking = Uint8Array.from([...pad, ...argBytes]);
  const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  return { opCost: st.metrics.operationCost, arith: st.metrics.arithmeticCost, instr: st.metrics.evaluatedInstructionCount, lockBytes: locking.length, err: st.error?String(st.error).slice(0,80):undefined };
}
const base6 = measure(`    require(a0+a1+a2+a3+a4+a5 != 0);`, 6);
const base10 = measure(`    require(a0+a1+a2+a3+a4+a5+a6+a7+a8+a9 != 0);`, 10);
console.log('base6', base6.opCost, 'arith', base6.arith);
console.log('base10', base10.opCost, 'arith', base10.arith);
const pd = measure(`    (int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int nxa,int nxb,int nya,int nyb,int nza,int nzb) = pointDouble(a0,a1,a2,a3,a4,a5);
    require(c0a+c0b+c1a+c1b+c2a+c2b+nxa+nxb+nya+nyb+nza+nzb != 0);`, 6);
const pa = measure(`    (int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int nxa,int nxb,int nya,int nyb,int nza,int nzb) = pointAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);
    require(c0a+c0b+c1a+c1b+c2a+c2b+nxa+nxb+nya+nyb+nza+nzb != 0);`, 10);
console.log('pointDouble', pd.opCost, 'arith', pd.arith, 'err?', pd.err, '=> net', pd.opCost-base6.opCost);
console.log('pointAdd', pa.opCost, 'arith', pa.arith, 'err?', pa.err, '=> net', pa.opCost-base10.opCost);
// single mulFp cost
const m1 = measure(`    require(mulFp(a0,a1) != 0);`, 2);
const base2 = measure(`    require(a0+a1 != 0);`,2);
console.log('mulFp net op ~', m1.opCost-base2.opCost, 'arith', m1.arith-base2.arith);
