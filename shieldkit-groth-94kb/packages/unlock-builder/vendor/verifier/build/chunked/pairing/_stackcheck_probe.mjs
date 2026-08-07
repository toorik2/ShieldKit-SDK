import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber, createTestAuthenticationProgramBch } from '@bitauth/libauth';
import { looseVm } from '/home/toorik/Projects/LeanBCH/optimizer/core/program.mjs';
import { Fp12, Fp } from './_millermath.mjs';
import { writeFileSync } from 'node:fs';
const P=Fp.ORDER;
const mk2=(a,b)=>({c0:((a%P)+P)%P,c1:((b%P)+P)%P});
const toF12=(L)=>({c0:{c0:mk2(L[0],L[1]),c1:mk2(L[2],L[3]),c2:mk2(L[4],L[5])},c1:{c0:mk2(L[6],L[7]),c1:mk2(L[8],L[9]),c2:mk2(L[10],L[11])}});
const flat=(f)=>[f.c0.c0.c0,f.c0.c0.c1,f.c0.c1.c0,f.c0.c1.c1,f.c0.c2.c0,f.c0.c2.c1,f.c1.c0.c0,f.c1.c0.c1,f.c1.c1.c0,f.c1.c1.c1,f.c1.c2.c0,f.c1.c2.c1];
const nobleMul=(A,B)=>flat(Fp12.mul(toF12(A),toF12(B)));
const push=(n)=>{const d=bigIntToVmNumber(n);if(d.length===0)return Uint8Array.from([0]);if(d.length===1&&d[0]>=1&&d[0]<=16)return Uint8Array.from([0x50+d[0]]);if(d.length===1&&d[0]===0x81)return Uint8Array.from([0x4f]);return Uint8Array.from([d.length,...d]);};
const unlockFor=(a)=>Uint8Array.from([...a].reverse().flatMap(x=>[...push(x)]));
const P4=Array.from({length:12},(_,i)=>'int a'+i).concat(Array.from({length:12},(_,i)=>'int b'+i)).join(',');
const A4=Array.from({length:12},(_,i)=>'a'+i).concat(Array.from({length:12},(_,i)=>'b'+i)).join(',');
const OUT=Array.from({length:12},(_,i)=>'int c'+i).join(',');
const A=Array.from({length:12},(_,i)=>P-BigInt(3+i)),B=Array.from({length:12},(_,i)=>P-BigInt(7+2*i));
const e=nobleMul(A,B);
function evalStack(chk){
  writeFileSync('generated/_ng.cash','pragma cashscript ^0.14.0;\nimport "../variants/V3_mul_delayed.cash";\ncontract C(){function r('+P4+'){'+OUT+' = fp12Mul('+A4+');require('+chk+');}}');
  const bc=utils.asmToBytecode(compileFile('generated/_ng.cash',{rescheduleStacks:true}).bytecode);
  const st=looseVm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:bc,unlockingBytecode:unlockFor([...A,...B]),valueSatoshis:1000n}));
  const top=st.stack[st.stack.length-1];
  const accept = st.error===undefined && st.stack.length===1 && top!==undefined && top.length===1 && top[0]===1;
  return {err:st.error?String(st.error).slice(0,50):null, len:st.stack.length, top:top?[...top]:null, accept};
}
console.log('CORRECT  :', JSON.stringify(evalStack(e.map((v,i)=>'c'+i+' == '+v).join(' && '))));
const bad=[...e]; bad[0]=(bad[0]+1n)%P;
console.log('WRONG c0 :', JSON.stringify(evalStack(bad.map((v,i)=>'c'+i+' == '+v).join(' && '))));
