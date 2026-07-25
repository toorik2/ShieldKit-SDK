import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
const { asmToBytecode } = utils;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const lib = readFileSync('../../singleton/bn254/lib/Miller.cash','utf8');
function extract(name){ const s=lib.split('\n'),o=[];let p=false,d=0;for(const l of s){if(!p&&l.startsWith(`function ${name}(`))p=true;if(p){o.push(l);d+=(l.match(/\{/g)||[]).length-(l.match(/\}/g)||[]).length;if(d===0&&l.includes('}'))break;}}return o.join('\n');}
// grab all functions g2Double, g2AddAffine depend on
const allfns=[...lib.matchAll(/^function (\w+)\(/gm)].map(m=>m[1]);
const libtext=allfns.map(extract).join('\n');
const OP_PUSHDATA2=0x4d;
function measure(body,nargs){
  const src=`pragma cashscript ^0.14.0;\ncontract T(){function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
  let raw;try{raw=asmToBytecode(compileString(src,{rescheduleStacks:true}).bytecode);}catch(e){return{err:String(e?.message??e).slice(0,90)};}
  const locking=Uint8Array.from(raw),pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
  const pad=Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(9000),...new Uint8Array(9000)]);
  const args=Array.from({length:nargs},(_,i)=>P-BigInt(1+i*7));
  const argBytes=Uint8Array.from([...args].reverse().flatMap(c=>[...pushInt(c)]));
  const st=vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:Uint8Array.from([...pad,...argBytes]),valueSatoshis:1000n}));
  return{opCost:st.metrics.operationCost,err:st.error?String(st.error).slice(0,90):undefined};
}
const b6=measure(`require(a0+a1+a2+a3+a4+a5!=0);`,6);
const b10=measure(`require(a0+a1+a2+a3+a4+a5+a6+a7+a8+a9!=0);`,10);
const gd=measure(`(int x0,int x1,int x2,int x3,int x4,int x5)=g2Double(a0,a1,a2,a3,a4,a5);require(x0+x1+x2+x3+x4+x5!=0);`,6);
const ga=measure(`(int x0,int x1,int x2,int x3,int x4,int x5)=g2AddAffine(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);require(x0+x1+x2+x3+x4+x5!=0);`,10);
console.log('g2Double net op:', gd.err||(gd.opCost-b6.opCost));
console.log('g2AddAffine net op:', ga.err||(ga.opCost-b10.opCost));
