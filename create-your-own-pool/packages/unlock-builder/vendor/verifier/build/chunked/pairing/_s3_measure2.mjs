import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
import { bn254, Fp2, pairsFor, vec } from './_millermath.mjs';
const { asmToBytecode } = utils;
const { Fp } = bn254.fields;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const B0=19485874751759354771024239261021720505790618469301721065564631296452457478373n, B1=266929791119991161246907387137283842545076965332900288569378510910307636690n;
const B3_0=(3n*B0)%P, B3_1=(3n*B1)%P;
const lib = readFileSync('variants/V3_millerres_lib.cash','utf8');
function extract(name){ const src=lib.split('\n'); const out=[]; let p=false,depth=0;
  for(const ln of src){ if(!p && ln.startsWith(`function ${name}(`)) p=true;
    if(p){ out.push(ln); depth += (ln.match(/\{/g)||[]).length-(ln.match(/\}/g)||[]).length; if(depth===0&&ln.includes('}')) break; } } return out.join('\n'); }
const need=['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale'];
const AFF = readFileSync('_afflib.cash','utf8');
const libtext = need.map(extract).join('\n\n') + '\n' + AFF;
const OP_PUSHDATA2=0x4d;
function measure(body, argvals){
  const nargs=argvals.length;
  const src=`pragma cashscript ^0.14.0;\ncontract T(){function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
  let raw; try{ raw=asmToBytecode(compileString(src,{rescheduleStacks:true}).bytecode);}catch(e){return{err:String(e?.message??e).slice(0,140)};}
  const locking=Uint8Array.from(raw);
  const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(n));
  const padN=9000, pad=Uint8Array.from([OP_PUSHDATA2,...numberToBinUint16LE(padN),...new Uint8Array(padN)]);
  const argBytes=Uint8Array.from([...argvals].reverse().flatMap(c=>[...pushInt(c)]));
  const st=vm.evaluate(createTestAuthenticationProgramBch({lockingBytecode:locking,unlockingBytecode:Uint8Array.from([...pad,...argBytes]),valueSatoshis:1000n}));
  return {opCost:st.metrics.operationCost,arith:st.metrics.arithmeticCost,lockBytes:locking.length,err:st.error?String(st.error).slice(0,140):undefined};
}
const fw=(i)=>P-BigInt(1+i*7);
const base6=measure(`require(a0+a1+a2+a3+a4+a5!=0);`,[0,1,2,3,4,5].map(fw));
const base10=measure(`require(a0+a1+a2+a3+a4+a5+a6+a7+a8+a9!=0);`,[0,1,2,3,4,5,6,7,8,9].map(fw));
const SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
const Q=pairsFor(vec.publicInputs)[0].Q.toAffine();
const lamD=Fp2.mul(SC(Fp2.sqr(Q.x),3n),Fp2.inv(Fp2.add(Q.y,Q.y)));
const affd=measure(`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affDbl(a0,a1,a2,a3,a4,a5);\nrequire(c0a+c0b+c1a+c1b+c2a+c2b+nxa+nxb+nya+nyb!=0);`,[Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,lamD.c0,lamD.c1]);
const twoQ=pairsFor(vec.publicInputs)[0].Q.double().toAffine();
const lamA=Fp2.mul(Fp2.sub(twoQ.y,Q.y),Fp2.inv(Fp2.sub(twoQ.x,Q.x)));
const affa=measure(`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);\nrequire(c0a+c0b+c1a+c1b+c2a+c2b+nxa+nxb+nya+nyb!=0);`,[twoQ.x.c0,twoQ.x.c1,twoQ.y.c0,twoQ.y.c1,Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1,lamA.c0,lamA.c1]);
console.log('base6',base6.opCost,'base10',base10.opCost);
console.log('affDbl',affd.err||('op '+affd.opCost+' net '+(affd.opCost-base6.opCost)));
console.log('affAdd',affa.err||('op '+affa.opCost+' net '+(affa.opCost-base10.opCost)));
if(!affd.err&&!affa.err){
  const dSave=193988-(affd.opCost-base6.opCost), aSave=247732-(affa.opCost-base10.opCost);
  console.log('saves/double',dSave,'saves/add',aSave);
  console.log('TOTAL pair0 op saving = 65*'+dSave+' + 23*'+aSave+' =', 65*dSave+23*aSave);
}
