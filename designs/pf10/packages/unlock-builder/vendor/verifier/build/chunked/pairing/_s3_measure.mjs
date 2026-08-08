import { readFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
const { asmToBytecode } = utils;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const B0 = 19485874751759354771024239261021720505790618469301721065564631296452457478373n;
const B1 = 266929791119991161246907387137283842545076965332900288569378510910307636690n;
const B3_0 = (3n*B0)%P, B3_1 = (3n*B1)%P;
const lib = readFileSync('variants/V3_millerres_lib.cash','utf8');
function extract(name){ const src=lib.split('\n'); const out=[]; let p=false,depth=0;
  for(const ln of src){ if(!p && ln.startsWith(`function ${name}(`)) p=true;
    if(p){ out.push(ln); depth += (ln.match(/\{/g)||[]).length-(ln.match(/\}/g)||[]).length; if(depth===0&&ln.includes('}')) break; } } return out.join('\n'); }
const need = ['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale','fp2MulByB','fp2Half','fp2MulXi','pointDouble','pointAdd'];
// affine check-back functions (appended to lib text)
const affLib = `
function affDbl(int xa,int xb, int ya,int yb, int la,int lb) returns (int,int,int,int,int,int, int,int,int,int) {
    int Pm = ${P};
    (int x2a,int x2b) = fp2Sqr(xa,xb);
    (int c1a,int c1b) = fp2Scale(x2a,x2b,3);
    (int y2a,int y2b) = fp2Add(ya,yb,ya,yb);
    (int cka,int ckb) = fp2Mul(la,lb,y2a,y2b);
    require((cka - c1a) % Pm == 0); require((ckb - c1b) % Pm == 0);
    (int c2a,int c2b) = fp2Neg(ya,yb,64);
    (int yya,int yyb) = fp2Sqr(ya,yb);
    (int c0a,int c0b) = fp2Sub(${B3_0}, ${B3_1}, yya, yyb, 1);
    (int l2a,int l2b) = fp2Sqr(la,lb);
    (int xna,int xnb) = fp2Sub(l2a,l2b, addFp(xa,xa), addFp(xb,xb), 1);
    (int dxa,int dxb) = fp2Sub(xa,xb,xna,xnb,64);
    (int lya,int lyb) = fp2Mul(la,lb,dxa,dxb);
    (int yna,int ynb) = fp2Sub(lya,lyb,ya,yb,1);
    return c0a,c0b,c1a,c1b,c2a,c2b, xna,xnb,yna,ynb;
}
function affAdd(int Rxa,int Rxb,int Rya,int Ryb, int Qxa,int Qxb,int Qya,int Qyb, int la,int lb) returns (int,int,int,int,int,int, int,int,int,int) {
    int Pm = ${P};
    require((Rxa - Qxa) % Pm != 0 || (Rxb - Qxb) % Pm != 0);
    (int t1a,int t1b) = fp2Sub(Rxa,Rxb,Qxa,Qxb,64);
    (int t0a,int t0b) = fp2Sub(Rya,Ryb,Qya,Qyb,64);
    (int cka,int ckb) = fp2Mul(la,lb,t1a,t1b);
    require((cka - t0a) % Pm == 0); require((ckb - t0b) % Pm == 0);
    (int q0a,int q0b) = fp2Mul(t0a,t0b,Qxa,Qxb);
    (int q1a,int q1b) = fp2Mul(t1a,t1b,Qya,Qyb);
    (int c0a,int c0b) = fp2Sub(q0a,q0b,q1a,q1b,3);
    (int c1a,int c1b) = fp2Neg(t0a,t0b,64);
    int c2a = t1a; int c2b = t1b;
    (int l2a,int l2b) = fp2Sqr(la,lb);
    (int s1a,int s1b) = fp2Sub(l2a,l2b,Rxa,Rxb,64);
    (int xna,int xnb) = fp2Sub(s1a,s1b,Qxa,Qxb,64);
    (int dxa,int dxb) = fp2Sub(Rxa,Rxb,xna,xnb,64);
    (int lya,int lyb) = fp2Mul(la,lb,dxa,dxb);
    (int yna,int ynb) = fp2Sub(lya,lyb,Rya,Ryb,1);
    return c0a,c0b,c1a,c1b,c2a,c2b, xna,xnb,yna,ynb;
}
`;
const libtext = need.map(extract).join('\n\n') + affLib;
const OP_PUSHDATA2=0x4d;
function measure(bodySrc, argvals){
  const nargs=argvals.length;
  const src = `pragma cashscript ^0.14.0;\ncontract T() {\n  function f(${Array.from({length:nargs},(_,i)=>`int a${i}`).join(', ')}, bytes unused pad) {\n${bodySrc}\n  }\n}\n${libtext}`;
  let raw; try { raw = asmToBytecode(compileString(src, { rescheduleStacks: true }).bytecode); } catch(e){ return {err:String(e?.message??e).slice(0,120)}; }
  const locking = Uint8Array.from(raw);
  const pushInt=(n)=> encodeDataPush(bigIntToVmNumber(n));
  const padN = 9000;
  const pad = Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(padN), ...new Uint8Array(padN)]);
  const argBytes = Uint8Array.from([...argvals].reverse().flatMap(c=>[...pushInt(c)]));
  const unlocking = Uint8Array.from([...pad, ...argBytes]);
  const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n }));
  return { opCost: st.metrics.operationCost, arith: st.metrics.arithmeticCost, lockBytes: locking.length, err: st.error?String(st.error).slice(0,120):undefined };
}
// realistic full-width point coords: use pair0's Q as x,y; witness lam arbitrary full-width (measurement only)
const fw=(i)=>P-BigInt(1+i*7);
// baseline consumers
const base6 = measure(`    require(a0+a1+a2+a3+a4+a5 != 0);`, [0,1,2,3,4,5].map(fw));
const base10 = measure(`    require(a0+a1+a2+a3+a4+a5+a6+a7+a8+a9 != 0);`, [0,1,2,3,4,5,6,7,8,9].map(fw));
// affDbl: 6 args (x,y,lam) but need lam consistent for require to pass -> use REAL values
import { bn254, Fp2, pairsFor, vec } from './_millermath.mjs';
const { Fp } = bn254.fields;
const Q = pairsFor(vec.publicInputs)[0].Q.toAffine();
const SC=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
const lamD = Fp2.mul(SC(Fp2.sqr(Q.x),3n), Fp2.inv(Fp2.add(Q.y,Q.y)));
const dblArgs = [Q.x.c0,Q.x.c1, Q.y.c0,Q.y.c1, lamD.c0,lamD.c1];
const affd = measure(`    (int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int nxa,int nxb,int nya,int nyb) = affDbl(a0,a1,a2,a3,a4,a5);
    require(c0a+c0b+c1a+c1b+c2a+c2b+nxa+nxb+nya+nyb != 0);`, dblArgs);
// affAdd: R=2Q, Q=Q, lam
const twoQ = pairsFor(vec.publicInputs)[0].Q.double().toAffine();
const lamA = Fp2.mul(Fp2.sub(twoQ.y,Q.y), Fp2.inv(Fp2.sub(twoQ.x,Q.x)));
const addArgs=[twoQ.x.c0,twoQ.x.c1,twoQ.y.c0,twoQ.y.c1, Q.x.c0,Q.x.c1,Q.y.c0,Q.y.c1, lamA.c0,lamA.c1];
const affa = measure(`    (int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int nxa,int nxb,int nya,int nyb) = affAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);
    require(c0a+c0b+c1a+c1b+c2a+c2b+nxa+nxb+nya+nyb != 0);`, addArgs);
console.log('base6', base6.opCost, '| base10', base10.opCost);
console.log('affDbl:', affd.err||('op '+affd.opCost+' arith '+affd.arith+' net '+(affd.opCost-base6.opCost)));
console.log('affAdd:', affa.err||('op '+affa.opCost+' arith '+affa.arith+' net '+(affa.opCost-base10.opCost)));
console.log('\nCURRENT pointDouble net ~193988, pointAdd net ~247732');
if(!affd.err&&!affa.err){
  console.log('affDbl saves ~', 193988-(affd.opCost-base6.opCost), 'op/double');
  console.log('affAdd saves ~', 247732-(affa.opCost-base10.opCost), 'op/add');
}
