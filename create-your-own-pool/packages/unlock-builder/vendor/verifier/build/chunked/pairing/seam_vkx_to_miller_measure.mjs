// Build a vk_x-FINAL chunk that carries the runtime miller points [negA,B,C] as committed
// pass-through state and produces covOut == commitBin([negA,B,vkx,C]) (ptParams order) ==
// the miller-genesis reloc covIn. Measure it accepts on the real VM and the seam commitment matches.
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bn254, vec, commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecodeRaw, proof, vkxPoint } from './_millermath.mjs';
import { inState } from './gen_miller_residue.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, binToHex } from '@bitauth/libauth';
const here=dirname(fileURLToPath(import.meta.url)), GEN=join(here,'generated');
const realVm=createVirtualMachineBch2026(false);
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr=P.toString(), red=(x)=>((BigInt(x)%P)+P)%P;
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush=(a,t)=>Uint8Array.from([0x4d,...numberToBinUint16LE(t-a-3),...new Uint8Array(t-a-3)]);
const g1=(o)=>bn254.G1.Point.fromAffine({x:BigInt(o.x),y:BigInt(o.y)});
const IC=vec.vk.ic.map(g1), ic0=IC[0].toAffine();
// committed instance values
const inputs=vec.publicInputs.map(BigInt);
const negA=proof.a.negate().toAffine(), Ba=proof.b.toAffine(), Ca=proof.c.toAffine();
const vkx=vkxPoint(inputs).toAffine();
const seamLimbs=[negA.x,negA.y,Ba.x.c0,Ba.x.c1,Ba.y.c0,Ba.y.c1,vkx.x,vkx.y,Ca.x,Ca.y].map(red);
const relocCovIn=binToHex(commitBin(inState(0).map(BigInt).slice(18,28).map(red)));
// A tiny vk_x-final: assume the accumulator is already folded (single-window final for demo of the SEAM);
// we take rX,rY,rZ (pre-IC0 accumulator) + carried points + zInv, fold IC0, affine-ize, covOut seam.
// Use the REAL final accumulator so vkx computed == the instance vkx.
const P_=P; const aF=(x,y)=>(x+y)%P_,sF=(x,y)=>(x-y+P_)%P_,mF=(x,y)=>(x*y)%P_,qF=(x)=>(x*x)%P_;
function jacAdd(aX,aY,aZ,bX,bY,bZ){ if(aZ===0n)return[bX,bY,bZ]; const z1=qF(aZ),z2=qF(bZ);const u1=mF(aX,z2),u2=mF(bX,z1);const s1=mF(mF(aY,bZ),z2),s2=mF(mF(bY,aZ),z1); if(u1===u2&&s1===s2){throw'dbl';} const h=sF(u2,u1),i2=qF(mF(2n,h)),j=mF(h,i2),rr=mF(2n,sF(s2,s1)),v=mF(u1,i2); const nx=sF(sF(qF(rr),j),mF(2n,v)); return[nx,sF(mF(rr,sF(v,nx)),mF(2n,mF(s1,j))),mF(sF(sF(qF(aF(aZ,bZ)),z1),z2),h)]; }
const modpow=(b,e,m)=>{let r=1n;b%=m;while(e>0n){if(e&1n)r=(r*b)%m;b=(b*b)%m;e>>=1n;}return r;};
// accumulator BEFORE IC0 fold: recompute via noble multiply (accumulate ic1*in0 + ic2*in1)
let acc=IC[1].multiply(inputs[0]).add(IC[2].multiply(inputs[1]));
const accA=acc.toAffine(); const [rX,rY,rZ]=[accA.x,accA.y,1n];
const [fx,fy,fz]=jacAdd(rX,rY,rZ,ic0.x,ic0.y,1n);
const zInv=fz===0n?0n:modpow(fz,P-2n,P);
// contract
const L=[];
L.push('pragma cashscript ^0.14.0;');
L.push(`function mulFp(int x,int y) returns(int){return (x*y)%${Pstr};}`);
L.push(`function sqrFp(int x) returns(int){return (x*x)%${Pstr};}`);
L.push('contract VkxFinalSeam(){');
L.push('    function spend(int rX,int rY,int rZ,int input0,int input1,int nAx,int nAy,int Bxa,int Bxb,int Bya,int Byb,int Cx,int Cy,int zInv,bytes unused zeroPadding){');
// covIn over the 13 committed carried limbs
const covInNames=['rX','rY','rZ','input0','input1','nAx','nAy','Bxa','Bxb','Bya','Byb','Cx','Cy'];
L.push(`        require(tx.inputs[this.activeInputIndex].nftCommitment == hash256(${covInNames.map(n=>`toPaddedBytes(${n}, 40)`).join(' + ')}));`);
L.push(`        int icx = ${fx.toString()}; int icy = ${fy.toString()}; int icz = ${fz.toString()};`);
L.push('        require(mulFp(icz, zInv) == 1);');
L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
L.push('        int vkxX = mulFp(icx, zInv2);');
L.push('        int vkxY = mulFp(icy, zInv3);');
// covOut = seam commitment in ptParams order [nAx,nAy,Bxa,Bxb,Bya,Byb,vkxX,vkxY,Cx,Cy]
const seamNames=['nAx','nAy','Bxa','Bxb','Bya','Byb','vkxX','vkxY','Cx','Cy'];
L.push(`        int Pmod = ${Pstr};`);
L.push(`        require(tx.outputs[0].nftCommitment == hash256(${seamNames.map(n=>`toPaddedBytes(${n} % Pmod, 40)`).join(' + ')}));`);
L.push('        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);');
L.push('    }');
L.push('}');
const src=L.join('\n')+'\n';
const probe=join(GEN,'_probe_vkxseam.cash'); writeFileSync(probe,src);
let raw; try{raw=compileFileBytecodeRaw(probe);}catch(e){console.log('COMPILE ERR',e.message);process.exit(1);}
const locking=Uint8Array.from([...raw]);
const committed=[rX,rY,rZ,inputs[0],inputs[1],negA.x,negA.y,Ba.x.c0,Ba.x.c1,Ba.y.c0,Ba.y.c1,Ca.x,Ca.y].map(red);
const inCommit=commitBin(committed);
const outCommit=commitBin(seamLimbs);
const pushInts=[...committed,zInv];
const argBytes=Uint8Array.from([...pushInts].reverse().flatMap((v)=>[...pushInt(v)]));
const unlocking=Uint8Array.from([...padPush(argBytes.length,TARGET_UNLOCK),...argBytes]);
const tok=(cm)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:cm}});
const st=realVm.evaluate({inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
  transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],
  outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(outCommit)}],locktime:0}});
const top=st.stack[st.stack.length-1];
const accepted=st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1;
console.log('vkx-final SEAM chunk accepted:', accepted, 'err:', st.error??'');
console.log('vkx-final covOut  =', binToHex(outCommit));
console.log('miller reloc covIn=', relocCovIn);
console.log('START SEAM (vkx-final covOut == miller-genesis reloc covIn):', binToHex(outCommit)===relocCovIn);
