// Export vkx-genesis non-canonical scenarios as P2SH32 txs for LeanBCH cross-check.
import { writeFileSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bn254, vec, commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecode, proof, le40 } from './_millermath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, binToHex,
  hash256, encodeLockingBytecodeP2sh32, encodeTransaction, encodeTransactionOutputs } from '@bitauth/libauth';
import { createHash } from 'node:crypto';
const here=dirname(fileURLToPath(import.meta.url)), GEN=join(here,'generated');
const realVm=createVirtualMachineBch2026(false);
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red=(x)=>((BigInt(x)%P)+P)%P;
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const sha256d=(b)=>createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const commitBufs=(bufs)=>new Uint8Array(sha256d(Buffer.concat(bufs)));
const g1=(o)=>bn254.G1.Point.fromAffine({x:BigInt(o.x),y:BigInt(o.y)});
const IC=vec.vk.ic.map(g1), ic1=IC[1].toAffine(), ic2=IC[2].toAffine(), Ta=IC[1].add(IC[2]).toAffine();
const inputs=vec.publicInputs.map(BigInt), in0=red(inputs[0]), in1=red(inputs[1]);
const negA=proof.a.negate().toAffine(), Ba=proof.b.toAffine(), Ca=proof.c.toAffine();
const seam=[negA.x,negA.y,Ba.x.c0,Ba.x.c1,Ba.y.c0,Ba.y.c1,Ca.x,Ca.y,in0,in1].map(red);
const seamCommit=commitBin(seam);
const aF=(x,y)=>(x+y)%P,sF=(x,y)=>(x-y+P)%P,mF=(x,y)=>(x*y)%P,qF=(x)=>(x*x)%P;
function jacDouble(X,Y,Z){const a=qF(X),b=qF(Y),c=qF(b);const d=mF(2n,sF(sF(qF(aF(X,b)),a),c));const e=mF(3n,a),f=qF(e);const nx=sF(f,mF(2n,d));return[nx,sF(mF(e,sF(d,nx)),mF(8n,c)),mF(2n,mF(Y,Z))];}
function jacAdd(aX,aY,aZ,bX,bY,bZ){if(aZ===0n)return[bX,bY,bZ];const z1=qF(aZ),z2=qF(bZ);const u1=mF(aX,z2),u2=mF(bX,z1);const s1=mF(mF(aY,bZ),z2),s2=mF(mF(bY,aZ),z1);if(u1===u2&&s1===s2)return jacDouble(aX,aY,aZ);const h=sF(u2,u1),i2=qF(mF(2n,h)),j=mF(h,i2),rr=mF(2n,sF(s2,s1)),v=mF(u1,i2);const nx=sF(sF(qF(rr),j),mF(2n,v));return[nx,sF(mF(rr,sF(v,nx)),mF(2n,mF(s1,j))),mF(sF(sF(qF(aF(aZ,bZ)),z1),z2),h)];}
const added=(i,I0,I1)=>{const b0=(I0>>BigInt(i))&1n,b1=(I1>>BigInt(i))&1n;if(b0&&b1)return[Ta.x,Ta.y];if(b0)return[ic1.x,ic1.y];if(b1)return[ic2.x,ic2.y];return null;};
function runWindow(lo,hi,rX,rY,rZ,I0,I1){for(let j=lo;j<hi;j++){const i=253-j;if(rZ!==0n)[rX,rY,rZ]=jacDouble(rX,rY,rZ);const ap=added(i,I0,I1);if(ap)[rX,rY,rZ]=jacAdd(rX,rY,rZ,ap[0],ap[1],1n);}return[rX,rY,rZ];}
const N=8, Pstr=P.toString();
const L=[];
L.push('pragma cashscript ^0.14.0;');
L.push(`function addFp(int x,int y) returns(int){return (x+y)%${Pstr};}`);
L.push(`function subFp(int x,int y) returns(int){return (x-y+${Pstr})%${Pstr};}`);
L.push(`function mulFp(int x,int y) returns(int){return (x*y)%${Pstr};}`);
L.push(`function sqrFp(int x) returns(int){return (x*x)%${Pstr};}`);
L.push(`function jacDouble(int x,int y,int z) returns(int,int,int){int a=sqrFp(x);int b=sqrFp(y);int c=sqrFp(b);int d=mulFp(2,subFp(subFp(sqrFp(addFp(x,b)),a),c));int e=mulFp(3,a);int f=sqrFp(e);int nx=subFp(f,mulFp(2,d));int ny=subFp(mulFp(e,subFp(d,nx)),mulFp(8,c));int nz=mulFp(2,mulFp(y,z));return nx,ny,nz;}`);
L.push(`function jacAdd(int aX,int aY,int aZ,int bX,int bY,int bZ) returns(int,int,int){int rx=bX;int ry=bY;int rz=bZ;if(aZ!=0){int z1=sqrFp(aZ);int z2=sqrFp(bZ);int u1=mulFp(aX,z2);int u2=mulFp(bX,z1);int s1=mulFp(mulFp(aY,bZ),z2);int s2=mulFp(mulFp(bY,aZ),z1);int h=subFp(u2,u1);int i2=sqrFp(mulFp(2,h));int jj=mulFp(h,i2);int rr=mulFp(2,subFp(s2,s1));int vv=mulFp(u1,i2);int anx=subFp(subFp(sqrFp(rr),jj),mulFp(2,vv));int any=subFp(mulFp(rr,subFp(vv,anx)),mulFp(2,mulFp(s1,jj)));int anz=mulFp(subFp(subFp(sqrFp(addFp(aZ,bZ)),z1),z2),h);rx=anx;ry=any;rz=anz;}return rx,ry,rz;}`);
L.push(`function selectPoint(int b0,int b1) returns(int,int,int){int aX=0;int aY=0;int doAdd=0;if(b0==1&&b1==1){aX=${Ta.x};aY=${Ta.y};doAdd=1;}else{if(b0==1){aX=${ic1.x};aY=${ic1.y};doAdd=1;}else{if(b1==1){aX=${ic2.x};aY=${ic2.y};doAdd=1;}}}return aX,aY,doAdd;}`);
L.push('contract VkxGenesisReloc(){');
L.push('    function spend(int nAx,int nAy,int Bxa,int Bxb,int Bya,int Byb,int Cx,int Cy,int input0,int input1,bytes unused zeroPadding){');
L.push(`        require(tx.inputs[this.activeInputIndex].nftCommitment == hash256(${['nAx','nAy','Bxa','Bxb','Bya','Byb','Cx','Cy','input0','input1'].map(n=>`toPaddedBytes(${n}, 40)`).join(' + ')}));`);
L.push('        int rX = 0; int rY = 1; int rZ = 0;');
L.push(`        for (int k = 0; k < ${N}; k = k + 1) {`);
L.push(`            int i = 253 - k;`);
L.push('            if (rZ != 0) { (int dx,int dy,int dz) = jacDouble(rX,rY,rZ); rX=dx; rY=dy; rZ=dz; }');
L.push('            int b0 = (input0 >> i) % 2; int b1 = (input1 >> i) % 2;');
L.push('            (int aX,int aY,int doAdd) = selectPoint(b0,b1);');
L.push('            if (doAdd == 1) { (int ax,int ay,int az)=jacAdd(rX,rY,rZ,aX,aY,1); rX=ax; rY=ay; rZ=az; }');
L.push('        }');
L.push(`        int Pmod = ${Pstr};`);
const outNames=['rX','rY','rZ','input0','input1','nAx','nAy','Bxa','Bxb','Bya','Byb','Cx','Cy'];
L.push(`        require(tx.outputs[0].nftCommitment == hash256(${outNames.map(n=>`toPaddedBytes(${n} % Pmod, 40)`).join(' + ')}));`);
L.push('        require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);');
L.push('    }');
L.push('}');
const probe=join(GEN,'_probe_vkxcanon2.cash'); writeFileSync(probe,L.join('\n')+'\n');
const redeem=Uint8Array.from([...compileFileBytecode(probe)]);
const rpush=encodeDataPush(redeem);
const locking=encodeLockingBytecodeP2sh32(hash256(redeem));
const tok=(cm)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:cm}});
const padBytes=(total)=>{const b=Math.max(2,total);const n=b<=76?b-1:b<=257?b-2:b-3;return encodeDataPush(new Uint8Array(n));};
function buildProg(inCommit,in0v,in1v,outCommit){
  const committed=[negA.x,negA.y,Ba.x.c0,Ba.x.c1,Ba.y.c0,Ba.y.c1,Ca.x,Ca.y].map(red).concat([in0v,in1v]);
  const argb=Uint8Array.from([...committed].reverse().flatMap((v)=>[...pushInt(v)]));
  const tail=rpush.length;
  const unlocking=Uint8Array.from([...padBytes(TARGET_UNLOCK-argb.length-tail),...argb,...rpush]);
  return {inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
    transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],
    outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(outCommit)}],locktime:0}};
}
function runLA(p){const st=realVm.evaluate(p);const t=st.stack[st.stack.length-1];return {accepted:st.error===undefined&&st.stack.length===1&&t?.length===1&&t[0]===1,op:st.metrics.operationCost,err:st.error??null};}
const [oX,oY,oZ]=runWindow(0,N,0n,1n,0n,in0,in1);
const canonOut=commitBin([oX,oY,oZ,in0,in1,negA.x,negA.y,Ba.x.c0,Ba.x.c1,Ba.y.c0,Ba.y.c1,Ca.x,Ca.y].map(red));
const rawLimbs=[negA.x,negA.y,Ba.x.c0,Ba.x.c1,Ba.y.c0,Ba.y.c1,Ca.x,Ca.y].map(red).concat([in0+P,in1]);
const craftedCommit=commitBufs(rawLimbs.map(le40));
const [gX,gY,gZ]=runWindow(0,N,0n,1n,0n,in0+P,in1);
const divergentOut=commitBin([gX,gY,gZ,red(in0+P),in1,negA.x,negA.y,Ba.x.c0,Ba.x.c1,Ba.y.c0,Ba.y.c1,Ca.x,Ca.y].map(red));

const which=process.env.VCASE;
const cases={
  A_realseam_reject: buildProg(seamCommit,in0+P,in1,canonOut),
  B_crafted_accept:  buildProg(craftedCommit,in0+P,in1,divergentOut),
};
for(const [name,p] of Object.entries(cases)){
  if(which && name!==which) continue;
  const r=runLA(p);
  if(which){ writeFileSync('/tmp/xcheck_tx.hex',binToHex(encodeTransaction(p.transaction)));
    writeFileSync('/tmp/xcheck_srcouts.hex',binToHex(encodeTransactionOutputs(p.sourceOutputs))); }
  console.log(`[${name}] libauth accepted=${r.accepted} op=${r.op} err=${r.err}`);
}
