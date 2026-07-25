// ADVERSARIAL: attack vkx-msm-binding. Reconstructs the UNIFIED vkx genesis/interior/final
// chunks (byte-matching unified_fullverifier.mjs) and runs forgeries on the real libauth VM.
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bn254, vec, proof, commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecodeRaw, decl, covIn, covOut } from './_millermath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, binToHex } from '@bitauth/libauth';
const here=dirname(fileURLToPath(import.meta.url)), GEN=join(here,'generated');
const realVm=createVirtualMachineBch2026(false);
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n, Pstr=P.toString();
const red=(x)=>((BigInt(x)%P)+P)%P;
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush=(a,t)=>Uint8Array.from([0x4d,...numberToBinUint16LE(t-a-3),...new Uint8Array(t-a-3)]);
const tok=(cm)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:cm}});
const modpow=(b,e,m)=>{let r=1n;b%=m;while(e>0n){if(e&1n)r=(r*b)%m;b=(b*b)%m;e>>=1n;}return r;};

// instance
const g1=(o)=>bn254.G1.Point.fromAffine({x:BigInt(o.x),y:BigInt(o.y)});
const IC=vec.vk.ic.map(g1);
const ic0=IC[0].toAffine(),ic1=IC[1].toAffine(),ic2=IC[2].toAffine(),Ta=IC[1].add(IC[2]).toAffine();
const IC0=[ic0.x,ic0.y],IC1=[ic1.x,ic1.y],IC2=[ic2.x,ic2.y],T=[Ta.x,Ta.y];
const inputs=vec.publicInputs.map(BigInt), in0=inputs[0], in1=inputs[1];
const negA=proof.a.negate().toAffine(), Ba=proof.b.toAffine(), Ca=proof.c.toAffine();
const nAx=red(negA.x),nAy=red(negA.y),Bxa=red(Ba.x.c0),Bxb=red(Ba.x.c1),Bya=red(Ba.y.c0),Byb=red(Ba.y.c1),Cx=red(Ca.x),Cy=red(Ca.y);

// reference jacobian (matches unified jDbl/jAdd)
const aF=(x,y)=>(x+y)%P,sF=(x,y)=>(x-y+P)%P,mF=(x,y)=>(x*y)%P,qF=(x)=>(x*x)%P;
function jDbl(X,Y,Z){const a=qF(X),b=qF(Y),c=qF(b);const d=mF(2n,sF(sF(qF(aF(X,b)),a),c));const e=mF(3n,a),f=qF(e);const nx=sF(f,mF(2n,d));return[nx,sF(mF(e,sF(d,nx)),mF(8n,c)),mF(2n,mF(Y,Z))];}
function jAdd(aX,aY,aZ,bX,bY,bZ){if(aZ===0n)return[bX,bY,bZ];const z1=qF(aZ),z2=qF(bZ);const u1=mF(aX,z2),u2=mF(bX,z1);const s1=mF(mF(aY,bZ),z2),s2=mF(mF(bY,aZ),z1);if(u1===u2&&s1===s2)return jDbl(aX,aY,aZ);const h=sF(u2,u1),i2=qF(mF(2n,h)),j=mF(h,i2),rr=mF(2n,sF(s2,s1)),v=mF(u1,i2);const nx=sF(sF(qF(rr),j),mF(2n,v));return[nx,sF(mF(rr,sF(v,nx)),mF(2n,mF(s1,j))),mF(sF(sF(qF(aF(aZ,bZ)),z1),z2),h)];}
const addedPt=(i)=>{const b0=(in0>>BigInt(i))&1n,b1=(in1>>BigInt(i))&1n;if(b0&&b1)return T;if(b0)return IC1;if(b1)return IC2;return null;};
function vkxWindow(lo,hi,rX,rY,rZ){for(let j=lo;j<hi;j++){const i=253-j;if(rZ!==0n)[rX,rY,rZ]=jDbl(rX,rY,rZ);const ap=addedPt(i);if(ap)[rX,rY,rZ]=jAdd(rX,rY,rZ,ap[0],ap[1],1n);}return[rX,rY,rZ];}

// unified vkx chunk generator (copied from unified_fullverifier.mjs)
const vkxPrologue=`function addFp(int x,int y) returns(int){return (x+y)%${Pstr};}
function subFp(int x,int y) returns(int){return (x-y+${Pstr})%${Pstr};}
function mulFp(int x,int y) returns(int){return (x*y)%${Pstr};}
function sqrFp(int x) returns(int){return (x*x)%${Pstr};}
function jacDouble(int x,int y,int z) returns(int,int,int){int a=sqrFp(x);int b=sqrFp(y);int c=sqrFp(b);int d=mulFp(2,subFp(subFp(sqrFp(addFp(x,b)),a),c));int e=mulFp(3,a);int f=sqrFp(e);int nx=subFp(f,mulFp(2,d));int ny=subFp(mulFp(e,subFp(d,nx)),mulFp(8,c));int nz=mulFp(2,mulFp(y,z));return nx,ny,nz;}
function jacAdd(int aX,int aY,int aZ,int bX,int bY,int bZ) returns(int,int,int){int rx=bX;int ry=bY;int rz=bZ;if(aZ!=0){int z1=sqrFp(aZ);int z2=sqrFp(bZ);int u1=mulFp(aX,z2);int u2=mulFp(bX,z1);int s1=mulFp(mulFp(aY,bZ),z2);int s2=mulFp(mulFp(bY,aZ),z1);if(u1==u2&&s1==s2){int da=sqrFp(aX);int db=sqrFp(aY);int dc=sqrFp(db);int dd=mulFp(2,subFp(subFp(sqrFp(addFp(aX,db)),da),dc));int de=mulFp(3,da);int df=sqrFp(de);int dnx=subFp(df,mulFp(2,dd));int dny=subFp(mulFp(de,subFp(dd,dnx)),mulFp(8,dc));int dnz=mulFp(2,mulFp(aY,aZ));rx=dnx;ry=dny;rz=dnz;}else{int h=subFp(u2,u1);int i2=sqrFp(mulFp(2,h));int jj=mulFp(h,i2);int rr=mulFp(2,subFp(s2,s1));int vv=mulFp(u1,i2);int anx=subFp(subFp(sqrFp(rr),jj),mulFp(2,vv));int any=subFp(mulFp(rr,subFp(vv,anx)),mulFp(2,mulFp(s1,jj)));int anz=mulFp(subFp(subFp(sqrFp(addFp(aZ,bZ)),z1),z2),h);rx=anx;ry=any;rz=anz;}}return rx,ry,rz;}
function selectPoint(int b0,int b1) returns(int,int,int){int aX=0;int aY=0;int doAdd=0;if(b0==1&&b1==1){aX=${T[0]};aY=${T[1]};doAdd=1;}else{if(b0==1){aX=${IC1[0]};aY=${IC1[1]};doAdd=1;}else{if(b1==1){aX=${IC2[0]};aY=${IC2[1]};doAdd=1;}}}return aX,aY,doAdd;}`;
const BNM=['Bxa','Bxb','Bya','Byb'];
const VKST=['rX','rY','rZ','input0','input1','nAx','nAy',...BNM,'Cx','Cy'];
const SEAM1=['nAx','nAy',...BNM,'Cx','Cy','input0','input1'];
const SEAM2=['nAx','nAy',...BNM,'vkxX','vkxY','Cx','Cy'];
function vkxChunk(lo,hi,isGenesis,isFinal){
  const count=hi-lo,hiBit=253-lo;const L=[];
  L.push('pragma cashscript ^0.14.0;');L.push(vkxPrologue);L.push('contract VkxU() {');
  L.push(`    function spend(${decl(VKST)}${isFinal?', int zInv':''}, bytes unused zeroPadding) {`);
  if(isGenesis){L.push(covIn(SEAM1));L.push('        require(rX == 0); require(rY == 1); require(rZ == 0);');}
  else L.push(covIn(VKST));
  L.push(`        for (int k = 0; k < ${count}; k = k + 1) {`);
  L.push(`            int i = ${hiBit} - k;`);
  L.push('            if (rZ != 0) { (int dx,int dy,int dz) = jacDouble(rX,rY,rZ); rX=dx; rY=dy; rZ=dz; }');
  L.push('            int b0 = (input0 >> i) % 2; int b1 = (input1 >> i) % 2;');
  L.push('            (int aX,int aY,int doAdd) = selectPoint(b0,b1);');
  L.push('            if (doAdd == 1) { (int ax,int ay,int az)=jacAdd(rX,rY,rZ,aX,aY,1); rX=ax; rY=ay; rZ=az; }');
  L.push('        }');
  if(isFinal){
    L.push(`        (int icx,int icy,int icz) = jacAdd(rX,rY,rZ,${IC0[0]},${IC0[1]},1);`);
    L.push('        require(mulFp(icz, zInv) == 1);');
    L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
    L.push('        int vkxX = mulFp(icx, zInv2);');
    L.push('        int vkxY = mulFp(icy, zInv3);');
    L.push(covOut(SEAM2));
  } else L.push(covOut(VKST));
  L.push('    }');L.push('}');return L.join('\n')+'\n';
}

function runChunk(name,src,inCommit,pushedArgs,outCommit){
  const probe=join(GEN,`_forge_${name}.cash`); writeFileSync(probe,src);
  let raw; try{raw=compileFileBytecodeRaw(probe);}catch(e){return {accepted:false,error:'COMPILE:'+e.message};}
  const locking=Uint8Array.from([...raw]);
  const argBytes=Uint8Array.from([...pushedArgs].reverse().flatMap((v)=>[...pushInt(v)]));
  const unlocking=Uint8Array.from([...padPush(argBytes.length,TARGET_UNLOCK),...argBytes]);
  const outputs = outCommit===null ? [{lockingBytecode:locking,valueSatoshis:1000n}] : [{lockingBytecode:locking,valueSatoshis:1000n,token:tok(outCommit)}];
  const st=realVm.evaluate({inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
    transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],outputs,locktime:0}});
  const top=st.stack[st.stack.length-1];
  const accepted=st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1;
  return {accepted,op:st.metrics.operationCost,error:st.error??null,locking,unlocking};
}

console.log('=== instance: in0='+in0+' in1='+in1+' ===');

// ---------- BASELINE genesis (honest) ----------
{
  const src=vkxChunk(0,37,true,false);
  const seam1=[nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1].map(red);
  const inCommit=commitBin(seam1);
  const [rx,ry,rz]=vkxWindow(0,37,0n,1n,0n);
  const outLimbs=[rx,ry,rz,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red);
  const outCommit=commitBin(outLimbs);
  // pushed args (decl order VKST): rX=0,rY=1,rZ=0,input0,input1,nAx,...
  const push=[0n,1n,0n,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const r=runChunk('genesis_honest',src,inCommit,push,outCommit);
  console.log('[GENESIS honest]      accept=',r.accepted,'op=',r.op,'err=',r.error);
}

// ---------- ATTACK 1: inject nonzero accumulator at genesis ----------
{
  const src=vkxChunk(0,37,true,false);
  const seam1=[nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1].map(red);
  const inCommit=commitBin(seam1);
  // attacker biases start accumulator: push rX=IC1x,rY=IC1y,rZ=1 (a valid point) hoping vk_x shifts
  const evilRX=red(IC1[0]),evilRY=red(IC1[1]),evilRZ=1n;
  const [rx,ry,rz]=vkxWindow(0,37,evilRX,evilRY,evilRZ);
  const outLimbs=[rx,ry,rz,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red);
  const outCommit=commitBin(outLimbs);
  const push=[evilRX,evilRY,evilRZ,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const r=runChunk('genesis_evilacc',src,inCommit,push,outCommit);
  console.log('[ATTACK1 evil-acc]    accept=',r.accepted,'op=',r.op,'err=',String(r.error).slice(0,60),'  (want REJECT)');
}

// ---------- ATTACK 5: non-canonical input0 at genesis (input0+P) ----------
{
  const src=vkxChunk(0,37,true,false);
  const seam1=[nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1].map(red);
  const inCommit=commitBin(seam1); // commits reduced in0
  const evilIn0=in0+P; // non-canonical rep of same residue
  const [rx,ry,rz]=vkxWindow(0,37,0n,1n,0n);
  const outLimbs=[rx,ry,rz,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red);
  const outCommit=commitBin(outLimbs);
  const push=[0n,1n,0n,evilIn0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const r=runChunk('genesis_noncanon_in0',src,inCommit,push,outCommit);
  console.log('[ATTACK5 in0+P]       accept=',r.accepted,'op=',r.op,'err=',String(r.error).slice(0,60),'  (want REJECT)');
}

// ---------- FINAL chunk baseline (honest) ----------
// incoming accumulator = vkxWindow(0,253,inf); final window [253,254)
const accBefore=vkxWindow(0,253,0n,1n,0n);
{
  const src=vkxChunk(253,254,false,true);
  const inState=[red(accBefore[0]),red(accBefore[1]),red(accBefore[2]),in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const inCommit=commitBin(inState);
  const [rx,ry,rz]=vkxWindow(253,254,accBefore[0],accBefore[1],accBefore[2]);
  const [fx,fy,fz]=jAdd(rx,ry,rz,IC0[0],IC0[1],1n);
  const zInv=modpow(fz,P-2n,P);
  const zi2=(zInv*zInv)%P, vkxX=red(fx*zi2%P), vkxY=red(fy*(zi2*zInv%P)%P);
  const outLimbs=[nAx,nAy,Bxa,Bxb,Bya,Byb,vkxX,vkxY,Cx,Cy].map(red);
  const outCommit=commitBin(outLimbs);
  const push=[...inState,zInv];
  const r=runChunk('final_honest',src,inCommit,push,outCommit);
  console.log('[FINAL honest]        accept=',r.accepted,'op=',r.op,'err=',r.error,' vkxX matches true=',vkxX===red(8849706566265323475308844786466876320844339848804625399173904868893806414653n));
}

// ---------- ATTACK 3: wrong zInv on final ----------
{
  const src=vkxChunk(253,254,false,true);
  const inState=[red(accBefore[0]),red(accBefore[1]),red(accBefore[2]),in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const inCommit=commitBin(inState);
  const [rx,ry,rz]=vkxWindow(253,254,accBefore[0],accBefore[1],accBefore[2]);
  const [fx,fy,fz]=jAdd(rx,ry,rz,IC0[0],IC0[1],1n);
  const zInv=modpow(fz,P-2n,P);
  const evilZ=(zInv+1n)%P; // wrong inverse
  // compute what vkx the wrong z produces, commit THAT (so covOut would match if gate passed)
  const zi2=(evilZ*evilZ)%P, vkxX=red(fx*zi2%P), vkxY=red(fy*(zi2*evilZ%P)%P);
  const outLimbs=[nAx,nAy,Bxa,Bxb,Bya,Byb,vkxX,vkxY,Cx,Cy].map(red);
  const outCommit=commitBin(outLimbs);
  const push=[...inState,evilZ];
  const r=runChunk('final_evilz',src,inCommit,push,outCommit);
  console.log('[ATTACK3 wrong-zInv]  accept=',r.accepted,'op=',r.op,'err=',String(r.error).slice(0,60),'  (want REJECT: gate mulFp(icz,zInv)==1)');
}

// ---------- ATTACK 4: force a WRONG vk_x committed (different point) ----------
{
  const src=vkxChunk(253,254,false,true);
  const inState=[red(accBefore[0]),red(accBefore[1]),red(accBefore[2]),in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const inCommit=commitBin(inState);
  const [rx,ry,rz]=vkxWindow(253,254,accBefore[0],accBefore[1],accBefore[2]);
  const [fx,fy,fz]=jAdd(rx,ry,rz,IC0[0],IC0[1],1n);
  const zInv=modpow(fz,P-2n,P);
  // target a bogus vk_x = IC0 (wrong), commit it, use honest zInv -> covOut mismatch expected
  const bogusX=red(IC0[0]),bogusY=red(IC0[1]);
  const outLimbs=[nAx,nAy,Bxa,Bxb,Bya,Byb,bogusX,bogusY,Cx,Cy].map(red);
  const outCommit=commitBin(outLimbs);
  const push=[...inState,zInv];
  const r=runChunk('final_wrongvkx',src,inCommit,push,outCommit);
  console.log('[ATTACK4 wrong-vkx]   accept=',r.accepted,'op=',r.op,'err=',String(r.error).slice(0,60),'  (want REJECT: computed vkx != committed)');
}

// ---------- ATTACK 2: interior accumulator injection (chunk-level trust demo) ----------
{
  const src=vkxChunk(37,73,false,false); // an interior window
  // MALICIOUS accumulator: not the true partial MSM. Use an arbitrary valid-ish point rep.
  const evilAcc=[red(12345678901234567890n),red(98765432109876543210n),1n]; // arbitrary
  const inState=[evilAcc[0],evilAcc[1],evilAcc[2],in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const inCommit=commitBin(inState); // attacker-crafted spent token
  const [rx,ry,rz]=vkxWindow(37,73,evilAcc[0],evilAcc[1],evilAcc[2]);
  const outLimbs=[red(rx),red(ry),red(rz),in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red);
  const outCommit=commitBin(outLimbs);
  const push=inState;
  const r=runChunk('interior_evilacc',src,inCommit,push,outCommit);
  console.log('[ATTACK2 interior-inj] accept=',r.accepted,'op=',r.op,'err=',r.error,'  (ACCEPTS iff attacker can craft the spent token = anchor problem)');
}
