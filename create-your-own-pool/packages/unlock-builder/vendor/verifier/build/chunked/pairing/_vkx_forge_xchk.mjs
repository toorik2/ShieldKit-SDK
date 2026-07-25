// Export selected vkx forgery cases to wire hex for LeanBCH cross-check.
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bn254, vec, proof, commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecodeRaw, decl, covIn, covOut } from './_millermath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, binToHex, encodeTransaction, encodeTransactionOutputs } from '@bitauth/libauth';
const here=dirname(fileURLToPath(import.meta.url)), GEN=join(here,'generated');
const realVm=createVirtualMachineBch2026(false);
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n, Pstr=P.toString();
const red=(x)=>((BigInt(x)%P)+P)%P;
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush=(a,t)=>Uint8Array.from([0x4d,...numberToBinUint16LE(t-a-3),...new Uint8Array(t-a-3)]);
const tok=(cm)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:cm}});
const modpow=(b,e,m)=>{let r=1n;b%=m;while(e>0n){if(e&1n)r=(r*b)%m;b=(b*b)%m;e>>=1n;}return r;};
const g1=(o)=>bn254.G1.Point.fromAffine({x:BigInt(o.x),y:BigInt(o.y)});
const IC=vec.vk.ic.map(g1);
const ic0=IC[0].toAffine(),ic1=IC[1].toAffine(),ic2=IC[2].toAffine(),Ta=IC[1].add(IC[2]).toAffine();
const IC0=[ic0.x,ic0.y],IC1=[ic1.x,ic1.y],IC2=[ic2.x,ic2.y],T=[Ta.x,Ta.y];
const inputs=vec.publicInputs.map(BigInt), in0=inputs[0], in1=inputs[1];
const negA=proof.a.negate().toAffine(), Ba=proof.b.toAffine(), Ca=proof.c.toAffine();
const nAx=red(negA.x),nAy=red(negA.y),Bxa=red(Ba.x.c0),Bxb=red(Ba.x.c1),Bya=red(Ba.y.c0),Byb=red(Ba.y.c1),Cx=red(Ca.x),Cy=red(Ca.y);
const aF=(x,y)=>(x+y)%P,sF=(x,y)=>(x-y+P)%P,mF=(x,y)=>(x*y)%P,qF=(x)=>(x*x)%P;
function jDbl(X,Y,Z){const a=qF(X),b=qF(Y),c=qF(b);const d=mF(2n,sF(sF(qF(aF(X,b)),a),c));const e=mF(3n,a),f=qF(e);const nx=sF(f,mF(2n,d));return[nx,sF(mF(e,sF(d,nx)),mF(8n,c)),mF(2n,mF(Y,Z))];}
function jAdd(aX,aY,aZ,bX,bY,bZ){if(aZ===0n)return[bX,bY,bZ];const z1=qF(aZ),z2=qF(bZ);const u1=mF(aX,z2),u2=mF(bX,z1);const s1=mF(mF(aY,bZ),z2),s2=mF(mF(bY,aZ),z1);if(u1===u2&&s1===s2)return jDbl(aX,aY,aZ);const h=sF(u2,u1),i2=qF(mF(2n,h)),j=mF(h,i2),rr=mF(2n,sF(s2,s1)),v=mF(u1,i2);const nx=sF(sF(qF(rr),j),mF(2n,v));return[nx,sF(mF(rr,sF(v,nx)),mF(2n,mF(s1,j))),mF(sF(sF(qF(aF(aZ,bZ)),z1),z2),h)];}
const addedPt=(i)=>{const b0=(in0>>BigInt(i))&1n,b1=(in1>>BigInt(i))&1n;if(b0&&b1)return T;if(b0)return IC1;if(b1)return IC2;return null;};
function vkxWindow(lo,hi,rX,rY,rZ){for(let j=lo;j<hi;j++){const i=253-j;if(rZ!==0n)[rX,rY,rZ]=jDbl(rX,rY,rZ);const ap=addedPt(i);if(ap)[rX,rY,rZ]=jAdd(rX,rY,rZ,ap[0],ap[1],1n);}return[rX,rY,rZ];}
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
  L.push(`        for (int k = 0; k < ${count}; k = k + 1) {`);L.push(`            int i = ${hiBit} - k;`);
  L.push('            if (rZ != 0) { (int dx,int dy,int dz) = jacDouble(rX,rY,rZ); rX=dx; rY=dy; rZ=dz; }');
  L.push('            int b0 = (input0 >> i) % 2; int b1 = (input1 >> i) % 2;');
  L.push('            (int aX,int aY,int doAdd) = selectPoint(b0,b1);');
  L.push('            if (doAdd == 1) { (int ax,int ay,int az)=jacAdd(rX,rY,rZ,aX,aY,1); rX=ax; rY=ay; rZ=az; }');
  L.push('        }');
  if(isFinal){
    L.push(`        (int icx,int icy,int icz) = jacAdd(rX,rY,rZ,${IC0[0]},${IC0[1]},1);`);
    L.push('        require(mulFp(icz, zInv) == 1);');
    L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
    L.push('        int vkxX = mulFp(icx, zInv2); int vkxY = mulFp(icy, zInv3);');
    L.push(covOut(SEAM2));
  } else L.push(covOut(VKST));
  L.push('    }');L.push('}');return L.join('\n')+'\n';
}
function buildProgram(name,src,inCommit,pushedArgs,outCommit){
  const probe=join(GEN,`_xf_${name}.cash`); writeFileSync(probe,src);
  const raw=compileFileBytecodeRaw(probe);
  const locking=Uint8Array.from([...raw]);
  const argBytes=Uint8Array.from([...pushedArgs].reverse().flatMap((v)=>[...pushInt(v)]));
  const unlocking=Uint8Array.from([...padPush(argBytes.length,TARGET_UNLOCK),...argBytes]);
  const outputs = outCommit===null?[{lockingBytecode:locking,valueSatoshis:1000n}]:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(outCommit)}];
  const program={inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
    transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],outputs,locktime:0}};
  const st=realVm.evaluate(program);
  const top=st.stack[st.stack.length-1];
  const accepted=st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1;
  return {program,accepted,op:st.metrics.operationCost,error:st.error??null};
}
const cases={};
// case A: genesis honest (accept)
{ const src=vkxChunk(0,37,true,false); const inCommit=commitBin([nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1].map(red));
  const [rx,ry,rz]=vkxWindow(0,37,0n,1n,0n); const outCommit=commitBin([rx,ry,rz,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red));
  cases['A_genesis_honest']=buildProgram('A',src,inCommit,[0n,1n,0n,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy],outCommit); }
// case B: genesis evil-acc (reject)
{ const src=vkxChunk(0,37,true,false); const inCommit=commitBin([nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy,in0,in1].map(red));
  const [rx,ry,rz]=vkxWindow(0,37,red(IC1[0]),red(IC1[1]),1n); const outCommit=commitBin([rx,ry,rz,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red));
  cases['B_genesis_evilacc']=buildProgram('B',src,inCommit,[red(IC1[0]),red(IC1[1]),1n,in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy],outCommit); }
// case C: final wrong-zInv (reject)
const accBefore=vkxWindow(0,253,0n,1n,0n);
{ const src=vkxChunk(253,254,false,true); const inState=[red(accBefore[0]),red(accBefore[1]),red(accBefore[2]),in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy]; const inCommit=commitBin(inState);
  const [rx,ry,rz]=vkxWindow(253,254,accBefore[0],accBefore[1],accBefore[2]); const [fx,fy,fz]=jAdd(rx,ry,rz,IC0[0],IC0[1],1n); const zInv=modpow(fz,P-2n,P); const evilZ=(zInv+1n)%P;
  const zi2=(evilZ*evilZ)%P; const vkxX=red(fx*zi2%P),vkxY=red(fy*(zi2*evilZ%P)%P); const outCommit=commitBin([nAx,nAy,Bxa,Bxb,Bya,Byb,vkxX,vkxY,Cx,Cy].map(red));
  cases['C_final_evilz']=buildProgram('C',src,inCommit,[...inState,evilZ],outCommit); }
// case D: interior injection (accepts - anchor dependent)
{ const src=vkxChunk(37,73,false,false); const evilAcc=[red(12345678901234567890n),red(98765432109876543210n),1n]; const inState=[evilAcc[0],evilAcc[1],evilAcc[2],in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy]; const inCommit=commitBin(inState);
  const [rx,ry,rz]=vkxWindow(37,73,evilAcc[0],evilAcc[1],evilAcc[2]); const outCommit=commitBin([red(rx),red(ry),red(rz),in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red));
  cases['D_interior_evilacc']=buildProgram('D',src,inCommit,inState,outCommit); }

const which=process.env.CASE;
if(which){ const c=cases[which]; const txHex=binToHex(encodeTransaction(c.program.transaction)); const soHex=binToHex(encodeTransactionOutputs(c.program.sourceOutputs));
  writeFileSync('/tmp/xcheck_tx.hex',txHex); writeFileSync('/tmp/xcheck_srcouts.hex',soHex);
  console.log(`CASE ${which}: libauthAccept=${c.accepted} op=${c.op} err=${c.error??''} -> wrote /tmp/xcheck_tx.hex (${txHex.length/2}B) srcouts(${soHex.length/2}B)`); }
else { for(const[k,c]of Object.entries(cases)) console.log(`${k.padEnd(22)} libauthAccept=${c.accepted} op=${c.op} err=${c.error??''}`); }

// ALL-export mode
if(process.env.ALL){ for(const[k,c]of Object.entries(cases)){ const txHex=binToHex(encodeTransaction(c.program.transaction)); const soHex=binToHex(encodeTransactionOutputs(c.program.sourceOutputs));
  writeFileSync(`/tmp/xchk_${k}_tx.hex`,txHex); writeFileSync(`/tmp/xchk_${k}_srcouts.hex`,soHex);
  console.log(`${k}: libauthAccept=${c.accepted}`);} }

// ---- case E: WINDOW-REORDER/SKIP. Feed honest genesis[0,37) output (a genuinely reachable
// accumulator) into the [73,109) chunk (skipping [37,73)). If accepted, the covenant does NOT
// self-bind window position => wrong MSM is computable within a single anchored token thread.
if(process.env.CASE_E){
  const acc37=vkxWindow(0,37,0n,1n,0n).map(red);          // real reachable state after window 0
  const src=vkxChunk(73,109,false,false);                 // the [73,109) window script (skips [37,73))
  const inState=[acc37[0],acc37[1],acc37[2],in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy];
  const inCommit=commitBin(inState);                       // == honest genesis covOut (same VKST shape)
  const [rx,ry,rz]=vkxWindow(73,109,acc37[0],acc37[1],acc37[2]);
  const outCommit=commitBin([red(rx),red(ry),red(rz),in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy].map(red));
  const c=buildProgram('E',src,inCommit,inState,outCommit);
  // sanity: is this genesis covOut == the honest [37,73) covIn (what SHOULD be next)?
  const honestNext=commitBin([acc37[0],acc37[1],acc37[2],in0,in1,nAx,nAy,Bxa,Bxb,Bya,Byb,Cx,Cy]);
  console.log('E_reorder_skip: libauthAccept='+c.accepted+' op='+c.op+' err='+(c.error??''));
  console.log('  genesis covOut(acc37) == wrong-window[73,109) covIn (hash match) =>', binToHex(inCommit)===binToHex(honestNext));
  const txHex=binToHex(encodeTransaction(c.program.transaction)); const soHex=binToHex(encodeTransactionOutputs(c.program.sourceOutputs));
  writeFileSync('/tmp/xchk_E_reorder_tx.hex',txHex); writeFileSync('/tmp/xchk_E_reorder_srcouts.hex',soHex);
}
