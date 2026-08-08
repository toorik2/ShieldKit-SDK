// UNIFIED single-scheme 28-chunk BN254 Groth16 verifier — freshly generate + MEASURE every
// chunk under the deployed buildCovStep byte convention (P2SH redeem-in-scriptSig + state-arg
// pushes + tuned zero pad, RESCHEDULED cashc compile). ALL 28 chunks use ONE generic hash256
// covenant chain (covIn/covOut = commitBin = sha256d over 40-byte LE mod-p limbs), threaded
// cross-stage: g2check(4) -> vkx(8) -> miller(15..) -> tail(1), with relocation-genesis seam
// chunks at each stage boundary. Verifies covOut[i]==covIn[i+1] for EVERY boundary + all accept.
//   node unified_fullverifier.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, vec, proof, vkxPoint, commitBin, CATEGORY, TARGET_UNLOCK, decl, covIn, covOut,
  compileFileBytecode, pairsFor, millerBatchOps,
} from './_millermath.mjs';
import { g2checkAccAt, g2checkFastZinv, G2CHECK_NBITS } from './gen_g2check.mjs';
import {
  genChunk as millerGenChunk, ops as millerOps, inState as millerInState,
  outState as millerOutState, states as millerStates,
} from './gen_miller_residue.mjs';
import { residueWitness, millerFusedOps, fp12limbsOf, COSET27 } from './_residuemath.mjs';
import {
  binToHex, bigIntToVmNumber, encodeDataPush, hash256,
  encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
  encodeTransaction, encodeTransactionOutputs,
} from '@bitauth/libauth';
const XCHUNKS = (process.env.XCHUNK ?? '').split(',').map((s) => s.trim()).filter(Boolean); // names to export
const XTAMPER = process.env.XTAMPER === '1'; // corrupt the input NFT commitment (expect BOTH VMs reject)
const xexports = [];

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr = P.toString();
const red = (x) => ((BigInt(x) % P) + P) % P;
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);

// ---- buildCovStep P2SH byte-counter (byte-identical to v3_fullverifier.mjs) --------------------
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
function evalCov(locking, unlocking, inCommit, outCommit) {
  const outHasTok = outCommit !== null;
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, ...(outHasTok ? { token: tok(outCommit) } : {}) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}
// compile src (RESCHED, deployed convention), P2SH-wrap, binary-search minimal accepting unlock.
// committedIn/outLimbs = decl-order limbs; pushedArgs = full push list (committedIn + witnesses).
// outLimbs=null => terminal (output[0] carries no token).
function measureChunk(name, src, committedIn, pushedArgs, outLimbs) {
  const probe = join(GEN, `_u_${name}.cash`);
  writeFileSync(probe, src);
  let redeem;
  try { redeem = Uint8Array.from([...compileFileBytecode(probe)]); }
  catch (e) { return { fits: false, accepted: false, error: String(e?.message ?? e) }; }
  const rpush = encodeDataPush(redeem);
  const locking = p2shSpk(redeem);
  const tail = rpush.length;
  const inCommit = commitBin(committedIn.map(BigInt));
  const outCommit = outLimbs === null ? null : commitBin(outLimbs.map(BigInt));
  const argb = Uint8Array.from([...pushedArgs].reverse().flatMap((c) => [...pushInt(c)]));
  const mkUnlock = (target) => { const pad = padBytes(target - argb.length - tail); return Uint8Array.from([...pad, ...argb, ...rpush]); };
  const minU = argb.length + tail + 2;
  const hiUnlock = mkUnlock(TARGET_UNLOCK);
  const topProbe = evalCov(locking, hiUnlock, inCommit, outCommit);
  let target, real;
  if (!topProbe.accepted || hiUnlock.length > TARGET_UNLOCK) { target = TARGET_UNLOCK; real = topProbe; }
  else {
    let loU = minU, hiU = TARGET_UNLOCK;
    while (loU < hiU) { const mid = (loU + hiU) >> 1; const r = evalCov(locking, mkUnlock(mid), inCommit, outCommit); if (r.accepted) hiU = mid; else loU = mid + 1; }
    target = hiU; real = evalCov(locking, mkUnlock(target), inCommit, outCommit);
  }
  const unlocking = mkUnlock(target);
  // ---- LeanBCH wire-export hook: dump the EXACT measured tx (byte-identical to the accepting one)
  const xtag = XCHUNKS.find((x) => name === x); // EXACT chunk-name match (pass e.g. g2_0, vkx_0, ml_0_17, tail)
  if (xtag) {
    for (const tamper of (XTAMPER ? [false, true] : [false])) {
      let inCommitUse = inCommit;
      if (tamper) { inCommitUse = Uint8Array.from(inCommit); inCommitUse[0] ^= 0x01; } // corrupt spent-token commitment
      const outHasTok = outCommit !== null;
      const program = {
        inputIndex: 0,
        sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommitUse) }],
        transaction: {
          version: 2,
          inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
          outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, ...(outHasTok ? { token: tok(outCommit) } : {}) }],
          locktime: 0,
        },
      };
      const st = realVm.evaluate(program);
      const top = st.stack[st.stack.length - 1];
      const acc = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
      const suff = tamper ? '_tamper' : '';
      writeFileSync(`/tmp/xc_${xtag}${suff}_tx.hex`, binToHex(encodeTransaction(program.transaction)));
      writeFileSync(`/tmp/xc_${xtag}${suff}_srcouts.hex`, binToHex(encodeTransactionOutputs(program.sourceOutputs)));
      const rec = { chunk: name, tag: xtag, tamper, libauthAccepted: acc, libauthOpCost: st.metrics.operationCost, err: String(st.error ?? 'none'), lockingBytes: locking.length, unlockingBytes: unlocking.length };
      xexports.push(rec);
    }
  }
  return {
    fits: real.accepted && unlocking.length <= TARGET_UNLOCK && real.operationCost <= OP_TARGET,
    lockingBytes: locking.length, unlockingBytes: unlocking.length,
    operationCost: real.operationCost, accepted: real.accepted,
    inCommit: binToHex(inCommit), outCommit: outCommit ? binToHex(outCommit) : null,
    error: real.error,
  };
}

// ======================================================================================
// instance reference values
// ======================================================================================
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const negA = proof.a.negate().toAffine(), Baf = proof.b.toAffine(), Caf = proof.c.toAffine();
const nAx = red(negA.x), nAy = red(negA.y);
const Bxa = red(Baf.x.c0), Bxb = red(Baf.x.c1), Bya = red(Baf.y.c0), Byb = red(Baf.y.c1);
const Cx = red(Caf.x), Cy = red(Caf.y);
const inputs = vec.publicInputs.map(BigInt);
const in0 = inputs[0], in1 = inputs[1];
const vkxAff = vkxPoint(inputs).toAffine();
const vkxX = red(vkxAff.x), vkxY = red(vkxAff.y);
const BforG2 = [[Bxa, Bxb], [Bya, Byb]];

// ======================================================================================
// STAGE 1: g2check (4 chunks) — validate negA,C on G1, B on G2, subgroup([x0]B endo)
//   state (16): R(6) B(4) nAx nAy Cx Cy in0 in1 ; genesis pins R=(0,1,0); final emits SEAM1(10)
// ======================================================================================
const BN_X = 4965661367192848881n, NBITS = 63;
const g2bit = (k) => (BN_X >> BigInt(NBITS - 1 - k)) & 1n;
const B2 = [19485874751759354771024239261021720505790618469301721065564631296452457478373n,
            266929791119991161246907387137283842545076965332900288569378510910307636690n];
const G2LIB = '../../../singleton/bn254/lib/Miller.cash';
const RN = ['RXa', 'RXb', 'RYa', 'RYb', 'RZa', 'RZb'], BNM = ['Bxa', 'Bxb', 'Bya', 'Byb'];
const PASS = ['nAx', 'nAy', 'Cx', 'Cy', 'input0', 'input1'];
const G2ST = [...RN, ...BNM, ...PASS];            // 16 interior state names
const SEAM1 = ['nAx', 'nAy', ...BNM, 'Cx', 'Cy', 'input0', 'input1']; // 10 (negA,B,C,in0,in1)

function g2Chunk(lo, hi, isFirst, isLast) {
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${G2LIB}";`);
  L.push('contract G2CheckU() {');
  L.push(`    function spend(${decl(G2ST)}${isLast ? ', int zinvA, int zinvB' : ''}, bytes unused zeroPadding) {`);
  L.push(covIn(G2ST));                    // 16-limb state binds spent token
  if (isFirst) {
    // genesis: pin R = infinity (0,1,0); R is a param (no constant-folding) pinned by requires
    L.push('        require(RXa == 0); require(RXb == 0); require(RYa == 1); require(RYb == 0); require(RZa == 0); require(RZb == 0);');
    L.push('        require(mulFp(nAy, nAy) == addFp(mulFp(mulFp(nAx, nAx), nAx), 3));'); // negA on G1
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));');     // C on G1
    L.push('        (int oxa,int oxb) = fp2Sqr(Bxa, Bxb);');                              // B on G2
    L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
    L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
    L.push('        (int oba,int obb) = fp2Sqr(Bya, Byb);');
    L.push('        require(oba == ora); require(obb == orb);');
  }
  let r = RN.slice(), uid = 0;
  const fresh = () => Array.from({ length: 6 }, () => `v${uid++}`);
  for (let k = lo; k < hi; k++) {
    const d = fresh(); L.push(`        (${decl(d)}) = g2Double(${r.join(',')});`); r = d;
    if (g2bit(k)) { const a = fresh(); L.push(`        (${decl(a)}) = g2AddAffine(${r.join(',')}, ${BNM.join(',')});`); r = a; }
  }
  if (isLast) {
    const [Rxa, Rxb, Rya, Ryb, Rza, Rzb] = r;
    L.push(`        (int gza,int gzb) = fp2Mul(${Rza}, ${Rzb}, zinvA, zinvB);`);
    L.push('        require(gza == 1); require(gzb == 0);');
    L.push('        (int zi2a,int zi2b) = fp2Sqr(zinvA, zinvB);');
    L.push('        (int zi3a,int zi3b) = fp2Mul(zi2a, zi2b, zinvA, zinvB);');
    L.push(`        (int a0xa,int a0xb) = fp2Mul(${Rxa}, ${Rxb}, zi2a, zi2b);`);
    L.push(`        (int a0ya,int a0yb) = fp2Mul(${Rya}, ${Ryb}, zi3a, zi3b);`);
    L.push('        (int bxa,int bxb,int bya,int byb) = psi(a0xa, a0xb, a0ya, a0yb);');
    L.push('        (int cxa,int cxb,int cya,int cyb) = psi(bxa, bxb, bya, byb);');
    L.push('        (int dxa,int dxb,int dya,int dyb) = psi(cxa, cxb, cya, cyb);');
    L.push('        (int l1xa,int l1xb,int l1ya,int l1yb,int l1za,int l1zb) = g2AddAffine(a0xa, a0xb, a0ya, a0yb, 1, 0, Bxa, Bxb, Bya, Byb);');
    L.push('        (int l2xa,int l2xb,int l2ya,int l2yb,int l2za,int l2zb) = g2AddAffine(l1xa, l1xb, l1ya, l1yb, l1za, l1zb, bxa, bxb, bya, byb);');
    L.push('        (int lxa,int lxb,int lya,int lyb,int lza,int lzb) = g2AddAffine(l2xa, l2xb, l2ya, l2yb, l2za, l2zb, cxa, cxb, cya, cyb);');
    L.push('        (int rxa,int rxb,int rya,int ryb,int rza,int rzb) = g2Double(dxa, dxb, dya, dyb, 1, 0);');
    L.push('        (int lz2a,int lz2b) = fp2Sqr(lza, lzb); (int lz3a,int lz3b) = fp2Mul(lz2a, lz2b, lza, lzb);');
    L.push('        (int rz2a,int rz2b) = fp2Sqr(rza, rzb); (int rz3a,int rz3b) = fp2Mul(rz2a, rz2b, rza, rzb);');
    L.push('        (int xl_a,int xl_b) = fp2Mul(lxa, lxb, rz2a, rz2b); (int xr_a,int xr_b) = fp2Mul(rxa, rxb, lz2a, lz2b);');
    L.push('        require(xl_a == xr_a); require(xl_b == xr_b);');
    L.push('        (int yl_a,int yl_b) = fp2Mul(lya, lyb, rz3a, rz3b); (int yr_a,int yr_b) = fp2Mul(rya, ryb, lz3a, lz3b);');
    L.push('        require(yl_a == yr_a); require(yl_b == yr_b);');
    L.push(covOut(SEAM1));                 // 10-limb seam -> vkx-genesis
  } else {
    L.push(covOut([...r, ...BNM, ...PASS])); // 16-limb interior
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
const g2State = (upto) => { const [X, Y, Z] = g2checkAccAt(BforG2, upto).map((c) => c.map(red)); return [X[0], X[1], Y[0], Y[1], Z[0], Z[1], Bxa, Bxb, Bya, Byb, nAx, nAy, Cx, Cy, in0, in1]; };
const g2zinv = g2checkFastZinv(BforG2).map(red);

// ======================================================================================
// STAGE 2: vkx (8 chunks, worst-case-sized windows) — MSM vk_x = IC0 + in0*IC1 + in1*IC2
//   interior state (13): rX rY rZ in0 in1 nAx nAy B(4) Cx Cy ; genesis reads SEAM1(10),
//   pins R=inf; final emits SEAM2(10) = [negA,B,vkx,C] (ptParams order)
// ======================================================================================
const IC = vec.vk.ic.map(g1);
const ic0 = IC[0].toAffine(), ic1 = IC[1].toAffine(), ic2 = IC[2].toAffine(), Ta = IC[1].add(IC[2]).toAffine();
const IC0 = [ic0.x, ic0.y], IC1 = [ic1.x, ic1.y], IC2 = [ic2.x, ic2.y], T = [Ta.x, Ta.y];
const aF = (x, y) => (x + y) % P, sF = (x, y) => (x - y + P) % P, mF = (x, y) => (x * y) % P, qF = (x) => (x * x) % P;
function jDbl(X, Y, Z) { const a = qF(X), b = qF(Y), c = qF(b); const d = mF(2n, sF(sF(qF(aF(X, b)), a), c)); const e = mF(3n, a), f = qF(e); const nx = sF(f, mF(2n, d)); return [nx, sF(mF(e, sF(d, nx)), mF(8n, c)), mF(2n, mF(Y, Z))]; }
function jAdd(aX, aY, aZ, bX, bY, bZ) { if (aZ === 0n) return [bX, bY, bZ]; const z1 = qF(aZ), z2 = qF(bZ); const u1 = mF(aX, z2), u2 = mF(bX, z1); const s1 = mF(mF(aY, bZ), z2), s2 = mF(mF(bY, aZ), z1); if (u1 === u2 && s1 === s2) return jDbl(aX, aY, aZ); const h = sF(u2, u1), i2 = qF(mF(2n, h)), j = mF(h, i2), rr = mF(2n, sF(s2, s1)), v = mF(u1, i2); const nx = sF(sF(qF(rr), j), mF(2n, v)); return [nx, sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j))), mF(sF(sF(qF(aF(aZ, bZ)), z1), z2), h)]; }
const addedPt = (i) => { const b0 = (in0 >> BigInt(i)) & 1n, b1 = (in1 >> BigInt(i)) & 1n; if (b0 && b1) return T; if (b0) return IC1; if (b1) return IC2; return null; };
function vkxWindow(lo, hi, rX, rY, rZ) { for (let j = lo; j < hi; j++) { const i = 253 - j; if (rZ !== 0n)[rX, rY, rZ] = jDbl(rX, rY, rZ); const ap = addedPt(i); if (ap)[rX, rY, rZ] = jAdd(rX, rY, rZ, ap[0], ap[1], 1n); } return [rX, rY, rZ]; }
const modpow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
const vkxPrologue = `function addFp(int x,int y) returns(int){return (x+y)%${Pstr};}
function subFp(int x,int y) returns(int){return (x-y+${Pstr})%${Pstr};}
function mulFp(int x,int y) returns(int){return (x*y)%${Pstr};}
function sqrFp(int x) returns(int){return (x*x)%${Pstr};}
function jacDouble(int x,int y,int z) returns(int,int,int){int a=sqrFp(x);int b=sqrFp(y);int c=sqrFp(b);int d=mulFp(2,subFp(subFp(sqrFp(addFp(x,b)),a),c));int e=mulFp(3,a);int f=sqrFp(e);int nx=subFp(f,mulFp(2,d));int ny=subFp(mulFp(e,subFp(d,nx)),mulFp(8,c));int nz=mulFp(2,mulFp(y,z));return nx,ny,nz;}
function jacAdd(int aX,int aY,int aZ,int bX,int bY,int bZ) returns(int,int,int){int rx=bX;int ry=bY;int rz=bZ;if(aZ!=0){int z1=sqrFp(aZ);int z2=sqrFp(bZ);int u1=mulFp(aX,z2);int u2=mulFp(bX,z1);int s1=mulFp(mulFp(aY,bZ),z2);int s2=mulFp(mulFp(bY,aZ),z1);if(u1==u2&&s1==s2){int da=sqrFp(aX);int db=sqrFp(aY);int dc=sqrFp(db);int dd=mulFp(2,subFp(subFp(sqrFp(addFp(aX,db)),da),dc));int de=mulFp(3,da);int df=sqrFp(de);int dnx=subFp(df,mulFp(2,dd));int dny=subFp(mulFp(de,subFp(dd,dnx)),mulFp(8,dc));int dnz=mulFp(2,mulFp(aY,aZ));rx=dnx;ry=dny;rz=dnz;}else{int h=subFp(u2,u1);int i2=sqrFp(mulFp(2,h));int jj=mulFp(h,i2);int rr=mulFp(2,subFp(s2,s1));int vv=mulFp(u1,i2);int anx=subFp(subFp(sqrFp(rr),jj),mulFp(2,vv));int any=subFp(mulFp(rr,subFp(vv,anx)),mulFp(2,mulFp(s1,jj)));int anz=mulFp(subFp(subFp(sqrFp(addFp(aZ,bZ)),z1),z2),h);rx=anx;ry=any;rz=anz;}}return rx,ry,rz;}
function selectPoint(int b0,int b1) returns(int,int,int){int aX=0;int aY=0;int doAdd=0;if(b0==1&&b1==1){aX=${T[0]};aY=${T[1]};doAdd=1;}else{if(b0==1){aX=${IC1[0]};aY=${IC1[1]};doAdd=1;}else{if(b1==1){aX=${IC2[0]};aY=${IC2[1]};doAdd=1;}}}return aX,aY,doAdd;}`;
const VKST = ['rX', 'rY', 'rZ', 'input0', 'input1', 'nAx', 'nAy', ...BNM, 'Cx', 'Cy']; // 13
const SEAM2 = ['nAx', 'nAy', ...BNM, 'vkxX', 'vkxY', 'Cx', 'Cy'];                       // 10 (ptParams order)
function vkxChunk(lo, hi, isGenesis, isFinal) {
  const count = hi - lo, hiBit = 253 - lo;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(vkxPrologue);
  L.push('contract VkxU() {');
  L.push(`    function spend(${decl(VKST)}${isFinal ? ', int zInv' : ''}, bytes unused zeroPadding) {`);
  if (isGenesis) {
    L.push(covIn(SEAM1));                 // reads 10-limb SEAM1 (negA,B,C,in0,in1)
    L.push('        require(rX == 0); require(rY == 1); require(rZ == 0);'); // pin accumulator = infinity
  } else {
    L.push(covIn(VKST));                  // 13-limb interior state
  }
  L.push(`        for (int k = 0; k < ${count}; k = k + 1) {`);
  L.push(`            int i = ${hiBit} - k;`);
  L.push('            if (rZ != 0) { (int dx,int dy,int dz) = jacDouble(rX,rY,rZ); rX=dx; rY=dy; rZ=dz; }');
  L.push('            int b0 = (input0 >> i) % 2; int b1 = (input1 >> i) % 2;');
  L.push('            (int aX,int aY,int doAdd) = selectPoint(b0,b1);');
  L.push('            if (doAdd == 1) { (int ax,int ay,int az)=jacAdd(rX,rY,rZ,aX,aY,1); rX=ax; rY=ay; rZ=az; }');
  L.push('        }');
  if (isFinal) {
    L.push(`        (int icx,int icy,int icz) = jacAdd(rX,rY,rZ,${IC0[0]},${IC0[1]},1);`);
    L.push('        require(mulFp(icz, zInv) == 1);');
    L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
    L.push('        int vkxX = mulFp(icx, zInv2);');
    L.push('        int vkxY = mulFp(icy, zInv3);');
    L.push(covOut(SEAM2));                 // 10-limb SEAM2 -> miller reloc genesis
  } else {
    L.push(covOut(VKST));                  // 13-limb interior
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
const vkxStateAt = (accX, accY, accZ) => [red(accX), red(accY), red(accZ), in0, in1, nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy];

// ======================================================================================
// DRIVER
// ======================================================================================
const chain = []; // {name, stage, lock, unlock, op, inCommit, outCommit, committedIn}
function record(name, stage, m) {
  if (!m.accepted) { console.error(`FAIL ${name}: acc=${m.accepted} op=${m.operationCost} err=${m.error ?? ''}`); throw new Error(`chunk ${name} did not accept`); }
  chain.push({ name, stage, lock: m.lockingBytes, unlock: m.unlockingBytes, op: m.operationCost, inCommit: m.inCommit, outCommit: m.outCommit });
  console.log(`${stage.padEnd(8)} ${name.padEnd(18)} lock=${String(m.lock ?? m.lockingBytes).padStart(3)} unlock=${String(m.unlockingBytes).padStart(5)} op=${String(m.operationCost).padStart(9)} acc=Y`);
}

// ---- STAGE 1: g2check windows (worst-case == real; instance-independent) ----
const G2_WINS = [[0, 21], [21, 41], [41, 62], [62, 63]];
for (let ci = 0; ci < G2_WINS.length; ci++) {
  const [lo, hi] = G2_WINS[ci];
  const isFirst = ci === 0, isLast = ci === G2_WINS.length - 1;
  const src = g2Chunk(lo, hi, isFirst, isLast);
  const committedIn = g2State(lo);
  const pushedArgs = isLast ? [...committedIn, ...g2zinv] : committedIn;
  const outLimbs = isLast ? [nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1] : g2State(hi);
  const m = measureChunk(`g2_${ci}`, src, committedIn, pushedArgs, outLimbs);
  record(`g2_${ci}[${lo},${hi})`, 'g2check', m);
}

// ---- STAGE 2: vkx windows (worst-case-sized boundaries, REAL-instance measured) ----
const VKX_WINS = [[0, 37], [37, 73], [73, 109], [109, 145], [145, 181], [181, 217], [217, 253], [253, 254]];
let acc = [0n, 1n, 0n];
for (let ci = 0; ci < VKX_WINS.length; ci++) {
  const [lo, hi] = VKX_WINS[ci];
  const isGenesis = ci === 0, isFinal = ci === VKX_WINS.length - 1;
  const src = vkxChunk(lo, hi, isGenesis, isFinal);
  const committedIn = isGenesis
    ? [nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1]   // SEAM1
    : vkxStateAt(acc[0], acc[1], acc[2]);
  const [rx, ry, rz] = vkxWindow(lo, hi, acc[0], acc[1], acc[2]);
  let outLimbs, pushedArgs;
  const stateInVals = isGenesis ? [0n, 1n, 0n, in0, in1, nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy] : vkxStateAt(acc[0], acc[1], acc[2]);
  if (isFinal) {
    const [fx, fy, fz] = jAdd(rx, ry, rz, IC0[0], IC0[1], 1n);
    const zInv = fz === 0n ? 0n : modpow(fz, P - 2n, P);
    outLimbs = [nAx, nAy, Bxa, Bxb, Bya, Byb, vkxX, vkxY, Cx, Cy]; // SEAM2
    pushedArgs = [...stateInVals, zInv];
  } else {
    outLimbs = vkxStateAt(rx, ry, rz);
    pushedArgs = stateInVals;
  }
  const m = measureChunk(`vkx_${ci}`, src, committedIn, pushedArgs, outLimbs);
  record(`vkx_${ci}[${lo},${hi})`, 'vkx', m);
  acc = [rx, ry, rz];
}

// ---- STAGE 3: miller (reloc genesis + greedy re-chunk under buildCovStep) ----
function measureMiller(lo, hi, relocGenesis) {
  const isFinal = hi === millerOps.length;
  const src = millerGenChunk(lo, hi, isFinal, relocGenesis);
  const inFull = millerInState(lo).map(BigInt);
  const committedIn = relocGenesis ? inFull.slice(18, 28).map(red) : inFull.map(red);
  const outLimbs = millerOutState(hi).map(red);
  return measureChunk(`ml_${lo}_${hi}`, src, committedIn, inFull, outLimbs);
}
let lo = 0, mIdx = 0, prevWidth = null;
while (lo < millerOps.length) {
  const relocGenesis = lo === 0;
  const guess = Math.min(millerOps.length, prevWidth ? lo + prevWidth : lo + (relocGenesis ? 14 : 27));
  let last = null;
  const gm = measureMiller(lo, guess, relocGenesis);
  if (gm.fits) {
    last = { hi: guess, m: gm };
    for (let hi = guess + 1; hi <= millerOps.length; hi++) { const mm = measureMiller(lo, hi, relocGenesis); if (mm.fits) last = { hi, m: mm }; else break; }
  } else {
    for (let hi = guess - 1; hi > lo; hi--) { const mm = measureMiller(lo, hi, relocGenesis); if (mm.fits) { last = { hi, m: mm }; break; } }
  }
  if (!last) throw new Error(`miller op ${lo} infeasible`);
  record(`ml_${mIdx}[${lo},${last.hi})${relocGenesis ? 'G' : ''}`, 'miller', last.m);
  prevWidth = last.hi - lo; lo = last.hi; mIdx++;
}

// ---- STAGE 4: residue tail (terminal, generic covIn = [fF,c,cInv]) ----
const TAIL_LIB = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const pairs = pairsFor(inputs);
const { boundary: fRaw } = millerBatchOps(pairs);
const { c: cWit, cInv: ciWit, w: wWit } = residueWitness(fRaw);
const fused = millerFusedOps(pairs, cWit, ciWit);
const tailState36 = [...fp12limbsOf(fused.boundary), ...fp12limbsOf(cWit), ...fp12limbsOf(ciWit)].map(red);
const wLimbs = fp12limbsOf(wWit).map(red);
const ROOT27L = fp12limbsOf(COSET27[1]).map(String);
const ROOT27_2L = fp12limbsOf(COSET27[2]).map(String);
const ONE_L = ['1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'];
const matchVec = (names, lits) => '(' + names.map((n, i) => `${n} == ${lits[i]}`).join(' && ') + ')';
function tailSrc() {
  const fFn = Array.from({ length: 12 }, (_, i) => `fF${i}`), cN = Array.from({ length: 12 }, (_, i) => `c${i}`);
  const ciN = Array.from({ length: 12 }, (_, i) => `ci${i}`), wN = Array.from({ length: 12 }, (_, i) => `w${i}`);
  const COMMIT = [...fFn, ...cN, ...ciN];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${TAIL_LIB}";`);
  L.push('contract ResidueTailU() {');
  L.push(`    function spend(${decl([...COMMIT, ...wN])}, bytes unused zeroPadding) {`);
  L.push(covIn(COMMIT));
  L.push(`        int P = ${Pstr};`);
  L.push('        ' + cN.map((n) => `require(${n} < P);`).join(' '));
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `p${i}`))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(p${i} % P == ${ONE_L[i]});`).join(' '));
  L.push(`        require(${matchVec(wN, ONE_L)} || ${matchVec(wN, ROOT27L)} || ${matchVec(wN, ROOT27_2L)});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cq${i}`))}) = fp12Frob1(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqq${i}`))}) = fp12Frob2(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqqq${i}`))}) = fp12Frob3(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `t${i}`))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `lhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `t${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqq${i}`).join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `rhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `cq${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqqq${i}`).join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(lhs${i} % P == rhs${i} % P);`).join(' '));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
{
  const src = tailSrc();
  const committedIn = tailState36;
  const pushedArgs = [...tailState36, ...wLimbs];
  const m = measureChunk('tail', src, committedIn, pushedArgs, null);
  record('tail', 'tail', m);
}

// ======================================================================================
// CHAIN VERIFICATION + TOTALS
// ======================================================================================
let internalChainOk = true;
const breaks = [];
for (let i = 1; i < chain.length; i++) {
  if (chain[i - 1].outCommit !== chain[i].inCommit) { internalChainOk = false; breaks.push(`${chain[i - 1].name} -> ${chain[i].name}`); }
}
const startSeam = chain[0].name.startsWith('g2_0'); // genesis root is chunk 0
const endSeam = chain[chain.length - 1].name === 'tail' && chain[chain.length - 1].outCommit === null;
const total = chain.reduce((s, c) => s + c.lock + c.unlock, 0);
const byStage = {};
for (const c of chain) { byStage[c.stage] = (byStage[c.stage] || 0) + c.lock + c.unlock; }
console.log('');
console.log(`chunk count: ${chain.length}`);
console.log('per-stage bytes:', JSON.stringify(byStage));
console.log(`internalChainOk=${internalChainOk} ${breaks.length ? 'BREAKS: ' + breaks.join(', ') : ''}`);
console.log(`UNIFIED end-to-end TOTAL = ${total} B  deltaVs274607=${total - 274607}  crownCrossed(<241518)=${total < 241518}  margin=${241518 - total}`);
console.log('JSON ' + JSON.stringify({
  chunkCount: chain.length, total, deltaVs274607: total - 274607, crownCrossed: total < 241518, margin: 241518 - total,
  internalChainOk, startSeam, endSeam, byStage,
  chunks: chain.map((c) => ({ name: c.name, stage: c.stage, lock: c.lock, unlock: c.unlock, op: c.op })),
}));
console.log('XEXPORTS ' + JSON.stringify(xexports));
for (const r of xexports) console.log(`XEXPORT tag=${r.tag} chunk=${r.chunk} tamper=${r.tamper} libauthAccepted=${r.libauthAccepted} libauthOpCost=${r.libauthOpCost} err=${r.err}`);
