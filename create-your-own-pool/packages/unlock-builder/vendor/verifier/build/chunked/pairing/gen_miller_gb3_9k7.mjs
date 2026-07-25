// K=13 generic-body generator: witness (state + pair0 slopes + chain) in the executor inBlob; consensus
// (mode + fixed lambdas) in a sibling DATA input read via tx introspection. dotC/dotCi threaded (not
// c/cInv) => 32-limb state. Reaches K=13 under the 10k unlock cap. Reuses the live trajectory verbatim.
import { createHash } from 'node:crypto';
import { trajectory, stepFactorSpec, ezCols, e6col, P, mod, madd, mmul, peval } from './_szmath.mjs';
import { f12limbs, vk, Fp2 } from './_millermath.mjs';
import { buildShared, CTX_LIMBS, WD_LIMBS, CD_LIMBS } from './t3_shared3_9k7.mjs';
import { rewriteChunk } from './_t4kp_specialize_local.mjs';
const KSPEC = process.env.KSPEC === '1'; // T4-KP: bake k*P => delete runtime k-mul per subFp
const t = trajectory(); const Pstr = P.toString();
const LIB = '../../../singleton/bn254/lib/lazy/Bn254LazyAff.cash';
export const stepCount = t.steps.length;
const EZCOLS = ezCols.map((c) => c.map(mod)), E6 = e6col.map((c) => c.map(mod));
const g2l = (Q) => { const a = Q.toAffine(); return [mod(a.x.c0), mod(a.x.c1), mod(a.y.c0), mod(a.y.c1)]; };
const GAMMA_Q = g2l(vk.gamma), DELTA_Q = g2l(vk.delta);
export const SHARED = buildShared({ GQXA: GAMMA_Q[0], GQXB: GAMMA_Q[1], GQYA: GAMMA_Q[2], GQYB: GAMMA_Q[3], DQXA: DELTA_Q[0], DQXB: DELTA_Q[1], DQYA: DELTA_Q[2], DQYB: DELTA_Q[3] });
function affStart(j) { const per = []; for (let i = 0; i < t.fused.ops.length; i++) if (t.fused.ops[i].t === 'sqr') { const R = t.fused.states[i].Rs[j]; per.push([mod(R.x.c0), mod(R.x.c1), mod(R.y.c0), mod(R.y.c1)]); } const last = t.fused.states[t.fused.states.length - 1].Rs[j]; per.push([mod(last.x.c0), mod(last.x.c1), mod(last.y.c0), mod(last.y.c1)]); return per; }
const R0S = affStart(0), TGS = affStart(2), TDS = affStart(3);
const chainLimbs = (i) => f12limbs(t.chain[i]).map(mod);
const cL = f12limbs(t.c).map(mod), ciL = f12limbs(t.cInv).map(mod);
const PTV = { nAx: mod(t.nA.x), nAy: mod(t.nA.y), vkxX: mod(t.vkxAff.x), vkxY: mod(t.vkxAff.y), Cx: mod(t.Caf.x), Cy: mod(t.Caf.y), Bxa: g2l(t.pf.b)[0], Bxb: g2l(t.pf.b)[1], Bya: g2l(t.pf.b)[2], Byb: g2l(t.pf.b)[3] };
const ezAtZ = ezCols.map((col) => peval(col.map(mod), t.z));
const dotC = cL.reduce((a, v, k) => madd(a, mmul(v, ezAtZ[k])), 0n);
const dotCi = ciL.reduce((a, v, k) => madd(a, mmul(v, ezAtZ[k])), 0n);

// per-step witness (wdat) + consensus (cdat)
export function perStep(i) {
  const spec = stepFactorSpec(t, i);
  const w = { sda: 0n, sdb: 0n, saa: 0n, sab: 0n, chain: chainLimbs(i + 1) };
  const c = { mode: 0, lgd: 0n, lgD: 0n, lga: 0n, lgA: 0n, ldd: 0n, ldD: 0n, lda: 0n, ldA: 0n };
  for (const f of spec) {
    if (f.kind === 'cfold') { c.mode = f.useC ? 1 : 2; continue; }
    if (f.kind === 'varline') { if (f.op === 'dl') { w.sda = mod(f.lam.c0); w.sdb = mod(f.lam.c1); } else { w.saa = mod(f.lam.c0); w.sab = mod(f.lam.c1); } }
    else if (f.kind === 'fixline') { const g = f.pair === 2; if (f.op === 'dl') { if (g) { c.lgd = mod(f.lam.c0); c.lgD = mod(f.lam.c1); } else { c.ldd = mod(f.lam.c0); c.ldD = mod(f.lam.c1); } } else { if (g) { c.lga = mod(f.lam.c0); c.lgA = mod(f.lam.c1); } else { c.lda = mod(f.lam.c0); c.ldA = mod(f.lam.c1); } } }
  }
  return { w, c };
}
// DYN-DERIVED: the cfold mode is a public function of the pinned block index,
// not a witness byte. Two bits per Miller step encode the live trajectory.
// The trajectory has two non-Miller sentinels (indices 0 and 64); deployed records are 1..63.
export const MODE_SCHEDULE = Array.from({ length: t.steps.length - 2 }, (_, k) => perStep(k + 1).c.mode);
if (MODE_SCHEDULE.some((m) => m < 0 || m > 2)) throw new Error('invalid cfold mode');
export const MODE_PACK = MODE_SCHEDULE.reduce((a, m, k) => a | (BigInt(m) << BigInt(2 * k)), 0n);
export const hasAddStep = (i) => stepFactorSpec(t, i).some((f) => f.kind === 'varline' && f.op === 'al');
export const SGB = ['gamma','z','blkidx','hInt','aggL','aggF','gp','fC','nAx','nAy','vkxX','vkxY','Cx','Cy','Bxa','Bxb','Bya','Byb','Rxa','Rxb','Rya','Ryb','Tgxa','Tgxb','Tgya','Tgyb','Tdxa','Tdxb','Tdya','Tdyb','dotC','dotCi'];
const HINT_I = SGB.indexOf('hInt');
export const STATE_LIMBS = SGB.length, W = 40, WD_B = WD_LIMBS * W;
// ---- SEAM-NARROW (E-onetx): the forward-threaded Miller-STATE limbs are %P-reduced field elements
// (outExpr bakes `x % P` for every limb EXCEPT hInt, which is the raw seam-hash accumulator). A %P value
// is < p < 2^254, so 32 LE bytes are lossless AND the top byte < 0x40 => a fixed-width int() read is
// sign-safe (+ve), reject-set byte-identical to the 40B read (the NW13/rb-recover canonical-limb rule).
// hInt is an UNREDUCED 256-bit hash (top bit can be set) => it must STAY 40B (32B would read -ve). So we
// narrow the 30 canonical limbs 40->32 and keep hInt@40. UNIFORM across all 9 chunks + the seam (one body,
// one width) — F20-safe. Gated by SEAMNARROW=1; SW overrides the narrowed width (default 32).
const SNW = process.env.SEAMNARROW === '1' ? Number(process.env.SW ?? 32) : 40;
export const stateW = (p) => (p === HINT_I ? 40 : SNW);          // per-limb state width; hInt raw => 40
export const STATE_BYTES = SGB.reduce((a, _n, p) => a + stateW(p), 0); // narrowed seam-state byte length
// ---- CDAT NARROW (rb-recover): consensus lambdas lgd..ldA are %P-reduced field elements < p < 2^254 =>
// 32 LE bytes lossless. CDNW = how many of the 8 lambda limbs (positions 1..8, mode@0 stays 40) narrow to
// 32B. UNIFORM across all 9 chunks (single-body invariant preserved). Fixed-width read (like baseline le40),
// just a smaller fixed width => reject-set stays byte-identical (deviations still fail the agg check;
// values >=2^256 were rejected before and are simply unrepresentable now). Score/wire drop 504B per limb.
export const CDNW = Number(process.env.CDNW ?? 1);         // rb-recover default: narrow 1 lambda limb (lgd)
export const CDWIDTH = Number(process.env.CDWIDTH ?? 34);  // tightest op-fitting width (all 9 chunks fit, worst 99.9%)
export const CDW = Array.from({ length: CD_LIMBS }, (_, i) => (i >= 1 && i <= CDNW) ? CDWIDTH : 40); // per-cdat-limb width
const CD_STEP_W = [1, CDW[1], CDW[2], CDW[5], CDW[6], CDW[3], CDW[4], CDW[7], CDW[8]];
export const CD_MAND_B = CD_STEP_W.slice(1, 5).reduce((a, w) => a + w, 0); // lgd,lgD,ldd,ldD
export const CD_ADD_B = CD_STEP_W.slice(5).reduce((a, w) => a + w, 0); // lga,lgA,lda,ldA
export const CD_B = 1 + CD_MAND_B + CD_ADD_B; // maximum compact cdat width (mode 1/2)

function stateVal(s) {
  const finZ = (i) => chainLimbs(i).reduce((a, v, k) => madd(a, mmul(v, ezAtZ[k])), 0n);
  let aggL = 0n, aggF = 0n, gp = 1n;
  for (let i = 0; i < s; i++) { const fc = finZ(i); const t_l = mmul(mmul(fc, fc), t.prodFactorZ[i]); aggL = madd(aggL, mmul(gp, t_l)); aggF = madd(aggF, mmul(gp, finZ(i + 1))); gp = mmul(gp, t.gamma); }
  const hbuf = t.seamH[Math.min(s + 2, t.seamH.length - 1)]; let hInt = 0n; for (let b = hbuf.length - 1; b >= 0; b--) hInt = (hInt << 8n) | BigInt(hbuf[b]);
  const m = {}; SGB.forEach((n) => m[n] = 0n); Object.assign(m, PTV);
  m.gamma = t.gamma; m.z = t.z; m.blkidx = BigInt(s + 2); m.hInt = hInt; m.aggL = aggL; m.aggF = aggF; m.gp = gp; m.fC = finZ(s); m.dotC = dotC; m.dotCi = dotCi;
  [m.Rxa, m.Rxb, m.Rya, m.Ryb] = R0S[s]; [m.Tgxa, m.Tgxb, m.Tgya, m.Tgyb] = TGS[s]; [m.Tdxa, m.Tdxb, m.Tdya, m.Tdyb] = TDS[s];
  return SGB.map((n) => m[n]);
}
export { stateVal };
const le40 = (n, raw = false) => { let v = raw ? BigInt(n) : mod(n); const o = new Uint8Array(40); for (let i = 0; i < 40; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
const cat = (...xs) => { const tl = xs.reduce((n, x) => n + x.length, 0); const o = new Uint8Array(tl); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
// ---- BOUNDED-W1 VARIANT B: per-chunk variable-width wdat, length-prefixed (1 len byte + w LE bytes) ----
// Every wdat limb is a %P-reduced canonical field element < p < 2^254 => 32 LE bytes lossless. Per chunk k
// (0..7, KMAX=8-aligned) we narrow the first NW[k] of the 16 wdat limbs to 32B, the rest stay 40B, so a
// dense chunk's exec unlock stays >= its op-floor ((41+unlockLen)*800 >= op) while light chunks narrow all.
// 9xK7 UNIFORM: 63 = 9*7. Every chunk K=7 with the SAME narrowed-limb count => ONE (K,NW) class =>
// ONE generic forward body legitimately serves EVERY chunk. UNW settable via env (default 16 = narrow
// all 16 wdat limbs to 32B; K7's lower op-floor admits it). All 9 entries identical => wdW/wdatBytes
// are chunk-invariant regardless of the /7 alignment.
const UNW = Number(process.env.UNW || 16);
const FIXED_WDAT = process.env.FIXED_WDAT === '1';
export const DYN_PACK = process.env.DYN_PACK === '1';
export const DERIVE_MODE = process.env.DERIVE_MODE === '1';
const DIRECT_FINALIZE_STATE = process.env.DIRECT_FINALIZE_STATE === '1';
const FINAL_EXECUTOR_INDEX = Math.ceil(63 / Number(process.env.KWIN ?? 9)) - 1;
const STRIPED = process.env.STRIPED === '1';
const DRIVER_PACK_DERIVED = STRIPED && process.env.DRIVER_PACK_DERIVED === '1';
const DRIVER_WINDOW_DERIVED = STRIPED && process.env.DRIVER_WINDOW_DERIVED === '1';
const RETAIN_CDAT = process.env.RETAIN_CDAT === '1';
const RETAIN_WDAT = process.env.RETAIN_WDAT === '1';
const FIN_PAD_SCHED = (process.env.FIN_PAD ?? '').split(',').filter((x) => x.length > 0).map(Number);
if (FIN_PAD_SCHED.length && FIN_PAD_SCHED.length !== 9) throw new Error('FIN_PAD requires 9 chunk lengths');
if (FIN_PAD_SCHED.some((n) => !Number.isInteger(n) || n < 0)) throw new Error('invalid FIN_PAD');
const sha256dHex = (n) => {
  const z = Buffer.alloc(n); const h1 = createHash('sha256').update(z).digest();
  return createHash('sha256').update(h1).digest('hex');
};
const FIN_PAD_HASHES = FIN_PAD_SCHED.map(sha256dHex);
const WDWIDTH = Number(process.env.WDWIDTH ?? 32);
const WIDE_POS = new Set((process.env.WIDE_POS ?? '').split(',').filter(Boolean).map(Number));
export const NW = Array(9).fill(UNW);                                // uniform narrowed-limb count, all 9 chunks
export const chunkIdxOf = (i) => Math.min(8, Math.floor((i - 1) / 7)); // step i (1..63) -> K7 chunk 0..8
const wdW = (i, p) => WIDE_POS.has(p) ? 40 : (p < NW[chunkIdxOf(i)] ? WDWIDTH : 40); // limb-position width for step i
const WD_MAND_POS = [0, 1, ...Array.from({ length: 12 }, (_, k) => k + 4)];
const WD_ADD_POS = [2, 3];
export const wdatBytesForMode = (i, mode) => [...WD_MAND_POS, ...(mode >= 1 || (DERIVE_MODE && RETAIN_WDAT) ? WD_ADD_POS : [])].reduce((a, p) => a + wdW(i, p), 0);
export const wdatBytesForChunk = (lo) => DYN_PACK ? wdatBytesForMode(lo, 1) : ((FIXED_WDAT ? 0 : 16) + Array.from({ length: 16 }, (_, p) => wdW(lo, p)).reduce((a, w) => a + w, 0)); // max record width
export function cdatBytesForStep(_i) { return CD_B; }
const leW = (n, w) => { let v = mod(n); const o = new Uint8Array(w); for (let i = 0; i < w; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
const lp = (n, w) => cat(Uint8Array.of(w), leW(n, w));              // length-prefixed limb: [w][w LE bytes]
const fw = (n, w) => leW(n, w);                                    // fixed-width canonical field limb
const leState = (n, p) => { const w = stateW(p); let v = (p === HINT_I) ? BigInt(n) : mod(n); const o = new Uint8Array(w); for (let i = 0; i < w; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
export function stateBlob(limbs) { return cat(...limbs.map((l, i) => leState(l, i))); }
export function wdatStep(i) {
  const { w, c } = perStep(i); const omitAdd = DYN_PACK && c.mode === 0 && !RETAIN_WDAT;
  const limbs = omitAdd ? [w.sda, w.sdb, ...w.chain] : [w.sda, w.sdb, c.mode === 0 ? w.sda : w.saa, c.mode === 0 ? w.sdb : w.sab, ...w.chain];
  return cat(...limbs.map((l, k) => { const p = omitAdd ? WD_MAND_POS[k] : k; return FIXED_WDAT ? fw(l, wdW(i, p)) : lp(l, wdW(i, p)); }));
}
export function cdatStep(i) {
  const { c } = perStep(i); const mandatory = [c.lgd, c.lgD, c.ldd, c.ldD]; const add = [c.lga, c.lgA, c.lda, c.ldA];
  if (DYN_PACK && DERIVE_MODE) {
    const retained = c.mode >= 1 ? add : (RETAIN_CDAT ? [c.lgd, c.lgD, c.ldd, c.ldD] : []);
    return cat(...mandatory.map((l, p) => leW(l, CD_STEP_W[p + 1])), ...retained.map((l, p) => leW(l, CD_STEP_W[p + 5])));
  }
  const fields = DYN_PACK && c.mode === 0 ? [BigInt(c.mode), ...mandatory] : [BigInt(c.mode), ...mandatory, ...add];
  return cat(...fields.map((l, p) => leW(l, CD_STEP_W[p])));
}
// executor inBlob (witness): state(lo) + per-step wdat
export function inBlobGB(lo, hi) {
  const body = cat(stateBlob(stateVal(lo)), ...Array.from({ length: hi - lo }, (_, k) => DYN_PACK ? cat(cdatStep(lo + k), wdatStep(lo + k)) : cat(wdatStep(lo + k), cdatStep(lo + k))));
  if (DYN_PACK && DERIVE_MODE && FIN_PAD_SCHED.length) return cat(body, new Uint8Array(FIN_PAD_SCHED[chunkIdxOf(lo)]));
  return body;
}
// data-sibling blob (consensus): per-step cdat
export function dataBlob(lo, hi) { return cat(...Array.from({ length: hi - lo }, (_, k) => cdatStep(lo + k))); }
export function outBlobGB(hi) { return stateBlob(stateVal(hi)); }

export function genChunkGB(lo, hi, cfg = {}) {
  const K = hi - lo, L = [];
  L.push('pragma cashscript ^0.14.0;', `import "${LIB}";`, SHARED, 'contract GbChunk2() {', '    function spend(bytes inBlob) {');
  let cur = 'inBlob';
  SGB.forEach((nm, p) => { L.push(`        bytes hh${p}, bytes r${p} = ${cur}.split(${stateW(p)}); int ${nm} = int(hh${p});`); cur = `r${p}`; });
  if (STRIPED && !DRIVER_WINDOW_DERIVED) {
    const driverLen = DRIVER_PACK_DERIVED ? 4 : 7;
    L.push(`        bytes driverBytes, bytes driverRest = ${cur}.split(${driverLen});`);
    if (DRIVER_PACK_DERIVED) L.push(
      '        bytes driverStartBytes, bytes driverEndBytes = driverBytes.split(2);',
      '        int driverStart = int(driverStartBytes); int driverEnd = int(driverEndBytes);');
    else L.push(
      '        bytes driverPackBytes, bytes driverWindow = driverBytes.split(3);',
      '        bytes driverStartBytes, bytes driverEndBytes = driverWindow.split(2);',
      '        int driverPack = int(driverPackBytes); int driverStart = int(driverStartBytes); int driverEnd = int(driverEndBytes);');
    cur = 'driverRest';
  }
  L.push(`        bytes rem = ${cur};`, '        bytes h = toPaddedBytes(hInt, 33).split(32)[0];', `        int P = ${Pstr};`);
  L.push('        int zp0 = 1; int zp1 = z % P;');
  for (let j = 2; j < 12; j++) L.push(`        int zp${j} = (zp${j - 1} * z) % P;`);
  const dotB = (co) => { const ts = co.map((c, j) => c === 0n ? null : `${c} * zp${j}`).filter(Boolean); return ts.length ? ts.join(' + ') : '0'; };
  for (let k = 0; k < 12; k++) L.push(`        int ec${k} = (${dotB(EZCOLS[k])}) % P;`);
  for (let sidx = 0; sidx < 6; sidx++) L.push(`        int ex${sidx} = (${dotB(E6[sidx])}) % P;`);
  // D2 fold pre-group: py*ex0, py*ex1, px*ex2, px*ex3 per pair (nA / vkx / C) — ONE-time per chunk.
  L.push(`        int kn0 = (nAy * ex0) % P; int kn1 = (nAy * ex1) % P; int kn2 = (nAx * ex2) % P; int kn3 = (nAx * ex3) % P;`);
  L.push(`        int kv0 = (vkxY * ex0) % P; int kv1 = (vkxY * ex1) % P; int kv2 = (vkxX * ex2) % P; int kv3 = (vkxX * ex3) % P;`);
  L.push(`        int kc0 = (Cy * ex0) % P; int kc1 = (Cy * ex1) % P; int kc2 = (Cx * ex2) % P; int kc3 = (Cx * ex3) % P;`);
  const balc = (arr) => arr.length === 1 ? arr[0] : `(${balc(arr.slice(0, arr.length >> 1))} + ${balc(arr.slice(arr.length >> 1))})`;
  // consensus data sibling: at activeInputIndex + 1
  const WD_B_k = wdatBytesForChunk(lo); // per-chunk variable wdat region size (Variant B)
  if (DYN_PACK && DERIVE_MODE) {
    if (STRIPED && DRIVER_WINDOW_DERIVED) L.push(`        require(this.activeInputIndex >= 0 && this.activeInputIndex < ${Math.ceil(63 / K)}); require(blkidx == this.activeInputIndex * ${K} + 3);`);
    else if (STRIPED && process.env.STRIPED_NO_WINDOW === '1') L.push('        require(driverStart == driverStart); require(driverEnd == driverEnd);');
    else if (STRIPED && process.env.STRIPED_WINDOW_TEST === '1') L.push('        require(driverStart == 3); require(driverEnd == 12);');
    else L.push(STRIPED
      ? `        require(driverStart == blkidx); require(driverEnd == blkidx + ${K});`
      : `        require(blkidx >= 3 && blkidx <= ${66 - K});`);
  }
  for (let s = 0; s < K; s++) {
    if (DYN_PACK) {
      const wd0 = wdatBytesForMode(lo + s, 0), wd1 = wdatBytesForMode(lo + s, 1);
      if (DERIVE_MODE) L.push(STRIPED
        ? (DRIVER_PACK_DERIVED
          ? `        int mode${s} = ((${MODE_PACK.toString()} >> (2 * (blkidx - 3))) % 4);`
          : `        int mode${s} = ((driverPack >> (2 * ${s})) % 4);`)
        : `        int mode${s} = ((${MODE_PACK.toString()} >> (2 * (blkidx - 3))) % 4);`);
      else L.push(`        bytes modeBytes${s}, bytes cdatRest${s} = rem.split(1); int mode${s} = int(modeBytes${s});`);
      if (DERIVE_MODE) L.push(`        bytes cdatTail${s}, bytes afterCdat${s} = rem.split(${CD_MAND_B});`);
      else L.push(`        int cdatTailLen${s} = ${CD_MAND_B}; if (mode${s} >= 1) { cdatTailLen${s} = ${CD_MAND_B + CD_ADD_B}; }`, `        bytes cdatTail${s}, bytes afterCdat${s} = cdatRest${s}.split(cdatTailLen${s});`);
      if (DERIVE_MODE && RETAIN_CDAT) L.push(`        bytes cdatAdd${s}, bytes afterCdatAdd${s} = afterCdat${s}.split(${CD_ADD_B}); cdatTail${s} = cdatTail${s} + cdatAdd${s}; afterCdat${s} = afterCdatAdd${s};`);
      else if (DERIVE_MODE) L.push(`        if (mode${s} >= 1) { bytes cdatAdd${s}, bytes afterCdatAdd${s} = afterCdat${s}.split(${CD_ADD_B}); cdatTail${s} = cdatTail${s} + cdatAdd${s}; afterCdat${s} = afterCdatAdd${s}; }`);
      L.push(`        int wdatLen${s} = ${wd0}; if (mode${s} >= 1) { wdatLen${s} = ${wd1}; }`);
      L.push(`        bytes wd${s}, bytes remn${s} = afterCdat${s}.split(wdatLen${s}); rem = remn${s};`);
    } else {
      L.push(`        bytes wd${s}, bytes remn${s} = rem.split(${WD_B_k}); rem = remn${s};`);
      L.push(`        bytes cd${s}, bytes remc${s} = rem.split(${CD_B}); rem = remc${s};`);
    }
    const stepArgs = DYN_PACK
      ? `ec0,ec1,ec2,ec3,ec4,ec5,ec6,ec7,ec8,ec9,ec10,ec11, ex4,ex5, mode${s}, wd${s}, cdatTail${s}`
      : `ec0,ec1,ec2,ec3,ec4,ec5,ec6,ec7,ec8,ec9,ec10,ec11, ex4,ex5, wd${s}, cd${s}`;
    L.push(`        (aggL,aggF,gp,fC, h, Rxa,Rxb,Rya,Ryb, Tgxa,Tgxb,Tgya,Tgyb, Tdxa,Tdxb,Tdya,Tdyb) = stepU(aggL,aggF,gp,fC, h, gamma, blkidx, dotC,dotCi, Rxa,Rxb,Rya,Ryb, Tgxa,Tgxb,Tgya,Tgyb, Tdxa,Tdxb,Tdya,Tdyb, kn0,kn1,kn2,kn3, kv0,kv1,kv2,kv3, kc0,kc1,kc2,kc3, Bxa,Bxb,Bya,Byb, ${stepArgs});`);
    L.push(`        blkidx = blkidx + 1;`);
  }
  if (DYN_PACK && DERIVE_MODE && FIN_PAD_SCHED.length) {
    L.push('        int finChunk = (blkidx - 10) / 7;', `        int finLen = ${FIN_PAD_SCHED[0]};`);
    for (let k = 1; k < FIN_PAD_SCHED.length; k++) L.push(`        if (finChunk == ${k}) { finLen = ${FIN_PAD_SCHED[k]}; }`);
    L.push('        bytes finPad, bytes finRest = rem.split(finLen); require(finRest.length == 0);', '        bytes finHash = hash256(finPad);');
    for (let k = 0; k < FIN_PAD_HASHES.length; k++) L.push(`        if (finChunk == ${k}) { require(finHash == 0x${FIN_PAD_HASHES[k]}); }`);
  } else if (process.env.NITS !== '0') L.push('        require(rem.length == 0);'); // NIT: no trailing witness bytes past the K consumed steps
  L.push('        int hOut = int(h + 0x00);');
  const outExpr = SGB.map((nm, p) => nm === 'hInt' ? `toPaddedBytes(hOut, ${stateW(p)})` : nm === 'blkidx' ? `toPaddedBytes(blkidx, ${stateW(p)})` : `toPaddedBytes(${nm} % P, ${stateW(p)})`);
  L.push(`        bytes outBlob = ${balc(outExpr)};`);
  if (cfg.forward && !(STRIPED && process.env.STRIPED_NO_FORWARD === '1')) {
    if (DIRECT_FINALIZE_STATE) {
      // The final executor's state is consumed by FINALIZE, not duplicated in GENESIS.
      // Keep one shared executor body by selecting the extra successor index only at the
      // final executor; all preceding executors retain the ordinary +1 edge.
      L.push(`        int nextInput = this.activeInputIndex + 1; if (this.activeInputIndex == ${FINAL_EXECUTOR_INDEX}) { nextInput = nextInput + 1; }`);
      L.push(`        require(outBlob == tx.inputs[nextInput].unlockingBytecode.split(3)[1].split(${STATE_BYTES})[0]);`);
    } else {
      L.push(`        require(outBlob == tx.inputs[this.activeInputIndex + 1].unlockingBytecode.split(3)[1].split(${STATE_BYTES})[0]);`);
    }
  }
  else if (cfg.forward) L.push(`        require(outBlob.length == ${STATE_BYTES});`);
  else if (cfg.expectOutHex) L.push(`        require(outBlob == 0x${cfg.expectOutHex});`);
  else L.push(`        require(outBlob.length == ${STATE_BYTES});`);
  L.push('    }', '}');
  let out = L.join('\n') + '\n';
  if (KSPEC) {
    // T4-KP k*P specialization (semantics-null): swap the residue-lib import to the k-baked variant
    // set and rewrite every subFp(...,lit)/fp2Sub/fp2Neg/... call to its _kN form so the runtime
    // `k * P` multiply is deleted (baked as a literal in the specialized lib). Bit-identical field values.
    out = rewriteChunk(out.replace(
      `import "${LIB}";`,
      `import "../../../singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash";`));
  }
  return out;
}
void CTX_LIMBS;
