// READ-ONLY op-cost probe: eager (shipped Bn254Lazy option-B) vs fully-delayed (V2/V3) reduction.
// Bills each arithmetic op with the EXACT BCH-2026 cost model (LeanBCH Cost/Arith.lean):
//   MUL/MOD: arith += intByteLen(a)*intByteLen(b) + intByteLen(result); push += intByteLen(result)
//   ADD/SUB: arith += intByteLen(result);                               push += intByteLen(result)
// operationCost = 100*instr + arith + push ; density budget 800/byte => bytes = opCost/800.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// intByteLen matching LeanBCH.Number exactly: minimal magnitude bytes + 0x80 sign-pad byte.
function intByteLen(z) {
  let n = z < 0n ? -z : z;
  if (n === 0n) return 0;
  const mag = [];
  while (n > 0n) { mag.push(Number(n & 255n)); n >>= 8n; }
  const top = mag[mag.length - 1];
  return top >= 128 ? mag.length + 1 : mag.length;
}

function mkBill() { return { instr: 0, arith: 0, push: 0, mulOperand: 0, modOperand: 0, muls: 0, mods: 0, adds: 0 }; }
function opCost(b) { return 100 * b.instr + b.arith + b.push; }

// billed ops. Each returns the numeric result; b accumulates cost.
const MUL = (b, x, y) => { const r = x * y; const la = intByteLen(x), lb = intByteLen(y), lr = intByteLen(r);
  b.instr++; b.arith += la * lb + lr; b.push += lr; b.mulOperand += la * lb; b.muls++; return r; };
const MOD = (b, x, m) => { let r = x % m; const la = intByteLen(x), lb = intByteLen(m), lr = intByteLen(r);
  b.instr++; b.arith += la * lb + lr; b.push += lr; b.modOperand += la * lb; b.mods++; return r; };
const ADD = (b, x, y) => { const r = x + y; const lr = intByteLen(r); b.instr++; b.arith += lr; b.push += lr; b.adds++; return r; };
const SUB = (b, x, y) => { const r = x - y; const lr = intByteLen(r); b.instr++; b.arith += lr; b.push += lr; b.adds++; return r; };

// ---------- EAGER scheme (shipped Bn254Lazy option-B) ----------
// mulFp = MUL then MOD. addFp = ADD. subFp(x,y,k) = SUB then ADD(const k*p) [FAVOURABLE: k*p constant-folded].
const E = {
  mulFp: (b, x, y) => MOD(b, MUL(b, x, y), P),
  addFp: (b, x, y) => ADD(b, x, y),
  subFp: (b, x, y, k) => ADD(b, SUB(b, x, y), k * P),           // 2 ops (const bias)
  fp2Mul(b, a0, a1, c0, c1) {
    const v0 = this.mulFp(b, a0, c0), v1 = this.mulFp(b, a1, c1);
    const r0 = this.subFp(b, v0, v1, 1n);
    const r1 = this.subFp(b, this.mulFp(b, this.addFp(b, a0, a1), this.addFp(b, c0, c1)), this.addFp(b, v0, v1), 2n);
    return [r0, r1];
  },
  fp2MulXi(b, a0, a1, k) { return [ this.subFp(b, this.mulFp(b, 9n, a0), a1, k), this.addFp(b, this.mulFp(b, 9n, a1), a0) ]; },
  fp2Add(b, a0, a1, c0, c1) { return [this.addFp(b, a0, c0), this.addFp(b, a1, c1)]; },
  fp2Sub(b, a0, a1, c0, c1, k) { return [this.subFp(b, a0, c0, k), this.subFp(b, a1, c1, k)]; },
  fp6Mul(b, a, c) { // a,c: 6-arrays [a0a,a0b,a1a,a1b,a2a,a2b]
    const t0 = this.fp2Mul(b, a[0], a[1], c[0], c[1]);
    const t1 = this.fp2Mul(b, a[2], a[3], c[2], c[3]);
    const t2 = this.fp2Mul(b, a[4], a[5], c[4], c[5]);
    const s1 = this.fp2Add(b, a[2], a[3], a[4], a[5]);
    const s2 = this.fp2Add(b, c[2], c[3], c[4], c[5]);
    const p1 = this.fp2Mul(b, s1[0], s1[1], s2[0], s2[1]);
    const d1 = this.fp2Sub(b, p1[0], p1[1], t1[0], t1[1], 3n);
    const d2 = this.fp2Sub(b, d1[0], d1[1], t2[0], t2[1], 3n);
    const x1 = this.fp2MulXi(b, d2[0], d2[1], 9n);
    const c0 = this.fp2Add(b, t0[0], t0[1], x1[0], x1[1]);
    const s3 = this.fp2Add(b, a[0], a[1], a[2], a[3]);
    const s4 = this.fp2Add(b, c[0], c[1], c[2], c[3]);
    const p2 = this.fp2Mul(b, s3[0], s3[1], s4[0], s4[1]);
    const d3 = this.fp2Sub(b, p2[0], p2[1], t0[0], t0[1], 3n);
    const d4 = this.fp2Sub(b, d3[0], d3[1], t1[0], t1[1], 3n);
    const x2 = this.fp2MulXi(b, t2[0], t2[1], 3n);
    const c1 = this.fp2Add(b, d4[0], d4[1], x2[0], x2[1]);
    const s5 = this.fp2Add(b, a[0], a[1], a[4], a[5]);
    const s6 = this.fp2Add(b, c[0], c[1], c[4], c[5]);
    const p3 = this.fp2Mul(b, s5[0], s5[1], s6[0], s6[1]);
    const d5 = this.fp2Sub(b, p3[0], p3[1], t0[0], t0[1], 3n);
    const d6 = this.fp2Sub(b, d5[0], d5[1], t2[0], t2[1], 3n);
    const c2 = this.fp2Add(b, d6[0], d6[1], t1[0], t1[1]);
    return [c0[0],c0[1],c1[0],c1[1],c2[0],c2[1]];
  },
  fp6Mul01(b, c, b0a,b0b,b1a,b1b) { // c: 6-array
    const t0 = this.fp2Mul(b, c[0],c[1], b0a,b0b);
    const t1 = this.fp2Mul(b, c[2],c[3], b1a,b1b);
    const s12 = this.fp2Add(b, c[2],c[3], c[4],c[5]);
    const m12 = this.fp2Mul(b, s12[0],s12[1], b1a,b1b);
    const u0 = this.fp2Sub(b, m12[0],m12[1], t1[0],t1[1], 3n);
    const xu0 = this.fp2MulXi(b, u0[0],u0[1], 6n);
    const r0 = this.fp2Add(b, xu0[0],xu0[1], t0[0],t0[1]);
    const sb = this.fp2Add(b, b0a,b0b, b1a,b1b);
    const sc = this.fp2Add(b, c[0],c[1], c[2],c[3]);
    const m1 = this.fp2Mul(b, sb[0],sb[1], sc[0],sc[1]);
    const u1 = this.fp2Sub(b, m1[0],m1[1], t0[0],t0[1], 3n);
    const r1 = this.fp2Sub(b, u1[0],u1[1], t1[0],t1[1], 3n);
    const s02 = this.fp2Add(b, c[0],c[1], c[4],c[5]);
    const m2 = this.fp2Mul(b, s02[0],s02[1], b0a,b0b);
    const u2 = this.fp2Sub(b, m2[0],m2[1], t0[0],t0[1], 3n);
    const r2 = this.fp2Add(b, u2[0],u2[1], t1[0],t1[1]);
    return [r0[0],r0[1],r1[0],r1[1],r2[0],r2[1]];
  },
  fp6MulByV(b, a, k) { const n0 = this.fp2MulXi(b, a[4],a[5], k); return [n0[0],n0[1],a[0],a[1],a[2],a[3]]; },
  fp6Add(b, a, c) { const r=[]; for (let i=0;i<6;i+=2){ r.push(this.addFp(b,a[i],c[i]), this.addFp(b,a[i+1],c[i+1])); } return r; },
  fp6Sub(b, a, c, k) { const r=[]; for (let i=0;i<6;i+=2){ r.push(this.subFp(b,a[i],c[i],k), this.subFp(b,a[i+1],c[i+1],k)); } return r; },
  mul034(b, F, o0a,o0b, o3a,o3b, o4a,o4b) { // F: 12-array
    const A0 = this.fp2Mul(b, F[0],F[1], o0a,o0b);
    const A2 = this.fp2Mul(b, F[2],F[3], o0a,o0b);
    const A4 = this.fp2Mul(b, F[4],F[5], o0a,o0b);
    const A = [A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
    const B = this.fp6Mul01(b, [F[6],F[7],F[8],F[9],F[10],F[11]], o3a,o3b, o4a,o4b);
    const S = this.fp6Add(b, [F[0],F[1],F[2],F[3],F[4],F[5]], [F[6],F[7],F[8],F[9],F[10],F[11]]);
    const qa = this.fp2Add(b, o0a,o0b, o3a,o3b);
    const G = this.fp6Mul01(b, S, qa[0],qa[1], o4a,o4b);
    const VB = this.fp6MulByV(b, B, 9n);
    const C0 = this.fp6Add(b, VB, A);
    const AB = this.fp6Add(b, A, B);
    const C6 = this.fp6Sub(b, G, AB, 12n);
    return [...C0, ...C6];
  },
  fp12Mul(b, A, Bb) { // A,Bb: 12-arrays
    const t0 = this.fp6Mul(b, A.slice(0,6), Bb.slice(0,6));
    const t1 = this.fp6Mul(b, A.slice(6,12), Bb.slice(6,12));
    const vt = this.fp6MulByV(b, t1, 12n);
    const C0 = this.fp6Add(b, t0, vt);
    const sa = this.fp6Add(b, A.slice(0,6), A.slice(6,12));
    const sb = this.fp6Add(b, Bb.slice(0,6), Bb.slice(6,12));
    const pr = this.fp6Mul(b, sa, sb);
    const qq = this.fp6Sub(b, pr, t0, 12n);
    const C6 = this.fp6Sub(b, qq, t1, 12n);
    return [...C0, ...C6];
  },
  fp12Sqr(b, A) {
    const t0 = this.fp6Mul(b, A.slice(0,6), A.slice(6,12));
    const s = this.fp6Add(b, A.slice(0,6), A.slice(6,12));
    const vc = this.fp6MulByV(b, A.slice(6,12), 64n);
    const u = this.fp6Add(b, A.slice(0,6), vc);
    const t1 = this.fp6Mul(b, s, u);
    const C6 = this.fp6Add(b, t0, t0);
    const vt = this.fp6MulByV(b, t0, 12n);
    const d = this.fp6Sub(b, t1, t0, 12n);
    const C0 = this.fp6Sub(b, d, vt, 13n);
    return [...C0, ...C6];
  },
};

// ---------- DELAYED scheme (V2/V3): wide carry, reduce 12 outputs ----------
const BIGSQR = 507361791401603590146065339884462786506408203206435770960198222587060229213828216047103990131139210776525628370024303086564595223859909885393566267333524240n;
const BIGMUL = 473346033904423368332684188674078595909661288732727612567210428627021252562119744690866504404556704362571480480121380658603450849396234800254307144706265583n;
const D = {
  reduceOut: (b, x, BIG) => MOD(b, ADD(b, x, BIG), P),
  fp2MulW(b, a0,a1, c0,c1) { const w0 = MUL(b,a0,c0), w1 = MUL(b,a1,c1);
    return [ SUB(b,w0,w1), SUB(b, MUL(b, ADD(b,a0,a1), ADD(b,c0,c1)), ADD(b,w0,w1)) ]; },
  fp2MulXiW(b, a0,a1) { return [ SUB(b, MUL(b,9n,a0), a1), ADD(b, MUL(b,9n,a1), a0) ]; },
  fp6MulW(b, a, c) {
    const t0 = this.fp2MulW(b, a[0],a[1], c[0],c[1]);
    const t1 = this.fp2MulW(b, a[2],a[3], c[2],c[3]);
    const t2 = this.fp2MulW(b, a[4],a[5], c[4],c[5]);
    const p1 = this.fp2MulW(b, ADD(b,a[2],a[4]),ADD(b,a[3],a[5]), ADD(b,c[2],c[4]),ADD(b,c[3],c[5]));
    const x1 = this.fp2MulXiW(b, SUB(b,SUB(b,p1[0],t1[0]),t2[0]), SUB(b,SUB(b,p1[1],t1[1]),t2[1]));
    const c0 = [ ADD(b,t0[0],x1[0]), ADD(b,t0[1],x1[1]) ];
    const p2 = this.fp2MulW(b, ADD(b,a[0],a[2]),ADD(b,a[1],a[3]), ADD(b,c[0],c[2]),ADD(b,c[1],c[3]));
    const x2 = this.fp2MulXiW(b, t2[0], t2[1]);
    const c1 = [ ADD(b, SUB(b,SUB(b,p2[0],t0[0]),t1[0]), x2[0]), ADD(b, SUB(b,SUB(b,p2[1],t0[1]),t1[1]), x2[1]) ];
    const p3 = this.fp2MulW(b, ADD(b,a[0],a[4]),ADD(b,a[1],a[5]), ADD(b,c[0],c[4]),ADD(b,c[1],c[5]));
    const c2 = [ ADD(b, SUB(b,SUB(b,p3[0],t0[0]),t2[0]), t1[0]), ADD(b, SUB(b,SUB(b,p3[1],t0[1]),t2[1]), t1[1]) ];
    return [c0[0],c0[1],c1[0],c1[1],c2[0],c2[1]];
  },
  fp6Mul01W(b, c, b0a,b0b, b1a,b1b) {
    const t0 = this.fp2MulW(b, c[0],c[1], b0a,b0b);
    const t1 = this.fp2MulW(b, c[2],c[3], b1a,b1b);
    const m12 = this.fp2MulW(b, ADD(b,c[2],c[4]),ADD(b,c[3],c[5]), b1a,b1b);
    const xu0 = this.fp2MulXiW(b, SUB(b,m12[0],t1[0]), SUB(b,m12[1],t1[1]));
    const r0 = [ ADD(b,xu0[0],t0[0]), ADD(b,xu0[1],t0[1]) ];
    const m1 = this.fp2MulW(b, ADD(b,b0a,b1a),ADD(b,b0b,b1b), ADD(b,c[0],c[2]),ADD(b,c[1],c[3]));
    const r1 = [ SUB(b,SUB(b,m1[0],t0[0]),t1[0]), SUB(b,SUB(b,m1[1],t0[1]),t1[1]) ];
    const m2 = this.fp2MulW(b, ADD(b,c[0],c[4]),ADD(b,c[1],c[5]), b0a,b0b);
    const r2 = [ ADD(b, SUB(b,m2[0],t0[0]), t1[0]), ADD(b, SUB(b,m2[1],t0[1]), t1[1]) ];
    return [r0[0],r0[1],r1[0],r1[1],r2[0],r2[1]];
  },
  fp6MulByVW(b, a) { const n0 = this.fp2MulXiW(b, a[4],a[5]); return [n0[0],n0[1],a[0],a[1],a[2],a[3]]; },
};
// mul034 delayed: c0 = v*B + A ; c1 = G - A - B
D.mul034 = function(b, F, o0a,o0b, o3a,o3b, o4a,o4b) {
  const A0 = this.fp2MulW(b, F[0],F[1], o0a,o0b);
  const A2 = this.fp2MulW(b, F[2],F[3], o0a,o0b);
  const A4 = this.fp2MulW(b, F[4],F[5], o0a,o0b);
  const A = [A0[0],A0[1],A2[0],A2[1],A4[0],A4[1]];
  const B = this.fp6Mul01W(b, [F[6],F[7],F[8],F[9],F[10],F[11]], o3a,o3b, o4a,o4b);
  const G = this.fp6Mul01W(b, [ADD(b,F[0],F[6]),ADD(b,F[1],F[7]),ADD(b,F[2],F[8]),ADD(b,F[3],F[9]),ADD(b,F[4],F[10]),ADD(b,F[5],F[11])],
                           ADD(b,o0a,o3a),ADD(b,o0b,o3b), o4a,o4b);
  const VB = this.fp6MulByVW(b, B);
  const out = [];
  for (let i=0;i<6;i++) out.push(this.reduceOut(b, ADD(b, VB[i], A[i]), BIGMUL));
  for (let i=0;i<6;i++) out.push(this.reduceOut(b, SUB(b, SUB(b, G[i], A[i]), B[i]), BIGMUL));
  return out;
};
D.fp12Mul = function(b, A, Bb) {
  const t0 = this.fp6MulW(b, A.slice(0,6), Bb.slice(0,6));
  const t1 = this.fp6MulW(b, A.slice(6,12), Bb.slice(6,12));
  const vt = this.fp6MulByVW(b, t1);
  const sa = []; for (let i=0;i<6;i++) sa.push(ADD(b, A[i], A[i+6]));
  const sb = []; for (let i=0;i<6;i++) sb.push(ADD(b, Bb[i], Bb[i+6]));
  const pr = this.fp6MulW(b, sa, sb);
  const out = [];
  for (let i=0;i<6;i++) out.push(this.reduceOut(b, ADD(b, t0[i], vt[i]), BIGMUL));
  for (let i=0;i<6;i++) out.push(this.reduceOut(b, SUB(b, SUB(b, pr[i], t0[i]), t1[i]), BIGMUL));
  return out;
};
D.fp12Sqr = function(b, A) {
  const t0 = this.fp6MulW(b, A.slice(0,6), A.slice(6,12));
  const vc = this.fp6MulByVW(b, A.slice(6,12));
  const s = []; for (let i=0;i<6;i++) s.push(ADD(b, A[i], A[i+6]));
  const u = []; for (let i=0;i<6;i++) u.push(ADD(b, A[i], vc[i]));
  const t1 = this.fp6MulW(b, s, u);
  const vt = this.fp6MulByVW(b, t0);
  const out = [];
  for (let i=0;i<6;i++) out.push(this.reduceOut(b, SUB(b, SUB(b, t1[i], t0[i]), vt[i]), BIGSQR));
  for (let i=0;i<6;i++) out.push(this.reduceOut(b, ADD(b, t0[i], t0[i]), BIGSQR));
  return out;
};

// ---- realistic pseudo-random reduced field elements (deterministic splitmix64-ish) ----
let _s = 0x9e3779b97f4a7c15n;
function rndFp() { // ~254-bit reduced element
  let r = 0n;
  for (let i=0;i<4;i++){ _s = (_s * 6364136223846793005n + 1442695040888963407n) & ((1n<<64n)-1n); r = (r<<64n) | _s; }
  return r % P;
}
const F = Array.from({length:12}, () => rndFp());
const o0a=rndFp(),o0b=rndFp(),o3a=rndFp(),o3b=rndFp(),o4a=rndFp(),o4b=rndFp();

function run(label, fn) { const b = mkBill(); fn(b); const oc = opCost(b);
  console.log(`${label.padEnd(22)} instr=${String(b.instr).padStart(4)} muls=${String(b.muls).padStart(3)} mods=${String(b.mods).padStart(3)} adds=${String(b.adds).padStart(4)}  mulOp=${String(b.mulOperand).padStart(6)} modOp=${String(b.modOperand).padStart(6)} arith=${String(b.arith).padStart(7)} push=${String(b.push).padStart(6)}  opCost=${String(oc).padStart(7)}  bytes=${(oc/800).toFixed(1)}`);
  return oc;
}

console.log('=== per-op operationCost (100*instr + arith + push); bytes = opCost/800 ===\n');
const e_034 = run('EAGER mul034',   b => E.mul034(b, F, o0a,o0b,o3a,o3b,o4a,o4b));
const d_034 = run('DELAYED mul034', b => D.mul034(b, F, o0a,o0b,o3a,o3b,o4a,o4b));
console.log(`   -> mul034 delta/op = ${e_034 - d_034} opCost = ${((e_034-d_034)/800).toFixed(1)} bytes ; x264 = ${(264*(e_034-d_034)/800).toFixed(0)} bytes\n`);
const e_sqr = run('EAGER fp12Sqr',   b => E.fp12Sqr(b, F));
const d_sqr = run('DELAYED fp12Sqr', b => D.fp12Sqr(b, F));
console.log(`   -> fp12Sqr delta/op = ${e_sqr - d_sqr} opCost = ${((e_sqr-d_sqr)/800).toFixed(1)} bytes ; x65 = ${(65*(e_sqr-d_sqr)/800).toFixed(0)} bytes\n`);
const Bb = Array.from({length:12}, () => rndFp());
const e_mul = run('EAGER fp12Mul',   b => E.fp12Mul(b, F, Bb));
const d_mul = run('DELAYED fp12Mul', b => D.fp12Mul(b, F, Bb));
console.log(`   -> fp12Mul delta/op = ${e_mul - d_mul} opCost = ${((e_mul-d_mul)/800).toFixed(1)} bytes\n`);

// Miller-core aggregate (mission counts): 264 mul034 + 65 fp12Sqr + a few fp12Mul.
const coreEager = 264*e_034 + 65*e_sqr;
const coreDelay = 264*d_034 + 65*d_sqr;
console.log('=== Miller-core aggregate (264 mul034 + 65 fp12Sqr) ===');
console.log(`EAGER  core opCost = ${coreEager}  (~${(coreEager/800/1000).toFixed(1)}k bytes)`);
console.log(`DELAY  core opCost = ${coreDelay}  (~${(coreDelay/800/1000).toFixed(1)}k bytes)`);
console.log(`SAVINGS = ${coreEager-coreDelay} opCost = ${((coreEager-coreDelay)/800).toFixed(0)} bytes  (${(100*(coreEager-coreDelay)/coreEager).toFixed(1)}%)`);

// single eager mulFp reference
const bref = mkBill(); E.mulFp(bref, P-1n, P-2n); console.log(`\nref: eager mulFp opCost=${opCost(bref)} (arith=${bref.arith}, mulOp=${bref.mulOperand}, modOp=${bref.modOperand})`);
