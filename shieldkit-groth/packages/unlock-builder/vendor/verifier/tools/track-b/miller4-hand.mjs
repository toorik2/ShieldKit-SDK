import { repoPath as vcRepoPath } from '#repo-paths';
// Track B — HAND-WRITTEN SHARED 4-pair BN254 Miller loop (the full prize).
// ONE shared f and ONE shared f^2 per NAF step serve all 4 pairs (vs cashc's 4 separate
// chains = 260 squarings). 36-var frame (f12 + 4*R6) hand-managed on miller.cash's tower.
// Gated vs noble: product of the 4 single-pair Miller boundaries.
import { execFileSync } from 'node:child_process';
import { hexToBin } from '../../node_modules/@bitauth/libauth/build/index.js';
import { bytecodeToScript, scriptToBytecode } from '../../vendor/cashc-resched/packages/utils/dist/index.js';
import { push, measure, O } from './asm-measure.mjs';
import { pathToFileURL } from 'node:url';

const { bn254 } = await import(pathToFileURL(vcRepoPath('node_modules/@noble/curves/esm/bn254.js')).href);
const Fp12 = bn254.fields.Fp12;
const f12 = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
                    x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];
const CLI = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');
const MIL = vcRepoPath('build/singleton/bn254/miller.cash');

const s = bytecodeToScript(hexToBin(execFileSync('node', [CLI, MIL, '-h'], { encoding: 'utf8' }).trim()));
let lastDef = -1; for (let i = 0; i < s.length; i++) if (s[i] === 0x89) lastDef = i;
const tableBc = scriptToBytecode(s.slice(0, lastDef + 1));
const ID = { fp12Sqr: 20, pointDouble: 23, line: 22, fp2Neg: 6, pointAdd: 24, psi: 25 };

// 4 test pairs + product boundary
const scalars = [[0x4242424242n, 0x1337133713n], [0x9999n, 0xabcdn], [0x55aa55aan, 0x73737373n], [0x12345n, 0x6789an]];
const pairs = scalars.map(([sg1, sg2]) => {
  const Pp = bn254.G1.ProjectivePoint.BASE.multiply(sg1).toAffine();
  const Qp = bn254.G2.ProjectivePoint.BASE.multiply(sg2).toAffine();
  const m = bn254.pairing(bn254.G1.ProjectivePoint.fromAffine(Pp), bn254.G2.ProjectivePoint.fromAffine(Qp), false);
  return { Px: Pp.x, Py: Pp.y, Qxa: Qp.x.c0, Qxb: Qp.x.c1, Qya: Qp.y.c0, Qyb: Qp.y.c1, m };
});
const boundary = pairs.reduce((acc, p) => Fp12.mul(acc, p.m), Fp12.ONE);
const Mexp = f12(boundary);
const nz = (k) => Number((3045737938581365386n >> BigInt(k)) & 1n);
const neg = (k) => Number((162306075919524482n >> BigInt(k)) & 1n);

function build() {
  const code = []; const Mod = []; let uniq = 0;
  const emit = (...b) => b.flat(Infinity).forEach((x) => code.push(x));
  const pushv = (v, name) => { emit(push(v)); Mod.unshift(name); };
  const call = (fnId, args, outNames) => {
    for (let i = args.length - 1; i >= 0; i--) {
      if (args[i].lit !== undefined) { emit(push(args[i].lit)); Mod.unshift('#l' + (uniq++)); continue; }
      const d = Mod.indexOf(args[i].name);
      if (d < 0) throw new Error('arg missing: ' + args[i].name);
      emit(push(d), args[i].mode === 'roll' ? O.OP_ROLL : O.OP_PICK);
      if (args[i].mode === 'roll') { Mod.splice(d, 1); Mod.unshift(args[i].name); }
      else { Mod.unshift('$' + (uniq++)); }
    }
    emit(push(fnId), O.OP_INVOKE);
    Mod.splice(0, args.length);
    for (let i = 1; i < outNames.length; i++) emit(push(i), O.OP_ROLL);
    for (let i = outNames.length - 1; i >= 0; i--) Mod.unshift(outNames[i]);
  };
  const roll = (names) => names.map((name) => ({ name, mode: 'roll' }));
  const pick = (names) => names.map((name) => ({ name, mode: 'pick' }));
  const F = Array.from({ length: 12 }, (_, i) => 'F' + i);
  const R = (i) => [`R${i}xa`, `R${i}xb`, `R${i}ya`, `R${i}yb`, `R${i}za`, `R${i}zb`];
  const lineArgs = (i, coeffs) => [...roll(F), ...roll(coeffs), { name: `Px${i}`, mode: 'pick' }, { name: `Py${i}`, mode: 'pick' }];

  // init: 4*(constants) deepest, then 4*R, then f on top
  for (let i = 0; i < 4; i++) {
    const p = pairs[i];
    pushv(p.Py, `Py${i}`); pushv(p.Px, `Px${i}`);
    pushv(p.Qyb, `Qyb${i}`); pushv(p.Qya, `Qya${i}`); pushv(p.Qxb, `Qxb${i}`); pushv(p.Qxa, `Qxa${i}`);
  }
  for (let i = 0; i < 4; i++) {
    const p = pairs[i];
    pushv(p.Qxb, `R${i}xb`); pushv(p.Qxa, `R${i}xa`); pushv(p.Qyb, `R${i}yb`); pushv(p.Qya, `R${i}ya`); pushv(0, `R${i}zb`); pushv(1, `R${i}za`);
  }
  for (let i = 0; i < 12; i++) pushv(i === 0 ? 1 : 0, 'F' + i);

  const KMAX = process.env.KMAX ? +process.env.KMAX : 65;
  const DBG = !!process.env.DBG;
  for (let k = 0; k < KMAX; k++) {
    call(ID.fp12Sqr, roll(F), F);                              // ONE shared squaring
    for (let i = 0; i < 4; i++) {
      const dc = [0, 1, 2, 3, 4, 5].map((j) => `d${i}_${j}`);
      call(ID.pointDouble, roll(R(i)), [...dc, ...R(i)]);
      call(ID.line, lineArgs(i, dc), F);
    }
    if (nz(k)) {
      for (let i = 0; i < 4; i++) {
        let uy = [`Qya${i}`, `Qyb${i}`], uyMode = 'pick';
        if (neg(k)) { call(ID.fp2Neg, [...pick([`Qya${i}`, `Qyb${i}`]), { lit: 64 }], [`u${i}a`, `u${i}b`]); uy = [`u${i}a`, `u${i}b`]; uyMode = 'roll'; }
        const ac = [0, 1, 2, 3, 4, 5].map((j) => `a${i}_${j}`);
        call(ID.pointAdd, [...roll(R(i)), { name: `Qxa${i}`, mode: 'pick' }, { name: `Qxb${i}`, mode: 'pick' },
          { name: uy[0], mode: uyMode }, { name: uy[1], mode: uyMode }], [...ac, ...R(i)]);
        call(ID.line, lineArgs(i, ac), F);
      }
    }
  }
  if (!DBG) for (let i = 0; i < 4; i++) {
    call(ID.psi, pick([`Qxa${i}`, `Qxb${i}`, `Qya${i}`, `Qyb${i}`]), [`q1${i}xa`, `q1${i}xb`, `q1${i}ya`, `q1${i}yb`]);
    const bc = [0, 1, 2, 3, 4, 5].map((j) => `b${i}_${j}`);
    call(ID.pointAdd, [...roll(R(i)), ...pick([`q1${i}xa`, `q1${i}xb`, `q1${i}ya`, `q1${i}yb`])], [...bc, ...R(i)]);
    call(ID.line, lineArgs(i, bc), F);
    call(ID.psi, roll([`q1${i}xa`, `q1${i}xb`, `q1${i}ya`, `q1${i}yb`]), [`q2${i}xa`, `q2${i}xb`, `q2${i}ya`, `q2${i}yb`]);
    call(ID.fp2Neg, [...roll([`q2${i}ya`, `q2${i}yb`]), { lit: 64 }], [`q2${i}nya`, `q2${i}nyb`]);
    const cc = [0, 1, 2, 3, 4, 5].map((j) => `c${i}_${j}`);
    call(ID.pointAdd, [...roll(R(i)), ...roll([`q2${i}xa`, `q2${i}xb`]), ...roll([`q2${i}nya`, `q2${i}nyb`])], [...cc, ...R(i)]);
    call(ID.line, lineArgs(i, cc), F);
  }
  const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
  if (DBG) { for (let i = 0; i < Mod.length; i++) emit(O.OP_DROP); emit(O.OP_1); return Uint8Array.from([...tableBc, ...code]); }
  for (let i = 0; i < 12; i++) { if (Mod[0] !== 'F' + i) throw new Error('want F' + i + ' got ' + Mod[0]); emit(push(P), O.OP_MOD, push(Mexp[i]), O.OP_NUMEQUAL, O.OP_VERIFY); Mod.shift(); }
  for (let i = 0; i < Mod.length; i++) emit(O.OP_DROP);
  emit(O.OP_1);
  return Uint8Array.from([...tableBc, ...code]);
}

const r = measure(build());
console.log('HAND SHARED 4-pair Miller:', JSON.stringify({ accepted: r.accepted, opCost: r.opCost, arith: r.arith, base: r.instr * 100, instr: r.instr, bytes: r.bytes, error: r.error }));
const C = 709563868, LZ = 641112329, DS = 590284226;
if (r.accepted) console.log('  vs cashc miller4', C.toLocaleString(), '=', (100 * (C - r.opCost) / C).toFixed(1) + '% | vs lazy', LZ.toLocaleString(), '| vs dedsqr', DS.toLocaleString());
console.log('  gate', r.accepted ? 'GREEN' : 'RED', r.error || '');
