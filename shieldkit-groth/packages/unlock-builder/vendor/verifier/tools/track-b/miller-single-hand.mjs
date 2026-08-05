import { repoPath as vcRepoPath } from '#repo-paths';
// Track B — HAND-WRITTEN single-pair BN254 optimal-ate Miller loop.
// Reuses miller.cash's verbatim OP_DEFINE'd tower (correct field math). Hand-emits the
// loop as a tracked stack frame: f(12)+R(6) live on the main stack above the persistent
// constants (Px,Py,Qx,Qy); each field op is OP_INVOKE'd with args marshalled to the top
// (ROLL for consumed state, PICK for constants) and outputs reversed (cashc functions
// mirror arg order: consume arg0-on-top, produce out0-on-bottom). UNROLLED 65 NAF steps
// (schedule baked at gen-time). Gated vs noble single-pair Miller boundary.
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

// ---- extract miller.cash's function table ----
const s = bytecodeToScript(hexToBin(execFileSync('node', [CLI, MIL, '-h'], { encoding: 'utf8' }).trim()));
let lastDef = -1; for (let i = 0; i < s.length; i++) if (s[i] === 0x89) lastDef = i;
const tableBc = scriptToBytecode(s.slice(0, lastDef + 1));
const ID = { fp12Sqr: 20, pointDouble: 23, line: 22, fp2Neg: 6, pointAdd: 24, psi: 25 };

// ---- test pair + golden single-pair Miller boundary ----
const Pp = bn254.G1.ProjectivePoint.BASE.multiply(0x4242424242n).toAffine();
const Qp = bn254.G2.ProjectivePoint.BASE.multiply(0x1337133713n).toAffine();
const Px = Pp.x, Py = Pp.y, Qxa = Qp.x.c0, Qxb = Qp.x.c1, Qya = Qp.y.c0, Qyb = Qp.y.c1;
const boundary = bn254.pairing(bn254.G1.ProjectivePoint.fromAffine(Pp), bn254.G2.ProjectivePoint.fromAffine(Qp), false);
const M = f12(boundary);
const nz = (k) => Number((3045737938581365386n >> BigInt(k)) & 1n);
const neg = (k) => Number((162306075919524482n >> BigInt(k)) & 1n);

function build() {
  const code = []; const Mod = []; let uniq = 0;
  const emit = (...b) => b.flat(Infinity).forEach((x) => code.push(x));
  const pushv = (v, name) => { emit(push(v)); Mod.unshift(name); };
  // call(fnId, args=[{name,mode}], outNames). marshals arg0→top, INVOKE, reverses outputs.
  const call = (fnId, args, outNames) => {
    for (let i = args.length - 1; i >= 0; i--) {
      if (args[i].lit !== undefined) { emit(push(args[i].lit)); Mod.unshift('#lit' + (uniq++)); continue; }
      const d = Mod.indexOf(args[i].name);
      if (d < 0) throw new Error('arg missing: ' + args[i].name + ' | M=' + Mod.slice(0, 8));
      emit(push(d), args[i].mode === 'roll' ? O.OP_ROLL : O.OP_PICK);
      if (args[i].mode === 'roll') { Mod.splice(d, 1); Mod.unshift(args[i].name); }
      else { Mod.unshift('$' + (uniq++)); }
    }
    emit(push(fnId), O.OP_INVOKE);
    Mod.splice(0, args.length);                       // consume the N args
    const n = outNames.length;
    for (let i = 1; i < n; i++) emit(push(i), O.OP_ROLL); // reverse top n (un-mirror)
    for (let i = n - 1; i >= 0; i--) Mod.unshift(outNames[i]); // outNames[0] ends on top
  };
  const F = Array.from({ length: 12 }, (_, i) => 'F' + i);
  const R = ['Rxa', 'Rxb', 'Rya', 'Ryb', 'Rza', 'Rzb'];
  const roll = (names) => names.map((name) => ({ name, mode: 'roll' }));
  const pick = (names) => names.map((name) => ({ name, mode: 'pick' }));

  // init: constants deepest, then R, then f on top
  pushv(Py, 'Py'); pushv(Px, 'Px');
  pushv(Qyb, 'Qyb'); pushv(Qya, 'Qya'); pushv(Qxb, 'Qxb'); pushv(Qxa, 'Qxa');
  pushv(Qxb, 'Rxb'); pushv(Qxa, 'Rxa'); // R = (Qx, Qy, 1) — push so names exist
  pushv(Qyb, 'Ryb'); pushv(Qya, 'Rya'); pushv(0, 'Rzb'); pushv(1, 'Rza');
  for (let i = 0; i < 12; i++) pushv(i === 0 ? 1 : 0, 'F' + i); // f = ONE
  // reorder note: names are tracked, physical order irrelevant.

  const dbl = ['dc0', 'dc1', 'dc2', 'dc3', 'dc4', 'dc5'];
  const lineArgs = (coeffs) => [...roll(F), ...roll(coeffs), { name: 'Px', mode: 'pick' }, { name: 'Py', mode: 'pick' }];

  const KMAX = process.env.KMAX ? +process.env.KMAX : 65;
  const DBG = !!process.env.DBG;
  for (let k = 0; k < KMAX; k++) {
    call(ID.fp12Sqr, roll(F), F);                                   // f = f^2
    call(ID.pointDouble, roll(R), [...dbl, ...R]);                  // (coeffs, R) = double(R)
    call(ID.line, lineArgs(dbl), F);                                // f = line(f, coeffs, P)
    if (nz(k)) {
      let uy = ['Qya', 'Qyb'], uyMode = 'pick';
      if (neg(k)) { call(ID.fp2Neg, [...pick(['Qya', 'Qyb']), { lit: 64 }], ['uya', 'uyb']); uy = ['uya', 'uyb']; uyMode = 'roll'; }
      const ac = ['ac0', 'ac1', 'ac2', 'ac3', 'ac4', 'ac5'];
      call(ID.pointAdd,
        [...roll(R), { name: 'Qxa', mode: 'pick' }, { name: 'Qxb', mode: 'pick' },
         { name: uy[0], mode: uyMode }, { name: uy[1], mode: uyMode }], [...ac, ...R]);
      call(ID.line, lineArgs(ac), F);
    }
  }
  if (DBG) { for (let i = 0; i < Mod.length; i++) emit(O.OP_DROP); emit(O.OP_1); return Uint8Array.from([...tableBc, ...code]); }
  // postPrecompute
  call(ID.psi, pick(['Qxa', 'Qxb', 'Qya', 'Qyb']), ['q1xa', 'q1xb', 'q1ya', 'q1yb']);
  const bc = ['bc0', 'bc1', 'bc2', 'bc3', 'bc4', 'bc5'];
  call(ID.pointAdd, [...roll(R), ...pick(['q1xa', 'q1xb', 'q1ya', 'q1yb'])], [...bc, ...R]);
  call(ID.line, lineArgs(bc), F);
  call(ID.psi, roll(['q1xa', 'q1xb', 'q1ya', 'q1yb']), ['q2xa', 'q2xb', 'q2ya', 'q2yb']);
  call(ID.fp2Neg, [...roll(['q2ya', 'q2yb']), { lit: 64 }], ['q2nya', 'q2nyb']);
  const cc = ['cc0', 'cc1', 'cc2', 'cc3', 'cc4', 'cc5'];
  call(ID.pointAdd, [...roll(R), ...roll(['q2xa', 'q2xb']), ...roll(['q2nya', 'q2nyb'])], [...cc, ...R]);
  call(ID.line, lineArgs(cc), F);

  // verify F % P == M (F0 on top), then drop the rest, leave [1]
  const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
  for (let i = 0; i < 12; i++) {
    if (Mod[0] !== 'F' + i) throw new Error('expected F' + i + ' on top, got ' + Mod[0]);
    emit(push(P), O.OP_MOD, push(M[i]), O.OP_NUMEQUAL, O.OP_VERIFY); Mod.shift();
  }
  for (let i = 0; i < Mod.length; i++) emit(O.OP_DROP);
  emit(O.OP_1);
  return Uint8Array.from([...tableBc, ...code]);
}

const prog = build();
const r = measure(prog);
console.log('HAND single-pair Miller (unrolled 65):', JSON.stringify({ accepted: r.accepted, opCost: r.opCost, arith: r.arith, base: r.instr * 100, instr: r.instr, bytes: r.bytes, error: r.error }));
console.log('  vs miller.cash baseline (single-pair) — gate', r.accepted ? 'GREEN' : 'RED', r.error || '');
