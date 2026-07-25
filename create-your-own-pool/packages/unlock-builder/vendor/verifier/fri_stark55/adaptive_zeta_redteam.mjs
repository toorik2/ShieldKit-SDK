// Regression for the pre-fix adaptive-zeta break.
//
// The old verifier squeezed a QM31 zeta challenge and then discarded it. A
// prover could therefore choose an on-circle zeta after committing a low-degree
// (here: constant) q and solve q(zeta) V(zeta) = residual(zeta, alpha). This
// forge is deliberately built with the current L2 transcript and deployment
// plumbing. The repaired verifier must reject it because zeta is now the
// rational-map image of the squeezed challenge.
import { P, mod, mul, pow as fpow } from '../fri_stark/m31.mjs';
import { QM31 } from '../fri_stark/qm31.mjs';
import {
  QTranscript, qConj, qRotate, qDeepLine, evalCFFTpointQ, qOodPoint,
} from '../fri_stark/qhelpers.mjs';
import { qFriLowDegreeL2, merkleTreeQ, traceMergeTree, vanishVsmoothQ } from '../fri_stark/qstark.mjs';
import { cfftColumn } from '../fri_stark/cfft.mjs';
import {
  buildDomain, merkleTree,
} from '../fri_stark/fri.mjs';
import {
  fibTrace, traceDomain, traceXs, traceGen, transitionVanisher,
} from '../fri_stark/stark.mjs';
import { init, buildBundle, evaluateBundle, allAccepted, accepted, jsResult } from './common.mjs';

const LOGN = 3;
const LOG_BLOWUP = 3;
const NUM_QUERIES = 5;
const Q = (v) => QM31.fromF(mod(v));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function falseTrace(n) {
  const a = new Array(n); const b = new Array(n);
  a[0] = 1n; b[0] = 1n; a[1] = 1n; b[1] = 3n;
  for (let i = 2; i < n; i++) {
    a[i] = b[i - 1];
    b[i] = mod(a[i - 1] + b[i - 1]);
  }
  return { a, b };
}

// A deterministic base-field circle point. It is intentionally not derived
// from the transcript; that is the attack being regression-tested.
function chooseFreeZeta(domainN, n, xLast, y0) {
  const exponent = (P + 1n) / 4n; // P = 3 mod 4
  for (let x = 2n; x < 100_000n; x++) {
    const rhs = mod(1n - mul(x, x));
    const y = fpow(rhs, exponent);
    if (y === 0n || mul(y, y) !== rhs) continue;
    if (domainN.some((point) => point[0] === x)) continue;
    const zeta = { x: Q(x), y: Q(y) };
    if (QM31.isZero(vanishVsmoothQ(zeta.x, zeta.y, n, xLast, y0))) continue;
    return zeta;
  }
  throw new Error('could not find deterministic free zeta');
}

function forgeAdaptiveZeta() {
  const n = 1 << LOGN;
  const logN = LOGN + LOG_BLOWUP;
  const N = 1 << logN;
  const domainNat = buildDomain(logN);
  const H = traceDomain(LOGN);
  const traceX = traceXs(LOGN);
  const g_n = traceGen(n);
  const H0 = H[0];
  const HL = H[n - 1];
  const vCoef = transitionVanisher(LOGN);
  const { a, b } = falseTrace(n);
  const c0col = cfftColumn(H, domainNat, a);
  const c1col = cfftColumn(H, domainNat, b);

  // Current deployment uses reflection-pair order: the FRI J partners are
  // adjacent and each trace leaf commits c0 and c1 together.
  const perm = new Array(N);
  for (let k = 0; k < N / 2; k++) {
    perm[2 * k] = k;
    perm[2 * k + 1] = N - 1 - k;
  }
  const domainN = perm.map((oldIndex) => domainNat[oldIndex]);
  const c0lde = perm.map((oldIndex) => c0col.lde[oldIndex]);
  const c1lde = perm.map((oldIndex) => c1col.lde[oldIndex]);
  const c0tree = merkleTree(c0lde);
  const c1tree = merkleTree(c1lde);
  const traceTree = traceMergeTree(c0lde, c1lde);
  const target = evalCFFTpointQ(c1col.coeffs, Q(HL[0]), Q(HL[1])).c0.a;

  const tr = new QTranscript();
  tr.absorbF(target);
  tr.absorb(traceTree.root);
  const alpha = tr.challengeQM31();

  // Pick the attacker's free zeta before the q commitment. q is constant, so
  // it is genuinely low degree and the DEEP/FRI portion can remain coherent.
  const zeta = chooseFreeZeta(domainN, n, HL[0], H0[1]);
  const conjZeta = qConj(zeta);
  const zetaNext = qRotate(zeta, g_n);
  const conjZetaNext = qConj(zetaNext);
  const evQ0 = (point) => evalCFFTpointQ(c0col.coeffs, point.x, point.y);
  const evQ1 = (point) => evalCFFTpointQ(c1col.coeffs, point.x, point.y);
  const c0_z = evQ0(zeta); const c0_zc = evQ0(conjZeta);
  const c1_z = evQ1(zeta); const c1_zc = evQ1(conjZeta);
  const c0_zn = evQ0(zetaNext); const c0_znc = evQ0(conjZetaNext);
  const c1_zn = evQ1(zetaNext); const c1_znc = evQ1(conjZetaNext);
  const Vz = vanishVsmoothQ(zeta.x, zeta.y, n, HL[0], H0[1]);
  const residual = QM31.add(
    QM31.sub(c0_zn, c1_z),
    QM31.mul(alpha, QM31.sub(c1_zn, QM31.add(c0_z, c1_z))),
  );
  const qConst = QM31.mul(residual, QM31.inv(Vz));
  const qlde = Array.from({ length: N }, () => qConst);
  const qtree = merkleTreeQ(qlde);

  // The old transcript absorbed the prover-chosen zeta, then continued
  // honestly. This produces a fully shaped proof; only the zeta derivation is
  // invalid under the repaired protocol.
  tr.absorb(qtree.root);
  const zetaChallenge = tr.challengeQM31();
  tr.absorbQ(zeta.x); tr.absorbQ(zeta.y);
  const c0_b0 = evQ0({ x: Q(H0[0]), y: Q(H0[1]) });
  const c0_b0c = evQ0({ x: Q(H0[0]), y: Q(mod(-H0[1])) });
  const c1_b0 = evQ1({ x: Q(H0[0]), y: Q(H0[1]) });
  const c1_b0c = evQ1({ x: Q(H0[0]), y: Q(mod(-H0[1])) });
  const c1_bL = evQ1({ x: Q(HL[0]), y: Q(HL[1]) });
  const c1_bLc = evQ1({ x: Q(HL[0]), y: Q(mod(-HL[1])) });
  const ood = {
    c0_z, c0_zc, c1_z, c1_zc, c0_zn, c0_znc, c1_zn, c1_znc,
    q_z: qConst, q_zc: qConst,
    c0_b0, c0_b0c, c1_b0, c1_b0c, c1_bL, c1_bLc,
  };
  for (const value of Object.values(ood)) tr.absorbQ(value);
  const gammas = Array.from({ length: 8 }, () => tr.challengeQM31());
  const lines = {
    L_c0z: qDeepLine(c0_z, c0_zc, zeta.y),
    L_c1z: qDeepLine(c1_z, c1_zc, zeta.y),
    L_qz: qDeepLine(qConst, qConst, zeta.y),
    L_c0zn: qDeepLine(c0_zn, c0_znc, zetaNext.y),
    L_c1zn: qDeepLine(c1_zn, c1_znc, zetaNext.y),
    L_c0b0: qDeepLine(c0_b0, c0_b0c, Q(H0[1])),
    L_c1b0: qDeepLine(c1_b0, c1_b0c, Q(H0[1])),
    L_c1bL: qDeepLine(c1_bL, c1_bLc, Q(HL[1])),
  };
  const deep = domainN.map(([x, y], index) => {
    const c0 = Q(c0lde[index]);
    const c1 = Q(c1lde[index]);
    const yQ = Q(y);
    const ixZ = QM31.inv(QM31.sub(Q(x), zeta.x));
    const ixZn = QM31.inv(QM31.sub(Q(x), zetaNext.x));
    const ixB0 = QM31.inv(QM31.sub(Q(x), Q(H0[0])));
    const ixBL = QM31.inv(QM31.sub(Q(x), Q(HL[0])));
    const term = (value, line, inverse) => QM31.mul(
      QM31.sub(value, QM31.add(line.A, QM31.mul(line.B, yQ))), inverse,
    );
    const terms = [
      term(c0, lines.L_c0z, ixZ), term(c1, lines.L_c1z, ixZ),
      term(qConst, lines.L_qz, ixZ), term(c0, lines.L_c0zn, ixZn),
      term(c1, lines.L_c1zn, ixZn), term(c0, lines.L_c0b0, ixB0),
      term(c1, lines.L_c1b0, ixB0), term(c1, lines.L_c1bL, ixBL),
    ];
    return terms.reduce((acc, value, i) => QM31.add(acc, QM31.mul(gammas[i], value)), QM31.zero());
  });
  const fri = qFriLowDegreeL2(deep, domainN, logN, LOGN, tr, NUM_QUERIES, N);

  const derivedZeta = qOodPoint(zetaChallenge, domainN);
  assert(!QM31.eq(zeta.x, derivedZeta.x) || !QM31.eq(zeta.y, derivedZeta.y), 'free zeta accidentally derived');
  return {
    L2: true, smoothV: true, logn: LOGN, logBlowup: LOG_BLOWUP, logN, n, N,
    blowup: 1 << LOG_BLOWUP, numQueries: NUM_QUERIES, target, domainN, H, traceX,
    g_n, H0, HL, vCoef, xLast: HL[0], y0: H0[1],
    c0tree, c1tree, traceTree, qtree, c0lde, c1lde, qlde,
    c0coeffs: c0col.coeffs, c1coeffs: c1col.coeffs, alpha,
    zetaChallenge, zeta, conjZeta, zetaNext, conjZetaNext, gammas, lines, ood,
    q: deep, fri,
  };
}

await init();
const forged = forgeAdaptiveZeta();
const honestTarget = fibTrace(1 << LOGN).target;
assert(forged.target !== honestTarget, `adaptive forge target unexpectedly honest (${honestTarget})`);
const js = jsResult(forged);
assert(js.ok === false && js.why === 'zeta mismatch', `adaptive zeta JS result: ${JSON.stringify(js)}`);
const bundle = buildBundle(forged);
const states = evaluateBundle(bundle, true);
assert(!allAccepted(states), 'adaptive zeta forge accepted on every standard BCH input');
const rejected = states.filter((state) => !accepted(state)).length;
console.log(`adaptive-zeta false trace: target=${forged.target} (honest=${honestTarget}); JS REJECT (${js.why}) + standard BCH VM REJECT (${rejected}/${states.length} inputs)`);
console.log('adaptive-zeta regression PASS: the pre-fix free-zeta forge is no longer accepted');
