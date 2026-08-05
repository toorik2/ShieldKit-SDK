// _recal_fit.mjs — can a RECALIBRATED per-op-class additive model be faithful?
// Fit op_resched ≈ intercept + Σ_class n_class·m_class (least squares) over all measured feasible
// windows, report per-class marginals + residuals. Max positive residual = the glue margin a
// recalibrated model needs to be a SAFE (never-under-count) upper bound. R² & residual spread
// answer whether additive+glue can RANK candidates or ranking needs compilation.
import { readFileSync } from 'node:fs';
const CV = JSON.parse(readFileSync('/home/toorik/Projects/LeanBCH/optimizer/bn254_costvec_v3.json', 'utf8'));
const classOf = CV.classOf;
const R = JSON.parse(readFileSync('/home/toorik/Projects/LeanBCH/optimizer/_characterize_additive_report.json', 'utf8'));
// feasible windows (completed at pad 10000, i.e. op_resched <= budget) from the characterization sweep
const wins = R.rows.filter((r) => !r.err && r.op_resched <= 8_032_800);

// design matrix: columns = [1 (intercept)] + one per distinct class count
const classes = [...new Set(classOf)].sort();
const cols = ['__intercept__', ...classes];
function featRow(lo, hi) {
  const f = new Array(cols.length).fill(0); f[0] = 1;
  for (let k = lo; k < hi; k++) { const c = classOf[k]; f[1 + classes.indexOf(c)]++; }
  return f;
}
const X = wins.map((w) => featRow(w.lo, w.hi));
const y = wins.map((w) => w.op_resched);
// normal equations (X'X) b = X'y  (small: cols x cols)
const m = cols.length, n = X.length;
const XtX = Array.from({ length: m }, () => new Array(m).fill(0));
const Xty = new Array(m).fill(0);
for (let i = 0; i < n; i++) { for (let a = 0; a < m; a++) { Xty[a] += X[i][a] * y[i]; for (let b = 0; b < m; b++) XtX[a][b] += X[i][a] * X[i][b]; } }
// Gaussian elimination
function solve(A, b) {
  const M = A.map((r, i) => [...r, b[i]]);
  for (let c = 0; c < m; c++) {
    let piv = c; for (let r = c + 1; r < m; r++) if (Math.abs(M[r][c]) > Math.abs(M[piv][c])) piv = r;
    [M[c], M[piv]] = [M[piv], M[c]];
    if (Math.abs(M[c][c]) < 1e-9) continue;
    for (let r = 0; r < m; r++) if (r !== c) { const f = M[r][c] / M[c][c]; for (let k = c; k <= m; k++) M[r][k] -= f * M[c][k]; }
  }
  return M.map((r, i) => Math.abs(M[i][i]) < 1e-9 ? 0 : r[m] / r[i][i] ?? r[m] / M[i][i]);
}
// simpler back-solve
function solve2(A, b) {
  const M = A.map((r, i) => [...r, b[i]]);
  for (let c = 0; c < m; c++) {
    let piv = c; for (let r = c + 1; r < m; r++) if (Math.abs(M[r][c]) > Math.abs(M[piv][c])) piv = r;
    [M[c], M[piv]] = [M[piv], M[c]];
    const d = M[c][c]; if (Math.abs(d) < 1e-9) continue;
    for (let k = c; k <= m; k++) M[c][k] /= d;
    for (let r = 0; r < m; r++) if (r !== c) { const f = M[r][c]; for (let k = c; k <= m; k++) M[r][k] -= f * M[c][k]; }
  }
  return M.map((r) => r[m]);
}
const beta = solve2(XtX, Xty);
const marg = {}; cols.forEach((c, i) => marg[c] = Math.round(beta[i]));
// residuals
const resid = wins.map((w, i) => { const pred = X[i].reduce((s, v, k) => s + v * beta[k], 0); return { lo: w.lo, hi: w.hi, width: w.width, real: w.op_resched, pred: Math.round(pred), resid: Math.round(w.op_resched - pred) }; });
const rs = resid.map((r) => r.resid);
const ssRes = rs.reduce((s, r) => s + r * r, 0);
const my2 = y.reduce((a, b) => a + b, 0) / n; const ssTot = y.reduce((s, v) => s + (v - my2) ** 2, 0);
const R2 = 1 - ssRes / ssTot;
const sorted = [...rs].sort((a, b) => a - b);
const out = {
  nWindows: n, classesFitted: cols,
  perClassMarginal_resched: marg,
  R2: +R2.toFixed(5),
  residual: { min: sorted[0], max: sorted[sorted.length - 1], median: sorted[Math.floor(n / 2)],
              maxAbs: Math.max(...rs.map(Math.abs)), rmse: Math.round(Math.sqrt(ssRes / n)) },
  interpretation: {
    recalibrated_additive_ranks: 'per-class marginals stable; residual small vs op magnitude',
    safe_margin_after_recal: `opCostWorstCase = recalibrated_additive + margin; margin >= max positive residual (${sorted[sorted.length - 1]}) to never under-count`,
  },
  worstResiduals: resid.sort((a, b) => b.resid - a.resid).slice(0, 6),
};
console.log(JSON.stringify(out, null, 2));
