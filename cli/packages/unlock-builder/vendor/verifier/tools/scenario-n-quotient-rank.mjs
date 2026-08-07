#!/usr/bin/env node
// Rank/sparsity probe for Scenario N's structured-bigQ idea.
//
// Usage:
//   SCENARIO_N_PAIRING_DIR=/path/to/build/chunked/pairing \
//     node tools/scenario-n-quotient-rank.mjs
//
// Optional:
//   SCENARIO_N_INSTANCES=default,worstcase,idx1,idx2,idx3
//
// This measures the honest per-step quotients q_i where:
//   q_i = (tower(chain_i)^2 * product(factors_i) - tower(chain_{i+1})) / P12
// and bigQ = sum_i gamma^i q_i.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const pairingDir = process.env.SCENARIO_N_PAIRING_DIR;
if (!pairingDir) {
  throw new Error('set SCENARIO_N_PAIRING_DIR to the build/chunked/pairing directory');
}
const szPath = join(pairingDir, '_szmath.mjs');
if (!existsSync(szPath)) throw new Error(`missing ${szPath}`);

const instanceSpec = (process.env.SCENARIO_N_INSTANCES ?? 'default,worstcase,idx1,idx2,idx3')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const bitLength = (x) => {
  const v = x < 0n ? -x : x;
  return v === 0n ? 0 : v.toString(2).length;
};

const quantiles = (xs) => {
  const ys = [...xs].sort((a, b) => a - b);
  const at = (p) => ys[Math.min(ys.length - 1, Math.floor(p * (ys.length - 1)))] ?? 0;
  return { min: ys[0] ?? 0, p25: at(0.25), median: at(0.5), p75: at(0.75), max: ys[ys.length - 1] ?? 0 };
};

function rankFp(rows, width, mod, minv, mmul, msub) {
  const A = rows
    .map((row) => Array.from({ length: width }, (_, i) => mod(row[i] ?? 0n)))
    .filter((row) => row.some((x) => x !== 0n));
  let r = 0;
  const pivots = [];
  for (let c = 0; c < width && r < A.length; c++) {
    let piv = -1;
    for (let i = r; i < A.length; i++) {
      if (A[i][c] !== 0n) { piv = i; break; }
    }
    if (piv < 0) continue;
    [A[r], A[piv]] = [A[piv], A[r]];
    const inv = minv(A[r][c]);
    for (let j = c; j < width; j++) A[r][j] = mmul(A[r][j], inv);
    for (let i = 0; i < A.length; i++) {
      if (i === r || A[i][c] === 0n) continue;
      const f = A[i][c];
      for (let j = c; j < width; j++) A[i][j] = msub(A[i][j], mmul(f, A[r][j]));
    }
    pivots.push(c);
    r++;
  }
  return { rank: r, pivots };
}

function pad(poly, width) {
  return Array.from({ length: width }, (_, i) => poly[i] ?? 0n);
}

async function loadSzFor(label, ordinal) {
  if (label === 'default') {
    delete process.env.ELIG_INSTANCE;
    delete process.env.ELIG_IDX;
  } else if (label === 'worstcase') {
    process.env.ELIG_INSTANCE = 'worstcase';
    delete process.env.ELIG_IDX;
  } else {
    const m = /^idx(\d+)$/.exec(label);
    if (!m) throw new Error(`unknown instance label: ${label}`);
    process.env.ELIG_INSTANCE = 'proof';
    process.env.ELIG_IDX = m[1];
  }
  const url = `${pathToFileURL(szPath).href}?scenarioNRank=${ordinal}-${encodeURIComponent(label)}-${Date.now()}`;
  return import(url);
}

function quotientRows(sz, t) {
  const rows = [];
  const remainders = [];
  for (let i = 0; i < t.statementFactors.length; i++) {
    const pin = sz.towerToPoly(t.chain[i]);
    let lhs = sz.pmul(pin, pin);
    for (const fp of t.statementFactors[i]) lhs = sz.pmul(lhs, fp);
    const divided = sz.pdivP12(sz.psub(lhs, sz.towerToPoly(t.chain[i + 1])));
    rows.push(divided.q.map(sz.mod));
    remainders.push(divided.r.map(sz.mod));
  }
  return { rows, remainders };
}

function aggregate(rows, gamma, width, sz) {
  let ci = 1n;
  let acc = [0n];
  for (const row of rows) {
    acc = sz.padd(acc, sz.pscale(row, ci));
    ci = sz.mmul(ci, gamma);
  }
  return pad(acc.map(sz.mod), width);
}

const allRows = [];
const allBigQs = [];
const instanceSummaries = [];
let fieldBits = 0;
let globalWidth = 0;
let rankFns = null;

for (let ordinal = 0; ordinal < instanceSpec.length; ordinal++) {
  const label = instanceSpec[ordinal];
  const sz = await loadSzFor(label, ordinal);
  rankFns ??= sz;
  fieldBits = bitLength(sz.P);
  const t = sz.trajectory();
  const { rows, remainders } = quotientRows(sz, t);
  const width = Math.max(t.bigQ.length, ...rows.map((r) => r.length));
  globalWidth = Math.max(globalWidth, width);
  const paddedRows = rows.map((r) => pad(r, width));
  const recomposed = aggregate(rows, t.gamma, width, sz);
  const bigQ = pad(t.bigQ.map(sz.mod), width);
  const recomposes = recomposed.every((x, i) => x === bigQ[i]);
  const remainderOk = remainders.every((r) => r.every((x) => x === 0n));
  const nonzeroCounts = paddedRows.map((r) => r.filter((x) => x !== 0n).length);
  const degrees = paddedRows.map((r) => {
    for (let i = r.length - 1; i >= 0; i--) if (r[i] !== 0n) return i;
    return -1;
  });
  const coeffBitLengths = paddedRows.flatMap((r) => r.filter((x) => x !== 0n).map(bitLength));
  const bigQCoeffBits = bigQ.filter((x) => x !== 0n).map(bitLength);
  const support = new Set();
  paddedRows.forEach((r) => r.forEach((x, i) => { if (x !== 0n) support.add(i); }));
  const byFactorCount = new Map();
  t.steps.forEach((step, i) => {
    const k = step.factors.length;
    if (!byFactorCount.has(k)) byFactorCount.set(k, []);
    byFactorCount.get(k).push(paddedRows[i]);
  });
  const rankAll = rankFp(paddedRows, width, sz.mod, sz.minv, sz.mmul, sz.msub);
  const rankByFactorCount = Object.fromEntries([...byFactorCount.entries()]
    .sort(([a], [b]) => Number(a) - Number(b))
    .map(([k, rs]) => [String(k), { rows: rs.length, rank: rankFp(rs, width, sz.mod, sz.minv, sz.mmul, sz.msub).rank }]));

  allRows.push(...rows);
  allBigQs.push(bigQ);
  instanceSummaries.push({
    label,
    steps: rows.length,
    width,
    bigQLength: t.bigQ.length,
    recomposes,
    remainderOk,
    rowRank: rankAll.rank,
    idealPerInstanceLinearBasisSavingsBytes: (width - rankAll.rank) * 32,
    rowRankPivots: rankAll.pivots,
    rankByFactorCount,
    supportSize: support.size,
    degree: quantiles(degrees),
    nonzeroCoeffsPerStep: quantiles(nonzeroCounts),
    avgNonzeroCoeffsPerStep: +(nonzeroCounts.reduce((s, x) => s + x, 0) / nonzeroCounts.length).toFixed(2),
    coeffBitLengths: quantiles(coeffBitLengths),
    bigQNonzeroCoeffs: bigQ.filter((x) => x !== 0n).length,
    bigQCoeffBitLengths: quantiles(bigQCoeffBits),
    factorCountHistogram: t.steps.reduce((h, s) => {
      const k = String(s.factors.length);
      h[k] = (h[k] ?? 0) + 1;
      return h;
    }, {}),
  });
}

const paddedAllRows = allRows.map((r) => pad(r, globalWidth));
const paddedBigQs = allBigQs.map((r) => pad(r, globalWidth));
const combinedRowRank = rankFp(
  paddedAllRows,
  globalWidth,
  rankFns.mod,
  rankFns.minv,
  rankFns.mmul,
  rankFns.msub,
);
const combinedBigQRank = rankFp(
  paddedBigQs,
  globalWidth,
  rankFns.mod,
  rankFns.minv,
  rankFns.mmul,
  rankFns.msub,
);

const combinedSupport = new Set();
paddedAllRows.forEach((r) => r.forEach((x, i) => { if (x !== 0n) combinedSupport.add(i); }));
const combinedIdealSavings = (globalWidth - combinedRowRank.rank) * 32;
const bestPerInstanceRank = Math.min(...instanceSummaries.map((s) => s.rowRank));
const bestPerInstanceIdealSavings = (globalWidth - bestPerInstanceRank) * 32;

console.log(JSON.stringify({
  pairingDir,
  env: {
    SZ_ALLAFF: process.env.SZ_ALLAFF ?? '',
    L17SEL: process.env.L17SEL ?? '',
  },
  instances: instanceSpec,
  fieldBits,
  width: globalWidth,
  instanceSummaries,
  combined: {
    rows: paddedAllRows.length,
    rowRank: combinedRowRank.rank,
    rowRankPivots: combinedRowRank.pivots,
    bigQVectors: paddedBigQs.length,
    bigQRank: combinedBigQRank.rank,
    supportSize: combinedSupport.size,
    idealLinearBasisSavingsBytes: combinedIdealSavings,
    bestPerInstanceIdealSavingsBytes: bestPerInstanceIdealSavings,
    lowRankBasisVerdict: combinedIdealSavings < 3000
      ? 'linear quotient-basis compression is far below Scenario N scale; even the sampled universal rank saves under 3kB before binding/code costs'
      : 'linear quotient-basis compression might be material; inspect binding/code costs before accepting route',
  },
}, null, 2));
