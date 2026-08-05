// verify_dp_optimality.mjs — ADVERSARIAL verification of chunkplan.planOptimal.
// Lens: DP-OPTIMALITY. Confirm planOptimal returns the GLOBAL minimum, not a greedy/local one.
//
// Strategy (independent of the module's own bruteForceOptimal):
//   * treat chunkBytes(costVec, lo, hi, params) as a BLACK-BOX cost oracle (this lens is about the
//     partitioning algorithm, not the byte formula);
//   * ORACLE A: my own exhaustive enumeration over all 2^(n-1) cut masks;
//   * ORACLE B: my own independent memoized recursive min-cost solver (different code path than the DP);
//   * fuzz hundreds of random cost vectors spanning floor-bound / op-pad-bound / forced-cut /
//     magnitude-dependent (worstCase>>typical) regimes, plus adversarial edge structures;
//   * assert planOptimal.totalBytes == ORACLE A == ORACLE B on EVERY case;
//   * structurally validate the returned partition (contiguous, covering, all feasible, byte-sum,
//     forced cuts honored, worst-case op <= budget).
// Any single sub-optimal answer or partition inconsistency => REFUTED.

import { planOptimal, chunkBytes, normalizeParams } from './chunkplan.mjs';

// ---- deterministic PRNG (mulberry32) so results are reproducible ----
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---- ORACLE A: brute force over all cut masks (independent reimplementation) ----
function oracleBrute(costVec, params) {
  const n = costVec.length;
  let best = Infinity, bestCuts = null;
  const masks = 1 << (n - 1);
  for (let mask = 0; mask < masks; mask++) {
    const cuts = [0];
    for (let k = 0; k < n - 1; k++) if (mask & (1 << k)) cuts.push(k + 1);
    cuts.push(n);
    let total = 0, ok = true;
    for (let c = 0; c + 1 < cuts.length; c++) {
      const cb = chunkBytes(costVec, cuts[c], cuts[c + 1], params);
      if (!cb.feasible) { ok = false; break; }
      total += cb.bytes;
    }
    if (ok && total < best) { best = total; bestCuts = cuts; }
  }
  return { totalBytes: best, cuts: bestCuts };
}

// ---- ORACLE B: independent memoized recursion (top-down), no forced-index shortcut ----
// cost(i) = min bytes to partition [i, n). This intentionally does NOT use lastForced tables;
// forced cuts are enforced purely through chunkBytes(...).feasible (forcedInside). Different code
// path from planOptimal's bottom-up DP with iMin pruning => a real independent check of the recurrence.
function oracleRecursive(costVec, params) {
  const n = costVec.length;
  const memo = new Array(n + 1).fill(undefined);
  function solve(i) {
    if (i === n) return 0;
    if (memo[i] !== undefined) return memo[i];
    let best = Infinity;
    for (let j = i + 1; j <= n; j++) {
      const cb = chunkBytes(costVec, i, j, params);
      if (!cb.feasible) continue; // includes forcedInside + budget + clamp
      const rest = solve(j);
      if (rest === Infinity) continue;
      const cand = cb.bytes + rest;
      if (cand < best) best = cand;
    }
    memo[i] = best;
    return best;
  }
  return solve(0);
}

// ---- structural validation of a returned partition ----
function validatePartition(res, costVec, params, tag) {
  const P = normalizeParams(params);
  const part = res.partition;
  if (!Array.isArray(part) || part.length === 0) return `${tag}: empty partition`;
  let cover = 0, sum = 0;
  const cuts = [];
  for (const c of part) {
    if (c.lo !== cover) return `${tag}: non-contiguous at lo=${c.lo}, expected ${cover}`;
    if (c.hi <= c.lo) return `${tag}: empty/inverted chunk [${c.lo},${c.hi})`;
    const cb = chunkBytes(costVec, c.lo, c.hi, params);
    if (!cb.feasible) return `${tag}: emitted INFEASIBLE chunk [${c.lo},${c.hi})`;
    if (cb.bytes !== c.bytes) return `${tag}: chunk byte mismatch [${c.lo},${c.hi}) ${cb.bytes} vs ${c.bytes}`;
    if (c.opWorstCase > P.opBudget) return `${tag}: chunk worst-case op ${c.opWorstCase} > budget ${P.opBudget}`;
    if (c.lo > 0) cuts.push(c.lo);
    sum += c.bytes;
    cover = c.hi;
  }
  if (cover !== costVec.length) return `${tag}: partition does not cover (ends at ${cover}/${costVec.length})`;
  if (sum !== res.totalBytes) return `${tag}: totalBytes ${res.totalBytes} != Σ chunk bytes ${sum}`;
  // forced cuts honored
  for (let k = 1; k < costVec.length; k++) {
    if (costVec[k].forcedCutBefore && !cuts.includes(k)) return `${tag}: forced cut ${k} NOT honored`;
  }
  return null;
}

// ---- random cost-vector generators across regimes ----
function randParams(rnd) {
  // random but well-formed adapter callbacks
  const ovhBase = Math.floor(rnd() * 60000);
  const ovhPer = Math.floor(rnd() * 200);
  const redBase = Math.floor(rnd() * 2000);
  const redPer = Math.floor(rnd() * 40);
  const finalState = Math.floor(rnd() * 2000);
  return {
    overheadOp: (a, b) => ovhBase + ovhPer * (a + b),
    redeemBytes: (lo, hi) => redBase + redPer * (hi - lo),
    finalStateBytes: finalState,
  };
}

function randVec(rnd, n, regime) {
  const v = [];
  for (let k = 0; k < n; k++) {
    let opCost, opWC, bsb;
    if (regime === 'floor') {
      opCost = Math.floor(rnd() * 200000);          // small op => floor-bound likely
      opWC = opCost + Math.floor(rnd() * 50000);
      bsb = Math.floor(rnd() * 8000);               // large committed state
    } else if (regime === 'oppad') {
      opCost = 800000 + Math.floor(rnd() * 2500000); // large op => op-pad bound
      opWC = opCost + Math.floor(rnd() * 400000);
      bsb = Math.floor(rnd() * 500);
    } else if (regime === 'magdep') {
      opCost = 500000 + Math.floor(rnd() * 800000);   // typical modest
      opWC = 5000000 + Math.floor(rnd() * 3000000);   // worst-case near/over budget (vk_x windows)
      bsb = Math.floor(rnd() * 400);
    } else { // mixed
      const r = rnd();
      if (r < 0.34) return randVec_one(rnd, 'floor');
      if (r < 0.67) return randVec_one(rnd, 'oppad');
      return randVec_one(rnd, 'magdep');
    }
    const e = { id: `${regime}.${k}`, stage: regime, opCost, opCostWorstCase: Math.max(opCost, opWC), boundaryStateBytes: bsb };
    if (k > 0 && rnd() < 0.18) e.forcedCutBefore = true; // sprinkle forced cuts
    v.push(e);
  }
  return v;
}
function randVec_one(rnd, regime) {
  let opCost, opWC, bsb;
  if (regime === 'floor') { opCost = Math.floor(rnd() * 200000); opWC = opCost + Math.floor(rnd() * 50000); bsb = Math.floor(rnd() * 8000); }
  else if (regime === 'oppad') { opCost = 800000 + Math.floor(rnd() * 2500000); opWC = opCost + Math.floor(rnd() * 400000); bsb = Math.floor(rnd() * 500); }
  else { opCost = 500000 + Math.floor(rnd() * 800000); opWC = 5000000 + Math.floor(rnd() * 3000000); bsb = Math.floor(rnd() * 400); }
  return { id: `${regime}`, opCost, opCostWorstCase: Math.max(opCost, opWC), boundaryStateBytes: bsb, stage: regime };
}
function buildMixed(rnd, n) {
  const v = [];
  for (let k = 0; k < n; k++) {
    const one = randVec_one(rnd, ['floor', 'oppad', 'magdep'][Math.floor(rnd() * 3)]);
    one.id = `mix.${k}`;
    if (k > 0 && rnd() < 0.18) one.forcedCutBefore = true;
    v.push(one);
  }
  return v;
}

// ---- run the fuzz campaign ----
function run() {
  const summary = { cases: 0, mismatches: [], structuralErrors: [], maxN: 0, infeasibleSkipped: 0,
                    regimeCounts: {}, examplesChecked: [] };
  const rnd = mulberry32(0xC0FFEE);
  const regimes = ['floor', 'oppad', 'magdep', 'mixed'];

  // Sweep n from 1..18 (2^17 = 131072 masks max — fast). Many trials per (regime, n).
  for (let n = 1; n <= 18; n++) {
    const trialsPer = n <= 12 ? 40 : (n <= 15 ? 20 : 8);
    for (const regime of regimes) {
      for (let t = 0; t < trialsPer; t++) {
        const params = randParams(rnd);
        const vec = regime === 'mixed' ? buildMixed(rnd, n) : randVec(rnd, n, regime);
        summary.regimeCounts[regime] = (summary.regimeCounts[regime] || 0) + 1;

        // Does ANY feasible partition exist? Check via oracleBrute; if none, both should throw.
        const brute = oracleBrute(vec, params);
        let plan;
        try {
          plan = planOptimal(vec, params);
        } catch (e) {
          if (brute.totalBytes === Infinity) { summary.infeasibleSkipped++; continue; } // both agree: infeasible
          summary.mismatches.push({ regime, n, kind: 'plan-threw-but-feasible-exists', bruteBytes: brute.totalBytes, err: String(e.message || e) });
          continue;
        }
        if (brute.totalBytes === Infinity) {
          summary.mismatches.push({ regime, n, kind: 'plan-succeeded-but-no-feasible-partition', planBytes: plan.totalBytes });
          continue;
        }

        summary.cases++;
        summary.maxN = Math.max(summary.maxN, n);

        // ORACLE B: independent recursion
        const recBytes = oracleRecursive(vec, params);

        // Cross-check all three
        if (plan.totalBytes !== brute.totalBytes) {
          summary.mismatches.push({ regime, n, kind: 'plan-vs-brute', plan: plan.totalBytes, brute: brute.totalBytes, delta: plan.totalBytes - brute.totalBytes });
        }
        if (recBytes !== brute.totalBytes) {
          summary.mismatches.push({ regime, n, kind: 'recursive-vs-brute', rec: recBytes, brute: brute.totalBytes });
        }
        // planOptimal must never be BELOW the true optimum (would mean a bug producing an invalid cheaper answer)
        if (plan.totalBytes < brute.totalBytes) {
          summary.mismatches.push({ regime, n, kind: 'plan-BELOW-optimum', plan: plan.totalBytes, brute: brute.totalBytes });
        }

        // structural validation of returned partition
        const err = validatePartition(plan, vec, params, `${regime}/n=${n}/t=${t}`);
        if (err) summary.structuralErrors.push(err);
      }
    }
  }

  // A couple of hand-crafted adversarial structures where greedy is known to be sub-optimal.
  const handParams = { overheadOp: () => 0, redeemBytes: () => 60, finalStateBytes: 100 };
  const handCases = [
    // high-state boundary trap (T3-like), extended
    [
      { id: 'a', opCost: 3_000_000, opCostWorstCase: 3_000_000, boundaryStateBytes: 100, stage: 'x' },
      { id: 'b', opCost: 3_000_000, opCostWorstCase: 3_000_000, boundaryStateBytes: 100, stage: 'x' },
      { id: 'c', opCost: 3_000_000, opCostWorstCase: 3_000_000, boundaryStateBytes: 9_000, stage: 'x' },
      { id: 'd', opCost: 3_000_000, opCostWorstCase: 3_000_000, boundaryStateBytes: 100, stage: 'x' },
      { id: 'e', opCost: 3_000_000, opCostWorstCase: 3_000_000, boundaryStateBytes: 9_500, stage: 'x' },
      { id: 'f', opCost: 3_000_000, opCostWorstCase: 3_000_000, boundaryStateBytes: 100, stage: 'x' },
    ],
    // alternating high/low state, all tiny op (pure floor regime) => cut placement matters a lot
    Array.from({ length: 10 }, (_, k) => ({ id: `s${k}`, opCost: 1000, opCostWorstCase: 1000, boundaryStateBytes: (k % 2 ? 7000 : 200), stage: 'x' })),
  ];
  for (let h = 0; h < handCases.length; h++) {
    const vec = handCases[h];
    const brute = oracleBrute(vec, handParams);
    const plan = planOptimal(vec, handParams);
    const rec = oracleRecursive(vec, handParams);
    summary.cases++;
    const ok = plan.totalBytes === brute.totalBytes && rec === brute.totalBytes;
    summary.examplesChecked.push({ hand: h, n: vec.length, plan: plan.totalBytes, brute: brute.totalBytes, rec, agree: ok, cuts: plan.partition.map(c => c.lo) });
    if (!ok) summary.mismatches.push({ kind: 'hand', h, plan: plan.totalBytes, brute: brute.totalBytes, rec });
    const err = validatePartition(plan, vec, handParams, `hand/${h}`);
    if (err) summary.structuralErrors.push(err);
  }

  return summary;
}

const s = run();
const pass = s.mismatches.length === 0 && s.structuralErrors.length === 0;
console.log(JSON.stringify({
  pass,
  totalCases: s.cases,
  maxN: s.maxN,
  infeasibleCasesAgreed: s.infeasibleSkipped,
  regimeCounts: s.regimeCounts,
  mismatchCount: s.mismatches.length,
  mismatches: s.mismatches.slice(0, 20),
  structuralErrorCount: s.structuralErrors.length,
  structuralErrors: s.structuralErrors.slice(0, 20),
  handExamples: s.examplesChecked,
}, null, 2));
process.exit(pass ? 0 : 1);
