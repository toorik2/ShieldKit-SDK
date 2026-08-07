// _advtest_a1.mjs — ADVERSARIAL A1/pinning probe of chunkplan.mjs core.
// Goal: try to make planOptimal/planGreedy/bruteForceOptimal return a partition whose
// WORST-CASE chunk op exceeds OP_BUDGET (=an A1 forgery: a dense-bit valid vk_x proof rejected).
import {
  planOptimal, planGreedy, bruteForceOptimal, chunkBytes,
  normalizeParams, DEFAULTS,
} from '/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/chunkplan.mjs';

const OP_BUDGET = DEFAULTS.opBudget; // 8,032,800
const params = {
  overheadOp: (inB, outB) => 30_000 + 80 * (inB + outB),
  redeemBytes: (lo, hi) => 1_600 + 20 * (hi - lo),
  finalStateBytes: 165,
};
const P = normalizeParams(params);

let failures = [];
const check = (cond, msg) => { if (!cond) { failures.push(msg); console.log('  FAIL: ' + msg); } };

// audit: return the max worst-case chunk op over a returned partition, and any violations
function audit(planName, plan) {
  let maxWC = 0, viol = [];
  for (const c of plan.partition) {
    maxWC = Math.max(maxWC, c.opWorstCase);
    if (c.opWorstCase > P.opBudget) viol.push({ lo: c.lo, hi: c.hi, opWorstCase: c.opWorstCase });
  }
  return { planName, maxWC, viol, over: viol.length };
}

// ============================================================================
// ATTACK 1 — DISCRIMINATING: typical op says MERGE, worst-case op says NEVER.
// vk_x windows: typical (avg-density) op LOW so opCost-sum of a pair fits budget,
// but all-bits-set opCostWorstCase HIGH so a merged pair is 2x7.65M >> budget.
// If the gate (wrongly) used typical opCost, the DP would merge windows -> A1 forgery.
// ============================================================================
console.log('ATTACK 1: discriminating typical-vs-worstcase (vk_x accumulator windows)');
{
  const nWin = 8;
  const v = [];
  for (let k = 0; k < nWin; k++) v.push({
    id: `vkx.win[${k}]`, stage: 'vkx',
    opCost: 1_300_000,          // avg-density: a PAIR (2.6M)+overhead easily fits budget
    opCostWorstCase: 7_650_000, // all-36-bits-set: a PAIR (15.3M) CANNOT fit budget
    boundaryStateBytes: 165,
    forcedCutBefore: false,     // NO pinning help: only the worst-case gate can stop a merge
  });
  // ground truth on the gate itself
  check(chunkBytes(v, 0, 1, P).feasible === true, 'A1 single vk_x window must be feasible');
  check(chunkBytes(v, 0, 2, P).feasible === false, 'A1 merged vk_x PAIR must be infeasible (worst-case gate)');
  // if the gate used typical op, a pair (2.6M) would be feasible — prove it is NOT:
  const pair = chunkBytes(v, 0, 2, P);
  check(pair.op <= P.opBudget, 'A1 sanity: the PAIR typical op DOES fit budget (so only worst-case blocks it)');
  check(pair.opWorstCase > P.opBudget, 'A1 the PAIR worst-case op DOES exceed budget');
  console.log(`  pair.op(typical)=${pair.op} <= budget=${P.opBudget} ; pair.opWorstCase=${pair.opWorstCase} > budget => gate uses WORST-CASE`);

  const dp = planOptimal(v, params);
  const gr = planGreedy(v, params);
  const bf = bruteForceOptimal(v, params);
  for (const [nm, pl] of [['planOptimal', dp], ['planGreedy', gr], ['bruteForce', bf]]) {
    const a = audit(nm, pl);
    check(a.over === 0, `A1 ${nm} returned ${a.over} over-budget chunk(s): ${JSON.stringify(a.viol)}`);
    check(pl.chunkCount === nWin, `A1 ${nm} must yield exactly ${nWin} singletons, got ${pl.chunkCount}`);
    console.log(`  ${nm}: chunks=${pl.chunkCount} maxWorstCaseOp=${a.maxWC} over=${a.over}`);
  }
}

// ============================================================================
// ATTACK 2 — THRESHOLD MONOTONICITY: the ONLY A1 invariant that matters is
// feasible(chunk) => opWorstCase <= OP_BUDGET. Scan opWorstCase across the whole
// budget neighborhood and prove: (a) there is a single threshold T, (b) T <= OP_BUDGET
// (i.e. the planner is at-or-more-conservative than budget — never emits > budget),
// (c) no feasible point has opWorstCase > OP_BUDGET. Being STRICTER than budget at the
// exact boundary (density clamp: padSafety+1 makes op==budget clamp to 10001>10000) is
// SAFE — it can only reject a chunk, never emit an over-budget one.
console.log('ATTACK 2: feasible => within-budget threshold scan');
{
  const inB = 165;
  const rB = params.redeemBytes(0, 1);
  const rpush = rB + (rB < 76 ? 1 : rB < 256 ? 2 : rB < 65536 ? 3 : 5);
  const ovh = params.overheadOp(inB, P.finalStateBytes);
  // one-block chunk [0,1); vary its opCostWorstCase so opWorstCase sweeps around OP_BUDGET
  let lastFeasibleWC = -1, firstInfeasibleWC = Infinity, feasibleOverBudget = 0;
  for (let d = -2000; d <= 2000; d++) {
    const targetOpWC = OP_BUDGET + d;
    const wc = targetOpWC - ovh - rpush;         // so opWorstCase == targetOpWC exactly
    const v = [{ id: 'b', stage: 'vkx', opCost: 5, opCostWorstCase: wc, boundaryStateBytes: inB }];
    const cb = chunkBytes(v, 0, 1, P);
    if (cb.opWorstCase !== targetOpWC) { failures.push(`A2 opWorstCase bookkeeping off: ${cb.opWorstCase} != ${targetOpWC}`); break; }
    if (cb.feasible) {
      lastFeasibleWC = Math.max(lastFeasibleWC, cb.opWorstCase);
      if (cb.opWorstCase > OP_BUDGET) feasibleOverBudget++;
    } else {
      firstInfeasibleWC = Math.min(firstInfeasibleWC, cb.opWorstCase);
    }
  }
  console.log(`  maxFeasibleWorstCaseOp=${lastFeasibleWC} (budget=${OP_BUDGET}, slack=${OP_BUDGET - lastFeasibleWC}) ; feasiblePointsOverBudget=${feasibleOverBudget}`);
  check(feasibleOverBudget === 0, `A2 found ${feasibleOverBudget} FEASIBLE point(s) with opWorstCase > budget (A1 HOLE)`);
  check(lastFeasibleWC <= OP_BUDGET, `A2 max feasible worst-case op ${lastFeasibleWC} exceeds budget ${OP_BUDGET} (A1 HOLE)`);
  // and the DP must never emit a chunk above budget even when a block sits +1 over:
  const vOver = [{ id: 'x', stage: 'vkx', opCost: 5, opCostWorstCase: OP_BUDGET - ovh - rpush + 1, boundaryStateBytes: inB }];
  let threw = false; try { planOptimal(vOver, params); } catch { threw = true; }
  check(threw, 'A2 a lone over-budget block must make planOptimal THROW (no over-budget partition returned)');
  console.log(`  lone over-budget block => planOptimal throws (no partition returned): ${threw}`);
}

// ============================================================================
// ATTACK 3 — RANDOMIZED FUZZ: 20000 random vk_x-like vectors (mixed magnitude-dependent
// blocks with opCostWorstCase >> opCost). Assert NO returned partition (DP/greedy/brute)
// ever contains a chunk whose worst-case op exceeds budget. One violation => refuted.
// ============================================================================
console.log('ATTACK 3: randomized fuzz (20000 vectors)');
{
  let rng = 0x9e3779b9 >>> 0;
  const rand = () => { rng ^= rng << 13; rng >>>= 0; rng ^= rng >> 17; rng ^= rng << 5; rng >>>= 0; return rng / 0xffffffff; };
  let totalPartitionsAudited = 0, worstSlack = Infinity, anyOver = 0;
  const trials = 20000;
  for (let t = 0; t < trials; t++) {
    const n = 2 + Math.floor(rand() * 9); // 2..10 blocks
    const v = [];
    for (let k = 0; k < n; k++) {
      const oc = Math.floor(rand() * 5_000_000);
      // worst-case is oc..~9M (sometimes exceeding budget by itself)
      const wc = oc + Math.floor(rand() * (9_500_000 - oc > 0 ? 9_500_000 - oc : 1));
      v.push({ id: `r${k}`, stage: 'vkx', opCost: oc, opCostWorstCase: Math.max(oc, wc),
               boundaryStateBytes: 100 + Math.floor(rand() * 2000),
               forcedCutBefore: rand() < 0.1 && k > 0 });
    }
    const rp = {
      overheadOp: (a, b) => 20_000 + 60 * (a + b),
      redeemBytes: (lo, hi) => 1000 + 15 * (hi - lo),
      finalStateBytes: 100,
    };
    for (const fn of [planOptimal, planGreedy, bruteForceOptimal]) {
      let pl;
      try { pl = fn(v, rp); }
      catch (e) { continue; } // infeasible (a lone block > budget) => throws, never returns over-budget: SAFE
      const a = audit(fn.name, pl);
      totalPartitionsAudited++;
      anyOver += a.over;
      if (a.over > 0) { failures.push(`A3 ${fn.name} over-budget: ${JSON.stringify(a.viol)} on vec ${JSON.stringify(v)}`); }
      worstSlack = Math.min(worstSlack, P.opBudget - a.maxWC);
    }
  }
  console.log(`  auditedPartitions=${totalPartitionsAudited} overBudgetChunks=${anyOver} minSlack(op)=${worstSlack}`);
  check(anyOver === 0, `A3 fuzz found ${anyOver} over-budget chunk(s)`);
  check(worstSlack >= 0, 'A3 min slack negative (some emitted chunk exceeded budget)');
}

// ============================================================================
// ATTACK 4 — try to fool the gate by making opCost tiny and opCostWorstCase huge
// across the WHOLE vector (pure worst-case-driven). DP optimality must still hold
// AND every chunk must be within worst-case budget. Cross-check DP==brute.
// ============================================================================
console.log('ATTACK 4: pure worst-case-driven optimality + soundness (DP==brute, all within budget)');
{
  const v = [];
  for (let k = 0; k < 10; k++) v.push({
    id: `w${k}`, stage: 'vkx',
    opCost: 5, // negligible typical: a greedy on typical op would pack ALL 10 into one chunk
    opCostWorstCase: 3_000_000 + (k % 3) * 1_000_000, // 3-5M each; at most ~2 fit a chunk worst-case
    boundaryStateBytes: 165,
  });
  const dp = planOptimal(v, params);
  const bf = bruteForceOptimal(v, params);
  check(dp.totalBytes === bf.totalBytes, `A4 DP ${dp.totalBytes} != brute ${bf.totalBytes}`);
  check(audit('planOptimal', dp).over === 0, 'A4 DP emitted over-budget chunk');
  check(audit('bruteForce', bf).over === 0, 'A4 brute emitted over-budget chunk');
  // if the gate used typical op, ALL 10 (typical 50) would merge into 1 chunk. Prove it did NOT:
  check(dp.chunkCount >= 5, `A4 DP must split into >=5 chunks (worst-case forces it), got ${dp.chunkCount}`);
  console.log(`  DP chunks=${dp.chunkCount} totalBytes=${dp.totalBytes} maxWorstCaseOp=${audit('planOptimal', dp).maxWC}`);
}

// ============================================================================
// ATTACK 5 — a1Certificate honesty: does trustManifest.a1Certificate.pass ever say
// PASS while a real over-budget chunk exists? Independently recompute vs the manifest.
// ============================================================================
console.log('ATTACK 5: a1Certificate cross-check vs independent audit');
{
  const nWin = 8;
  const v = [];
  for (let k = 0; k < nWin; k++) v.push({ id: `vkx${k}`, stage: 'vkx', opCost: 1_300_000, opCostWorstCase: 7_650_000, boundaryStateBytes: 165 });
  const dp = planOptimal(v, params);
  const a = audit('planOptimal', dp);
  const cert = dp.trustManifest.a1Certificate;
  check(cert.pass === (a.over === 0), 'A5 a1Certificate.pass disagrees with independent audit');
  check(cert.maxWorstCaseChunkOp === a.maxWC, `A5 cert.maxWorstCaseChunkOp ${cert.maxWorstCaseChunkOp} != audit ${a.maxWC}`);
  check(cert.maxWorstCaseChunkOp <= cert.opBudget, 'A5 cert maxWorstCaseChunkOp > opBudget while pass');
  console.log(`  cert.pass=${cert.pass} maxWC=${cert.maxWorstCaseChunkOp} budget=${cert.opBudget} slack=${cert.slack}`);
}

console.log('\n================ RESULT ================');
if (failures.length === 0) {
  console.log('ALL ADVERSARIAL A1 CHECKS PASSED — no partition ever exceeded worst-case budget.');
  process.exit(0);
} else {
  console.log(`REFUTED — ${failures.length} A1 violation(s):`);
  for (const f of failures) console.log('  * ' + f);
  process.exit(1);
}
