// RECONCILED economic model. KEY INSIGHT: padding = unlocking bytecode = op-cost/800.
// densityControlLength = 41 + unlockBytes. So a chunk's budgets are SELF-SCALING with its padding:
//   op-budget   = 800 * (41 + unlockBytes)  -> chunk fills padding until op-budget == op-cost
//   hash-budget = 0.5 * (41 + unlockBytes)  (std)  =  op-cost/1600 iters
//   hash-cost   = 192/iter (std)
// The WITNESS (R limbs) and FS-HASH ops can be paid out of the SAME padding the chunk already carries
// when op-bound. The question: does the chunk stay op-bound, or flip to hash-bound / witness-bound,
// and what is the resulting chunk count + bytes.

const DCL_BASE = 41, OP_PER_BYTE = 800;
const HIPB_STD = 0.5, HIPB_NONSTD = 3.5, HCOST_STD = 192, HCOST_NONSTD = 64;
const hashIters = (L) => 2 + Math.ceil((L + 8) / 64);

// MEASURED
const PERMUL_SZ = 94_569;           // chained Horner block, real-VM op-cost
const TOWER_PERMUL = 442_849;       // 146.14M / 330
const MILLER_OP = 146_140_316, MILLER_BYTES = 291_915, MILLER_LOCK = 109_227;
const N_MULS = 330;

// FS hash: commit 12 R-limbs/mul. Incremental packed. iters/mul:
const FS_ITERS_PER_MUL = hashIters(32 + 8 * 40) + hashIters(32 + 4 * 40); // 2 packed hashes
const FS_HASH_OP_PER_MUL_STD = FS_ITERS_PER_MUL * HCOST_STD + 3 * 100; // +cat/hash instr overhead

console.log('FS iters/mul =', FS_ITERS_PER_MUL, '; FS hash op/mul (std) =', FS_HASH_OP_PER_MUL_STD);
console.log('SZ per-mul op (Horner+hash, std) =', (PERMUL_SZ + FS_HASH_OP_PER_MUL_STD).toLocaleString());
console.log('tower per-mul op =', TOWER_PERMUL.toLocaleString());
console.log();

// New Miller op-cost with SZ (all 330 muls become Horner+hash, plus a one-time big_Q M(z) batch ~ negligible):
const SZ_MILLER_OP = N_MULS * (PERMUL_SZ + FS_HASH_OP_PER_MUL_STD);
console.log('SZ Miller op-cost =', SZ_MILLER_OP.toLocaleString(), '(', (SZ_MILLER_OP / MILLER_OP * 100).toFixed(1) + '% of baked Miller', MILLER_OP.toLocaleString(), ')');
console.log();

// ===== HASH DENSITY: the real gate =====
// In an op-bound chunk, unlockBytes ≈ opcost/800. Hash budget = 0.5*(41+unlockBytes) ≈ opcost/1600.
// Hash DEMAND = (muls in chunk) * FS_ITERS_PER_MUL.
// muls in chunk (op-bound) = opcost / (PERMUL_SZ + FS_HASH_OP).  Check demand <= budget:
const perMulOp = PERMUL_SZ + FS_HASH_OP_PER_MUL_STD;
// For a chunk at op-budget OB: muls = OB/perMulOp ; unlockBytes ≈ OB/800 ; hash-budget = 0.5*(41+OB/800).
// demand = muls*FS_ITERS_PER_MUL. Need demand <= budget.
function chunkCheck(OB) {
  const muls = OB / perMulOp;
  const unlockBytes = OB / 800;
  const hashBudget = HIPB_STD * (DCL_BASE + unlockBytes);
  const hashDemand = muls * FS_ITERS_PER_MUL;
  const witnessBytes = muls * 12 * 33; // R limbs pushed
  return { OB, muls: muls.toFixed(1), unlockBytes: Math.round(unlockBytes), hashBudget: Math.round(hashBudget), hashDemand: Math.round(hashDemand), hashOK: hashDemand <= hashBudget, witnessBytes: Math.round(witnessBytes), witnessVsUnlock: (witnessBytes/unlockBytes).toFixed(2) };
}
console.log('=== Per-chunk feasibility at op-budget OB (standard relay) ===');
for (const OB of [7_700_000, 8_000_000]) console.log('  ', JSON.stringify(chunkCheck(OB)));
console.log();

// ===== NONSTANDARD (consensus, miner-direct): hash 3.5/byte, cost 64/iter =====
const FS_HASH_OP_PER_MUL_NS = FS_ITERS_PER_MUL * HCOST_NONSTD + 3 * 100;
const perMulOpNS = PERMUL_SZ + FS_HASH_OP_PER_MUL_NS;
function chunkCheckNS(OB) {
  const muls = OB / perMulOpNS;
  const unlockBytes = OB / 800;
  const hashBudget = HIPB_NONSTD * (DCL_BASE + unlockBytes);
  const hashDemand = muls * FS_ITERS_PER_MUL;
  return { OB, muls: muls.toFixed(1), hashBudget: Math.round(hashBudget), hashDemand: Math.round(hashDemand), hashOK: hashDemand <= hashBudget };
}
console.log('=== NONSTANDARD (consensus) per-chunk ===');
console.log('  SZ per-mul op (NS) =', perMulOpNS.toLocaleString());
for (const OB of [8_000_000]) console.log('  ', JSON.stringify(chunkCheckNS(OB)));
console.log();

// ===== NET BYTES =====
// New chunk count = ceil(SZ_MILLER_OP / 8.03M). New bytes = SZ_MILLER_OP/800 (pad) + nChunks*locking/chunk.
const BUDGET = 8_032_800;
const nChunksSZ = Math.ceil(SZ_MILLER_OP / BUDGET);
const lockPerChunk = MILLER_LOCK / 20; // ~5461B; SZ chunk locking likely SMALLER (no tower fns) but assume similar upper bound
const padSZ = SZ_MILLER_OP / 800;
const witnessTotal = N_MULS * 12 * 33;
// In op-bound chunks, witness REPLACES junk padding (both are unlocking bytes) up to the pad amount.
// pad already = SZ_MILLER_OP/800. witness = 130,680. If witness < pad, witness is FREE (absorbed). Check:
console.log('=== NET BYTE PROJECTION (standard) ===');
console.log('SZ Miller op =', SZ_MILLER_OP.toLocaleString(), '=> chunks =', nChunksSZ);
console.log('padding (op/800) =', Math.round(padSZ).toLocaleString());
console.log('witness mass (330*12*33) =', witnessTotal.toLocaleString(), '<= padding?', witnessTotal <= padSZ, '(if yes, witness absorbed FREE into padding)');
const lockTotal = nChunksSZ * lockPerChunk;
const bytesSZ = padSZ + lockTotal;
console.log('locking total (', nChunksSZ, 'chunks *', Math.round(lockPerChunk), 'B) =', Math.round(lockTotal).toLocaleString());
console.log('SZ Miller bytes ~', Math.round(bytesSZ).toLocaleString(), 'vs baked', MILLER_BYTES.toLocaleString(), '=>', ((bytesSZ - MILLER_BYTES)/MILLER_BYTES*100).toFixed(1)+'%');
console.log();
console.log('VERIFIER: 738,099 record; baked-only=594,496.');
const verifierSZ = 594_496 - (MILLER_BYTES - bytesSZ);
console.log('  with SZ Miller =>', Math.round(verifierSZ).toLocaleString());
