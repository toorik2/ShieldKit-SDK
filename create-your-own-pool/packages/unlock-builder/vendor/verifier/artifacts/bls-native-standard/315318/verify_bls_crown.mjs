// INDEPENDENT harness-level A1 verification of the BLS12-381 grouped-residue crown.
// Trusts ONLY: (a) the frozen committed vectors JSON, (b) @bitauth/libauth.
// Reconstructs the per-group CashToken-carrying tx from the vectors' own group
// metadata (no generator code imported), evaluates every input on BOTH the harness
// loosened VM and the REAL BCH-2026 consensus VM, confirms accept + op-cost, scores it,
// and confirms the two invalid runs reject + the extra-proof run (same lockings) accepts.
import { readFileSync } from 'node:fs';
import {
  ConsensusBch2025, createInstructionSetBch2026, createVirtualMachine,
  createVirtualMachineBch2026, ripemd160, secp256k1, sha1, sha256, hexToBin,
} from '@bitauth/libauth';

const VEC = '/home/toorik/Projects/verifier.cash/harness/src/bch/groth16-bls12381-grouped-residue-vectors.json';
const j = JSON.parse(readFileSync(VEC, 'utf8'));

// ---- VMs -------------------------------------------------------------------
const HUGE = Number.MAX_SAFE_INTEGER;
const loosenedConsensus = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE,
  maximumOperationCount: HUGE,
};
const loosenedVm = createVirtualMachine(createInstructionSetBch2026(false, {
  consensus: loosenedConsensus, ripemd160, secp256k1, sha1, sha256,
}));
const realVm = createVirtualMachineBch2026(false);

const CATEGORY = hexToBin(j.category);
const OP_RETURN = Uint8Array.from([0x6a]);
const h = (s) => (s == null ? new Uint8Array(0) : hexToBin(s));
const tokenOf = (t) => (t ? { amount: 0n, category: CATEGORY, nft: { capability: t.capability, commitment: h(t.commitment) } } : undefined);

// Build the group tx exactly as the on-chain deployment: input 0 of the group carries
// inToken; the single output carries outToken under outLocking (or OP_RETURN for the last group).
function evalGroup(vm, stepsInGroup, gmeta, index) {
  const inputs = stepsInGroup.map((s) => ({ locking: h(s.locking), unlocking: h(s.unlocking) }));
  const st = vm.evaluate({
    inputIndex: index,
    sourceOutputs: inputs.map((inp, n) => ({
      lockingBytecode: inp.locking, valueSatoshis: 1000n,
      token: n === 0 ? tokenOf(gmeta.inToken) : undefined,
    })),
    transaction: {
      version: 2,
      inputs: inputs.map((inp, n) => ({
        outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0,
        unlockingBytecode: inp.unlocking,
      })),
      outputs: gmeta.outToken
        ? [{ lockingBytecode: h(gmeta.outLocking), valueSatoshis: 1000n, token: tokenOf(gmeta.outToken) }]
        : [{ lockingBytecode: OP_RETURN, valueSatoshis: 1000n }],
      locktime: 0,
    },
  });
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// Evaluate a whole run (steps[] + groups[]) input-by-input on `vm`.
function evalRun(vm, run) {
  const res = [];
  run.groups.forEach((gm) => {
    const stepsInGroup = run.steps.slice(gm.lo, gm.hi + 1);
    for (let k = gm.lo; k <= gm.hi; k++) res[k] = evalGroup(vm, stepsInGroup, gm, k - gm.lo);
  });
  return res;
}

// ---- scoring (mirror harness/src/harness/benchmark.ts stepTxOverhead intraTx path) ----
const varintLen = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9);
const TXN_ENVELOPE = 8, INPUT_FIXED = 40;
function score(run) {
  let scriptBytes = 0, txOverhead = 0;
  run.groups.forEach((gm) => {
    const groupSize = gm.hi - gm.lo + 1;
    for (let i = gm.lo; i <= gm.hi; i++) {
      const s = run.steps[i];
      const lock = h(s.locking).length, unlock = h(s.unlocking).length;
      scriptBytes += lock + unlock;
      const inputOv = INPUT_FIXED + varintLen(unlock);
      const sharedOnFirst = i === gm.lo ? TXN_ENVELOPE + varintLen(groupSize) + varintLen(1) + (8 + varintLen(1) + 1) : 0;
      txOverhead += inputOv + sharedOnFirst;
    }
  });
  return { scriptBytes, txOverhead, full: scriptBytes + txOverhead };
}

// ---- run VALID -------------------------------------------------------------
console.log('=== VALID run (committed proof) ===');
const vLoose = evalRun(loosenedVm, j.valid);
const vReal = evalRun(realVm, j.valid);
let allAcceptL = true, allAcceptR = true, maxOpR = 0, sumOpR = 0, opMatch = true, budgetOk = true;
const BUDGET = j.budgetPerInput;
for (let i = 0; i < j.valid.steps.length; i++) {
  const L = vLoose[i], R = vReal[i];
  if (!L.accepted) allAcceptL = false;
  if (!R.accepted) allAcceptR = false;
  if (L.operationCost !== R.operationCost) opMatch = false;
  if (R.operationCost > BUDGET) budgetOk = false;
  maxOpR = Math.max(maxOpR, R.operationCost);
  sumOpR += R.operationCost;
  if (!L.accepted || !R.accepted || R.operationCost > BUDGET) {
    console.log(`  step ${i} g${j.valid.steps[i].group} "${j.valid.steps[i].label}" acceptL=${L.accepted} acceptR=${R.accepted} op=${R.operationCost} err=${L.error||R.error}`);
  }
}
console.log(`  all-accept loosened: ${allAcceptL}`);
console.log(`  all-accept REAL consensus VM: ${allAcceptR}`);
console.log(`  loosened op-cost == real op-cost (every step): ${opMatch}`);
console.log(`  every step op-cost <= budget ${BUDGET.toLocaleString()}: ${budgetOk}  (maxOp=${maxOpR.toLocaleString()})`);
console.log(`  sum op-cost = ${sumOpR.toLocaleString()} (vectors totalOperationCost=${j.totalOperationCost.toLocaleString()}, match=${sumOpR===j.totalOperationCost})`);
console.log(`  vectors maxStepOperationCost=${j.maxStepOperationCost.toLocaleString()} (match=${maxOpR===j.maxStepOperationCost})`);

// ---- score -----------------------------------------------------------------
const sc = score(j.valid);
console.log('\n=== SCORE ===');
console.log(`  script bytes (Σ locking+unlocking) = ${sc.scriptBytes.toLocaleString()}  (vectors totalBytes=${j.totalBytes.toLocaleString()}, match=${sc.scriptBytes===j.totalBytes})`);
console.log(`  tx overhead (Σ)                     = ${sc.txOverhead.toLocaleString()}`);
console.log(`  FULL SCORE (bytes+overhead)         = ${sc.full.toLocaleString()}`);

// per-group byte check vs vectors groupBytes
console.log('\n=== per-group script+ov bytes ===');
j.valid.groups.forEach((gm, gi) => {
  let b = 8 + 1 + 1; // envelope + in-count varint + out-count varint (matches generator groupBytes)
  for (let i = gm.lo; i <= gm.hi; i++) b += h(j.valid.steps[i].unlocking).length + 43; // PER_INPUT_OV=43
  b += gm.outToken ? 8 + 3 + (1 + 32 + 1 + 1 + 32) : 8 + 1 + 1;
  console.log(`  group ${gi} [${gm.lo},${gm.hi}] size ${gm.hi-gm.lo+1}: computed groupBytes=${b.toLocaleString()} vectors=${j.groupBytes[gi].toLocaleString()} match=${b===j.groupBytes[gi]}`);
});

// ---- INVALID runs (must reject) -------------------------------------------
console.log('\n=== INVALID runs (must each REJECT) ===');
j.invalid.forEach((run, idx) => {
  const res = evalRun(realVm, run);
  const rejected = res.some((m) => !m.accepted);
  const firstFail = res.findIndex((m) => !m.accepted);
  console.log(`  invalid[${idx}]: rejected=${rejected}  firstFailingStep=${firstFail}${firstFail>=0?` (g${run.steps[firstFail].group} "${run.steps[firstFail].label}")`:''}`);
});

// ---- EXTRA valid proof (proof-generality: SAME lockings, different witness) --
console.log('\n=== EXTRA valid proof(s) — proof-generality (same lockings must accept a distinct proof) ===');
j.extraValidProofs.forEach((run, idx) => {
  // confirm the extra run uses the SAME lockings as the committed valid run
  const sameLockings = run.steps.every((s, i) => s.locking === j.valid.steps[i].locking);
  const res = evalRun(realVm, run);
  const allAcc = res.every((m) => m.accepted);
  console.log(`  extraValidProofs[${idx}]: sameLockingsAsValid=${sameLockings} allAccept=${allAcc}`);
});

console.log('\n=== SUMMARY ===');
console.log(JSON.stringify({
  allAcceptLoosened: allAcceptL, allAcceptReal: allAcceptR, opCostVMsMatch: opMatch,
  budgetOk, scoreScriptBytes: sc.scriptBytes, scoreFull: sc.full,
  totalBytesMatch: sc.scriptBytes === j.totalBytes, totalBytesExpected: 315318, fullScoreExpected: 316946,
}, null, 2));
