// _selfpin_probe.mjs — measure the TRUE per-chunk op-cost + byte cost the covOut successor
// self-pin adds. For representative interior miller windows, compile the DEPLOYED (rescheduled)
// chunk WITH succSpk (self-pin: OP_TXOUTPUTCOUNT==1 + OP_OUTPUTBYTECODE==<35B P2SH32>) and WITHOUT
// (succSpk=null), drive each through the real BCH-2026 covenant tx at max pad, and diff op10000 +
// redeem bytes. Also measures the CHEAPER BINDING: pinning only the 32-byte P2SH32 HASH (via a
// hash256(outputbytecode-slice)) is not directly expressible, so we bound the saving by the byte/op
// delta between pushing a 35-byte spk literal vs a 32-byte hash literal in the OP_EQUALVERIFY.
import { writeFileSync } from 'node:fs';
import { genChunk, ops, inState, outState } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/gen_miller_residue.mjs';
import { compileFileBytecode, commitBin, CATEGORY, TARGET_UNLOCK, OP_BUDGET } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/chunked/pairing/_millermath.mjs';
import { bigIntToVmNumber, encodeDataPush, encodeLockingBytecodeP2sh32, hash256, createVirtualMachineBch2026, binToHex } from '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/node_modules/@bitauth/libauth/build/index.js';

const N = ops.length;
const VM = createVirtualMachineBch2026(false);
const LIB_ABS = '/home/toorik/Projects/ZK-Proofs/verifier.cash/build/singleton/bn254/lib/lazy/Bn254Lazy.cash';
const LIB_REL = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const PROBE = '/tmp/_selfpin_probe.cash';
// 35-byte P2SH32-shaped spk (OP_HASH256 <32B> OP_EQUAL); its VALUE is irrelevant to size/op-cost.
const PLAN_SPK_BIN = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x11), 0x87]);
const PLAN_SPK = binToHex(PLAN_SPK_BIN);

const gen = (lo, hi, isFinal, reloc, spk) => genChunk(lo, hi, isFinal, reloc, spk).replace(LIB_REL, LIB_ABS);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padBytes = (t) => { const b = Math.max(2, t); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const p2shSpk = (r) => encodeLockingBytecodeP2sh32(hash256(r));
const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });

// measure window [lo,hi) with a given succSpk (null=no pin). output[0].lockingBytecode is set to the
// pinned spk (so the pin require passes) or to the chunk's own spk when unpinned.
function measure(lo, hi, spk) {
  const isFinal = hi === N, reloc = lo === 0;
  writeFileSync(PROBE, gen(lo, hi, isFinal, reloc, spk));
  let redeem;
  try { redeem = Uint8Array.from([...compileFileBytecode(PROBE)]); }
  catch (e) { return { err: String(e?.message ?? e).slice(0, 120) }; }
  const rpush = encodeDataPush(redeem), locking = p2shSpk(redeem), tail = rpush.length;
  const inLimbs = inState(lo).map(BigInt), outLimbs = outState(hi).map(BigInt);
  const covIn = reloc ? inState(lo).slice(18, 28).map(BigInt) : inLimbs;
  const argb = Uint8Array.from([...inLimbs].reverse().flatMap((c) => [...pushInt(c)]));
  const padTot = TARGET_UNLOCK - argb.length - tail;
  if (padTot < 2) return { err: 'args+redeem exceed 10000' };
  const unlocking = Uint8Array.from([...padBytes(padTot), ...argb, ...rpush]);
  const outLock = spk ? PLAN_SPK_BIN : locking;   // pinned output routes to the pinned spk
  const st = VM.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(covIn)) }],
    transaction: { version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: outLock, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 },
  });
  return { op10000: st.metrics.operationCost, redeem: redeem.length, completed: st.error === undefined,
           accepted: st.error === undefined, err: st.error ? String(st.error).slice(0, 120) : null };
}

const WINS = [[10, 24], [40, 54], [80, 94], [130, 144], [190, 204], [250, 264], [300, 314], [331, 345]];
console.log('window        | no-pin op10000 |  pin op10000 | dOp(pin) | no-pin red | pin red | dRed | no-pin acc | pin acc');
const rows = [];
for (const [lo, hi] of WINS) {
  const a = measure(lo, hi, null);
  const b = measure(lo, hi, PLAN_SPK);
  if (a.err || b.err) { console.log(`[${lo},${hi}) ERR nopin=${a.err ?? ''} pin=${b.err ?? ''}`); continue; }
  const dOp = b.op10000 - a.op10000, dRed = b.redeem - a.redeem;
  rows.push({ lo, hi, w: hi - lo, dOp, dRed, noPinOp: a.op10000, pinOp: b.op10000, noPinAcc: a.accepted, pinAcc: b.accepted });
  console.log(`[${String(lo).padStart(3)},${String(hi).padStart(3)}) | ${String(a.op10000).padStart(14)} | ${String(b.op10000).padStart(12)} | ${String(dOp).padStart(8)} | ${String(a.redeem).padStart(10)} | ${String(b.redeem).padStart(7)} | ${String(dRed).padStart(4)} | ${String(a.accepted).padStart(10)} | ${b.accepted}`);
}
const dOps = rows.map((r) => r.dOp);
const dReds = rows.map((r) => r.dRed);
const mean = (a) => a.reduce((s, x) => s + x, 0) / a.length;
console.log('\n=== self-pin per-chunk op-cost (op10000, deployed rescheduled, max-pad) ===');
console.log('dOp   min/mean/max:', Math.min(...dOps), '/', Math.round(mean(dOps)), '/', Math.max(...dOps));
console.log('dRed  min/mean/max:', Math.min(...dReds), '/', +mean(dReds).toFixed(2), '/', Math.max(...dReds), 'bytes redeem');
// byte cost of the self-pin per chunk = dRed (redeem grows) + the op-pad it forces (dOp/800 bytes of
// unlocking pad) — but only the op-pad-bound chunks pay the op in bytes. Report both.
console.log('self-pin op forces  ~', +(mean(dOps) / 800).toFixed(1), 'bytes of op-pad per chunk (op-pad-bound)');
console.log('self-pin redeem adds', +mean(dReds).toFixed(1), 'bytes to redeem (=> ~', +(mean(dReds)).toFixed(0), 'B *2 push/tail per chunk-ish)');
writeFileSync('/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/_selfpin_probe_report.json', JSON.stringify({ WINS, rows,
  dOp: { min: Math.min(...dOps), mean: Math.round(mean(dOps)), max: Math.max(...dOps) },
  dRed: { min: Math.min(...dReds), mean: +mean(dReds).toFixed(2), max: Math.max(...dReds) } }, null, 2));
