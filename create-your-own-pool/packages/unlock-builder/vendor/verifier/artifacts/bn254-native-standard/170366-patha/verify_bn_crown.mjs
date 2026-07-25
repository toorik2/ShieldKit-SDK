// A1 HONEST + SCORE + HASH-PIN + CHAIN-BINDING reproducer for the FROZEN BN254 crown (170,366 B).
// Reads ONLY the frozen artifact chunks.json (this dir) + @bitauth/libauth. Reconstructs each of the
// 19 deployed chunks EXACTLY as the builder's evalCov does, runs the real BCH-2026 consensus VM
// (createVirtualMachineBch2026(false)), and asserts: 19/19 accept, per-chunk op-cost == recorded,
// Sigma(locking+unlocking) == 170,366, redeem hash256-pins to its P2SH32 locking (unbypassable),
// and the covenant chain is byte-bound seam-to-seam (outCommit[i] == inCommit[i+1]).
//   node verify_bn_crown.mjs [chunks.json]
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, binToHex, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  createVirtualMachineBch2026,
} from '@bitauth/libauth';

const HERE = dirname(fileURLToPath(import.meta.url));
const chunksPath = process.argv[2] ?? join(HERE, 'chunks.json');
const chunks = JSON.parse(readFileSync(chunksPath, 'utf8'));
const CATEGORY = new Uint8Array(32).fill(0xcd); // covenant thread id (32B) — matches _millermath.mjs
const vm = createVirtualMachineBch2026(false);   // real BCH-2026 consensus VM (non-standard/consensus)

const tok = (commitmentHex) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: hexToBin(commitmentHex) } });
function programFor(idx) {
  const c = chunks[idx];
  const isTerminal = c.outCommit === null;
  const succLockHex = isTerminal ? c.lockingHex : chunks[idx + 1].lockingHex;
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: hexToBin(c.lockingHex), valueSatoshis: 1000n, token: tok(c.inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: hexToBin(c.unlockingHex) }],
      outputs: [{ lockingBytecode: hexToBin(succLockHex), valueSatoshis: 1000n, ...(isTerminal ? {} : { token: tok(c.outCommit) }) }],
      locktime: 0,
    },
  };
}
function accepts(program) {
  const st = vm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, op: st.metrics.operationCost, err: st.error };
}

let fail = 0;
let totalBytes = 0, totalOp = 0, maxOp = 0;
const BUDGET = 8_032_800;
console.log('=== HONEST + OP-COST + BYTES (real BCH-2026 consensus VM) ===');
for (let i = 0; i < chunks.length; i++) {
  const c = chunks[i];
  const lb = hexToBin(c.lockingHex).length, ub = hexToBin(c.unlockingHex).length;
  if (lb !== c.lockingBytes) { console.log(`  ${c.name}: lockingBytes mismatch ${lb} != ${c.lockingBytes}`); fail++; }
  if (ub !== c.unlockingBytes) { console.log(`  ${c.name}: unlockingBytes mismatch ${ub} != ${c.unlockingBytes}`); fail++; }
  totalBytes += lb + ub;
  const r = accepts(programFor(i));
  totalOp += r.op; if (r.op > maxOp) maxOp = r.op;
  const opMatch = r.op === c.operationCost;
  const opOk = r.op <= BUDGET;
  if (!r.accepted || !opMatch || !opOk) fail++;
  console.log(`  [${String(i).padStart(2)}] ${c.name.padEnd(16)} accept=${r.accepted} op=${r.op} (rec ${c.operationCost} match=${opMatch}) <=budget=${opOk}${r.err ? ' ERR=' + r.err : ''}`);
}
console.log(`\ntotalBytes = ${totalBytes}  (expect 170366: ${totalBytes === 170366 ? 'OK' : '*** MISMATCH ***'})`);
if (totalBytes !== 170366) fail++;
console.log(`totalOperationCost = ${totalOp}  maxStepOp = ${maxOp}  budget/input = ${BUDGET}  margin = ${BUDGET - maxOp}`);

console.log('\n=== HASH-PIN (redeem hash256-committed to its P2SH32 locking; on-chain logic unbypassable) ===');
let pinFail = 0;
for (let i = 0; i < chunks.length; i++) {
  const c = chunks[i];
  const redeem = hexToBin(c.redeemHex);
  const derivedLock = binToHex(encodeLockingBytecodeP2sh32(hash256(redeem)));
  const lockOk = derivedLock === c.lockingHex.toLowerCase();
  // the redeem must be the trailing pushdata of the unlocking (redeem-in-scriptSig, P2SH)
  const rpush = binToHex(encodeDataPush(redeem));
  const embedOk = c.unlockingHex.toLowerCase().endsWith(rpush.toLowerCase());
  if (!lockOk || !embedOk) { pinFail++; console.log(`  ${c.name}: lockPin=${lockOk} redeemEmbedded=${embedOk} *** FAIL ***`); }
}
console.log(pinFail === 0 ? `  19/19 redeems hash256-pinned to their lockings AND embedded in unlocking. OK` : `  *** ${pinFail} pin failures ***`);
if (pinFail) fail++;

console.log('\n=== CHAIN-BINDING (covOut[i] == covIn[i+1]; token-threaded state, seam by seam) ===');
let seamFail = 0, seams = 0;
for (let i = 0; i < chunks.length - 1; i++) {
  seams++;
  const ok = chunks[i].outCommit === chunks[i + 1].inCommit;
  if (!ok) { seamFail++; console.log(`  seam ${chunks[i].name} -> ${chunks[i + 1].name}: *** MISMATCH ***`); }
}
const tailTerminal = chunks[chunks.length - 1].outCommit === null;
console.log(`  ${seams} seams, ${seamFail} mismatches; tail terminal (outCommit==null): ${tailTerminal}`);
if (seamFail || !tailTerminal) fail++;

// successor-pin structural: each non-terminal deployed chunk's committed successor spk == next lockingHex.
// (Proven load-bearing dynamically in forge_battery.mjs thread-escape; here we confirm the wiring is consistent.)

console.log(`\n=== RESULT: ${fail === 0 ? 'PASS — honest chain verifies, bytes/op reproduce, redeems pinned, chain bound' : '*** ' + fail + ' FAILURES ***'} ===`);
process.exit(fail === 0 ? 0 : 1);
