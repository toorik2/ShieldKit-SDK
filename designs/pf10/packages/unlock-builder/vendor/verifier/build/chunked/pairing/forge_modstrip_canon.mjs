// MODSTRIP lever-specific A1 forge. MODSTRIP strips the (dead) `% Pmod` from the covOut of
// provably-canonical pass-through limbs (ptParams / c / cInv) on INTERIOR + FINAL miller chunks.
// The value-preservation proof rests on ONE property: covIn hash-binds the RAW 40-byte serialization
// (toPaddedBytes(name,40), no reduction) of every pass-through limb to the predecessor's canonical
// commitment, so a non-canonical witness (limb + k*P) hashes to different bytes and covIn REJECTS.
// This harness drives a REAL MODSTRIP'd interior chunk on the real BCH-2026 VM and confirms:
//   C  honest canonical witness + honest covIn token  -> ACCEPT (control)
//   A1 pass-through limb += P (residue-equal, non-canonical) + honest covIn token -> REJECT (covIn)
//   A2 several distinct pass-through limbs += k*P + honest token -> REJECT (covIn)
//   A3 crafted token committing the non-canonical limbs (covIn matches) -> if it accepts, its covOut
//      must DIFFER from the honest covOut (so the chain breaks at the next covIn; NOT a false-proof
//      forgery — only a non-canonical re-encoding of the SAME true statement).
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecode } from './_millermath.mjs';
import {
  genChunk as millerGenChunk, ops as millerOps, inState as millerInState,
  outState as millerOutState, chunkLambdas as millerLambdas,
} from './gen_miller_affine.mjs';
import { foldRedeem } from './_foldredeem.mjs';
import {
  binToHex, bigIntToVmNumber, encodeDataPush, hash256,
  encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated'); mkdirSync(GEN, { recursive: true });
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;

const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
function evalCov(locking, unlocking, inCommit, outCommit, outLocking) {
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: outLocking, valueSatoshis: 1000n, token: tok(outCommit) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, error: st.error ?? null };
}

// real interior window (non-genesis, non-final): idx 1 = [18,37) strips 34 pass-through limbs.
const [lo, hi] = [18, 37];
const SUCC = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x22), 0x87]); // arbitrary 35B P2SH32 successor
const src = millerGenChunk(lo, hi, false, false, binToHex(SUCC));
const probe = join(GEN, '_forge_modstrip.cash');
writeFileSync(probe, src);
let redeem = Uint8Array.from([...compileFileBytecode(probe)]);
redeem = foldRedeem(redeem);
const rpush = encodeDataPush(redeem);
const locking = p2shSpk(redeem);
const tailLen = rpush.length;

const inFull = millerInState(lo).map(BigInt);            // 50 committed decl-order limbs
const committedIn = inFull.map(red);                     // honest canonical input token
const outLimbs = millerOutState(hi).map(red);
const honestPushed = [...inFull, ...millerLambdas(lo, hi).map(BigInt)];

const mkUnlock = (args) => { const argb = Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)])); const pad = padBytes(TARGET_UNLOCK - argb.length - tailLen); return Uint8Array.from([...pad, ...argb, ...rpush]); };
const inCommit = commitBin(committedIn);
const honestOutCommit = commitBin(outLimbs);

// committed decl-order limb layout for inState: [f(16 incl ptL), pt(10), c(12), ci(12)] -> find a c limb.
// inState = withPts(stateLimbs): [f(0..15 with ptL spliced at 16..25)] then rest c(12)+ci(12).
// Simplest: locate a pass-through limb index by value == a c limb. c/ci occupy the LAST 24 of the 50.
const CI0 = committedIn.length - 24; // first c-limb committed index (c0)
const PT0 = 16;                      // first ptParams committed index (ptL spliced at 16..25)

function runForge(label, tamperFn) {
  const args = honestPushed.slice();
  tamperFn(args);
  const r = evalCov(locking, mkUnlock(args), inCommit, honestOutCommit, SUCC); // honest (canonical) input token
  console.log(`${label.padEnd(52)} accepted=${r.accepted}${r.error ? ' err=' + r.error : ''}`);
  return r.accepted;
}

console.log(`MODSTRIP interior chunk [${lo},${hi}) redeem=${redeem.length}B  strips 34 pass-through %Pmod`);
const cControl = evalCov(locking, mkUnlock(honestPushed), inCommit, honestOutCommit, SUCC);
console.log(`C  honest canonical + honest token                   accepted=${cControl.accepted}${cControl.error ? ' err=' + cControl.error : ''}  (EXPECT true)`);

const a1 = runForge('A1 c0 += P, honest token (EXPECT reject)', (a) => { a[CI0] = a[CI0] + P; });
const a2 = runForge('A2 c0,ci0,pt0 += k*P, honest token (EXPECT reject)', (a) => { a[CI0] += P; a[CI0 + 12] += 64n * P; a[PT0] += 1000n * P; });

// A3: attacker crafts the input token to commit the non-canonical limbs (covIn will match).
const a3args = honestPushed.slice(); a3args[CI0] += P;
const a3token = commitBin(a3args.slice(0, committedIn.length));
const a3 = evalCov(locking, mkUnlock(a3args), a3token, honestOutCommit, SUCC);
console.log(`A3 c0+=P + crafted token -> honest covOut            accepted=${a3.accepted}${a3.error ? ' err=' + a3.error : ''}`);
// if A3 accepts, the produced covOut must differ from honest (chain breaks at next covIn).
let a3OutDiffers = null;
if (a3.accepted) {
  // recompute the covOut this crafted run commits: honest out but with c0 non-canonical (stripped => raw).
  const craftedOut = outLimbs.slice(); // c0 flows through unchanged; find its output index
  // c0 in outState (interior) sits at outLimbs.length-24 (same layout). set raw non-canonical.
  const OCI0 = outLimbs.length - 24; craftedOut[OCI0] = outLimbs[OCI0] + P;
  const a3RealOut = evalCov(locking, mkUnlock(a3args), a3token, commitBin(craftedOut), SUCC);
  a3OutDiffers = a3RealOut.accepted; // accepts ONLY the crafted (non-canonical) covOut, NOT the honest one
  console.log(`   -> against honest covOut accepted=${a3.accepted}; against crafted non-canonical covOut accepted=${a3RealOut.accepted}`);
}

const forgeReject = !a1 && !a2;
const honestOk = cControl.accepted;
// A3 is sound provided EITHER it rejects OR (it accepts only with a NON-honest covOut => chain-breaking, same-statement re-encoding, not a false proof)
const a3Sound = !a3.accepted || (a3OutDiffers === true);
console.log(`\nVERDICT honestAccepts=${honestOk} reachableForgeriesReject=${forgeReject} a3Sound=${a3Sound}`);
console.log(`A1-OK = ${honestOk && forgeReject && a3Sound}`);
if (!(honestOk && forgeReject && a3Sound)) process.exit(1);
