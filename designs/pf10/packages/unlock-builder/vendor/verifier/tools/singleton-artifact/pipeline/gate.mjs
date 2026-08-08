import { repoPath as vcRepoPath } from '#repo-paths';
import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect, runSubroutine } from './program.mjs';
import { globalCse, P } from './global_cse.mjs';
import {
  createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin,
} from '@bitauth/libauth';

const CANON = '/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/expderiv-blob/optimized.hex';
const MP = vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json');
const arity = JSON.parse(readFileSync('./arity.json', 'utf8'));

const log = (...a) => console.error('[stage]', ...a);
const orig = Uint8Array.from(Buffer.from(readFileSync(CANON, 'utf8').trim(), 'hex'));
const { bytes: pooled, poolId, dropped } = globalCse(orig, { poolId: 13 });
log('transform done', orig.length, '->', pooled.length, 'delta', orig.length - pooled.length);

const results = { origLen: orig.length, pooledLen: pooled.length, delta: orig.length - pooled.length, poolId, dropped };

// ---------- GATE 1: byte-exact round-trip of the transform (re-dissect matches intent) ----------
const dp = dissect(pooled);
let rtOK = true; const rtNotes = [];
// p-define body pushes p
const pd = dp.bodies.get(poolId);
const pdOps = parse(pd);
if (!(pdOps.length === 1 && pdOps[0].data && pdOps[0].data.length === 32)) { rtOK = false; rtNotes.push('p-define shape'); }
// dropped ids absent, all others present
for (const id of dropped) if (dp.order.includes(id)) { rtOK = false; rtNotes.push('dropped ' + id + ' still present'); }
// re-serialize round-trips (dissect->rebuild identity)
{ const re = serialize(parse(pooled)); if (!Buffer.from(re).equals(Buffer.from(pooled))) { rtOK = false; rtNotes.push('reserialize mismatch'); } }
results.roundtrip = { ok: rtOK, notes: rtNotes, pooledDefines: dp.order.length };
log('gate1 roundtrip', rtOK);

// ---------- GATE 2: per-subroutine differential on random Fp inputs ----------
const rnd = (s) => { let x = BigInt(s + 7); for (let i = 0; i < 8; i++) x = (x * 6364136223846793005n + 1442695040888963407n) % P; return x; };
const dOrig = dissect(orig);
const redirect = new Map(); for (const id of dropped) redirect.set(id, 14); // def#15->#14 (verified below)
let subPass = 0, subTotal = 0, subFail = [];
for (const id of dOrig.order) {
  const a = arity[String(id)]; if (!a) continue;
  const targetPooledId = redirect.has(id) ? redirect.get(id) : id;
  for (let t = 0; t < 3; t++) {
    const ins = Array.from({ length: a.in }, (_, i) => rnd(i * 101 + id * 7 + t * 1000));
    const ro = runSubroutine(dOrig, id, ins);
    const rp = runSubroutine(dp, targetPooledId, ins);
    subTotal++;
    const so = ro.stack.map(String).join(','), sp = rp.stack.map(String).join(',');
    if (!ro.error && !rp.error && so === sp) subPass++;
    else if (subFail.length < 8) subFail.push({ id, targetPooledId, err: [String(ro.error), String(rp.error)], so: so.slice(0, 40), sp: sp.slice(0, 40) });
  }
}
// p-define returns p
{ const rp = runSubroutine(dp, poolId, []); results.pDefineReturnsP = rp.stack.length === 1 && rp.stack[0] === P; }
results.subDifferential = { pass: subPass, total: subTotal, ok: subPass === subTotal && results.pDefineReturnsP, fails: subFail };
log('gate2 subDiff', subPass + '/' + subTotal, 'pDefP', results.pDefineReturnsP);

// ---------- GATE 3: E2E multiproof (accept valid / reject invalid / differential) ----------
const HUGE = Number.MAX_SAFE_INTEGER;
const loose = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE };
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loose, ripemd160, secp256k1, sha1, sha256 }));
const runLock = (lock, unl) => vm.verify(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: hexToBin(unl), valueSatoshis: 10000n })) === true;
const mp = JSON.parse(readFileSync(MP, 'utf8'));
let oa = 0, or = 0, pa = 0, pr = 0, diff = 0; const n = mp.proofs.length;
let pi_ = 0;
for (const p of mp.proofs) {
  const ov = runLock(orig, p.unlocking), oi = runLock(orig, p.invalidUnlocking);
  const pv = runLock(pooled, p.unlocking), pi = runLock(pooled, p.invalidUnlocking);
  if (ov) oa++; if (!oi) or++; if (pv) pa++; if (!pi) pr++;
  if (ov === pv && oi === pi) diff++;
  log('proof', ++pi_, 'origAcc', ov, 'origRej', !oi, 'poolAcc', pv, 'poolRej', !pi);
}
results.e2e = { n, origAccept: oa, origReject: or, pooledAccept: pa, pooledReject: pr, differential: diff, ok: pa === n && pr === n && diff === n && oa === n && or === n };

results.GATE_PASS = results.roundtrip.ok && results.subDifferential.ok && results.e2e.ok;
results.score = { locking: pooled.length, witness: 272, txOvhd: 87, total: pooled.length + 272 + 87 };
console.log(JSON.stringify(results, null, 2));
