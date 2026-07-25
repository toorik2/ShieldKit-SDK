// INDEPENDENT adversarial forge battery against the FROZEN BLS12-381 grouped-residue crown.
// Trusts ONLY the committed vectors JSON + @bitauth/libauth. Reconstructs the per-group
// CashToken tx exactly (evalGroup), then mounts real forgery attempts by mutating the
// witness data / tx context and confirming the REAL BCH-2026 consensus VM REJECTS each.
// Honest controls must ACCEPT. 1 accepting forgery => soundness break.
import { readFileSync } from 'node:fs';
import { createVirtualMachineBch2026, hexToBin, binToHex, hash256, encodeLockingBytecodeP2sh32 } from '@bitauth/libauth';

const VEC = '/home/toorik/Projects/verifier.cash/harness/src/bch/groth16-bls12381-grouped-residue-vectors.json';
const j = JSON.parse(readFileSync(VEC, 'utf8'));
const realVm = createVirtualMachineBch2026(false);
const CATEGORY = hexToBin(j.category);
const OP_RETURN = Uint8Array.from([0x6a]);
const h = (s) => (s == null ? new Uint8Array(0) : hexToBin(s));
const tokenOf = (t, catOverride) => (t ? { amount: 0n, category: catOverride ?? CATEGORY, nft: { capability: t.capability, commitment: h(t.commitment) } } : undefined);

// Evaluate one input of a group's token tx. `opts` lets a forge tweak the tx shape:
//   opts.extraOutputs, opts.catOverrideOut, opts.capOverrideOut, opts.outLockingOverride, opts.outCommitOverride, opts.inCommitOverride, opts.catOverrideIn
function evalGroup(steps, gmeta, index, opts = {}) {
  const inputs = steps.map((s) => ({ locking: h(s.locking), unlocking: h(s.unlocking) }));
  const inTok = gmeta.inToken
    ? { amount: 0n, category: opts.catOverrideIn ?? CATEGORY, nft: { capability: opts.capOverrideIn ?? gmeta.inToken.capability, commitment: opts.inCommitOverride ?? h(gmeta.inToken.commitment) } }
    : undefined;
  let outputs;
  if (gmeta.outToken) {
    const outTok = { amount: 0n, category: opts.catOverrideOut ?? CATEGORY, nft: { capability: opts.capOverrideOut ?? gmeta.outToken.capability, commitment: opts.outCommitOverride ?? h(gmeta.outToken.commitment) } };
    outputs = [{ lockingBytecode: opts.outLockingOverride ?? h(gmeta.outLocking), valueSatoshis: 1000n, token: outTok }];
  } else {
    outputs = [{ lockingBytecode: OP_RETURN, valueSatoshis: 1000n }];
  }
  if (opts.extraOutputs) outputs = [...outputs, ...opts.extraOutputs];
  const st = realVm.evaluate({
    inputIndex: index,
    sourceOutputs: inputs.map((inp, n) => ({ lockingBytecode: inp.locking, valueSatoshis: 1000n, token: n === 0 ? inTok : undefined })),
    transaction: {
      version: 2,
      inputs: inputs.map((inp, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: inp.unlocking })),
      outputs, locktime: 0,
    },
  });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, error: st.error ?? null };
}

// group index for a global step index
const groupOf = (i) => j.valid.groups.findIndex((g) => i >= g.lo && i <= g.hi);
// evaluate ONLY the group containing step `i` (with given steps/groups), return true if that group REJECTS
function groupRejects(steps, groups, gi, opts = {}) {
  const g = groups[gi];
  const sub = steps.slice(g.lo, g.hi + 1);
  for (let k = g.lo; k <= g.hi; k++) {
    const r = evalGroup(sub, g, k - g.lo, opts);
    if (!r.accepted) return { rejected: true, at: k, error: r.error };
  }
  return { rejected: false };
}
// full-run reject (all groups)
function runRejects(run, opts = {}) {
  for (let gi = 0; gi < run.groups.length; gi++) {
    const r = groupRejects(run.steps, run.groups, gi, opts);
    if (r.rejected) return r;
  }
  return { rejected: false };
}

// ---- push parser: returns [{op,dataStart,dataLen}] over a hex string's bytes ----
function parsePushes(hex) {
  const b = hexToBin(hex); let i = 0; const out = [];
  while (i < b.length) {
    const op = b[i];
    if (op >= 0x01 && op <= 0x4b) { out.push({ op, dataStart: i + 1, dataLen: op }); i += 1 + op; }
    else if (op === 0x4c) { const l = b[i + 1]; out.push({ op, dataStart: i + 2, dataLen: l }); i += 2 + l; }
    else if (op === 0x4d) { const l = b[i + 1] | (b[i + 2] << 8); out.push({ op, dataStart: i + 3, dataLen: l }); i += 3 + l; }
    else if (op === 0x4e) { const l = b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24); out.push({ op, dataStart: i + 5, dataLen: l }); i += 5 + l; }
    else { out.push({ op, opcodeOnly: true, at: i }); i += 1; }
  }
  return out;
}
// flip one byte inside push #p of a step's unlocking hex; return new hex (same length)
function tamperPush(hex, p, byteOffsetInData = 0) {
  const b = hexToBin(hex); const pushes = parsePushes(hex); const pu = pushes[p];
  if (pu.opcodeOnly || pu.dataLen === 0) throw new Error(`push ${p} has no data`);
  const at = pu.dataStart + Math.min(byteOffsetInData, pu.dataLen - 1);
  b[at] ^= 0x01;
  return binToHex(b);
}
// deep clone a run
const clone = (run) => JSON.parse(JSON.stringify(run));
const results = [];
const record = (cat, name, expectReject, outcomeRejected, note = '') => {
  const pass = expectReject === outcomeRejected;
  results.push({ cat, name, expect: expectReject ? 'REJECT' : 'ACCEPT', got: outcomeRejected ? 'REJECT' : 'ACCEPT', pass, note });
  console.log(`  [${pass ? 'OK ' : 'XXX'}] ${cat} :: ${name} — expect ${expectReject ? 'REJECT' : 'ACCEPT'}, got ${outcomeRejected ? 'REJECT' : 'ACCEPT'}${note ? '  ('+note+')' : ''}`);
};

// ============ CONTROL: honest run accepts ============
console.log('=== CONTROL ===');
record('control', 'honest committed run', false, runRejects(j.valid).rejected);
record('control', 'honest extra-proof run (proof#1, same lockings)', false, runRejects(j.extraValidProofs[0]).rejected);

// ============ A. forward-commitment integrity: flip 1 byte of EVERY step inBlob (push[0]) ============
console.log('\n=== A. committed-state integrity sweep (flip inBlob byte of each step -> group must reject) ===');
let aFail = 0;
for (let i = 0; i < j.valid.steps.length; i++) {
  const gi = groupOf(i);
  const run = clone(j.valid);
  run.steps[i].unlocking = tamperPush(run.steps[i].unlocking, 0, 8); // flip a byte inside inBlob
  const rej = groupRejects(run.steps, run.groups, gi).rejected;
  if (!rej) { aFail++; console.log(`  [XXX] step ${i} g${gi} "${j.valid.steps[i].label.slice(0,40)}" inBlob-flip ACCEPTED (forgery!)`); }
}
record('A', `inBlob-byte-flip sweep (all 36 steps)`, true, aFail === 0, `${36-aFail}/36 rejected`);

// ============ B. uncommitted-witness forcing (slopes / residue w / ECIP extras) ============
console.log('\n=== B. uncommitted-witness forcing ===');
// B1: L10 slope tamper. step 1 (miller[0,9)) pushes: [inBlob, slope0a, slope0b, ...]. flip push[1].
{
  const run = clone(j.valid);
  run.steps[1].unlocking = tamperPush(run.steps[1].unlocking, 1, 4);
  record('B', 'L10 slope tamper (step1 push[1])', true, groupRejects(run.steps, run.groups, 0).rejected);
}
// B1b: tamper a slope in a mid-miller step (step 5)
{
  const p = parsePushes(j.valid.steps[5].unlocking);
  const slopeIdx = p.findIndex((x, k) => k > 0 && x.dataLen === 48); // first 48-byte extra after inBlob
  const run = clone(j.valid);
  run.steps[5].unlocking = tamperPush(run.steps[5].unlocking, slopeIdx, 4);
  record('B', 'L10 slope tamper (step5 mid-group)', true, groupRejects(run.steps, run.groups, 0).rejected);
}
// B2: residue w tamper. step 30 (residue walk[0,11)) has w extras; flip the non-zero w limb push[12].
{
  const p = parsePushes(j.valid.steps[30].unlocking);
  // find a non-empty extra push (dataLen>0) that is NOT push[0] (inBlob) and not the last two (pad,redeem)
  let wIdx = -1;
  for (let k = 1; k < p.length - 2; k++) if (p[k].dataLen && p[k].dataLen <= 48) { wIdx = k; break; }
  const run = clone(j.valid);
  run.steps[30].unlocking = tamperPush(run.steps[30].unlocking, wIdx, 4);
  record('B', `residue-w tamper (step30 push[${wIdx}])`, true, groupRejects(run.steps, run.groups, 3).rejected);
}
// B3: ECIP extra tamper. step 0 push[1] (a hint/Q limb) flip -> FS challenge / identity fails.
{
  const run = clone(j.valid);
  run.steps[0].unlocking = tamperPush(run.steps[0].unlocking, 1, 4);
  record('B', 'ECIP hint/witness tamper (step0 push[1])', true, groupRejects(run.steps, run.groups, 0).rejected);
}
// B3b: tamper the ECIP grblob (large byte blob among extras) if present
{
  const p = parsePushes(j.valid.steps[0].unlocking);
  // grblob is a byte blob; find a 0x4d push that isn't the last (redeem) or the pad. redeem is last push.
  const redeemIdx = p.length - 1; const padIdx = p.length - 2;
  const blobIdx = p.findIndex((x, k) => k > 0 && k < padIdx && x.op === 0x4d && x.dataLen > 100 && x.dataLen < 2000);
  if (blobIdx >= 0) {
    const run = clone(j.valid);
    run.steps[0].unlocking = tamperPush(run.steps[0].unlocking, blobIdx, 4);
    record('B', `ECIP grblob tamper (step0 push[${blobIdx}], len=${p[blobIdx].dataLen})`, true, groupRejects(run.steps, run.groups, 0).rejected);
  } else console.log('  [i] no grblob-sized push found in step0 (nfail may be 0); covered by B3');
}

// ============ C. cross-instance splice (statement binding / no substitution) ============
console.log('\n=== C. cross-instance splice (proof#1 witness into proof#0 run) ===');
const p1 = j.extraValidProofs[0];
for (const k of [0, 5, 9, 18, 30]) {
  const gi = groupOf(k);
  const run = clone(j.valid);
  run.steps[k].unlocking = p1.steps[k].unlocking; // valid-but-different-instance witness, SAME locking
  // if k is a group boundary consuming a token, the covInHash / forward check must catch the mismatch
  record('C', `splice proof#1 step ${k} (g${gi}) into committed run`, true, groupRejects(run.steps, run.groups, gi).rejected);
}
// C-full-group: replace ALL of group1's witnesses with proof#1's group1 -> boundary NFT mismatch
{
  const run = clone(j.valid);
  const g = j.valid.groups[1];
  for (let k = g.lo; k <= g.hi; k++) run.steps[k].unlocking = p1.steps[k].unlocking;
  record('C', 'splice entire group1 from proof#1 (NFT boundary must reject)', true, groupRejects(run.steps, run.groups, 1).rejected);
}

// ============ D. covenant / tx structural (chain-binding) ============
console.log('\n=== D. covenant / tx structural attacks ===');
// D1: NFT out-commitment swap on group0 -> covout hash256 check must fail
{
  const g0 = j.valid.groups[0];
  const bad = hexToBin(g0.outToken.commitment); bad[0] ^= 0x01;
  record('D', 'group0 outToken commitment tamper (covout hash256)', true, groupRejects(j.valid.steps, j.valid.groups, 0, { outCommitOverride: bad }).rejected);
}
// D1b: NFT in-commitment swap on group1 -> covInHash check must fail
{
  const g1 = j.valid.groups[1];
  const bad = hexToBin(g1.inToken.commitment); bad[0] ^= 0x01;
  record('D', 'group1 inToken commitment tamper (covInHash hash256)', true, groupRejects(j.valid.steps, j.valid.groups, 1, { inCommitOverride: bad }).rejected);
}
// D2: category swap on group0 output token -> covout requires out category == in[0] category
{
  const badCat = new Uint8Array(32).fill(0xcd);
  record('D', 'group0 output token CATEGORY swap (be->cd)', true, groupRejects(j.valid.steps, j.valid.groups, 0, { catOverrideOut: badCat }).rejected);
}
// D2b: category swap on BOTH in and out of group0 (attacker uses own category thread) -> covout in==out so passes? test honestly
{
  const badCat = new Uint8Array(32).fill(0xcd);
  const r = groupRejects(j.valid.steps, j.valid.groups, 0, { catOverrideOut: badCat, catOverrideIn: badCat });
  record('D', 'group0 in+out CATEGORY both swapped (continuity self-consistent)', false, r.rejected, 'genesis inToken empty; tests if any category is pinned to a constant');
}
// D3: covOut locking splice -> attacker P2SH successor (state token pinned, but is the LOCKING pinned?)
{
  const attackerRedeem = Uint8Array.from([0x51]); // OP_1
  const attackerLock = encodeLockingBytecodeP2sh32(hash256(attackerRedeem));
  const r = groupRejects(j.valid.steps, j.valid.groups, 0, { outLockingOverride: attackerLock });
  record('D', 'group0 outLocking splice to attacker P2SH', /*expect reject?*/ false, r.rejected, 'reveals whether successor SCRIPT is pinned (vs only state token)');
}
// D4: thread-escape: append an extra attacker output to group0's tx
{
  const attackerLock = encodeLockingBytecodeP2sh32(hash256(Uint8Array.from([0x51])));
  const extra = [{ lockingBytecode: attackerLock, valueSatoshis: 1000n }];
  const r = groupRejects(j.valid.steps, j.valid.groups, 0, { extraOutputs: extra });
  record('D', 'group0 extra attacker output appended', false, r.rejected, 'reveals whether output count is constrained');
}
// D5: capability escalation mutable -> minting on group0 output token
{
  const r = groupRejects(j.valid.steps, j.valid.groups, 0, { capOverrideOut: 'minting' });
  record('D', 'group0 output token capability mutable->minting', false, r.rejected, 'reveals whether capability is pinned');
}

// ============ SUMMARY ============
console.log('\n=== SUMMARY ===');
const soundnessCats = ['control', 'A', 'B', 'C'];
const structuralFindings = results.filter((r) => r.cat === 'D' && !r.expect.includes('REJECT'));
const soundnessResults = results.filter((r) => soundnessCats.includes(r.cat) || (r.cat === 'D' && r.expect === 'REJECT'));
const soundnessFails = soundnessResults.filter((r) => !r.pass);
console.log(`soundness-critical checks: ${soundnessResults.length}, failures: ${soundnessFails.length}`);
if (soundnessFails.length) { console.log('!!! SOUNDNESS FAILURES:'); soundnessFails.forEach((r) => console.log('   ', JSON.stringify(r))); }
console.log('\nstructural/token-safety observations (D, informational):');
structuralFindings.forEach((r) => console.log(`   ${r.name}: got ${r.got} — ${r.note}`));
console.log('\nVERDICT:', soundnessFails.length === 0 ? 'SOUND (every soundness forgery rejected; controls accept)' : 'UNSOUND — see failures');
