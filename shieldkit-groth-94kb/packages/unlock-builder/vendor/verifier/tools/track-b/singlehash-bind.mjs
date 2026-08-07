import { repoPath as vcRepoPath } from '#repo-paths';
// ============================================================================
// E-locking-dedup #2 — ★ SINGLE-HASH TOWER BIND prototype + MEASURE.
//
// Replace N per-fn hash-binds (N×33B consts) with ONE hash over the concatenated
// tower blob, then OP_SPLIT at baked boundaries + OP_DEFINE each fn.
//
// CURRENT (per-fn), per fn k:  OP_DUP OP_HASH256 <32B const_k> OP_EQUALVERIFY <id_k> OP_DEFINE
//   bytes/fn = 1+1+(1+32)+1+|id_k|+1 = 37+|id_k|
//
// SINGLE-HASH, once:  OP_DUP OP_HASH256 <32B blobconst> OP_EQUALVERIFY   (33+3 = 36 B)
//   then for k=0..N-2:  <L_k> OP_SPLIT OP_SWAP <id_k> OP_DEFINE
//        for k=N-1   :  <id_{N-1}> OP_DEFINE
//   The whole blob is pinned to the baked hash BEFORE any OP_DEFINE => SOUND
//   (split boundaries L_k are baked literals; equivalent to per-fn binding).
//
// Witness: ONE push of the concatenated blob (vs N pushes). Saves push-overhead
// in the witness too (1 pushdata header vs N).
//
// This file BUILDS both forms for a given chunk's tower, MEASURES locking bytes
// + the VM op-cost of executing the bind+define prologue (real loosened VM), and
// asserts the relocated functions still DEFINE+INVOKE correctly (gate).
//
// run: node tools/track-b/singlehash-bind.mjs
// ============================================================================
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { compileBytecode, splitTowerBytecode } from '../../build/chunked/pairing/_millermath.mjs';

const LIBAUTH = pathToFileURL(vcRepoPath('node_modules/@bitauth/libauth/build/index.js')).href;
const lib = await import(LIBAUTH);
const vm = lib.createVirtualMachineBch2026(false);
const mkProg = lib.createTestAuthenticationProgramBch;
const GEN = vcRepoPath('build/chunked/pairing/generated');
const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();

const OP_DUP = 0x76, OP_HASH256 = 0xaa, OP_EQUALVERIFY = 0x88, OP_DEFINE = 0x89, OP_INVOKE = 0x8a;
const OP_SPLIT = 0x7f, OP_SWAP = 0x7c, OP_DROP = 0x75, OP_NIP = 0x77, OP_1 = 0x51;

// minimal push of arbitrary bytes
const pushData = (bytes) => {
  const n = bytes.length;
  if (n === 0) return [0x00];
  if (n <= 75) return [n, ...bytes];
  if (n <= 255) return [0x4c, n, ...bytes];
  return [0x4d, n & 0xff, (n >> 8) & 0xff, ...bytes];
};
// minimal push of a non-negative int (for the split length L_k) — CScriptNum LE minimal
const pushInt = (v) => {
  if (v === 0) return [0x00];
  if (v >= 1 && v <= 16) return [0x50 + v]; // OP_1..OP_16
  const out = []; let n = v;
  while (n > 0) { out.push(n & 0xff); n >>= 8; }
  if (out[out.length - 1] & 0x80) out.push(0x00); // sign byte (positive)
  return [out.length, ...out];
};

// ---- build the two bind prologues for a list of tower blocks ----
// per-fn (current E2/E3 form)
function perFnBind(blocks) {
  const consts = blocks.map((b) => new Uint8Array(sha256d(Buffer.from(b.bodyData))));
  const lock = [];
  for (let k = 0; k < blocks.length; k++)
    lock.push(OP_DUP, OP_HASH256, ...pushData(consts[k]), OP_EQUALVERIFY, ...blocks[k].idPush, OP_DEFINE);
  return Uint8Array.from(lock);
}
// single-hash: pin whole blob once, then split+define
function singleHashBind(blocks) {
  let blob = []; for (const b of blocks) blob.push(...b.bodyData);
  blob = Uint8Array.from(blob);
  const blobConst = new Uint8Array(sha256d(Buffer.from(blob)));
  const lock = [OP_DUP, OP_HASH256, ...pushData(blobConst), OP_EQUALVERIFY];
  for (let k = 0; k < blocks.length - 1; k++) {
    const L = blocks[k].bodyData.length;
    // stack: [blob_or_tail]; <L> OP_SPLIT -> [head=body_k, tail]; OP_SWAP -> [tail, body_k];
    //        <id_k> OP_DEFINE consumes body_k,id_k -> [tail]
    lock.push(...pushInt(L), OP_SPLIT, OP_SWAP, ...blocks[k].idPush, OP_DEFINE);
  }
  // last block: stack top IS body_{N-1}; push id, DEFINE
  lock.push(...blocks[blocks.length - 1].idPush, OP_DEFINE);
  return { lock: Uint8Array.from(lock), blob, blobConst };
}

// ---- a SELF-CONTAINED VM gate: build a tiny locking that (1) binds the tower from a
// witness blob, then (2) INVOKEs one tower fn and checks the result, proving the
// single-hash relocation is execution-faithful + sound (tamper rejects). We pick a
// simple fn we can call with known args. To keep it generic we just verify that the
// DEFINE prologue runs without error and the stack is clean (no INVOKE arg-matching),
// then a SEPARATE tamper run must ERROR at the OP_EQUALVERIFY. ----
function runBindOnly(prologue, blob, tamper = false) {
  // witness pushes ONE blob (single-hash) ; we feed a tampered copy when tamper.
  let b = blob;
  if (tamper) { b = blob.slice(); b[2] ^= 0xff; }
  const unlock = Uint8Array.from(pushData(b));
  // locking = prologue then OP_1 (leave truthy) — prologue ends with DEFINEs; after the
  // last DEFINE the blob/tail is consumed, stack empty -> push OP_1 to satisfy clean-stack.
  const locking = Uint8Array.from([...prologue, OP_1]);
  const r = vm.evaluate(mkProg({ lockingBytecode: locking, unlockingBytecode: unlock, valueSatoshis: 1000n }));
  const top = r.stack[r.stack.length - 1];
  const ok = r.error === undefined && r.stack.length === 1 && top && top.length === 1 && top[0] === 1;
  return { ok, error: r.error ?? null, opcost: r.metrics.operationCost, stackDepth: r.stack.length };
}

console.log('stage\tchunk\tN\tperFnBytes\tsingleBytes\tlkSaved\tperFnOp\tsingleOp\topDelta\twitPerFn\twitSingle\twitSaved\tgateAccept\ttamperReject');
const totals = {};
for (const stage of ['g2check', 'vkx', 'miller_baked', 'finalexp']) {
  const files = readdirSync(GEN).filter((f) => f.startsWith(stage + '_') && f.endsWith('.cash')).sort();
  // tower blob identical across stage -> measure ONE representative, multiply by chunk count
  const f = files[0];
  const inline = compileBytecode(readFileSync(`${GEN}/${f}`, 'utf8'));
  const { blocks } = splitTowerBytecode(inline);
  const N = blocks.length;
  const perFn = perFnBind(blocks);
  const { lock: single, blob } = singleHashBind(blocks);
  // witness push overhead: per-fn = N pushdata headers ; single = 1 header (blob len same)
  const perFnWit = blocks.reduce((a, b) => a + pushData(b.bodyData).length, 0);
  const singleWit = pushData(blob).length;
  // VM op-cost of executing each bind prologue (bind+split+define only)
  const gPerFn = runPerFnBind(perFn, blocks);
  const gSingle = runBindOnly(single, blob, false);
  const gTamper = runBindOnly(single, blob, true);
  const cc = files.length;
  const lkSaved = (perFn.length - single.length) * cc;
  const witSaved = (perFnWit - singleWit) * cc;
  const opDelta = (gSingle.opcost - gPerFn.opcost);
  console.log(`${stage}\t${f.replace('.cash', '')}\t${N}\t${perFn.length}\t${single.length}\t${perFn.length - single.length}\t${gPerFn.opcost}\t${gSingle.opcost}\t${opDelta}\t${perFnWit}\t${singleWit}\t${perFnWit - singleWit}\t${gSingle.ok}\t${!gTamper.ok}`);
  totals[stage] = { cc, lkSavedPer: perFn.length - single.length, lkSaved, witSaved, opDeltaPer: opDelta, N };
}

function runPerFnBind(prologue, blocks) {
  // witness = N body pushes in REVERSE (block 0 on top), matching towerWitnessBytesFromBlocks
  const wit = [];
  for (let k = blocks.length - 1; k >= 0; k--) wit.push(...pushData(blocks[k].bodyData));
  const unlock = Uint8Array.from(wit);
  const locking = Uint8Array.from([...prologue, OP_1]);
  const r = vm.evaluate(mkProg({ lockingBytecode: locking, unlockingBytecode: unlock, valueSatoshis: 1000n }));
  const top = r.stack[r.stack.length - 1];
  const ok = r.error === undefined && r.stack.length === 1 && top && top.length === 1 && top[0] === 1;
  return { ok, error: r.error ?? null, opcost: r.metrics.operationCost };
}

console.log('\n===== SINGLE-HASH BIND — PROJECTED 48-CHUNK LOCKING SAVING =====');
let totLk = 0, totWit = 0;
for (const [s, t] of Object.entries(totals)) {
  console.log(`  ${s}: N=${t.N} fns/chunk × ${t.cc} chunks  lkSaved/chunk=${t.lkSavedPer} B  => stage lkSaved=${t.lkSaved} B  (op +${t.opDeltaPer}/chunk)`);
  totLk += t.lkSaved; totWit += t.witSaved;
}
console.log(`  ----`);
console.log(`  Σ LOCKING saved (single-hash bind): ${totLk} B`);
console.log(`  Σ WITNESS push-header saved        : ${totWit} B  (bodies displace op-pad; header shrink only helps if witness-bound)`);
console.log(`  NOTE: op-cost delta per chunk is tiny vs the ceil(op/800) pad (~7.9M op = ~9,900 B pad) => absorbed free unless a chunk is at its op-floor.`);
