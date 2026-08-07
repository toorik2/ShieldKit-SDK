import { repoPath as vcRepoPath } from '#repo-paths';
// ============================================================================
// E-locking-dedup #2 — EXACT scored-byte delta of the SINGLE-HASH TOWER BIND,
// computed from the REAL per-chunk {op, lockLen, argLen, bodyLen} of the honest
// chain (DUMP_MEAS=/tmp/meas_e3.json) + the MEASURED per-stage bind-op deltas.
//
// scored unlock = max(ceil(op/800), argLen + bodyLen)   [E-byte-accounting meas formula]
// single-hash:  lock' = lock - lkSavedPerChunk(stage)
//               op'   = op + bindOpDelta(stage)           [prologue re-cost, MEASURED]
//               body' = body - witHeaderSavedPerChunk(stage)  [N pushdata headers -> 1]
//               unl'  = max(ceil(op'/800), argLen + body')
// reports per-chunk + per-stage + total: locking saved, unlock clawback, NET.
// ============================================================================
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { compileBytecode, splitTowerBytecode } from '../../build/chunked/pairing/_millermath.mjs';

const meas = JSON.parse(readFileSync('/tmp/meas_e3.json', 'utf8'));
const GEN = vcRepoPath('build/chunked/pairing/generated');
const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const LIBAUTH = pathToFileURL(vcRepoPath('node_modules/@bitauth/libauth/build/index.js')).href;
const lib = await import(LIBAUTH);
const vm = lib.createVirtualMachineBch2026(false);
const mkProg = lib.createTestAuthenticationProgramBch;

const OP_DUP = 0x76, OP_HASH256 = 0xaa, OP_EQUALVERIFY = 0x88, OP_DEFINE = 0x89;
const OP_SPLIT = 0x7f, OP_SWAP = 0x7c, OP_1 = 0x51;
const pushData = (bytes) => { const n = bytes.length; if (n === 0) return [0x00]; if (n <= 75) return [n, ...bytes]; if (n <= 255) return [0x4c, n, ...bytes]; return [0x4d, n & 0xff, (n >> 8) & 0xff, ...bytes]; };
const pushInt = (v) => { if (v === 0) return [0x00]; if (v >= 1 && v <= 16) return [0x50 + v]; const out = []; let n = v; while (n > 0) { out.push(n & 0xff); n >>= 8; } if (out[out.length - 1] & 0x80) out.push(0x00); return [out.length, ...out]; };

// per-stage tower structure (blob identical across chunks of a stage)
function stageInfo(stage) {
  const f = readdirSync(GEN).filter((x) => x.startsWith(stage + '_') && x.endsWith('.cash')).sort()[0];
  const inline = compileBytecode(readFileSync(`${GEN}/${f}`, 'utf8'));
  const { blocks } = splitTowerBytecode(inline);
  // per-fn bind bytes + op
  const perFnLock = [];
  for (const b of blocks) perFnLock.push(OP_DUP, OP_HASH256, ...pushData(new Uint8Array(sha256d(Buffer.from(b.bodyData)))), OP_EQUALVERIFY, ...b.idPush, OP_DEFINE);
  // single-hash bind bytes + op
  let blob = []; for (const b of blocks) blob.push(...b.bodyData); blob = Uint8Array.from(blob);
  const blobConst = new Uint8Array(sha256d(Buffer.from(blob)));
  const single = [OP_DUP, OP_HASH256, ...pushData(blobConst), OP_EQUALVERIFY];
  for (let k = 0; k < blocks.length - 1; k++) single.push(...pushInt(blocks[k].bodyData.length), OP_SPLIT, OP_SWAP, ...blocks[k].idPush, OP_DEFINE);
  single.push(...blocks[blocks.length - 1].idPush, OP_DEFINE);
  // MEASURE bind-only op for each form
  const runPerFn = () => { const wit = []; for (let k = blocks.length - 1; k >= 0; k--) wit.push(...pushData(blocks[k].bodyData)); const r = vm.evaluate(mkProg({ lockingBytecode: Uint8Array.from([...perFnLock, OP_1]), unlockingBytecode: Uint8Array.from(wit), valueSatoshis: 1000n })); return { op: r.metrics.operationCost, ok: r.error === undefined }; };
  const runSingle = () => { const r = vm.evaluate(mkProg({ lockingBytecode: Uint8Array.from([...single, OP_1]), unlockingBytecode: Uint8Array.from(pushData(blob)), valueSatoshis: 1000n })); return { op: r.metrics.operationCost, ok: r.error === undefined }; };
  const pf = runPerFn(), sg = runSingle();
  // witness body header bytes: per-fn = N pushData headers; single = 1 header. body CONTENT same.
  const perFnWitHeaders = blocks.reduce((a, b) => a + (pushData(b.bodyData).length - b.bodyData.length), 0);
  const singleWitHeaders = pushData(blob).length - blob.length;
  return {
    N: blocks.length,
    lkSavedPerChunk: perFnLock.length - single.length,
    bindOpDelta: sg.op - pf.op,
    witHeaderSaved: perFnWitHeaders - singleWitHeaders,
    perFnOk: pf.ok, singleOk: sg.ok,
  };
}
const SI = {};
for (const s of ['g2check', 'vkx', 'miller_baked', 'finalexp']) SI[s] = stageInfo(s);

const stageOf = (label) => label.startsWith('miller_') ? 'miller_baked' : label.replace(/_\d+$/, '');

let baseTot = 0, newTot = 0, lkSavedTot = 0, unlClawTot = 0;
const per = {};
for (const r of meas) {
  const stg = stageOf(r.label);
  const si = SI[stg];
  const padBase = Math.ceil(r.op / 800);
  const unlBase = Math.max(padBase, r.argLen + r.bodyLen);
  const lockBase = r.lockLen;
  // single-hash
  const lockNew = r.lockLen - si.lkSavedPerChunk;
  const opNew = r.op + si.bindOpDelta;
  const bodyNew = r.bodyLen - si.witHeaderSaved;
  const padNew = Math.ceil(opNew / 800);
  const unlNew = Math.max(padNew, r.argLen + bodyNew);
  const base = lockBase + unlBase, neu = lockNew + unlNew;
  baseTot += base; newTot += neu;
  lkSavedTot += (lockBase - lockNew);
  unlClawTot += (unlNew - unlBase);
  per[stg] ??= { n: 0, lkSaved: 0, unlClaw: 0, net: 0, opBound: 0, witBound: 0 };
  const p = per[stg]; p.n++; p.lkSaved += (lockBase - lockNew); p.unlClaw += (unlNew - unlBase); p.net += (neu - base);
  if (padNew >= r.argLen + bodyNew) p.opBound++; else p.witBound++;
}

console.log('=== SINGLE-HASH TOWER BIND — EXACT scored delta (real per-chunk op/arg/body) ===');
console.log('stage         | #ch | lkSaved | unlClaw | NET     | op-bound | wit-bound');
for (const [s, p] of Object.entries(per))
  console.log(`${s.padEnd(13)} | ${String(p.n).padStart(3)} | ${String(p.lkSaved).padStart(7)} | ${String(p.unlClaw).padStart(7)} | ${String(p.net).padStart(7)} | ${String(p.opBound).padStart(8)} | ${p.witBound}`);
console.log('-'.repeat(72));
console.log(`Σ locking saved : ${lkSavedTot}`);
console.log(`Σ unlock clawback: ${unlClawTot}  (op-pad growth that EXCEEDS the witness floor)`);
console.log(`Σ NET delta     : ${newTot - baseTot}  (negative = byte WIN)`);
console.log(`base scored total (E3 reloc, this convention): ${baseTot}`);
console.log(`single-hash scored total                     : ${newTot}`);
console.log(`\nbind correctness: per-fn ok=${Object.values(SI).every(s => s.perFnOk)}  single-hash ok=${Object.values(SI).every(s => s.singleOk)}`);
console.log('per-stage bind-op delta (single - perFn):', Object.fromEntries(Object.entries(SI).map(([k, v]) => [k, v.bindOpDelta])));
console.log('per-stage lkSaved/chunk:', Object.fromEntries(Object.entries(SI).map(([k, v]) => [k, v.lkSavedPerChunk])));
