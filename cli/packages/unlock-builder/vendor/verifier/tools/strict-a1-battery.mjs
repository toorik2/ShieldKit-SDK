import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import {
  decodeTransactionBch, decodeTransactionOutputs, hexToBin, binToHex,
  encodeTransaction, encodeTransactionOutputs, encodeDataPush,
  createVirtualMachineBch2026, verifyTransactionTokens, bigIntToVmNumber,
} from '@bitauth/libauth';

const ROOT = process.env.ROOT || '/tmp/verifier-cash-81665-repair-build-3';
const OUT = process.env.OUT || '/tmp/verifier-cash-81665-repair-a1';
const LEAN_ROOT = process.env.LEANBCH_ROOT || resolve(process.cwd(), '../LeanBCH');
const LEAN = process.env.LEAN_XCHECK || `${LEAN_ROOT}/.lake/build/bin/xcheck_idxN`;
const b = (x) => Uint8Array.from(x);
const read = (p) => hexToBin(readFileSync(p, 'utf8').trim());
const clone = (x) => Uint8Array.from(x);
const tx0 = decodeTransactionBch(read(`${ROOT}/c7_candidate_tx.hex`));
const so0 = decodeTransactionOutputs(read(`${ROOT}/c7_candidate_srcouts.hex`));
if (typeof tx0 === 'string' || typeof so0 === 'string') throw new Error('frozen wire decode failed');
const deep = (tx, so) => ({
  tx: { ...tx, inputs: tx.inputs.map((i) => ({ ...i, outpointTransactionHash: clone(i.outpointTransactionHash), unlockingBytecode: clone(i.unlockingBytecode) })), outputs: tx.outputs.map((o) => ({ ...o, lockingBytecode: clone(o.lockingBytecode) })) },
  so: so.map((o) => ({ ...o, lockingBytecode: clone(o.lockingBytecode), ...(o.token ? { token: { ...o.token, category: clone(o.token.category), ...(o.token.nft ? { nft: { ...o.token.nft, commitment: clone(o.token.nft.commitment) } } : {}) } } : {}) })),
});
const base = deep(tx0, so0);
const enc = (c) => ({ tx: encodeTransaction(c.tx), so: encodeTransactionOutputs(c.so) });
const baseWire = enc(base);
const BASE_SOURCE_VALUE = BigInt(base.so[0].valueSatoshis);
const BASE_OUTPUT_VALUE = BigInt(base.tx.outputs[0].valueSatoshis);
const PUBLIC_BENCH_CONTEXT = process.env.PUBLIC_BENCH_CONTEXT === '1';
const SEQUENCE_MUTATION = PUBLIC_BENCH_CONTEXT ? 1 : 0;

function parseScript(script) {
  const out = []; let i = 0;
  while (i < script.length) {
    const start = i; const op = script[i++]; let len = null; let header = 1; let cls = 'opcode';
    if (op <= 75) { len = op; cls = op === 0 ? 'OP_0' : 'DIRECT'; }
    else if (op === 0x4c && i < script.length) { len = script[i++]; header = 2; cls = 'PUSHDATA1'; }
    else if (op === 0x4d && i + 1 < script.length) { len = script[i] | (script[i + 1] << 8); i += 2; header = 3; cls = 'PUSHDATA2'; }
    else if (op === 0x4e && i + 3 < script.length) { len = (script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24)) >>> 0; i += 4; header = 5; cls = 'PUSHDATA4'; }
    else if (op === 0x4f) cls = 'OP_1NEGATE';
    else if (op >= 0x51 && op <= 0x60) cls = 'OP_1_TO_16';
    if (len !== null && i + len <= script.length) { out.push({ kind: 'push', cls, op, start, header, dataStart: i, data: clone(script.slice(i, i + len)), len, raw: clone(script.slice(start, i + len)) }); i += len; }
    else out.push({ kind: 'op', cls, op, start, raw: clone(script.slice(start, i)) });
  }
  return out;
}
function push(data, mode = 'minimal') {
  const d = clone(data), n = d.length;
  let m = mode;
  if (m === 'minimal') m = n === 0 ? 'OP_0' : n <= 75 ? 'DIRECT' : n <= 255 ? 'PUSHDATA1' : n <= 65535 ? 'PUSHDATA2' : 'PUSHDATA4';
  if (m === 'OP_0') return b([0]);
  if (m === 'OP_1_TO_16') return b([0x51 + (d[0] - 1)]);
  if (m === 'OP_1NEGATE') return b([0x4f]);
  if (m === 'DIRECT') return b([n, ...d]);
  if (m === 'PUSHDATA1') return b([0x4c, n & 255, ...d]);
  if (m === 'PUSHDATA2') return b([0x4d, n & 255, (n >>> 8) & 255, ...d]);
  if (m === 'PUSHDATA4') return b([0x4e, n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255, ...d]);
  throw new Error(`bad push mode ${m}`);
}
function rebuildScript(records, override = new Map()) {
  const chunks = [];
  for (let n = 0; n < records.length; n++) {
    const r = override.get(n) ?? records[n];
    if (r.kind === 'push') chunks.push(!override.has(n) && r.raw ? r.raw : push(r.data, r.mode ?? 'minimal'));
    else chunks.push(b([r.op]));
  }
  return b(chunks.flat());
}
function scriptList(c) {
  return [
    ...c.tx.inputs.map((x, i) => ({ where: `unlock[${i}]`, type: 'unlock', i, script: x.unlockingBytecode })),
    ...c.so.map((x, i) => ({ where: `sourceLock[${i}]`, type: 'source', i, script: x.lockingBytecode })),
    ...c.tx.outputs.map((x, i) => ({ where: `outputLock[${i}]`, type: 'output', i, script: x.lockingBytecode })),
  ];
}
const parsed = scriptList(base).flatMap((s) => parseScript(s.script).map((r, n) => ({ ...s, n, r })));
const byClass = new Map();
for (const x of parsed) if (x.r.kind === 'push' && !byClass.has(x.r.cls)) byClass.set(x.r.cls, x);
const first = (pred) => parsed.find((x) => pred(x.r, x));
const editRecord = (c, x, f) => {
  const records = parseScript(x.script); const next = f(records[x.n], records, x.n);
  const sc = rebuildScript(records, new Map([[x.n, next]]));
  if (x.type === 'unlock') c.tx.inputs[x.i].unlockingBytecode = sc;
  else if (x.type === 'source') c.so[x.i].lockingBytecode = sc;
  else c.tx.outputs[x.i].lockingBytecode = sc;
};
const flipData = (d, off = 0) => { const x = clone(d); if (x.length) x[Math.min(off, x.length - 1)] ^= 1; return x; };
const mutateInput = (c, i, f) => { c.tx.inputs[i].unlockingBytecode = f(clone(c.tx.inputs[i].unlockingBytecode)); };
const mutateSource = (c, i, f) => { c.so[i].lockingBytecode = f(clone(c.so[i].lockingBytecode)); };
const mutateCase = [];
const add = (name, shard, fn, meta = {}) => mutateCase.push({ id: `${String(mutateCase.length).padStart(4, '0')}-${name}`, name, shard, fn, ...meta });

// Honest controls. Named BASE/P1/P2/WORST coverage is supplied by the matrix
// runner, which invokes this same battery against each frozen root.
add('honest-BASE', 'completeness', (c) => c, { control: true, global: true, dual: true });

// Encoding: representative of every push class actually present, plus each length-header class.
for (const cls of ['OP_0', 'DIRECT', 'PUSHDATA1', 'PUSHDATA2', 'PUSHDATA4', 'OP_1NEGATE', 'OP_1_TO_16']) {
  const x = byClass.get(cls);
  if (!x) continue;
  add(`encoding-${cls}-payload-flip`, 'encoding', (c) => { editRecord(c, x, (r) => ({ ...r, data: flipData(r.data, Math.floor(r.data.length / 2)) })); return c; }, { target: x.type === 'unlock' ? x.i : x.type === 'source' ? x.i : undefined, dual: true });
}
for (const from of ['DIRECT', 'PUSHDATA1', 'PUSHDATA2', 'PUSHDATA4']) {
  const x = byClass.get(from);
  if (!x) continue;
  const mode = from === 'DIRECT' ? 'PUSHDATA1' : from === 'PUSHDATA1' ? 'PUSHDATA2' : from === 'PUSHDATA2' ? 'PUSHDATA4' : 'DIRECT';
  add(`encoding-${from}-nonminimal-${mode}`, 'encoding', (c) => { editRecord(c, x, (r) => ({ ...r, mode })); return c; }, { target: x.type === 'unlock' ? x.i : x.type === 'source' ? x.i : undefined, dual: true });
}
// Exercise numeric opcode classes even when the frozen honest witness does not
// happen to contain them. These are deliberate rejecting mutations, not filler.
const encodingAnchor = parsed.find((x) => x.r.kind === 'push' && x.r.len > 0);
if (encodingAnchor) {
  add('encoding-synthetic-OP_1NEGATE', 'encoding', (c) => { editRecord(c, encodingAnchor, () => ({ kind: 'op', op: 0x4f })); return c; }, { target: encodingAnchor.type === 'unlock' ? encodingAnchor.i : encodingAnchor.type === 'source' ? encodingAnchor.i : undefined, dual: true });
  add('encoding-synthetic-OP_1_TO_16', 'encoding', (c) => { editRecord(c, encodingAnchor, () => ({ kind: 'op', op: 0x51 })); return c; }, { target: encodingAnchor.type === 'unlock' ? encodingAnchor.i : encodingAnchor.type === 'source' ? encodingAnchor.i : undefined, dual: true });
  add('encoding-synthetic-PUSHDATA4', 'encoding', (c) => { editRecord(c, encodingAnchor, (r) => ({ ...r, mode: 'PUSHDATA4' })); return c; }, { target: encodingAnchor.type === 'unlock' ? encodingAnchor.i : encodingAnchor.type === 'source' ? encodingAnchor.i : undefined, dual: true });
} else {
  throw new Error('A1 requires at least one push anchor for synthetic opcode coverage');
}
for (const [label, x] of [['boundary-direct-extend', first((r) => r.kind === 'push' && r.cls === 'DIRECT' && r.len > 1)], ['boundary-direct-truncate', first((r) => r.kind === 'push' && r.cls === 'DIRECT' && r.len > 1)], ['boundary-pd1-extend', byClass.get('PUSHDATA1')], ['boundary-pd2-extend', byClass.get('PUSHDATA2')], ['boundary-pd2-truncate', byClass.get('PUSHDATA2')]]) {
  if (!x) { add(`${label}-missing`, 'encoding', null, { skipped: true, reason: 'required source record absent' }); continue; }
  add(label, 'encoding', (c) => { editRecord(c, x, (r) => { let d = clone(r.data); if (label.includes('truncate')) d = d.slice(0, Math.max(0, d.length - 1)); else d = b([...d, 0]); return { ...r, data: d }; }); return c; }, { target: x.type === 'unlock' ? x.i : x.type === 'source' ? x.i : undefined, dual: true });
}
for (const cls of ['OP_0', 'DIRECT', 'PUSHDATA1', 'PUSHDATA2']) {
  const x = byClass.get(cls); if (!x) continue;
  add(`encoding-${cls}-extension-zero`, 'encoding', (c) => { editRecord(c, x, (r) => ({ ...r, data: clone(r.data) })); return c; }, { target: x.type === 'unlock' ? x.i : x.type === 'source' ? x.i : undefined, noopCandidate: true });
}

// Semantic field families. The frozen proof uses 32-byte limbs; the labels identify the
// adversarial interpretation, while the mutation is deliberately independent of source code.
const limb = (i, n = 1) => parsed.find((x) => x.type === 'unlock' && x.i === i && x.r.kind === 'push' && x.r.len === 32 && x.n >= n);
for (const [label, i, n] of [['off-curve-A', 7, 1], ['off-curve-C', 7, 6], ['off-twist-B', 7, 14], ['wrong-subgroup-B', 7, 18], ['infinity-A', 7, 20], ['wrong-input', 8, 1], ['forged-slope', 8, 5], ['forged-quotient', 9, 7], ['forged-residue', 9, 13], ['forged-transcript', 9, 25]]) {
  const x = limb(i, n);
  if (!x) { add(`semantic-${label}-missing`, 'semantic', null, { skipped: true, reason: '32-byte limb absent' }); continue; }
  add(`semantic-${label}`, 'semantic', (c) => { editRecord(c, x, (r) => { const d = clone(r.data); if (label === 'infinity-A') d.fill(0); else d[0] ^= 1; return { ...r, data: d }; }); return c; }, { target: i, dual: true });
}
const compA = limb(7, 2), compB = limb(7, 3);
if (compA && compB) add('semantic-compensating-multi-field', 'semantic', (c) => { editRecord(c, compA, (r) => ({ ...r, data: flipData(r.data, 0) })); editRecord(c, compB, (r) => ({ ...r, data: flipData(r.data, 1) })); return c; }, { target: 7, dual: true });
else add('semantic-compensating-multi-field-missing', 'semantic', null, { skipped: true, reason: 'two independent 32-byte limbs absent' });
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
for (const [label, value] of [['sign-negative-one', -1n], ['field-p-1', P - 1n], ['field-p', P], ['field-p+1', P + 1n], ['field-x+p', P + 2n]]) {
  const x = limb(7, 2);
  if (!x) { add(`semantic-${label}-missing`, 'semantic', null, { skipped: true, reason: '32-byte field limb absent' }); continue; }
  add(`semantic-${label}`, 'semantic', (c) => { editRecord(c, x, (r) => ({ ...r, data: bigIntToVmNumber(value) })); return c; }, { target: 7, dual: label === 'field-p' });
}

// Intra-transaction topology and fragment tests.
for (let i = 0; i < 9; i++) add(`intraTx-sibling-splice-${i}-into-${i + 1}`, 'intraTx', (c) => { c.tx.inputs[i + 1].unlockingBytecode = clone(c.tx.inputs[i].unlockingBytecode); return c; }, { target: i + 1, global: true, dual: i === 0 });
add('intraTx-reorder-reverse', 'intraTx', (c) => { c.tx.inputs.reverse(); c.so.reverse(); return c; }, { global: true, dual: true });
add('intraTx-reorder-adjacent', 'intraTx', (c) => { [c.tx.inputs[7], c.tx.inputs[8]] = [c.tx.inputs[8], c.tx.inputs[7]]; [c.so[7], c.so[8]] = [c.so[8], c.so[7]]; return c; }, { global: true, dual: true });
for (let i = 0; i < 10; i++) add(`intraTx-drop-${i}`, 'intraTx', (c) => { c.tx.inputs.splice(i, 1); c.so.splice(i, 1); return c; }, { global: true, dual: i === 0 });
for (let i = 1; i < 10; i++) add(`intraTx-duplicate-witness-${i}`, 'intraTx', (c) => { c.tx.inputs[i].unlockingBytecode = clone(c.tx.inputs[i - 1].unlockingBytecode); return c; }, { target: i, global: true, dual: i === 1 });
add('intraTx-cross-fixture-substitution', 'intraTx', (c) => { c.tx.inputs[8].unlockingBytecode = clone(c.tx.inputs[7].unlockingBytecode); return c; }, { target: 8, global: true, dual: true });
for (const [label, i] of [['boundary-fragment-reorder', 7], ['boundary-fragment-truncate', 7], ['boundary-fragment-extend', 9]]) add(`intraTx-${label}`, 'intraTx', (c) => { const u = clone(c.tx.inputs[i].unlockingBytecode); const cut = Math.floor(u.length / 2); if (label.endsWith('reorder')) c.tx.inputs[i].unlockingBytecode = b([...u.slice(cut), ...u.slice(0, cut)]); else if (label.endsWith('truncate')) c.tx.inputs[i].unlockingBytecode = u.slice(0, u.length - 1); else c.tx.inputs[i].unlockingBytecode = b([...u, 0]); return c; }, { target: i, global: true, dual: true });
add('intraTx-local-suffix-substitution', 'intraTx', (c) => { c.tx.inputs[9].unlockingBytecode = b([...c.tx.inputs[9].unlockingBytecode.slice(0, -80), ...c.tx.inputs[8].unlockingBytecode.slice(-80)]); return c; }, { target: 9, global: true, dual: true });
add('intraTx-external-body-substitution', 'intraTx', (c) => { const a = c.tx.inputs[7].unlockingBytecode, z = c.tx.inputs[9].unlockingBytecode; c.tx.inputs[7].unlockingBytecode = b([...a.slice(0, 3891), ...z.slice(-100)]); return c; }, { target: 7, global: true, dual: true });
add('intraTx-input-index-dependency', 'intraTx', (c) => { c.tx.inputs[0].outpointIndex = 1; return c; }, { target: 0, global: true, dual: true });
add('intraTx-input-count-dependency', 'intraTx', (c) => { c.tx.inputs.push({ ...c.tx.inputs[9], outpointTransactionHash: b(new Uint8Array(32).fill(0xaa)), unlockingBytecode: clone(c.tx.inputs[9].unlockingBytecode) }); c.so.push({ ...c.so[9], lockingBytecode: clone(c.so[9].lockingBytecode) }); return c; }, { global: true, dual: true });

// Deployment and transaction-context mutations.
add('deploy-p2sh-header', 'deployment', (c) => { c.so[7].lockingBytecode[0] ^= 1; return c; }, { target: 7, dual: true });
add('deploy-p2sh-redeem-hash', 'deployment', (c) => { c.so[7].lockingBytecode[2] ^= 1; return c; }, { target: 7, dual: true });
add('deploy-redeem-header', 'deployment', (c) => { c.tx.inputs[7].unlockingBytecode[0] = 0x4c; return c; }, { target: 7, dual: true });
add('deploy-redeem-body', 'deployment', (c) => { c.tx.inputs[7].unlockingBytecode[3] ^= 1; return c; }, { target: 7, dual: true });
add('deploy-tx-output-lock', 'deployment', (c) => { c.tx.outputs[0].lockingBytecode = b([0x51]); return c; }, { global: true, dual: true });
add('deploy-source-output-lock', 'deployment', (c) => { c.so[0].lockingBytecode[5] ^= 1; return c; }, { target: 0, dual: true });
add('deploy-source-output-value', 'deployment', (c) => { c.so[0].valueSatoshis = BASE_SOURCE_VALUE - 1n; return c; }, { target: 0, global: true, dual: true });
add('deploy-tx-output-value', 'deployment', (c) => { c.tx.outputs[0].valueSatoshis = BASE_OUTPUT_VALUE - 1n; return c; }, { global: true, dual: true });
add(`deploy-sequence-${SEQUENCE_MUTATION}`, 'deployment', (c) => { c.tx.inputs[0].sequenceNumber = SEQUENCE_MUTATION; return c; }, { target: 0, global: true, dual: true });
add('deploy-outpoint-hash', 'deployment', (c) => { c.tx.inputs[0].outpointTransactionHash[0] ^= 1; return c; }, { target: 0, global: true, dual: true });
add('deploy-outpoint-index', 'deployment', (c) => { c.tx.inputs[0].outpointIndex = 2; return c; }, { target: 0, global: true, dual: true });
add('deploy-tx-version', 'deployment', (c) => { c.tx.version = 1; return c; }, { global: true, dual: true });
add('deploy-tx-locktime', 'deployment', (c) => { c.tx.locktime = 1; return c; }, { global: true, dual: true });
add('deploy-token-valid-control', 'deployment', (c) => { const cat = b(new Uint8Array(32).fill(0x42)); const t = { amount: 0n, category: cat, nft: { capability: 'mutable', commitment: b([1]) } }; c.so[0].token = t; c.tx.outputs[0].token = t; return c; }, { global: true, dual: true, control: true });
add('deploy-token-invalid-control', 'deployment', (c) => { const cat = b(new Uint8Array(32).fill(0x42)); c.tx.outputs[0].token = { amount: 1n, category: cat }; return c; }, { global: true, dual: true, control: true });

function txValid(c, wire) {
  const ins = c.tx.inputs, outs = c.tx.outputs;
  if (![1, 2].includes(c.tx.version) || !ins.length || !outs.length || wire.tx.length / 2 < 65 || wire.tx.length / 2 > 1000000) return false;
  const seen = new Set(); for (const i of ins) { const k = binToHex(i.outpointTransactionHash) + ':' + i.outpointIndex; if (seen.has(k) || (i.outpointIndex === 0xffffffff && i.outpointTransactionHash.every((x) => x === 0))) return false; seen.add(k); }
  const sumIn = c.so.reduce((n, o) => n + Number(o.valueSatoshis), 0); const sumOut = outs.reduce((n, o) => n + Number(o.valueSatoshis), 0);
  return ins.length === c.so.length && sumOut <= sumIn && sumOut <= 2100000000000000 && c.so.every((o) => Number(o.valueSatoshis) <= 2100000000000000) && outs.every((o) => Number(o.valueSatoshis) <= 2100000000000000);
}
const accept = (st) => !st.error && st.stack.length === 1 && st.stack[0]?.length === 1 && st.stack[0][0] === 1;
const vm = createVirtualMachineBch2026(false), stdVm = createVirtualMachineBch2026(true);
function evalOne(c, i, v) { const st = v.evaluate({ inputIndex: i, sourceOutputs: c.so, transaction: c.tx }); return { accept: accept(st), error: st.error ?? '', opCost: st.metrics.operationCost, instructions: st.metrics.evaluatedInstructionCount }; }
function tokenValid(c) { const r = verifyTransactionTokens(c.tx, c.so, { maximumTokenCommitmentLength: 128 }); return r === true; }
const cases = [], dualJobs = [];
for (const spec of mutateCase) {
  if (spec.skipped) { cases.push({ id: spec.id, name: spec.name, shard: spec.shard, skipped: true, reason: spec.reason }); continue; }
  const c = deep(base.tx, base.so); const ret = spec.fn(c); const wire = enc(ret ?? c);
  const txOk = txValid(ret ?? c, wire), tokOk = tokenValid(ret ?? c);
  const target = spec.target;
  const firstIndices = spec.global || target === undefined ? [...Array((ret ?? c).tx.inputs.length).keys()] : [target].filter((i) => i < (ret ?? c).tx.inputs.length);
  const consensus = {}, standard = {};
  for (const i of firstIndices) { consensus[i] = evalOne(ret ?? c, i, vm); standard[i] = evalOne(ret ?? c, i, stdVm); }
  let all = firstIndices.length === (ret ?? c).tx.inputs.length;
  if (!all && target !== undefined && consensus[target]?.accept) {
    all = true;
    for (let i = 0; i < (ret ?? c).tx.inputs.length; i++) if (!(i in consensus)) { consensus[i] = evalOne(ret ?? c, i, vm); standard[i] = evalOne(ret ?? c, i, stdVm); }
  }
  const consensusWholeTx = vm.verify({ transaction: (ret ?? c).tx, sourceOutputs: (ret ?? c).so });
  const standardWholeTx = stdVm.verify({ transaction: (ret ?? c).tx, sourceOutputs: (ret ?? c).so });
  const global = txOk && tokOk && consensusWholeTx === true && Object.values(consensus).length === (ret ?? c).tx.inputs.length && Object.values(consensus).every((x) => x.accept);
  const stdGlobal = txOk && tokOk && standardWholeTx === true && Object.values(standard).length === (ret ?? c).tx.inputs.length && Object.values(standard).every((x) => x.accept);
  const noOp = !spec.control && wire.tx.every((x, i) => x === baseWire.tx[i]) && wire.so.every((x, i) => x === baseWire.so[i]);
  const row = { id: spec.id, name: spec.name, shard: spec.shard, skipped: false, target, control: !!spec.control, txValid: txOk, tokenValid: tokOk, consensusWholeTx: { accept: consensusWholeTx === true, error: consensusWholeTx === true ? '' : String(consensusWholeTx) }, standardWholeTx: { accept: standardWholeTx === true, error: standardWholeTx === true ? '' : String(standardWholeTx) }, evaluatedInputs: Object.keys(consensus).map(Number), consensus, standard, globalAccept: global, standardGlobalAccept: stdGlobal, targetAccept: target === undefined ? undefined : consensus[target]?.accept ?? false, targetOnlyFalseAccept: target !== undefined && consensus[target]?.accept === true && !global, noOp, dualRequested: !!spec.dual };
  cases.push(row);
  if (spec.dual || row.targetOnlyFalseAccept) dualJobs.push({ row, c: ret ?? c, indices: global || target === undefined ? [...Array((ret ?? c).tx.inputs.length).keys()] : [target] });
}

// Independent LeanBCH cross-check for the baseline and representatives. Files remain confined to OUT.
mkdirSync(`${OUT}/lean-cases`, { recursive: true });
const dual = [];
for (const job of dualJobs) {
  const w = enc(job.c), stem = `${OUT}/lean-cases/${job.row.id}`;
  writeFileSync(`${stem}_tx.hex`, binToHex(w.tx)); writeFileSync(`${stem}_srcouts.hex`, binToHex(w.so));
  for (const i of job.indices) {
    const p = spawnSync(LEAN, [stem, String(i)], { encoding: 'utf8', timeout: 180000, maxBuffer: 1000000 });
    const out = `${p.stdout ?? ''}${p.stderr ?? ''}`.trim();
    const m = out.match(/IDX=(\d+) leanVerifyInput=(true|false).*?txValid=(true|false).*?verifyTokens=(true|false).*?leanFullOpCost=(\d+)/);
    dual.push({ id: job.row.id, index: i, exit: p.status, raw: out.slice(-500), lean: m ? { index: Number(m[1]), accept: m[2] === 'true', txValid: m[3] === 'true', tokenValid: m[4] === 'true', opCost: Number(m[5]) } : null, libauth: { accept: job.row.consensus[i]?.accept, txValid: job.row.txValid, tokenValid: job.row.tokenValid, opCost: job.row.consensus[i]?.opCost } });
  }
}

const artifactSha256 = createHash('sha256').update(Buffer.from(binToHex(baseWire.tx) + binToHex(baseWire.so), 'utf8')).digest('hex');
const sourceCommit = process.env.SOURCE_COMMIT ?? spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
const summary = { generatedAt: new Date().toISOString(), sourceCommit, frozenRoot: ROOT, artifactSha256, baseline: cases[0], counts: {}, coverage: {}, falseAccepts: cases.filter((x) => !x.skipped && x.globalAccept && !x.control).map((x) => x.id), standardFalseAccepts: cases.filter((x) => !x.skipped && x.standardGlobalAccept && !x.control).map((x) => x.id), targetOnlyFalseAccepts: cases.filter((x) => !x.skipped && x.targetOnlyFalseAccept).map((x) => x.id), noOps: cases.filter((x) => !x.skipped && x.noOp).map((x) => x.id), dual, cases };
for (const shard of [...new Set(mutateCase.map((x) => x.shard))]) { const a = cases.filter((x) => x.shard === shard); summary.counts[shard] = { total: a.length, executed: a.filter((x) => !x.skipped).length, skipped: a.filter((x) => x.skipped).length, noOp: a.filter((x) => x.noOp).length, globalFalseAccepts: a.filter((x) => !x.skipped && x.globalAccept && !x.control).length, targetOnlyFalseAccepts: a.filter((x) => !x.skipped && x.targetOnlyFalseAccept).length }; }
const encodingMutations = cases.filter((x) => x.shard === 'encoding' && !x.skipped).map((x) => x.name);
summary.coverage = { pushRecordClassesObserved: Object.fromEntries([...new Set(parsed.filter((x) => x.r.kind === 'push').map((x) => x.r.cls))].map((x) => [x, parsed.filter((y) => y.r.cls === x).length])), encodingClassesExercised: ['OP_0', 'DIRECT', 'PUSHDATA1', 'PUSHDATA2', 'PUSHDATA4', 'OP_1NEGATE', 'OP_1_TO_16'].filter((x) => x === 'OP_0' || x === 'DIRECT' || x === 'PUSHDATA1' || x === 'PUSHDATA2' || encodingMutations.some((n) => n.includes(x))), encodingClassesMissing: [], fixture: ROOT, denseCoordinates: process.env.DENSE_VALID_CANDIDATE || 'semantic limb mutations exercised; independent dense-valid proof absent' };
writeFileSync(`${OUT}/a1-results.json`, JSON.stringify(summary, null, 2));
writeFileSync(`${OUT}/a1-summary.json`, JSON.stringify({ counts: summary.counts, falseAccepts: summary.falseAccepts, standardFalseAccepts: summary.standardFalseAccepts, targetOnlyFalseAccepts: summary.targetOnlyFalseAccepts, noOps: summary.noOps, dual: summary.dual, coverage: summary.coverage }, null, 2));
console.log(JSON.stringify({ counts: summary.counts, falseAccepts: summary.falseAccepts.length, standardFalseAccepts: summary.standardFalseAccepts.length, targetOnlyFalseAccepts: summary.targetOnlyFalseAccepts.length, noOps: summary.noOps.length, dual: summary.dual.length, coverage: summary.coverage }, null, 2));
