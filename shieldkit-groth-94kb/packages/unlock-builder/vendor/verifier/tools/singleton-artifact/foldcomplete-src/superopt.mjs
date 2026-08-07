// superopt.mjs -- RIGOROUS peephole-completeness search.
// For every maximal run of PURE, context-free stack ops in the artifact, slide windows
// of size 2..5 and search for a strictly-FEWER-BYTES pure-stack-op sequence with an
// IDENTICAL stack effect, verified on the real BCH-2026 VM across several sentinel depths
// (context-free => depth-independent once depth exceeds the touched window). Report every
// window that admits a shorter equivalent (= a genuine byte-saving fold beyond the three).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';
import { createTestAuthenticationProgramBch } from '@bitauth/libauth';
import { looseVm } from './program.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const bytes = Uint8Array.from(Buffer.from(readFileSync(join(here, 'singleton-richpeep-locking.hex'), 'utf8').trim(), 'hex'));
const d = dissect(bytes);

// ---- pure, context-free stack ops (NO altstack: TOALT/FROMALT excluded; NO IFDUP/DEPTH:
// value/context dependent; NO INVOKE/DEFINE) ----
// token model: {bytes:Uint8Array, reads:maxDepthRead}  reads used only to pick test depths.
const B = (arr) => Uint8Array.from(arr);
// 1-byte ops
const ONE = {
  DUP:   B([0x76]), DROP:  B([0x75]), OVER: B([0x78]), SWAP: B([0x7c]), ROT: B([0x7b]),
  NIP:   B([0x77]), TUCK:  B([0x7d]), '2DUP': B([0x6e]), '2DROP': B([0x6d]),
  '2OVER': B([0x70]), '2SWAP': B([0x72]), '2ROT': B([0x71]), '3DUP': B([0x6f]),
};
// numeric-index PICK/ROLL (2 bytes) for small k -- valid pure ops, used as replacements too
function idxOp(k, which) { return B([0x50 + k, which]); } // <k> is 0x51..0x60 for k=1..16; k=0 -> 0x00
function idxPush(k) { return k === 0 ? B([0x00]) : B([0x50 + k]); }
const PICK = 0x79, ROLL = 0x7a;

// build replacement alphabet: all 1-byte ops (13) and <k>PICK/<k>ROLL for k=0..6
const REPL = [];
for (const [name, by] of Object.entries(ONE)) REPL.push({ name, bytes: by, len: 1 });
for (let k = 0; k <= 6; k++) { REPL.push({ name: `<${k}>PICK`, bytes: new Uint8Array([...idxPush(k), PICK]), len: 1 + idxPush(k).length });
  REPL.push({ name: `<${k}>ROLL`, bytes: new Uint8Array([...idxPush(k), ROLL]), len: 1 + idxPush(k).length }); }

// ---- run an op-byte-sequence on a sentinel stack of depth D; return output as array of
// source hex strings, or null on error/insufficient-depth ----
function effect(seqBytes, D) {
  // sentinels: distinct 3-byte pushes value = i
  const push = [];
  for (let i = 0; i < D; i++) push.push(0x03, 0x10 + i, 0x22, 0x33);
  const lock = Uint8Array.from([...push, ...seqBytes]);
  const s = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
  // benign clean-stack errors OK; hard errors (bad opcode / stack underflow) -> null
  if (s.error && !/Non-P2SH|clean stack|exactly one|single/i.test(String(s.error))) return null;
  return s.stack.map((x) => Buffer.from(x).toString('hex'));
}
// equivalence over depths (context-free): equal outputs on D in tset (all > window)
const TSET = [7, 8, 9, 10];
function equiv(aBytes, bBytes) {
  for (const D of TSET) {
    const ea = effect(aBytes, D), eb = effect(bBytes, D);
    if (ea === null || eb === null) return false;
    if (ea.length !== eb.length || !ea.every((x, i) => x === eb[i])) return false;
  }
  return true;
}

// enumerate replacement sequences with total bytes < maxBytes (len 0,1,2 sequences)
function* shorter(maxBytes) {
  // length 0 (delete)
  if (0 < maxBytes) yield { name: '(delete)', bytes: new Uint8Array() };
  // length 1
  for (const r of REPL) if (r.len < maxBytes) yield { name: r.name, bytes: r.bytes };
  // length 2 (only 1-byte ops to keep small; enough to hit 2-byte targets from >=3-byte windows)
  const ones = REPL.filter((r) => r.len === 1);
  for (const a of ones) for (const b of ones) if (2 < maxBytes) yield { name: a.name + ' ' + b.name, bytes: new Uint8Array([...a.bytes, ...b.bytes]) };
}

// ---- classify an op as a PURE stack op (part of a run) ----
// returns {bytes, name} or null if not pure/context-free (INVOKE, DEFINE, TOALT, FROMALT,
// IFDUP, DEPTH, arbitrary PUSH, arithmetic/crypto). <k>PICK / <k>ROLL count as pure units.
const NAME1 = { 0x76:'DUP',0x75:'DROP',0x78:'OVER',0x7c:'SWAP',0x7b:'ROT',0x77:'NIP',0x7d:'TUCK',
  0x6e:'2DUP',0x6d:'2DROP',0x70:'2OVER',0x72:'2SWAP',0x71:'2ROT',0x6f:'3DUP' };
function isSmallInt(o){ if(o.op===0x00) return 0; if(o.op>=0x51&&o.op<=0x60) return o.op-0x50; if(o.data&&o.data.length<=1){ if(o.data.length===0) return 0; return o.data[0]; } return null; }

// Build a token stream where <k> PICK and <k> ROLL are merged into single pure units.
function tokenize(ops) {
  const toks = [];
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i], n = ops[i + 1];
    const k = isSmallInt(o);
    if (k !== null && k >= 0 && k <= 16 && n && n.data === undefined && (n.op === PICK || n.op === ROLL)) {
      toks.push({ pure: true, name: `<${k}>${n.op === PICK ? 'PICK' : 'ROLL'}`, bytes: new Uint8Array([...idxPush(k), n.op]) });
      i++; continue;
    }
    if (o.data === undefined && NAME1[o.op]) { toks.push({ pure: true, name: NAME1[o.op], bytes: Uint8Array.from([o.op]) }); continue; }
    toks.push({ pure: false });
  }
  return toks;
}

// ---- scan: maximal pure runs, windowed superopt ----
const found = [];
let windowsChecked = 0;
function scan(ops, label) {
  const toks = tokenize(ops);
  let i = 0;
  while (i < toks.length) {
    if (!toks[i].pure) { i++; continue; }
    let j = i; while (j < toks.length && toks[j].pure) j++;
    const run = toks.slice(i, j); // pure run [i,j)
    // slide windows of size 2..5 within the run
    for (let w = 2; w <= 5; w++) {
      for (let s = 0; s + w <= run.length; s++) {
        const win = run.slice(s, s + w);
        const winBytes = new Uint8Array(win.reduce((a, t) => [...a, ...t.bytes], []));
        const L = winBytes.length;
        if (L < 2) continue;
        // search for shorter equivalent
        let best = null;
        for (const cand of shorter(L)) {
          windowsChecked++;
          if (equiv(winBytes, cand.bytes)) { best = cand; break; }
        }
        if (best) found.push({ label, w, winNames: win.map((t) => t.name).join(' '), L, replName: best.name, replLen: best.bytes.length, save: L - best.bytes.length });
      }
    }
    i = j;
  }
}

for (const id of d.order) scan(parse(d.bodies.get(id)), 'def#' + id);
scan(d.mainOps, 'main');

console.log(`superopt windows checked: ${windowsChecked}`);
console.log(`shorter-equivalent windows found: ${found.length}`);
// dedupe by (winNames -> replName)
const byPat = new Map();
for (const f of found) {
  const key = `${f.winNames}  ==>  ${f.replName}  (${f.L}B -> ${f.replLen}B, save ${f.save})`;
  byPat.set(key, (byPat.get(key) || 0) + 1);
}
if (byPat.size === 0) console.log('  NONE. No pure-stack-op window admits a strictly-shorter provably-identical replacement.');
else { console.log('\n== distinct shorter-equivalent patterns (freq) =='); [...byPat.entries()].sort((a,b)=>b[1]-a[1]).forEach(([k,v]) => console.log(`  x${v}  ${k}`)); }
