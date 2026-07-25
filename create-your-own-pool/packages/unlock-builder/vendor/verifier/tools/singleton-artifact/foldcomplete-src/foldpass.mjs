// foldpass.mjs -- GREEDY superoptimizing fold pass over maximal PURE stack-op runs,
// restricted to the DECOMPILER-SAFE alphabet (no 3DUP). Every replacement is a live
// VM-verified stack identity across sentinel depths (context-free). Applied to fixpoint,
// composed on top of the 5613 artifact (which already carries the three banked folds).
// Then run the two hard gates exactly like build_richpeep: (1) identity round-trip
// byte-exact, (2) per-subroutine differential vs the crown on random Fp.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { parse, serialize } from './asm.mjs';
import { dissect, rebuild, runSubroutine, decompileProgram, recompileProgram, looseVm } from './program.mjs';
import { createTestAuthenticationProgramBch, bigIntToVmNumber, vmNumberToBigInt } from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const START = Uint8Array.from(Buffer.from(readFileSync(join(here, 'singleton-richpeep-locking.hex'), 'utf8').trim(), 'hex'));
console.log(`START (richpeep 3-fold): ${START.length} B  sha ${sha(START)}`);
const d0 = dissect(START);

// ---------- SAFE pure-op alphabet (decompiler-handled; NO 3DUP/IFDUP/DEPTH/altstack) ----------
const PICK = 0x79, ROLL = 0x7a;
const idxPush = (k) => k === 0 ? [0x00] : [0x50 + k];
const ONE = { DUP:0x76,DROP:0x75,OVER:0x78,SWAP:0x7c,ROT:0x7b,NIP:0x77,TUCK:0x7d,
  '2DUP':0x6e,'2DROP':0x6d,'2OVER':0x70,'2ROT':0x71,'2SWAP':0x72 };
const REPL = [];
for (const [name, op] of Object.entries(ONE)) REPL.push({ name, bytes: Uint8Array.from([op]), len: 1 });
for (let k = 0; k <= 8; k++) {
  REPL.push({ name: `<${k}>PICK`, bytes: Uint8Array.from([...idxPush(k), PICK]), len: 1 + idxPush(k).length });
  REPL.push({ name: `<${k}>ROLL`, bytes: Uint8Array.from([...idxPush(k), ROLL]), len: 1 + idxPush(k).length });
}
const ONES = REPL.filter((r) => r.len === 1);

// ---------- VM stack-effect oracle (context-free identity across depths) ----------
function effect(seqBytes, D) {
  const push = []; for (let i = 0; i < D; i++) push.push(0x03, 0x10 + i, 0x22, 0x33);
  const lock = Uint8Array.from([...push, ...seqBytes]);
  const s = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
  if (s.error && !/Non-P2SH|clean stack|exactly one|single/i.test(String(s.error))) return null;
  return s.stack.map((x) => Buffer.from(x).toString('hex'));
}
const TSET = [7, 8, 9, 10, 11];
function equiv(a, b) {
  for (const D of TSET) { const ea = effect(a, D), eb = effect(b, D); if (ea === null || eb === null) return false; if (ea.length !== eb.length || !ea.every((x, i) => x === eb[i])) return false; }
  return true;
}
function* shorter(maxBytes) {
  if (0 < maxBytes) yield { name: '(delete)', bytes: new Uint8Array() };   // full-identity window -> delete
  for (const r of REPL) if (r.len < maxBytes) yield r;                 // len 1 (and 2 for <k>PICK/ROLL)
  for (const a of ONES) for (const b of ONES) if (2 < maxBytes) yield { name: a.name + ' ' + b.name, bytes: Uint8Array.from([...a.bytes, ...b.bytes]) };
}

// ---------- tokenize into pure units (<k>PICK/<k>ROLL merged) ----------
const NAME1 = { 0x76:'DUP',0x75:'DROP',0x78:'OVER',0x7c:'SWAP',0x7b:'ROT',0x77:'NIP',0x7d:'TUCK',0x6e:'2DUP',0x6d:'2DROP',0x70:'2OVER',0x71:'2ROT',0x72:'2SWAP' };
const smallInt = (o) => { if (o.op===0x00) return 0; if (o.op>=0x51&&o.op<=0x60) return o.op-0x50; if (o.data&&o.data.length===1) return o.data[0]; if (o.data&&o.data.length===0) return 0; return null; };
function tokenize(ops) {
  const t = [];
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i], n = ops[i + 1], k = smallInt(o);
    if (k !== null && k >= 0 && k <= 16 && n && n.data === undefined && (n.op === PICK || n.op === ROLL)) { t.push({ pure: true, name: `<${k}>${n.op===PICK?'PICK':'ROLL'}`, bytes: Uint8Array.from([...idxPush(k), n.op]) }); i++; continue; }
    if (o.data === undefined && NAME1[o.op]) { t.push({ pure: true, name: NAME1[o.op], bytes: Uint8Array.from([o.op]) }); continue; }
    t.push({ pure: false, raw: o });
  }
  return t;
}
// serialize a token list back to a flat op list (parse of its bytes) for rebuild
function tokensToOps(toks) { const bytes = []; for (const t of toks) { if (t.pure) bytes.push(...t.bytes); else bytes.push(...serialize([t.raw])); } return parse(Uint8Array.from(bytes)); }

// ---------- greedy longest-window fold to fixpoint over pure runs ----------
const foldLog = new Map();
function foldRun(run) {
  // run: array of pure tokens. Greedy: at pos i, try window sizes 5..2, longest shorter-equiv wins.
  let changed = true; let cur = run.slice();
  while (changed) {
    changed = false; const out = [];
    let i = 0;
    while (i < cur.length) {
      let done = false;
      for (let w = Math.min(5, cur.length - i); w >= 2 && !done; w--) {
        const win = cur.slice(i, i + w);
        const wb = Uint8Array.from(win.reduce((a, t) => [...a, ...t.bytes], []));
        const L = wb.length; if (L < 2) continue;
        for (const cand of shorter(L)) {
          if (equiv(wb, cand.bytes)) {
            const key = `${win.map(t=>t.name).join(' ')}  =>  ${cand.name||'(delete)'} [${L}->${cand.bytes.length}B, -${L-cand.bytes.length}]`;
            foldLog.set(key, (foldLog.get(key)||0)+1);
            // push replacement as pure tokens (re-tokenize its bytes)
            for (const rt of tokenize(parse(cand.bytes))) out.push(rt);
            i += w; done = true; changed = true; break;
          }
        }
      }
      if (!done) { out.push(cur[i]); i++; }
    }
    cur = out;
  }
  return cur;
}
function foldOps(ops) {
  const toks = tokenize(ops); const out = [];
  let i = 0;
  while (i < toks.length) {
    if (!toks[i].pure) { out.push(toks[i]); i++; continue; }
    let j = i; while (j < toks.length && toks[j].pure) j++;
    for (const t of foldRun(toks.slice(i, j))) out.push(t);
    i = j;
  }
  return tokensToOps(out);
}

// ---------- apply to every body + main ----------
const override = new Map();
let bodyStart = 0, bodyNew = 0;
const rows = [];
for (const id of d0.order) {
  const orig = d0.bodies.get(id);
  const folded = serialize(foldOps(parse(orig)));
  override.set(id, folded);
  bodyStart += orig.length; bodyNew += folded.length;
  if (folded.length !== orig.length) rows.push({ id, from: orig.length, to: folded.length });
}
const mainNew = serialize(foldOps(d0.mainOps.slice()));
const mainOrig = serialize(d0.mainOps);
const rebuilt = rebuild(d0, override, mainNew);
writeFileSync(join(here, 'foldhunt-locking.hex'), Buffer.from(rebuilt).toString('hex'));
console.log(`\nfolds applied (distinct atomic identities):`);
[...foldLog.entries()].sort((a,b)=>b[1]-a[1]).forEach(([k,v]) => console.log(`  x${String(v).padStart(3)}  ${k}`));
console.log(`\nbodies changed: ${rows.length}/${d0.order.length}`);
rows.forEach(r => console.log(`  def#${r.id}: ${r.from}->${r.to} (-${r.from-r.to})`));
if (mainNew.length !== mainOrig.length) console.log(`  main: ${mainOrig.length}->${mainNew.length} (-${mainOrig.length-mainNew.length})`);
console.log(`\nNEW artifact: ${rebuilt.length} B  (delta vs 5613 = -${START.length - rebuilt.length} B)`);
console.log(`score (lock+359): ${rebuilt.length + 359}`);
console.log(`sha256: ${sha(rebuilt)}`);

// ================= GATE 1: identity round-trip byte-exact =================
console.log('\n== GATE 1: identity round-trip (decompile(new)->recompile == new) ==');
let RT_PASS = false;
try {
  const dNew = dissect(rebuilt);
  const irNew = decompileProgram(dNew, arity, 10);
  const rt = recompileProgram(dNew, irNew, arity);
  const rtExact = Buffer.from(rt.bytes).equals(Buffer.from(rebuilt));
  const bodiesExact = rt.perBody.filter((b) => b.exact).length;
  console.log(`  bodies byte-exact: ${bodiesExact}/${dNew.order.length}   main: ${rt.mainExact}   FULL: ${rtExact}`);
  if (rt.perBody.some((b) => !b.exact)) console.log('  NON-EXACT:', rt.perBody.filter((b)=>!b.exact).map((b)=>`def#${b.id}(${b.origLen}->${b.recLen})`).join(', '));
  RT_PASS = rtExact && bodiesExact === dNew.order.length && rt.mainExact;
} catch (e) { console.log(`  *** decompile THREW: ${e.message} -> ROUND-TRIP FAIL`); RT_PASS = false; }

// ================= GATE 2: per-subroutine differential =================
console.log('\n== GATE 2: per-subroutine differential (folded body vs crown body, random Fp) ==');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function mkrng(seed){let x=BigInt(seed)*6364136223846793005n+1n;return()=>{x=(x*6364136223846793005n+1442695040888963407n)&((1n<<64n)-1n);let z=x;z=(z^(z>>30n))*0xbf58476d1ce4e5b9n&((1n<<64n)-1n);z=(z^(z>>27n))*0x94d049bb133111ebn&((1n<<64n)-1n);return(z^(z>>31n))&((1n<<64n)-1n);};}
function randFp(rng){let v=0n;for(let i=0;i<4;i++)v=(v<<64n)|rng();return v%P;}
const eq=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
const NTRIAL=16; const fails=[]; let passB=0;
for (const id of d0.order) {
  const ov = new Map([[id, override.get(id)]]);
  let clean=0, mism=0;
  for (let s=0;s<NTRIAL;s++){
    const rng=mkrng(s*1009+id*7+1);
    const inputs=Array.from({length:arity[id].in},()=>randFp(rng));
    const ro=runSubroutine(d0,id,inputs);            // crown body
    const rs=runSubroutine(d0,id,inputs,ov);         // folded body
    if (ro.error) continue; clean++;
    if (!(!rs.error && eq(ro.stack, rs.stack))) mism++;
  }
  if (mism>0){ fails.push(id); console.log(`  def#${id} *** FAIL *** (${mism}/${clean})`); } else passB++;
}
console.log(`  bodies PASS: ${passB}/${d0.order.length}` + (fails.length?`  FAILURES def#${fails.join(', def#')}`:'  (all bit-identical)'));
const G2_PASS = fails.length === 0;

console.log('\n===================== SUMMARY =====================');
console.log(`locking bytes : ${rebuilt.length}  (was 5613; additional -${START.length-rebuilt.length} B)`);
console.log(`sha256        : ${sha(rebuilt)}`);
console.log(`GATE1 rt      : ${RT_PASS?'PASS':'FAIL'}`);
console.log(`GATE2 differ  : ${G2_PASS?'PASS':'FAIL'} (${passB}/${d0.order.length})`);
console.log(`OVERALL       : ${(RT_PASS&&G2_PASS)?'PASS (ready for parent E2E gate)':'FAIL'}`);
