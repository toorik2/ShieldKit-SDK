// T4-KP SPECIALIZER — source-to-source transform that bakes k*P into k-indexed subFp
// variants and specializes the whole bias-forwarding wrapper chain, deleting the runtime
// k-plumbing at every frame level. Exposes:
//   specializeLib()  -> { libText, neededList }  (the specialized Bn254LazyAff lib source)
//   rewriteChunk(src) -> chunk source with literal-k calls rewritten to _kN variants
// Semantics-null: every k*P literal is the exact same integer computed at runtime.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
// LOCAL: specialize from THIS worktree's base lib (differs from master — it's more optimized),
// so the k*P-baked variants are semantics-null against the code actually being measured.
const _here = dirname(fileURLToPath(import.meta.url));
const LIB = join(_here, '../../singleton/bn254/lib/lazy/Bn254LazyAff.cash');

// k-carrying functions: their LAST parameter is the bias k forwarded (transitively) to subFp.
const KCARRY = new Set(['subFp','fp2Sub','fp2Neg','fp2Conj','fp2MulXi','fp6Sub','fp6MulByV','fp6Neg']);

// --- parse top-level `function NAME(...) returns (...) { body }` blocks ---
function parseFunctions(src) {
  const lines = src.split('\n');
  const fns = new Map(); const order = [];
  let cur = null, buf = [], depth = 0, sigLine = '', seenOpen = false;
  const close = () => { fns.set(cur,{sig:sigLine,text:buf.join('\n')}); order.push(cur); cur=null; seenOpen=false; };
  for (const ln of lines) {
    const nOpen = (ln.match(/\{/g)||[]).length, nClose = (ln.match(/\}/g)||[]).length;
    if (cur === null) {
      const m = ln.match(/^function\s+([A-Za-z0-9_]+)\s*\(/);
      if (m) { cur = m[1]; buf = [ln]; sigLine = ln; depth = nOpen - nClose; if (nOpen>0) seenOpen = true; if (seenOpen && depth===0) close(); }
    } else {
      buf.push(ln); depth += nOpen - nClose; if (nOpen>0) seenOpen = true;
      if (seenOpen && depth===0) close(); // close only after the body brace has actually opened
    }
  }
  return { fns, order };
}

// find the matching close paren index for an open paren at position `open` in text
function matchParen(text, open) {
  let d = 0;
  for (let i = open; i < text.length; i++) { if (text[i]==='(') d++; else if (text[i]===')') { d--; if (d===0) return i; } }
  return -1;
}
// split a comma-separated arg list (top level only) into trimmed strings
function topArgs(inner) {
  const args = []; let d = 0, s = 0;
  for (let i=0;i<inner.length;i++){ const c=inner[i]; if(c==='('||c==='[')d++; else if(c===')'||c===']')d--; else if(c===','&&d===0){args.push(inner.slice(s,i));s=i+1;} }
  args.push(inner.slice(s)); return args.map(a=>a.trim());
}
const isIntLit = (s) => /^\d+$/.test(s);

// Rewrite every call FN(args..., <intlit>) with FN in KCARRY -> FN_k<lit>(args-minus-last).
// Records needed (FN,K). Runs to a fixpoint (handles nesting). Returns {out, needed:Set('FN|K')}.
function rewriteCalls(text, needed) {
  let changed = true; let out = text;
  while (changed) {
    changed = false;
    // scan for a k-carrying call whose last top-level arg is a pure int literal, innermost-first
    // (process leftmost occurrence each pass; loop to fixpoint)
    let best = null;
    const re = /\b(subFp|fp2Sub|fp2Neg|fp2Conj|fp2MulXi|fp6Sub|fp6MulByV|fp6Neg)\(/g;
    let m;
    while ((m = re.exec(out))) {
      const fn = m[1]; const open = m.index + m[0].length - 1;
      // skip a DEFINITION: preceding token is 'function'
      const pre = out.slice(0, m.index).trimEnd();
      if (pre.endsWith('function')) continue;
      const close = matchParen(out, open);
      if (close < 0) continue;
      const inner = out.slice(open+1, close);
      const args = topArgs(inner);
      const last = args[args.length-1];
      if (!isIntLit(last)) continue;
      // choose the call with the DEEPEST (latest-starting) match to handle nesting inner-first
      if (!best || m.index > best.mi) best = { fn, mi: m.index, open, close, args, K: last };
    }
    if (best) {
      const { fn, mi, close, args, K } = best;
      const newArgs = args.slice(0, -1).join(', ');
      const repl = `${fn}_k${K}(${newArgs})`;
      // find the start of the call name
      const nameStart = out.lastIndexOf(fn, best.open);
      out = out.slice(0, nameStart) + repl + out.slice(close+1);
      needed.add(`${fn}|${K}`);
      changed = true;
    }
  }
  return out;
}

// Build a specialized def for (FN,K): clone body, substitute whole-word k -> K, rewrite inner calls.
function makeVariant(fnText, fn, K, needed) {
  // replace signature: `function FN(...) returns` -> `function FN_kK(... minus last int k) returns`
  const sigMatch = fnText.match(/^function\s+[A-Za-z0-9_]+\s*\(([^]*?)\)\s*returns\s*\(([^]*?)\)\s*\{/);
  if (!sigMatch) throw new Error('cannot parse signature of '+fn);
  const params = topArgs(sigMatch[1]);
  const rettypes = sigMatch[2];
  const newParams = params.slice(0, -1).join(', '); // drop trailing `int k`
  const bodyStart = fnText.indexOf('{');
  let body = fnText.slice(bodyStart+1, fnText.lastIndexOf('}'));
  if (fn === 'subFp') {
    body = ` return x - y + ${(BigInt(K)*P).toString()}; `; // bake k*P literal directly
  } else {
    body = body.replace(/\bk\b/g, K);              // substitute the bias k literal
    body = rewriteCalls(body, needed);              // subFp(...,K) -> subFp_kK etc
  }
  return `function ${fn}_k${K}(${newParams}) returns (${rettypes}) {${body}}`;
}

export function specializeLib(seedSources = []) {
  const src = readFileSync(LIB, 'utf8');
  const { fns } = parseFunctions(src);
  // 1) rewrite all NON-k-carrying function bodies' literal-k calls; collect needed variants
  const needed = new Set();
  // SEED: also collect variants demanded directly by caller-supplied chunk sources (the SHARED
  // body's affDblT/affAddT/fold call subFp(...,3) etc. which the base lib alone never triggers).
  for (const seed of (seedSources || [])) rewriteCalls(seed, needed);
  const outParts = [];
  for (const [name, obj] of fns) {
    if (KCARRY.has(name)) { outParts.push(obj.text); continue; } // keep originals (DCE'd if unused)
    outParts.push(rewriteCalls(obj.text, needed));
  }
  // 2) close the variant set to a fixpoint (variant bodies call other variants)
  const emitted = new Map();
  let frontier = [...needed];
  while (frontier.length) {
    const next = [];
    for (const key of frontier) {
      if (emitted.has(key)) continue;
      const [fn, K] = key.split('|');
      const def = makeVariant(fns.get(fn).text, fn, K, needed);
      emitted.set(key, def);
      // any newly-added needed keys go to the frontier
      for (const nk of needed) if (!emitted.has(nk) && !next.includes(nk)) next.push(nk);
    }
    frontier = next.filter(k => !emitted.has(k));
  }
  const libText = [ ...emitted.values(), ...outParts ].join('\n\n') + '\n';
  return { libText, needed: [...emitted.keys()].sort() };
}

export function rewriteChunk(src) {
  const needed = new Set();
  return rewriteCalls(src, needed); // chunk's direct fp2Neg(...,64) etc -> _k64 (variants live in specialized lib)
}

if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const { libText, needed } = specializeLib();
  console.log('needed specializations (', needed.length, '):');
  console.log(needed.join('  '));
  console.log('\nspecialized lib bytes:', libText.length);
  // sanity: show the generated subFp_k12 and fp6Sub_k12
  for (const nm of ['subFp_k12','fp2Sub_k12','fp6Sub_k12','fp2Neg_k64','fp2MulXi_k9']) {
    const re = new RegExp('function '+nm+'\\b[^]*?\\n?}', 'm');
    const mm = libText.match(re);
    console.log('\n--- '+nm+' ---\n'+(mm?mm[0]:'(not generated)'));
  }
}
