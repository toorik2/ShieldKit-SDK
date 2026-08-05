// T1 DEFINE-LIB architecture core — proven on the REAL SZ-miller chunk code.
// Reuses gen_miller_sz.genChunk (real w=1 SZ math, untouched) + Bn254LazyAff.cash (shared tower).
// Transforms a covenant SZ chunk into a state-via-SIBLING intratx chunk (blob-in + forward-check),
// then externalizes the chunk body into a scored library input read by executors via
// OP_INPUTBYTECODE -> hash-pin -> OP_DEFINE -> OP_INVOKE (the CR-probe primitive, PASSED real VM).
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';
import {
  genChunk, committedIn, pushedArgs, outLimbs, STATE,
} from './gen_miller_sz.mjs';
import { compileFileBytecode } from './_millermath.mjs';
import {
  bigIntToVmNumber, encodeDataPush, hash256, binToHex,
  encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
export const GEN = process.env.C7_GEN || join(here, 'generated');
const REPO_ROOT = resolve(here, '../../../');
const CASH_SINGLETON_ROOT = join(REPO_ROOT, 'build', 'singleton');
export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const PRIME = P.toString();
const W = 40;
const HINT_IDX = STATE.indexOf('hInt'); // 38 — the only RAW (unreduced) state limb

// CashScript resolves imports relative to the generated source file. Keep generated probes
// relocatable: C7_GEN may be outside the repository, but the imported library remains in-tree.
export function relocateCashImports(src, targetPath) {
  return src.replace(/import\s+"\.\.\/\.\.\/\.\.\/singleton\/([^"]+)";/g, (_, relPath) => {
    let importPath = relative(dirname(targetPath), join(CASH_SINGLETON_ROOT, relPath)).replaceAll('\\', '/');
    if (!importPath.startsWith('.')) importPath = `./${importPath}`;
    return `import "${importPath}";`;
  });
}

// ---- opcodes ----
export const OP = {
  _0: 0x00, _1: 0x51, _2: 0x52, _3: 0x53, _4: 0x54,
  DROP: 0x75, DUP: 0x76, NIP: 0x77, SPLIT: 0x7f, CAT: 0x7e,
  EQUAL: 0x87, EQUALVERIFY: 0x88, HASH256: 0xaa,
  INPUTBYTECODE: 0xca, DEFINE: 0x89, INVOKE: 0x8a,
};
export const cat = (...xs) => { const t = xs.reduce((n, x) => n + x.length, 0); const o = new Uint8Array(t); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
export const b = (...xs) => Uint8Array.from(xs);
const vm = (n) => bigIntToVmNumber(BigInt(n));
export const push = (d) => encodeDataPush(d);
const pushInt = (n) => encodeDataPush(vm(n));
const mod = (x) => ((BigInt(x) % P) + P) % P;

// 40-byte little-endian limb, matching cashscript toPaddedBytes(x,40); hInt kept RAW (unreduced).
const le40raw = (n) => { let v = BigInt(n); const o = new Uint8Array(40); for (let i = 0; i < 40; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; };
// state blob for an intratx chunk's inBlob: reduce every limb mod P EXCEPT hInt (index 38), raw.
export const szBlob = (limbs) => cat(...limbs.map((l, i) => le40raw(i === HINT_IDX ? BigInt(l) : mod(l))));

// ---- SZ-aware intratx transform ----------------------------------------------------------------
// Turn a covenant SZ chunk (covIn(STATE)/covOut(...succSpk)) into a linked intratx chunk:
//   prologue: split the incoming state out of `bytes inBlob` (STATE order), casting each limb int().
//   epilogue: rebuild outBlob using the generator's OWN covOut serialization expr (verbatim, so the
//     canonical/%Pmod split + hInt-raw handling is preserved byte-for-byte), then either
//       forward:  require(outBlob == tx.inputs[activeInputIndex+1].unlockingBytecode.split(off)[1].split(cmpLen)[0])
//       terminal: require(outBlob.length == outLen)   (consume it; last executor has no in-tx successor)
// The arithmetic body between covIn and covOut is reused VERBATIM.
export function szIntratx(src, cfg) {
  const lines = src.split('\n');
  const sigIdx = lines.findIndex((l) => /function spend\(/.test(l));
  const header = lines.slice(0, sigIdx);
  const ciIdx = lines.findIndex((l) => l.includes('activeInputIndex].nftCommitment'));
  const coIdx = lines.findIndex((l, i) => i > ciIdx && l.includes('tx.outputs[0].nftCommitment'));
  // ALL spend params in declaration order except the trailing `bytes unused zeroPadding` pad.
  // The blob layout is: STATE(45) limbs, then the per-step witnesses (fout + slopes), all 40-byte LE.
  const sig = lines[sigIdx];
  const inner = sig.slice(sig.indexOf('(') + 1, sig.lastIndexOf(')'));
  const allNames = inner.split(',').map((p) => p.trim()).map((p) => {
    const m = p.match(/^int\s+(\w+)$/); return m ? m[1] : null; // ints only; drops `bytes unused zeroPadding`
  }).filter(Boolean);
  // validate covIn binds the first 45 (STATE) — the committed boundary the forward-check compares.
  const ciNames = [...lines[ciIdx].matchAll(/toPaddedBytes\((\w+),\s*40\)/g)].map((m) => m[1]);
  if (ciNames.join(',') !== STATE.join(',')) throw new Error('covIn != STATE');
  if (allNames.slice(0, 45).join(',') !== STATE.join(',')) throw new Error('sig prefix != STATE');

  // extract covOut EXPR = the argument to hash256(...) — reused verbatim as outBlob (preserves the
  // canonical/%Pmod split + hInt-raw serialization byte-for-byte).
  const coLine = lines[coIdx];
  const hstart = coLine.indexOf('hash256(') + 'hash256('.length;
  let depth = 1, k = hstart;
  for (; k < coLine.length; k++) { if (coLine[k] === '(') depth++; else if (coLine[k] === ')') { depth--; if (depth === 0) break; } }
  const outExpr = coLine.slice(hstart, k);
  const outNames = [...coLine.matchAll(/toPaddedBytes\((\w+)(?:\s*%\s*Pmod)?,\s*40\)/g)].map((m) => m[1]);
  const outLen = outNames.length * W; // 45 state limbs => 1800

  const hasPmod = /int Pmod =/.test(lines[coIdx - 1]);
  const body = lines.slice(ciIdx + 1, hasPmod ? coIdx - 1 : coIdx);

  const epilogue = [`        int Pmod = ${PRIME};`, `        bytes outBlob = ${outExpr};`];
  if (cfg.forward) {
    const off = 3 + (cfg.skip ?? 0); // successor's inBlob is its FIRST push; PUSHDATA2 header = 3 B
    epilogue.push(`        require(outBlob == tx.inputs[this.activeInputIndex + 1].unlockingBytecode.split(${off})[1].split(${cfg.cmpLen ?? outLen})[0]);`);
  } else {
    epilogue.push(`        require(outBlob.length == ${outLen});`);
  }

  // prologue: sequential split of inBlob into the limbs the body/epilogue actually reference.
  // Unread limbs before the last read one are split PAST (cursor advance); trailing unread ones skipped.
  const usedText = [...body, ...epilogue].join('\n');
  const used = allNames.map((nm) => new RegExp(`\\b${nm}\\b`).test(usedText));
  let maxUsed = -1; used.forEach((u, p) => { if (u) maxUsed = p; });
  const prologue = [];
  let cur = 'inBlob';
  for (let p = 0; p <= maxUsed; p++) {
    const nm = allNames[p];
    if (p === maxUsed) prologue.push(p === allNames.length - 1 ? `        int ${nm} = int(${cur});` : `        int ${nm} = int(${cur}.split(40)[0]);`);
    else if (used[p]) { prologue.push(`        bytes hh${p}, bytes rr${p} = ${cur}.split(40); int ${nm} = int(hh${p});`); cur = `rr${p}`; }
    else { prologue.push(`        bytes rr${p} = ${cur}.split(40)[1];`); cur = `rr${p}`; }
  }
  const newSig = '    function spend(bytes inBlob) {';
  return { src: [...header, newSig, ...prologue, ...body, ...epilogue, '    }', '}'].join('\n'), allNames, outNames, outLen };
}

// ---- compile a transformed chunk to redeem bytecode (import resolves from generated/) ----
let _probeN = 0;
export function compileIntratx(transformedSrc) {
  const pth = join(GEN, `_t1_probe_${_probeN++}.cash`);
  writeFileSync(pth, relocateCashImports(transformedSrc, pth));
  return Uint8Array.from([...compileFileBytecode(pth)]);
}

// ---- extras: pushedArgs beyond the 45 STATE limbs are the per-step witnesses (fout+slopes) ----
// they are declared params AFTER STATE and BEFORE the trailing `zeroPadding` pad. In intratx they
// stay as int params in the ORIGINAL order but must be pushed after inBlob. We fold them INTO the
// contract by leaving them as spend params? No — szIntratx collapses the whole signature to
// (bytes inBlob). So the step-witnesses must ride INSIDE inBlob too. Handle in caller via wide blob.
export { PRIME, W, HINT_IDX };

export const realVm = createVirtualMachineBch2026(false);
export const p2sh32 = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
export const accept = (st) => st.error === undefined && st.stack.length === 1 && st.stack[0]?.length === 1 && st.stack[0][0] === 1;
