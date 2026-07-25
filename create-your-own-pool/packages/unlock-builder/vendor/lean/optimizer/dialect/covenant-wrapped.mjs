// dialect/covenant-wrapped.mjs — the DEPLOYED covenant-chunk framing (ANALYZE-ONLY).
//
// A deployed chunk wraps the verifier in a covenant self-check: a prologue of the form
//   DROP DUP OP_HASH256 <32-byte commitment> OP_EQUALVERIFY ...
// which REQUIRES that the (witness-supplied) body blob hashes to a committed constant. That
// commitment is pinned by an already-on-chain parent output. So if the optimizer changed any body,
// its hash would no longer match the commitment and the covenant becomes UNSPENDABLE (or, worse, a
// forgery vector). ⇒ in-place optimization of a deployed covenant chunk is UNSOUND, always.
//
// This dialect therefore refuses to emit. Its value is (1) RECOGNIZING the covenant framing (so the
// CLI auto-selects analyze-only), (2) the safe/unsafe CLASSIFIER that proves the refusal is
// warranted, and (3) locating the wrapper so op-cost analysis can proceed. Producing a *deployable*
// optimized chunk is a separate, harder tool (re-thread every commitment across the chain) and is an
// explicit non-goal. Inherits cashc-standard's id/opcode conventions for the inner framing.
import { cashcStandard } from './cashc-standard.mjs';

const HASH256 = 0xaa, HASH160 = 0xa9, SHA256 = 0xa8;
const EQUALVERIFY = 0x88, EQUAL = 0x87;
const isHash = (op) => op === HASH256 || op === HASH160 || op === SHA256;

/** Parse bytecode into flat op records (op + optional data) — same shape core/asm uses. */
function ops(b) {
  const out = []; let i = 0;
  while (i < b.length) {
    const op = b[i]; const s = i; i++;
    let data;
    if (op >= 1 && op <= 0x4b) { data = b.slice(i, i + op); i += op; }
    else if (op === 0x4c) { const n = b[i]; i++; data = b.slice(i, i + n); i += n; }
    else if (op === 0x4d) { const n = b[i] | (b[i + 1] << 8); i += 2; data = b.slice(i, i + n); i += n; }
    else if (op === 0x4e) { const n = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24); i += 4; data = b.slice(i, i + n); i += n; }
    out.push({ op, data, at: s });
  }
  return out;
}

/** Does this bytecode start with a covenant self-check prologue? (the auto-detect signature) */
export function looksCovenant(bytes) {
  const o = ops(bytes);
  // a hash op feeding an EQUAL/EQUALVERIFY within the first ~10 ops, BEFORE the first OP_DEFINE
  const firstDef = o.findIndex((x) => x.op === cashcStandard.defineOpcode);
  const head = o.slice(0, firstDef < 0 ? o.length : firstDef);
  for (let k = 0; k < head.length - 1; k++)
    if (isHash(head[k].op) && (head[k + 1].op === EQUALVERIFY || head[k + 1].op === EQUAL || head[k + 2]?.op === EQUALVERIFY))
      return true;
  return false;
}

/** Split covenant bytecode into { prologue, defRegionOps, mainOps, epilogue }. The prologue is the
 *  ops up to the first OP_DEFINE; the def region + main follow the cashc-standard inner framing. */
export function locateDefRegion(bytes) {
  const o = ops(bytes);
  const firstDef = o.findIndex((x) => x.op === cashcStandard.defineOpcode);
  if (firstDef < 0) return { prologue: o, defRegionOps: [], mainOps: [], epilogue: [] };
  // the define run starts 2 ops before the first DEFINE ([body|split-recipe][id][DEFINE])
  const defStart = Math.max(0, firstDef - 2);
  return { prologue: o.slice(0, defStart), defRegionOps: o.slice(defStart), mainOps: [], epilogue: [] };
}

/** Prove the refusal: is there a hash-commitment in the prologue that pins the (mutable) body blob?
 *  Returns { safe, reason }. safe=false ⇒ optimizing bodies breaks the commitment ⇒ refuse to emit. */
export function classifyEmitSafety(bytes) {
  const { prologue } = locateDefRegion(bytes);
  for (let k = 0; k < prologue.length - 1; k++)
    if (isHash(prologue[k].op) && (prologue[k + 1].op === EQUALVERIFY || prologue[k + 2]?.op === EQUALVERIFY))
      return { safe: false, reason: `prologue op#${k} ${'0x' + prologue[k].op.toString(16)} (hash) feeds EQUALVERIFY — the body blob is hash-committed; optimizing it breaks the commitment (unspendable/forgeable).` };
  return { safe: false, reason: 'covenant dialect is analyze-only by policy (deployable re-optimization needs whole-chain commitment re-threading — a separate tool).' };
}

export const covenantWrapped = {
  ...cashcStandard,             // inherit id/opcode conventions for the inner framing
  name: 'covenant-wrapped',
  analyzeOnly: true,
  looksCovenant,
  locateDefRegion,
  classifyEmitSafety,
};

export default covenantWrapped;
