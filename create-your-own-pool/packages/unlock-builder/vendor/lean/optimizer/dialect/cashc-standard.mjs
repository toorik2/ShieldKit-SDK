// dialect/cashc-standard.mjs — the cashc "reusable functions" define/invoke framing.
//
// A Dialect is the ONLY format-coupled code in the optimizer. The IR + passes are
// format-agnostic; a Dialect knows how the function-definition table is framed in bytes,
// how ids are encoded, and how to emit a minted invoke/define. Swapping the Dialect
// retargets the tool to a different bytecode shape WITHOUT touching the passes or proofs.
//
// This adapter is a FAITHFUL EXTRACTION of the framing the singleton pipeline hardcoded:
// the define table is a run of `[body-push][id-push][OP_DEFINE]` triples at the head of the
// program, ids are OP_1..OP_16 (1..16) or a minimal VM-number push, and OP_INVOKE consumes
// a pushed id. Every method returns EXACTLY the bytes the old inline code produced, so the
// refactor is behavior-preserving (byte-identity gate).
//
// See dialect/dialect.mjs for the interface contract these adapters satisfy.
import { bigIntToVmNumber } from '@bitauth/libauth';

const DEFINE = 0x89;
const INVOKE = 0x8a;

/** Decode a pushed id op back to its numeric id (mirror of the old `idVal`). VM-free + total. */
function decodeId(o) {
  if (!o) return null;
  if (o.op === 0) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;           // OP_1..OP_16
  if (o.data && o.data.length <= 2) { let v = 0; for (let i = o.data.length - 1; i >= 0; i--) v = (v << 8) | o.data[i]; return v; }
  return null;
}

/** The id-push op(s) for a numeric id: OP_n for 1..16, else a minimal VM-number push.
 *  Matches both the arity-probe target encoding and CSE's minted-id encoding (ids >= 40
 *  serialize to a single PUSHBYTES_1 of the id byte, identical to the old `[id]` push). */
function encodeId(id) {
  if (id >= 1 && id <= 16) return [{ op: 0x50 + id }];
  return [{ op: 0, data: bigIntToVmNumber(BigInt(id)) }];
}

export const cashcStandard = {
  name: 'cashc-standard',
  defineOpcode: DEFINE,
  invokeOpcode: INVOKE,

  // ---- parse (oracle face) ----
  /** True iff a `[body-push][id-push][OP_DEFINE]` triple starts at ops[i]. */
  isDefineAt(ops, i) {
    return i + 2 < ops.length && !!ops[i].data && !!ops[i + 2] && ops[i + 2].op === DEFINE;
  },
  decodeId,

  // ---- emit (codec face) ----
  encodeId,
  /** ops that push `id` then OP_INVOKE. */
  emitInvoke(id) { return [...encodeId(id), { op: INVOKE }]; },
  /** ops for one define record: body push, id push, OP_DEFINE. */
  emitDefine(id, body) { return [{ op: 0, data: body }, ...encodeId(id), { op: DEFINE }]; },
};

export default cashcStandard;
