// ir.mjs — the canonical, dialect-INDEPENDENT intermediate representation.
//
// This is the frozen contract between the format-coupled edges (dialect/*) and the
// format-agnostic optimizer passes (passes/*). The passes operate ONLY on this IR;
// they never see byte framing. A dialect produces the IR at parse and consumes it at
// emit. See dialect/dialect.mjs for the edge contract.
//
// THE BUNDLE (what a dialect.parse produces / a dialect.recompile consumes):
//   { bodies: Map<id, Item[]>,   // decompiled function bodies, keyed by define id
//     main:   Item[],            // the main routine
//     arity:  Map<id,{in,out}>,  // probed subroutine arities (part of the contract)
//     shell }                    // dialect-OPAQUE carrier: def order, verbatim frame
//                                // bytes (id/DEFINE records, body-push headers), and any
//                                // wrapper (covenant prologue/epilogue). Passes MUST NOT
//                                // read or mutate `shell` — they carry it through untouched.
//
// AN ITEM is either a straight-line block or a control op:
//   Block: { block: { entryDepth, entryAlt, exit: Ref[], exitAlt: Ref[], rawOps, opRange } }
//   Ctrl:  { ctrl: <opcode>, isVerify: bool }
//
// A REF (in exit / node inputs) is one of:
//   { k:'in',    i }              // main-stack input slot i
//   { k:'ain',   i }              // alt-stack input slot i
//   { k:'const', data, enc }      // a constant; `enc` = the EXACT bytes to re-emit (fidelity)
//   { k:'out',   node, j }        // output j of a value-producing node
// A NODE (value producer) is one of:
//   { k:'prim',   code, ins }     // a primitive op with input refs
//   { k:'invoke', invId, ins }    // a subroutine call with input refs
//
// FIDELITY INVARIANT (why this IR is a *sufficient* contract):
//   Every leaf that cannot be re-derived from its semantic value carries its exact bytes:
//   consts carry `enc`; each block carries `rawOps` (so the IDENTITY path re-emits byte-exact
//   straight from the IR). `prim`/`invoke` nodes are re-emitted THROUGH the dialect (their bytes
//   are a function of the dialect, not stored) — so they never appear on the identity/round-trip
//   path; only rescheduled/minted sites go through the dialect emitter.
//
// The IR shapes themselves live in core/decompile.mjs (the decompiler that produces them);
// this module is the NAMED CONTRACT + light guards. Freezing it here is the seam that lets a
// new dialect be added without touching a single pass.

/** Is this item a straight-line block (vs a control op)? */
export const isBlock = (item) => item && item.block !== undefined;
/** Is this item a control op (IF/ELSE/ENDIF/BEGIN/UNTIL/VERIFY…)? */
export const isCtrl = (item) => item && item.ctrl !== undefined;

/** Shallow shape check on a parsed bundle — catches a dialect returning the wrong shape. */
export function assertBundle(b) {
  if (!b || !(b.bodies instanceof Map) || !Array.isArray(b.main) || !(b.arity && typeof b.arity === 'object'))
    throw new Error('ir: malformed bundle (need {bodies:Map, main:[], arity, shell})');
  return b;
}

export const REF_KINDS = ['in', 'ain', 'const', 'out'];
export const NODE_KINDS = ['prim', 'invoke'];
