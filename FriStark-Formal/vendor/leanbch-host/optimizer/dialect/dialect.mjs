// dialect/dialect.mjs — the Dialect interface: the ONLY format-coupled surface.
//
// The optimizer's IR (ir.mjs) and passes (passes/*) are format-agnostic. A Dialect is the
// thin adapter that knows how one concrete bytecode shape frames its function-definition table,
// encodes ids, and emits minted invoke/define sites. Swapping the Dialect retargets the whole
// tool to a new shape WITHOUT touching a pass or a proof.
//
// A Dialect has three faces, each with a distinct trust status:
//
//   parse (ORACLE — validated per-run by the gate's byte-exact round-trip; keep VM-FREE + TOTAL
//          so it stays Lean-upgradeable à la LeanBCH `Codec.parse_encode`):
//     isDefineAt(ops, i) -> bool        // does a define record start at ops[i]?
//     decodeId(op)       -> number|null // numeric id of a pushed id op
//
//   emit (CODEC — the LeanBCH `Codec.parse_encode` register; byte round-trip is provable):
//     encodeId(id)          -> op[]     // the id-push op(s)
//     emitInvoke(id)        -> op[]     // push id, then INVOKE
//     emitDefine(id, body)  -> op[]     // body push, id push, DEFINE
//
//   constants:
//     name          : string           // dialect id (goes in the trust report)
//     defineOpcode  : byte
//     invokeOpcode  : byte
//
// Later dialects (e.g. covenant-wrapped, P3) additionally provide wrapper/probe faces:
//     locateDefRegion(bytes) -> { prologue, defRegionOps, mainOps, epilogue }
//     buildProbeHarness(bundle, id, inputs) -> { locking, unlocking }
// cashc-standard omits these (empty wrapper; the shared synthetic-table probe suffices).
//
// TRUST RULE the manifest enforces: output trust = min(parse tier, transform tier). A dialect
// whose parse is byte-exact round-trip-certified is Tier-3-certified; one that is only
// structural (covenant) is a strictly weaker label and forbids round-trip-certified arity recovery.

/** Assert an object satisfies the minimal Dialect contract (fail fast on a bad adapter). */
export function assertDialect(d) {
  const need = ['name', 'defineOpcode', 'invokeOpcode', 'isDefineAt', 'decodeId', 'encodeId', 'emitInvoke', 'emitDefine'];
  for (const k of need) if (d[k] === undefined) throw new Error(`dialect '${d && d.name}': missing ${k}`);
  return d;
}
