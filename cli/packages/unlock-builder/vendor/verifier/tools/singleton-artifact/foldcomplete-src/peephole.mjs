// peephole.mjs -- PASS 3: local stack-op folding on a straight-line op list.
// Semantics-preserving rewrites of adjacent op pairs. Applied per-block (blocks are
// straight-line, so no control op ever sits between a folded pair). Idempotent; iterate
// to fixpoint. Note: the scheduler ALREADY emits OVER/DUP/SWAP/ROT directly (the fold is
// inlined in codegen), so on this artifact pass-3's incremental yield is measured, not
// assumed.
const b = (o) => (o.data === undefined && o._raw === undefined) ? o.op : (o._raw ? -1 : -2);

// small-int push opcode -> value (0x00=0, 0x51..0x60 = 1..16)
const intVal = (o) => {
  if (o._raw || o.data !== undefined) return null;
  if (o.op === 0x00) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  return null;
};
const OP = { PICK: 0x79, ROLL: 0x7a, OVER: 0x78, DUP: 0x76, SWAP: 0x7c, ROT: 0x7b, DROP: 0x75, NIP: 0x77,
  TUCK: 0x7d, TWODUP: 0x6e, TWODROP: 0x6d };

// RICHER-PEEPHOLE GRAMMAR (added 2026-07-02): three context-free, provably stack-preserving
// 2->1 folds that the per-block emitter / existing PASS-3 currently miss. Each is a bytecode-level
// local stack IDENTITY, matching the libauth VM opcode semantics exactly:
//   OP_OVER OP_OVER (78 78) -> OP_2DUP  (6e) : (a,b) -> (a,b,a,b)   [both]
//   OP_SWAP OP_OVER (7c 78) -> OP_TUCK  (7d) : (a,b) -> (b,a,b)     [both]
//   OP_DROP OP_DROP (75 75) -> OP_2DROP (6d) : (a,b) -> ()          [both]
// Fires ONLY when the two ops are truly adjacent in emit order (context-free): an adjacent pair
// in the parsed op list has NO op -- and in particular no control op -- between them, so the
// rewrite never crosses a block/control boundary. Conservative: only these three proven folds
// (e.g. OP_DUP OP_DUP is NOT a 2->1 identity and is excluded). Iterated to fixpoint.
export function peephole2(ops) {
  let cur = ops.slice();
  let changed = true;
  const stats = { twodup: 0, tuck: 0, twodrop: 0 };
  while (changed) {
    changed = false;
    const out = [];
    for (let i = 0; i < cur.length; i++) {
      const o = cur[i], n = cur[i + 1];
      if (n) {
        const ob = b(o), nb = b(n);
        if (ob === OP.OVER && nb === OP.OVER) { out.push({ op: OP.TWODUP });  i++; changed = true; stats.twodup++;  continue; }
        if (ob === OP.SWAP && nb === OP.OVER) { out.push({ op: OP.TUCK });    i++; changed = true; stats.tuck++;    continue; }
        if (ob === OP.DROP && nb === OP.DROP) { out.push({ op: OP.TWODROP }); i++; changed = true; stats.twodrop++; continue; }
      }
      out.push(o);
    }
    cur = out;
  }
  peephole2.lastStats = stats;
  return cur;
}

export function peephole(ops) {
  let cur = ops.slice();
  let changed = true;
  while (changed) {
    changed = false;
    const out = [];
    for (let i = 0; i < cur.length; i++) {
      const o = cur[i], n = cur[i + 1];
      if (n) {
        const v = intVal(o), nb = b(n);
        // [OP_k, PICK] -> depth-k copy : k=0 DUP, k=1 OVER
        if (v === 0 && nb === OP.PICK) { out.push({ op: OP.DUP }); i++; changed = true; continue; }
        if (v === 1 && nb === OP.PICK) { out.push({ op: OP.OVER }); i++; changed = true; continue; }
        // [OP_k, ROLL] -> k=1 SWAP, k=2 ROT (k=0 ROLL is a no-op)
        if (v === 0 && nb === OP.ROLL) { i++; changed = true; continue; }
        if (v === 1 && nb === OP.ROLL) { out.push({ op: OP.SWAP }); i++; changed = true; continue; }
        if (v === 2 && nb === OP.ROLL) { out.push({ op: OP.ROT }); i++; changed = true; continue; }
        const ob = b(o);
        // [SWAP, SWAP] -> nothing ; [DUP, DROP] -> nothing
        if (ob === OP.SWAP && nb === OP.SWAP) { i++; changed = true; continue; }
        if (ob === OP.DUP && nb === OP.DROP) { i++; changed = true; continue; }
        if (ob === OP.OVER && nb === OP.DROP) { i++; changed = true; continue; } // OVER then DROP = nop
        // [SWAP, DROP] -> NIP
        if (ob === OP.SWAP && nb === OP.DROP) { out.push({ op: OP.NIP }); i++; changed = true; continue; }
        // RICHER-PEEPHOLE folds (applied to fixpoint AFTER the existing rules, same loop):
        // [OVER, OVER] -> 2DUP ; [SWAP, OVER] -> TUCK ; [DROP, DROP] -> 2DROP
        if (ob === OP.OVER && nb === OP.OVER) { out.push({ op: OP.TWODUP });  i++; changed = true; continue; }
        if (ob === OP.SWAP && nb === OP.OVER) { out.push({ op: OP.TUCK });    i++; changed = true; continue; }
        if (ob === OP.DROP && nb === OP.DROP) { out.push({ op: OP.TWODROP }); i++; changed = true; continue; }
      }
      out.push(o);
    }
    cur = out;
  }
  return cur;
}
