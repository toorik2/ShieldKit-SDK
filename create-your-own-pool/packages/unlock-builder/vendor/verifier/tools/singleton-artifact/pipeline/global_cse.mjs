// GLOBAL-CSE pass: constant-hoisting (p-pool) + body-dedup, applied over the whole
// program (all subroutine bodies + main), at the parsed op-stream level.
//
//  [A] p-POOL: the BN254 field modulus p is baked as a 32-byte push (33-byte token
//      0x20||pLE) 6x across def#1..6. Hoist to a nullary OP_DEFINE at a free id whose
//      body simply pushes p; rewrite each inline p-push -> `OP_<id> INVOKE` (2 bytes).
//  [B] BODY-DEDUP: byte-identical subroutine bodies (def#14==def#15) are merged: keep
//      the lowest id, redirect every `OP_<dup> INVOKE` -> `OP_<keep> INVOKE`, drop the
//      duplicate DEFINE record.
//
// Sound (semantics-preserving: same value pushed / same subroutine invoked), general
// (p is the universal BN254 modulus; no vk_x / statement baking), op-count neutral per use.
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';

const DEFINE = 0x89, INVOKE = 0x8a;
export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const toLE = (x, n) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; };
const pLE = toLE(P, 32);

const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const idVal = (o) => {
  if (!o) return null;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  if (o.data && o.data.length >= 1 && o.data.length <= 2) { let v = 0; for (let i = o.data.length - 1; i >= 0; i--) v = (v << 8) | o.data[i]; return v; }
  return null;
};
// build the id-push op record for a given subroutine id (matches the define/invoke encoding)
const idPushOp = (id) => (id >= 1 && id <= 16) ? { op: 0x50 + id } : { op: 0, data: Uint8Array.from([id]) };

// Rewrite an op stream: (1) replace each 32-byte p-push with [OP_poolId, INVOKE];
// (2) for consecutive [id-push, INVOKE] whose id is in `redirect`, swap the id-push.
function rewriteOps(ops, poolId, redirect) {
  const out = [];
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    if (o.data && o.data.length === 32 && eq(o.data, pLE)) {
      out.push(idPushOp(poolId), { op: INVOKE });
      continue;
    }
    // invoke-redirect: id-push directly followed by INVOKE
    if (i + 1 < ops.length && ops[i + 1].op === INVOKE) {
      const v = idVal(o);
      if (v != null && redirect.has(v)) { out.push(idPushOp(redirect.get(v)), ops[i + 1]); i++; continue; }
    }
    out.push(o);
  }
  return out;
}

export function globalCse(bytes, { poolId = 13 } = {}) {
  const d = dissect(bytes);
  if (d.order.includes(poolId)) throw new Error(`poolId ${poolId} already defined`);

  // [B] find byte-identical duplicate bodies -> redirect map (dup id -> keep id)
  const firstByHex = new Map();       // bodyHex -> keep id (lowest)
  const redirect = new Map();         // dup id -> keep id
  for (const id of d.order) {
    const h = Buffer.from(d.bodies.get(id)).toString('hex');
    if (firstByHex.has(h)) redirect.set(id, firstByHex.get(h));
    else firstByHex.set(h, id);
  }

  // Rewrite every body + main
  const newBodies = new Map();
  for (const id of d.order) newBodies.set(id, serialize(rewriteOps(parse(d.bodies.get(id)), poolId, redirect)));
  const newMain = serialize(rewriteOps(d.mainOps, poolId, redirect));

  // Reassemble define table: p-define FIRST, then original defines minus dropped dups.
  const recs = [];
  const pBody = serialize([{ op: 0, data: pLE }]); // 0x20 || pLE (33 bytes)
  recs.push({ id: poolId, body: pBody });
  for (const id of d.order) { if (redirect.has(id)) continue; recs.push({ id, body: newBodies.get(id) }); }

  const ops = [];
  for (const r of recs) { ops.push({ op: 0, data: r.body }); ops.push(idPushOp(r.id)); ops.push({ op: DEFINE }); }
  for (const o of parse(newMain)) ops.push(o);
  return { bytes: serialize(ops), poolId, dropped: [...redirect.keys()], redirect };
}
