// Hardened decompiler: a subroutine body -> linear sequence of [Block | CtrlOp].
//
// Each Block is a straight-line segment transforming an entry stack of `entryDepth`
// opaque main slots + `entryAlt` alt slots into an exit main+alt layout of value-DAGs
// over those slots. Control opcodes (IF/NOTIF/ELSE/ENDIF/BEGIN/UNTIL and the
// side-effecting require checks VERIFY/NUMEQUALVERIFY/EQUALVERIFY) are recorded
// verbatim between blocks. Because each block's entry stacks are relabeled as fresh
// slots and BOTH the main and alt physical layouts are preserved at every boundary,
// blocks can be re-scheduled independently and recomposed with the ctrl opcodes
// unchanged.
//
// HARDENING over the prior art (mr-zwets recompiler/decompile.mjs), per ARCHITECT:
//   (a) branch-shape consistency  -- THEN and ELSE arms must leave identical main AND
//       alt depths at ENDIF; an IF-without-ELSE arm must be depth-neutral. Fail loud.
//   (b) loop-invariance          -- the layout at OP_UNTIL (after popping the cond)
//       must equal the layout at the matching OP_BEGIN, else the loop desyncs across
//       iterations. Fail loud.
//   (c) verify-boundary tagging  -- ctrl items that are require()/verify checks are
//       tagged so the differential tester feeds VALID witnesses instead of random Fp.
//   (d) provenance hooks         -- optional opIndex range carried per block for the
//       Step-3 shallow-layout regalloc (cashc debug.sourceMap join).
//
// decompile(body, arity, inArity) throws (does not silently mis-model) on: unknown
// INVOKE id, unhandled opcode, stack underflow, or a broken branch/loop invariant.
import { parse, serialize } from './asm.mjs';
const serializeOne = (o) => serialize([o]);

export const OPC = {
  TOALT: 0x6b, FROMALT: 0x6c, '2DROP': 0x6d, '2DUP': 0x6e,
  '2OVER': 0x70, '2ROT': 0x71, '2SWAP': 0x72, NIP: 0x77, OVER: 0x78,
  PICK: 0x79, ROLL: 0x7a, ROT: 0x7b, SWAP: 0x7c, TUCK: 0x7d,
  DROP: 0x75, DUP: 0x76,
  IF: 0x63, NOTIF: 0x64, BEGIN: 0x65, UNTIL: 0x66, ELSE: 0x67, ENDIF: 0x68,
  INVOKE: 0x8a, DEFINE: 0x89, NUMEQUALVERIFY: 0x9d, VERIFY: 0x69, EQUALVERIFY: 0x88,
};
// side-effecting require() checks: pop operands, produce no value -> block boundaries.
export const VERIFY_OPS = new Set([OPC.VERIFY, OPC.NUMEQUALVERIFY, OPC.EQUALVERIFY]);
export const CTRL = new Set([OPC.IF, OPC.NOTIF, OPC.BEGIN, OPC.UNTIL, OPC.ELSE, OPC.ENDIF,
  OPC.NUMEQUALVERIFY, OPC.VERIFY, OPC.EQUALVERIFY]);
// value-producing ops: opcode -> {in, out}
export const VALOP = new Map([
  [0x8b, [1, 1]], [0x91, [1, 1]],                                                 // 1ADD, NOT
  [0x8d, [2, 1]], [0x8e, [2, 1]],                                                 // LSHIFTNUM, RSHIFTNUM
  [0x93, [2, 1]], [0x94, [2, 1]], [0x95, [2, 1]], [0x96, [2, 1]], [0x97, [2, 1]], // ADD SUB MUL DIV MOD
  [0x9a, [2, 1]], [0x9b, [2, 1]], [0x9c, [2, 1]], [0x9e, [2, 1]], [0x9f, [2, 1]], // BOOLAND BOOLOR NUMEQUAL NUMNOTEQUAL LESSTHAN
  [0xa0, [2, 1]], [0xa1, [2, 1]], [0xa2, [2, 1]],                                 // GREATERTHAN LE GE
]);

function constNum(ref) {
  if (!ref || ref.k !== 'const') return null;
  const d = ref.data;
  if (d.length === 0) return 0;
  let n = 0n;
  for (let i = d.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(d[i] & (i === d.length - 1 ? 0x7f : 0xff));
  if (d[d.length - 1] & 0x80) n = -n;
  return Number(n);
}

let UID = 0;
const freshNode = (props) => ({ id: ++UID, ...props });

export function decompile(body, arity, inArity = 0, ctx = {}) {
  const label = ctx.label ?? '?';
  const ops = parse(body);
  const items = [];
  let main = new Array(inArity).fill(0).map((_, i) => ({ k: 'in', i })); // body starts with input args
  let alt = [];
  let entryDepth = 0, entryAlt = 0;
  let rawStart = 0;
  // control reconciliation stacks
  const ctrlDepth = []; // {m, a, thenM, thenA, hadElse, opIndex}
  const loopStack = []; // {m, a, opIndex}

  const fail = (msg, i) => { throw new Error(`[body ${label}] ${msg} at op#${i}`); };
  const pop = (i, why) => { if (main.length === 0) fail(`main underflow (${why})`, i); return main.pop(); };
  const popN = (i, n, why) => { const r = []; for (let k = 0; k < n; k++) r.unshift(pop(i, why)); return r; };

  function beginBlock() {
    entryDepth = main.length; entryAlt = alt.length;
    main = main.map((_, i) => ({ k: 'in', i }));
    alt = alt.map((_, i) => ({ k: 'ain', i }));
  }
  function closeBlock(opIndexEnd) {
    const rawOps = ops.slice(rawStart, opIndexEnd);
    items.push({
      block: {
        entryDepth, entryAlt,
        exit: main.slice(), exitAlt: alt.slice(),
        rawOps,
        opRange: [rawStart, opIndexEnd], // provenance hook (d)
      },
    });
  }

  beginBlock();
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    const op = o.op;
    if (CTRL.has(op)) {
      closeBlock(i);
      if (op === OPC.IF || op === OPC.NOTIF) {
        pop(i, 'if-cond');
        ctrlDepth.push({ m: main.length, a: alt.length, thenM: null, thenA: null, hadElse: false, opIndex: i });
      } else if (op === OPC.ELSE) {
        if (!ctrlDepth.length) fail('ELSE without IF', i);
        const s = ctrlDepth[ctrlDepth.length - 1];
        s.thenM = main.length; s.thenA = alt.length; s.hadElse = true;
        main.length = s.m; alt.length = s.a; // ELSE arm re-starts from the IF entry layout
      } else if (op === OPC.ENDIF) {
        if (!ctrlDepth.length) fail('ENDIF without IF', i);
        const s = ctrlDepth.pop();
        // (a) branch-shape consistency
        if (s.hadElse) {
          if (main.length !== s.thenM || alt.length !== s.thenA)
            fail(`branch-shape mismatch: THEN leaves (m=${s.thenM},a=${s.thenA}) ELSE leaves (m=${main.length},a=${alt.length})`, i);
        } else {
          if (main.length !== s.m || alt.length !== s.a)
            fail(`branch-shape mismatch: IF-without-ELSE arm not depth-neutral (entry m=${s.m},a=${s.a} -> exit m=${main.length},a=${alt.length})`, i);
        }
      } else if (op === OPC.BEGIN) {
        loopStack.push({ m: main.length, a: alt.length, opIndex: i });
      } else if (op === OPC.UNTIL) {
        pop(i, 'until-cond');
        if (!loopStack.length) fail('UNTIL without BEGIN', i);
        const s = loopStack.pop();
        // (b) loop-invariance
        if (main.length !== s.m || alt.length !== s.a)
          fail(`loop-invariance mismatch: BEGIN layout (m=${s.m},a=${s.a}) != UNTIL layout (m=${main.length},a=${alt.length})`, i);
      } else if (op === OPC.VERIFY) {
        pop(i, 'verify');
      } else if (op === OPC.NUMEQUALVERIFY || op === OPC.EQUALVERIFY) {
        pop(i, 'nverify-a'); pop(i, 'nverify-b');
      }
      items.push({ ctrl: op, isVerify: VERIFY_OPS.has(op) }); // (c) tag verify boundaries
      rawStart = i + 1;
      beginBlock();
      continue;
    }
    // ---- straight-line op: update symbolic stacks ----
    // `enc` = the EXACT encoded bytes cashc emitted for this push, so a re-scheduled
    // block reproduces the constant byte-for-byte (never re-canonicalized).
    if (o.data !== undefined) { main.push({ k: 'const', data: o.data, enc: serializeOne(o) }); continue; }
    if (op === 0x00) { main.push({ k: 'const', data: new Uint8Array(), enc: Uint8Array.from([0x00]) }); continue; }
    if (op === 0x4f) { main.push({ k: 'const', data: Uint8Array.from([0x81]), enc: Uint8Array.from([0x4f]) }); continue; }
    if (op >= 0x51 && op <= 0x60) { main.push({ k: 'const', data: Uint8Array.from([op - 0x50]), enc: Uint8Array.from([op]) }); continue; }
    switch (op) {
      case OPC.DUP: { const t = main[main.length - 1]; if (!t) fail('DUP underflow', i); main.push(t); break; }
      case OPC.DROP: pop(i, 'drop'); break;
      case OPC['2DROP']: pop(i, '2drop'); pop(i, '2drop'); break;
      case OPC['2DUP']: { const b = main[main.length - 1], a = main[main.length - 2]; if (!a || !b) fail('2DUP underflow', i); main.push(a, b); break; }
      case OPC.OVER: { const v = main[main.length - 2]; if (!v) fail('OVER underflow', i); main.push(v); break; }
      case OPC['2OVER']: { const a = main[main.length - 4], b = main[main.length - 3]; if (a === undefined || b === undefined) fail('2OVER underflow', i); main.push(a, b); break; }
      case OPC.SWAP: { const n = main.length; if (n < 2) fail('SWAP underflow', i); [main[n - 1], main[n - 2]] = [main[n - 2], main[n - 1]]; break; }
      case OPC['2SWAP']: { const n = main.length; if (n < 4) fail('2SWAP underflow', i); const a = main[n - 4], b = main[n - 3], c = main[n - 2], dd = main[n - 1]; main[n - 4] = c; main[n - 3] = dd; main[n - 2] = a; main[n - 1] = b; break; }
      case OPC.ROT: { const n = main.length; if (n < 3) fail('ROT underflow', i); const a = main[n - 3]; main[n - 3] = main[n - 2]; main[n - 2] = main[n - 1]; main[n - 1] = a; break; }
      case OPC['2ROT']: { const n = main.length; if (n < 6) fail('2ROT underflow', i); const a = main[n - 6], b = main[n - 5]; for (let k = n - 6; k < n - 2; k++) main[k] = main[k + 2]; main[n - 2] = a; main[n - 1] = b; break; }
      case OPC.TUCK: { const n = main.length; if (n < 2) fail('TUCK underflow', i); const b = main[n - 1], a = main[n - 2]; main[n - 2] = b; main[n - 1] = a; main.push(b); break; }
      case OPC.NIP: { if (main.length < 2) fail('NIP underflow', i); main.splice(main.length - 2, 1); break; }
      case OPC.TOALT: alt.push(pop(i, 'toalt')); break;
      case OPC.FROMALT: { if (alt.length === 0) fail('FROMALT alt underflow', i); main.push(alt.pop()); break; }
      case OPC.PICK: { const n = constNum(pop(i, 'pick-n')); if (n === null) fail('PICK non-const depth', i); const v = main[main.length - 1 - n]; if (v === undefined) fail(`PICK depth ${n} underflow`, i); main.push(v); break; }
      case OPC.ROLL: { const n = constNum(pop(i, 'roll-n')); if (n === null) fail('ROLL non-const depth', i); const idx = main.length - 1 - n; if (idx < 0) fail(`ROLL depth ${n} underflow`, i); const v = main.splice(idx, 1)[0]; main.push(v); break; }
      case OPC.INVOKE: {
        const id = constNum(pop(i, 'invoke-id')); if (id === null) fail('INVOKE non-const id', i);
        const a = arity[id]; if (!a) fail(`unknown invoke id ${id}`, i);
        const ins = popN(i, a.in, 'invoke-arg');
        const node = freshNode({ k: 'invoke', invId: id, ins });
        for (let j = 0; j < a.out; j++) main.push({ k: 'out', node, j });
        break;
      }
      default: {
        if (VALOP.has(op)) {
          const [nin, nout] = VALOP.get(op);
          const ins = popN(i, nin, 'valop-arg');
          const node = freshNode({ k: 'prim', code: op, ins });
          for (let j = 0; j < nout; j++) main.push({ k: 'out', node, j });
          break;
        }
        fail(`unhandled opcode 0x${op.toString(16)}`, i);
      }
    }
  }
  if (ctrlDepth.length) fail('unbalanced IF (missing ENDIF)', ops.length);
  if (loopStack.length) fail('unbalanced BEGIN (missing UNTIL)', ops.length);
  closeBlock(ops.length);
  return items;
}

// Identity recompile: concatenate every block's rawOps and ctrl ops in order.
// serialize(this) === body proves the block partition + boundary set is a faithful,
// byte-exact cover of the input (no optimization applied).
export function flattenIdentity(items) {
  const ops = [];
  for (const it of items) {
    if (it.block) for (const o of it.block.rawOps) ops.push(o);
    else ops.push({ op: it.ctrl });
  }
  return ops;
}
