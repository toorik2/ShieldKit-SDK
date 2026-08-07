// Program-level: dissect the locking bytecode into the OP_DEFINE subroutine table +
// main routine, probe each subroutine's (in->out) arity on the loosened BCH-2026 VM,
// decompile every body + main into the block-DAG IR, and recompile byte-exactly.
//
// The byte-EXACT round-trip gate lives here: recompileProgram(decompileProgram(x)) === x.
// We rebuild each body as serialize(flattenIdentity(decompile(body))) and splice it back
// into the ORIGINAL op stream (id-push + OP_DEFINE records untouched), so any byte
// mismatch can only come from an unfaithful block partition -- exactly what we want to
// catch.
import {
  createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
  bigIntToVmNumber, vmNumberToBigInt,
} from '@bitauth/libauth';
import { parse, serialize } from './asm.mjs';
import { decompile, flattenIdentity } from './decompile.mjs';

const DEFINE = 0x89, INVOKE = 0x8a;
const HUGE = Number.MAX_SAFE_INTEGER;
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
export const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));

const idVal = (o) => {
  if (!o) return null;
  if (o.op === 0) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  if (o.data && o.data.length <= 2) { let v = 0; for (let i = o.data.length - 1; i >= 0; i--) v = (v << 8) | o.data[i]; return v; }
  return null;
};

// Split locking bytecode into the OP_DEFINE table + main. Keeps the raw op records for
// each body-push / id-push / DEFINE so we can splice byte-exactly.
export function dissect(bytes) {
  const ops = parse(bytes);
  const bodies = new Map(); const order = []; const defRecs = [];
  let i = 0;
  while (i + 2 < ops.length && ops[i].data && ops[i + 2] && ops[i + 2].op === DEFINE) {
    const id = idVal(ops[i + 1]);
    bodies.set(id, ops[i].data); order.push(id);
    defRecs.push({ id, bodyRec: ops[i], idRec: ops[i + 1], defRec: ops[i + 2] });
    i += 3;
  }
  return { bodies, order, defRecs, mainOps: ops.slice(i), headerLen: i };
}

export function rebuild(d, override, mainOverride) {
  const out = [];
  for (const r of d.defRecs) {
    const body = override && override.has(r.id) ? override.get(r.id) : d.bodies.get(r.id);
    out.push({ op: 0, data: body });        // body push (minimal header via serialize)
    out.push(r.idRec);                        // original id-push record, verbatim
    out.push(r.defRec);                       // OP_DEFINE, verbatim
  }
  const main = mainOverride ? parse(mainOverride) : d.mainOps;
  for (const o of main) out.push(o);
  return serialize(out);
}

// Run ONE subroutine in isolation on integer inputs -> {stack, error}.
export function runSubroutine(d, targetId, inputs, override) {
  const out = [];
  for (const r of d.defRecs) {
    const body = override && override.has(r.id) ? override.get(r.id) : d.bodies.get(r.id);
    out.push({ op: 0, data: body }); out.push(r.idRec); out.push(r.defRec);
  }
  for (const n of inputs) out.push({ op: 0, data: bigIntToVmNumber(BigInt(n)) });
  if (targetId >= 1 && targetId <= 16) out.push({ op: 0x50 + targetId });
  else out.push({ op: 0, data: bigIntToVmNumber(BigInt(targetId)) });
  out.push({ op: INVOKE });
  const state = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: serialize(out), unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
  const benign = !state.error || /Non-P2SH|clean stack|exactly one|single/i.test(String(state.error));
  return { stack: state.stack.map((b) => vmNumberToBigInt(b, { maximumVmNumberByteLength: HUGE })), error: benign ? undefined : state.error };
}

const rnd = (s) => { let x = BigInt(s + 7); for (let i = 0; i < 6; i++) x = (x * 6364136223846793005n + 1442695040888963407n) % P; return x; };

// Determine (in->out) arity of every subroutine by probing input counts.
export function probeArity(d) {
  const table = {};
  for (const id of d.order) {
    let maxErr = -1, netBig = 0;
    for (let k = 0; k <= 30; k++) {
      const r = runSubroutine(d, id, Array.from({ length: k }, (_, i) => rnd(i * 31 + id)));
      if (r.error) maxErr = k; else netBig = r.stack.length - k;
    }
    table[id] = { in: maxErr + 1, out: maxErr + 1 + netBig };
  }
  return table;
}

// Decompile every body + main into the block-DAG IR (with the hardening asserts live).
export function decompileProgram(d, arity, mainInArity = 10) {
  const bodies = new Map();
  for (const id of d.order) bodies.set(id, decompile(d.bodies.get(id), arity, arity[id].in, { label: 'def#' + id }));
  const mainItems = decompile(serialize(d.mainOps), arity, mainInArity, { label: 'main' });
  return { bodies, mainItems };
}

// Recompile the IR back to bytes (identity: no optimization) and splice byte-exactly.
export function recompileProgram(d, ir, arity) {
  const override = new Map();
  const perBody = [];
  for (const id of d.order) {
    const rec = serialize(flattenIdentity(ir.bodies.get(id)));
    const orig = d.bodies.get(id);
    const exact = Buffer.from(rec).equals(Buffer.from(orig));
    perBody.push({ id, exact, origLen: orig.length, recLen: rec.length });
    override.set(id, rec);
  }
  const mainRec = serialize(flattenIdentity(ir.mainItems));
  const mainOrig = serialize(d.mainOps);
  const mainExact = Buffer.from(mainRec).equals(Buffer.from(mainOrig));
  const bytes = rebuild(d, override, mainRec);
  return { bytes, perBody, mainExact, mainOrigLen: mainOrig.length, mainRecLen: mainRec.length };
}
