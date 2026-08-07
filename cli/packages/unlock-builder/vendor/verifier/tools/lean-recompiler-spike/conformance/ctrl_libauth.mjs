// libauth CONTROL side: emit each structured case to FLAT bytecode:
//   - set up main stack (bottom->top pushes) and alt stack (push + OP_TOALTSTACK)
//   - EMIT the Prog tree: block ops verbatim, ifte -> IF..[ELSE..]ENDIF, loop -> BEGIN..UNTIL,
//     verify -> OP_VERIFY.  Control opcodes are the single bytes confirmed by probe_control.mjs.
// Runs the FLAT bytecode on the REAL BCH2026 VM (loosened consensus) via vm.debug and reads the
// post-execution main+alt. cleanStack finalization substring => the program SUCCEEDED.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url'; import { dirname, join } from 'node:path';
import { createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256 } from '@bitauth/libauth';
const here = dirname(fileURLToPath(import.meta.url));

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE };
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
// BOUNDED VM for {nonterm:true} cases: real DEFAULT-ish consensus whose op-cost density limit
// ABORTS an otherwise-infinite loop after ~O(100) iterations (probe_control.mjs confirmed), so the
// runner never hangs. Lean returns none (fuel bound) for the same cases => both FAIL => match.
const ConsensusBch2026 = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: 1000, maximumStandardLockingBytecodeLength: 201,
  maximumStandardUnlockingBytecodeLength: 10000, maximumTokenCommitmentLength: 128 };
const vmBounded = createVirtualMachine(createInstructionSetBch2026(false, { consensus: ConsensusBch2026, ripemd160, secp256k1, sha1, sha256 }));

const CLEANSTACK = 'completed evaluation with an unexpected number of items';
const CTRL = { IF:0x63, NOTIF:0x64, BEGIN:0x65, UNTIL:0x66, ELSE:0x67, ENDIF:0x68, VERIFY:0x69 };
const OPCODE = { DUP:0x76, DROP:0x75, OVER:0x78, SWAP:0x7c, ROT:0x7b, NIP:0x77, TUCK:0x7d,
  PICK:0x79, ROLL:0x7a, TOALT:0x6b, FROMALT:0x6c, '2DROP':0x6d, '2DUP':0x6e, '3DUP':0x6f,
  '2OVER':0x70, '2ROT':0x71, '2SWAP':0x72 };

function pushValue(v){
  if (v === 0) return [0x00];          // OP_0 -> empty item (FALSE)
  if (v === 1) return [0x51];          // OP_1 -> [0x01] (TRUE)
  if (v >= 17 && v <= 250 && v !== 128) return [0x01, v];  // single nonzero byte
  throw new Error('bad value '+v);
}
function pushNum(n){
  if (n === 0) return [0x00];
  if (n >= 1 && n <= 16) return [0x50 + n];
  if (n <= 127) return [0x01, n];
  throw new Error('n too large: '+n);
}
function emitOp(o){
  if (o.op === 'PUSH') return pushValue(o.v);
  if (o.op === 'PICK' || o.op === 'ROLL') return [...pushNum(o.n), OPCODE[o.op]];
  const c = OPCODE[o.op]; if (c===undefined) throw new Error('bad op '+o.op);
  return [c];
}
function emitItem(it){
  switch(it.t){
    case 'block':  return it.ops.flatMap(emitOp);
    case 'verify': return [CTRL.VERIFY];
    case 'loop':   return [CTRL.BEGIN, ...emitProg(it.body), CTRL.UNTIL];
    case 'ifte': {
      const opc = it.neg ? CTRL.NOTIF : CTRL.IF;   // OP_NOTIF (0x64) vs OP_IF (0x63)
      const then = emitProg(it.then);
      if (it.noElse && (!it.else || it.else.length===0))
        return [opc, ...then, CTRL.ENDIF];
      return [opc, ...then, CTRL.ELSE, ...emitProg(it.else||[]), CTRL.ENDIF];
    }
    default: throw new Error('bad item '+it.t);
  }
}
function emitProg(prog){ return prog.flatMap(emitItem); }

function buildBytecode(c){
  const b = [];
  for (let i = c.main.length - 1; i >= 0; i--) b.push(...pushValue(c.main[i]));      // bottom->top
  for (let i = c.alt.length - 1;  i >= 0; i--){ b.push(...pushValue(c.alt[i])); b.push(0x6b); }
  b.push(...emitProg(c.prog));
  return Uint8Array.from(b);
}

function itemToNat(x){ return x.length===0 ? 0 : x[0]; }
function evalCase(c){
  let bc; try { bc = buildBytecode(c); } catch(e){ return { id:c.id, fail:true, emitErr:String(e) }; }
  const prog = createTestAuthenticationProgramBch({ lockingBytecode: bc,
    unlockingBytecode: Uint8Array.from([]), valueSatoshis: 10000n });
  const trace = (c.nonterm ? vmBounded : vm).debug(prog);
  const last = trace[trace.length - 1];
  const err = last.error || null;
  if (err && !err.includes(CLEANSTACK)) return { id: c.id, fail: true, err };
  const main = (last.stack || []).map(itemToNat).reverse();
  const alt  = (last.alternateStack || []).map(itemToNat).reverse();
  return { id: c.id, fail: false, main, alt };
}

const inFile  = process.argv[2] || 'ctrl_cases.json';
const outFile = process.argv[3] || 'ctrl_libauth_results.json';
const { cases } = JSON.parse(readFileSync(join(here,inFile),'utf8'));
const results = cases.map(evalCase);
writeFileSync(join(here,outFile), JSON.stringify(results, null, 0));
console.log('libauth: evaluated', results.length, 'cases;', results.filter(r=>r.fail).length, 'FAIL/abort');
