// libauth side: for each case, build locking bytecode that (a) pushes the main stack
// (bottom->top), (b) pre-populates the alt stack via push+OP_TOALTSTACK prefix, (c) for
// PICK/ROLL pushes n, then (d) runs EXACTLY the target opcode. Executes on the REAL
// BCH2026 VM via vm.debug and reads the post-op main+alt stack.
//
// Reading the result: vm.debug's LAST state is a two-phase FINALIZATION state that only
// adds a "clean stack (must be exactly 1)" error (it does NOT modify the stack). So:
//   - error is the cleanStack message  => the target op SUCCEEDED; read that state's stacks
//   - error is null                    => SUCCEEDED (op happened to leave 1 item)
//   - any OTHER error (empty stack / empty alt / invalid stack index) => real underflow => FAIL
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

const OPCODE = { DUP:0x76, DROP:0x75, OVER:0x78, SWAP:0x7c, ROT:0x7b, NIP:0x77, TUCK:0x7d,
  PICK:0x79, ROLL:0x7a, TOALT:0x6b, FROMALT:0x6c, '2DROP':0x6d, '2DUP':0x6e, '3DUP':0x6f,
  '2OVER':0x70, '2ROT':0x71, '2SWAP':0x72 };
const CLEANSTACK = 'completed evaluation with an unexpected number of items';

// push a sentinel value v (17..250, !=129): OP_PUSHBYTES_1 <v>  (minimal for v>16, v<129)
function pushSentinel(v){ return [0x01, v]; }
// push a small non-negative int n as a MINIMAL script number (for OP_PICK/OP_ROLL depth)
function pushNum(n){
  if (n === 0) return [0x00];                 // OP_0 pushes empty => number 0
  if (n >= 1 && n <= 16) return [0x50 + n];    // OP_1 .. OP_16
  if (n <= 127) return [0x01, n];              // single-byte minimal number
  throw new Error('n too large: '+n);
}

function buildBytecode(c){
  const b = [];
  // (a) main stack bottom->top: main is TOP-FIRST, so push reversed(main)
  for (let i = c.main.length - 1; i >= 0; i--) b.push(...pushSentinel(c.main[i]));
  // (b) alt prefix: alt is TOP-FIRST; push its bottom first. For each (bottom->top) push+TOALT.
  for (let i = c.alt.length - 1; i >= 0; i--){ b.push(...pushSentinel(c.alt[i])); b.push(0x6b); }
  // (c) PICK/ROLL depth n
  if (c.op === 'PICK' || c.op === 'ROLL') b.push(...pushNum(c.n));
  // (d) the target opcode
  b.push(OPCODE[c.op]);
  return Uint8Array.from(b);
}

function evalCase(c){
  const prog = createTestAuthenticationProgramBch({ lockingBytecode: buildBytecode(c),
    unlockingBytecode: Uint8Array.from([]), valueSatoshis: 10000n });
  const trace = vm.debug(prog);
  const last = trace[trace.length - 1];
  const err = last.error || null;
  if (err && !err.includes(CLEANSTACK)) return { id: c.id, fail: true };
  // success: read top-first stacks
  const main = (last.stack || []).map(x => x[0]).reverse();
  const alt  = (last.alternateStack || []).map(x => x[0]).reverse();
  return { id: c.id, fail: false, main, alt };
}

const inFile  = process.argv[2] || 'cases.json';
const outFile = process.argv[3] || 'libauth_results.json';
const { cases } = JSON.parse(readFileSync(join(here,inFile),'utf8'));
const results = cases.map(evalCase);
writeFileSync(join(here,outFile), JSON.stringify(results, null, 0));
console.log('libauth: evaluated', results.length, 'cases;', results.filter(r=>r.fail).length, 'FAIL');
