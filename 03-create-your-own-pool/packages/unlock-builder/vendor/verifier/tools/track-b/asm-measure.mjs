// Track B foundation: emit RAW Bitcoin Cash Script (opcode bytes) by hand and
// measure it on the SAME loosened libauth BCH-2026 VM the cashc graders use —
// bypassing cashc entirely. This is the toolchain for the direct-bytecode Miller
// loop generator (the answer to F5/F6: the loop-carried-state cost the compiler
// can't fix is a hand-managed-stack-frame problem).
import {
  hexToBin, binToHex, bigIntToVmNumber, OpcodesBch,
  createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025,
  ripemd160, secp256k1, sha1, sha256, disassembleBytecodeBch,
} from '../../node_modules/@bitauth/libauth/build/index.js';

export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const O = OpcodesBch; // opcode-name -> byte

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE,
  maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, {
  consensus: loosened, ripemd160, secp256k1, sha1, sha256,
}));

// minimal VM-number push (matches the graders' encoding; libauth rejects non-minimal)
export const push = (n) => {
  const d = bigIntToVmNumber(BigInt(n));
  if (d.length === 0) return [0x00];
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return [0x50 + d[0]];
  if (d.length === 1 && d[0] === 0x81) return [0x4f];
  if (d.length <= 75) return [d.length, ...d];
  if (d.length <= 255) return [0x4c, d.length, ...d];
  return [0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d];
};
// concat a mixed list of (number=opcode byte | number[]=bytes) into a Uint8Array
export const asm = (...parts) => Uint8Array.from(parts.flat(Infinity));

export const measure = (locking, unlocking = Uint8Array.from([])) => {
  const program = createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: unlocking, valueSatoshis: 1000n });
  const state = looseVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  const m = state.metrics;
  return {
    accepted, error: state.error,
    opCost: m.operationCost, arith: m.arithmeticCost ?? 0, push: m.stackPushedBytes ?? 0,
    instr: m.evaluatedInstructionCount ?? 0, bytes: locking.length + unlocking.length,
    stack: state.stack.map((s) => binToHex(s)),
  };
};
export const dis = (b) => disassembleBytecodeBch(b);
// decode a VM-number hex (little-endian, sign-magnitude) to bigint
export const vmHexToBig = (hex) => {
  if (!hex) return 0n;
  const b = hexToBin(hex); if (b.length === 0) return 0n;
  let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i] & (i === b.length - 1 ? 0x7f : 0xff));
  return (b[b.length - 1] & 0x80) ? -n : n;
};

// ---- self-test: validate the toolchain on a known modular multiply ----
if (import.meta.url === `file://${process.argv[1]}`) {
  const x = 1234567890123456789n, y = 9876543210987654321n;
  const expected = (x * y) % P;
  // locking: <x> <y> OP_MUL <P> OP_MOD <expected> OP_EQUAL   (leaves 1 iff correct)
  const good = asm(push(x), push(y), O.OP_MUL, push(P), O.OP_MOD, push(expected), O.OP_EQUAL);
  const bad  = asm(push(x), push(y), O.OP_MUL, push(P), O.OP_MOD, push(expected + 1n), O.OP_EQUAL);
  const rGood = measure(good);
  const rBad = measure(bad);
  console.log('disasm:', dis(good));
  console.log('GOOD (correct modmul):', JSON.stringify(rGood));
  console.log('BAD  (wrong expected) accepted=', rBad.accepted, '(must be false)');
  console.log('toolchain OK =', rGood.accepted === true && rBad.accepted === false);
}
