import { compileFile, utils } from 'cashc';
import { bigIntToVmNumber, createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256 } from '@bitauth/libauth';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE };
const is = createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 });
// instrument: wrap operations
const stat = { rollCount:0, rollDepthSum:0, rollItemBytes:0, pickCount:0, pickBytes:0,
  toalt:0, fromalt:0, byOp:{} };
const OPN = { 0x79:'PICK', 0x7a:'ROLL', 0x6b:'TOALT', 0x6c:'FROMALT', 0x76:'DUP',0x78:'OVER',0x7c:'SWAP',0x7b:'ROT',0x77:'NIP',0x75:'DROP' };
const origOps = is.operations;
const wrapped = {};
for (const [code, fn] of Object.entries(origOps)) {
  const c = Number(code);
  wrapped[c] = (state) => {
    if (c === 0x7a) { // ROLL: top of stack is depth
      const depth = Number(state.stack[state.stack.length-1] ? bigIntFromVm(state.stack[state.stack.length-1]) : 0n);
      const item = state.stack[state.stack.length-2-depth];
      stat.rollCount++; stat.rollDepthSum += depth; if(item) stat.rollItemBytes += item.length;
    } else if (c === 0x79) { // PICK
      const depth = Number(bigIntFromVm(state.stack[state.stack.length-1]));
      const item = state.stack[state.stack.length-2-depth];
      stat.pickCount++; if(item) stat.pickBytes += item.length;
    } else if (c === 0x6b) stat.toalt++;
    else if (c === 0x6c) stat.fromalt++;
    if (OPN[c]) stat.byOp[OPN[c]] = (stat.byOp[OPN[c]]||0)+1;
    return fn(state);
  };
}
function bigIntFromVm(u8){ if(!u8||u8.length===0) return 0n; let r=0n; for(let i=u8.length-1;i>=0;i--){r=(r<<8n)|BigInt(u8[i]&0xff);} const neg=(u8[u8.length-1]&0x80)!==0; if(neg){ r &= ~(0x80n<<BigInt(8*(u8.length-1))); return -r;} return r; }
is.operations = wrapped;
const vm = createVirtualMachine(is);
const asm = compileFile('generated/fp12bench.cash', { rescheduleStacks: true }).bytecode;
const bc = utils.asmToBytecode(asm);
const a = Array.from({length:12},(_,i)=> P - BigInt(1+i*7));
const push = (n)=>{const d=bigIntToVmNumber(n); return Uint8Array.from([d.length,...d]);};
const unlock = Uint8Array.from([...a].reverse().flatMap(x=> [...push(x)]));
const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: bc, unlockingBytecode: unlock, valueSatoshis: 1000n }));
const m = st.metrics;
console.log('opCost', m.operationCost, 'instr', m.evaluatedInstructionCount, 'push', m.stackPushedBytes, 'arith', m.arithmeticCost);
console.log('ROLL count', stat.rollCount, 'depthSum', stat.rollDepthSum, '(op-cost from depth term =', stat.rollDepthSum,') itemBytes', stat.rollItemBytes);
console.log('PICK count', stat.pickCount, 'itemBytes', stat.pickBytes);
console.log('TOALT', stat.toalt, 'FROMALT', stat.fromalt);
console.log('byOp', JSON.stringify(stat.byOp));
console.log('--- ROLL depth term as % of opCost:', (100*stat.rollDepthSum/m.operationCost).toFixed(3)+'%');
console.log('--- base(instr*100)=', m.evaluatedInstructionCount*100, ' push=', m.stackPushedBytes);
