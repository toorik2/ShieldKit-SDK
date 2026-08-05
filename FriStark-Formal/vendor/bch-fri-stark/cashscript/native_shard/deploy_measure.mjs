// HP4 K3 deployable per-input harness: assemble a REDEEM (verifier logic) file and an UNLOCK
// (push-only witness data) file, run them as locking/unlocking bytecode on the real
// createVirtualMachineBch2026, and report redeem bytes + unlock bytes + total. DEPLOY MODEL
// (grounded 2026-07-02 vs the official libauth bch-2026-consensus.js + bch-2023-instruction-set.js
// verify(), the VM instantiated below): a standard deploy is P2SH32 -- a bare >201B verifier
// locking output is NON-standard (maximumStandardLockingBytecodeLength=201, BCH_2026 override),
// so the redeem is REVEALED in the spending scriptSig (verify() takes it as unlockingResult.stack
// .pop()). Hence the real per-input scriptSig = unlock + PUSH(redeem) = `totalScriptSig` here,
// which must be <=10000B standard (maximumStandardUnlockingBytecodeLength=10000 in the BCH_2026
// override -- the old ConsensusCommon 1650 is overridden/removed), and the SUM over all inputs
// must be <100000B (maximumStandardTransactionSize) = the binding whole-tx budget. op-cost +
// hash-digest vs CHIP-2021-05 maxima (density = (41 + scriptSig_len) controls both:
// maxOps=(41+L)*800, maxHashIters=(41+L)/2 -- a fatter scriptSig buys MORE budget). NOTE:
// vm.debug here measures ONE input's script execution (op/hash/accept); the standard limits above
// are enforced by verify() on relay, not by this harness. Putting the witness in the unlock is
// what buys the hash-density budget. Real VM, real bytes -- no mock (TEST_RULES).
import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin, binToHex } from '@bitauth/libauth';

const vm = createVirtualMachineBch2026();
const redeem = cashAssemblyToBin(readFileSync(process.argv[2], 'utf8').replace(/\n/g, ' ').trim());
const unlock = cashAssemblyToBin(readFileSync(process.argv[3], 'utf8').replace(/\n/g, ' ').trim());
if (typeof redeem === 'string') { console.log(JSON.stringify({ asmError: 'redeem: ' + redeem })); process.exit(0); }
if (typeof unlock === 'string') { console.log(JSON.stringify({ asmError: 'unlock: ' + unlock })); process.exit(0); }

const tx = {
  version: 2,
  inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32),
             sequenceNumber: 0, unlockingBytecode: unlock }],
  outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n }],
  locktime: 0,
};
const trace = vm.debug({ inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: redeem, valueSatoshis: 1000n }], transaction: tx });
const last = trace[trace.length - 1];
const top = last.stack && last.stack.length ? last.stack[last.stack.length - 1] : undefined;
const ok = !last.error && top && top.length > 0 && !(top.length === 1 && top[0] === 0);
console.log(JSON.stringify({
  redeemBytes: redeem.length,
  unlockBytes: unlock.length,
  totalScriptSig: redeem.length + unlock.length,
  error: last.error ?? null,
  metrics: last.metrics ?? {},
  accept: ok,
  stack: (last.stack ?? []).map((b) => binToHex(b)),
}));
