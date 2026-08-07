// P2SH32-ACCURATE per-input harness (grounded vs official libauth bch-2026 + CHIP-2021-05 VM-Limits):
// unlike deploy_measure.mjs (which passes the redeem as a BARE locking bytecode -> density control length
// = witness only, an UNDERESTIMATE of the real op-cost budget), this models the REAL P2SH32 spend:
//   sourceOutput.lockingBytecode = OP_HASH256 <hash256(redeem)> OP_EQUAL   (encodeLockingBytecodeP2sh32)
//   input.unlockingBytecode      = <unlock witness pushes> <PUSH(redeem)>  (the redeem is REVEALED in scriptSig)
// so libauth's Density Control Length = 41 + unlockingBytecode length = 41 + (witness + PUSH(redeem)) --
// exactly the CHIP-2021-05 formula (maxOps=(41+L)*800, maxHashIters=(41+L)/2). This is the op-cost/hash
// budget the network actually applies at relay. Reports the REAL operationCost/hashDigestIterations vs the
// P2SH32-correct maxima + accept. Real VM, real bytes, no mock (TEST_RULES).
import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin, hash256, encodeDataPush,
         encodeLockingBytecodeP2sh32, flattenBinArray } from '@bitauth/libauth';

const vm = createVirtualMachineBch2026();

function measure(redeem, unlock) {
  const locking = encodeLockingBytecodeP2sh32(hash256(redeem));       // OP_HASH256 <32B> OP_EQUAL
  const scriptSig = flattenBinArray([unlock, encodeDataPush(redeem)]); // witness + PUSH(redeem)
  const tx = { version: 2,
    inputs: [{ outpointIndex: 0, outpointTransactionHash: new Uint8Array(32),
               sequenceNumber: 0, unlockingBytecode: scriptSig }],
    outputs: [{ lockingBytecode: Uint8Array.of(0x6a), valueSatoshis: 0n }], locktime: 0 };
  const trace = vm.debug({ inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n }], transaction: tx });
  const last = trace[trace.length - 1];
  const top = last.stack && last.stack.length ? last.stack[last.stack.length - 1] : undefined;
  const ok = !last.error && top && top.length > 0 && !(top.length === 1 && top[0] === 0);
  const L = scriptSig.length;
  return { redeemBytes: redeem.length, unlockBytes: unlock.length, scriptSigBytes: L,
           densityControlLength: 41 + L, maxOpsFormula: (41 + L) * 800, maxHashItersFormula: Math.floor((41 + L) / 2),
           error: last.error ?? null, metrics: last.metrics ?? {}, accept: ok };
}

if (process.argv.length < 4) {                                        // self-test: trivial P2SH32 (OP_1 redeem)
  const r = measure(Uint8Array.of(0x51), new Uint8Array(0));         // redeem=OP_1, empty witness
  console.log(JSON.stringify({ selftest: true, accept: r.accept, error: r.error,
                               scriptSigBytes: r.scriptSigBytes, redeemBytes: r.redeemBytes }));
  process.exit(0);
}
const asm = (p) => cashAssemblyToBin(readFileSync(p, 'utf8').replace(/\n/g, ' ').trim());
const redeem = asm(process.argv[2]), unlock = asm(process.argv[3]);
if (typeof redeem === 'string') { console.log(JSON.stringify({ asmError: 'redeem: ' + redeem })); process.exit(0); }
if (typeof unlock === 'string') { console.log(JSON.stringify({ asmError: 'unlock: ' + unlock })); process.exit(0); }
console.log(JSON.stringify(measure(redeem, unlock)));
