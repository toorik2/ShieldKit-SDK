// HP11 whole-tx P2SH32 harness: an N-input P2SH32 tx on the real BCH-2026 VM, reporting per-input accept
// (fail-closed) AND the exact serialized transaction size (the <100000B standard-tx constraint). Combines
// p2sh_measure.mjs's P2SH32 model (sourceOutput locking = OP_HASH256 <hash256(redeem)> OP_EQUAL; input
// scriptSig = witness ++ PUSH(redeem)) with multi_input.mjs's N-input evaluation, and adds the standard
// BCH transaction byte size (version + varint counts + per-input [36 outpoint + scriptSig + 4 sequence] +
// per-output [8 value + lockingScript] + 4 locktime) so the whole-tx <100KB budget is a MEASURED number,
// not an estimate. Args: a JSON spec {inputs:[{redeem,unlock}], outputs?:[hexLockingScript], evaluate?:[i]}.
// Real VM, real bytes, no mock (TEST_RULES).
import { readFileSync } from 'fs';
import { createVirtualMachineBch2026, cashAssemblyToBin, hash256, encodeDataPush,
         encodeLockingBytecodeP2sh32, flattenBinArray, hexToBin } from '@bitauth/libauth';

const vm = createVirtualMachineBch2026();
const asm = (s) => cashAssemblyToBin(String(s).replace(/\n/g, ' ').trim());
const spec = JSON.parse(readFileSync(process.argv[2], 'utf8'));

// varint (CompactSize) byte length, per the Bitcoin/BCH tx serialization
const varintLen = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9);

// compile every input to its P2SH32 (locking, scriptSig) pair
const compiled = spec.inputs.map((inp, i) => {
  const r = asm(inp.redeem), u = asm(inp.unlock ?? '');
  for (const [n, b] of [[`redeem${i}`, r], [`unlock${i}`, u]])
    if (typeof b === 'string') { console.log(JSON.stringify({ asmError: n + ': ' + b })); process.exit(0); }
  // default P2SH32 locking; a test may override with a raw locking (e.g. a bare OP_DROP OP_1 output) to prove the
  // HP8 terminal bind rejects a filler whose scriptSig merely CONTAINS the committed redeem bytes (audit 2026-07-20).
  const locking = inp.lockingHex !== undefined ? hexToBin(inp.lockingHex) : encodeLockingBytecodeP2sh32(hash256(r));
  const scriptSig = flattenBinArray([u, encodeDataPush(r)]);         // witness ++ PUSH(redeem) = the real unlocking bytecode
  return { redeem: r, unlock: u, locking, scriptSig };
});

// outputs: default a single OP_RETURN (0x6a) placeholder; a real deploy may pass hex locking scripts
const outputs = (spec.outputs ?? ['6a']).map((h) => ({ lockingBytecode: hexToBin(h), valueSatoshis: 0n }));

const tx = {
  version: 2,
  inputs: compiled.map((c, i) => ({ outpointIndex: i, outpointTransactionHash: new Uint8Array(32),
                                    sequenceNumber: 0, unlockingBytecode: c.scriptSig })),
  outputs,
  locktime: 0,
};
const sourceOutputs = compiled.map((c) => ({ lockingBytecode: c.locking, valueSatoshis: 1000n }));

// exact standard BCH transaction size (bytes)
function txByteSize() {
  let b = 4 + varintLen(compiled.length);                            // version + input count
  for (const c of compiled) b += 36 + varintLen(c.scriptSig.length) + c.scriptSig.length + 4;  // outpoint + scriptSig + sequence
  b += varintLen(outputs.length);
  for (const o of outputs) b += 8 + varintLen(o.lockingBytecode.length) + o.lockingBytecode.length;  // value + lock
  return b + 4;                                                      // locktime
}

function evalInput(idx) {
  const tr = vm.debug({ inputIndex: idx, sourceOutputs, transaction: tx });
  const l = tr[tr.length - 1];
  const t = l.stack && l.stack.length ? l.stack[l.stack.length - 1] : undefined;
  return { idx, ok: !l.error && t && t.length > 0 && !(t.length === 1 && t[0] === 0),
           error: l.error ?? null, redeemBytes: compiled[idx].redeem.length,
           scriptSigBytes: compiled[idx].scriptSig.length, metrics: l.metrics ?? {} };
}

const indices = spec.evaluate ?? compiled.map((_, i) => i);
const txBytes = txByteSize();
console.log(JSON.stringify({
  results: indices.map(evalInput),
  nInputs: compiled.length,
  txBytes,
  underStandardLimit: txBytes < 100000,
}));
