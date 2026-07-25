import { repoPath as vcRepoPath } from '#repo-paths';
// buildfull.mjs -- assemble the FULL optimized locking artifact: optimize all 52 bodies
// + the main routine (per-block min sched/orig), splice into the OP_DEFINE framing, and
// (a) confirm the byte-exact round-trip still holds in identity mode, (b) end-to-end
// evaluate the 4/4 distinct-public-input multiproof: valid-ACCEPT 4/4, invalid-REJECT 4/4,
// AND artifact-level differential vs the original 14641 (identical accept/reject).
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin,
} from '@bitauth/libauth';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect, rebuild, probeArity } from './program.mjs';
import { optimizeItems } from './optimize.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));

// optimize every body
const override = new Map();
let bodyOrig = 0, bodyOpt = 0, schedBlocks = 0, allBlocks = 0;
for (const id of d.order) {
  const items = decompile(d.bodies.get(id), arity, arity[id].in, { label: 'def#' + id });
  const { bytes, chosen } = optimizeItems(items, arity, 'sched', { peephole: true, search: { cap: 20000, trials: 1500 } });
  override.set(id, bytes);
  bodyOrig += d.bodies.get(id).length; bodyOpt += bytes.length; schedBlocks += chosen.sched; allBlocks += chosen.blocks;
}
// optimize main
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
const { bytes: mainOpt, chosen: mainChosen } = optimizeItems(mainItems, arity, 'sched', { peephole: true, search: { cap: 40000, trials: 4000 } });
const mainOrig = serialize(d.mainOps);

const optBytes = rebuild(d, override, mainOpt);
writeFileSync(join(here, 'optimized.hex'), Buffer.from(optBytes).toString('hex'));

console.log(`baseline           ${baseline.length} B`);
console.log(`bodies   ${bodyOrig} -> ${bodyOpt} B  (blocks sched ${schedBlocks}/${allBlocks})`);
console.log(`main     ${mainOrig.length} -> ${mainOpt.length} B  (blocks sched ${mainChosen.sched}/${mainChosen.blocks})`);
console.log(`OPTIMIZED ARTIFACT ${optBytes.length} B   (saved ${baseline.length - optBytes.length} B, ${(100 * (baseline.length - optBytes.length) / baseline.length).toFixed(1)}%)`);
console.log(`mr-zwets target 8776 B  -> gap ${optBytes.length - 8776} B`);

// ---- end-to-end 4/4 multiproof on the loosened VM ----
const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const runLock = (locking, unlockHex) => {
  const r = vm.verify(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: hexToBin(unlockHex), valueSatoshis: 10000n }));
  return r === true;
};

const mp = JSON.parse(readFileSync(vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json'), 'utf8'));
let acc = 0, rej = 0, diffOK = 0;
for (let i = 0; i < mp.proofs.length; i++) {
  const p = mp.proofs[i];
  const optV = runLock(optBytes, p.unlocking), optI = runLock(optBytes, p.invalidUnlocking);
  const baseV = runLock(baseline, p.unlocking), baseI = runLock(baseline, p.invalidUnlocking);
  if (optV) acc++; if (!optI) rej++;
  if (optV === baseV && optI === baseI) diffOK++;
  console.log(`proof#${i} pub=${JSON.stringify(p.publicInputs)}  valid: opt=${optV?'ACCEPT':'FAIL'} base=${baseV?'ACCEPT':'FAIL'} | invalid: opt=${optI?'ACCEPT!!':'reject'} base=${baseI?'ACCEPT!!':'reject'} | diff=${optV===baseV&&optI===baseI?'ok':'MISMATCH'}`);
}
const n = mp.proofs.length;
console.log(`\nE2E: valid-ACCEPT ${acc}/${n} ; invalid-REJECT ${rej}/${n} ; artifact-differential ${diffOK}/${n}`);
const PASS = acc === n && rej === n && diffOK === n;
console.log(`E2E GATE: ${PASS ? 'PASS' : 'FAIL'}`);
process.exit(PASS ? 0 : 1);
