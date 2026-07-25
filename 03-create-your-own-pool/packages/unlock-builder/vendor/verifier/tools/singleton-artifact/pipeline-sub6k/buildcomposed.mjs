import { repoPath as vcRepoPath } from '#repo-paths';
// buildcomposed.mjs -- COMPOSED full build. Merges all three sound angles via optimize.mjs's
// per-block MIN candidate pool: greedy CONFIGS + node-order search (exhaustive<=cap / sampled)
// + def30 fixed overrides (nodeorders.json). Budget env: CAP_MAIN/TRIALS_MAIN, CAP_BODY/TRIALS_BODY.
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
const NODEORDERS = JSON.parse(readFileSync(join(here, 'nodeorders.json'), 'utf8'));

const CAP_MAIN = +(process.env.CAP_MAIN || 50000), TRIALS_MAIN = +(process.env.TRIALS_MAIN || 16000);
const CAP_BODY = +(process.env.CAP_BODY || 30000), TRIALS_BODY = +(process.env.TRIALS_BODY || 8000);
console.log(`[composed] CAP_MAIN=${CAP_MAIN} TRIALS_MAIN=${TRIALS_MAIN} CAP_BODY=${CAP_BODY} TRIALS_BODY=${TRIALS_BODY}`);

const override = new Map();
let bodyOrig = 0, bodyOpt = 0, schedBlocks = 0, allBlocks = 0;
for (const id of d.order) {
  const items = decompile(d.bodies.get(id), arity, arity[id].in, { label: 'def#' + id });
  const { bytes, chosen } = optimizeItems(items, arity, 'sched', {
    peephole: true, label: 'def#' + id, nodeOrders: NODEORDERS,
    search: { cap: CAP_BODY, trials: TRIALS_BODY },
  });
  override.set(id, bytes);
  bodyOrig += d.bodies.get(id).length; bodyOpt += bytes.length; schedBlocks += chosen.sched; allBlocks += chosen.blocks;
}
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
const { bytes: mainOpt, chosen: mainChosen } = optimizeItems(mainItems, arity, 'sched', {
  peephole: true, label: 'main', nodeOrders: NODEORDERS,
  search: { cap: CAP_MAIN, trials: TRIALS_MAIN },
});
const mainOrig = serialize(d.mainOps);

const optBytes = rebuild(d, override, mainOpt);
writeFileSync(join(here, 'optimized.hex'), Buffer.from(optBytes).toString('hex'));

console.log(`baseline           ${baseline.length} B`);
console.log(`bodies   ${bodyOrig} -> ${bodyOpt} B  (blocks sched ${schedBlocks}/${allBlocks})`);
console.log(`main     ${mainOrig.length} -> ${mainOpt.length} B  (blocks sched ${mainChosen.sched}/${mainChosen.blocks})`);
console.log(`OPTIMIZED ARTIFACT ${optBytes.length} B (locking); score = ${optBytes.length + 272 + 87}`);

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
  console.log(`proof#${i} valid: opt=${optV?'ACCEPT':'FAIL'} base=${baseV?'ACCEPT':'FAIL'} | invalid: opt=${optI?'ACCEPT!!':'reject'} base=${baseI?'ACCEPT!!':'reject'} | diff=${optV===baseV&&optI===baseI?'ok':'MISMATCH'}`);
}
const n = mp.proofs.length;
console.log(`\nE2E: valid-ACCEPT ${acc}/${n} ; invalid-REJECT ${rej}/${n} ; artifact-differential ${diffOK}/${n}`);
const PASS = acc === n && rej === n && diffOK === n;
console.log(`E2E GATE: ${PASS ? 'PASS' : 'FAIL'}`);
process.exit(PASS ? 0 : 1);
