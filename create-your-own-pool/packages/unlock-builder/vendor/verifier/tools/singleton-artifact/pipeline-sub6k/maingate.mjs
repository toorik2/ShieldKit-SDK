import { repoPath as vcRepoPath } from '#repo-paths';
// maingate.mjs -- MAIN-focused: optimize bodies with the CROWN heuristic (no search), MAIN
// WITH node-order search, splice, measure locking bytes, then GATE:
//  (1) round-trip byte-exact identity (IR faithfulness) via recompileProgram
//  (2) E2E multiproof: valid-ACCEPT n/n, invalid-REJECT n/n, artifact-differential vs baseline
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin,
} from '@bitauth/libauth';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect, rebuild, decompileProgram, recompileProgram } from './program.mjs';
import { optimizeItems } from './optimize.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));

// bodies: reuse the CROWN's already-optimized body bytes (dissect the 5,695 crown artifact)
// so we only pay to re-derive MAIN. The crown at /tmp/.../aggressive-scheduler/optimized.hex.
const CROWN = '/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/aggressive-scheduler/optimized.hex';
const crownBytes = Uint8Array.from(Buffer.from(readFileSync(CROWN, 'utf8').trim(), 'hex'));
const dc = dissect(crownBytes);
const override = new Map();
let bodyOpt = 0;
for (const id of d.order) { const body = dc.bodies.get(id); override.set(id, body); bodyOpt += body.length; }
console.log(`crown bodies reused: ${bodyOpt} B; crown artifact ${crownBytes.length} B`);
// MAIN: with node-order search
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
const { bytes: mainHeur } = optimizeItems(mainItems, arity, 'sched', { peephole: true });
const { bytes: mainOpt } = optimizeItems(mainItems, arity, 'sched', { peephole: true, search: { cap: 40000, trials: 4000 } });

const optBytes = rebuild(d, override, mainOpt);
writeFileSync(join(here, 'optimized.hex'), Buffer.from(optBytes).toString('hex'));

console.log(`baseline           ${baseline.length} B`);
console.log(`main   heuristic ${mainHeur.length} B  ->  search ${mainOpt.length} B  (main saved ${mainHeur.length - mainOpt.length} B)`);
console.log(`OPTIMIZED ARTIFACT ${optBytes.length} B`);

// (1) round-trip byte-exact identity
const ir = decompileProgram(d, arity, 10);
const rr = recompileProgram(d, ir, arity);
const rtExact = Buffer.from(rr.bytes).equals(Buffer.from(baseline));
console.log(`ROUND-TRIP byte-exact: ${rtExact} (mainExact=${rr.mainExact})`);

// (2) E2E multiproof
const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
};
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const runLock = (locking, unlockHex) => vm.verify(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: hexToBin(unlockHex), valueSatoshis: 10000n })) === true;

const mp = JSON.parse(readFileSync(vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json'), 'utf8'));
let acc = 0, rej = 0, diffOK = 0;
for (let i = 0; i < mp.proofs.length; i++) {
  const p = mp.proofs[i];
  const optV = runLock(optBytes, p.unlocking), optI = runLock(optBytes, p.invalidUnlocking);
  const baseV = runLock(baseline, p.unlocking), baseI = runLock(baseline, p.invalidUnlocking);
  if (optV) acc++; if (!optI) rej++;
  if (optV === baseV && optI === baseI) diffOK++;
}
const n = mp.proofs.length;
console.log(`E2E: valid-ACCEPT ${acc}/${n} ; invalid-REJECT ${rej}/${n} ; artifact-differential ${diffOK}/${n}`);
const PASS = rtExact && acc === n && rej === n && diffOK === n;
console.log(`GATE: ${PASS ? 'PASS' : 'FAIL'}`);
process.exit(PASS ? 0 : 1);
