import { repoPath as vcRepoPath } from '#repo-paths';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url'; import { dirname, join } from 'node:path';
import { createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin } from '@bitauth/libauth';
const here = dirname(fileURLToPath(import.meta.url));
const opt = hexToBin(readFileSync(join(here,'optimized.hex'),'utf8').trim());
const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE };
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const runLock = (unlockHex) => vm.verify(createTestAuthenticationProgramBch({ lockingBytecode: opt, unlockingBytecode: hexToBin(unlockHex), valueSatoshis: 10000n })) === true;
const mp = JSON.parse(readFileSync(vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json'),'utf8'));
let acc=0,rej=0; const n=mp.proofs.length;
console.log('opt locking bytes', opt.length, 'proofs', n);
for (let i=0;i<n;i++){ const p=mp.proofs[i];
  const oV=runLock(p.unlocking); const oI=runLock(p.invalidUnlocking);
  if(oV)acc++; if(!oI)rej++;
  console.log(`proof#${i} pub=${JSON.stringify(p.publicInputs)} valid=${oV?'ACCEPT':'FAIL'} invalid=${oI?'ACCEPT!!':'reject'}`);
}
console.log(`\nE2E(opt-only): valid-ACCEPT ${acc}/${n} ; invalid-REJECT ${rej}/${n}`);
console.log('E2E GATE:', (acc===n&&rej===n)?'PASS':'FAIL');
