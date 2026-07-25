import { repoPath as vcRepoPath } from '#repo-paths';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url'; import { dirname, join } from 'node:path';
import { createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin } from '@bitauth/libauth';
const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here,'baseline.json'),'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode||raw.bytecodeHex||raw.hex,'hex'));
const opt = hexToBin(readFileSync(join(here,'optimized.hex'),'utf8').trim());
console.log('optimized locking bytes:', opt.length, ' baseline:', baseline.length);
const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE,
  maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE,
  maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE,
  maximumBytecodeLength: HUGE, maximumOperationCount: HUGE };
const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
const runLock = (lock, unlockHex) => vm.verify(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: hexToBin(unlockHex), valueSatoshis: 10000n })) === true;
const mp = JSON.parse(readFileSync(vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json'),'utf8'));
let acc=0,rej=0,diff=0; const n=mp.proofs.length;
for (let i=0;i<n;i++){ const p=mp.proofs[i];
  const oV=runLock(opt,p.unlocking), oI=runLock(opt,p.invalidUnlocking), bV=runLock(baseline,p.unlocking), bI=runLock(baseline,p.invalidUnlocking);
  if(oV)acc++; if(!oI)rej++; if(oV===bV&&oI===bI)diff++;
  console.log(`proof#${i} pub=${JSON.stringify(p.publicInputs)} valid opt=${oV?'ACCEPT':'FAIL'} base=${bV?'ACCEPT':'FAIL'} | invalid opt=${oI?'ACCEPT!!':'reject'} base=${bI?'ACCEPT!!':'reject'} | diff=${oV===bV&&oI===bI?'ok':'MISMATCH'}`);
}
console.log(`\nE2E: valid-ACCEPT ${acc}/${n} ; invalid-REJECT ${rej}/${n} ; artifact-differential ${diff}/${n}`);
console.log('E2E GATE:', (acc===n&&rej===n&&diff===n)?'PASS':'FAIL');
