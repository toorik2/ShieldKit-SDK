import { readFileSync, writeFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';

const mat = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const a = mat.actions.deposit;
const base = [...a.verifierRoles, ...a.structural].map((role) => ({
  lockingBytecode: Uint8Array.from(Buffer.from(role.lock, 'hex')),
  unlockingBytecode: Uint8Array.from(Buffer.from(role.unlock, 'hex')),
  valueSatoshis: 1000n, sequenceNumber: 0n,
}));
const vm = createRealVm();
const run = (inputs, label) => {
  let gateOk = true;
  const rows = [];
  for (let i = 0; i < inputs.length; i++) {
    const out = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined,
      { index: i, inputs, outputValueSatoshis: 1000n });
    const accepts = out.accepted === true;
    rows.push(accepts);
    if (i < 6 && !accepts) gateOk = false;
  }
  console.log(`${label}: verifier gateOk=${gateOk} rows=${rows.slice(0,6).map(r => r?'Y':'N').join('')}`);
  return gateOk;
};

// 1) honest baseline
run(base, 'honest');

// 2) tamper: flip one byte in exec0's unlock witness (proof limb)
const t1 = base.map((i, idx) => idx === 0 ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, k) => k === 20 ? b ^ 0x01 : b) } : i);
run(t1, 'tamper-exec0-proof-limb');

// 3) tamper: mutate the packet input (input 6) — digest mismatch -> terminal reject
const t2 = base.map((i, idx) => idx === 6 ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((b, k) => k === 30 ? b ^ 0x01 : b) } : i);
run(t2, 'tamper-packet');

// 4) tamper: swap genesis unlock for terminal's (role substitution)
const t3 = base.map((i, idx) => idx === 4 ? { ...i, unlockingBytecode: base[5].unlockingBytecode } : i);
run(t3, 'tamper-role-substitution');
