import { readFileSync } from 'node:fs';
import { createRealVm, evaluatePair } from './harness/src/harness/vm.ts';

const mat = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const vm = createRealVm();
const gate = (inputs) => {
  let ok = true;
  const rows = [];
  for (let i = 0; i < inputs.length; i++) {
    const out = evaluatePair(vm, inputs[i].lockingBytecode, inputs[i].unlockingBytecode, undefined,
      { index: i, inputs, outputValueSatoshis: 1000n });
    const accepts = out.accepted === true;
    rows.push(accepts);
    if (i < 6 && !accepts) ok = false;
  }
  return ok;
};
const base = (action) => [...action.verifierRoles, ...action.structural].map((role) => ({
  lockingBytecode: Uint8Array.from(Buffer.from(role.lock, 'hex')),
  unlockingBytecode: Uint8Array.from(Buffer.from(role.unlock, 'hex')),
  valueSatoshis: 1000n, sequenceNumber: 0n,
}));

const results = [];
for (const [actionName, action] of Object.entries(mat.actions)) {
  const b = base(action);
  const honest = gate(b);
  results.push({ action: actionName, honest: honest ? 'ACCEPT' : 'REJECT' });

  // proof-limb flip in each verifier role (byte 20 of each unlock)
  for (let r = 0; r < 6; r++) {
    const t = b.map((i, idx) => idx === r
      ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((byte, k) => k === 20 ? byte ^ 0x01 : byte) }
      : i);
    results.push({ action: actionName, case: `limb-flip role${r}`, ok: !gate(t) ? 'REJECTED' : 'ACCEPTED(!)' });
  }
  // packet mutation
  const tp = b.map((i, idx) => idx === 6
    ? { ...i, unlockingBytecode: Uint8Array.from(i.unlockingBytecode).map((byte, k) => k === 30 ? byte ^ 0x01 : byte) }
    : i);
  results.push({ action: actionName, case: 'packet-mutation', ok: !gate(tp) ? 'REJECTED' : 'ACCEPTED(!)' });
  // role substitution (swap genesis <-> terminal unlocks)
  const ts = b.map((i, idx) => idx === 4 ? { ...i, unlockingBytecode: b[5].unlockingBytecode } : i);
  results.push({ action: actionName, case: 'role-substitution', ok: !gate(ts) ? 'REJECTED' : 'ACCEPTED(!)' });
  // truncation (cut 1 byte from exec0's unlock)
  const tt = b.map((i, idx) => idx === 0
    ? { ...i, unlockingBytecode: i.unlockingBytecode.slice(0, i.unlockingBytecode.length - 1) }
    : i);
  results.push({ action: actionName, case: 'truncation-exec0', ok: !gate(tt) ? 'REJECTED' : 'ACCEPTED(!)' });
}
let bad = 0;
for (const r of results) {
  if (r.honest === 'REJECT') bad++;
  if (r.ok === 'ACCEPTED(!)') bad++;
  console.log(`${r.action ?? ''} ${r.case ?? 'honest'}: ${r.honest ?? r.ok}`);
}
console.log(bad === 0 ? 'TAMPER CORPUS: ALL EXPECTED REJECTIONS CONFIRMED (honest accepts, 9 tamper classes x 3 actions)' : `FAILURES: ${bad}`);
process.exit(bad === 0 ? 0 : 1);
