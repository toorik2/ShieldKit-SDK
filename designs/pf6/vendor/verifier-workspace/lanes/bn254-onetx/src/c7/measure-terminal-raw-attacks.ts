import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { hexToBin } from '@bitauth/libauth';
import { createRealVm, evaluatePair } from '../../../../harness/src/harness/vm.ts';

type Item = { name: string; lock: Uint8Array; unlock: Uint8Array; token?: any };

const runDir = resolve(process.argv[2]);
const outPath = resolve(process.argv[3] ?? resolve(runDir, 'raw-attacks.json'));
const raw = JSON.parse(readFileSync(resolve(runDir, 'inputs_dump.json'), 'utf8')) as Array<{ name: string; lock: string; unlock: string; token?: any }>;
const base: Item[] = raw.map((x) => ({
  name: x.name,
  lock: hexToBin(x.lock),
  unlock: hexToBin(x.unlock),
  ...(x.token ? { token: { category: hexToBin(x.token.category), capability: x.token.capability, commitment: hexToBin(x.token.commitment) } } : {}),
}));
const vm = createRealVm();

const clone = (): Item[] => base.map((x) => ({
  ...x,
  lock: new Uint8Array(x.lock),
  unlock: new Uint8Array(x.unlock),
  ...(x.token ? { token: { ...x.token, category: new Uint8Array(x.token.category), commitment: new Uint8Array(x.token.commitment) } } : {}),
}));
const terminalIndex = base.findIndex((item) => item.name === 'terminal');
if (terminalIndex < 0) throw new Error('terminal role unavailable');
// The closed PF7 route may be either the exact seven-role profile or a
// larger experimental context. Never mutate unevaluated structural roles.
const verifierRoleCount = terminalIndex + 1;
const evaluate = (items: Item[]) => items.slice(0, verifierRoleCount).map((x, index) =>
  evaluatePair(vm, x.lock, x.unlock, undefined, {
    index,
    inputs: items.map((y) => ({
      lockingBytecode: y.lock,
      unlockingBytecode: y.unlock,
      valueSatoshis: 1000n,
      sequenceNumber: 0,
      ...(y.token ? { token: y.token } : {}),
    })),
    outputValueSatoshis: 1000n,
  }));
const attacks: Array<{ name: string; apply: (items: Item[]) => void }> = [];
for (let i = 0; i < verifierRoleCount; i++) attacks.push({ name: `role-byte-${i}`, apply: (x) => { x[i].lock[10] ^= 1; } });
// The current terminal authenticates the shared executor implementation from
// one P2SH32 locking bytecode, so swapping executor locks is a no-op: there is
// no historical per-role INPUTINDEX selector in the terminal unlocking data to
// mutate. Substitute each *role-bound carrier witness* with an adjacent role
// instead. Every source slot remains present, but its state/record/fragment
// assignment is wrong and must reject in the closed sibling context.
for (let i = 0; i < verifierRoleCount; i++) attacks.push({ name: `role-witness-substitute-${i}`, apply: (x) => {
  const next = (i + 1) % verifierRoleCount;
  [x[i].unlock, x[next].unlock] = [x[next].unlock, x[i].unlock];
} });
attacks.push({ name: 'source-lock-permutation', apply: (x) => { [x[0].lock, x[terminalIndex].lock] = [x[terminalIndex].lock, x[0].lock]; } });
attacks.push({ name: 'witness-permutation', apply: (x) => { [x[0].unlock, x[1].unlock] = [x[1].unlock, x[0].unlock]; } });
attacks.push({ name: 'carrier-length', apply: (x) => { x[0].unlock = Uint8Array.from([...x[0].unlock, 0]); } });
attacks.push({ name: 'carrier-byte', apply: (x) => { x[0].unlock[8088 + 3] ^= 1; } });

const honest = evaluate(clone());
const results = attacks.map(({ name, apply }) => {
  const items = clone();
  try { apply(items); } catch (e) { return { name, status: 'setup-error', error: String(e) }; }
  const rows = evaluate(items);
  return { name, status: rows.every((r) => r.accepted) ? 'FALSE_ACCEPT' : 'reject', rows: rows.map((r) => ({ accepted: r.accepted, operationCost: r.operationCost, error: r.accepted ? '' : (r.error ?? 'bad final stack') })) };
});
const report = { runDir, honest: { allAccept: honest.every((r) => r.accepted) }, total: results.length, rejected: results.filter((r) => r.status === 'reject').length, falseAccepts: results.filter((r) => r.status === 'FALSE_ACCEPT').length, setupErrors: results.filter((r) => r.status === 'setup-error').length, results };
writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
if (!report.honest.allAccept || report.falseAccepts > 0 || report.setupErrors > 0) process.exitCode = 1;
