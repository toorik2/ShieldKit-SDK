import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { hexToBin } from '@bitauth/libauth';
import { createRealVm, evaluatePair } from '../../../../harness/src/harness/vm.ts';

type Item = { name: string; lock: Uint8Array; unlock: Uint8Array; token?: any };
type Push = { opcode: number; opcodeOffset: number; dataOffset: number; length: number };

const runDir = resolve(process.argv[2] ?? '.vc/runs/sub75-luna-r3-close-fusion9-v2/build');
const outPath = resolve(process.argv[3] ?? resolve(runDir, 'terminal-mutations.json'));
const raw = JSON.parse(readFileSync(resolve(runDir, 'inputs_dump.json'), 'utf8')) as Array<{ name: string; lock: string; unlock: string; token?: any }>;
const base: Item[] = raw.map((x) => ({
  name: x.name,
  lock: hexToBin(x.lock),
  unlock: hexToBin(x.unlock),
  ...(x.token ? { token: { category: hexToBin(x.token.category), capability: x.token.capability, commitment: hexToBin(x.token.commitment) } } : {}),
}));
const vm = createRealVm();

const parsePushes = (script: Uint8Array): Push[] => {
  const out: Push[] = [];
  for (let i = 0; i < script.length;) {
    const opcode = script[i++];
    if (opcode === 0x00 || opcode === 0x4f || (opcode >= 0x51 && opcode <= 0x60)) {
      out.push({ opcode, opcodeOffset: i - 1, dataOffset: i, length: 0 });
      continue;
    }
    let length: number;
    if (opcode <= 75) length = opcode;
    else if (opcode === 0x4c) length = script[i++];
    else if (opcode === 0x4d) { length = script[i] | (script[i + 1] << 8); i += 2; }
    else if (opcode === 0x4e) { length = script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24); i += 4; }
    else continue;
    out.push({ opcode, opcodeOffset: i - (opcode === 0x4c ? 2 : opcode === 0x4d ? 3 : opcode === 0x4e ? 5 : 1), dataOffset: i, length });
    i += length;
  }
  return out;
};

const clone = (): Item[] => base.map((x) => ({
  ...x,
  lock: new Uint8Array(x.lock),
  unlock: new Uint8Array(x.unlock),
  ...(x.token ? { token: { ...x.token, category: new Uint8Array(x.token.category), commitment: new Uint8Array(x.token.commitment) } } : {}),
}));

const evaluate = (items: Item[]) => {
  const siblings = items.map((x) => ({
    lockingBytecode: x.lock,
    unlockingBytecode: x.unlock,
    valueSatoshis: 1000n,
    sequenceNumber: 0,
    ...(x.token ? { token: x.token } : {}),
  }));
  const rows = items.map((x, index) => {
    const r = evaluatePair(vm, x.lock, x.unlock, undefined, { index, inputs: siblings, outputValueSatoshis: 1000n });
    return {
      index,
      accepts: r.accepted,
      operationCost: r.operationCost,
      instructionCount: r.instructionCount,
      error: r.accepted ? '' : (r.error ?? 'bad final stack'),
    };
  });
  return { accepts: rows.every((x) => x.accepts), rows };
};

const mutatePush = (items: Item[], input: number, pushIndex: number, byteInPush = 0) => {
  const pushes = parsePushes(items[input].unlock);
  const p = pushes[pushIndex];
  if (!p) throw new Error(`push ${pushIndex} unavailable on input ${input}`);
  if (p.length === 0) {
    items[input].unlock[p.opcodeOffset] = p.opcode === 0x00 ? 0x51 : 0x00;
  } else {
    if (p.length <= byteInPush) throw new Error(`push ${pushIndex} unavailable on input ${input}`);
    items[input].unlock[p.dataOffset + byteInPush] ^= 1;
  }
  return { input, pushIndex, byteInPush, length: p.length };
};
const firstDataPush = (items: Item[], input: number, lo: number, hi: number) => {
  const pushes = parsePushes(items[input].unlock);
  for (let i = lo; i <= hi; i++) if (pushes[i]) return mutatePush(items, input, i);
  throw new Error(`no stack push in ${lo}..${hi}`);
};

const mutations: Array<{ name: string; apply: (items: Item[]) => any }> = [
  { name: 'r65', apply: (x) => firstDataPush(x, 8, 26, 37) },
  { name: 'c', apply: (x) => firstDataPush(x, 8, 50, 61) },
  { name: 'cInv', apply: (x) => firstDataPush(x, 8, 38, 49) },
  { name: 'bq', apply: (x) => mutatePush(x, 8, 1, 100) },
  { name: 'w', apply: (x) => firstDataPush(x, 8, 2, 13) },
  { name: 'state', apply: (x) => mutatePush(x, 0, 0, 7) },
  { name: 'seam', apply: (x) => mutatePush(x, 8, 0, 161) },
  { name: 'role', apply: (x) => { x[7].lock[10] ^= 1; return { input: 7, byte: 10 }; } },
  { name: 'carrier-length', apply: (x) => { x[0].unlock = Uint8Array.from([...x[0].unlock, 0]); return { input: 0, appended: 1 }; } },
  { name: 'carrier-byte', apply: (x) => { const baseLen = 8088; x[0].unlock[baseLen + 3] ^= 1; return { input: 0, offset: baseLen + 3 }; } },
];

const honest = evaluate(clone());
const results = mutations.map(({ name, apply }) => {
  const items = clone();
  let detail: any;
  try { detail = apply(items); } catch (error) { return { name, status: 'setup-error', error: String(error) }; }
  const result = evaluate(items);
  return { name, status: result.accepts ? 'FALSE_ACCEPT' : 'reject', detail, rows: result.rows };
});
const report = {
  runDir,
  honest: { allAccept: honest.accepts, rows: honest.rows },
  total: results.length,
  rejected: results.filter((x) => x.status === 'reject').length,
  falseAccepts: results.filter((x) => x.status === 'FALSE_ACCEPT').length,
  noOps: results.filter((x) => x.status === 'FALSE_ACCEPT').map((x) => x.name),
  results,
};
writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
if (!honest.accepts || report.falseAccepts > 0 || results.some((x) => x.status === 'setup-error')) process.exitCode = 1;
