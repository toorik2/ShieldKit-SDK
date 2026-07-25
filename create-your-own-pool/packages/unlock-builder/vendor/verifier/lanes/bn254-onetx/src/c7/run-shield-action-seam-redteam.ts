// Adversarial battery for the bounded shield.cash raw-digest seam.
// Only verifier roles 0..6 are evaluated; packet/state/fee remain explicitly
// structural. Every evaluation nevertheless uses the complete ten-input list.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  bigIntToVmNumber,
  binToHex,
  encodeDataPush,
  hexToBin,
  vmNumberToBigInt,
} from '@bitauth/libauth';

import { createRealVm, evaluatePair } from '../../../../harness/src/harness/vm.ts';

type RawInput = { name: string; lock: string; unlock: string };
type Item = { name: string; lock: Uint8Array; unlock: Uint8Array };
type Push = { start: number; data: number; length: number; opcode: number };
type Row = { index: number; name: string; accepts: boolean; error: string; operationCost: number };

const argv = process.argv.slice(2);
const value = (name: string) => {
  const index = argv.indexOf(name);
  if (index < 0 || argv[index + 1] === undefined) throw new Error(`missing ${name}`);
  return argv[index + 1]!;
};
const values = (name: string) => argv.flatMap((entry, index) =>
  entry === name && argv[index + 1] !== undefined ? [argv[index + 1]!] : []);

const honestDir = resolve(value('--honest'));
const fixturePath = resolve(value('--fixture'));
const outputPath = resolve(value('--out'));
const crossDirs = values('--cross').map((directory) => resolve(directory));
const fixtureDocument = JSON.parse(readFileSync(fixturePath, 'utf8'));
const fixture = fixtureDocument.verifierCashFixture ?? fixtureDocument;

const readRun = (directory: string): Item[] => {
  const raw = JSON.parse(readFileSync(resolve(directory, 'inputs_dump.json'), 'utf8')) as RawInput[];
  assert.deepEqual(raw.map((row) => row.name), [
    'exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal', 'packet', 'state', 'fee',
  ]);
  return raw.map((row) => ({
    name: row.name,
    lock: hexToBin(row.lock),
    unlock: hexToBin(row.unlock),
  }));
};

const honest = readRun(honestDir);
const crosses = crossDirs.map(readRun);
const clone = (items: readonly Item[]): Item[] => items.map((item) => ({
  name: item.name,
  lock: Uint8Array.from(item.lock),
  unlock: Uint8Array.from(item.unlock),
}));
const parsePushes = (script: Uint8Array): Push[] => {
  const pushes: Push[] = [];
  for (let index = 0; index < script.length;) {
    const start = index;
    const opcode = script[index++]!;
    if (opcode === 0x00 || opcode === 0x4f || (opcode >= 0x51 && opcode <= 0x60)) {
      pushes.push({ start, data: index, length: 0, opcode });
      continue;
    }
    let length: number;
    if (opcode <= 75) length = opcode;
    else if (opcode === 0x4c) length = script[index++]!;
    else if (opcode === 0x4d) { length = script[index]! | (script[index + 1]! << 8); index += 2; }
    else if (opcode === 0x4e) {
      length = script[index]! | (script[index + 1]! << 8)
        | (script[index + 2]! << 16) | (script[index + 3]! << 24);
      index += 4;
    } else throw new Error(`non-push opcode 0x${opcode.toString(16)} at ${start}`);
    if (index + length > script.length) throw new Error(`truncated push at ${start}`);
    pushes.push({ start, data: index, length, opcode });
    index += length;
  }
  return pushes;
};
const replacePublicInput = (items: Item[], oldValue: bigint, newValue: bigint) => {
  const genesis = items[5]!;
  const matches = parsePushes(genesis.unlock).filter((push) => push.length > 0
    && vmNumberToBigInt(genesis.unlock.subarray(push.data, push.data + push.length), {
      requireMinimalEncoding: false,
    }) === oldValue);
  assert.equal(matches.length, 1, `expected one public-input push equal to ${oldValue}`);
  const match = matches[0]!;
  const encoded = encodeDataPush(bigIntToVmNumber(newValue));
  assert.equal(encoded.length, match.data + match.length - match.start, 'public-input mutation changes push width');
  genesis.unlock.set(encoded, match.start);
};
const evaluate = (items: Item[]): Row[] => {
  const vm = createRealVm();
  const inputs = items.map((item) => ({
    lockingBytecode: item.lock,
    unlockingBytecode: item.unlock,
    valueSatoshis: 1000n,
    sequenceNumber: 0,
  }));
  return items.slice(0, 7).map((item, index) => {
    const result = evaluatePair(vm, item.lock, item.unlock, undefined, {
      index,
      inputs,
      outputValueSatoshis: 1000n,
    });
    return {
      index,
      name: item.name,
      accepts: result.accepted,
      error: result.accepted ? '' : (result.error ?? 'bad final stack'),
      operationCost: result.operationCost,
    };
  });
};
const attacks: Record<string, Row[]> = {};
const attack = (name: string, mutate: (items: Item[]) => void, firstReject?: number) => {
  const run = clone(honest);
  mutate(run);
  const rows = evaluate(run);
  assert.ok(rows.some((row) => !row.accepts), `${name}: verifier roles unexpectedly accepted`);
  if (firstReject !== undefined) {
    assert.equal(rows.slice(0, firstReject).every((row) => row.accepts), true, `${name}: earlier verifier rejected`);
    assert.equal(rows[firstReject]!.accepts, false, `${name}: expected input ${firstReject} to reject`);
  }
  attacks[name] = rows;
};

const honestRows = evaluate(honest);
assert.equal(honestRows.every((row) => row.accepts), true, 'honest verifier role rejected');
assert.equal(binToHex(honest[5]!.unlock.slice(0, 3)), '4de001');
assert.equal(binToHex(honest[7]!.unlock.slice(0, 3)), '4df002');
assert.equal(honest[7]!.unlock.length, 755);

attack('packet-byte', (items) => { items[7]!.unlock[3 + 377] ^= 1; }, 6);
attack('packet-header', (items) => { items[7]!.unlock[0] ^= 1; }, 6);
attack('packet-short', (items) => { items[7]!.unlock = items[7]!.unlock.slice(0, -1); }, 6);
attack('packet-trailing', (items) => {
  items[7]!.unlock = Uint8Array.from([...items[7]!.unlock, 0]);
}, 6);
attack('packet-nonminimal-push', (items) => {
  items[7]!.unlock = Uint8Array.from([0x4e, 0xf0, 0x02, 0, 0, ...items[7]!.unlock.slice(3)]);
}, 6);
attack('carrier-digest-byte', (items) => { items[5]!.unlock[451 + 9] ^= 1; }, 5);
attack('carrier-header', (items) => { items[5]!.unlock[0] ^= 1; }, 5);
attack('carrier-swapped-halves', (items) => {
  const digest = items[5]!.unlock.slice(451, 483);
  items[5]!.unlock.set(digest.slice(16), 451);
  items[5]!.unlock.set(digest.slice(0, 16), 467);
}, 5);
attack('carrier-little-endian-halves', (items) => {
  const digest = items[5]!.unlock.slice(451, 483);
  items[5]!.unlock.set(Uint8Array.from(digest.slice(0, 16)).reverse(), 451);
  items[5]!.unlock.set(Uint8Array.from(digest.slice(16)).reverse(), 467);
}, 5);
attack('carrier-high-bit', (items) => { items[5]!.unlock[451] ^= 0x80; }, 5);
attack('altered-in0', (items) => replacePublicInput(items, BigInt(fixture.in0), BigInt(fixture.in0) + 1n), 5);
attack('altered-in1', (items) => replacePublicInput(items, BigInt(fixture.in1), BigInt(fixture.in1) + 1n), 5);
attack('input5-input7-swap', (items) => {
  const genesis = items[5]!.unlock;
  items[5]!.unlock = items[7]!.unlock;
  items[7]!.unlock = genesis;
});

const crossAction = crosses.map((cross, index) => {
  for (let input = 0; input < 7; input++) {
    assert.equal(
      binToHex(cross[input]!.lock),
      binToHex(honest[input]!.lock),
      `cross-${index}: verifier source lock drift at input ${input}`,
    );
  }
  const packetSubstitution = clone(honest);
  packetSubstitution[7]!.unlock = Uint8Array.from(cross[7]!.unlock);
  const packetRows = evaluate(packetSubstitution);
  assert.equal(packetRows.slice(0, 6).every((row) => row.accepts), true);
  assert.equal(packetRows[6]!.accepts, false, `cross-${index}: cross-action packet/proof accepted`);

  const genesisSubstitution = clone(honest);
  genesisSubstitution[5]!.unlock = Uint8Array.from(cross[5]!.unlock);
  const genesisRows = evaluate(genesisSubstitution);
  assert.ok(genesisRows.some((row) => !row.accepts), `cross-${index}: cross-action genesis accepted`);
  return { packetSubstitution: packetRows, genesisSubstitution: genesisRows };
});

const report = {
  schema: 'verifier.cash/bn254-onetx-shield-action-seam-redteam/v1',
  honestDir,
  fixture: fixturePath,
  scope: 'seven verifier roles evaluated in complete ten-input context; packet/state/fee structural roles unevaluated',
  honest: honestRows,
  attacks,
  crossAction,
  attackCount: Object.keys(attacks).length + crossAction.length * 2,
  verdict: 'pass',
};
writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ verdict: report.verdict, attackCount: report.attackCount, output: outputPath }, null, 2));
