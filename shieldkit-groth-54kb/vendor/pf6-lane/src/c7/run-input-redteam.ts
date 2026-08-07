// Closed-transaction EIP-197 input-validation battery for the six/seven-input
// fixed-G2 route and its bounded ten-input shield.cash verifier context. This
// is deliberately intratx-aware: every altered witness is installed in the
// shared input list before each verifier role is evaluated.
//
// Inputs are real C7 build directories (the `c7/` directories emitted by
// `npm run vc -- exec -- … build.ts`):
//   tsx run-input-redteam.ts --honest RUN/c7 --offsub RUN/c7 --fixture FILE \
//     [--extra RUN/c7 ...] [--worst RUN/c7] --out DIR
//
// The off-subgroup run must have been rebuilt from the supplied on-curve,
// non-torsion fixture.  It cannot be a point swap into the honest run: the
// complete trajectory and all state witnesses must correspond to that point.
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
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

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const argv = process.argv.slice(2);
const value = (name: string) => {
  const index = argv.indexOf(name);
  if (index < 0 || argv[index + 1] === undefined) throw new Error(`missing ${name}`);
  return argv[index + 1]!;
};
const values = (name: string) => argv.flatMap((entry, index) => entry === name && argv[index + 1] !== undefined ? [argv[index + 1]!] : []);
const optional = (name: string) => {
  const index = argv.indexOf(name);
  return index < 0 ? undefined : argv[index + 1];
};
const honestDir = resolve(value('--honest'));
const offsubDir = resolve(value('--offsub'));
const fixturePath = resolve(value('--fixture'));
const outDir = resolve(value('--out'));
const extraDirs = values('--extra').map((dir) => resolve(dir));
const worstDir = optional('--worst');
mkdirSync(outDir, { recursive: true });

const TOPO_6 = ['exec0', 'exec1', 'exec2', 'exec3', 'genesis', 'terminal'] as const;
const TOPO_7 = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'] as const;
const TOPO_10 = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal', 'packet', 'state', 'fee'] as const;
const readRun = (dir: string): Item[] => {
  const raw = JSON.parse(readFileSync(resolve(dir, 'inputs_dump.json'), 'utf8')) as RawInput[];
  assert.ok(raw.length === 6 || raw.length === 7 || raw.length === 10, `${dir}: expected six, seven, or bounded ten input records, got ${raw.length}`);
  return raw.map((row) => ({ name: row.name, lock: hexToBin(row.lock), unlock: hexToBin(row.unlock) }));
};
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as Record<string, string>;
const honest = readRun(honestDir);
const offsub = readRun(offsubDir);
const extraValid = extraDirs.map(readRun);
const worstCase = worstDir === undefined ? undefined : readRun(resolve(worstDir));
const expectedNames = honest.length === 6 ? [...TOPO_6] : honest.length === 7 ? [...TOPO_7] : [...TOPO_10];
const genesisIndex = honest.findIndex((item) => item.name === 'genesis');
const terminalIndex = honest.findIndex((item) => item.name === 'terminal');
const packetIndex = honest.findIndex((item) => item.name === 'packet');
const verifierRoleCount = packetIndex >= 0 ? packetIndex : honest.length;
assert.ok(genesisIndex >= 0 && terminalIndex >= 0, 'missing genesis/terminal roles');
if (honest.length === 10) assert.equal(packetIndex, 7, 'bounded ten-role packet must be input 7');

assert.deepEqual(honest.map((x) => x.name), expectedNames);
const assertSameLockings = (run: Item[], label: string) => {
  assert.deepEqual(run.map((x) => x.name), honest.map((x) => x.name), `${label}: role topology drift`);
  for (const [index, item] of honest.entries()) {
    assert.equal(binToHex(item.lock), binToHex(run[index]!.lock), `${label}: locking drift at input ${index}`);
  }
};
assertSameLockings(offsub, 'off-subgroup');
extraValid.forEach((run, index) => assertSameLockings(run, `extra-valid-${index}`));
if (worstCase !== undefined) assertSameLockings(worstCase, 'worst-case');

const parsePushes = (script: Uint8Array): Push[] => {
  const out: Push[] = [];
  for (let i = 0; i < script.length;) {
    const start = i;
    const opcode = script[i++]!;
    if (opcode === 0x00 || opcode === 0x4f || (opcode >= 0x51 && opcode <= 0x60)) {
      out.push({ start, data: i, length: 0, opcode });
      continue;
    }
    let length: number;
    if (opcode <= 75) length = opcode;
    else if (opcode === 0x4c) length = script[i++]!;
    else if (opcode === 0x4d) { length = script[i]! | (script[i + 1]! << 8); i += 2; }
    else if (opcode === 0x4e) { length = script[i]! | (script[i + 1]! << 8) | (script[i + 2]! << 16) | (script[i + 3]! << 24); i += 4; }
    else throw new Error(`non-push opcode 0x${opcode.toString(16)} at ${start}`);
    if (i + length > script.length) throw new Error(`truncated push at ${start}`);
    out.push({ start, data: i, length, opcode });
    i += length;
  }
  return out;
};

const clone = (items: readonly Item[]): Item[] => items.map((item) => ({
  name: item.name,
  lock: Uint8Array.from(item.lock),
  unlock: Uint8Array.from(item.unlock),
}));

// LE 32 B field limb (no modular reduction — needed for non-canonical Bxa+P attacks).
const leBytes32 = (value: bigint): Uint8Array => {
  assert.ok(value >= 0n && value < (1n << 256n), `value out of 32-byte range: ${value}`);
  let current = value;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(current & 0xffn);
    current >>= 8n;
  }
  return out;
};

const replaceGenesisArgument = (items: Item[], oldValue: bigint, newValue: bigint) => {
  const genesis = items[genesisIndex]!;
  const pushes = parsePushes(genesis.unlock);
  // 1) Prefer a standalone int push (legacy ECIP seam/WIT layout).
  const intMatches = pushes.filter((push) => push.length > 0
    && vmNumberToBigInt(genesis.unlock.subarray(push.data, push.data + push.length), { requireMinimalEncoding: false }) === oldValue);
  if (intMatches.length === 1) {
    const oldPush = intMatches[0]!;
    const encoded = encodeDataPush(bigIntToVmNumber(newValue));
    const oldTotal = oldPush.data + oldPush.length - oldPush.start;
    assert.equal(encoded.length, oldTotal, 'adversarial mutation unexpectedly changes script encoding length');
    genesis.unlock.set(encoded, oldPush.start);
    return;
  }
  // 2) Context-deduped layout: statement points live as LE 32 B limbs inside the
  //    448 B projectionContext (first large push at unlock offset 0 for siblings).
  const oldLimb = leBytes32(((oldValue % P) + P) % P);
  const newLimb = leBytes32(newValue < 0n ? ((newValue % P) + P) % P : newValue);
  const blobMatches: { data: number; offset: number }[] = [];
  for (const push of pushes) {
    if (push.length < 32) continue;
    const blob = genesis.unlock.subarray(push.data, push.data + push.length);
    for (let offset = 0; offset + 32 <= blob.length; offset += 32) {
      let eq = true;
      for (let i = 0; i < 32; i++) {
        if (blob[offset + i] !== oldLimb[i]) { eq = false; break; }
      }
      if (eq) blobMatches.push({ data: push.data, offset });
    }
  }
  assert.equal(blobMatches.length, 1, `expected exactly one genesis argument equal to ${oldValue}, found ${intMatches.length} int + ${blobMatches.length} limb`);
  const hit = blobMatches[0]!;
  genesis.unlock.set(newLimb, hit.data + hit.offset);
};

type Row = { index: number; name: string; accepts: boolean; error: string; operationCost: number };
const evaluate = (items: Item[]): Row[] => {
  const vm = createRealVm();
  const inputs = items.map((item) => ({
    lockingBytecode: item.lock,
    unlockingBytecode: item.unlock,
    valueSatoshis: 1000n,
    sequenceNumber: 0,
  }));
  return items.slice(0, verifierRoleCount).map((item, index) => {
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
const assertFirstReject = (name: string, rows: Row[], index: number) => {
  assert.equal(rows.slice(0, index).every((row) => row.accepts), true, `${name}: an earlier input rejected`);
  assert.equal(rows[index]!.accepts, false, `${name}: expected input ${index} to reject`);
};
// Context-deduped genesis stores statement points in the sibling-facing projection
// blob. Tampering that blob can make an earlier executor reject first; the
// battery only requires that the closed transaction still rejects.
const assertAnyReject = (name: string, rows: Row[]) => {
  assert.ok(rows.some((row) => !row.accepts), `${name}: expected at least one input to reject`);
};
const tamperLargestPush = (items: Item[], index: number) => {
  const target = items[index]!;
  const pushes = parsePushes(target.unlock)
    .filter((push) => push.length > 0)
    .sort((a, b) => b.length - a.length);
  const push = pushes[0];
  assert.ok(push, `input ${index} has no data push to tamper`);
  target.unlock[push.data + Math.floor(push.length / 2)]! ^= 1;
};

const offCurveA = clone(honest);
const ax = BigInt(fixture.Ax);
replaceGenesisArgument(offCurveA, ax, ax + 1n);
const offCurveARows = evaluate(offCurveA);
assertAnyReject('off-curve-A', offCurveARows);

const offCurveB = clone(honest);
const bya = BigInt(fixture.Bya);
replaceGenesisArgument(offCurveB, bya, bya + 1n);
const offCurveBRows = evaluate(offCurveB);
assertAnyReject('off-curve-B', offCurveBRows);

const nonCanonicalB = clone(honest);
const bxa = BigInt(fixture.Bxa);
replaceGenesisArgument(nonCanonicalB, bxa, bxa + P);
const nonCanonicalBRows = evaluate(nonCanonicalB);
assertAnyReject('noncanonical-B', nonCanonicalBRows);

const offsubRows = evaluate(offsub);
assertFirstReject('off-subgroup-B', offsubRows, terminalIndex);

const honestRows = evaluate(honest);
assert.equal(honestRows.every((row) => row.accepts), true, 'honest verifier role rejected');

const publicLimbMutation = clone(honest);
const in0 = BigInt(fixture.in0);
replaceGenesisArgument(publicLimbMutation, in0, in0 + 1n);
const publicLimbMutationRows = evaluate(publicLimbMutation);
assertAnyReject('public-limb', publicLimbMutationRows);

const packetMutationRows = packetIndex < 0 ? undefined : (() => {
  const run = clone(honest);
  tamperLargestPush(run, packetIndex);
  const rows = evaluate(run);
  assertFirstReject('packet', rows, terminalIndex);
  return rows;
})();

const extraValidRows = extraValid.map((run, index) => {
  assert.notEqual(
    binToHex(run[genesisIndex]!.unlock),
    binToHex(honest[genesisIndex]!.unlock),
    `extra-valid-${index}: genesis witness is not distinct from the primary proof`,
  );
  const rows = evaluate(run);
  assert.equal(rows.every((row) => row.accepts), true, `extra-valid-${index}: a valid proof rejected`);
  return rows;
});
const worstCaseRows = worstCase === undefined ? undefined : (() => {
  assert.notEqual(binToHex(worstCase[genesisIndex]!.unlock), binToHex(honest[genesisIndex]!.unlock), 'worst-case: genesis witness is not distinct from the primary proof');
  const rows = evaluate(worstCase);
  assert.equal(rows.every((row) => row.accepts), true, 'worst-case: valid proof rejected');
  return rows;
})();

const witnessTampers = honest.slice(0, verifierRoleCount).map((_, index) => {
  const run = clone(honest);
  tamperLargestPush(run, index);
  const rows = evaluate(run);
  assert.equal(rows.some((row) => !row.accepts), true, `witness tamper ${index} unexpectedly accepted`);
  return { run, rows };
});

const genesisSource = readFileSync(resolve(honestDir, '..', 'generated', '_c7_merged.cash'), 'utf8');
const terminalSource = readFileSync(resolve(honestDir, '..', 'generated', '_sb_terminal.cash'), 'utf8');
// Accept either the historical inlined form or the eFpRange helper hoist —
// both require non-negative, <P canonical G2 coordinates before the twist.
const twistAt = genesisSource.indexOf('(int oxa,int oxb) = eFp2Mul(Bxa, Bxb, Bxa, Bxb);');
const inlinedCanonicalAt = genesisSource.indexOf('require(Bxa >= 0); require(Bxa < Pmod);');
// dual-require or dens-rich combined `require(x>=0&&x<P)` — both bound [0,P)
const helperDefAt = Math.max(
  genesisSource.indexOf('function eFpRange(int x){require(x>=0);require(x<'),
  genesisSource.indexOf('function eFpRange(int x){require(x>=0&&x<'),
);
const helperUseAt = genesisSource.indexOf('eFpRange(Bxa);');
const canonicalAt = inlinedCanonicalAt >= 0
  ? inlinedCanonicalAt
  : (helperDefAt >= 0 && helperUseAt >= 0 ? helperUseAt : -1);
assert.ok(canonicalAt >= 0 && twistAt >= 0 && canonicalAt < twistAt,
  'canonical G2 guards must precede the twist equation');
assert.match(terminalSource, /q3xa.*= psi\(q2xa, q2xb, q2ya, q2yb\)/);
assert.match(terminalSource, /require\(v26 == q3xa %/);
assert.match(terminalSource, /require\(v28 == nq3ya %/);

const toRaw = (items: readonly Item[]) => items.map((item) => ({
  label: item.name,
  locking: binToHex(item.lock),
  unlocking: binToHex(item.unlock),
}));
const vectors = {
  schema: 'verifier.cash/bn254-onetx-static-fixed-g2-vectors/v1',
  topology: `single BCH transaction; ${honest.length} linked inputs`,
  steps: toRaw(honest),
  extraValidProofs: extraValid.map(toRaw),
  ...(worstCase === undefined ? {} : { worstCaseProof: toRaw(worstCase) }),
  invalid: witnessTampers.map(({ run }) => toRaw(run)),
  invalidInputs: [toRaw(offCurveA), toRaw(offCurveB), toRaw(nonCanonicalB), toRaw(offsub), toRaw(publicLimbMutation), ...(packetIndex < 0 ? [] : [toRaw((() => { const run = clone(honest); tamperLargestPush(run, packetIndex); return run; })())])],
};
const report = {
  schema: 'verifier.cash/bn254-onetx-input-redteam/v1',
  honestDir,
  offsubDir,
  fixture: fixturePath,
  checks: {
    sourceCanonicalG2BeforeTwist: true,
    sourceT5FoldPresent: true,
    honest: honestRows,
    offCurveA: offCurveARows,
    offCurveB: offCurveBRows,
    nonCanonicalB: nonCanonicalBRows,
    offSubgroupB: offsubRows,
    publicLimbMutation: publicLimbMutationRows,
    ...(packetMutationRows === undefined ? {} : { packetMutation: packetMutationRows }),
    extraValidProofs: extraValidRows,
    ...(worstCaseRows === undefined ? {} : { worstCase: worstCaseRows }),
    witnessTampers: witnessTampers.map(({ rows }) => rows),
  },
  verdict: 'pass',
  note: 'The off-subgroup trajectory is rebuilt from the on-curve off-torsion B fixture. Its first rejection is the terminal containing the explicit R_end == -psi^3(B) T5-1 fold. The accompanying T5-1 cofactor-kernel gate establishes that this fold has no twist-cofactor kernel. In the bounded ten-input context, only inputs 0..6 are verifier roles; packet/state/fee remain structural and unevaluated.',
};
writeFileSync(resolve(outDir, 'vectors.json'), `${JSON.stringify(vectors, null, 2)}\n`);
writeFileSync(resolve(outDir, 'input-redteam.json'), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify({ verdict: report.verdict, extraValidProofs: extraValid.length, worstCase: worstCase !== undefined, vectors: resolve(outDir, 'vectors.json'), report: resolve(outDir, 'input-redteam.json') }, null, 2));
