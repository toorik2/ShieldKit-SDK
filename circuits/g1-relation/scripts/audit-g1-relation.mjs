// Local pre-setup constraint audit. It never creates a ptau, zkey, proof, or
// network request. The core-generated vectors are the only valid baselines.
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { readR1cs } from 'r1csfile';

const run = promisify(execFile);
const [buildDirectory, vectorDirectory, output] = process.argv.slice(2);
if (!buildDirectory || !vectorDirectory || !output) {
  throw new Error('usage: audit-g1-relation.mjs BUILD_DIRECTORY VECTOR_DIRECTORY OUTPUT.json');
}

const wasm = path.join(buildDirectory, 'g1_relation_js', 'g1_relation.wasm');
const witnessGenerator = path.join(buildDirectory, 'g1_relation_js', 'generate_witness.js');
const r1csFile = path.join(buildDirectory, 'g1_relation.r1cs');
const symFile = path.join(buildDirectory, 'g1_relation.sym');
const actions = Object.fromEntries(await Promise.all(['deposit', 'transfer', 'withdrawal'].map(async (kind) => [
  kind,
  JSON.parse(await readFile(path.join(vectorDirectory, `${kind}.json`), 'utf8')),
])));

const clone = (value) => structuredClone(value);
const toggle = (value) => BigInt(value) === 0n ? '1' : '0';
const asFr = (value) => Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
const asU32 = (value) => { const out = Buffer.alloc(4); out.writeUInt32LE(Number(BigInt(value))); return out; };
const asU64 = (value) => { const out = Buffer.alloc(8); out.writeBigUInt64LE(BigInt(value)); return out; };
const asU128 = (hi, lo) => Buffer.concat([
  Buffer.from(BigInt(hi).toString(16).padStart(32, '0'), 'hex'),
  Buffer.from(BigInt(lo).toString(16).padStart(32, '0'), 'hex'),
]);
const recordFromBits = (bits) => Buffer.from(Array.from({ length: 192 }, (_, byte) => Number.parseInt(bits.slice(byte * 8, byte * 8 + 8).join(''), 2)));
const state = (input, prefix) => Buffer.concat([
  asU128(input.profileHi, input.profileLo), asU128(input.instanceHi, input.instanceLo),
  asFr(input[`${prefix}NoteRoot`]), asFr(input[`${prefix}NullifierRoot`]),
  asU32(input[`${prefix}NextLeafIndex`]), asU64(input[`${prefix}ActionSequence`]),
  asU32(input[`${prefix}LiveNoteCount`]), asU64(input[`${prefix}ReserveSats`]),
  asU64(input[`${prefix}MaximumReserve`]), asFr(input[`${prefix}StateCommitment`]),
]);
const kindByte = (input) => input.isDeposit === '1' ? 1 : input.isTransfer === '1' ? 2 : input.isWithdrawal === '1' ? 3 : null;
function packetFromInput(input) {
  const kind = kindByte(input);
  if (kind === null) throw new Error('input does not have a one-hot action selector');
  return Buffer.concat([
    Buffer.from('SCAR'), Buffer.from([1, 2, kind, 0]), state(input, 'pre'), state(input, 'post'),
    asFr(input.inputCm), asFr(input.inputNf), asFr(input.outputCm), recordFromBits(input.recordBits),
    asU64(input.boundaryAmount), asU128(input.withdrawalScriptHi, input.withdrawalScriptLo),
    asU128(input.transactionContextHi, input.transactionContextLo),
  ]);
}
function rebindDigest(input) {
  const digest = createHash('sha256').update(packetFromInput(input)).digest();
  input.publicDigestHi = BigInt(`0x${digest.subarray(0, 16).toString('hex')}`).toString();
  input.publicDigestLo = BigInt(`0x${digest.subarray(16).toString('hex')}`).toString();
  return digest.toString('hex');
}
function limbs(input) {
  return [BigInt(input.publicDigestHi).toString(16).padStart(32, '0'), BigInt(input.publicDigestLo).toString(16).padStart(32, '0')];
}

const parity = Object.fromEntries(Object.entries(actions).map(([kind, input]) => {
  const packet = packetFromInput(input);
  const digest = createHash('sha256').update(packet).digest('hex');
  const observedLimbs = limbs(input);
  const expectedLimbs = [digest.slice(0, 32), digest.slice(32)];
  return [kind, {
    packetBytes: packet.length,
    digest,
    expectedLimbs,
    observedLimbs,
    pass: packet.length === 752 && expectedLimbs[0] === observedLimbs[0] && expectedLimbs[1] === observedLimbs[1],
  }];
}));
if (Object.values(parity).some((result) => !result.pass)) throw new Error('core packet limb parity failure');

function inputLeaves(input) {
  return Object.entries(input).flatMap(([name, value]) => Array.isArray(value)
    ? value.map((_, index) => `main.${name}[${index}]`)
    : [`main.${name}`]);
}
async function directInputIncidence() {
  const [sym, r1cs] = await Promise.all([
    readFile(symFile, 'utf8'), readR1cs(r1csFile, true, true, true),
  ]);
  const wanted = new Set(inputLeaves(actions.deposit));
  const symbols = new Map(sym.trim().split('\n').map((line) => {
    const [label, wire, component, name] = line.split(',');
    return [name, { label: Number(label), wire: Number(wire), component: Number(component) }];
  }).filter(([name]) => wanted.has(name)));
  const referenced = new Set();
  for (const constraint of r1cs.constraints) {
    for (const polynomial of constraint) for (const wire of Object.keys(polynomial)) referenced.add(Number(wire));
  }
  const missingSymbols = [...wanted].filter((name) => !symbols.has(name));
  const noConstraint = [...symbols.entries()].filter(([, symbol]) => !referenced.has(symbol.wire)).map(([name]) => name);
  // The compiler aliases postMaximumReserve to preMaximumReserve for the
  // equality constraint. Its direct wire consequently disappears after
  // simplification, but it remains independently SHA-packet-bound and the
  // mutation matrix verifies fixed public limbs reject its alteration.
  const packetBoundNoDirectConstraint = noConstraint.filter((name) => name === 'main.postMaximumReserve');
  const unconstrainedAndUnbound = noConstraint.filter((name) => !packetBoundNoDirectConstraint.includes(name));
  return {
    directInputLeaves: wanted.size,
    privateInputLeaves: wanted.size - 2,
    r1csPrivateInputs: r1cs.nPrvInputs,
    r1csPublicInputs: r1cs.nPubInputs,
    r1csConstraints: r1cs.nConstraints,
    publicOrder: ['main.publicDigestHi', 'main.publicDigestLo'],
    observedPublicWires: ['main.publicDigestHi', 'main.publicDigestLo'].map((name) => symbols.get(name)?.wire),
    missingSymbols,
    noDirectConstraint: noConstraint,
    packetBoundNoDirectConstraint,
    unconstrainedAndUnbound,
    pass: missingSymbols.length === 0 && unconstrainedAndUnbound.length === 0,
  };
}

const cases = [];
const mutateScalar = (action, family, field, value = undefined, rebind = false) => cases.push({
  name: `${action}.${field}`,
  action,
  family,
  expected: rebind ? 'accept-legitimate-alternative' : 'reject',
  mutate: (input) => { input[field] = value === undefined ? toggle(input[field]) : value; if (rebind) rebindDigest(input); },
});
const mutateArray = (action, family, field, index, rebind = false) => cases.push({
  name: `${action}.${field}[${index}]`,
  action,
  family,
  expected: rebind ? 'accept-legitimate-alternative' : 'reject',
  mutate: (input) => { input[field][index] = toggle(input[field][index]); if (rebind) rebindDigest(input); },
});

// Action one-hot, identifiers, complete state, counters/cap, and field bounds.
for (const field of ['isDeposit', 'isTransfer', 'isWithdrawal']) mutateScalar('deposit', 'action-one-hot', field);
for (const field of ['profileHi', 'profileLo', 'instanceHi', 'instanceLo']) mutateScalar('deposit', 'profile-instance', field);
for (const field of ['preNoteRoot', 'preNullifierRoot', 'preStateCommitment', 'postNoteRoot', 'postNullifierRoot', 'postStateCommitment']) mutateScalar('deposit', 'state-roots-commitments', field);
for (const field of ['preNextLeafIndex', 'postNextLeafIndex', 'preActionSequence', 'postActionSequence', 'preLiveNoteCount', 'postLiveNoteCount', 'preReserveSats', 'postReserveSats', 'preMaximumReserve', 'postMaximumReserve', 'maximumLiveNotes']) mutateScalar('deposit', 'counters-cap-denomination', field);
mutateScalar('deposit', 'u32-boundary', 'preNextLeafIndex', (1n << 32n).toString());
mutateScalar('deposit', 'u64-boundary', 'preReserveSats', (1n << 64n).toString());
mutateScalar('deposit', 'u128-boundary', 'profileHi', (1n << 128n).toString());

// Spend, membership, nullifier key/path, output, and inactive branches.
for (const field of ['inSk', 'inRho', 'inR', 'inputAk', 'inputCm', 'inputNf']) mutateScalar('transfer', 'spend-secret-ak-cm-nf', field);
mutateScalar('transfer', 'membership-index-path', 'noteIndex');
for (const index of [0, 15, 31]) mutateArray('transfer', 'membership-index-path', 'noteSiblings', index);
for (const index of [0, 63, 127]) mutateArray('transfer', 'nullifier-key-path', 'nullifierSiblings', index);
// The post-root is deliberately substituted as a pre-root: this is a known
// occupied-nullifier state. It must fail the empty-leaf precondition.
cases.push({ name: 'transfer.duplicate-nullifier-pre-root', action: 'transfer', family: 'nullifier-duplicate-collision', expected: 'reject', mutate: (input) => { input.preNullifierRoot = input.postNullifierRoot; } });
for (const field of ['outputAk', 'outputRho', 'outputR', 'outputCm']) mutateScalar('deposit', 'output-note', field);
for (const field of ['outputAk', 'outputRho', 'outputR', 'outputCm']) mutateScalar('withdrawal', 'inactive-output', field);
for (const field of ['inSk', 'inRho', 'inR', 'inputAk', 'inputCm', 'inputNf', 'noteIndex']) mutateScalar('deposit', 'inactive-spend', field);
for (const index of [0, 31]) mutateArray('deposit', 'inactive-spend-path', 'noteSiblings', index);
for (const index of [0, 127]) mutateArray('deposit', 'inactive-nullifier-path', 'nullifierSiblings', index);
for (const index of [0, 31]) mutateArray('withdrawal', 'inactive-append-path', 'appendSiblings', index);

// Packet-only fields. Fixed public limbs must reject; re-bound opaque values
// are legitimate alternative relation witnesses and are recorded as such.
mutateScalar('deposit', 'boundary-script', 'boundaryAmount');
for (const field of ['withdrawalScriptHi', 'withdrawalScriptLo']) mutateScalar('deposit', 'inactive-boundary-script', field);
mutateScalar('transfer', 'boundary-script', 'boundaryAmount');
for (const field of ['withdrawalScriptHi', 'withdrawalScriptLo']) mutateScalar('transfer', 'inactive-boundary-script', field);
for (const field of ['withdrawalScriptHi', 'withdrawalScriptLo']) mutateScalar('withdrawal', 'boundary-script', field);
for (const index of [0, 767, 1535]) mutateArray('deposit', 'record-bytes', 'recordBits', index);
for (const index of [0, 1535]) mutateArray('withdrawal', 'inactive-record-bytes', 'recordBits', index);
for (const field of ['transactionContextHi', 'transactionContextLo']) mutateScalar('transfer', 'transaction-context-digest', field);
for (const field of ['publicDigestHi', 'publicDigestLo']) mutateScalar('withdrawal', 'public-digest-limbs', field);
mutateArray('deposit', 'record-rebound-alternative', 'recordBits', 0, true);
mutateScalar('transfer', 'context-rebound-alternative', 'transactionContextHi', undefined, true);
mutateScalar('withdrawal', 'script-rebound-alternative', 'withdrawalScriptHi', undefined, true);

const temporary = await mkdtemp(path.join(tmpdir(), 'g1-audit-witness-'));
async function attempt(name, input) {
  const source = path.join(temporary, `${name}.json`);
  const witness = path.join(temporary, `${name}.wtns`);
  await writeFile(source, `${JSON.stringify(input)}\n`);
  try {
    await run(process.execPath, [witnessGenerator, wasm, source, witness], { maxBuffer: 1024 * 1024 });
    return 'accept';
  } catch {
    return 'reject';
  }
}

let results;
try {
  const valid = {};
  for (const [action, input] of Object.entries(actions)) valid[action] = await attempt(`valid-${action}`, input);
  results = [];
  for (const test of cases) {
    const input = clone(actions[test.action]);
    test.mutate(input);
    const observed = await attempt(test.name.replaceAll(/[^a-zA-Z0-9_.-]/g, '_'), input);
    const pass = test.expected === 'reject' ? observed === 'reject' : observed === 'accept';
    results.push({ name: test.name, action: test.action, family: test.family, expected: test.expected, observed, pass });
  }
  const incidence = await directInputIncidence();
  const summary = {
    schema: 'shield.cash/g1-relation-audit/v1',
    packetParity: parity,
    validWitnesses: valid,
    directInputIncidence: incidence,
    mutationCases: results,
    counts: {
      total: results.length,
      pass: results.filter((result) => result.pass).length,
      unexpectedAccepts: results.filter((result) => result.expected === 'reject' && result.observed === 'accept').length,
      unexpectedRejects: results.filter((result) => result.expected !== 'reject' && result.observed === 'reject').length,
    },
  };
  await writeFile(output, `${JSON.stringify(summary, null, 2)}\n`);
  if (Object.values(valid).some((observed) => observed !== 'accept')) throw new Error('valid core vector rejected');
  if (!incidence.pass || summary.counts.unexpectedAccepts || summary.counts.unexpectedRejects) throw new Error('constraint audit failure');
  console.log(JSON.stringify(summary.counts));
} finally {
  await rm(temporary, { recursive: true, force: true });
}
