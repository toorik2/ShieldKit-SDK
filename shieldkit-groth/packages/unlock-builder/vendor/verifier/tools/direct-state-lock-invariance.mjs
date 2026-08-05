import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const root = process.argv[2] || '/tmp/verifier-cash-direct-state-sweep-20260717';
const runsRoot = join(root, 'runs');
if (!existsSync(runsRoot)) throw new Error(`missing runs directory: ${runsRoot}`);

const sha256Hex = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const dirs = readdirSync(runsRoot, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && /^\d{3}-/.test(entry.name) && !/-gen$/.test(entry.name))
  .map((entry) => entry.name)
  .sort();
if (!dirs.length) throw new Error(`no candidate run directories under ${runsRoot}`);

const rows = dirs.map((name) => {
  const dir = join(runsRoot, name);
  const inputs = JSON.parse(readFileSync(join(dir, 'inputs_dump.json'), 'utf8'));
  const result = JSON.parse(readFileSync(join(dir, 'result.json'), 'utf8'));
  return { name, inputs, result };
});
const inputCount = rows[0].inputs.length;
if (!rows.every((row) => row.inputs.length === inputCount)) throw new Error('candidate input arity drift');

const lockHashes = Array.from({ length: inputCount }, (_, index) => [
  ...new Set(rows.map((row) => sha256Hex(row.inputs[index].lock))),
]);
const unlockUniqueCounts = Array.from({ length: inputCount }, (_, index) =>
  new Set(rows.map((row) => sha256Hex(row.inputs[index].unlock))).size,
);
const gateGreen = rows.every((row) => row.result.built === true
  && row.result.gateOk === true
  && row.result.manual?.length === inputCount
  && row.result.manual.every((step) => step.accepts === true && step.unlockLen < 10000));
const scores = rows.map((row) => row.result.score);
const output = {
  schema: 'verifier.cash/direct-state-lock-invariance/v1',
  root,
  rows: rows.length,
  inputCount,
  gateGreen,
  allLocksInvariant: lockHashes.every((hashes) => hashes.length === 1),
  lockUniquePerInput: lockHashes.map((hashes) => hashes.length),
  unlockUniqueCounts,
  scoreRange: { min: Math.min(...scores), max: Math.max(...scores) },
  lockHashes: lockHashes.map((hashes) => hashes[0]),
};
console.log(JSON.stringify(output, null, 2));
if (!gateGreen || !output.allLocksInvariant || unlockUniqueCounts.some((count) => count !== rows.length)) {
  process.exitCode = 1;
}
