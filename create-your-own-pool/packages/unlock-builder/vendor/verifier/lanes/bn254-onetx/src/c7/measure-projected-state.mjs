// Research-only compiler probe for a five-executor state projection. It does
// not assemble a transaction or emit a candidate. The projection keeps the
// complete evolving Miller state in each executor witness and reads immutable
// statement/VK context from a separately authenticated genesis blob.
const gb3 = await import(process.env.C7_ZBITS_GB3 ?? '../../../../build/chunked/pairing/gen_miller_gb3_9k7.mjs');
import { compileIntratx } from '../../../../build/chunked/pairing/t1_lib.mjs';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const FULL_STATE = [
  'gamma', 'z', 'blkidx', 'hInt', 'aggL', 'aggF', 'gp', 'fC',
  'nAx', 'nAy', 'vkxX', 'vkxY', 'Cx', 'Cy', 'Bxa', 'Bxb', 'Bya', 'Byb',
  'Rxa', 'Rxb', 'Rya', 'Ryb', 'Tgxa', 'Tgxb', 'Tgya', 'Tgyb',
  'Tdxa', 'Tdxb', 'Tdya', 'Tdyb', 'dotC', 'dotCi',
];
const CONTEXT = [
  'gamma', 'z', 'nAx', 'nAy', 'vkxX', 'vkxY', 'Cx', 'Cy',
  'Bxa', 'Bxb', 'Bya', 'Byb', 'dotC', 'dotCi',
];
const DYNAMIC = FULL_STATE.filter((name) => !CONTEXT.includes(name) && name !== 'blkidx');
const bytesOf = (name) => name === 'hInt' ? 40 : 32;
const balancedCat = (parts) => parts.length === 1 ? parts[0]
  : `(${balancedCat(parts.slice(0, Math.floor(parts.length / 2)))} + ${balancedCat(parts.slice(Math.floor(parts.length / 2)))})`;

export const projectedStateLayout = Object.freeze({
  context: CONTEXT,
  dynamic: DYNAMIC,
  contextBytes: CONTEXT.reduce((sum, name) => sum + bytesOf(name), 0),
  dynamicBytes: DYNAMIC.reduce((sum, name) => sum + bytesOf(name), 0),
});

export function projectedExecutorSource({ lo = 1, hi = 14, genesisInputIndex = 5 } = {}) {
  if (process.env.KWIN !== '13') throw new Error('projected-state probe requires KWIN=13');
  if (!Number.isInteger(lo) || !Number.isInteger(hi) || hi <= lo || hi - lo > 13) {
    throw new Error('projected-state probe requires a nonempty executor of at most thirteen steps');
  }
  if (process.env.DRIVER_WINDOW_DERIVED !== '1') throw new Error('projected-state probe requires derived windows');
  const source = gb3.genChunkGB(lo, hi, { forward: true });
  const lines = source.split('\n');
  const parseStart = lines.findIndex((line) => line.includes('bytes hh0, bytes r0 = inBlob.split('));
  const remIndex = lines.findIndex((line) => line.includes('bytes rem = r31;'));
  if (parseStart < 0 || remIndex < 0 || remIndex <= parseStart) throw new Error('projected-state probe could not locate full-state parser');

  const parser = [
    `        bytes contextPush, bytes contextRest = tx.inputs[${genesisInputIndex}].unlockingBytecode.split(3);`,
    '        require(contextPush == 0x4dc001);',
    `        bytes context, bytes contextTail = contextRest.split(${projectedStateLayout.contextBytes});`,
  ];
  let contextRest = 'context';
  CONTEXT.forEach((name, index) => {
    const next = `contextR${index}`;
    parser.push(`        bytes context_${name}, bytes ${next} = ${contextRest}.split(${bytesOf(name)}); int ${name} = int(context_${name});`);
    contextRest = next;
  });
  parser.push(`        require(${contextRest}.length == 0);`);
  // The enclosing genesis script has further arguments and its redeem push.
  // Keep the split tail live solely because cashc rejects unused tuple values.
  parser.push('        require(contextTail.length >= 0);');
  let dynamicRest = 'inBlob';
  DYNAMIC.forEach((name, index) => {
    const next = `dynamicR${index}`;
    parser.push(`        bytes dynamic_${name}, bytes ${next} = ${dynamicRest}.split(${bytesOf(name)}); int ${name} = int(dynamic_${name});`);
    dynamicRest = next;
  });
  parser.push(`        int blkidx = this.activeInputIndex * 13 + 3;`);
  parser.push(`        bytes rem = ${dynamicRest};`);
  lines.splice(parseStart, remIndex - parseStart + 1, ...parser);

  const outIndex = lines.findIndex((line) => line.includes('bytes outBlob ='));
  if (outIndex < 0) throw new Error('projected-state probe could not locate full-state serializer');
  const output = DYNAMIC.map((name) => name === 'hInt'
    ? `toPaddedBytes(hOut, ${bytesOf(name)})`
    : `toPaddedBytes(${name} % P, ${bytesOf(name)})`);
  lines[outIndex] = `        bytes outBlob = ${balancedCat(output)};`;

  const fullStateMarker = String(gb3.STATE_BYTES);
  return lines.join('\n')
    .replaceAll(`.split(${fullStateMarker})`, `.split(${projectedStateLayout.dynamicBytes})`)
    .replaceAll(`outBlob.length == ${fullStateMarker}`, `outBlob.length == ${projectedStateLayout.dynamicBytes}`);
}

const foldAndCanonicalize = (raw) => {
  const directory = mkdtempSync(join(tmpdir(), 'verifier-cash-projected-state-'));
  try {
    const input = join(directory, 'input.hex');
    const folded = join(directory, 'folded.hex');
    const canonical = join(directory, 'canonical.hex');
    const tool = process.env.C7_TOOL ?? 'tools/singleton-artifact';
    writeFileSync(input, Buffer.from(raw).toString('hex'));
    let result = spawnSync('node', [join(tool, 'optimize.mjs'), input, folded], { encoding: 'utf8' });
    if (result.status !== 0) throw new Error(result.stderr || result.stdout || 'projected-state optimize failed');
    result = spawnSync('node', [join(tool, 'minpush_canon.mjs'), folded, canonical], { encoding: 'utf8' });
    if (result.status !== 0) throw new Error(result.stderr || result.stdout || 'projected-state canonicalization failed');
    return Buffer.from(readFileSync(canonical, 'utf8').trim(), 'hex');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

if (import.meta.url === `file://${process.argv[1]}`) {
  const source = projectedExecutorSource();
  const bytecode = compileIntratx(source);
  const optimized = foldAndCanonicalize(bytecode);
  console.log(JSON.stringify({
    fullStateBytes: gb3.STATE_BYTES,
    ...projectedStateLayout,
    sourceBytes: Buffer.byteLength(source),
    rawBytecodeBytes: bytecode.length,
    optimizedBytecodeBytes: optimized.length,
  }, null, 2));
}
