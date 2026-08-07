// Compiler-only boundary measurement for the five-executor projected-state
// design. This is not a candidate builder: it measures the exact shared-body
// costs of (a) reading an authenticated terminal BQ slice and (b) producing a
// full final seam for the unchanged terminal verifier.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { compileIntratx } from '../../../../build/chunked/pairing/t1_lib.mjs';
import { genChunkGB } from '../../../../build/chunked/pairing/gen_miller_gb3_9k7.mjs';
import { projectedExecutorSource } from './measure-projected-state.mjs';

const requireSingleLine = (source, marker, label) => {
  const matches = source.split('\n').filter((line) => line.includes(marker));
  if (matches.length !== 1) throw new Error(`${label}: expected one ${marker}, got ${matches.length}`);
  return matches[0];
};

const optimize = (raw) => {
  const directory = mkdtempSync(join(tmpdir(), 'verifier-cash-projected-bq-shape-'));
  try {
    const input = join(directory, 'input.hex');
    const optimized = join(directory, 'optimized.hex');
    const canonical = join(directory, 'canonical.hex');
    const tool = process.env.C7_TOOL ?? 'tools/singleton-artifact';
    writeFileSync(input, Buffer.from(raw).toString('hex'));
    let result = spawnSync('node', [join(tool, 'optimize.mjs'), input, optimized], { encoding: 'utf8' });
    if (result.status !== 0) throw new Error(result.stderr || result.stdout || 'optimizer failed');
    result = spawnSync('node', [join(tool, 'minpush_canon.mjs'), optimized, canonical], { encoding: 'utf8' });
    if (result.status !== 0) throw new Error(result.stderr || result.stdout || 'minpush failed');
    return Buffer.from(readFileSync(canonical, 'utf8').trim(), 'hex');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

const measure = (source) => {
  const raw = compileIntratx(source);
  const optimized = optimize(raw);
  return { sourceBytes: Buffer.byteLength(source), rawBytes: raw.length, optimizedBytes: optimized.length };
};

const bqReadShape = [
  '        int bqAcc = 0;',
  '        bytes termHead, bytes termAfterHead = tx.inputs[6].unlockingBytecode.split(3);',
  '        require(termHead == 0x4d0804);',
  '        bytes termSeam, bytes termAfterSeam = termAfterHead.split(1032);',
  '        require(termSeam.length == 1032);',
  '        bytes bqHead, bytes termAfterBqHead = termAfterSeam.split(3);',
  '        require(bqHead == 0x4de00c);',
  '        bytes bqBlob, bytes bqTail = termAfterBqHead.split(3296);',
  '        require(bqBlob.length == 3296);',
  '        require(bqTail.length >= 0);',
  '        bytes bqSegment = bqBlob.split(2624)[1];',
  '        int bqCoefficient = int(bqSegment.split(640)[1].reverse());',
  '        bqAcc = (bqAcc * z + bqCoefficient) % P;',
  '        require(bqAcc >= 0);',
];

export const measureProjectedBqTopology = () => {
  if (process.env.KWIN !== '13') throw new Error('projected BQ shape requires KWIN=13');
  const projected = projectedExecutorSource({ lo: 1, hi: 14, genesisInputIndex: 5 });
  const projectedOut = requireSingleLine(projected, 'bytes outBlob =', 'projected source');
  const fullOut = requireSingleLine(genChunkGB(1, 14, { forward: true }), 'bytes outBlob =', 'full source')
    .replace('bytes outBlob =', 'bytes terminalBlob =');

  const withBq = projected.replace(projectedOut, [...bqReadShape, projectedOut].join('\n'));
  const withTerminalSeam = projected.replace(projectedOut, [
    projectedOut.replace('bytes outBlob =', 'bytes dynamicOut ='),
    '        if (this.activeInputIndex == 4) {',
    fullOut,
    '            require(terminalBlob.length == 1032);',
    '        }',
    '        bytes outBlob = dynamicOut;',
  ].join('\n'));
  const combined = projected.replace(projectedOut, [
    ...bqReadShape,
    projectedOut.replace('bytes outBlob =', 'bytes dynamicOut ='),
    '        if (this.activeInputIndex == 4) {',
    fullOut,
    '            require(terminalBlob.length == 1032);',
    '        }',
    '        bytes outBlob = dynamicOut;',
  ].join('\n'));

  const base = measure(projected);
  const bq = measure(withBq);
  const terminalSeam = measure(withTerminalSeam);
  const both = measure(combined);
  const delta = (row) => ({
    rawBytes: row.rawBytes - base.rawBytes,
    optimizedBytes: row.optimizedBytes - base.optimizedBytes,
  });
  return { base, bq, terminalSeam, both, delta: { bq: delta(bq), terminalSeam: delta(terminalSeam), both: delta(both) } };
};

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(measureProjectedBqTopology(), null, 2));
}
