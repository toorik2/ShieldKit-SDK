// Static fixed-G2 executor specialization for the K=13 research topology.
//
// Unlike the earlier storage probe, this module consumes every table limb in
// the actual Miller accumulator: each record supplies the gamma and delta
// line coefficients that would otherwise be derived from the carried affine
// T_gamma/T_delta coordinates and witnessed slopes.  The complete window is
// hash-bound before parsing.  It is deliberately not wired into a candidate
// profile until its source-lock carrier and complete terminal are both real.
import { createHash } from 'node:crypto';
import {
  COMPACT_LINE_PAIR_BYTES,
  FP_BYTES,
  LINE_PAIR_BYTES,
  assertCompactFixedLineTable,
  assertFixedLineTable,
  assertNormalizedFixedAddTable,
  compactFixedLineWindow,
  fixedLineWindow,
  normalizedFixedLineWindow,
} from './fixed-g2-lines.mjs';
import { assertXOnlyFixedLineTable, xOnlyFixedLineWindow } from './fixed-g2-xonly-lines.mjs';

const base = await import(process.env.C7_ZBITS_GB3 ?? '../../../../build/chunked/pairing/gen_miller_gb3_9k7.mjs');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const COMPACT_FIXED_LINES = process.env.C7_FIXED_G2_COMPACT === '1';
const NORMALIZED_FIXED_ADDS = process.env.C7_FIXED_G2_NORMALIZED_ADDS === '1';
const XONLY_FIXED_G2 = process.env.C7_FIXED_G2_XONLY === '1';
// A standard P2SH executor cannot introspect a table embedded in its old
// direct locking program: its UTXO bytecode is only the 35-byte hash template.
// This opt-in carrier moves the *authenticated, consumed* table to inBlob.
// It is intentionally separate from the legacy partial witness split.
const ALL_TABLE_WITNESS = process.env.C7_FIXED_G2_ALL_TABLE_WITNESS === '1';
if (NORMALIZED_FIXED_ADDS && !COMPACT_FIXED_LINES) throw new Error('normalized fixed-G2 additions require compact fixed lines');
if (XONLY_FIXED_G2 && (!COMPACT_FIXED_LINES || !NORMALIZED_FIXED_ADDS)) {
  throw new Error('x/slope fixed-G2 transport requires compact doubles and normalized additions');
}
const FIXED_DOUBLE_PAIR_BYTES = XONLY_FIXED_G2 ? 4 * FP_BYTES : (COMPACT_FIXED_LINES ? COMPACT_LINE_PAIR_BYTES : LINE_PAIR_BYTES);
const FIXED_ADD_PAIR_BYTES = NORMALIZED_FIXED_ADDS ? 4 * FP_BYTES : FIXED_DOUBLE_PAIR_BYTES;
const C3BA = '14681138511599513868579906292550611339979233093309515871315818100066920017953';
const C3BB = '800789373359973483740722161411851527635230895998700865708135532730922910070';
const INV4 = ((P + 1n) / 4n).toString();

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
const STATIC_G2 = ['Tgxa', 'Tgxb', 'Tgya', 'Tgyb', 'Tdxa', 'Tdxb', 'Tdya', 'Tdyb'];
const DYNAMIC = FULL_STATE.filter((name) => !CONTEXT.includes(name) && name !== 'blkidx' && !STATIC_G2.includes(name));
const bytesOf = (name) => name === 'hInt' ? 40 : 32;
const cat = (...parts) => {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const fieldBytes = (value, width, raw = false) => {
  let current = raw ? BigInt(value) : ((BigInt(value) % P) + P) % P;
  const out = new Uint8Array(width);
  for (let i = 0; i < width; i++) { out[i] = Number(current & 0xffn); current >>= 8n; }
  return out;
};
const balancedCat = (parts) => parts.length === 1 ? parts[0]
  : `(${balancedCat(parts.slice(0, Math.floor(parts.length / 2)))} + ${balancedCat(parts.slice(Math.floor(parts.length / 2)))})`;
const valuesAt = (step) => Object.fromEntries(base.SGB.map((name, index) => [name, BigInt(base.stateVal(step)[index])]));
const dynamicBytesAt = (step) => {
  const values = valuesAt(step);
  return cat(...DYNAMIC.map((name) => fieldBytes(values[name], bytesOf(name), name === 'hInt')));
};
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha256d = (bytes) => {
  const once = createHash('sha256').update(bytes).digest();
  return Uint8Array.from(createHash('sha256').update(once).digest());
};
const pushPrefix = (length) => {
  if (!Number.isInteger(length) || length < 0 || length > 0xffff) throw new Error(`invalid fixed-G2 table length ${length}`);
  if (length <= 75) return Uint8Array.of(length);
  if (length <= 0xff) return Uint8Array.of(0x4c, length);
  return Uint8Array.of(0x4d, length & 0xff, length >>> 8);
};

// The striped topology invokes one authenticated, shared executor body from
// every one of its five source locks.  A body specialized to table zero would
// (correctly) reject the other four carriers before the Miller loop.  Keep the
// *code* shared, but select the exact source-lock envelope from the already
// topology-bound active input index.  This is deliberately an allow-list, not
// a default/fallback: a sixth input cannot reuse a valid table-0 envelope.
// PairFold-7 mixed ranges (must match MIXED_EXECUTOR_RANGES_7 / XONLY_WINDOWS_PF7).
const SHARED_WINDOWS_PF7 = Object.freeze([[1, 14], [14, 26], [26, 38], [38, 50], [50, 64]]);
// PairFold-6 pure-pair ranges (must match MIXED_EXECUTOR_RANGES_6).
const SHARED_WINDOWS_PF6 = Object.freeze([[2, 16], [16, 32], [32, 48], [48, 64]]);
// dens-rich PF6 (scalar): genHi=1 mixed head (must match MIXED_EXECUTOR_RANGES_6_DENSE).
const SHARED_WINDOWS_PF6_DENSE = Object.freeze([[1, 16], [16, 32], [32, 48], [48, 64]]);
const SHARED_WINDOWS_K13 = Object.freeze([[1, 14], [14, 27], [27, 40], [40, 53], [53, 64]]);
const _topo = process.env.C7_PAIRFOLD_TOPOLOGY ?? '7';
const SHARED_WINDOWS = Object.freeze(
  (process.env.C7_COMPOSED_P2SH === '1' && _topo === '7')
    ? [...SHARED_WINDOWS_PF7]
    : (process.env.C7_COMPOSED_P2SH === '1' && _topo === '6')
      ? (process.env.C7_SCALAR_ENDPOINT === '1' ? [...SHARED_WINDOWS_PF6_DENSE] : [...SHARED_WINDOWS_PF6])
      : [...SHARED_WINDOWS_K13],
);
// A table record may live in either the source lock or the corresponding
// executor witness, but it must exist exactly once.  The witness suffix is
// appended after the ordinary per-step witness data and concatenated with the
// source prefix before a single full-table digest check.  These are not density
// pads: every byte becomes a gamma/delta line coefficient consumed by stepU.
const defaultWitnessTableBytes = [0, 1536, 1536, 1536, 2304];
const requestedWitnessTableBytes = process.env.C7_FIXED_G2_WITNESS_TABLE_BYTES;
const parseWitnessTableBytes = (raw) => {
  if (raw === undefined) return defaultWitnessTableBytes;
  const parsed = raw.split(',').map((value) => Number(value));
  if ((parsed.length !== 4 && parsed.length !== 5 && parsed.length !== 6 && parsed.length !== SHARED_WINDOWS.length)
    || parsed.some((value) => !Number.isInteger(value) || value < 0)) {
    throw new Error('C7_FIXED_G2_WITNESS_TABLE_BYTES must specify 4–6 non-negative integer byte counts');
  }
  return parsed;
};
const WITNESS_TABLE_BYTES = process.env.C7_FIXED_G2_UNLOCK_TABLE === '1'
  ? Object.freeze(parseWitnessTableBytes(requestedWitnessTableBytes))
  : Object.freeze([0, 0, 0, 0, 0]);
const windowIndex = (lo, hi) => SHARED_WINDOWS.findIndex(([a, b]) => a === lo && b === hi);
const tableCarrier = (lo, hi) => {
  const table = XONLY_FIXED_G2
    ? xOnlyFixedLineWindow(lo, hi)
    : (NORMALIZED_FIXED_ADDS ? normalizedFixedLineWindow(lo, hi) : (COMPACT_FIXED_LINES ? compactFixedLineWindow(lo, hi) : fixedLineWindow(lo, hi)));
  const index = windowIndex(lo, hi);
  if (index < 0) throw new Error(`fixed-G2 table is outside the five-executor topology: [${lo}, ${hi})`);
  let witnessBytes = ALL_TABLE_WITNESS ? table.bytes.length : WITNESS_TABLE_BYTES[index];
  // dens-rich/xonly: clamp legacy witness alloc to actual table mass
  if (Number.isInteger(witnessBytes) && witnessBytes > table.bytes.length) witnessBytes = table.bytes.length;
  if (!Number.isInteger(witnessBytes) || witnessBytes < 0 || witnessBytes > table.bytes.length) {
    throw new Error(`invalid fixed-G2 witness-table allocation for [${lo}, ${hi}): ${witnessBytes}`);
  }
  return { ...table, witnessBytes, sourceBytes: table.bytes.slice(0, table.bytes.length - witnessBytes) };
};
const tableEnvelopeParser = (table, shared) => {
  if (ALL_TABLE_WITNESS) {
    const tables = shared ? SHARED_WINDOWS.map(([lo, hi]) => tableCarrier(lo, hi)) : [table];
    return {
      lines: [
        '        int fixedTableIndex = this.activeInputIndex;',
        `        require(fixedTableIndex >= 0 && fixedTableIndex < ${tables.length});`,
        `        int fixedLineWitnessBytes = ${tables[0].bytes.length};`,
        ...tables.slice(1).map((entry, index) => `        if (fixedTableIndex == ${index + 1}) { fixedLineWitnessBytes = ${entry.bytes.length}; }`),
      ],
      hashGuards: tables.map((entry, index) => `        if (fixedTableIndex == ${index}) { require(hash256(fixedLines) == 0x${hex(sha256d(entry.bytes))}); }`),
      fixedLinesExpr: 'fixedLineWitness',
    };
  }
  if (!shared) return {
    lines: [
      `        int fixedLineWitnessBytes = ${table.witnessBytes};`,
      `        bytes tablePush, bytes afterTablePush = tx.inputs[this.activeInputIndex].lockingBytecode.split(${pushPrefix(table.sourceBytes.length).length});`,
      `        require(tablePush == 0x${hex(pushPrefix(table.sourceBytes.length))});`,
      `        bytes sourceFixedLines, bytes afterFixedLines = afterTablePush.split(${table.sourceBytes.length});`,
      '        bytes tableDrop, bytes sourceBody = afterFixedLines.split(1);',
      '        require(tableDrop == 0x75); require(sourceBody.length > 0);',
    ],
    hashGuards: [`        require(hash256(fixedLines) == 0x${hex(sha256d(table.bytes))});`],
    fixedLinesExpr: 'sourceFixedLines + fixedLineWitness',
  };

  const tables = SHARED_WINDOWS.map(([lo, hi]) => tableCarrier(lo, hi));
  const allSourceEmpty = tables.every((entry) => entry.sourceBytes.length === 0);
  return {
    lines: [
    '        int fixedTableIndex = this.activeInputIndex;',
    `        require(fixedTableIndex >= 0 && fixedTableIndex < ${tables.length});`,
    `        int fixedSourceBytes = ${tables[0].sourceBytes.length};`,
    `        int fixedLineWitnessBytes = ${tables[0].witnessBytes};`,
    ...tables.slice(1).flatMap((entry, index) => [
      `        if (fixedTableIndex == ${index + 1}) { fixedSourceBytes = ${entry.sourceBytes.length}; }`,
      `        if (fixedTableIndex == ${index + 1}) { fixedLineWitnessBytes = ${entry.witnessBytes}; }`,
    ]),
    `        bytes tablePush, bytes afterTablePush = tx.inputs[this.activeInputIndex].lockingBytecode.split(${allSourceEmpty ? 1 : 3});`,
    ...tables.map((entry, index) => `        if (fixedTableIndex == ${index}) { require(tablePush == 0x${hex(pushPrefix(entry.sourceBytes.length))}); }`),
    '        bytes sourceFixedLines, bytes afterFixedLines = afterTablePush.split(fixedSourceBytes);',
    '        bytes tableDrop, bytes sourceBody = afterFixedLines.split(1);',
    '        require(tableDrop == 0x75); require(sourceBody.length > 0);',
    ],
    hashGuards: tables.map((entry, index) => `        if (fixedTableIndex == ${index}) { require(hash256(fixedLines) == 0x${hex(sha256d(entry.bytes))}); }`),
    fixedLinesExpr: 'sourceFixedLines + fixedLineWitness',
  };
};

export const staticStateLayout = Object.freeze({
  context: CONTEXT,
  dynamic: DYNAMIC,
  contextBytes: CONTEXT.reduce((sum, name) => sum + bytesOf(name), 0),
  dynamicBytes: DYNAMIC.reduce((sum, name) => sum + bytesOf(name), 0),
  removedState: STATIC_G2,
});

const requireMarker = (source, marker, label) => {
  const index = source.indexOf(marker);
  if (index < 0) throw new Error(`fixed-G2 static executor could not locate ${label}`);
  return index;
};

const lineParser = (root, names, prefix) => {
  const lines = [];
  let rest = root;
  names.forEach((name, index) => {
    const next = `${prefix}r${index}`;
    lines.push(`    bytes ${name}Bytes, bytes ${next} = ${rest}.split(${FP_BYTES}); int ${name} = int(${name}Bytes);`);
    rest = next;
  });
  return { lines, rest };
};

const compactDoubleC0 = (prefix) => [
  `(int ${prefix}sq0,int ${prefix}sq1) = fp2Sqr(${prefix}4,${prefix}5);`,
  `int ${prefix}0 = subFp(${C3BA}, mulFp(${prefix}sq0, ${INV4}), 1);`,
  `int ${prefix}1 = subFp(${C3BB}, mulFp(${prefix}sq1, ${INV4}), 1);`,
];
const compactAddC0 = (prefix, qx0, qx1, qy0, qy1) => [
  `(int ${prefix}x0,int ${prefix}x1) = fp2Mul(${prefix}2,${prefix}3, ${qx0},${qx1});`,
  `(int ${prefix}y0,int ${prefix}y1) = fp2Mul(${prefix}4,${prefix}5, ${qy0},${qy1});`,
  `(int ${prefix}s0,int ${prefix}s1) = fp2Add(${prefix}x0,${prefix}x1, ${prefix}y0,${prefix}y1);`,
  `(int ${prefix}0,int ${prefix}1) = fp2Neg(${prefix}s0,${prefix}s1,1);`,
];
const normalizedAddC0 = (prefix, qx0, qx1, qy0, qy1) => [
  `(int ${prefix}x0,int ${prefix}x1) = fp2Mul(${prefix}2,${prefix}3, ${qx0},${qx1});`,
  `(int ${prefix}s0,int ${prefix}s1) = fp2Add(${prefix}x0,${prefix}x1, ${qy0},${qy1});`,
  `(int ${prefix}0,int ${prefix}1) = fp2Neg(${prefix}s0,${prefix}s1,1);`,
  `int ${prefix}4 = 1; int ${prefix}5 = 0;`,
];

const xOnlyDouble = (prefix, next, x0, x1, m0, m1) => [
  `(int ${prefix}x2a,int ${prefix}x2b) = fp2Sqr(${x0},${x1});`,
  `(int ${prefix}m2a,int ${prefix}m2b) = fp2Sqr(${m0},${m1});`,
  `(int ${prefix}x4a,int ${prefix}x4b) = fp2Sqr(${prefix}x2a,${prefix}x2b);`,
  `(int ${prefix}bma,int ${prefix}bmb) = fp2MulByB(${prefix}m2a,${prefix}m2b);`,
  `(int ${prefix}b12a,int ${prefix}b12b) = fp2Scale(${prefix}bma,${prefix}bmb,12);`,
  `(int ${prefix}x9a,int ${prefix}x9b) = fp2Scale(${prefix}x4a,${prefix}x4b,9);`,
  `(int ${prefix}0,int ${prefix}1) = fp2Sub(${prefix}b12a,${prefix}b12b,${prefix}x9a,${prefix}x9b,2);`,
  `(int ${prefix}m2x2a,int ${prefix}m2x2b) = fp2Mul(${prefix}m2a,${prefix}m2b,${prefix}x2a,${prefix}x2b);`,
  `(int ${prefix}2,int ${prefix}3) = fp2Scale(${prefix}m2x2a,${prefix}m2x2b,12);`,
  `(int ${prefix}mx2a,int ${prefix}mx2b) = fp2Mul(${m0},${m1},${prefix}x2a,${prefix}x2b);`,
  `(int ${prefix}4,int ${prefix}5) = fp2Scale(${prefix}mx2a,${prefix}mx2b,12);`,
  `(int ${prefix}twoXa,int ${prefix}twoXb) = fp2Add(${x0},${x1},${x0},${x1});`,
  `(int ${next}0,int ${next}1) = fp2Sub(${prefix}m2a,${prefix}m2b,${prefix}twoXa,${prefix}twoXb,2);`,
];
const xOnlyAddNext = (next, m0, m1, qx0, qx1) => [
  `(int ${next}m2a,int ${next}m2b) = fp2Sqr(${m0},${m1});`,
  `(int ${next}ta,int ${next}tb) = fp2Sub(${next}m2a,${next}m2b,${next}0,${next}1,2);`,
  `(${next}0,${next}1) = fp2Sub(${next}ta,${next}tb,${qx0},${qx1},2);`,
];

const xOnlyStepSource = () => {
  const shared = base.SHARED;
  const stepAt = requireMarker(shared, 'function stepU(', 'dynamic stepU');
  const dynamicStep = shared.slice(stepAt);
  const wdatAt = requireMarker(dynamicStep, '    bytes wdatc = wdat;', 'dynamic witness parser');
  const fnAt = requireMarker(dynamicStep, '    int fn = ', 'line-fold start');
  const pfAt = requireMarker(dynamicStep, '    int pf = 1;', 'accumulator start');
  const addAt = dynamicStep.indexOf('    if (mode >= 1) {', pfAt);
  const tailAt = requireMarker(dynamicStep, '    // The remainder operator retains a negative dividend', 'accumulator tail');
  if (addAt < 0 || !(wdatAt < fnAt && fnAt < pfAt && pfAt < addAt && addAt < tailAt)) {
    throw new Error('x/slope fixed-G2 executor found an unexpected dynamic step shape');
  }
  const wdatParser = dynamicStep.slice(wdatAt, fnAt);
  const lineAndTranscript = dynamicStep.slice(fnAt, pfAt);
  const addBlock = dynamicStep.slice(addAt, tailAt);
  const pair0AddStart = requireMarker(addBlock, '        int qy0a', 'pair0 add prelude');
  const fixedAddStart = requireMarker(addBlock, '        (int bb0', 'fixed-G2 add update');
  const pair0Add = addBlock.slice(pair0AddStart, fixedAddStart);
  const gammaQ = addBlock.match(/affAddT\(G0,G1,G2,G3,\s*([^,]+),\s*([^,]+),gqya,gqyb,/);
  const deltaQ = addBlock.match(/affAddT\(D0,D1,D2,D3,\s*([^,]+),\s*([^,]+),dqya,dqyb,/);
  if (!gammaQ || !deltaQ) throw new Error('x/slope fixed-G2 executor could not locate fixed addend literals');
  const dbl = lineParser('fixedLines', ['gm0', 'gm1', 'dm0', 'dm1'], 'd');
  const add = lineParser(dbl.rest, ['bb2', 'bb3', 'uu2', 'uu3'], 'a');
  const compactAdds = [
    ...normalizedAddC0('bb', gammaQ[1].trim(), gammaQ[2].trim(), 'gqya', 'gqyb'),
    ...normalizedAddC0('uu', deltaQ[1].trim(), deltaQ[2].trim(), 'dqya', 'dqyb'),
  ];
  return [
    'function stepU(int aggL,int aggF,int gp,int fC, bytes h, int gamma, int blkidx, int dotC,int dotCi,',
    '        int rxa,int rxb,int rya,int ryb,',
    '        int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3, int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,',
    '        int ec0,int ec1,int ec2,int ec3,int ec4,int ec5,int ec6,int ec7,int ec8,int ec9,int ec10,int ec11, int ex4,int ex5, int mode, bytes wdat, bytes fixedLines, int gx0,int gx1,int dx0,int dx1)',
    '    returns (int,int,int,int, bytes, int,int,int,int, int,int,int,int) {',
    `    int Pm = ${P};`,
    '    require(mode <= 2);',
    wdatParser.trimEnd(),
    lineAndTranscript.trimEnd(),
    '    int pf = 1; if (mode == 1) { pf = dotC; } if (mode == 2) { pf = dotCi; }',
    '    (int a0,int a1,int a2,int a3,int a4,int a5, int R0,int R1,int R2,int R3) = affDbl(rxa,rxb,rya,ryb,sda,sdb);',
    '    pf = fold1(Pm, pf, a0,a1,a2,a3,a4,a5, kn0,kn1,kn2,kn3, ex4,ex5);',
    ...dbl.lines,
    ...xOnlyDouble('b', 'ngx', 'gx0', 'gx1', 'gm0', 'gm1'),
    ...xOnlyDouble('uo', 'ndx', 'dx0', 'dx1', 'dm0', 'dm1'),
    '    pf = fold1(Pm, pf, b0,b1,b2,b3,b4,b5, kv0,kv1,kv2,kv3, ex4,ex5);',
    '    pf = fold1(Pm, pf, uo0,uo1,uo2,uo3,uo4,uo5, kc0,kc1,kc2,kc3, ex4,ex5);',
    '    int xCarry = 1; if (blkidx == 15 || blkidx == 28 || blkidx == 41 || blkidx == 54 || blkidx == 65) { xCarry = 0; }',
    '    if (mode >= 1) {',
    pair0Add.trimEnd(),
    ...add.lines,
    ...compactAdds,
    '        pf = fold1(Pm, pf, bb0,bb1,bb2,bb3,bb4,bb5, kv0,kv1,kv2,kv3, ex4,ex5);',
    '        pf = fold1(Pm, pf, uu0,uu1,uu2,uu3,uu4,uu5, kc0,kc1,kc2,kc3, ex4,ex5);',
    '        if (xCarry == 1) {',
    ...xOnlyAddNext('ngx', 'bb2', 'bb3', gammaQ[1].trim(), gammaQ[2].trim()),
    ...xOnlyAddNext('ndx', 'uu2', 'uu3', deltaQ[1].trim(), deltaQ[2].trim()),
    '        }',
    `        require(${add.rest}.length == 0);`,
    '    }',
    `    if (mode == 0) { require(${dbl.rest}.length == 0); }`,
    '    pf = (pf + Pm) % Pm;',
    '    fn = (fn + Pm) % Pm;',
    '    int t_l = (((fC*fC) % Pm) * pf) % Pm;',
    '    int nAggL = (aggL + Pm + (gp * t_l) % Pm) % Pm;',
    '    int nAggF = (aggF + Pm + (gp * fn) % Pm) % Pm;',
    '    int nG = (gp * gamma) % Pm;',
    '    bytes nh = hash256(h + toPaddedBytes(blkidx,4).reverse() + 0x00000180 + foutblk);',
    '    return nAggL, nAggF, nG, fn, nh, R0,R1,R2,R3, ngx0,ngx1,ndx0,ndx1; }',
  ].join('\n');
};

const staticStepSource = () => {
  if (XONLY_FIXED_G2) return xOnlyStepSource();
  const shared = base.SHARED;
  const stepAt = requireMarker(shared, 'function stepU(', 'dynamic stepU');
  const dynamicStep = shared.slice(stepAt);
  const wdatAt = requireMarker(dynamicStep, '    bytes wdatc = wdat;', 'dynamic witness parser');
  const fnAt = requireMarker(dynamicStep, '    int fn = ', 'line-fold start');
  const pfAt = requireMarker(dynamicStep, '    int pf = 1;', 'accumulator start');
  const addAt = dynamicStep.indexOf('    if (mode >= 1) {', pfAt);
  const tailAt = requireMarker(dynamicStep, '    // The remainder operator retains a negative dividend', 'accumulator tail');
  if (addAt < 0 || !(wdatAt < fnAt && fnAt < pfAt && pfAt < addAt && addAt < tailAt)) {
    throw new Error('fixed-G2 static executor found an unexpected dynamic step shape');
  }
  const wdatParser = dynamicStep.slice(wdatAt, fnAt);
  const lineAndTranscript = dynamicStep.slice(fnAt, pfAt);
  const addBlock = dynamicStep.slice(addAt, tailAt);
  const pair0AddStart = requireMarker(addBlock, '        int qy0a', 'pair0 add prelude');
  const fixedAddStart = requireMarker(addBlock, '        (int bb0', 'fixed-G2 add update');
  const pair0Add = addBlock.slice(pair0AddStart, fixedAddStart);
  const gammaQ = addBlock.match(/affAddT\(G0,G1,G2,G3,\s*([^,]+),\s*([^,]+),gqya,gqyb,/);
  const deltaQ = addBlock.match(/affAddT\(D0,D1,D2,D3,\s*([^,]+),\s*([^,]+),dqya,dqyb,/);
  if (!gammaQ || !deltaQ) throw new Error('fixed-G2 static executor could not locate fixed addend literals');
  const dbl = lineParser('fixedLines', COMPACT_FIXED_LINES
    ? ['b2', 'b3', 'b4', 'b5', 'uo2', 'uo3', 'uo4', 'uo5']
    : ['b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'uo0', 'uo1', 'uo2', 'uo3', 'uo4', 'uo5'], 'd');
  const add = lineParser(dbl.rest, NORMALIZED_FIXED_ADDS
    ? ['bb2', 'bb3', 'uu2', 'uu3']
    : (COMPACT_FIXED_LINES
      ? ['bb2', 'bb3', 'bb4', 'bb5', 'uu2', 'uu3', 'uu4', 'uu5']
      : ['bb0', 'bb1', 'bb2', 'bb3', 'bb4', 'bb5', 'uu0', 'uu1', 'uu2', 'uu3', 'uu4', 'uu5']), 'a');
  const compactDoubles = COMPACT_FIXED_LINES ? [
    ...compactDoubleC0('b'),
    ...compactDoubleC0('uo'),
  ] : [];
  const compactAdds = NORMALIZED_FIXED_ADDS ? [
    ...normalizedAddC0('bb', gammaQ[1].trim(), gammaQ[2].trim(), 'gqya', 'gqyb'),
    ...normalizedAddC0('uu', deltaQ[1].trim(), deltaQ[2].trim(), 'dqya', 'dqyb'),
  ] : (COMPACT_FIXED_LINES ? [
    ...compactAddC0('bb', gammaQ[1].trim(), gammaQ[2].trim(), 'gqya', 'gqyb'),
    ...compactAddC0('uu', deltaQ[1].trim(), deltaQ[2].trim(), 'dqya', 'dqyb'),
  ] : []);
  return [
    'function stepU(int aggL,int aggF,int gp,int fC, bytes h, int gamma, int blkidx, int dotC,int dotCi,',
    '        int rxa,int rxb,int rya,int ryb,',
    '        int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3, int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,',
    '        int ec0,int ec1,int ec2,int ec3,int ec4,int ec5,int ec6,int ec7,int ec8,int ec9,int ec10,int ec11, int ex4,int ex5, int mode, bytes wdat, bytes fixedLines)',
    '    returns (int,int,int,int, bytes, int,int,int,int) {',
    `    int Pm = ${P};`,
    '    require(mode <= 2);',
    wdatParser.trimEnd(),
    lineAndTranscript.trimEnd(),
    '    int pf = 1; if (mode == 1) { pf = dotC; } if (mode == 2) { pf = dotCi; }',
    '    (int a0,int a1,int a2,int a3,int a4,int a5, int R0,int R1,int R2,int R3) = affDbl(rxa,rxb,rya,ryb,sda,sdb);',
    '    pf = fold1(Pm, pf, a0,a1,a2,a3,a4,a5, kn0,kn1,kn2,kn3, ex4,ex5);',
    ...dbl.lines,
    ...compactDoubles,
    '    pf = fold1(Pm, pf, b0,b1,b2,b3,b4,b5, kv0,kv1,kv2,kv3, ex4,ex5);',
    '    pf = fold1(Pm, pf, uo0,uo1,uo2,uo3,uo4,uo5, kc0,kc1,kc2,kc3, ex4,ex5);',
    '    if (mode >= 1) {',
    pair0Add.trimEnd(),
    ...add.lines,
    ...compactAdds,
    '        pf = fold1(Pm, pf, bb0,bb1,bb2,bb3,bb4,bb5, kv0,kv1,kv2,kv3, ex4,ex5);',
    '        pf = fold1(Pm, pf, uu0,uu1,uu2,uu3,uu4,uu5, kc0,kc1,kc2,kc3, ex4,ex5);',
    `        require(${add.rest}.length == 0);`,
    '    }',
    `    if (mode == 0) { require(${dbl.rest}.length == 0); }`,
    '    // The table contains coefficients, never stale affine state.  The only',
    '    // forwarded point is the runtime proof point R used by the terminal fold.',
    '    pf = (pf + Pm) % Pm;',
    '    fn = (fn + Pm) % Pm;',
    '    int t_l = (((fC*fC) % Pm) * pf) % Pm;',
    '    int nAggL = (aggL + Pm + (gp * t_l) % Pm) % Pm;',
    '    int nAggF = (aggF + Pm + (gp * fn) % Pm) % Pm;',
    '    int nG = (gp * gamma) % Pm;',
    '    bytes nh = hash256(h + toPaddedBytes(blkidx,4).reverse() + 0x00000180 + foutblk);',
    '    return nAggL, nAggF, nG, fn, nh, R0,R1,R2,R3; }',
  ].join('\n');
};

export const STATIC_SHARED = (() => {
  const shared = base.SHARED;
  const fixedAt = requireMarker(shared, 'function affDblT(', 'fixed affine helper');
  const foldAt = requireMarker(shared, 'function fold1(', 'fold helper');
  const stepAt = requireMarker(shared, 'function stepU(', 'dynamic step helper');
  if (!(fixedAt < foldAt && foldAt < stepAt)) throw new Error('fixed-G2 static executor shared-library order changed');
  return shared.slice(0, fixedAt) + shared.slice(foldAt, stepAt) + staticStepSource();
})();

const replaceLine = (source, oldLine, nextLines, label) => {
  const at = source.indexOf(oldLine);
  if (at < 0) throw new Error(`fixed-G2 static executor could not locate ${label}`);
  return source.slice(0, at) + nextLines.join('\n') + source.slice(at + oldLine.length);
};

const rewriteStepRecordParsers = (source, lo, hi) => {
  let rewritten = source;
  if (XONLY_FIXED_G2) {
    const oldDest = '(aggL,aggF,gp,fC, h, Rxa,Rxb,Rya,Ryb, Tgxa,Tgxb,Tgya,Tgyb, Tdxa,Tdxb,Tdya,Tdyb) = stepU(';
    const newDest = '(aggL,aggF,gp,fC, h, Rxa,Rxb,Rya,Ryb, gx0,gx1,dx0,dx1, Tgxa,Tgxb,Tgya,Tgyb, Tdxa,Tdxb,Tdya,Tdyb) = stepU(';
    if (!rewritten.includes(oldDest)) throw new Error('x/slope fixed-G2 executor could not locate step destinations');
    rewritten = rewritten.replaceAll(oldDest, newDest);
  }
  for (let s = 0; s < hi - lo; s++) {
    const cdat = `        bytes cdatTail${s}, bytes afterCdat${s} = rem.split(`;
    const cdatAt = requireMarker(rewritten, cdat, `consensus record ${s}`);
    const wdatAt = requireMarker(rewritten.slice(cdatAt), `        int wdatLen${s} = `, `witness record ${s}`) + cdatAt;
    const prefix = [
      `        int fixedLineBytes${s} = ${FIXED_DOUBLE_PAIR_BYTES}; if (mode${s} >= 1) { fixedLineBytes${s} = ${FIXED_DOUBLE_PAIR_BYTES + FIXED_ADD_PAIR_BYTES}; }`,
      `        bytes fixedLine${s}, bytes fixedLineRest${s} = fixedLines.split(fixedLineBytes${s});`,
      `        fixedLines = fixedLineRest${s};`,
    ].join('\n');
    rewritten = rewritten.slice(0, cdatAt) + prefix + '\n' + rewritten.slice(wdatAt);
    rewritten = rewritten.replace(`afterCdat${s}`, 'rem');
    const oldCall = `, wd${s}, cdatTail${s});`;
    if (!rewritten.includes(oldCall)) throw new Error(`fixed-G2 static executor could not locate step call ${s}`);
    rewritten = rewritten.replace(oldCall, XONLY_FIXED_G2
      ? `, wd${s}, fixedLine${s}, gx0,gx1,dx0,dx1);`
      : `, wd${s}, fixedLine${s});`);
  }
  return rewritten;
};

export function fixedG2ExecutorSource({ lo = 1, hi = 14, genesisInputIndex = 5 } = {}) {
  if (process.env.KWIN !== '13') throw new Error('fixed-G2 static executor requires KWIN=13');
  if (process.env.DYN_PACK !== '1' || process.env.DERIVE_MODE !== '1' || process.env.DRIVER_WINDOW_DERIVED !== '1') {
    throw new Error('fixed-G2 static executor requires derived dynamic packing and derived windows');
  }
  // Stock KWIN=13 striping; PairFold-6 ranges allow up to 16 steps/role.
  const maxWidth = (process.env.C7_COMPOSED_P2SH === '1' && (process.env.C7_PAIRFOLD_TOPOLOGY ?? '7') === '6')
    ? 16
    : 13;
  if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < 1 || hi <= lo || hi - lo > maxWidth) {
    throw new Error(`fixed-G2 static executor requires a nonempty window width≤${maxWidth}: [${lo},${hi})`);
  }
  if (XONLY_FIXED_G2) assertXOnlyFixedLineTable();
  else if (NORMALIZED_FIXED_ADDS) assertNormalizedFixedAddTable();
  else if (COMPACT_FIXED_LINES) assertCompactFixedLineTable();
  else assertFixedLineTable();
  const table = tableCarrier(lo, hi);
  const sharedTableEnvelope = process.env.C7_FIXED_G2_SHARED_WINDOWS === '1';
  let source = base.genChunkGB(lo, hi, { forward: true });
  // Generator variants may make a byte-neutral formatting change to the
  // shared string.  Replace the semantic helper span instead of demanding a
  // byte-identical copy of the imported module string.
  const helperStart = requireMarker(source, 'function affDblT(', 'dynamic fixed-G2 helper span');
  const helperReturn = 'return nAggL, nAggF, nG, fn, nh, R0,R1,R2,R3, G0,G1,G2,G3, D0,D1,D2,D3; }';
  const helperEndAt = requireMarker(source.slice(helperStart), helperReturn, 'dynamic step return') + helperStart + helperReturn.length;
  source = source.slice(0, helperStart) + STATIC_SHARED + source.slice(helperEndAt);
  source = rewriteStepRecordParsers(source, lo, hi);

  const lines = source.split('\n');
  // The shared K=13 body is invoked by five inputs, but the final trajectory
  // interval is only [53,64): eleven real Miller steps.  Suppress exactly the
  // two trailing generated step blocks for input 4 rather than inventing
  // records or executing beyond the signed loop.  The remaining `rem` and
  // fixed-line exhaustiveness checks then prove that the tail consumed exactly
  // its eleven authentic witness/table records.
  if (sharedTableEnvelope && lo === 1 && hi === 14) {
    const tailStart = lines.findIndex((line) => line.includes('int mode11 ='));
    const tailCall = lines.findIndex((line, index) => index > tailStart && line.includes('mode12, wd12, fixedLine12'));
    const tailEnd = lines.findIndex((line, index) => index > tailCall && line.includes('blkidx = blkidx + 1;'));
    if (tailStart < 0 || tailCall < 0 || tailEnd < 0) {
      throw new Error('fixed-G2 static executor could not locate the two-step tail span');
    }
    lines.splice(tailStart, 0, '        if (this.activeInputIndex != 4) {');
    lines.splice(tailEnd + 2, 0, '        }');
  }
  const parseStart = lines.findIndex((line) => line.includes('bytes hh0, bytes r0 = inBlob.split('));
  const remIndex = lines.findIndex((line) => line.includes('bytes rem = r31;'));
  if (parseStart < 0 || remIndex < 0 || remIndex <= parseStart) throw new Error('fixed-G2 static executor could not locate full-state parser');
  const envelope = tableEnvelopeParser(table, sharedTableEnvelope);
  const parser = [
  // Legacy direct source locks expose their table through UTXO introspection.
  // The standard-P2SH carrier instead supplies the complete table inBlob and
  // pins its full digest before the first record is parsed.
    ...envelope.lines,
    '        bytes staticBlob = inBlob;',
    `        bytes contextPush, bytes contextRest = tx.inputs[${genesisInputIndex}].unlockingBytecode.split(3);`,
    '        require(contextPush == 0x4dc001);',
    `        bytes context, bytes contextTail = contextRest.split(${staticStateLayout.contextBytes});`,
  ];
  let contextRest = 'context';
  CONTEXT.forEach((name, index) => {
    const next = `contextR${index}`;
    parser.push(`        bytes context_${name}, bytes ${next} = ${contextRest}.split(${bytesOf(name)}); int ${name} = int(context_${name});`);
    contextRest = next;
  });
  parser.push(`        require(${contextRest}.length == 0);`);
  parser.push('        require(contextTail.length >= 0);');
  let dynamicRest = 'staticBlob';
  DYNAMIC.forEach((name, index) => {
    const next = `dynamicR${index}`;
    parser.push(`        bytes dynamic_${name}, bytes ${next} = ${dynamicRest}.split(${bytesOf(name)}); int ${name} = int(dynamic_${name});`);
    dynamicRest = next;
  });
  parser.push('        int blkidx = this.activeInputIndex * 13 + 3;');
  parser.push(`        bytes rem = ${dynamicRest};`);
  parser.push('        bytes fixedLineWitness = 0x;');
  parser.push('        if (fixedLineWitnessBytes > 0) {');
  parser.push('            bytes witnessHead, bytes witnessTail = rem.split(rem.length - fixedLineWitnessBytes);');
  parser.push('            rem = witnessHead; fixedLineWitness = witnessTail;');
  parser.push('        }');
  parser.push(`        bytes fixedLines = ${envelope.fixedLinesExpr};`);
  parser.push(...envelope.hashGuards);
  if (XONLY_FIXED_G2) {
    parser.push('        bytes xSeed, bytes fixedLineTail = fixedLines.split(128); fixedLines = fixedLineTail;');
    const seed = lineParser('xSeed', ['gx0', 'gx1', 'dx0', 'dx1'], 'x');
    parser.push(...seed.lines);
    parser.push(`        require(${seed.rest}.length == 0);`);
  }
  lines.splice(parseStart, remIndex - parseStart + 1, ...parser);

  // The base generator threads two affine fixed-G2 points through every
  // step.  `stepU` above returns only the proof-point R, so eliminate both
  // the obsolete tuple destinations and their call arguments together.
  const fixedStateArgs = ', Tgxa,Tgxb,Tgya,Tgyb, Tdxa,Tdxb,Tdya,Tdyb';
  for (let index = 0; index < lines.length; index++) {
    if (!lines[index].includes(') = stepU(')) continue;
    const before = lines[index];
    lines[index] = before.replaceAll(fixedStateArgs, '');
    if (lines[index] === before || lines[index].includes('Tgxa') || lines[index].includes('Tdxa')) {
      throw new Error('fixed-G2 static executor could not remove threaded fixed state');
    }
  }

  const outIndex = lines.findIndex((line) => line.includes('bytes outBlob ='));
  if (outIndex < 0) throw new Error('fixed-G2 static executor could not locate serializer');
  const output = DYNAMIC.map((name) => name === 'hInt'
    ? `toPaddedBytes(hOut, ${bytesOf(name)})`
    : `toPaddedBytes(${name} % P, ${bytesOf(name)})`);
  lines[outIndex] = `        bytes outBlob = ${balancedCat(output)};`;
  const fixedUseAt = lines.findIndex((line) => line.includes('int hOut = int(h + 0x00);'));
  if (fixedUseAt < 0) throw new Error('fixed-G2 static executor could not locate table exhaustiveness check');
  lines.splice(fixedUseAt, 0, '        require(fixedLines.length == 0);');
  return lines.join('\n')
    .replaceAll(`.split(${base.STATE_BYTES})`, `.split(${staticStateLayout.dynamicBytes})`)
    .replaceAll(`outBlob.length == ${base.STATE_BYTES}`, `outBlob.length == ${staticStateLayout.dynamicBytes}`);
}

export const DYNAMIC_STATE_BYTES = staticStateLayout.dynamicBytes;
export const TERMINAL_SEAM_BYTES = DYNAMIC_STATE_BYTES;
export const STATE_BYTES = DYNAMIC_STATE_BYTES;
export const MODE_SCHEDULE = base.MODE_SCHEDULE;
export const FIXED_TABLE_ALL_WITNESS = ALL_TABLE_WITNESS;
// The static table is supplied by the locking bytecode carrier, so executor
// witnesses no longer contain a fixed-G2 consensus record.
export const cdatStep = () => new Uint8Array();
export const wdatStep = base.wdatStep;
export const stateW = base.stateW;
export const stateVal = base.stateVal;
export const SHARED = STATIC_SHARED;
export const projectionContext = (step = 1) => {
  const values = valuesAt(step);
  return cat(...CONTEXT.map((name) => fieldBytes(values[name], bytesOf(name), name === 'hInt')));
};
export const inBlobGB = (lo, hi) => cat(
  dynamicBytesAt(lo),
  ...Array.from({ length: hi - lo }, (_, k) => base.wdatStep(lo + k)),
  tableCarrier(lo, hi).bytes.slice(tableCarrier(lo, hi).sourceBytes.length),
);
export const outBlobGB = (hi) => dynamicBytesAt(hi);
export const lineTable = (lo, hi) => XONLY_FIXED_G2
  ? xOnlyFixedLineWindow(lo, hi)
  : (NORMALIZED_FIXED_ADDS ? normalizedFixedLineWindow(lo, hi) : (COMPACT_FIXED_LINES ? compactFixedLineWindow(lo, hi) : fixedLineWindow(lo, hi)));
export const lineCarrier = (lo, hi) => tableCarrier(lo, hi);
export const fixedG2State = (step) => {
  const values = valuesAt(step);
  return Object.fromEntries(STATIC_G2.map((name) => [name, values[name]]));
};
export const fixedG2StateBytes = (step) => {
  return cat(...Object.values(fixedG2State(step)).map((value) => fieldBytes(value, 32)));
};
export const genChunkGB = (lo, hi, cfg = {}) => {
  if (!cfg.forward) throw new Error('fixed-G2 static executor requires authenticated forward edges');
  return fixedG2ExecutorSource({ lo, hi, genesisInputIndex: 5 });
};
