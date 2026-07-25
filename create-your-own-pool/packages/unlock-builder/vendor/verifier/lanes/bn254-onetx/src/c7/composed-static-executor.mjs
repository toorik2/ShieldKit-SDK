// Executor-shaped w=2 static fixed-G2 transition.
//
// This is the bridge between the small kernel probes and the shared P2SH
// executor: it accepts the actual fixed-width dynamic state, the authenticated
// genesis context, packed pair records, and a compact fixed-line table.  It
// serializes exactly the next mixed-transcript boundary. It can take the fixed
// lines directly for narrow VM probes or reconstruct them from exact sibling
// scriptSig ranges for the standard-P2SH carrier route.
import { staticFactorOnlyShared } from './composed-window-kernel.mjs';

const P = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const FIELD_BYTES = 32;
const HASH_STATE_BYTES = 40;
const CONTEXT = ['gamma', 'z', 'nAx', 'nAy', 'vkxX', 'vkxY', 'Cx', 'Cy', 'Bxa', 'Bxb', 'Bya', 'Byb', 'dotC', 'dotCi'];
const DYNAMIC = ['hInt', 'aggL', 'aggF', 'gp', 'fC', 'Rxa', 'Rxb', 'Rya', 'Ryb'];

const balancedCat = (parts) => parts.length === 1 ? parts[0]
  : `(${balancedCat(parts.slice(0, Math.floor(parts.length / 2)))} + ${balancedCat(parts.slice(Math.floor(parts.length / 2)))})`;

const parser = (root, names, widths, prefix) => {
  let rest = root;
  const lines = names.map((name, index) => {
    const next = `${prefix}${index}`;
    const width = widths[index];
    const line = `bytes ${prefix}${name}, bytes ${next} = ${rest}.split(${width}); int ${name} = int(${prefix}${name});`;
    rest = next;
    return line;
  });
  return { lines, rest };
};

const endpointParser = (pair) => {
  let rest = `endpoint${pair}`;
  const lines = Array.from({ length: 12 }, (_, limb) => {
    const next = `endpoint${pair}R${limb}`;
    const line = `bytes endpoint${pair}L${limb}, bytes ${next} = ${rest}.split(32); int f${pair}_${limb} = int(endpoint${pair}L${limb});`;
    rest = next;
    return line;
  });
  return { lines, rest };
};

const zPrologue = () => {
  // Full Fp12 e(z) needs zp0..zp11 and all 12 ec limbs (full-endpoint path).
  // Scalar-endpoint only needs ex0..ex5 for kn/kv/kc + staticStepF; drop
  // zp10/zp11 and the unused ec limbs + the *0 keep-alives that existed solely
  // to reference them through sharedPair.
  if (process.env.C7_SCALAR_ENDPOINT === '1') {
    // zp0 ≡ 1, so ex0 ≡ 1 and kn0/kv0/kc0 are free multiplies-by-one.
    // Dens-rich: alias Pm9 once — do not re-embed (P-9) as three full field lits.
    const lines = ['int Pm9 = P - 9;', 'int zp1 = z % P;'];
    lines.push('int zp2 = (zp1 * z) % P;');
    lines.push('int zp3 = (zp2 * z) % P;');
    lines.push('int zp4 = (zp3 * z) % P;');
    lines.push('int zp5 = (zp4 * z) % P;');
    lines.push('int zp6 = (zp5 * z) % P;');
    lines.push('int zp7 = (zp6 * z) % P;');
    lines.push('int zp8 = (zp7 * z) % P;');
    lines.push('int zp9 = (zp8 * z) % P;');
    // ex mapping matches full path: ex = [ec0,ec1,ec6,ec7,ec8,ec9] with zp0=1
    lines.push('int ex1 = (Pm9 + zp6) % P;');
    lines.push('int ex3 = (Pm9 * zp1 + zp7) % P;');
    lines.push('int ex4 = zp3; int ex5 = (Pm9 * zp3 + zp9) % P;');
    lines.push('int kn0 = nAy; int kn1 = (nAy * ex1) % P; int kn2 = (nAx * zp1) % P; int kn3 = (nAx * ex3) % P;');
    lines.push('int kv0 = vkxY; int kv1 = (vkxY * ex1) % P; int kv2 = (vkxX * zp1) % P; int kv3 = (vkxX * ex3) % P;');
    lines.push('int kc0 = Cy; int kc1 = (Cy * ex1) % P; int kc2 = (Cx * zp1) % P; int kc3 = (Cx * ex3) % P;');
    return lines;
  }
  const lines = ['int zp0 = 1; int zp1 = z % P;'];
  for (let index = 2; index < 12; index += 1) lines.push(`int zp${index} = (zp${index - 1} * z) % P;`);
  // e(z) uses the Fp12 limb order [z^0,z^2,z^4,z^1,z^3,z^5], with
  // the adjacent odd limb carrying -9*z^k + z^(k+6).
  const degrees = [0, 2, 4, 1, 3, 5];
  for (const [pair, degree] of degrees.entries()) {
    lines.push(`int ec${pair * 2} = zp${degree};`);
    lines.push(`int ec${pair * 2 + 1} = ((${P} - 9) * zp${degree} + zp${degree + 6}) % P;`);
  }
  lines.push('int ex0 = ec0; int ex1 = ec1; int ex2 = ec6; int ex3 = ec7; int ex4 = ec8; int ex5 = ec9;');
  lines.push('int kn0 = (nAy * ex0) % P; int kn1 = (nAy * ex1) % P; int kn2 = (nAx * ex2) % P; int kn3 = (nAx * ex3) % P;');
  lines.push('int kv0 = (vkxY * ex0) % P; int kv1 = (vkxY * ex1) % P; int kv2 = (vkxX * ex2) % P; int kv3 = (vkxX * ex3) % P;');
  lines.push('int kc0 = (Cy * ex0) % P; int kc1 = (Cy * ex1) % P; int kc2 = (Cx * ex2) % P; int kc3 = (Cx * ex3) % P;');
  return lines;
};

const validateCarrierTable = (carrierTable) => {
  if (carrierTable === undefined || carrierTable === null) return;
  if (!Array.isArray(carrierTable) || !carrierTable.length) {
    throw new Error('composed static executor carrier table must contain exact sibling slices');
  }
  const seen = new Set();
  for (const [index, slice] of carrierTable.entries()) {
    if (!slice || !Number.isInteger(slice.inputIndex) || slice.inputIndex < 0
        || !Number.isInteger(slice.payloadOffset) || slice.payloadOffset < 0
        || !Number.isInteger(slice.length) || slice.length < 1
        || !Number.isInteger(slice.unlockingBytes) || slice.unlockingBytes < slice.payloadOffset + slice.length) {
      throw new Error(`composed static executor carrier slice ${index} is invalid`);
    }
    const key = `${slice.inputIndex}:${slice.payloadOffset}:${slice.length}`;
    if (seen.has(key)) throw new Error(`composed static executor carrier slice ${index} duplicates a byte range`);
    seen.add(key);
  }
};

const validate = ({ modes, tableHash, blockIndexStart, carrierTable }) => {
  if (!Array.isArray(modes) || modes.length < 2 || modes.length % 2 !== 0 || modes.some((mode) => !Number.isInteger(mode) || mode < 0 || mode > 2)) {
    throw new Error('composed static executor requires a nonempty even mode schedule');
  }
  if (typeof tableHash !== 'string' || !/^[0-9a-f]{64}$/i.test(tableHash)) throw new Error('composed static executor requires a SHA256d table digest');
  if (!Number.isInteger(blockIndexStart) || blockIndexStart < 0) throw new Error('composed static executor requires a non-negative transcript block index');
  validateCarrierTable(carrierTable);
};

export const composedStaticExecutorSource = ({ shared, modes, tableHash, blockIndexStart, library = '', carrierTable = null }) => {
  validate({ modes, tableHash, blockIndexStart, carrierTable });
  const helper = staticFactorOnlyShared(shared);
  const pairs = modes.length / 2;
  const context = parser('context', CONTEXT, Array(CONTEXT.length).fill(FIELD_BYTES), 'ctxR');
  const dynamic = parser('stateBlob', DYNAMIC, [HASH_STATE_BYTES, ...Array(DYNAMIC.length - 1).fill(FIELD_BYTES)], 'stateR');
  const pairBlocks = Array.from({ length: pairs }, (_, pair) => {
    const modeA = modes[pair * 2];
    const modeB = modes[pair * 2 + 1];
    const wdatABytes = modeA === 0 ? 64 : 128;
    const wdatBBytes = modeB === 0 ? 64 : 128;
    const fixedABytes = modeA === 0 ? FIXED_MODE0_BYTES : FIXED_MODEGE1_BYTES;
    const fixedBBytes = modeB === 0 ? FIXED_MODE0_BYTES : FIXED_MODEGE1_BYTES;
    const endpoint = endpointParser(pair);
    const inR = pair === 0 ? ['Rxa', 'Rxb', 'Rya', 'Ryb'] : [`out${pair - 1}a`, `out${pair - 1}b`, `out${pair - 1}c`, `out${pair - 1}d`];
    const mid = [`mid${pair}a`, `mid${pair}b`, `mid${pair}c`, `mid${pair}d`];
    const out = [`out${pair}a`, `out${pair}b`, `out${pair}c`, `out${pair}d`];
    const stepArgs = (point, mode, wdat, fixed) => [
      'dotC', 'dotCi', ...point,
      'kn0', 'kn1', 'kn2', 'kn3', 'kv0', 'kv1', 'kv2', 'kv3', 'kc0', 'kc1', 'kc2', 'kc3',
      'Bxa', 'Bxb', 'Bya', 'Byb', 'ex4', 'ex5', String(mode), wdat, fixed,
    ].join(', ');
    const endpointDot = Array.from({ length: 12 }, (_, limb) => `f${pair}_${limb} * ec${limb}`).join(' + ');
    const endpointTranscript = balancedCat(Array.from({ length: 12 }, (_, limb) => `toPaddedBytes(f${pair}_${limb}, 32).reverse()`));
    return [
      `bytes wd${pair}a, bytes afterWd${pair}a = recordsRem.split(${wdatABytes});`,
      `bytes fixed${pair}a, bytes afterFixed${pair}a = fixedRem.split(${fixedABytes});`,
      `bytes wd${pair}b, bytes afterWd${pair}b = afterWd${pair}a.split(${wdatBBytes});`,
      `bytes fixed${pair}b, bytes afterFixed${pair}b = afterFixed${pair}a.split(${fixedBBytes});`,
      `bytes endpoint${pair}, bytes afterEndpoint${pair} = afterWd${pair}b.split(384);`,
      ...endpoint.lines,
      `require(${endpoint.rest}.length == 0);`,
      `recordsRem = afterEndpoint${pair}; fixedRem = afterFixed${pair}b;`,
      `(int pf${pair}a, int ${mid[0]},int ${mid[1]},int ${mid[2]},int ${mid[3]}) = staticStepF(${stepArgs(inR, modeA, `wd${pair}a`, `fixed${pair}a`)});`,
      `(int pf${pair}b, int ${out[0]},int ${out[1]},int ${out[2]},int ${out[3]}) = staticStepF(${stepArgs(mid, modeB, `wd${pair}b`, `fixed${pair}b`)});`,
      `int inner${pair} = (((fC * fC) % P) * pf${pair}a) % P;`,
      `int product${pair} = (((inner${pair} * inner${pair}) % P) * pf${pair}b) % P;`,
      `int fn${pair} = (${endpointDot}) % P;`,
      `aggL = (aggL + P + (gp * product${pair}) % P) % P;`,
      `aggF = (aggF + P + (gp * fn${pair}) % P) % P;`,
      'gp = (gp * gamma) % P; fC = fn' + pair + ';',
      `bytes fout${pair} = ${endpointTranscript};`,
      `h = hash256(h + toPaddedBytes(${blockIndexStart + pair},4).reverse() + 0x00000180 + fout${pair});`,
    ].map((line) => `    ${line}`).join('\n');
  }).join('\n');
  const finalR = [`out${pairs - 1}a`, `out${pairs - 1}b`, `out${pairs - 1}c`, `out${pairs - 1}d`];
  const output = balancedCat([
    'toPaddedBytes(int(h + 0x00), 40)', 'toPaddedBytes(aggL % P, 32)', 'toPaddedBytes(aggF % P, 32)',
    'toPaddedBytes(gp % P, 32)', 'toPaddedBytes(fC % P, 32)', ...finalR.map((name) => `toPaddedBytes(${name} % P, 32)`),
  ]);
  const carrierSlices = carrierTable?.map((slice, index) => [
    `require(tx.inputs[${slice.inputIndex}].unlockingBytecode.length == ${slice.unlockingBytes});`,
    `bytes carrierHead${index}, bytes carrierRest${index} = tx.inputs[${slice.inputIndex}].unlockingBytecode.split(${slice.payloadOffset});`,
    `bytes tableSlice${index}, bytes carrierTail${index} = carrierRest${index}.split(${slice.length});`,
    `require(carrierHead${index}.length == ${slice.payloadOffset});`,
    `require(carrierTail${index}.length == ${slice.unlockingBytes - slice.payloadOffset - slice.length});`,
  ]).flat() ?? [];
  const fixedLines = carrierTable ? balancedCat(carrierTable.map((_, index) => `tableSlice${index}`)) : 'fixedLines';
  const fixedLinesDeclaration = carrierTable ? `bytes fixedLines = ${fixedLines};` : '';
  const argumentsList = carrierTable
    ? 'bytes stateBlob, bytes records, bytes context, bytes expectedOut'
    : 'bytes stateBlob, bytes records, bytes fixedLines, bytes context, bytes expectedOut';
  return `pragma cashscript ^0.14.0;
contract ComposedStaticExecutor() {
  function spend(${argumentsList}) {
    int P = ${P};
    ${carrierSlices.join('\n    ')}
    ${fixedLinesDeclaration}
    require(hash256(fixedLines) == 0x${tableHash});
    ${context.lines.join('\n    ')}
    require(${context.rest}.length == 0);
    ${dynamic.lines.join('\n    ')}
    require(${dynamic.rest}.length == 0);
    bytes h = toPaddedBytes(hInt, 33).split(32)[0];
    ${zPrologue().join('\n    ')}
    bytes recordsRem = records; bytes fixedRem = fixedLines;
${pairBlocks}
    require(recordsRem.length == 0); require(fixedRem.length == 0);
    bytes outBlob = ${output};
    require(outBlob == expectedOut);
  }
}
${library}
${helper}`;
};

const packedModes = (modes) => modes.reduce((pack, mode, index) => pack | (BigInt(mode) << BigInt(2 * index)), 0n);

const pairCountOf = (modes, role) => {
  // Role-0 historically packs a leading singleton mode (odd length). Pure-pair
  // PairFold-6 schedules have even length on every role — including role-0.
  const pairModes = (role === 0 && modes.length % 2 === 1) ? modes.length - 1 : modes.length;
  if (pairModes < 0 || pairModes % 2 !== 0) throw new Error(`role ${role} mode schedule is not pair-aligned: ${modes.length}`);
  return pairModes / 2;
};

// Accept PairFold-7 and PairFold-6 pure-pair schedules (including Ideal gen6-4exec).
// PairFold-6 pure-pair schedules must be even-length on every role; pair counts
// may be non-uniform (Ideal gen-absorb ends in a light 2-pair tail).
const PAIRFOLD6_SHARED_SCHEDULES = [
  [14, 16, 16, 16], // stock near-pf6 / pure-pair after genesis [0,2)
  [15, 16, 16, 16], // dens-rich PF6 mixed head genHi=1 [1,16)+pure-16×3
  [14, 16, 16, 14], // gen6-4exec gen-absorb [7,8,8,7]
  [16, 16, 14, 14], // short-04 gen-absorb [8,8,7,7]
  [16, 16, 16, 12], // alternate gen-absorb (pure-8 density-tight)
  [16, 16, 16, 4],  // aspirational Ideal genP=6 (density-blocked)
];
// PairFold-7 (5 roles): stock mixed singleton role0, or pure-pair gen-absorb, or head-heavy reorder.
const PAIRFOLD7_SHARED_SCHEDULES = [
  [13, 12, 12, 12, 14], // stock PF7
  [15, 12, 12, 12, 12], // short-03 head-heavy [7,6,6,6,6] + role0 singleton
  [14, 14, 14, 14, 4],  // short-02 pure-pair gen-absorb [7,7,7,7,2]
  [12, 12, 12, 12, 14], // pf7-genhead2 pure-pair after gen [0,2)
];
// PairFold-8 spike (6 roles): MIXED_EXECUTOR_RANGES_8 mode lengths.
const PAIRFOLD8_SHARED_SCHEDULES = [
  [11, 10, 10, 10, 10, 12], // spike [1,12),[12,22),…,[52,64)
];

const scheduleTableFor = (nRoles) => {
  if (nRoles === 4) return PAIRFOLD6_SHARED_SCHEDULES;
  if (nRoles === 5) return PAIRFOLD7_SHARED_SCHEDULES;
  if (nRoles === 6) return PAIRFOLD8_SHARED_SCHEDULES;
  return null;
};

const validateShared = ({ roleModes, tableHashes, pairBlockStarts }) => {
  if (!Array.isArray(roleModes) || ![4, 5, 6].includes(roleModes.length)
      || roleModes.some((modes) => !Array.isArray(modes) || !modes.length || modes.length > 18
        || modes.some((mode) => !Number.isInteger(mode) || mode < 0 || mode > 2))) {
    throw new Error('shared composed executor requires four, five, or six canonical role mode schedules');
  }
  const lengths = roleModes.map((modes) => modes.length);
  const table = scheduleTableFor(roleModes.length);
  const expected = table.find((schedule) => schedule.every((n, i) => n === lengths[i]));
  if (!expected || lengths.some((n, index) => n !== expected[index])) {
    const allowed = table.map((s) => JSON.stringify(s)).join(' or ');
    throw new Error(`shared composed executor requires the ${allowed} mixed schedule (got ${JSON.stringify(lengths)})`);
  }
  // HASH160 digests are 40 hex chars; HASH256 are 64. Scalar PF7 opts into HASH160.
  const useHash160 = tableHashes?.every?.((h) => typeof h === 'string' && /^[0-9a-f]{40}$/i.test(h))
    || roleModes.length === 4;
  const tableHashRe = useHash160 ? /^[0-9a-f]{40}$/i : /^[0-9a-f]{64}$/i;
  if (!Array.isArray(tableHashes) || tableHashes.length !== roleModes.length
      || tableHashes.some((hash) => typeof hash !== 'string' || !tableHashRe.test(hash))) {
    throw new Error(useHash160
      ? 'shared composed executor requires one HASH160 table digest per role'
      : 'shared composed executor requires one SHA256d table digest per role');
  }
  if (!Array.isArray(pairBlockStarts) || pairBlockStarts.length !== roleModes.length
      || pairBlockStarts.some((index) => !Number.isInteger(index) || index < 0)) {
    throw new Error('shared composed executor requires exact pair transcript block indexes');
  }
};

// The deployable P2SH route cannot afford five executor bodies. This source
// uses activeInputIndex only to select a fixed, audited schedule: it does not
// accept a caller-controlled route or mode byte. Role zero consumes its real
// singleton [1,2) first; roles 0..3 then execute six composed pairs and role
// four executes the exact seven-pair tail [50,64).
export const sharedComposedStaticExecutorSource = ({
  shared,
  roleModes,
  tableHashes,
  pairBlockStarts,
  library = '',
}) => {
  validateShared({ roleModes, tableHashes, pairBlockStarts });
  const helper = staticFactorOnlyShared(shared);
  const context = parser('context', CONTEXT, Array(CONTEXT.length).fill(FIELD_BYTES), 'ctxR');
  const dynamic = parser('stateBlob', DYNAMIC, [HASH_STATE_BYTES, ...Array(DYNAMIC.length - 1).fill(FIELD_BYTES)], 'stateR');
  const modePacks = roleModes.map((modes) => packedModes(modes).toString());
  const tableChecks = tableHashes.map((hash, role) => `if (role == ${role}) { require(hash256(fixedLines) == 0x${hash}); }`).join('\n    ');
  const roleSelect = (name, values) => [
    `int ${name} = ${values[0]};`,
    ...values.slice(1).map((value, index) => `if (role == ${index + 1}) { ${name} = ${value}; }`),
  ].join('\n    ');
  const singleton = (() => {
    const endpoint = endpointParser('single');
    const endpointDot = Array.from({ length: 12 }, (_, limb) => `fsingle_${limb} * ec${limb}`).join(' + ');
    const endpointTranscript = balancedCat(Array.from({ length: 12 }, (_, limb) => `toPaddedBytes(fsingle_${limb}, 32).reverse()`));
    return [
      'if (role == 0) {',
      '    int singleMode = modePack % 4; require(singleMode <= 2);',
      `    int singleWdBytes = 128; int singleFixedBytes = ${FIXED_MODEGE1_BYTES};`,
      `    if (singleMode == 0) { singleWdBytes = 64; singleFixedBytes = ${FIXED_MODE0_BYTES}; }`,
      '    bytes singleWd, bytes singleAfterWd = recordsRem.split(singleWdBytes);',
      '    bytes singleFixed, bytes singleAfterFixed = fixedRem.split(singleFixedBytes);',
      '    bytes endpointsingle, bytes singleAfterEndpoint = singleAfterWd.split(384);',
      ...endpoint.lines.map((line) => `    ${line}`),
      `    require(${endpoint.rest}.length == 0);`,
      '    recordsRem = singleAfterEndpoint; fixedRem = singleAfterFixed;',
      '    (int singlePf, int singleOutA,int singleOutB,int singleOutC,int singleOutD) = staticStepF(dotC, dotCi, curRxa,curRxb,curRya,curRyb, kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3, Bxa,Bxb,Bya,Byb,ex4,ex5, singleMode, singleWd, singleFixed);',
      '    int singleProduct = (((fC * fC) % P) * singlePf) % P;',
      `    int singleFn = (${endpointDot}) % P;`,
      '    aggL = (aggL + P + (gp * singleProduct) % P) % P;',
      '    aggF = (aggF + P + (gp * singleFn) % P) % P;',
      '    gp = (gp * gamma) % P; fC = singleFn;',
      `    bytes singleFout = ${endpointTranscript};`,
      '    h = hash256(h + toPaddedBytes(3,4).reverse() + 0x00000180 + singleFout);',
      '    curRxa = singleOutA; curRxb = singleOutB; curRya = singleOutC; curRyb = singleOutD;',
      '}',
    ].map((line) => `    ${line}`).join('\n');
  })();
  const pairBlock = (pair, minPairs = 0) => {
    const endpoint = endpointParser(pair);
    const modeOffset = `modeOffset + ${pair * 2}`;
    const endpointDot = Array.from({ length: 12 }, (_, limb) => `f${pair}_${limb} * ec${limb}`).join(' + ');
    const endpointTranscript = balancedCat(Array.from({ length: 12 }, (_, limb) => `toPaddedBytes(f${pair}_${limb}, 32).reverse()`));
    const block = [
      `int mode${pair}a = (modePack >> (2 * (${modeOffset}))) % 4; int mode${pair}b = (modePack >> (2 * (${modeOffset} + 1))) % 4;`,
      `require(mode${pair}a <= 2 && mode${pair}b <= 2);`,
      `int wd${pair}aBytes = 128; int wd${pair}bBytes = 128; int fixed${pair}aBytes = 384; int fixed${pair}bBytes = 384;`,
      `if (mode${pair}a == 0) { wd${pair}aBytes = 64; fixed${pair}aBytes = 256; }`,
      `if (mode${pair}b == 0) { wd${pair}bBytes = 64; fixed${pair}bBytes = 256; }`,
      `bytes wd${pair}a, bytes afterWd${pair}a = recordsRem.split(wd${pair}aBytes);`,
      `bytes fixed${pair}a, bytes afterFixed${pair}a = fixedRem.split(fixed${pair}aBytes);`,
      `bytes wd${pair}b, bytes afterWd${pair}b = afterWd${pair}a.split(wd${pair}bBytes);`,
      `bytes fixed${pair}b, bytes afterFixed${pair}b = afterFixed${pair}a.split(fixed${pair}bBytes);`,
      `bytes endpoint${pair}, bytes afterEndpoint${pair} = afterWd${pair}b.split(384);`,
      ...endpoint.lines,
      `require(${endpoint.rest}.length == 0);`,
      `recordsRem = afterEndpoint${pair}; fixedRem = afterFixed${pair}b;`,
      `(int pf${pair}a, int mid${pair}a,int mid${pair}b,int mid${pair}c,int mid${pair}d) = staticStepF(dotC, dotCi, curRxa,curRxb,curRya,curRyb, kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3, Bxa,Bxb,Bya,Byb,ex4,ex5, mode${pair}a, wd${pair}a, fixed${pair}a);`,
      `(int pf${pair}b, int out${pair}a,int out${pair}b,int out${pair}c,int out${pair}d) = staticStepF(dotC, dotCi, mid${pair}a,mid${pair}b,mid${pair}c,mid${pair}d, kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3, Bxa,Bxb,Bya,Byb,ex4,ex5, mode${pair}b, wd${pair}b, fixed${pair}b);`,
      `int inner${pair} = (((fC * fC) % P) * pf${pair}a) % P;`,
      `int product${pair} = (((inner${pair} * inner${pair}) % P) * pf${pair}b) % P;`,
      `int fn${pair} = (${endpointDot}) % P;`,
      `aggL = (aggL + P + (gp * product${pair}) % P) % P;`,
      `aggF = (aggF + P + (gp * fn${pair}) % P) % P;`,
      `gp = (gp * gamma) % P; fC = fn${pair};`,
      `bytes fout${pair} = ${endpointTranscript};`,
      `h = hash256(h + toPaddedBytes(pairBlockIndex + ${pair},4).reverse() + 0x00000180 + fout${pair});`,
      `curRxa = out${pair}a; curRxb = out${pair}b; curRya = out${pair}c; curRyb = out${pair}d;`,
    ].map((line) => `    ${line}`).join('\n');
    if (pair < minPairs) return block;
    return `    if (pairCount > ${pair}) {\n${block}\n    }`;
  };
  const output = balancedCat([
    'toPaddedBytes(int(h + 0x00), 40)', 'toPaddedBytes(aggL % P, 32)', 'toPaddedBytes(aggF % P, 32)',
    'toPaddedBytes(gp % P, 32)', 'toPaddedBytes(fC % P, 32)',
    'toPaddedBytes(curRxa % P, 32)', 'toPaddedBytes(curRxb % P, 32)', 'toPaddedBytes(curRya % P, 32)', 'toPaddedBytes(curRyb % P, 32)',
  ]);
  return `pragma cashscript ^0.14.0;
contract SharedComposedStaticExecutor() {
  function spend(bytes stateBlob, bytes records, bytes fixedLines, bytes context, bytes expectedOut) {
    int P = ${P};
    int role = this.activeInputIndex; require(role < ${roleModes.length});
    ${roleSelect('modePack', modePacks)}
    ${roleSelect('pairBlockIndex', pairBlockStarts)}
    ${roleSelect('pairCount', roleModes.map((modes, role) => pairCountOf(modes, role)))}
    ${tableChecks}
    ${context.lines.join('\n    ')}
    require(${context.rest}.length == 0);
    ${dynamic.lines.join('\n    ')}
    require(${dynamic.rest}.length == 0);
    bytes h = toPaddedBytes(hInt, 33).split(32)[0];
    ${zPrologue().join('\n    ')}
    bytes recordsRem = records; bytes fixedRem = fixedLines;
    ${XONLY_FIXED_G2 ? `bytes gx0b, bytes seedR0 = fixedRem.split(32); int gx0 = int(gx0b);
    bytes gx1b, bytes seedR1 = seedR0.split(32); int gx1 = int(gx1b);
    bytes dx0b, bytes seedR2 = seedR1.split(32); int dx0 = int(dx0b);
    bytes dx1b, bytes seedR3 = seedR2.split(32); int dx1 = int(dx1b);
    fixedRem = seedR3;` : ''}
    int curRxa = Rxa; int curRxb = Rxb; int curRya = Rya; int curRyb = Ryb;
    int modeOffset = 0; if (role == 0) { modeOffset = 1; }
${singleton}
${(() => { const _maxP = Math.max(...roleModes.map((modes, role) => pairCountOf(modes, role))); const _minP = Math.min(...roleModes.map((modes, role) => pairCountOf(modes, role))); return Array.from({ length: _maxP }, (_, pair) => pairBlock(pair, _minP)).join('\n'); })()}
    require(recordsRem.length == 0); require(fixedRem.length == 0);
    bytes outBlob = ${output};
    require(outBlob == expectedOut);
  }
}
${library}
${helper}`;
};

const SCALAR_ENDPOINT = process.env.C7_SCALAR_ENDPOINT === '1';
const XONLY_FIXED_G2 = process.env.C7_FIXED_G2_XONLY === '1';
const FIXED_MODE0_BYTES = XONLY_FIXED_G2 ? 128 : 256;
const FIXED_MODEGE1_BYTES = XONLY_FIXED_G2 ? 256 : 384;
const XONLY_SEED_BYTES = 128;

// Scalar mode: 32 B bind (FS) + 32 B fn (aggF) = 64 B vs full 384 B Fp12 endpoint.
// FS length prefix covers only the bind payload (32 B), not the fn tail.
const ENDPOINT_BYTES = SCALAR_ENDPOINT ? 64 : 384;
const ENDPOINT_LEN_HEX = SCALAR_ENDPOINT ? '0x00000020' : '0x00000180';

const factoredPairTransition = () => {
  const endpoint = endpointParser('pair');
  const endpointDot = Array.from({ length: 12 }, (_, limb) => `fpair_${limb} * ec${limb}`).join(' + ');
  const endpointTranscript = balancedCat(Array.from({ length: 12 }, (_, limb) => `toPaddedBytes(fpair_${limb}, 32).reverse()`));
  const scalarEndpointBody = [
    `bytes endpointpair, bytes afterEndpoint = afterWdB.split(${ENDPOINT_BYTES});`,
    // bind (FS) || fn (aggF), each a 32-byte big-endian field element
    'bytes fsBindBytes, bytes fnBytes = endpointpair.split(32);',
    'require(fnBytes.length == 32);',
    // Parse BE→int via reverse to LE for CashScript int()
    // dens: fsBind only bound as bytes in fout; drop unused int parse/range (a3-fscan)
    'bytes fnLE = fnBytes.reverse(); int fn = ((int(fnLE) % P) + P) % P;',
    'bytes fout = fsBindBytes;', // 32 B FS payload (BE), matches offline serLimbs([bind])
  ].join('\n    ');
  const fullEndpointBody = [
    `bytes endpointpair, bytes afterEndpoint = afterWdB.split(${ENDPOINT_BYTES});`,
    `${endpoint.lines.join('\n    ')}`,
    `require(${endpoint.rest}.length == 0);`,
  ].join('\n    ');
  // Scalar-endpoint: drop the 12 unused ec* params (fn is payload-bound; no endpointDot).
  const sharedPairEcParams = SCALAR_ENDPOINT
    ? 'int Bxa,int Bxb,int Bya,int Byb,int ex4,int ex5,'
    : 'int Bxa,int Bxb,int Bya,int Byb,int ec0,int ec1,int ec2,int ec3,int ec4,int ec5,int ec6,int ec7,int ec8,int ec9,int ec10,int ec11,int ex4,int ex5,';
  return `function sharedPair(int aggL,int aggF,int gp,int fC,bytes h,int gamma,
        int dotC,int dotCi,int curRxa,int curRxb,int curRya,int curRyb,
        int kn0,int kn1,int kn2,int kn3,int kv0,int kv1,int kv2,int kv3,int kc0,int kc1,int kc2,int kc3,
        ${sharedPairEcParams}
        int modeA,int modeB,bytes records,bytes fixedLines,int blockIndex${XONLY_FIXED_G2 ? ',int gx0,int gx1,int dx0,int dx1' : ''})
    returns (int,int,int,int,bytes,int,int,int,int,bytes,bytes${XONLY_FIXED_G2 ? ',int,int,int,int' : ''}) {
    int P = ${P};
    // modeA/B from packed 2-bit modePack (0..2); skip bound requires (body dens probe a3-modreq)
    int wdABytes = 128; int wdBBytes = 128; int fixedABytes = ${FIXED_MODEGE1_BYTES}; int fixedBBytes = ${FIXED_MODEGE1_BYTES};
    if (modeA == 0) { wdABytes = 64; fixedABytes = ${FIXED_MODE0_BYTES}; }
    if (modeB == 0) { wdBBytes = 64; fixedBBytes = ${FIXED_MODE0_BYTES}; }
    bytes wdA, bytes afterWdA = records.split(wdABytes);
    bytes fixedA, bytes afterFixedA = fixedLines.split(fixedABytes);
    bytes wdB, bytes afterWdB = afterWdA.split(wdBBytes);
    bytes fixedB, bytes afterFixedB = afterFixedA.split(fixedBBytes);
    ${SCALAR_ENDPOINT ? scalarEndpointBody : fullEndpointBody}
    ${XONLY_FIXED_G2
    ? `(int pfA, int midA,int midB,int midC,int midD, int gxA0,int gxA1,int dxA0,int dxA1) = staticStepF(dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,ex4,ex5,modeA,wdA,fixedA,gx0,gx1,dx0,dx1);
    (int pfB, int outA,int outB,int outC,int outD, int gxB0,int gxB1,int dxB0,int dxB1) = staticStepF(dotC,dotCi,midA,midB,midC,midD,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,ex4,ex5,modeB,wdB,fixedB,gxA0,gxA1,dxA0,dxA1);
    gx0 = gxB0; gx1 = gxB1; dx0 = dxB0; dx1 = dxB1;`
    : `(int pfA, int midA,int midB,int midC,int midD) = staticStepF(dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,ex4,ex5,modeA,wdA,fixedA);
    (int pfB, int outA,int outB,int outC,int outD) = staticStepF(dotC,dotCi,midA,midB,midC,midD,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,ex4,ex5,modeB,wdB,fixedB);`}
    int inner = (((fC * fC) % P) * pfA) % P;
    int product = (((inner * inner) % P) * pfB) % P;
    ${SCALAR_ENDPOINT
    ? '// fn already from scalar endpoint payload'
    : `int fn = (${endpointDot}) % P;\n    bytes fout = ${endpointTranscript};`}
    aggL = (aggL + P + (gp * product) % P) % P;
    aggF = (aggF + P + (gp * fn) % P) % P;
    gp = (gp * gamma) % P;
    h = hash256(h + toPaddedBytes(blockIndex,4).reverse() + ${ENDPOINT_LEN_HEX} + fout);
    return aggL,aggF,gp,fn,h,outA,outB,outC,outD,afterEndpoint,afterFixedB${XONLY_FIXED_G2 ? ',gx0,gx1,dx0,dx1' : ''};
}`;
};

const validateIntraTx = (intraTx) => {
  if (intraTx === null || intraTx === undefined) return;
  const validSlice = (slice) => slice && Number.isInteger(slice.inputIndex) && slice.inputIndex >= 0
    && Number.isInteger(slice.payloadOffset) && slice.payloadOffset >= 0
    && Number.isInteger(slice.length) && slice.length > 0;
  if (!validSlice(intraTx.context) || intraTx.context.length !== 448) {
    throw new Error('factored shared executor intratx context must be one exact 448-byte input slice');
  }
  if (!Array.isArray(intraTx.nextStates) || ![4, 5, 6].includes(intraTx.nextStates.length)
      || intraTx.nextStates.some((slice) => !validSlice(slice) || slice.length !== 296)) {
    throw new Error('factored shared executor intratx route needs four or five exact 296-byte successor states');
  }
  if (!Array.isArray(intraTx.tableCarriers) || intraTx.tableCarriers.length !== intraTx.nextStates.length
      || intraTx.tableCarriers.some((role) => !Array.isArray(role) || !role.length || role.some((slice) => !validSlice(slice)))) {
    throw new Error('factored shared executor intratx route needs exact table slices for every role');
  }
};

// Every cross-input byte range is authenticated by the same four conditions:
// the complete sibling scriptSig length, the prefix length, the requested
// slice length, and the exact remaining suffix.  Keep that implementation in
// one CashScript helper rather than inlining it for each table fragment.  This
// is a source-level factoring only: callers still supply compile-time fixed
// coordinates, so it cannot broaden a role's accepted byte range.
const exactInputSliceCall = (slice) => `exactInputSlice(${slice.inputIndex}, ${slice.payloadOffset}, ${slice.length})`;

// Pin only the exact payload window. Total scriptSig length is deliberately
// not bound: multiproof instances change minimal int encodings in genesis
// and terminal witnesses, and baking those lengths into the shared redeem
// would force a different P2SH lock per proof. Every authenticated table and
// state range is still fully covered by exact offset/length splits.
// Note: dropping the three length requires was measured worse (r138: +98 ops)
// under cashc's [1]/[0] emission — keep the require form.
const exactInputSliceHelper = () => `function exactInputSlice(int inputIndex, int payloadOffset, int payloadLength) returns (bytes) {
    require(tx.inputs[inputIndex].unlockingBytecode.length >= payloadOffset + payloadLength);
    bytes head, bytes rest = tx.inputs[inputIndex].unlockingBytecode.split(payloadOffset);
    require(head.length == payloadOffset);
    bytes payload = rest.split(payloadLength)[0];
    require(payload.length == payloadLength);
    return payload;
}`;

const intraTxPrelude = (intraTx) => {
  if (intraTx === null || intraTx === undefined) return '';
  const tableRoles = intraTx.tableCarriers.map((slices, role) => {
    const names = slices.map((slice, index) => `table${role}_${index}`);
    const lines = slices.map((slice, index) => `bytes ${names[index]} = ${exactInputSliceCall(slice)};`);
    return [
      `if (role == ${role}) {`,
      ...lines.map((line) => `    ${line}`),
      `    fixedLines = ${balancedCat(names)};`,
      '}',
    ];
  }).flat();
  // Alias-free context binding (r128: role2 +1 op — drop one bytes assignment).
  const contextLines = [`bytes context = ${exactInputSliceCall(intraTx.context)};`];
  const successors = intraTx.nextStates.map((slice, role) => [
    `if (role == ${role}) {`,
    `    expectedOut = ${exactInputSliceCall(slice)};`,
    '}',
  ]).flat();
  return [
    'bytes fixedLines = 0x;',
    ...tableRoles,
    ...contextLines,
    'bytes expectedOut = 0x;',
    ...successors,
  ].join('\n    ');
};

// This is the size-safe form of the shared executor. The arithmetic and
// byte parsers for one pair live in an OP_DEFINEd CashScript function rather
// than being emitted seven times into the redeem. That preserves the exact
// active-index schedule above while keeping the final redeem below BCH's
// 10,000-byte consensus bytecode ceiling.
export const factoredSharedComposedStaticExecutorSource = ({
  shared,
  roleModes,
  tableHashes,
  pairBlockStarts,
  library = '',
  intraTx = null,
}) => {
  validateShared({ roleModes, tableHashes, pairBlockStarts });
  validateIntraTx(intraTx);
  const helper = staticFactorOnlyShared(shared);
  const context = parser('context', CONTEXT, Array(CONTEXT.length).fill(FIELD_BYTES), 'ctxR');
  const dynamic = parser('stateBlob', DYNAMIC, [HASH_STATE_BYTES, ...Array(DYNAMIC.length - 1).fill(FIELD_BYTES)], 'stateR');
  const modePacks = roleModes.map((modes) => packedModes(modes).toString());
  // PairFold-6 / scalar-PF7: HASH160 table pin (cheaper). Stock PF7: HASH256.
  const tablePinOp = (tableHashes[0]?.length === 40 || roleModes.length === 4) ? 'hash160' : 'hash256';
  const tableChecks = tableHashes.map((hash, role) => `if (role == ${role}) { require(${tablePinOp}(fixedLines) == 0x${hash}); }`).join('\n    ');
  const roleSelect = (name, values) => [
    `int ${name} = ${values[0]};`,
    ...values.slice(1).map((value, index) => `if (role == ${index + 1}) { ${name} = ${value}; }`),
  ].join('\n    ');
  const purePairs = roleModes.every((modes) => modes.length % 2 === 0);
  const singleton = purePairs ? '' : (() => {
    const endpoint = endpointParser('single');
    const endpointDot = Array.from({ length: 12 }, (_, limb) => `fsingle_${limb} * ec${limb}`).join(' + ');
    const endpointTranscript = balancedCat(Array.from({ length: 12 }, (_, limb) => `toPaddedBytes(fsingle_${limb}, 32).reverse()`));
    const scalarSingle = [
      `    bytes endpointsingle, bytes singleAfterEndpoint = singleAfterWd.split(${ENDPOINT_BYTES});`,
      '    bytes singleBindBytes, bytes singleFnBytes = endpointsingle.split(32);',
      '    require(singleFnBytes.length == 32);',
      // dens: singleBind only as bytes in singleFout; drop unused int parse (a3-fscan)
      '    bytes singleFnLE = singleFnBytes.reverse(); int singleFn = ((int(singleFnLE) % P) + P) % P;',
      '    bytes singleFout = singleBindBytes;',
    ];
    const fullSingle = [
      '    bytes endpointsingle, bytes singleAfterEndpoint = singleAfterWd.split(384);',
      ...endpoint.lines.map((line) => `    ${line}`),
      `    require(${endpoint.rest}.length == 0);`,
      `    int singleFn = (${endpointDot}) % P;`,
      `    bytes singleFout = ${endpointTranscript};`,
    ];
    return [
      'if (role == 0) {',
      '    int singleMode = modePack % 4; require(singleMode <= 2);',
      `    int singleWdBytes = 128; int singleFixedBytes = ${FIXED_MODEGE1_BYTES};`,
      `    if (singleMode == 0) { singleWdBytes = 64; singleFixedBytes = ${FIXED_MODE0_BYTES}; }`,
      '    bytes singleWd, bytes singleAfterWd = recordsRem.split(singleWdBytes);',
      '    bytes singleFixed, bytes singleAfterFixed = fixedRem.split(singleFixedBytes);',
      ...(SCALAR_ENDPOINT ? scalarSingle : fullSingle),
      '    recordsRem = singleAfterEndpoint; fixedRem = singleAfterFixed;',
      `    ${XONLY_FIXED_G2 ? `(int singlePf, int singleOutA,int singleOutB,int singleOutC,int singleOutD, int sgx0,int sgx1,int sdx0,int sdx1) = staticStepF(dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,ex4,ex5,singleMode,singleWd,singleFixed,gx0,gx1,dx0,dx1); gx0=sgx0;gx1=sgx1;dx0=sdx0;dx1=sdx1;` : `(int singlePf, int singleOutA,int singleOutB,int singleOutC,int singleOutD) = staticStepF(dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,ex4,ex5,singleMode,singleWd,singleFixed);`}`,
      '    int singleProduct = (((fC * fC) % P) * singlePf) % P;',
      '    aggL = (aggL + P + (gp * singleProduct) % P) % P;',
      '    aggF = (aggF + P + (gp * singleFn) % P) % P;',
      '    gp = (gp * gamma) % P; fC = singleFn;',
      `    h = hash256(h + toPaddedBytes(3,4).reverse() + ${ENDPOINT_LEN_HEX} + singleFout);`,
      '    curRxa = singleOutA; curRxb = singleOutB; curRya = singleOutC; curRyb = singleOutD;',
      '}',
    ].map((line) => `    ${line}`).join('\n');
  })();
  const callPair = (pair, minPairs = 0) => {
    const modeOffset = purePairs ? `${pair * 2}` : `modeOffset + ${pair * 2}`;
    const call = [
      `int mode${pair}a = (modePack >> (2 * (${modeOffset}))) % 4; int mode${pair}b = (modePack >> (2 * (${modeOffset} + 1))) % 4;`,
      `${XONLY_FIXED_G2
        ? `(int nextAggL${pair},int nextAggF${pair},int nextGp${pair},int nextFC${pair},bytes nextH${pair},int nextRxa${pair},int nextRxb${pair},int nextRya${pair},int nextRyb${pair},bytes nextRecords${pair},bytes nextFixed${pair},int nextGx0p${pair},int nextGx1p${pair},int nextDx0p${pair},int nextDx1p${pair}) = sharedPair(aggL,aggF,gp,fC,h,gamma,dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,${SCALAR_ENDPOINT ? '' : 'ec0,ec1,ec2,ec3,ec4,ec5,ec6,ec7,ec8,ec9,ec10,ec11,'}ex4,ex5,mode${pair}a,mode${pair}b,recordsRem,fixedRem,pairBlockIndex + ${pair},gx0,gx1,dx0,dx1);`
        : `(int nextAggL${pair},int nextAggF${pair},int nextGp${pair},int nextFC${pair},bytes nextH${pair},int nextRxa${pair},int nextRxb${pair},int nextRya${pair},int nextRyb${pair},bytes nextRecords${pair},bytes nextFixed${pair}) = sharedPair(aggL,aggF,gp,fC,h,gamma,dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,${SCALAR_ENDPOINT ? '' : 'ec0,ec1,ec2,ec3,ec4,ec5,ec6,ec7,ec8,ec9,ec10,ec11,'}ex4,ex5,mode${pair}a,mode${pair}b,recordsRem,fixedRem,pairBlockIndex + ${pair});`}`,
      `aggL = nextAggL${pair}; aggF = nextAggF${pair}; gp = nextGp${pair}; fC = nextFC${pair}; h = nextH${pair};`,
      `curRxa = nextRxa${pair}; curRxb = nextRxb${pair}; curRya = nextRya${pair}; curRyb = nextRyb${pair}; recordsRem = nextRecords${pair}; fixedRem = nextFixed${pair};`,
      `${XONLY_FIXED_G2 ? `gx0 = nextGx0p${pair}; gx1 = nextGx1p${pair}; dx0 = nextDx0p${pair}; dx1 = nextDx1p${pair};` : ''}`,
    ].map((line) => `    ${line}`).join('\n');
    if (pair < minPairs) return call;
    return `    if (pairCount > ${pair}) {\n${call}\n    }`;
  };
  const output = balancedCat([
    'toPaddedBytes(int(h + 0x00), 40)', 'toPaddedBytes(aggL % P, 32)', 'toPaddedBytes(aggF % P, 32)',
    'toPaddedBytes(gp % P, 32)', 'toPaddedBytes(fC % P, 32)',
    'toPaddedBytes(curRxa % P, 32)', 'toPaddedBytes(curRxb % P, 32)', 'toPaddedBytes(curRya % P, 32)', 'toPaddedBytes(curRyb % P, 32)',
  ]);
  const argumentsList = intraTx === null
    ? 'bytes stateBlob, bytes records, bytes fixedLines, bytes context, bytes expectedOut'
    : 'bytes stateBlob, bytes records';
  return `pragma cashscript ^0.14.0;
contract FactoredSharedComposedStaticExecutor() {
  function spend(${argumentsList}) {
    int P = ${P};
    // Keep role < N: removing it measured +13 ops (r144) — cashc uses the bound
    // when lowering the role-select if-ladder.
    int role = this.activeInputIndex; require(role < ${roleModes.length});
    ${roleSelect('modePack', modePacks)}
    ${roleSelect('pairBlockIndex', pairBlockStarts)}
    ${roleSelect('pairCount', roleModes.map((modes, role) => pairCountOf(modes, role)))}
    ${intraTxPrelude(intraTx)}
    ${tableChecks}
    ${context.lines.join('\n    ')}
    require(${context.rest}.length == 0);
    ${dynamic.lines.join('\n    ')}
    require(${dynamic.rest}.length == 0);
    bytes h = toPaddedBytes(hInt, 33).split(32)[0];
    ${zPrologue().join('\n    ')}
    bytes recordsRem = records; bytes fixedRem = fixedLines;
    ${XONLY_FIXED_G2 ? `bytes gx0b, bytes seedR0 = fixedRem.split(32); int gx0 = int(gx0b);
    bytes gx1b, bytes seedR1 = seedR0.split(32); int gx1 = int(gx1b);
    bytes dx0b, bytes seedR2 = seedR1.split(32); int dx0 = int(dx0b);
    bytes dx1b, bytes seedR3 = seedR2.split(32); int dx1 = int(dx1b);
    fixedRem = seedR3;` : ''}
    int curRxa = Rxa; int curRxb = Rxb; int curRya = Rya; int curRyb = Ryb;
    ${purePairs ? '' : 'int modeOffset = 0; if (role == 0) { modeOffset = 1; }'}
${singleton}
${(() => {
    const counts = roleModes.map((modes, role) => pairCountOf(modes, role));
    const _maxP = Math.max(...counts);
    const _minP = Math.min(...counts);
    const longRoles = counts.map((c, i) => (c === _maxP ? i : -1)).filter((i) => i >= 0);
    // Bake the final pair's modes only when a single role owns the max pair count
    // (unique 9th pair on the old cliff schedules). Shared max (e.g. three pure-8
    // roles under [15,16,16,16]) must keep modePack extraction.
    const bakeLast = _maxP > _minP && longRoles.length === 1;
    const lines = Array.from({ length: _maxP - (bakeLast ? 1 : 0) }, (_, pair) => callPair(pair, _minP));
    if (bakeLast) {
      const longRole = longRoles[0];
      const modes = roleModes[longRole];
      const singletonPad = (longRole === 0 && modes.length % 2 === 1) ? 1 : 0;
      const modeA = modes[singletonPad + (_maxP - 1) * 2];
      const modeB = modes[singletonPad + (_maxP - 1) * 2 + 1];
      const pair = _maxP - 1;
      lines.push(`    if (pairCount > ${pair}) {
      int mode${pair}a = ${modeA}; int mode${pair}b = ${modeB};
      ${XONLY_FIXED_G2
      ? `(int nextAggL${pair},int nextAggF${pair},int nextGp${pair},int nextFC${pair},bytes nextH${pair},int nextRxa${pair},int nextRxb${pair},int nextRya${pair},int nextRyb${pair},bytes nextRecords${pair},bytes nextFixed${pair},int nextGx0p${pair},int nextGx1p${pair},int nextDx0p${pair},int nextDx1p${pair}) = sharedPair(aggL,aggF,gp,fC,h,gamma,dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,${SCALAR_ENDPOINT ? '' : 'ec0,ec1,ec2,ec3,ec4,ec5,ec6,ec7,ec8,ec9,ec10,ec11,'}ex4,ex5,mode${pair}a,mode${pair}b,recordsRem,fixedRem,pairBlockIndex + ${pair},gx0,gx1,dx0,dx1);
      gx0 = nextGx0p${pair}; gx1 = nextGx1p${pair}; dx0 = nextDx0p${pair}; dx1 = nextDx1p${pair};`
      : `(int nextAggL${pair},int nextAggF${pair},int nextGp${pair},int nextFC${pair},bytes nextH${pair},int nextRxa${pair},int nextRxb${pair},int nextRya${pair},int nextRyb${pair},bytes nextRecords${pair},bytes nextFixed${pair}) = sharedPair(aggL,aggF,gp,fC,h,gamma,dotC,dotCi,curRxa,curRxb,curRya,curRyb,kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,Bxa,Bxb,Bya,Byb,${SCALAR_ENDPOINT ? '' : 'ec0,ec1,ec2,ec3,ec4,ec5,ec6,ec7,ec8,ec9,ec10,ec11,'}ex4,ex5,mode${pair}a,mode${pair}b,recordsRem,fixedRem,pairBlockIndex + ${pair});`}
      aggL = nextAggL${pair}; aggF = nextAggF${pair}; gp = nextGp${pair}; fC = nextFC${pair}; h = nextH${pair};
      curRxa = nextRxa${pair}; curRxb = nextRxb${pair}; curRya = nextRya${pair}; curRyb = nextRyb${pair}; recordsRem = nextRecords${pair}; fixedRem = nextFixed${pair};
    }`);
    }
    return lines.join('\n');
  })()}
    require(recordsRem.length == 0 && fixedRem.length == 0);
    bytes outBlob = ${output};
    require(outBlob == expectedOut);
  }
}
${factoredPairTransition()}
${intraTx === null ? '' : exactInputSliceHelper()}
${library}
${helper}`;
};
