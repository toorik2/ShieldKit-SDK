import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  DIRECT_V2_MILLER_E6_COLUMNS,
  DIRECT_V2_MILLER_ENDPOINT_BYTES,
  DIRECT_V2_MILLER_RESIDUE_BYTES,
  DIRECT_V2_MILLER_SLOPE_BYTES,
  DIRECT_V2_MILLER_TAG_GAMMA,
  directV2MillerFixedStep0,
} from './identity-aware-miller.mjs';
import {
  DIRECT_V2_MILLER_EZ_COLUMNS,
} from './identity-aware-miller.mjs';

const P = 21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583n;
const HEX_35 = /^[0-9a-f]{70}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const LAZY_AFFINE_LIBRARY = fileURLToPath(new URL(
  '../vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash',
  import.meta.url,
));

export class DirectV2IdentityAwareMillerCashScriptError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2IdentityAwareMillerCashScriptError';
  }
}

const fail = (message) => {
  throw new DirectV2IdentityAwareMillerCashScriptError(message);
};

const sha256d = (value) => {
  const first = createHash('sha256').update(value).digest();
  return createHash('sha256').update(first).digest('hex');
};

const mod = (value) => {
  const reduced = BigInt(value) % P;
  return reduced < 0n ? reduced + P : reduced;
};

const balanced = (terms) => {
  if (terms.length === 0) return '0x';
  if (terms.length === 1) return terms[0];
  const middle = terms.length >> 1;
  return `(${balanced(terms.slice(0, middle))} + ${balanced(terms.slice(middle))})`;
};

const be = (expression) => `toPaddedBytes(${expression}, 32).reverse()`;

const g1 = (point) => {
  const affine = point.toAffine();
  return [mod(affine.x), mod(affine.y)];
};

const g2 = (point) => {
  const affine = point.toAffine();
  return [
    mod(affine.x.c0),
    mod(affine.x.c1),
    mod(affine.y.c0),
    mod(affine.y.c1),
  ];
};

const dot = (names, coefficients = names.map((_, index) => `ec${index}`)) =>
  `(${names.map((name, index) => `${name} * ${coefficients[index]}`).join(' + ')}) % P`;

const lineEvaluation = (coefficients, px, py) => {
  const [c0, c1, c2] = coefficients;
  return `(mulFp(mulFp(${mod(c2.c0)}, ${py}), ex0)`
    + ` + mulFp(mulFp(${mod(c2.c1)}, ${py}), ex1)`
    + ` + mulFp(mulFp(${mod(c1.c0)}, ${px}), ex2)`
    + ` + mulFp(mulFp(${mod(c1.c1)}, ${px}), ex3)`
    + ` + mulFp(${mod(c0.c0)}, ex4)`
    + ` + mulFp(${mod(c0.c1)}, ex5)) % P`;
};

const pushData2Header = (length) => {
  if (!Number.isInteger(length) || length < 256 || length > 65_535) {
    fail('PUSHDATA2 width must be from 256 to 65535 bytes');
  }
  return `4d${(length & 0xff).toString(16).padStart(2, '0')}${(length >> 8).toString(16).padStart(2, '0')}`;
};

const parseFixedBeBlob = ({
  source,
  root,
  names,
  prefix,
  expectedBytes,
}) => {
  source.push(`        require(${root}.length == ${expectedBytes});`);
  let rest = root;
  names.forEach((name, index) => {
    if (index === names.length - 1) {
      source.push(`        int ${name} = int(${rest}.reverse() + 0x00);`);
      return;
    }
    source.push(`        bytes ${prefix}b${index}, bytes ${prefix}r${index} = ${rest}.split(32);`);
    source.push(`        int ${name} = int(${prefix}b${index}.reverse() + 0x00);`);
    rest = `${prefix}r${index}`;
  });
};

const parseContext = (source) => {
  const names = [
    'gammaW', 'zW',
    'nAx', 'nAy',
    'Qx', 'Qy',
    'Cx', 'Cy',
    'Bxa', 'Bxb', 'Bya', 'Byb',
    'dotC', 'dotCi',
  ];
  source.push('        bytes sourceUnlock = tx.inputs[8].unlockingBytecode;');
  source.push('        bytes sourceSignalHeader, bytes sourceAfterSignalHeader = sourceUnlock.split(3);');
  source.push('        require(sourceSignalHeader == 0x4de001);');
  source.push('        bytes projectionSignalCarrier, bytes sourceRemainder = sourceAfterSignalHeader.split(480);');
  source.push('        require(sourceRemainder.length > 0);');
  source.push('        bytes projectionContext, bytes actionDigest = projectionSignalCarrier.split(448);');
  source.push('        require(actionDigest.length == 32);');
  let rest = 'projectionContext';
  names.forEach((name, index) => {
    if (index === names.length - 1) {
      source.push(`        int ${name} = int(${rest});`);
      return;
    }
    source.push(`        bytes ctxb${index}, bytes ctxr${index} = ${rest}.split(32);`);
    source.push(`        int ${name} = int(ctxb${index});`);
    rest = `ctxr${index}`;
  });
};

/**
 * Render the standalone PF11 input-9 singleton Miller genesis.
 *
 * This role reads Q from the exact 480-byte projection signal carried by
 * input 8. The only infinity selector is the canonical Q byte pair itself:
 * Q=(0,0) omits the vkx/gamma line; every finite canonical Q executes it.
 *
 * Input 8 already pins this input-9 locking bytecode. This role deliberately
 * does not reciprocally pin input 8's lock: that would form a role8<->role9
 * hash cycle. The final state helper authenticates the complete verifier lock
 * set. Input 9 instead pins its tail-built terminal successor at input 10.
 *
 * The state locking bytecode is intentionally not a renderer input and is not
 * pinned here. Input 12 pins verifier locks in the completed PF11 DAG, so a
 * reciprocal verifier->state-lock hash edge would create a construction
 * cycle. This role still binds the state category, mutable capability,
 * zero amount, 128-byte commitment, exact outpoint position, and common
 * parent.
 */
export function renderDirectV2IdentityAwareMillerGenesis({
  verificationKey,
  inputIndex = 9,
  sourceInputIndex = 8,
  executorHeadInputIndex = 0,
  successorInputIndex = 10,
  successorLockingBytecodeHex,
  bindingInputIndex = 11,
  bindingLockingBytecodeHex,
  stateInputIndex = 12,
  stateCategoryHex,
  expectedInputCount = 14,
  ownWitnessPayloadOffset = 0,
  zeroPaddingBytes,
  libraryImportPath = LAZY_AFFINE_LIBRARY,
}) {
  for (const [value, label] of [
    [inputIndex, 'inputIndex'],
    [sourceInputIndex, 'sourceInputIndex'],
    [executorHeadInputIndex, 'executorHeadInputIndex'],
    [successorInputIndex, 'successorInputIndex'],
    [bindingInputIndex, 'bindingInputIndex'],
    [stateInputIndex, 'stateInputIndex'],
    [expectedInputCount, 'expectedInputCount'],
    [ownWitnessPayloadOffset, 'ownWitnessPayloadOffset'],
    [zeroPaddingBytes, 'zeroPaddingBytes'],
  ]) {
    if (!Number.isInteger(value) || value < 0) {
      fail(`${label} must be a nonnegative integer`);
    }
  }
  const pf11 = (
    inputIndex !== 9
    ? false
    : sourceInputIndex === 8
      && executorHeadInputIndex === 0
      && successorInputIndex === 10
      && bindingInputIndex === 11
      && stateInputIndex === 12
      && expectedInputCount === 14
      && ownWitnessPayloadOffset === 0
  );
  const pf10Fused = (
    inputIndex === 8
    && sourceInputIndex === 8
    && executorHeadInputIndex === 0
    && successorInputIndex === 9
    && bindingInputIndex === 10
    && stateInputIndex === 11
    && expectedInputCount === 13
    && ownWitnessPayloadOffset > 0
  );
  if (!pf11 && !pf10Fused) {
    fail('identity-aware Miller genesis must select exact PF11 or PF10-FusedQGenesis topology');
  }
  for (const [value, label] of [
    [successorLockingBytecodeHex, 'successorLockingBytecodeHex'],
    [bindingLockingBytecodeHex, 'bindingLockingBytecodeHex'],
  ]) {
    if (!HEX_35.test(value)) fail(`${label} must contain exactly 35 lowercase hexadecimal bytes`);
  }
  if (!HEX_32.test(stateCategoryHex)) {
    fail('stateCategoryHex must contain exactly 32 lowercase hexadecimal bytes');
  }
  if (zeroPaddingBytes < 256 || zeroPaddingBytes > 7_500) {
    fail('zeroPaddingBytes must be from 256 to 7500');
  }
  if (typeof libraryImportPath !== 'string' || libraryImportPath.length === 0) {
    fail('libraryImportPath must be a nonempty path');
  }

  const fixed = directV2MillerFixedStep0(verificationKey);
  const key = fixed.key;
  const alpha = g1(key.alpha);
  const beta = g2(key.beta);
  const gamma = g2(key.gamma);
  const delta = g2(key.delta);
  const paddingDigest = sha256d(Buffer.alloc(zeroPaddingBytes));
  const h0 = sha256d(Buffer.from(DIRECT_V2_MILLER_TAG_GAMMA)).toString('hex');
  const cNames = Array.from({ length: 12 }, (_, index) => `c${index}`);
  const ciNames = Array.from({ length: 12 }, (_, index) => `ci${index}`);
  const wNames = Array.from({ length: 12 }, (_, index) => `w${index}`);
  const endpointNames = Array.from({ length: 12 }, (_, index) => `r1_${index}`);
  const source = [];

  source.push('pragma cashscript ^0.14.0;');
  source.push(`import "${libraryImportPath.replaceAll('\\', '/')}";`);
  source.push(
    pf11
      ? '// ShieldKit V2 Direct PF11 role 9: total singleton Miller genesis [0,1).'
      : '// ShieldKit V2 Direct PF10-FusedQGenesis role 8: Miller component [0,1).',
  );
  source.push('contract DirectV2IdentityAwareMillerGenesis() {');
  source.push('    function spend(bytes zeroPadding, bytes residueBE, bytes endpointBE, bytes slopeBE) {');
  source.push(`        require(this.activeInputIndex == ${inputIndex});`);
  source.push(`        require(tx.inputs.length == ${expectedInputCount});`);
  source.push(`        require(tx.inputs[${executorHeadInputIndex}].outpointIndex == ${executorHeadInputIndex + 1});`);
  source.push(`        require(tx.inputs[${sourceInputIndex}].outpointIndex == ${sourceInputIndex + 1});`);
  source.push(`        require(tx.inputs[${inputIndex}].outpointIndex == ${inputIndex + 1});`);
  source.push(`        require(tx.inputs[${successorInputIndex}].outpointIndex == ${successorInputIndex + 1});`);
  source.push(`        require(tx.inputs[${bindingInputIndex}].outpointIndex == ${bindingInputIndex + 1});`);
  source.push(`        require(tx.inputs[${stateInputIndex}].outpointIndex == 0);`);
  for (const other of [
    executorHeadInputIndex,
    sourceInputIndex,
    successorInputIndex,
    bindingInputIndex,
    stateInputIndex,
  ]) {
    source.push(`        require(tx.inputs[${inputIndex}].outpointTransactionHash == tx.inputs[${other}].outpointTransactionHash);`);
  }
  source.push(`        require(tx.inputs[${successorInputIndex}].lockingBytecode == 0x${successorLockingBytecodeHex});`);
  source.push(`        require(tx.inputs[${bindingInputIndex}].lockingBytecode == 0x${bindingLockingBytecodeHex});`);
  source.push(`        require(tx.inputs[${stateInputIndex}].tokenCategory == 0x${stateCategoryHex}01);`);
  source.push(`        require(tx.inputs[${stateInputIndex}].nftCommitment.length == 128);`);
  source.push(`        require(tx.inputs[${stateInputIndex}].tokenAmount == 0);`);
  source.push(`        require(zeroPadding.length == ${zeroPaddingBytes});`);
  source.push(`        require(hash256(zeroPadding) == 0x${paddingDigest});`);

  source.push(`        require(residueBE.length == ${DIRECT_V2_MILLER_RESIDUE_BYTES});`);
  source.push(`        require(endpointBE.length == ${DIRECT_V2_MILLER_ENDPOINT_BYTES});`);
  source.push(`        require(slopeBE.length == ${DIRECT_V2_MILLER_SLOPE_BYTES});`);
  source.push(`        bytes ownUnlock = tx.inputs[${inputIndex}].unlockingBytecode;`);
  if (ownWitnessPayloadOffset === 0) {
    source.push('        bytes ownSlopeHeader, bytes ownAfterSlopeHeader = ownUnlock.split(1);');
  } else {
    source.push(`        bytes ownPrefix, bytes ownWitness = ownUnlock.split(${ownWitnessPayloadOffset});`);
    source.push(`        require(ownPrefix.length == ${ownWitnessPayloadOffset});`);
    source.push('        bytes ownSlopeHeader, bytes ownAfterSlopeHeader = ownWitness.split(1);');
  }
  source.push('        require(ownSlopeHeader == 0x40);');
  source.push(`        bytes ownSlope, bytes ownAfterSlope = ownAfterSlopeHeader.split(${DIRECT_V2_MILLER_SLOPE_BYTES});`);
  source.push('        require(ownSlope == slopeBE);');
  source.push('        bytes ownEndpointHeader, bytes ownAfterEndpointHeader = ownAfterSlope.split(3);');
  source.push(`        require(ownEndpointHeader == 0x${pushData2Header(DIRECT_V2_MILLER_ENDPOINT_BYTES)});`);
  source.push(`        bytes ownEndpoint, bytes ownAfterEndpoint = ownAfterEndpointHeader.split(${DIRECT_V2_MILLER_ENDPOINT_BYTES});`);
  source.push('        require(ownEndpoint == endpointBE);');
  source.push('        bytes ownResidueHeader, bytes ownAfterResidueHeader = ownAfterEndpoint.split(3);');
  source.push(`        require(ownResidueHeader == 0x${pushData2Header(DIRECT_V2_MILLER_RESIDUE_BYTES)});`);
  source.push(`        bytes ownResidue, bytes ownAfterResidue = ownAfterResidueHeader.split(${DIRECT_V2_MILLER_RESIDUE_BYTES});`);
  source.push('        require(ownResidue == residueBE);');
  source.push('        bytes ownPaddingHeader, bytes ownAfterPaddingHeader = ownAfterResidue.split(3);');
  source.push(`        require(ownPaddingHeader == 0x${pushData2Header(zeroPaddingBytes)});`);
  source.push(`        bytes ownPadding, bytes ownRedeemPush = ownAfterPaddingHeader.split(${zeroPaddingBytes});`);
  source.push('        require(ownPadding == zeroPadding && ownRedeemPush.length > 0);');

  parseContext(source);
  source.push(`        int P = ${P};`);
  source.push('        require(gammaW >= 0 && gammaW < P); require(zW >= 0 && zW < P);');
  source.push('        require(nAx >= 0 && nAx < P); require(nAy >= 0 && nAy < P);');
  source.push('        require(Qx >= 0 && Qx < P); require(Qy >= 0 && Qy < P);');
  source.push('        require(Cx >= 0 && Cx < P); require(Cy >= 0 && Cy < P);');
  source.push('        require(Bxa >= 0 && Bxa < P); require(Bxb >= 0 && Bxb < P);');
  source.push('        require(Bya >= 0 && Bya < P); require(Byb >= 0 && Byb < P);');
  source.push('        require(dotC >= 0 && dotC < P); require(dotCi >= 0 && dotCi < P);');
  source.push('        require(mulFp(nAy, nAy) == (mulFp(mulFp(nAx, nAx), nAx) + 3) % P);');
  source.push('        require(mulFp(Cy, Cy) == (mulFp(mulFp(Cx, Cx), Cx) + 3) % P);');
  source.push('        int qInf = 0;');
  source.push('        if (Qx == 0 && Qy == 0) { qInf = 1; }');
  source.push('        if (qInf == 0) { require(mulFp(Qy, Qy) == (mulFp(mulFp(Qx, Qx), Qx) + 3) % P); }');
  source.push('        int bxx = mulFp(Bxa, Bxa); int bxy = mulFp(Bxb, Bxb);');
  source.push('        int bx0 = (bxx + P - bxy) % P;');
  source.push('        int bx1 = (mulFp(Bxa + Bxb, Bxa + Bxb) + 2*P - bxx - bxy) % P;');
  source.push('        int bc0 = (mulFp(bx0, Bxa) + P - mulFp(bx1, Bxb)) % P;');
  source.push('        int bc1 = (mulFp(bx0 + bx1, Bxa + Bxb) + 2*P - mulFp(bx0, Bxa) - mulFp(bx1, Bxb)) % P;');
  source.push('        int byy = mulFp(Bya, Bya); int byz = mulFp(Byb, Byb);');
  source.push('        int by0 = (byy + P - byz) % P;');
  source.push('        int by1 = (mulFp(Bya + Byb, Bya + Byb) + 2*P - byy - byz) % P;');
  source.push('        require(by0 == (bc0 + 19485874751759354771024239261021720505790618469301721065564631296452457478373) % P);');
  source.push('        require(by1 == (bc1 + 266929791119991161246907387137283842545076965332900288569378510910307636690) % P);');

  parseFixedBeBlob({
    source,
    root: 'residueBE',
    names: [...cNames, ...ciNames, ...wNames],
    prefix: 'rs',
    expectedBytes: DIRECT_V2_MILLER_RESIDUE_BYTES,
  });
  parseFixedBeBlob({
    source,
    root: 'endpointBE',
    names: endpointNames,
    prefix: 'ep',
    expectedBytes: DIRECT_V2_MILLER_ENDPOINT_BYTES,
  });
  parseFixedBeBlob({
    source,
    root: 'slopeBE',
    names: ['s0a', 's0b'],
    prefix: 'sl',
    expectedBytes: DIRECT_V2_MILLER_SLOPE_BYTES,
  });
  for (const name of [...cNames, ...ciNames, ...wNames, ...endpointNames, 's0a', 's0b']) {
    source.push(`        require(${name} >= 0 && ${name} < P);`);
  }

  source.push('        int zp0 = 1; int zp1 = zW;');
  for (let power = 2; power < 12; power += 1) {
    source.push(`        int zp${power} = mulFp(zp${power - 1}, zW);`);
  }
  const powers = Array.from({ length: 12 }, (_, index) => `zp${index}`);
  const polynomial = (coefficients) => {
    const terms = coefficients.map((coefficient, index) =>
      mod(coefficient) === 0n ? null : `${mod(coefficient)} * ${powers[index]}`)
      .filter(Boolean);
    return terms.length === 0 ? '0' : terms.join(' + ');
  };
  DIRECT_V2_MILLER_EZ_COLUMNS.forEach((column, index) => {
    source.push(`        int ec${index} = (${polynomial(column)}) % P;`);
  });
  DIRECT_V2_MILLER_E6_COLUMNS.forEach((column, index) => {
    source.push(`        int ex${index} = (${polynomial(column)}) % P;`);
  });
  source.push(`        require(${dot(cNames)} == dotC);`);
  source.push(`        require(${dot(ciNames)} == dotCi);`);

  source.push('        int Ax = nAx; int Ay = (P - nAy) % P;');
  const statementTerms = [
    be('Ax'), be('Ay'),
    be('Bxa'), be('Bxb'), be('Bya'), be('Byb'),
    be('Cx'), be('Cy'),
    be('Qx'), be('Qy'),
    ...alpha.map((value) => be(value)),
    ...beta.map((value) => be(value)),
    ...gamma.map((value) => be(value)),
    ...delta.map((value) => be(value)),
    ...cNames.map(be),
    ...ciNames.map(be),
    ...wNames.map(be),
  ];
  source.push(`        bytes stmtBlock = ${balanced(statementTerms)};`);
  source.push(`        bytes h = hash256(0x${h0} + 0x00000000 + 0x00000780 + stmtBlock);`);
  source.push(`        bytes ris0 = ${balanced(ciNames.map(be))};`);
  source.push('        h = hash256(h + 0x00000001 + 0x00000180 + ris0);');
  source.push('        int aL = 0; int aF = 0; int gP = 1;');
  source.push(`        int fC = ${dot(ciNames)};`);
  source.push('        int pf0 = 1;');
  source.push('        (int v0,int v1,int v2,int v3,int v4,int v5,int v6,int v7,int v8,int v9) = affDbl(Bxa,Bxb,Bya,Byb,s0a,s0b);');
  source.push('        pf0 = mulFp(pf0, (mulFp(mulFp(v4,nAy),ex0) + mulFp(mulFp(v5,nAy),ex1) + mulFp(mulFp(v2,nAx),ex2) + mulFp(mulFp(v3,nAx),ex3) + mulFp(v0,ex4) + mulFp(v1,ex5)) % P);');
  source.push('        // gamma-line: the canonical identity branch omits this multiplicative factor.');
  source.push(`        if (qInf == 0) { pf0 = mulFp(pf0, ${lineEvaluation(fixed.gamma.coefficients, 'Qx', 'Qy')}); }`);
  source.push(`        pf0 = mulFp(pf0, ${lineEvaluation(fixed.delta.coefficients, 'Cx', 'Cy')});`);
  source.push(`        int fn0 = ${dot(endpointNames)};`);
  // Script's remainder keeps the dividend sign. A congruent negative pf0
  // therefore makes mulFp return a negative representative; canonicalize the
  // serialized boundary value so it matches the JS field encoding.
  source.push(
    '        aL = (mulFp(mulFp(fC, fC), pf0) + P) % P;',
  );
  source.push('        aF = fn0;');
  source.push('        gP = gammaW;');
  source.push(`        h = hash256(h + 0x00000002 + 0x00000180 + ${balanced(endpointNames.map(be))});`);
  source.push('        fC = fn0;');
  source.push('        int hOut = int(h + 0x00);');
  source.push('        bytes headBlob = toPaddedBytes(hOut,40)');
  source.push('            + toPaddedBytes(aL,32)');
  source.push('            + toPaddedBytes(aF,32)');
  source.push('            + toPaddedBytes(gP,32)');
  source.push('            + toPaddedBytes(fC,32)');
  source.push('            + toPaddedBytes(v6 % P,32)');
  source.push('            + toPaddedBytes(v7 % P,32)');
  source.push('            + toPaddedBytes(v8 % P,32)');
  source.push('            + toPaddedBytes(v9 % P,32);');
  source.push(`        bytes successorUnlock = tx.inputs[${executorHeadInputIndex}].unlockingBytecode;`);
  source.push('        bytes successorHeadHeader, bytes successorAfterHeadHeader = successorUnlock.split(3);');
  source.push('        require(successorHeadHeader == 0x4d2801);');
  source.push('        bytes successorHead, bytes successorRemainder = successorAfterHeadHeader.split(296);');
  source.push('        require(successorHead == headBlob && successorRemainder.length > 0);');
  source.push('    }');
  source.push('}');
  return `${source.join('\n')}\n`;
}

/**
 * Render only the Miller half of the distinct PF10-FusedQGenesis role 8.
 *
 * The executable PF10 redeem runs this component first, verifies its success,
 * then runs the final exact-MSM component against the arguments left beneath
 * it. `ownWitnessPayloadOffset` is the exact byte length of that lower MSM
 * argument prefix in role 8's unlocking bytecode.
 */
export function renderDirectV2Pf10FusedQGenesisMillerComponent({
  ownWitnessPayloadOffset,
  ...options
}) {
  return renderDirectV2IdentityAwareMillerGenesis({
    ...options,
    inputIndex: 8,
    sourceInputIndex: 8,
    executorHeadInputIndex: 0,
    successorInputIndex: 9,
    bindingInputIndex: 10,
    stateInputIndex: 11,
    expectedInputCount: 13,
    ownWitnessPayloadOffset,
  });
}
