import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  bigIntToVmNumber,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

import {
  xonlyStaticStepFSource,
} from '../vendor/verifier/lanes/bn254-onetx/src/c7/composed-window-kernel.mjs';
import {
  PSI_X,
  PSI_Y,
} from '../vendor/verifier/build/chunked/pairing/_millermath.mjs';
import {
  COSET27,
  fp12limbsOf,
} from '../vendor/verifier/build/chunked/pairing/_residuemath.mjs';
import {
  BN254_BASE_FIELD,
} from './exact-msm.mjs';
import {
  DIRECT_V2_MILLER_TAG_GAMMA_FINAL,
  DIRECT_V2_MILLER_TAG_Z,
} from './identity-aware-miller.mjs';
import {
  DIRECT_V2_PAIRFOLD_ENDPOINT_BYTES,
  DIRECT_V2_PAIRFOLD_RANGES,
  DIRECT_V2_PAIRFOLD_STATE_BYTES,
} from './total-pairfold.mjs';

const P = BN254_BASE_FIELD;
const HEX_35 = /^[0-9a-f]{70}$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const LAZY_AFFINE_LIBRARY = fileURLToPath(new URL(
  '../vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff.cash',
  import.meta.url,
));

export class DirectV2TotalPairFoldCashScriptError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2TotalPairFoldCashScriptError';
  }
}

const fail = (message) => {
  throw new DirectV2TotalPairFoldCashScriptError(message);
};

const mod = (value) => {
  const reduced = BigInt(value) % P;
  return reduced < 0n ? reduced + P : reduced;
};

const g2 = (point) => {
  const affine = point.toAffine();
  return Object.freeze({
    x0: mod(affine.x.c0),
    x1: mod(affine.x.c1),
    y0: mod(affine.y.c0),
    y1: mod(affine.y.c1),
  });
};

const balanced = (terms) => {
  if (terms.length === 0) return '0x';
  if (terms.length === 1) return terms[0];
  const middle = terms.length >> 1;
  return `(${balanced(terms.slice(0, middle))} + ${balanced(terms.slice(middle))})`;
};

const be = (expression) => `toPaddedBytes(${expression}, 32).reverse()`;

const polynomial = (coefficients, powers) => {
  const terms = coefficients.map((coefficient, index) =>
    mod(coefficient) === 0n
      ? null
      : `${mod(coefficient)} * ${powers[index]}`).filter(Boolean);
  return terms.length === 0 ? '0' : terms.join(' + ');
};

const zPrologue = () => {
  // e(z) is sparse in this BN254 basis:
  //   even limbs = [1,z^2,z^4,z,z^3,z^5]
  //   odd limbs  = -9 * even + the matching z^(degree+6).
  // The six e6 limbs consumed by the Miller fold are exact aliases
  // [ec0,ec1,ec6,ec7,ec8,ec9], so do not evaluate those polynomials twice.
  const lines = [
    'int Pm9 = P - 9;',
    'int zp0 = 1; int zp1 = zW;',
  ];
  for (let power = 2; power < 12; power += 1) {
    lines.push(`int zp${power} = mulFp(zp${power - 1}, zW);`);
  }
  lines.push('int ec0 = zp0; int ec1 = (Pm9 + zp6) % P;');
  lines.push('int ec2 = zp2; int ec3 = (Pm9 * zp2 + zp8) % P;');
  lines.push('int ec4 = zp4; int ec5 = (Pm9 * zp4 + zp10) % P;');
  lines.push('int ec6 = zp1; int ec7 = (Pm9 * zp1 + zp7) % P;');
  lines.push('int ec8 = zp3; int ec9 = (Pm9 * zp3 + zp9) % P;');
  lines.push('int ec10 = zp5; int ec11 = (Pm9 * zp5 + zp11) % P;');
  lines.push('int ex1 = ec1; int ex2 = ec6; int ex3 = ec7; int ex4 = ec8; int ex5 = ec9;');
  lines.push('int kn0 = nAy; int kn1 = mulFp(nAy,ex1); int kn2 = mulFp(nAx,ex2); int kn3 = mulFp(nAx,ex3);');
  lines.push('int kv0 = Qy; int kv1 = mulFp(Qy,ex1); int kv2 = mulFp(Qx,ex2); int kv3 = mulFp(Qx,ex3);');
  lines.push('int kc0 = Cy; int kc1 = mulFp(Cy,ex1); int kc2 = mulFp(Cx,ex2); int kc3 = mulFp(Cx,ex3);');
  return lines.join('\n        ');
};

const fold1Source = () => `function fold1(int Pm,int pf,
        int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,
        int kye0,int kye1,int kxe2,int kxe3,int ex4,int ex5)
    returns (int) {
    return (pf * (c2a*kye0 + c2b*kye1 + c1a*kxe2 + c1b*kxe3 + c0a*ex4 + c0b*ex5)) % Pm;
}`;

// The density library's historical `affDbl`/`affAdd` helpers intentionally
// omit proof-derived slope checks. Never call them directly for pair 0.
// These wrappers restore the exact division-free relations, then reuse the
// library only for the derived coordinates and line coefficients.
const checkedAffineSource = () => `function checkedAffDbl(int xa,int xb,int ya,int yb,int la,int lb)
    returns (int,int,int,int,int,int,int,int,int,int) {
    int Pm = ${P};
    (int x2a,int x2b) = fp2Sqr(xa,xb);
    (int cka,int ckb) = fp2Mul(la,lb,ya+ya,yb+yb);
    require((cka - (x2a+x2a+x2a)) % Pm == 0);
    require((ckb - (x2b+x2b+x2b)) % Pm == 0);
    (int o0,int o1,int o2,int o3,int o4,int o5,int o6,int o7,int o8,int o9) =
        affDbl(xa,xb,ya,yb,la,lb);
    return o0,o1,o2,o3,o4,o5,o6,o7,o8,o9;
}
function checkedAffAdd(int rxa,int rxb,int rya,int ryb,
        int qxa,int qxb,int qya,int qyb,int la,int lb)
    returns (int,int,int,int,int,int,int,int,int,int) {
    int Pm = ${P};
    int t1a = rxa-qxa+64*Pm; int t1b = rxb-qxb+64*Pm;
    int t0a = rya-qya+64*Pm; int t0b = ryb-qyb+64*Pm;
    (int cka,int ckb) = fp2Mul(la,lb,t1a,t1b);
    require((cka-t0a) % Pm == 0); require((ckb-t0b) % Pm == 0);
    (int o0,int o1,int o2,int o3,int o4,int o5,int o6,int o7,int o8,int o9) =
        affAdd(rxa,rxb,rya,ryb,qxa,qxb,qya,qyb,la,lb);
    return o0,o1,o2,o3,o4,o5,o6,o7,o8,o9;
}`;

const totalStaticStepSource = (verificationKey) => {
  const gamma = g2(verificationKey.gamma);
  const delta = g2(verificationKey.delta);
  const replacements = new Map([
    ['13700863412905423759250606799218875849166292978636329233814994817818554546431', gamma.x0.toString()],
    ['21761028412726985313317130874134828290145951226051416150723277301116006118078', gamma.x1.toString()],
    ['21547676276454546410296902538495425432829390494566673627605034971294784210249', gamma.y0.toString()],
    ['6398877257285935365249802814125273995578953055511620955996813742572019651748', gamma.y1.toString()],
    ['15825285363846036862295217228464959249112247579247978462621447842724817286232', delta.x0.toString()],
    ['3543600181522862329564888283473085279940669956506060026762005346996341806108', delta.x1.toString()],
    ['21514667205241674535457714632061047258097217169787877277363751636045743019390', delta.y0.toString()],
    ['10670741793215758088800930336726579942257175283397977169474518534600570072949', delta.y1.toString()],
  ]);
  let source = xonlyStaticStepFSource()
    .replace(
      'int ex4,int ex5, int mode, bytes wdat, bytes fixedLines,',
      'int ex4,int ex5, int qInf, int mode, bytes wdat, bytes fixedLines,',
    );
  source = source
    .replaceAll('= affDbl(', '= checkedAffDbl(')
    .replaceAll('= affAdd(', '= checkedAffAdd(');
  for (const [from, to] of replacements) source = source.replaceAll(from, to);
  const gammaDouble = 'pf = fold1(Pm, pf, b0,b1,b2,b3,b4,b5, kv0,kv1,kv2,kv3, ex4,ex5);';
  const gammaAdd = 'pf = fold1(Pm, pf, bb0,bb1,bb2,bb3,bb4,bb5, kv0,kv1,kv2,kv3, ex4,ex5);';
  if (!source.includes(gammaDouble) || !source.includes(gammaAdd)) {
    fail('x-only fixed-G2 source shape changed');
  }
  source = source
    .replace(gammaDouble, `if (qInf == 0) { ${gammaDouble} }`)
    .replace(gammaAdd, `if (qInf == 0) { ${gammaAdd} }`);
  return source;
};

const splitFieldSource = (root, names, prefix) => {
  let rest = root;
  const lines = [];
  names.forEach((name, index) => {
    const next = `${prefix}R${index}`;
    lines.push(
      `bytes ${prefix}B${index}, bytes ${next} = ${rest}.split(32); int ${name} = int(${prefix}B${index});`,
    );
    rest = next;
  });
  return { lines, rest };
};

const precomputedStaticStepSource = () => {
  const doubles = splitFieldSource(
    'fixedLines',
    [
      'b0', 'b1', 'b2', 'b3', 'b4', 'b5',
      'uo0', 'uo1', 'uo2', 'uo3', 'uo4', 'uo5',
    ],
    'fd',
  );
  const adds = splitFieldSource(
    doubles.rest,
    [
      'bb0', 'bb1', 'bb2', 'bb3', 'bb4', 'bb5',
      'uu0', 'uu1', 'uu2', 'uu3', 'uu4', 'uu5',
    ],
    'fa',
  );
  return `function staticStepF(int dotC,int dotCi,
        int rxa,int rxb,int rya,int ryb,
        int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3,
        int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,
        int ex4,int ex5, int qInf, int mode, bytes wdat, bytes fixedLines,
        int gx0,int gx1,int dx0,int dx1)
    returns (int, int,int,int,int, int,int,int,int) {
    int Pm = ${P};
    bytes wdatc = wdat;
    bytes sdaBytes, bytes sdaRest = wdatc.split(32); int sda = int(sdaBytes); wdatc = sdaRest;
    bytes sdbBytes, bytes sdbRest = wdatc.split(32); int sdb = int(sdbBytes); wdatc = sdbRest;
    int saa = 0; int sab = 0;
    if (mode >= 1) {
        bytes saaBytes, bytes saaRest = wdatc.split(32); saa = int(saaBytes); wdatc = saaRest;
        bytes sabBytes, bytes sabRest = wdatc.split(32); sab = int(sabBytes); wdatc = sabRest;
    }
    require(wdatc.length == 0);
    int pf = 1; if (mode == 1) { pf = dotC; } if (mode == 2) { pf = dotCi; }
    (int a0,int a1,int a2,int a3,int a4,int a5,
     int R0,int R1,int R2,int R3) =
        checkedAffDbl(rxa,rxb,rya,ryb,sda,sdb);
    pf = fold1(Pm,pf,a0,a1,a2,a3,a4,a5,
      kn0,kn1,kn2,kn3,ex4,ex5);
    ${doubles.lines.join('\n    ')}
    if (qInf == 0) {
        pf = fold1(Pm,pf,b0,b1,b2,b3,b4,b5,
          kv0,kv1,kv2,kv3,ex4,ex5);
    }
    pf = fold1(Pm,pf,uo0,uo1,uo2,uo3,uo4,uo5,
      kc0,kc1,kc2,kc3,ex4,ex5);
    if (mode >= 1) {
        int qy0a = Bya; int qy0b = Byb;
        if (mode == 1) {
            qy0a = (Pm - Bya) % Pm;
            qy0b = (Pm - Byb) % Pm;
        }
        (int aa0,int aa1,int aa2,int aa3,int aa4,int aa5,
         int rr0,int rr1,int rr2,int rr3) =
            checkedAffAdd(R0,R1,R2,R3,Bxa,Bxb,qy0a,qy0b,saa,sab);
        pf = fold1(Pm,pf,aa0,aa1,aa2,aa3,aa4,aa5,
          kn0,kn1,kn2,kn3,ex4,ex5);
        R0=rr0;R1=rr1;R2=rr2;R3=rr3;
        ${adds.lines.join('\n        ')}
        if (qInf == 0) {
            pf = fold1(Pm,pf,bb0,bb1,bb2,bb3,bb4,bb5,
              kv0,kv1,kv2,kv3,ex4,ex5);
        }
        pf = fold1(Pm,pf,uu0,uu1,uu2,uu3,uu4,uu5,
          kc0,kc1,kc2,kc3,ex4,ex5);
        require(${adds.rest}.length == 0);
    }
    if (mode == 0) { require(${doubles.rest}.length == 0); }
    pf = (pf + Pm) % Pm;
    return pf,R0,R1,R2,R3,gx0,gx1,dx0,dx1;
}`;
};

const parseContext = () => {
  const names = [
    'gammaW', 'zW', 'nAx', 'nAy', 'Qx', 'Qy', 'Cx', 'Cy',
    'Bxa', 'Bxb', 'Bya', 'Byb', 'dotC', 'dotCi',
  ];
  let rest = 'projectionContext';
  const lines = [];
  names.forEach((name, index) => {
    const next = `ctxR${index}`;
    lines.push(`bytes ctx${index}, bytes ${next} = ${rest}.split(32); int ${name} = int(ctx${index});`);
    rest = next;
  });
  lines.push(`require(${rest}.length == 0);`);
  return lines.join('\n        ');
};

const parseState = () => {
  const names = ['hInt', 'aggL', 'aggF', 'gp', 'fC', 'Rxa', 'Rxb', 'Rya', 'Ryb'];
  const widths = [40, ...Array(8).fill(32)];
  let rest = 'stateBlob';
  const lines = [];
  names.forEach((name, index) => {
    const next = `stateR${index}`;
    lines.push(`bytes state${index}, bytes ${next} = ${rest}.split(${widths[index]}); int ${name} = int(state${index});`);
    rest = next;
  });
  lines.push(`require(${rest}.length == 0);`);
  return lines.join('\n        ');
};

const modePack = (modes) => modes.reduce(
  (packed, mode, index) => packed | (BigInt(mode) << BigInt(index * 2)),
  0n,
);

const roleSelect = (name, values) => [
  `int ${name} = ${values[0]};`,
  ...values.slice(1).map(
    (value, index) => `if (role == ${index + 1}) { ${name} = ${value}; }`,
  ),
].join('\n        ');

const endpointParser = (prefix, root) => {
  let rest = root;
  const lines = [];
  const names = [];
  for (let index = 0; index < 12; index += 1) {
    const name = `${prefix}${index}`;
    const next = `${prefix}R${index}`;
    lines.push(`bytes ${prefix}B${index}, bytes ${next} = ${rest}.split(32); int ${name} = int(${prefix}B${index});`);
    names.push(name);
    rest = next;
  }
  lines.push(`require(${rest}.length == 0);`);
  return { lines, names };
};

const endpointDot = (names) =>
  `(${names.map((name, index) => `${name} * ec${index}`).join(' + ')}) % P`;

const endpointBytes = (names) => balanced(names.map(be));

const sharedPairSource = ({ precomputedFixedLines = false } = {}) => {
  const endpoint = endpointParser('ep', 'endpoint');
  const fixedDoubleBytes = precomputedFixedLines ? 384 : 128;
  const fixedAddBytes = precomputedFixedLines ? 768 : 256;
  return `function sharedPair(int aggL,int aggF,int gp,int fC,bytes h,int gammaW,int qInf,
        int dotC,int dotCi,int curRxa,int curRxb,int curRya,int curRyb,
        int kn0,int kn1,int kn2,int kn3,int kv0,int kv1,int kv2,int kv3,
        int kc0,int kc1,int kc2,int kc3,
        int Bxa,int Bxb,int Bya,int Byb,
        int ec0,int ec1,int ec2,int ec3,int ec4,int ec5,
        int ec6,int ec7,int ec8,int ec9,int ec10,int ec11,
        int ex4,int ex5,int modeA,int modeB,bytes records,bytes fixedLines,
        int blockIndex,int gx0,int gx1,int dx0,int dx1)
    returns (int,int,int,int,bytes,int,int,int,int,bytes,bytes,int,int,int,int) {
    int P = ${P};
    int wdABytes = 64; int wdBBytes = 64;
    int fixedABytes = ${fixedDoubleBytes}; int fixedBBytes = ${fixedDoubleBytes};
    if (modeA >= 1) { wdABytes = 128; fixedABytes = ${fixedAddBytes}; }
    if (modeB >= 1) { wdBBytes = 128; fixedBBytes = ${fixedAddBytes}; }
    bytes wdA, bytes afterWdA = records.split(wdABytes);
    bytes fixedA, bytes afterFixedA = fixedLines.split(fixedABytes);
    bytes wdB, bytes afterWdB = afterWdA.split(wdBBytes);
    bytes fixedB, bytes afterFixedB = afterFixedA.split(fixedBBytes);
    bytes endpoint, bytes afterEndpoint = afterWdB.split(${DIRECT_V2_PAIRFOLD_ENDPOINT_BYTES});
    ${endpoint.lines.join('\n    ')}
    (int pfA,int midA,int midB,int midC,int midD,int gxA0,int gxA1,int dxA0,int dxA1) =
        staticStepF(dotC,dotCi,curRxa,curRxb,curRya,curRyb,
          kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,
          Bxa,Bxb,Bya,Byb,ex4,ex5,qInf,modeA,wdA,fixedA,gx0,gx1,dx0,dx1);
    (int pfB,int outA,int outB,int outC,int outD,int gxB0,int gxB1,int dxB0,int dxB1) =
        staticStepF(dotC,dotCi,midA,midB,midC,midD,
          kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,
          Bxa,Bxb,Bya,Byb,ex4,ex5,qInf,modeB,wdB,fixedB,gxA0,gxA1,dxA0,dxA1);
    int inner = (((fC*fC) % P) * pfA) % P;
    int product = (((inner*inner) % P) * pfB) % P;
    int fn = ${endpointDot(endpoint.names)};
    aggL = (aggL + (gp*product) % P) % P;
    aggF = (aggF + (gp*fn) % P) % P;
    gp = (gp*gammaW) % P;
    h = hash256(h + toPaddedBytes(blockIndex,4).reverse() + 0x00000180 + ${endpointBytes(endpoint.names)});
    return aggL,aggF,gp,fn,h,outA,outB,outC,outD,afterEndpoint,afterFixedB,gxB0,gxB1,dxB0,dxB1;
}`;
};

const fixedTableCarrierSource = (fixedTableCarriers) => {
  const roleBlocks = fixedTableCarriers.map((slices, role) => {
    const names = slices.map((_, index) => `remoteFixed${role}_${index}`);
    const loads = slices.map((slice, index) =>
      `bytes ${names[index]} = tx.inputs[${slice.inputIndex}].unlockingBytecode.split(${slice.payloadOffset})[1].split(${slice.length})[0];`);
    return `if (role == ${role}) {
            ${loads.join('\n            ')}
            remoteFixedLines = ${balanced(names)};
        }`;
  });
  return `bytes remoteFixedLines = 0x;
        ${roleBlocks.join('\n        ')}
        bytes fixedTable = fixedLines + remoteFixedLines;`;
};

/**
 * Render the shared executable body for PairFold roles 0..4.
 *
 * The returned source is invoked behind a small P2SH32 loader. The loader
 * reconstructs and hash-pins this body from five exact scriptSig fragments,
 * while this function verifies the proof-dependent state/records and the
 * VK-fixed x-only tables.
 */
export function renderDirectV2TotalPairFoldExecutor({
  verificationKey,
  template,
  terminalLockingBytecodeHex,
  stateCategoryHex,
  bqShardBytes,
  terminalInputIndex = 10,
  stateInputIndex = 12,
  projectionInputIndex = 8,
  fixedTableCarriers = null,
  libraryImportPath = LAZY_AFFINE_LIBRARY,
}) {
  if (!template?.roles || template.roles.length !== 5) {
    fail('PairFold executor renderer requires one five-role witness template');
  }
  if (!HEX_35.test(terminalLockingBytecodeHex)) {
    fail('terminalLockingBytecodeHex must contain exactly 35 lowercase hexadecimal bytes');
  }
  if (!HEX_32.test(stateCategoryHex)) {
    fail('stateCategoryHex must contain exactly 32 lowercase hexadecimal bytes');
  }
  for (const [value, label] of [
    [terminalInputIndex, 'terminalInputIndex'],
    [stateInputIndex, 'stateInputIndex'],
    [projectionInputIndex, 'projectionInputIndex'],
  ]) {
    if (!Number.isInteger(value) || value < 0) {
      fail(`${label} must be a nonnegative integer`);
    }
  }
  if (
    !Array.isArray(bqShardBytes)
    || bqShardBytes.length !== 5
    || bqShardBytes.some((length) => !Number.isInteger(length) || length < 1)
  ) {
    fail('bqShardBytes must contain five positive fixed lengths');
  }
  const precomputedFixedLines =
    template.fixedLineFormat === 'precomputed-full';
  if (
    template.fixedLineFormat !== 'xonly-slopes'
    && !precomputedFixedLines
  ) {
    fail('PairFold template has an unsupported fixed-line format');
  }
  if (precomputedFixedLines) {
    if (
      !Array.isArray(fixedTableCarriers)
      || fixedTableCarriers.length !== 5
    ) {
      fail('precomputed PairFold requires five fixed-table carrier layouts');
    }
    fixedTableCarriers.forEach((slices, role) => {
      if (
        !Array.isArray(slices)
        || slices.length < 1
        || slices.some((slice) =>
          !Number.isInteger(slice?.inputIndex)
          || slice.inputIndex < 0
          || !Number.isInteger(slice.payloadOffset)
          || slice.payloadOffset < 0
          || !Number.isInteger(slice.length)
          || slice.length < 1
          || slice.payloadOffset + slice.length > 10_000)
      ) {
        fail(`precomputed PairFold role ${role} has an invalid carrier slice`);
      }
      const carriedBytes = slices.reduce(
        (sum, slice) => sum + slice.length,
        0,
      );
      if (carriedBytes !== template.roles[role].remoteTable?.length) {
        fail(`precomputed PairFold role ${role} carrier length mismatch`);
      }
    });
  } else if (fixedTableCarriers !== null) {
    fail('x-only PairFold does not accept fixed-table carriers');
  }
  const modes = template.roles.map((role) => role.modes);
  const packs = modes.map(modePack);
  const pairCounts = [6, 6, 6, 6, 7];
  const pairStarts = template.roles.map((role, index) =>
    role.endpointBlocks[index === 0 ? 1 : 0]);
  const tableHashes = template.roles.map((role) => role.tableHash256);
  if (tableHashes.some((hash) => !HEX_32.test(hash))) {
    fail('PairFold template contains an invalid table hash');
  }
  const tableChecks = tableHashes.map(
    (hash, role) =>
      `if (role == ${role}) { require(hash256(${precomputedFixedLines ? 'fixedTable' : 'fixedLines'}) == 0x${hash}); }`,
  ).join('\n        ');
  const counts = (name, values) => roleSelect(name, values);

  const singletonEndpoint = endpointParser('singleEp', 'singleEndpoint');
  const singleFixedDoubleBytes = precomputedFixedLines ? 384 : 128;
  const singleFixedAddBytes = precomputedFixedLines ? 768 : 256;
  const singleton = `if (role == 0) {
            int singleMode = modePack % 4;
            int singleWdBytes = 64; int singleFixedBytes = ${singleFixedDoubleBytes};
            if (singleMode >= 1) { singleWdBytes = 128; singleFixedBytes = ${singleFixedAddBytes}; }
            bytes singleWd, bytes singleAfterWd = recordsRem.split(singleWdBytes);
            bytes singleFixed, bytes singleAfterFixed = fixedRem.split(singleFixedBytes);
            bytes singleEndpoint, bytes singleAfterEndpoint = singleAfterWd.split(384);
            ${singletonEndpoint.lines.join('\n            ')}
            (int singlePf,int singleOutA,int singleOutB,int singleOutC,int singleOutD,
             int sgx0,int sgx1,int sdx0,int sdx1) =
                staticStepF(dotC,dotCi,curRxa,curRxb,curRya,curRyb,
                  kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,
                  Bxa,Bxb,Bya,Byb,ex4,ex5,qInf,singleMode,singleWd,singleFixed,gx0,gx1,dx0,dx1);
            int singleProduct = (((fC*fC) % P) * singlePf) % P;
            int singleFn = ${endpointDot(singletonEndpoint.names)};
            aggL = (aggL + (gp*singleProduct) % P) % P;
            aggF = (aggF + (gp*singleFn) % P) % P;
            gp = (gp*gammaW) % P; fC = singleFn;
            h = hash256(h + 0x00000003 + 0x00000180 + ${endpointBytes(singletonEndpoint.names)});
            curRxa=singleOutA;curRxb=singleOutB;curRya=singleOutC;curRyb=singleOutD;
            gx0=sgx0;gx1=sgx1;dx0=sdx0;dx1=sdx1;
            recordsRem=singleAfterEndpoint;fixedRem=singleAfterFixed;
        }`;

  const calls = Array.from({ length: 7 }, (_, pair) => {
    const call = `int mode${pair}a = (modePack >> (modeOffset + ${pair * 4})) % 4;
            int mode${pair}b = (modePack >> (modeOffset + ${pair * 4 + 2})) % 4;
            (int naL${pair},int naF${pair},int ngp${pair},int nfC${pair},bytes nh${pair},
             int nrxa${pair},int nrxb${pair},int nrya${pair},int nryb${pair},
             bytes nrec${pair},bytes nfix${pair},int ngx0${pair},int ngx1${pair},int ndx0${pair},int ndx1${pair}) =
                sharedPair(aggL,aggF,gp,fC,h,gammaW,qInf,dotC,dotCi,
                  curRxa,curRxb,curRya,curRyb,
                  kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,
                  Bxa,Bxb,Bya,Byb,ec0,ec1,ec2,ec3,ec4,ec5,ec6,ec7,ec8,ec9,ec10,ec11,
                  ex4,ex5,mode${pair}a,mode${pair}b,recordsRem,fixedRem,
                  pairBlockStart + ${pair},gx0,gx1,dx0,dx1);
            aggL=naL${pair};aggF=naF${pair};gp=ngp${pair};fC=nfC${pair};h=nh${pair};
            curRxa=nrxa${pair};curRxb=nrxb${pair};curRya=nrya${pair};curRyb=nryb${pair};
            recordsRem=nrec${pair};fixedRem=nfix${pair};
            gx0=ngx0${pair};gx1=ngx1${pair};dx0=ndx0${pair};dx1=ndx1${pair};`;
    return pair < 6 ? call : `if (pairCount == 7) {\n            ${call}\n        }`;
  }).join('\n        ');
  const fixedTableSetup = precomputedFixedLines
    ? `int gx0=0;int gx1=0;int dx0=0;int dx1=0;
        bytes fixedRem = fixedTable;`
    : `bytes gx0b, bytes seedR0 = fixedLines.split(32); int gx0 = int(gx0b);
        bytes gx1b, bytes seedR1 = seedR0.split(32); int gx1 = int(gx1b);
        bytes dx0b, bytes seedR2 = seedR1.split(32); int dx0 = int(dx0b);
        bytes dx1b, bytes seedR3 = seedR2.split(32); int dx1 = int(dx1b);
        bytes fixedRem = seedR3;`;

  return `pragma cashscript ^0.14.0;
import "${libraryImportPath.replaceAll('\\', '/')}";
contract DirectV2TotalPairFoldExecutor() {
    function spend(bytes fixedLines,bytes records,bytes stateBlob) {
        int P = ${P};
        int role = this.activeInputIndex; require(role < 5);
        // The unique mutable state NFT authenticates the state helper, which
        // owns the exact input-count/outpoint/common-parent checks. Keep
        // only the directional verifier-lock edges here.
        if (role < 4) {
            require(tx.inputs[role + 1].lockingBytecode == tx.inputs[role].lockingBytecode);
        }
        if (role == 4) { require(tx.inputs[${terminalInputIndex}].lockingBytecode == 0x${terminalLockingBytecodeHex}); }
        require(tx.inputs[${stateInputIndex}].tokenCategory == 0x${stateCategoryHex}01);
        // The predecessor edge authenticates the canonical first state push;
        // CashScript's argument stack supplies that same item as stateBlob.
        bytes projectionHeader, bytes projectionAfterHeader = tx.inputs[${projectionInputIndex}].unlockingBytecode.split(3);
        require(projectionHeader == 0x4de001);
        bytes projectionSignal = projectionAfterHeader.split(480)[0];
        bytes projectionContext = projectionSignal.split(448)[0];
        ${parseContext()}
        int qInf = 0; if (Qx == 0 && Qy == 0) { qInf = 1; }
        ${parseState()}
        bytes h = toPaddedBytes(hInt,40).split(32)[0];
        ${zPrologue()}
        ${counts('modePack', packs)}
        ${counts('pairBlockStart', pairStarts)}
        ${counts('pairCount', pairCounts)}
        ${precomputedFixedLines
    ? fixedTableCarrierSource(fixedTableCarriers)
    : ''}
        ${tableChecks}
        ${fixedTableSetup}
        bytes recordsRem = records;
        int curRxa=Rxa;int curRxb=Rxb;int curRya=Rya;int curRyb=Ryb;
        int modeOffset = 0; if (role == 0) { modeOffset = 2; }
        ${singleton}
        ${calls}
        require(recordsRem.length == 0 && fixedRem.length == 0);
        bytes outBlob = toPaddedBytes(int(h + 0x00),40)
          + toPaddedBytes(aggL % P,32)+toPaddedBytes(aggF % P,32)
          + toPaddedBytes(gp % P,32)+toPaddedBytes(fC % P,32)
          + toPaddedBytes(curRxa % P,32)+toPaddedBytes(curRxb % P,32)
          + toPaddedBytes(curRya % P,32)+toPaddedBytes(curRyb % P,32);
        int successor = role + 1; if (role == 4) { successor = ${terminalInputIndex}; }
        bytes nextHeader, bytes nextAfterHeader = tx.inputs[successor].unlockingBytecode.split(3);
        require(nextHeader == 0x4d2801);
        bytes expectedOut = nextAfterHeader.split(${DIRECT_V2_PAIRFOLD_STATE_BYTES})[0];
        require(outBlob == expectedOut);
    }
}
${sharedPairSource({ precomputedFixedLines })}
${fold1Source()}
${checkedAffineSource()}
${precomputedFixedLines
    ? precomputedStaticStepSource()
    : totalStaticStepSource(verificationKey)}
`;
}

const fp2 = (value) => Object.freeze([
  mod(value.c0),
  mod(value.c1),
]);

const parseLeFieldsSource = (root, names, prefix) => {
  let rest = root;
  return names.map((name, index) => {
    if (index === names.length - 1) {
      return `int ${name} = int(${rest});`;
    }
    const next = `${prefix}R${index}`;
    const line = `bytes ${prefix}B${index}, bytes ${next} = ${rest}.split(32); int ${name} = int(${prefix}B${index});`;
    rest = next;
    return line;
  }).join('\n        ');
};

const parseBeFieldsSource = (root, names, prefix) => {
  let rest = root;
  return names.map((name, index) => {
    if (index === names.length - 1) {
      return `int ${name} = int(${rest}.reverse() + 0x00);`;
    }
    const next = `${prefix}R${index}`;
    const line = `bytes ${prefix}B${index}, bytes ${next} = ${rest}.split(32); int ${name} = int(${prefix}B${index}.reverse() + 0x00);`;
    rest = next;
    return line;
  }).join('\n        ');
};

const fp12Decl = (prefix) =>
  Array.from({ length: 12 }, (_, index) => `int ${prefix}${index}`).join(',');

const fp12Names = (prefix) =>
  Array.from({ length: 12 }, (_, index) => `${prefix}${index}`);

const rootMatch = (names, values) =>
  `(${names.map((name, index) => `${name} == ${values[index]}`).join(' && ')})`;

/**
 * Render PF11 input 10: total step 64, final transcript/S-Z closure, and the
 * canonical residue-tail relation. The 6,080-byte quotient is reconstructed
 * from exact slices in executor inputs 0..4; it is never accepted as a scalar
 * supplied after z is known.
 */
export function renderDirectV2TotalPairFoldTerminal({
  verificationKey,
  template,
  stateCategoryHex,
  bqShards,
  terminalInputIndex = 10,
  stateInputIndex = 12,
  projectionInputIndex = 8,
  residueInputIndex = 9,
  residuePayloadOffset = 455,
  libraryImportPath = LAZY_AFFINE_LIBRARY,
}) {
  if (
    !template?.terminal
    || template.terminal.state?.length !== DIRECT_V2_PAIRFOLD_STATE_BYTES
    || template.terminal.records?.length !== 576
    || template.terminal.table?.length !== 768
    || template.terminal.bigQ?.length !== 6_080
    || template.terminal.fAB?.length !== 12
  ) {
    fail('PairFold terminal renderer requires one complete total witness template');
  }
  if (!HEX_32.test(stateCategoryHex)) {
    fail('stateCategoryHex must contain exactly 32 lowercase hexadecimal bytes');
  }
  for (const [value, label] of [
    [terminalInputIndex, 'terminalInputIndex'],
    [stateInputIndex, 'stateInputIndex'],
    [projectionInputIndex, 'projectionInputIndex'],
    [residueInputIndex, 'residueInputIndex'],
    [residuePayloadOffset, 'residuePayloadOffset'],
  ]) {
    if (!Number.isInteger(value) || value < 0) {
      fail(`${label} must be a nonnegative integer`);
    }
  }
  if (
    !Array.isArray(bqShards)
    || bqShards.length !== 5
    || bqShards.some((shard, index) =>
      shard?.inputIndex !== index
      || !Number.isInteger(shard.offset)
      || shard.offset < 0
      || !Number.isInteger(shard.length)
      || shard.length < 1)
    || bqShards.reduce((sum, shard) => sum + shard.length, 0) !== 6_080
  ) {
    fail('PairFold terminal requires five ordered exact BQ slices totaling 6080 bytes');
  }
  if (!HEX_32.test(template.terminal.tableHash256)) {
    fail('PairFold terminal table hash is invalid');
  }

  const psiX = fp2(PSI_X);
  const psiY = fp2(PSI_Y);
  const one = ['1', ...Array(11).fill('0')];
  const root = fp12limbsOf(COSET27[1]).map((value) => mod(value).toString());
  const root2 = fp12limbsOf(COSET27[2]).map((value) => mod(value).toString());
  const c = fp12Names('c');
  const ci = fp12Names('ci');
  const w = fp12Names('w');
  const endpoint = fp12Names('ep');
  const fAbZ = polynomial(template.terminal.fAB, fp12Names('ec'));
  const bqLoads = bqShards.map((shard, index) =>
    `bytes bqS${index} = tx.inputs[${shard.inputIndex}].unlockingBytecode.split(${shard.offset})[1].split(${shard.length})[0];`,
  ).join('\n        ');
  const bqBlob = balanced(bqShards.map((_, index) => `bqS${index}`));
  const fixedPpNames = [
    'g10a', 'g10b', 'g11a', 'g11b',
    'g20a', 'g20b', 'g21a', 'g21b',
    'd10a', 'd10b', 'd11a', 'd11b',
    'd20a', 'd20b', 'd21a', 'd21b',
  ];
  const terminalEndpoint = endpointParser('ep', 'endpointBlob');

  return `pragma cashscript ^0.14.0;
import "${libraryImportPath.replaceAll('\\', '/')}";
contract DirectV2TotalPairFoldTerminal() {
    function spend(bytes unused densityPad,bytes fixedLines,bytes records,bytes stateBlob) {
        int P = ${P};
        require(this.activeInputIndex == ${terminalInputIndex});
        require(tx.inputs[${stateInputIndex}].tokenCategory == 0x${stateCategoryHex}01);
        require(stateBlob.length == ${DIRECT_V2_PAIRFOLD_STATE_BYTES});
        require(records.length == 576);
        require(fixedLines.length == 768);
        require(hash256(fixedLines) == 0x${template.terminal.tableHash256});

        bytes projectionHeader, bytes projectionAfterHeader = tx.inputs[${projectionInputIndex}].unlockingBytecode.split(3);
        require(projectionHeader == 0x4de001);
        bytes projectionSignal = projectionAfterHeader.split(480)[0];
        bytes projectionContext, bytes actionDigest = projectionSignal.split(448);
        require(actionDigest.length == 32);
        ${parseContext()}
        int qInf = 0; if (Qx == 0 && Qy == 0) { qInf = 1; }
        ${parseState()}
        bytes h = toPaddedBytes(hInt,40).split(32)[0];
        ${zPrologue()}

        bytes gx0b, bytes seedR0 = fixedLines.split(32); int gx0 = int(gx0b);
        bytes gx1b, bytes seedR1 = seedR0.split(32); int gx1 = int(gx1b);
        bytes dx0b, bytes seedR2 = seedR1.split(32); int dx0 = int(dx0b);
        bytes dx1b, bytes seedR3 = seedR2.split(32); int dx1 = int(dx1b);
        bytes doubleFixed, bytes ppFixed = seedR3.split(128);
        ${parseLeFieldsSource('ppFixed', fixedPpNames, 'fx')}

        bytes doubleRecord, bytes afterDoubleRecord = records.split(64);
        bytes ppRecord, bytes endpointBlob = afterDoubleRecord.split(128);
        ${parseLeFieldsSource('ppRecord', ['l1a', 'l1b', 'l2a', 'l2b'], 'pr')}
        ${terminalEndpoint.lines.join('\n        ')}

        (int pf,int drxa,int drxb,int drya,int dryb,
         int tgx0,int tgx1,int tdx0,int tdx1) =
            staticStepF(dotC,dotCi,Rxa,Rxb,Rya,Ryb,
              kn0,kn1,kn2,kn3,kv0,kv1,kv2,kv3,kc0,kc1,kc2,kc3,
              Bxa,Bxb,Bya,Byb,ex4,ex5,qInf,0,doubleRecord,doubleFixed,
              gx0,gx1,dx0,dx1);
        require(tgx0 >= 0 && tgx1 >= 0 && tdx0 >= 0 && tdx1 >= 0);

        (int cbx0,int cbx1) = fp2Conj(Bxa,Bxb,64);
        (int q1xa,int q1xb) = fp2Mul(cbx0,cbx1,${psiX[0]},${psiX[1]});
        (int cby0,int cby1) = fp2Conj(Bya,Byb,64);
        (int q1ya,int q1yb) = fp2Mul(cby0,cby1,${psiY[0]},${psiY[1]});
        (int cq1x0,int cq1x1) = fp2Conj(q1xa,q1xb,64);
        (int q2xa,int q2xb) = fp2Mul(cq1x0,cq1x1,${psiX[0]},${psiX[1]});
        (int cq1y0,int cq1y1) = fp2Conj(q1ya,q1yb,64);
        (int q2ypa,int q2ypb) = fp2Mul(cq1y0,cq1y1,${psiY[0]},${psiY[1]});
        (int q2ya,int q2yb) = fp2Neg(q2ypa,q2ypb,64);

        (int v10,int v11,int v12,int v13,int v14,int v15,
         int r1xa,int r1xb,int r1ya,int r1yb) =
            checkedAffAdd(drxa,drxb,drya,dryb,q1xa,q1xb,q1ya,q1yb,l1a,l1b);
        pf = fold1(P,pf,v10,v11,v12,v13,v14,v15,
          kn0,kn1,kn2,kn3,ex4,ex5);
        if (qInf == 0) {
            pf = fold1(P,pf,g10a,g10b,g11a,g11b,1,0,
              kv0,kv1,kv2,kv3,ex4,ex5);
        }
        pf = fold1(P,pf,d10a,d10b,d11a,d11b,1,0,
          kc0,kc1,kc2,kc3,ex4,ex5);

        (int v20,int v21,int v22,int v23,int v24,int v25,
         int r2xa,int r2xb,int r2ya,int r2yb) =
            checkedAffAdd(r1xa,r1xb,r1ya,r1yb,q2xa,q2xb,q2ya,q2yb,l2a,l2b);
        pf = fold1(P,pf,v20,v21,v22,v23,v24,v25,
          kn0,kn1,kn2,kn3,ex4,ex5);
        if (qInf == 0) {
            pf = fold1(P,pf,g20a,g20b,g21a,g21b,1,0,
              kv0,kv1,kv2,kv3,ex4,ex5);
        }
        pf = fold1(P,pf,d20a,d20b,d21a,d21b,1,0,
          kc0,kc1,kc2,kc3,ex4,ex5);
        require(r2xa >= 0 && r2xb >= 0 && r2ya >= 0 && r2yb >= 0);
        int fAbZ = (${fAbZ}) % P;
        pf = mulFp(pf,fAbZ);

        int product = mulFp(mulFp(fC,fC),pf);
        int fn = ${endpointDot(endpoint)};
        int finalAggL = (aggL + mulFp(gp,product)) % P;
        int finalAggF = (aggF + mulFp(gp,fn)) % P;
        h = hash256(h + 0x00000023 + 0x00000180 + ${endpointBytes(endpoint)});
        h = hash256(h + 0x${DIRECT_V2_TOTAL_PAIRFOLD_FINAL_TAG_HEX} + 0x00000024);
        require(gammaW == int(h.reverse() + 0x00) % P);

        ${bqLoads}
        bytes bqBlob = ${bqBlob};
        require(zW == int(hash256(0x${DIRECT_V2_TOTAL_PAIRFOLD_Z_TAG_HEX}
          + toPaddedBytes(gammaW,32).reverse() + bqBlob).reverse() + 0x00) % P);
        int bqz = 0; bytes bqRest = bqBlob; bytes bqLo = 0x;
        do {
            (bqRest,bqLo) = bqRest.split(bqRest.length - 32);
            bqz = (mulFp(bqz,zW) + int(bqLo.reverse())) % P;
        } while (bqRest.length > 0);
        int z2=mulFp(zW,zW); int z4=mulFp(z2,z2);
        int z6=mulFp(z4,z2); int z12=mulFp(z6,z6);
        int p12z=(z12 + P - mulFp(18,z6) + 82) % P;
        require((finalAggL + P - finalAggF) % P == mulFp(bqz,p12z));

        bytes residueBE = tx.inputs[${residueInputIndex}].unlockingBytecode.split(${residuePayloadOffset})[1].split(1152)[0];
        ${parseBeFieldsSource('residueBE', [...c, ...ci, ...w], 'rs')}
        (${fp12Decl('iv')}) = fp12Mul(${c.join(',')},${ci.join(',')});
        ${fp12Names('iv').map((name, index) =>
    `require(${name} % P == ${one[index]});`).join(' ')}
        require(${rootMatch(w, one)} || ${rootMatch(w, root)} || ${rootMatch(w, root2)});
        (${fp12Decl('cqq')}) = fp12Frob2(${c.join(',')});
        (${fp12Decl('cu')}) = fp12Mul(${c.join(',')},${fp12Names('cqq').join(',')});
        (${fp12Decl('rhs')}) = fp12Frob1(${fp12Names('cu').join(',')});
        (${fp12Decl('fw')}) = fp12Mul(${endpoint.join(',')},${w.join(',')});
        (${fp12Decl('lhs')}) = fp12Mul(${fp12Names('fw').join(',')},${fp12Names('cqq').join(',')});
        ${fp12Names('lhs').map((name, index) =>
    `require(${name} % P == rhs${index} % P);`).join(' ')}
    }
}
${fold1Source()}
${checkedAffineSource()}
${totalStaticStepSource(verificationKey)}
`;
}

const op = Object.freeze({
  ZERO: 0x00,
  NOP: 0x61,
  TWO_DROP: 0x6d,
  DROP: 0x75,
  DUP: 0x76,
  NIP: 0x77,
  SWAP: 0x7c,
  CAT: 0x7e,
  SPLIT: 0x7f,
  EQUALVERIFY: 0x88,
  DEFINE: 0x89,
  INVOKE: 0x8a,
  HASH256: 0xaa,
  INPUTBYTECODE: 0xca,
});

const pushInt = (value) => encodeDataPush(bigIntToVmNumber(BigInt(value)));
const byte = (...values) => Uint8Array.from(values);
const concat = (...parts) => Uint8Array.from(
  parts.flatMap((part) => [...part]),
);

const inputSlice = (inputIndex, offset, length) => concat(
  pushInt(inputIndex),
  byte(op.INPUTBYTECODE),
  pushInt(offset),
  byte(op.SPLIT, op.NIP),
  pushInt(length),
  byte(op.SPLIT, op.DROP),
);

export function splitDirectV2PairFoldBody(body, layout = 5) {
  const count = Array.isArray(layout) ? layout.length : layout;
  if (
    !(body instanceof Uint8Array)
    || !Number.isInteger(count)
    || count < 1
    || body.length < count
  ) {
    fail('PairFold executable body is too short to stripe');
  }
  if (Array.isArray(layout)) {
    if (
      layout.some((length) => !Number.isInteger(length) || length < 1)
      || layout.reduce((sum, length) => sum + length, 0) !== body.length
    ) {
      fail('PairFold executable body layout must be positive and exhaustive');
    }
    let cursor = 0;
    return Object.freeze(layout.map((length) => {
      const fragment = Uint8Array.from(body.slice(cursor, cursor + length));
      cursor += length;
      return fragment;
    }));
  }
  const base = Math.floor(body.length / count);
  let remainder = body.length - base * count;
  let cursor = 0;
  return Object.freeze(Array.from({ length: count }, () => {
    const length = base + (remainder-- > 0 ? 1 : 0);
    const fragment = Uint8Array.from(body.slice(cursor, cursor + length));
    cursor += length;
    return fragment;
  }));
}

export function buildDirectV2PairFoldLoader({
  body,
  fragmentOffsets,
  fragmentLengths,
  functionId = 7,
  densityPadBytes = 0,
  densityNops = 0,
}) {
  if (
    !(body instanceof Uint8Array)
    || !Array.isArray(fragmentOffsets)
    || !Array.isArray(fragmentLengths)
    || fragmentOffsets.length !== 5
    || fragmentLengths.length !== 5
  ) {
    fail('PairFold loader requires one body and five exact fragment slices');
  }
  if (
    !Number.isInteger(densityPadBytes)
    || densityPadBytes < 0
    || densityPadBytes > 1_024
  ) {
    fail('PairFold loader densityPadBytes must be from 0 to 1024');
  }
  if (
    !Number.isInteger(densityNops)
    || densityNops < 0
    || densityNops > 32
  ) {
    fail('PairFold loader densityNops must be from 0 to 32');
  }
  const slices = fragmentOffsets.map((offset, inputIndex) => {
    const length = fragmentLengths[inputIndex];
    if (
      !Number.isInteger(offset)
      || offset < 0
      || !Number.isInteger(length)
      || length < 1
    ) {
      fail(`invalid PairFold body fragment slice ${inputIndex}`);
    }
    return inputSlice(inputIndex, offset, length);
  });
  const reconstructed = [];
  slices.forEach((slice, index) => {
    reconstructed.push(slice);
    if (index > 0) reconstructed.push(byte(op.CAT));
  });
  const executable = concat(
    byte(...Array(densityNops).fill(op.NOP)),
    byte(op.TWO_DROP),
    ...reconstructed,
    byte(op.DUP, op.HASH256),
    encodeDataPush(hash256(body)),
    byte(op.EQUALVERIFY),
    pushInt(functionId),
    byte(op.DEFINE),
    pushInt(functionId),
    byte(op.INVOKE),
  );
  const densityPad = Uint8Array.from(
    { length: densityPadBytes },
    (_, index) => (index * 13 + 0x3c) & 0xff,
  );
  const loader = densityPadBytes === 0
    ? executable
    : concat(byte(op.DROP), executable);
  return Object.freeze({
    densityPad,
    loader,
    lock: encodeLockingBytecodeP2sh32(hash256(loader)),
  });
}

export function buildDirectV2PairFoldUnlock({
  state,
  records,
  table,
  bqShard,
  bodyFragment,
  densityPad,
  loader,
}) {
  for (const [value, label] of [
    [state, 'state'],
    [records, 'records'],
    [table, 'table'],
    [bqShard, 'bqShard'],
    [bodyFragment, 'bodyFragment'],
    [loader, 'loader'],
  ]) {
    if (!(value instanceof Uint8Array) || value.length === 0) {
      fail(`${label} must be nonempty bytecode data`);
    }
  }
  if (
    densityPad !== undefined
    && (!(densityPad instanceof Uint8Array) || densityPad.length === 0)
  ) {
    fail('densityPad must be nonempty when supplied');
  }
  if (state.length !== DIRECT_V2_PAIRFOLD_STATE_BYTES) {
    fail('PairFold state must contain exactly 296 bytes');
  }
  return concat(
    encodeDataPush(state),
    encodeDataPush(records),
    encodeDataPush(table),
    encodeDataPush(bqShard),
    encodeDataPush(bodyFragment),
    ...(densityPad === undefined ? [] : [encodeDataPush(densityPad)]),
    encodeDataPush(loader),
  );
}

export function buildDirectV2PairFoldTerminalUnlock({
  state,
  records,
  table,
  densityPad,
  redeem,
}) {
  for (const [value, label] of [
    [state, 'state'],
    [records, 'records'],
    [table, 'table'],
    [redeem, 'redeem'],
  ]) {
    if (!(value instanceof Uint8Array) || value.length === 0) {
      fail(`${label} must be nonempty bytecode data`);
    }
  }
  if (
    state.length !== DIRECT_V2_PAIRFOLD_STATE_BYTES
    || records.length !== 576
    || table.length !== 768
  ) {
    fail('PairFold terminal witness widths are invalid');
  }
  if (
    densityPad !== undefined
    && (!(densityPad instanceof Uint8Array) || densityPad.length === 0)
  ) {
    fail('PairFold terminal densityPad must be nonempty when supplied');
  }
  return concat(
    encodeDataPush(state),
    encodeDataPush(records),
    encodeDataPush(table),
    ...(densityPad === undefined ? [] : [encodeDataPush(densityPad)]),
    encodeDataPush(redeem),
  );
}

export const DIRECT_V2_TOTAL_PAIRFOLD_LIBRARY = LAZY_AFFINE_LIBRARY;
export const DIRECT_V2_TOTAL_PAIRFOLD_FINAL_TAG_HEX =
  Buffer.from(DIRECT_V2_MILLER_TAG_GAMMA_FINAL).toString('hex');
export const DIRECT_V2_TOTAL_PAIRFOLD_Z_TAG_HEX =
  Buffer.from(DIRECT_V2_MILLER_TAG_Z).toString('hex');
