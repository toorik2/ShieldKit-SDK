// Emit a two-step C7/SZ kernel that recomputes both factor groups on-chain
// while witnessing only the even endpoint. It is deliberately a small,
// stand-alone primitive: the full executor will add rolling-FS absorption,
// state serialization, table transport, and cross-input binding around this
// exact relation.
//
// The important boundary is structural. `wdat0` and `wdat1` contain only the
// affine-line slope witnesses; the eliminated odd Fp12 anchor is absent from
// both the function signature and the data parser.

const functionSpan = (source, name) => {
  const start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`missing ${name}`);
  let depth = 0;
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    else if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  throw new Error(`unterminated ${name}`);
};

// Rewrite the stock step helper into a factor-only helper. The source slices
// are deliberately marker-checked because a generator-shape drift must fail
// closed rather than silently reintroduce the old chain witness parser.
export const factorOnlyHelper = (shared) => {
  const original = functionSpan(shared, 'stepU');
  const bodyStart = original.indexOf('{') + 1;
  const bodyEnd = original.lastIndexOf('}');
  const body = original.slice(bodyStart, bodyEnd);
  const pmStart = body.indexOf('    int Pm =');
  const pmEnd = body.indexOf('\n', pmStart);
  const chainStart = body.search(/    bytes ch0(?:_l|Bytes)/);
  const chainLast = body.search(/    bytes ch11(?:_l|Bytes)/);
  const chainEnd = body.indexOf('\n', chainLast) + 1;
  const fnStart = body.indexOf('    int fn =', chainEnd);
  const factorStart = body.indexOf('    int pf = 1;', fnStart);
  const normalizeStart = body.indexOf('    // The remainder operator retains a negative dividend', factorStart);
  if (pmStart < 0 || pmEnd < 0 || chainStart < 0 || chainLast < 0 || chainEnd < 0 || fnStart < 0 || factorStart < 0 || normalizeStart < 0) {
    throw new Error('unexpected stepU shape while extracting composed factor kernel');
  }
  // The generated parser changes order with the packing profile. Keep every
  // parser statement before and after the contiguous `ch0..ch11` region, but
  // never the region itself. This preserves its exact canonicality checks.
  const parser = `${body.slice(pmEnd + 1, chainStart)}${body.slice(chainEnd, fnStart)}`;
  const factorBody = body.slice(factorStart, normalizeStart);
  const explicitMode = original.includes(' int mode, bytes wdat');
  const modeParameter = explicitMode ? 'int mode, ' : '';
  return [
    'function stepF(int dotC,int dotCi,',
    '        int rxa,int rxb,int rya,int ryb, int tgxa,int tgxb,int tgya,int tgyb, int tdxa,int tdxb,int tdya,int tdyb,',
    '        int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3, int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,',
    `        int ex4,int ex5, ${modeParameter}bytes wdat, bytes cdat)`,
    '    returns (int, int,int,int,int, int,int,int,int, int,int,int,int) {',
    '    int Pm = 21888242871839275222246405745257275088696311157297823662689037894645226208583;',
    parser.trimEnd(),
    factorBody.trimEnd(),
    '    pf = (pf + Pm) % Pm;',
    '    return pf, R0,R1,R2,R3, G0,G1,G2,G3, D0,D1,D2,D3;',
    '}',
  ].join('\n');
};

export const factorOnlyShared = (shared) => {
  const start = shared.indexOf('function stepU(');
  if (start < 0) throw new Error('shared C7 source has no stepU helper');
  return `${shared.slice(0, start)}${factorOnlyHelper(shared)}\n`;
};

export const stripChainWitness = (wdat, { fixedWidth = 0, factorLimbs = 4 } = {}) => {
  if (fixedWidth > 0) {
    const length = fixedWidth * factorLimbs;
    if (!Number.isInteger(factorLimbs) || factorLimbs < 2 || wdat.length < length) {
      throw new Error('invalid fixed-width composed factor witness');
    }
    return wdat.slice(0, length);
  }
  let offset = 0;
  // The stock helper uses four length-prefixed Fp2 slope limbs before its
  // twelve chain limbs. This parser is intentionally exact rather than a
  // guessed byte count: changed field widths invalidate the experiment.
  for (let index = 0; index < 4; index += 1) {
    const length = wdat[offset];
    if (length === undefined || length < 1 || offset + 1 + length > wdat.length) {
      throw new Error(`invalid slope witness limb ${index}`);
    }
    offset += 1 + length;
  }
  return wdat.slice(0, offset);
};

const decl = (names) => names.map((name) => `int ${name}`).join(', ');

export const composedKernelSource = ({ shared, p, library = '', modes = null }) => {
  const helper = factorOnlyShared(shared);
  const explicitMode = functionSpan(shared, 'stepU').includes(' int mode, bytes wdat');
  if (explicitMode && (!Array.isArray(modes) || modes.length !== 2 || modes.some((mode) => !Number.isInteger(mode) || mode < 0 || mode > 2))) {
    throw new Error('explicit-mode factor helper requires two canonical mode literals');
  }
  const fOut = Array.from({ length: 12 }, (_, index) => `f${index}`);
  const pointNames = [
    'rxa', 'rxb', 'rya', 'ryb',
    'tgxa', 'tgxb', 'tgya', 'tgyb',
    'tdxa', 'tdxb', 'tdya', 'tdyb',
  ];
  const knotNames = ['kn0', 'kn1', 'kn2', 'kn3', 'kv0', 'kv1', 'kv2', 'kv3', 'kc0', 'kc1', 'kc2', 'kc3'];
  const bNames = ['Bxa', 'Bxb', 'Bya', 'Byb'];
  const ecNames = Array.from({ length: 12 }, (_, index) => `ec${index}`);
  const nextNames = [
    'nextRxa', 'nextRxb', 'nextRya', 'nextRyb',
    'nextTgxa', 'nextTgxb', 'nextTgya', 'nextTgyb',
    'nextTdxa', 'nextTdxb', 'nextTdya', 'nextTdyb',
  ];
  const endpointDot = `(${fOut.map((name, index) => `${name} * ec${index}`).join(' + ')}) % P`;
  const stepArgs = (r, tg, td, mode, wdat, cdat) => [
    'dotC', 'dotCi', ...r, ...tg, ...td, ...knotNames, ...bNames, 'ex4', 'ex5', ...(explicitMode ? [String(mode)] : []), wdat, cdat,
  ].join(', ');
  return `pragma cashscript ^0.14.0;
contract ComposedWindowKernel() {
  function spend(int fC, int aggL, int aggF, int gp, int gamma,
      int qEval, int p12z, int expectedAggL, int expectedAggF, int expectedGp, int expectedFC,
      int dotC, int dotCi, ${decl(nextNames)},
      ${decl(pointNames)}, ${decl(knotNames)}, ${decl(bNames)}, ${decl(ecNames)}, int ex4, int ex5,
      bytes wdat0, bytes cdat0, bytes wdat1, bytes cdat1, ${decl(fOut)}) {
    int P = ${p};
    (int pf0, int r0a,int r0b,int r0c,int r0d, int tg0a,int tg0b,int tg0c,int tg0d, int td0a,int td0b,int td0c,int td0d) = stepF(${stepArgs(['rxa', 'rxb', 'rya', 'ryb'], ['tgxa', 'tgxb', 'tgya', 'tgyb'], ['tdxa', 'tdxb', 'tdya', 'tdyb'], explicitMode ? modes[0] : null, 'wdat0', 'cdat0')});
    (int pf1, int r1a,int r1b,int r1c,int r1d, int tg1a,int tg1b,int tg1c,int tg1d, int td1a,int td1b,int td1c,int td1d) = stepF(${stepArgs(['r0a', 'r0b', 'r0c', 'r0d'], ['tg0a', 'tg0b', 'tg0c', 'tg0d'], ['td0a', 'td0b', 'td0c', 'td0d'], explicitMode ? modes[1] : null, 'wdat1', 'cdat1')});
    int inner = (((fC * fC) % P) * pf0) % P;
    int product = (((inner * inner) % P) * pf1) % P;
    int fn = ${endpointDot};
    int nextAggL = (aggL + P + (gp * product) % P) % P;
    int nextAggF = (aggF + P + (gp * fn) % P) % P;
    int nextGp = (gp * gamma) % P;
    require(product == (fn + (qEval * p12z) % P) % P);
    require(nextAggL == expectedAggL); require(nextAggF == expectedAggF);
    require(nextGp == expectedGp); require(fn == expectedFC);
    // The production executor serializes these into the next even-boundary
    // state. Bind them exactly here so a bad curve update cannot be hidden
    // behind a valid factor scalar.
    require(r1a == nextRxa && r1b == nextRxb && r1c == nextRya && r1d == nextRyb);
    require(tg1a == nextTgxa && tg1b == nextTgxb && tg1c == nextTgya && tg1d == nextTgyb);
    require(td1a == nextTdxa && td1b == nextTdxb && td1c == nextTdya && td1d == nextTdyb);
  }
}
${library}
${helper}`;
};

// The promoted C7 path does not recompute the gamma/delta addition lines from
// affine state. It consumes their compact, quotient-normalized fixed table.
// This extractor is therefore the only one suitable for the static candidate:
// it removes the chain parser and old transcript endpoint but preserves the
// table parser and every on-chain factor fold exactly.
export const staticFactorOnlyHelper = (shared) => {
  const original = functionSpan(shared, 'stepU');
  const bodyStart = original.indexOf('{') + 1;
  const body = original.slice(bodyStart, original.lastIndexOf('}'));
  const pmStart = body.indexOf('    int Pm =');
  const pmEnd = body.indexOf('\n', pmStart);
  const chainStart = body.search(/    bytes ch0(?:_l|Bytes)/);
  const chainLast = body.search(/    bytes ch11(?:_l|Bytes)/);
  const chainEnd = body.indexOf('\n', chainLast) + 1;
  const fnStart = body.indexOf('    int fn =', chainEnd);
  const factorStart = body.indexOf('    int pf = 1;', fnStart);
  const normalizeStart = body.indexOf('    pf = (pf + Pm) % Pm;', factorStart);
  if (pmStart < 0 || pmEnd < 0 || chainStart < 0 || chainLast < 0 || chainEnd < 0 || fnStart < 0 || factorStart < 0 || normalizeStart < 0) {
    throw new Error('unexpected static stepU shape while extracting composed factor kernel');
  }
  const parser = `${body.slice(pmEnd + 1, chainStart)}${body.slice(chainEnd, fnStart)}`;
  let factorBody = body.slice(factorStart, normalizeStart);
  // Dens-rich: alias repeated multi-digit field lits once at the top of staticStepF
  // so cashc/bytecode does not re-embed the same 32 B push for every use site.
  // Soundness-preserving: pure common-subexpression of immutable constants.
  {
    const litRe = /\b(\d{20,})\b/g;
    const counts = new Map();
    for (const m of factorBody.matchAll(litRe)) {
      counts.set(m[1], (counts.get(m[1]) || 0) + 1);
    }
    const aliases = [];
    let aliasIndex = 0;
    for (const [lit, n] of [...counts.entries()].sort((a, b) => b[1] - a[1] || b[0].length - a[0].length)) {
      if (n < 2) continue;
      // Skip the field modulus itself — already bound as Pm.
      if (lit === '21888242871839275222246405745257275088696311157297823662689037894645226208583') continue;
      const name = `kC${aliasIndex++}`;
      aliases.push(`    int ${name} = ${lit};`);
      factorBody = factorBody.replaceAll(lit, name);
    }
    if (aliases.length) {
      factorBody = `${aliases.join('\n')}\n${factorBody}`;
    }
  }
  return [
    'function staticStepF(int dotC,int dotCi,',
    '        int rxa,int rxb,int rya,int ryb,',
    '        int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3, int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,',
    '        int ex4,int ex5, int mode, bytes wdat, bytes fixedLines)',
    '    returns (int, int,int,int,int) {',
    '    int Pm = 21888242871839275222246405745257275088696311157297823662689037894645226208583;',
    parser.trimEnd(),
    factorBody.trimEnd(),
    '    pf = (pf + Pm) % Pm;',
    '    return pf, R0,R1,R2,R3;',
    '}',
  ].join('\n');
};

// XONLY staticStepF: fixed-32 wdat (composed scalar) + slope fixedLines + gx/dx seeds.
// Literals match fixed-G2 / xOnlyStepSource gamma/delta addends (deployment-fixed).
export const xonlyStaticStepFSource = () => {
  const GQYA = '21547676276454546410296902538495425432829390494566673627605034971294784210249';
  const GQYB = '6398877257285935365249802814125273995578953055511620955996813742572019651748';
  const DQYA = '21514667205241674535457714632061047258097217169787877277363751636045743019390';
  const DQYB = '10670741793215758088800930336726579942257175283397977169474518534600570072949';
  const GQXA = '13700863412905423759250606799218875849166292978636329233814994817818554546431';
  const GQXB = '21761028412726985313317130874134828290145951226051416150723277301116006118078';
  const DQXA = '15825285363846036862295217228464959249112247579247978462621447842724817286232';
  const DQXB = '3543600181522862329564888283473085279940669956506060026762005346996341806108';
  return `function staticStepF(int dotC,int dotCi,
        int rxa,int rxb,int rya,int ryb,
        int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3, int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,
        int ex4,int ex5, int mode, bytes wdat, bytes fixedLines,
        int gx0,int gx1,int dx0,int dx1)
    returns (int, int,int,int,int, int,int,int,int) {
    int Pm = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
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
    (int a0,int a1,int a2,int a3,int a4,int a5, int R0,int R1,int R2,int R3) = affDbl(rxa,rxb,rya,ryb,sda,sdb);
    pf = fold1(Pm, pf, a0,a1,a2,a3,a4,a5, kn0,kn1,kn2,kn3, ex4,ex5);
    bytes gm0Bytes, bytes dr0 = fixedLines.split(32); int gm0 = int(gm0Bytes);
    bytes gm1Bytes, bytes dr1 = dr0.split(32); int gm1 = int(gm1Bytes);
    bytes dm0Bytes, bytes dr2 = dr1.split(32); int dm0 = int(dm0Bytes);
    bytes dm1Bytes, bytes dr3 = dr2.split(32); int dm1 = int(dm1Bytes);
    (int bx2a,int bx2b) = fp2Sqr(gx0,gx1);
    (int bm2a,int bm2b) = fp2Sqr(gm0,gm1);
    (int bx4a,int bx4b) = fp2Sqr(bx2a,bx2b);
    (int bbma,int bbmb) = fp2MulByB(bm2a,bm2b);
    (int bb12a,int bb12b) = fp2Scale(bbma,bbmb,12);
    (int bx9a,int bx9b) = fp2Scale(bx4a,bx4b,9);
    (int b0,int b1) = fp2Sub(bb12a,bb12b,bx9a,bx9b,2);
    (int bm2x2a,int bm2x2b) = fp2Mul(bm2a,bm2b,bx2a,bx2b);
    (int b2,int b3) = fp2Scale(bm2x2a,bm2x2b,12);
    (int bmx2a,int bmx2b) = fp2Mul(gm0,gm1,bx2a,bx2b);
    (int b4,int b5) = fp2Scale(bmx2a,bmx2b,12);
    (int btwoXa,int btwoXb) = fp2Add(gx0,gx1,gx0,gx1);
    (int ngx0,int ngx1) = fp2Sub(bm2a,bm2b,btwoXa,btwoXb,2);
    (int uox2a,int uox2b) = fp2Sqr(dx0,dx1);
    (int uom2a,int uom2b) = fp2Sqr(dm0,dm1);
    (int uox4a,int uox4b) = fp2Sqr(uox2a,uox2b);
    (int uobma,int uobmb) = fp2MulByB(uom2a,uom2b);
    (int uob12a,int uob12b) = fp2Scale(uobma,uobmb,12);
    (int uox9a,int uox9b) = fp2Scale(uox4a,uox4b,9);
    (int uo0,int uo1) = fp2Sub(uob12a,uob12b,uox9a,uox9b,2);
    (int uom2x2a,int uom2x2b) = fp2Mul(uom2a,uom2b,uox2a,uox2b);
    (int uo2,int uo3) = fp2Scale(uom2x2a,uom2x2b,12);
    (int uomx2a,int uomx2b) = fp2Mul(dm0,dm1,uox2a,uox2b);
    (int uo4,int uo5) = fp2Scale(uomx2a,uomx2b,12);
    (int uotwoXa,int uotwoXb) = fp2Add(dx0,dx1,dx0,dx1);
    (int ndx0,int ndx1) = fp2Sub(uom2a,uom2b,uotwoXa,uotwoXb,2);
    pf = fold1(Pm, pf, b0,b1,b2,b3,b4,b5, kv0,kv1,kv2,kv3, ex4,ex5);
    pf = fold1(Pm, pf, uo0,uo1,uo2,uo3,uo4,uo5, kc0,kc1,kc2,kc3, ex4,ex5);
    if (mode >= 1) {
        int qy0a = Bya; int qy0b = Byb;
        int gqya = ${GQYA}; int gqyb = ${GQYB}; int dqya = ${DQYA}; int dqyb = ${DQYB};
        if (mode == 1) { qy0a = (Pm - Bya) % Pm; qy0b = (Pm - Byb) % Pm; gqya = (Pm - ${GQYA}) % Pm; gqyb = (Pm - ${GQYB}) % Pm; dqya = (Pm - ${DQYA}) % Pm; dqyb = (Pm - ${DQYB}) % Pm; }
        (int aa0,int aa1,int aa2,int aa3,int aa4,int aa5, int rr0,int rr1,int rr2,int rr3) = affAdd(R0,R1,R2,R3, Bxa,Bxb,qy0a,qy0b, saa,sab);
        pf = fold1(Pm, pf, aa0,aa1,aa2,aa3,aa4,aa5, kn0,kn1,kn2,kn3, ex4,ex5); R0=rr0;R1=rr1;R2=rr2;R3=rr3;
        bytes bb2Bytes, bytes ar0 = dr3.split(32); int bb2 = int(bb2Bytes);
        bytes bb3Bytes, bytes ar1 = ar0.split(32); int bb3 = int(bb3Bytes);
        bytes uu2Bytes, bytes ar2 = ar1.split(32); int uu2 = int(uu2Bytes);
        bytes uu3Bytes, bytes ar3 = ar2.split(32); int uu3 = int(uu3Bytes);
        (int bbx0,int bbx1) = fp2Mul(bb2,bb3, ${GQXA},${GQXB});
        (int bbs0,int bbs1) = fp2Add(bbx0,bbx1, gqya,gqyb);
        (int bb0,int bb1) = fp2Neg(bbs0,bbs1,1);
        int bb4 = 1; int bb5 = 0;
        (int uux0,int uux1) = fp2Mul(uu2,uu3, ${DQXA},${DQXB});
        (int uus0,int uus1) = fp2Add(uux0,uux1, dqya,dqyb);
        (int uu0,int uu1) = fp2Neg(uus0,uus1,1);
        int uu4 = 1; int uu5 = 0;
        pf = fold1(Pm, pf, bb0,bb1,bb2,bb3,bb4,bb5, kv0,kv1,kv2,kv3, ex4,ex5);
        pf = fold1(Pm, pf, uu0,uu1,uu2,uu3,uu4,uu5, kc0,kc1,kc2,kc3, ex4,ex5);
        (int ngxm2a,int ngxm2b) = fp2Sqr(bb2,bb3);
        (int ngxta,int ngxtb) = fp2Sub(ngxm2a,ngxm2b,ngx0,ngx1,2);
        (ngx0,ngx1) = fp2Sub(ngxta,ngxtb,${GQXA},${GQXB},2);
        (int ndxm2a,int ndxm2b) = fp2Sqr(uu2,uu3);
        (int ndxta,int ndxtb) = fp2Sub(ndxm2a,ndxm2b,ndx0,ndx1,2);
        (ndx0,ndx1) = fp2Sub(ndxta,ndxtb,${DQXA},${DQXB},2);
        require(ar3.length == 0);
    }
    if (mode == 0) { require(dr3.length == 0); }
    pf = (pf + Pm) % Pm;
    return pf, R0,R1,R2,R3, ngx0,ngx1,ndx0,ndx1;
}`;
};

export const staticFactorOnlyShared = (shared) => {
  const stepStart = shared.indexOf('function stepU(');
  if (stepStart < 0) throw new Error('static C7 source has no stepU helper');
  // fold1-1mod (a3): drop intermediate %Pm in fold1 product — one final mod only.
  // Sound when the intermediate sum stays within the bigint domain before final %Pm.
  const fold1Dual = 'return (pf * ((c2a*kye0 + c2b*kye1 + c1a*kxe2 + c1b*kxe3 + c0a*ex4 + c0b*ex5) % Pm)) % Pm;';
  const fold1One = 'return (pf * (c2a*kye0 + c2b*kye1 + c1a*kxe2 + c1b*kxe3 + c0a*ex4 + c0b*ex5)) % Pm;';
  let head = shared.slice(0, stepStart);
  if (head.includes(fold1Dual)) head = head.replace(fold1Dual, fold1One);
  // densNeed (a1): dual-mod congruence a%P==b%P → single-mod (a-b)%P==0.
  // Equivalence: a≡b (mod P) ⇔ (a-b)≡0. Saves one OP_MOD per limb per slope check
  // (affDbl + affAdd; ~84 checks × 2 limbs). Does not change the checked relation.
  head = head.replace(
    /require\((\w+) % Pm == (\w+) % Pm\);\s*require\((\w+) % Pm == (\w+) % Pm\);/g,
    'require(($1 - $2) % Pm == 0); require(($3 - $4) % Pm == 0);',
  );
  if (process.env.C7_FIXED_G2_XONLY === '1') {
    return `${head}${xonlyStaticStepFSource()}\n`;
  }
  return `${head}${staticFactorOnlyHelper(shared)}\n`;
};

export const composedStaticKernelSource = ({ shared, p, modes, tableHashes, library = '' }) => {
  if (!Array.isArray(modes) || modes.length !== 2 || modes.some((mode) => !Number.isInteger(mode) || mode < 0 || mode > 2)) {
    throw new Error('static composed factor helper requires two canonical mode literals');
  }
  if (!Array.isArray(tableHashes) || tableHashes.length !== 2 || tableHashes.some((hash) => !/^[0-9a-f]{64}$/i.test(hash))) {
    throw new Error('static composed factor helper requires two SHA256d table digests');
  }
  const helper = staticFactorOnlyShared(shared);
  const fOut = Array.from({ length: 12 }, (_, index) => `f${index}`);
  const currentR = ['rxa', 'rxb', 'rya', 'ryb'];
  const nextR = ['nextRxa', 'nextRxb', 'nextRya', 'nextRyb'];
  const knotNames = ['kn0', 'kn1', 'kn2', 'kn3', 'kv0', 'kv1', 'kv2', 'kv3', 'kc0', 'kc1', 'kc2', 'kc3'];
  const bNames = ['Bxa', 'Bxb', 'Bya', 'Byb'];
  const ecNames = Array.from({ length: 12 }, (_, index) => `ec${index}`);
  const endpointDot = `(${fOut.map((name, index) => `${name} * ec${index}`).join(' + ')}) % P`;
  const stepArgs = (r, mode, wdat, fixed) => [
    'dotC', 'dotCi', ...r, ...knotNames, ...bNames, 'ex4', 'ex5', String(mode), wdat, fixed,
  ].join(', ');
  return `pragma cashscript ^0.14.0;
contract ComposedStaticWindowKernel() {
  function spend(int fC, int aggL, int aggF, int gp, int gamma,
      int qEval, int p12z, int expectedAggL, int expectedAggF, int expectedGp, int expectedFC,
      int dotC, int dotCi, ${decl(nextR)}, ${decl(currentR)},
      ${decl(knotNames)}, ${decl(bNames)}, ${decl(ecNames)}, int ex4, int ex5,
      bytes wdat0, bytes fixed0, bytes wdat1, bytes fixed1, ${decl(fOut)}) {
    int P = ${p};
    require(hash256(fixed0) == 0x${tableHashes[0]});
    require(hash256(fixed1) == 0x${tableHashes[1]});
    (int pf0, int r0a,int r0b,int r0c,int r0d) = staticStepF(${stepArgs(currentR, modes[0], 'wdat0', 'fixed0')});
    (int pf1, int r1a,int r1b,int r1c,int r1d) = staticStepF(${stepArgs(['r0a', 'r0b', 'r0c', 'r0d'], modes[1], 'wdat1', 'fixed1')});
    int inner = (((fC * fC) % P) * pf0) % P;
    int product = (((inner * inner) % P) * pf1) % P;
    int fn = ${endpointDot};
    int nextAggL = (aggL + P + (gp * product) % P) % P;
    int nextAggF = (aggF + P + (gp * fn) % P) % P;
    int nextGp = (gp * gamma) % P;
    require(product == (fn + (qEval * p12z) % P) % P);
    require(nextAggL == expectedAggL); require(nextAggF == expectedAggF);
    require(nextGp == expectedGp); require(fn == expectedFC);
    require(r1a == nextRxa && r1b == nextRxb && r1c == nextRya && r1d == nextRyb);
  }
}
${library}
${helper}`;
};

// A stateful multi-window probe for the eventual executor body. Unlike the
// one-pair kernel above it deliberately does not accept per-window quotient
// evaluations: production checks only the gamma-aggregated BQ identity in
// the terminal. It therefore measures the exact interior transition that an
// executor may perform: consume factors, advance R, absorb one even endpoint
// per pair, and carry (aggL, aggF, gp, fC) forward.
export const composedStaticWindowKernelSource = ({ shared, p, modes, tableHashes, library = '' }) => {
  if (!Array.isArray(modes) || modes.length < 2 || modes.length % 2 !== 0 || modes.some((mode) => !Number.isInteger(mode) || mode < 0 || mode > 2)) {
    throw new Error('stateful composed static kernel requires an even nonempty mode schedule');
  }
  const pairs = modes.length / 2;
  if (!Array.isArray(tableHashes) || tableHashes.length !== modes.length || tableHashes.some((hash) => !/^[0-9a-f]{64}$/i.test(hash))) {
    throw new Error('stateful composed static kernel requires one SHA256d digest per fixed record');
  }
  const helper = staticFactorOnlyShared(shared);
  const knotNames = ['kn0', 'kn1', 'kn2', 'kn3', 'kv0', 'kv1', 'kv2', 'kv3', 'kc0', 'kc1', 'kc2', 'kc3'];
  const bNames = ['Bxa', 'Bxb', 'Bya', 'Byb'];
  const ecNames = Array.from({ length: 12 }, (_, index) => `ec${index}`);
  const pairDecls = Array.from({ length: pairs }, (_, index) => [
    `bytes wdat${index}a`, `bytes fixed${index}a`, `bytes wdat${index}b`, `bytes fixed${index}b`,
    ...Array.from({ length: 12 }, (_, limb) => `int end${index}_${limb}`),
  ]).flat();
  const stepArgs = (r, mode, wdat, fixed) => [
    'dotC', 'dotCi', ...r, ...knotNames, ...bNames, 'ex4', 'ex5', String(mode), wdat, fixed,
  ].join(', ');
  const pairBody = Array.from({ length: pairs }, (_, index) => {
    const r0 = index === 0 ? ['rxa', 'rxb', 'rya', 'ryb'] : [`out${index - 1}a`, `out${index - 1}b`, `out${index - 1}c`, `out${index - 1}d`];
    const r1 = [`mid${index}a`, `mid${index}b`, `mid${index}c`, `mid${index}d`];
    const r2 = [`out${index}a`, `out${index}b`, `out${index}c`, `out${index}d`];
    const endpointDot = Array.from({ length: 12 }, (_, limb) => `end${index}_${limb} * ec${limb}`).join(' + ');
    return [
      `    require(hash256(fixed${index}a) == 0x${tableHashes[index * 2]});`,
      `    require(hash256(fixed${index}b) == 0x${tableHashes[index * 2 + 1]});`,
      `(int pf${index}a, int ${r1[0]},int ${r1[1]},int ${r1[2]},int ${r1[3]}) = staticStepF(${stepArgs(r0, modes[index * 2], `wdat${index}a`, `fixed${index}a`)});`,
      `(int pf${index}b, int ${r2[0]},int ${r2[1]},int ${r2[2]},int ${r2[3]}) = staticStepF(${stepArgs(r1, modes[index * 2 + 1], `wdat${index}b`, `fixed${index}b`)});`,
      `int inner${index} = (((fC * fC) % P) * pf${index}a) % P;`,
      `int product${index} = (((inner${index} * inner${index}) % P) * pf${index}b) % P;`,
      `int fn${index} = (${endpointDot}) % P;`,
      `aggL = (aggL + P + (gp * product${index}) % P) % P;`,
      `aggF = (aggF + P + (gp * fn${index}) % P) % P;`,
      '    gp = (gp * gamma) % P;',
      `    fC = fn${index};`,
    ].join('\n');
  }).join('\n');
  const finalR = [`out${pairs - 1}a`, `out${pairs - 1}b`, `out${pairs - 1}c`, `out${pairs - 1}d`];
  return `pragma cashscript ^0.14.0;
contract ComposedStaticWindowKernel() {
  function spend(int fC, int aggL, int aggF, int gp, int gamma,
      int expectedAggL, int expectedAggF, int expectedGp, int expectedFC,
      int dotC, int dotCi, int expectedRxa, int expectedRxb, int expectedRya, int expectedRyb,
      int rxa, int rxb, int rya, int ryb,
      ${decl(knotNames)}, ${decl(bNames)}, ${decl(ecNames)}, int ex4, int ex5,
      ${pairDecls.join(', ')}) {
    int P = ${p};
${pairBody}
    require(aggL == expectedAggL); require(aggF == expectedAggF);
    require(gp == expectedGp); require(fC == expectedFC);
    require(${finalR[0]} == expectedRxa && ${finalR[1]} == expectedRxb && ${finalR[2]} == expectedRya && ${finalR[3]} == expectedRyb);
  }
}
${library}
${helper}`;
};

// Same transition as `composedStaticWindowKernelSource`, but with the record
// shape used by a real executor: two slope records plus one fixed-width even
// Fp12 endpoint per pair, and one authenticated fixed-line table. This is the
// bridge from argument-level VM probes to the eventual inBlob parser.
export const composedStaticWindowBlobKernelSource = ({ shared, p, modes, tableHash, library = '' }) => {
  if (!Array.isArray(modes) || modes.length < 2 || modes.length % 2 !== 0 || modes.some((mode) => !Number.isInteger(mode) || mode < 0 || mode > 2)) {
    throw new Error('blob composed static kernel requires an even nonempty mode schedule');
  }
  if (typeof tableHash !== 'string' || !/^[0-9a-f]{64}$/i.test(tableHash)) {
    throw new Error('blob composed static kernel requires the SHA256d of its full fixed table');
  }
  const pairs = modes.length / 2;
  const helper = staticFactorOnlyShared(shared);
  const knotNames = ['kn0', 'kn1', 'kn2', 'kn3', 'kv0', 'kv1', 'kv2', 'kv3', 'kc0', 'kc1', 'kc2', 'kc3'];
  const bNames = ['Bxa', 'Bxb', 'Bya', 'Byb'];
  const ecNames = Array.from({ length: 12 }, (_, index) => `ec${index}`);
  const stepArgs = (r, mode, wdat, fixed) => [
    'dotC', 'dotCi', ...r, ...knotNames, ...bNames, 'ex4', 'ex5', String(mode), wdat, fixed,
  ].join(', ');
  const pairBody = Array.from({ length: pairs }, (_, index) => {
    const r0 = index === 0 ? ['rxa', 'rxb', 'rya', 'ryb'] : [`out${index - 1}a`, `out${index - 1}b`, `out${index - 1}c`, `out${index - 1}d`];
    const mid = [`mid${index}a`, `mid${index}b`, `mid${index}c`, `mid${index}d`];
    const out = [`out${index}a`, `out${index}b`, `out${index}c`, `out${index}d`];
    const wd0Length = modes[index * 2] === 0 ? 64 : 128;
    const wd1Length = modes[index * 2 + 1] === 0 ? 64 : 128;
    const fixed0Length = modes[index * 2] === 0 ? 256 : 384;
    const fixed1Length = modes[index * 2 + 1] === 0 ? 256 : 384;
    const endpointParse = Array.from({ length: 12 }, (_, limb) => {
      const next = limb === 11 ? `recordAfterEnd${index}` : `endRest${index}_${limb}`;
      return `bytes end${index}_${limb}Bytes, bytes ${next} = ${limb === 0 ? `recordAfterWd${index}b` : `endRest${index}_${limb - 1}`}.split(32); int end${index}_${limb} = int(end${index}_${limb}Bytes);`;
    });
    const endpointDot = Array.from({ length: 12 }, (_, limb) => `end${index}_${limb} * ec${limb}`).join(' + ');
    return [
      `bytes wdat${index}a, bytes recordAfterWd${index}a = recordRem.split(${wd0Length});`,
      `bytes fixed${index}a, bytes fixedAfter${index}a = fixedRem.split(${fixed0Length});`,
      `bytes wdat${index}b, bytes recordAfterWd${index}b = recordAfterWd${index}a.split(${wd1Length});`,
      `bytes fixed${index}b, bytes fixedAfter${index}b = fixedAfter${index}a.split(${fixed1Length});`,
      ...endpointParse,
      `recordRem = recordAfterEnd${index}; fixedRem = fixedAfter${index}b;`,
      `(int pf${index}a, int ${mid[0]},int ${mid[1]},int ${mid[2]},int ${mid[3]}) = staticStepF(${stepArgs(r0, modes[index * 2], `wdat${index}a`, `fixed${index}a`)});`,
      `(int pf${index}b, int ${out[0]},int ${out[1]},int ${out[2]},int ${out[3]}) = staticStepF(${stepArgs(mid, modes[index * 2 + 1], `wdat${index}b`, `fixed${index}b`)});`,
      `int inner${index} = (((fC * fC) % P) * pf${index}a) % P;`,
      `int product${index} = (((inner${index} * inner${index}) % P) * pf${index}b) % P;`,
      `int fn${index} = (${endpointDot}) % P;`,
      `aggL = (aggL + P + (gp * product${index}) % P) % P;`,
      `aggF = (aggF + P + (gp * fn${index}) % P) % P;`,
      'gp = (gp * gamma) % P;',
      `fC = fn${index};`,
    ].map((line) => `    ${line}`).join('\n');
  }).join('\n');
  const finalR = [`out${pairs - 1}a`, `out${pairs - 1}b`, `out${pairs - 1}c`, `out${pairs - 1}d`];
  return `pragma cashscript ^0.14.0;
contract ComposedStaticWindowBlobKernel() {
  function spend(int fC, int aggL, int aggF, int gp, int gamma,
      int expectedAggL, int expectedAggF, int expectedGp, int expectedFC,
      int dotC, int dotCi, int expectedRxa, int expectedRxb, int expectedRya, int expectedRyb,
      int rxa, int rxb, int rya, int ryb,
      ${decl(knotNames)}, ${decl(bNames)}, ${decl(ecNames)}, int ex4, int ex5,
      bytes records, bytes fixedLines) {
    int P = ${p};
    require(hash256(fixedLines) == 0x${tableHash});
    bytes recordRem = records; bytes fixedRem = fixedLines;
${pairBody}
    require(recordRem.length == 0); require(fixedRem.length == 0);
    require(aggL == expectedAggL); require(aggF == expectedAggF);
    require(gp == expectedGp); require(fC == expectedFC);
    require(${finalR[0]} == expectedRxa && ${finalR[1]} == expectedRxb && ${finalR[2]} == expectedRya && ${finalR[3]} == expectedRyb);
  }
}
${library}
${helper}`;
};
