// Shared DEFINE'd body v2 (K=13 path): stepU reads WITNESS (wdat: pair0 slopes + chain) from the executor
// inBlob and CONSENSUS (cdat: mode + fixed lambdas) from a hash-pinned sibling DATA input. VK fixed-Q
// (gamma/delta affine) baked as literals; add-signs derived from mode (mode1=neg/useC, mode2=pos/useCinv).
// dotC/dotCi threaded (not c/cInv). => witness inBlob shrinks enough that K=13 fits the 10k unlock.
const P = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const B2A = '19485874751759354771024239261021720505790618469301721065564631296452457478373';
const B2B = '266929791119991161246907387137283842545076965332900288569378510910307636690';
// D2: 3*B2 reduced mod p, BAKED (proof-independent consensus literal) so the two per-call mulFp(3,B2)
// vanish. c0 = 3B - y^2 unchanged mod p.
const C3BA = '14681138511599513868579906292550611339979233093309515871315818100066920017953';
const C3BB = '800789373359973483740722161411851527635230895998700865708135532730922910070';
const affDblT = `function affDblT(int xa,int xb, int ya,int yb, int la,int lb) returns (int,int,int,int,int,int, int,int,int,int) {
    int Pm = ${P};
    (int x2a,int x2b) = fp2Sqr(xa,xb); int c1a = x2a+x2a+x2a; int c1b = x2b+x2b+x2b;
    (int c2a,int c2b) = fp2Neg(addFp(ya,ya),addFp(yb,yb),64); (int yya,int yyb) = fp2Sqr(ya,yb);
    int rc0a = subFp(${C3BA}, yya, 1); int rc0b = subFp(${C3BB}, yyb, 1);
    (int l2a,int l2b) = fp2Sqr(la,lb);
    int xna = (subFp(l2a, addFp(xa,xa), 2)) % Pm; int xnb = (subFp(l2b, addFp(xb,xb), 2)) % Pm;
    (int lya,int lyb) = fp2Mul(la,lb, subFp(xa,xna,1), subFp(xb,xnb,1));
    int yna = (subFp(lya, ya, 1)) % Pm; int ynb = (subFp(lyb, yb, 1)) % Pm;
    return rc0a,rc0b,c1a,c1b,c2a,c2b, xna,xnb,yna,ynb; }`;
const affAddT = `function affAddT(int Rxa,int Rxb,int Rya,int Ryb, int Qxa,int Qxb,int Qya,int Qyb, int la,int lb) returns (int,int,int,int,int,int, int,int,int,int) {
    int Pm = ${P};
    (int t1a,int t1b) = fp2Sub(Rxa,Rxb,Qxa,Qxb,64); (int t0a,int t0b) = fp2Sub(Rya,Ryb,Qya,Qyb,64);
    (int q0a,int q0b) = fp2Mul(t0a,t0b, Qxa,Qxb); (int q1a,int q1b) = fp2Mul(t1a,t1b, Qya,Qyb);
    (int c0a,int c0b) = fp2Sub(q0a,q0b,q1a,q1b,3); (int c1a,int c1b) = fp2Neg(t0a,t0b,64); int c2a = t1a; int c2b = t1b;
    (int l2a,int l2b) = fp2Sqr(la,lb);
    int xna = (subFp(subFp(l2a, Rxa, 64), Qxa, 64)) % Pm; int xnb = (subFp(subFp(l2b, Rxb, 64), Qxb, 64)) % Pm;
    (int lya,int lyb) = fp2Mul(la,lb, subFp(Rxa,xna,1), subFp(Rxb,xnb,1));
    int yna = (subFp(lya, Rya, 1)) % Pm; int ynb = (subFp(lyb, Ryb, 1)) % Pm;
    return c0a,c0b,c1a,c1b,c2a,c2b, xna,xnb,yna,ynb; }`;
// D2: fold pre-grouping. px,py (runtime G1 point) and ex0..3 (z-power covectors) are BOTH chunk-constant
// (step-independent), so the products py*ex0, py*ex1, px*ex2, px*ex3 are precomputed ONCE per chunk in the
// prologue (kye0,kye1,kxe2,kxe3 per pair). Each fold term then costs ONE mulFp (c*K) instead of TWO
// (c*py, then *ex). By associativity of mulFp mod p the folded value is byte-identical. 11 mulFp -> 7.
// D13 (composed into D16 acc-merge): fold1 INLINED. D2 kept the 6 covector products as mulFp() CALLS,
// each with its own %P reduction, then reduced the sum again — 6 DEFINE'd invokes + 7 modular reductions
// per fold. Inlining to a single raw dot with ONE deferred %P removes all 6 invokes and 5 redundant mods.
// Byte-identical mod p; op/step −5-7%. Orthogonal to the agg-merge (which only touches the final nAgg fold).
const fold1 = `function fold1(int Pm, int pf, int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int kye0,int kye1,int kxe2,int kxe3, int ex4,int ex5) returns (int) {
    return (pf * (c2a*kye0 + c2b*kye1 + c1a*kxe2 + c1b*kxe3 + c0a*ex4 + c0b*ex5)) % Pm; }`;

// ctx (18): ec0..11, ex0..5   wdat (16): sda,sdb,saa,sab, ch0..ch11   cdat (9): mode, lgd,lgD,lga,lgA, ldd,ldD,lda,ldA
// EX_ALIAS=1 is an opt-in source/codegen variant: ex0..5 are field-identical to
// ec0,ec1,ec6,ec7,ec8,ec9. The four prologue-only aliases are addressed through
// their ec names; the two aliases formerly carried into stepU are reconstructed
// locally after unpack. Unset remains byte-identical.
const CTX = [...Array.from({length:12},(_,k)=>`ec${k}`), 'ex0','ex1','ex2','ex3','ex4','ex5'];
const WD = ['sda','sdb','saa','sab', ...Array.from({length:12},(_,k)=>`ch${k}`)];
const CD = ['mode','lgd','lgD','lga','lgA','ldd','ldD','lda','ldA'];
export const EX_ALIAS = process.env.EX_ALIAS === '1';
export const CTX_LIMBS = EX_ALIAS ? 12 : CTX.length, WD_LIMBS = WD.length, CD_LIMBS = CD.length;

export function buildShared(q) {
  const Pbig = BigInt(P);
  const mP = (x) => (((BigInt(x) % Pbig) + Pbig) % Pbig).toString();       // canonical literal
  const nP = (x) => ((Pbig - ((BigInt(x) % Pbig) + Pbig) % Pbig) % Pbig).toString(); // baked negation
  const unpack = (blob, names) => { const L = [`    bytes ${blob}c = ${blob};`]; names.forEach((nm,i)=>{const last=i===names.length-1; L.push(`    int ${nm} = int(${blob}c.split(40)[0]);${last?'':` ${blob}c = ${blob}c.split(40)[1];`}`);}); return L.join('\n'); };
  // rb-recover: width-aware fixed unpack (mode@0 =40; lambdas 1..CDNW =32). Fixed-width read of a %P value
  // < 2^254 => int() recovers it losslessly (byte(w-1) < 0x40 => +ve), identical semantics to the 40B read.
  const CDNW = Number(process.env.CDNW ?? 1);
  const CDWIDTH = Number(process.env.CDWIDTH ?? 34);
  const CDW = (n) => Array.from({ length: n }, (_, i) => (i >= 1 && i <= CDNW) ? CDWIDTH : 40);
  const unpackW = (blob, names, widths) => { const L = [`    bytes ${blob}c = ${blob};`]; names.forEach((nm,i)=>{const w=widths[i];const last=i===names.length-1;const bindRaw=XOR_BIND && (nm==='saa' || nm==='sab'); L.push(bindRaw ? `    bytes ${nm}Bytes, bytes ${nm}Rest = ${blob}c.split(${w}); int ${nm} = int(${nm}Bytes);${last?` require(${nm}Rest.length == 0);`:` ${blob}c = ${nm}Rest;`}` : `    int ${nm} = int(${blob}c.split(${w})[0]);${last?'':` ${blob}c = ${blob}c.split(${w})[1];`}`);}); return L.join('\n'); };
  const UNW = Number(process.env.UNW ?? 16);
  const WDWIDTH = Number(process.env.WDWIDTH ?? 32);
  const WIDE_POS = new Set((process.env.WIDE_POS ?? '').split(',').filter(Boolean).map(Number));
  const WDW = Array.from({ length: WD.length }, (_, i) => WIDE_POS.has(i) ? 40 : (i < UNW ? WDWIDTH : 40));
  const FIXED_WDAT = process.env.FIXED_WDAT === '1';
  const DYN_PACK = process.env.DYN_PACK === '1';
  const RETAIN_CDAT = process.env.RETAIN_CDAT === '1';
  const RETAIN_WDAT = process.env.RETAIN_WDAT === '1';
  const XOR_BIND = process.env.XOR_BIND === '1';
  const PAD_HASH = process.env.PAD_HASH === '1';
  const NO_TAIL = process.env.NO_TAIL === '1';
  // BOUNDED-W1 VARIANT B: length-prefixed variable-width unpack (data-driven, chunk-agnostic). Each limb is
  // [1 len byte L][L LE bytes]; L in {32,40}. Reads L from the prefix so the ONE shared body decodes any
  // per-chunk width. Values are %P-reduced < 2^254 so int() recovers them losslessly (byte31 < 0x40 => +ve).
  const unpackLP = (blob, names) => { const L = [`    bytes ${blob}c = ${blob};`]; names.forEach((nm)=>{ L.push(`    bytes ${nm}_l, bytes ${nm}_a = ${blob}c.split(1); bytes ${nm}_d, bytes ${nm}_r = ${nm}_a.split(int(${nm}_l)); int ${nm} = int(${nm}_d); ${blob}c = ${nm}_r;`); }); return L.join('\n'); };
  // Compact cdat: mode is one byte; the remaining fixed record is parsed in mandatory-first order.
  // Mode-0 add fields are producer-zeroed and equality-bound, so fixed padding is not dead data.
  const cdatParse = () => {
    const widths = CDW(CD.length);
    const zero160 = `0x${'00'.repeat(160)}`;
    const L = ['    bytes cdm, bytes cdRest0 = cdat.split(1); int mode = int(cdm);', '    require(mode <= 2);'];
    let splitNo = 0;
    let rest = 'cdRest0';
    for (const [name, width] of [['lgd', widths[1]], ['lgD', widths[2]], ['ldd', widths[5]], ['ldD', widths[6]]]) {
      const next = `cdNext${splitNo++}`;
      L.push(`    bytes ${name}Bytes, bytes ${next} = ${rest}.split(${width}); int ${name} = int(${name}Bytes); ${rest} = ${next};`);
      rest = next;
    }
    L.push('    int lga = 0; int lgA = 0; int lda = 0; int ldA = 0;');
    if (XOR_BIND) {
      const z32 = `0x${'00'.repeat(32)}`;
      const z24 = `0x${'00'.repeat(24)}`;
      L.push(`    bytes deadLga0 = ${z32}; bytes deadLga1 = ${z32}; bytes deadLgA0 = ${z32}; bytes deadLgA1 = ${z32}; bytes deadLda0 = ${z32}; bytes deadLda1 = ${z32}; bytes deadLdA0 = ${z32}; bytes deadLdA1 = ${z32};`, `    if (mode == 0) { bytes cdPad, bytes cdTail = ${rest}.split(160); require(cdTail.length == 0); bytes d0, bytes dr0 = cdPad.split(40); bytes d1, bytes dr1 = dr0.split(40); bytes d2, bytes dr2 = dr1.split(40); bytes d3, bytes dr3 = dr2.split(40); require(dr3.length == 0); bytes d0l, bytes d0h = d0.split(32); bytes d1l, bytes d1h = d1.split(32); bytes d2l, bytes d2h = d2.split(32); bytes d3l, bytes d3h = d3.split(32); deadLga0 = d0l; deadLga1 = d0h + ${z24}; deadLgA0 = d1l; deadLgA1 = d1h + ${z24}; deadLda0 = d2l; deadLda1 = d2h + ${z24}; deadLdA0 = d3l; deadLdA1 = d3h + ${z24}; }`);
    } else if (PAD_HASH) {
      L.push(`    bytes pad = ${zero160};`, `    if (mode == 0) { bytes cdPad, bytes cdTail = ${rest}.split(160); require(cdTail.length == 0); pad = cdPad; }`);
    } else if (NO_TAIL) {
      L.push(`    if (mode == 0) { bytes cdPad, bytes cdTail = ${rest}.split(160); int unused cdTailLen = cdTail.length; require(cdPad == ${zero160}); }`);
    } else {
      L.push(`    if (mode == 0) { bytes cdPad, bytes cdTail = ${rest}.split(160); require(cdPad == ${zero160}); require(cdTail.length == 0); }`);
    }
    L.push('    if (mode >= 1) {');
    for (const [name, width] of [['lga', widths[3]], ['lgA', widths[4]], ['lda', widths[7]], ['ldA', widths[8]]]) {
      const next = `cdNext${splitNo++}`;
      L.push(`        bytes ${name}Bytes, bytes ${next} = ${rest}.split(${width}); ${name} = int(${name}Bytes); ${rest} = ${next};`);
    }
    L.push(`        require(${rest}.length == 0);`, '    }');
    return L.join('\n');
  };
  // Mode-first compact record: mode + mandatory cdat, optional add cdat, then wdat.
  // No mode-0 dead bytes exist; every retained field is consumed by the selected path.
  const cdatParseDyn = () => {
    const widths = CDW(CD.length);
    const L = ['    require(mode <= 2);'];
    let splitNo = 0;
    let rest = 'cdat';
    for (const [name, width] of [['lgd', widths[1]], ['lgD', widths[2]], ['ldd', widths[5]], ['ldD', widths[6]]]) {
      const next = `cdDyn${splitNo++}`;
      L.push(`    bytes ${name}Bytes, bytes ${next} = ${rest}.split(${width}); int ${name} = int(${name}Bytes); ${rest} = ${next};`);
      rest = next;
    }
    const mandatoryRest = rest;
    L.push('    int lga = 0; int lgA = 0; int lda = 0; int ldA = 0;');
    if (RETAIN_CDAT) {
      for (const [name, width] of [['lga', widths[3]], ['lgA', widths[4]], ['lda', widths[7]], ['ldA', widths[8]]]) {
        const next = `cdDyn${splitNo++}`;
        L.push(`    bytes ${name}Bytes, bytes ${next} = ${rest}.split(${width}); ${name} = int(${name}Bytes); ${rest} = ${next};`);
        rest = next;
      }
      L.push(`    require(${rest}.length == 0);`, '    if (mode == 0) { require(lga == lgd && lgA == lgD && lda == ldd && ldA == ldD); }');
    } else {
      L.push('    if (mode >= 1) {');
      for (const [name, width] of [['lga', widths[3]], ['lgA', widths[4]], ['lda', widths[7]], ['ldA', widths[8]]]) {
        const next = `cdDyn${splitNo++}`;
        L.push(`        bytes ${name}Bytes, bytes ${next} = ${rest}.split(${width}); ${name} = int(${name}Bytes); ${rest} = ${next};`);
        rest = next;
      }
      L.push(`        require(${rest}.length == 0);`, '    }', `    if (mode == 0) { require(${mandatoryRest}.length == 0); }`);
    }
    return L.join('\n');
  };
  const unpackDynW = () => {
    const widths = WDW;
    const L = ['    bytes wdatc = wdat;'];
    const take = (name, pos, indent = '    ') => {
      const w = widths[pos];
      L.push(`${indent}bytes ${name}Bytes, bytes ${name}Rest = wdatc.split(${w}); int ${name} = int(${name}Bytes); wdatc = ${name}Rest;`);
    };
    const takeAssign = (name, pos, indent = '    ') => {
      const w = widths[pos];
      L.push(`${indent}bytes ${name}Bytes, bytes ${name}Rest = wdatc.split(${w}); ${name} = int(${name}Bytes); wdatc = ${name}Rest;`);
    };
    take('sda', 0); take('sdb', 1);
    L.push('    int saa = 0; int sab = 0;');
    if (RETAIN_WDAT) {
      takeAssign('saa', 2); takeAssign('sab', 3);
      L.push('    if (mode == 0) { require(saa == sda && sab == sdb); }');
    } else {
      L.push('    if (mode >= 1) {');
      takeAssign('saa', 2, '        '); takeAssign('sab', 3, '        ');
      L.push('    }');
    }
    for (let k = 0; k < 12; k++) take(`ch${k}`, k + 4);
    L.push('    require(wdatc.length == 0);');
    return L.join('\n');
  };
  const be = (e) => `toPaddedBytes(${e},32).reverse()`;
  const bal = (a) => a.length === 1 ? a[0] : `(${bal(a.slice(0,a.length>>1))} + ${bal(a.slice(a.length>>1))})`;
  const foutPlain = `bytes foutblk = ${bal(Array.from({length:12},(_,k)=>be(`ch${k}`)))};`;
  const foutXor = [
    '    bytes f0 = ' + be('ch0') + '; bytes f1 = ' + be('ch1') + '; bytes f2 = ' + be('ch2') + '; bytes f3 = ' + be('ch3') + ';',
    '    bytes f4 = ' + be('ch4') + '; bytes f5 = ' + be('ch5') + '; bytes f6 = ' + be('ch6') + '; bytes f7 = ' + be('ch7') + ';',
    '    bytes f8 = ' + be('ch8') + '; bytes f9 = ' + be('ch9') + '; bytes f10 = ' + be('ch10') + '; bytes f11 = ' + be('ch11') + ';',
    '    if (mode == 0) { f0 = f0 ^ saaBytes; f1 = f1 ^ sabBytes; f2 = f2 ^ deadLga0; f3 = f3 ^ deadLga1; f4 = f4 ^ deadLgA0; f5 = f5 ^ deadLgA1; f6 = f6 ^ deadLda0; f7 = f7 ^ deadLda1; f8 = f8 ^ deadLdA0; f9 = f9 ^ deadLdA1; }',
    `    bytes foutblk = ${bal(Array.from({length:12},(_,k)=>`f${k}`))};`,
  ].join('\n');
  const stepU = `function stepU(int aggL,int aggF,int gp,int fC, bytes h, int gamma, int blkidx, int dotC,int dotCi,
        int rxa,int rxb,int rya,int ryb, int tgxa,int tgxb,int tgya,int tgyb, int tdxa,int tdxb,int tdya,int tdyb,
        int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3, int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,
        int ec0,int ec1,int ec2,int ec3,int ec4,int ec5,int ec6,int ec7,int ec8,int ec9,int ec10,int ec11,${EX_ALIAS ? '' : ' int ex4,int ex5,'} ${DYN_PACK ? 'int mode, ' : ''}bytes wdat, bytes cdat)
    returns (int,int,int,int, bytes, int,int,int,int, int,int,int,int, int,int,int,int) {
    int Pm = ${P};
${DYN_PACK ? `${cdatParseDyn()}\n${unpackDynW()}` : `${FIXED_WDAT ? unpackW('wdat', WD, WDW) : unpackLP('wdat', WD)}\n${cdatParse()}`}
${EX_ALIAS ? '    int ex4 = ec8; int ex5 = ec9;\n' : ''}${process.env.NITS !== '0' ? '    require(sda < Pm);\n' : ''}${DYN_PACK ? '' : (XOR_BIND ? '' : `    if (mode == 0) {\n        require(saa == 0 && sab == 0 && lga == 0 && lgA == 0 && lda == 0 && ldA == 0);\n    }\n`)}
    int fn = (${Array.from({length:12},(_,k)=>`ch${k}*ec${k}`).join('+')}) % Pm;
    ${XOR_BIND && !DYN_PACK ? foutXor.replace(/^/gm, '    ').trimStart() : foutPlain}
    int pf = 1; if (mode == 1) { pf = dotC; } if (mode == 2) { pf = dotCi; }
    (int a0,int a1,int a2,int a3,int a4,int a5, int R0,int R1,int R2,int R3) = affDbl(rxa,rxb,rya,ryb,sda,sdb);
    pf = fold1(Pm, pf, a0,a1,a2,a3,a4,a5, kn0,kn1,kn2,kn3, ex4,ex5);
    (int b0,int b1,int b2,int b3,int b4,int b5, int G0,int G1,int G2,int G3) = affDblT(tgxa,tgxb,tgya,tgyb,lgd,lgD);
    pf = fold1(Pm, pf, b0,b1,b2,b3,b4,b5, kv0,kv1,kv2,kv3, ex4,ex5);
    (int uo0,int uo1,int uo2,int uo3,int uo4,int uo5, int D0,int D1,int D2,int D3) = affDblT(tdxa,tdxb,tdya,tdyb,ldd,ldD);
    pf = fold1(Pm, pf, uo0,uo1,uo2,uo3,uo4,uo5, kc0,kc1,kc2,kc3, ex4,ex5);
    if (mode >= 1) {
        int qy0a = Bya; int qy0b = Byb;
        int gqya = ${q.GQYA}; int gqyb = ${q.GQYB}; int dqya = ${q.DQYA}; int dqyb = ${q.DQYB};
        if (mode == 1) { qy0a = (Pm - Bya) % Pm; qy0b = (Pm - Byb) % Pm; gqya = (Pm - ${q.GQYA}) % Pm; gqyb = (Pm - ${q.GQYB}) % Pm; dqya = (Pm - ${q.DQYA}) % Pm; dqyb = (Pm - ${q.DQYB}) % Pm; }
        (int aa0,int aa1,int aa2,int aa3,int aa4,int aa5, int rr0,int rr1,int rr2,int rr3) = affAdd(R0,R1,R2,R3, Bxa,Bxb,qy0a,qy0b, saa,sab);
        pf = fold1(Pm, pf, aa0,aa1,aa2,aa3,aa4,aa5, kn0,kn1,kn2,kn3, ex4,ex5); R0=rr0;R1=rr1;R2=rr2;R3=rr3;
        (int bb0,int bb1,int bb2,int bb3,int bb4,int bb5, int gg0,int gg1,int gg2,int gg3) = affAddT(G0,G1,G2,G3, ${q.GQXA},${q.GQXB},gqya,gqyb, lga,lgA);
        pf = fold1(Pm, pf, bb0,bb1,bb2,bb3,bb4,bb5, kv0,kv1,kv2,kv3, ex4,ex5); G0=gg0;G1=gg1;G2=gg2;G3=gg3;
        (int uu0,int uu1,int uu2,int uu3,int uu4,int uu5, int dd0,int dd1,int dd2,int dd3) = affAddT(D0,D1,D2,D3, ${q.DQXA},${q.DQXB},dqya,dqyb, lda,ldA);
        pf = fold1(Pm, pf, uu0,uu1,uu2,uu3,uu4,uu5, kc0,kc1,kc2,kc3, ex4,ex5); D0=dd0;D1=dd1;D2=dd2;D3=dd3;
    }
    // The remainder operator retains a negative dividend in the BCH VM. Each of these values is
    // serialized into a fixed-width field limb, so normalize the equivalent
    // field representative before forwarding it to the next executor.
    pf = (pf + Pm) % Pm;
    fn = (fn + Pm) % Pm;
    int t_l = (((fC*fC) % Pm) * pf) % Pm;
    int nAggL = (aggL + Pm + (gp * t_l) % Pm) % Pm;
    int nAggF = (aggF + Pm + (gp * fn) % Pm) % Pm;
    int nG = (gp * gamma) % Pm;
    bytes nh = hash256(h + toPaddedBytes(blkidx,4).reverse() + 0x00000180 + foutblk${PAD_HASH && !DYN_PACK && !XOR_BIND ? ' + pad' : ''});
    return nAggL, nAggF, nG, fn, nh, R0,R1,R2,R3, G0,G1,G2,G3, D0,D1,D2,D3; }`;
  return [affDblT, affAddT, fold1, stepU].join('\n');
}
