// tools/instrument/funcs.mjs
// ---------------------------------------------------------------------------
// Per-FUNCTION op-cost instrument (task #10): the catalogue of every BN254
// tower field function we attribute, each defined as a *self-feeding* CashScript
// fragment so we can call it N times in an unrolled chain and take the marginal
// op-cost per call. Source-of-truth bodies are copied verbatim from the graders
// (fp2.cash / fp6.cash / fp12.cash / mul034.cash / g2lines.cash / miller4.cash)
// so the instrument measures the EXACT code that runs inside miller4.cash.
//
// Each function entry provides:
//   name      : attribution key
//   defs      : the internal-function definitions this target needs (deduped at
//               emit time across all targets present in a contract)
//   stateN    : how many ints the chained "state" carries (== fan-in we reseed)
//   call(i)   : emits ONE invocation of the target, reading state vars s0..s{N-1}
//               of the PREVIOUS iteration and writing fresh `t{i}_*` outputs, then
//               rebinds s0..s{N-1} so the next call consumes this call's outputs.
//               Outputs are folded back into the N-int state via cheap re-use so
//               the optimiser can never treat a call as dead.
//
// The differential cancels everything that is identical between the K-call and
// (K+dK)-call contracts: the chain rebinding `int sX = ...` ops are present in
// BOTH and per-iteration-identical, so (cost(K+dK)-cost(K))/dK isolates the
// target call plus the constant rebinding glue. A SECOND "glue-only" build (same
// chain, target replaced by an identity rebind of equal output arity) measures
// that glue, and unit = call_delta - glue_delta. See unit-costs.mjs.
// ---------------------------------------------------------------------------

export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr = '21888242871839275222246405745257275088696311157297823662689037894645226208583';

// ---- shared internal-function source (verbatim from the graders) -----------
const DEFS = {
  addFp: `internal function addFp(int x, int y) returns (int) { return (x + y) % ${Pstr}; }`,
  subFp: `internal function subFp(int x, int y) returns (int) { return (x - y + ${Pstr}) % ${Pstr}; }`,
  mulFp: `internal function mulFp(int x, int y) returns (int) { return (x * y) % ${Pstr}; }`,
  fp2Add: `internal function fp2Add(int a0,int a1,int b0,int b1) returns (int,int) { return addFp(a0,b0), addFp(a1,b1); }`,
  fp2Sub: `internal function fp2Sub(int a0,int a1,int b0,int b1) returns (int,int) { return subFp(a0,b0), subFp(a1,b1); }`,
  fp2Neg: `internal function fp2Neg(int a0,int a1) returns (int,int) { return subFp(0,a0), subFp(0,a1); }`,
  fp2Mul: `internal function fp2Mul(int a0,int a1,int b0,int b1) returns (int,int) {
    int v0 = mulFp(a0,b0); int v1 = mulFp(a1,b1);
    return subFp(v0,v1), subFp(mulFp(addFp(a0,a1), addFp(b0,b1)), addFp(v0,v1)); }`,
  fp2Sqr: `internal function fp2Sqr(int a0,int a1) returns (int,int) {
    return mulFp(addFp(a0,a1), subFp(a0,a1)), mulFp(2, mulFp(a0,a1)); }`,
  fp2Scale: `internal function fp2Scale(int a0,int a1,int k) returns (int,int) { return mulFp(a0,k), mulFp(a1,k); }`,
  fp2MulXi: `internal function fp2MulXi(int a0,int a1) returns (int,int) { return subFp(mulFp(9,a0), a1), addFp(mulFp(9,a1), a0); }`,
  fp2Conj: `internal function fp2Conj(int a0,int a1) returns (int,int) { return a0, subFp(0,a1); }`,
  fp2MulByB: `internal function fp2MulByB(int a0,int a1) returns (int,int) {
    (int r0,int r1) = fp2Mul(a0,a1, 19485874751759354771024239261021720505790618469301721065564631296452457478373, 266929791119991161246907387137283842545076965332900288569378510910307636690);
    return r0,r1; }`,
  fp2Half: `internal function fp2Half(int a0,int a1) returns (int,int) {
    return mulFp(a0, 10944121435919637611123202872628637544348155578648911831344518947322613104292),
           mulFp(a1, 10944121435919637611123202872628637544348155578648911831344518947322613104292); }`,
  fp6Add: `internal function fp6Add(int a0a,int a0b,int a1a,int a1b,int a2a,int a2b,int b0a,int b0b,int b1a,int b1b,int b2a,int b2b) returns (int,int,int,int,int,int) {
    (int c0a,int c0b)=fp2Add(a0a,a0b,b0a,b0b); (int c1a,int c1b)=fp2Add(a1a,a1b,b1a,b1b); (int c2a,int c2b)=fp2Add(a2a,a2b,b2a,b2b);
    return c0a,c0b,c1a,c1b,c2a,c2b; }`,
  fp6Sub: `internal function fp6Sub(int a0a,int a0b,int a1a,int a1b,int a2a,int a2b,int b0a,int b0b,int b1a,int b1b,int b2a,int b2b) returns (int,int,int,int,int,int) {
    (int c0a,int c0b)=fp2Sub(a0a,a0b,b0a,b0b); (int c1a,int c1b)=fp2Sub(a1a,a1b,b1a,b1b); (int c2a,int c2b)=fp2Sub(a2a,a2b,b2a,b2b);
    return c0a,c0b,c1a,c1b,c2a,c2b; }`,
  fp6MulByV: `internal function fp6MulByV(int a0a,int a0b,int a1a,int a1b,int a2a,int a2b) returns (int,int,int,int,int,int) {
    (int n0a,int n0b)=fp2MulXi(a2a,a2b); return n0a,n0b,a0a,a0b,a1a,a1b; }`,
  fp6Mul: `internal function fp6Mul(int a0a,int a0b,int a1a,int a1b,int a2a,int a2b,int b0a,int b0b,int b1a,int b1b,int b2a,int b2b) returns (int,int,int,int,int,int) {
    (int t0a,int t0b)=fp2Mul(a0a,a0b,b0a,b0b); (int t1a,int t1b)=fp2Mul(a1a,a1b,b1a,b1b); (int t2a,int t2b)=fp2Mul(a2a,a2b,b2a,b2b);
    (int s1a,int s1b)=fp2Add(a1a,a1b,a2a,a2b); (int s2a,int s2b)=fp2Add(b1a,b1b,b2a,b2b);
    (int p1a,int p1b)=fp2Mul(s1a,s1b,s2a,s2b); (int d1a,int d1b)=fp2Sub(p1a,p1b,t1a,t1b); (int d2a,int d2b)=fp2Sub(d1a,d1b,t2a,t2b);
    (int x1a,int x1b)=fp2MulXi(d2a,d2b); (int c0a,int c0b)=fp2Add(t0a,t0b,x1a,x1b);
    (int s3a,int s3b)=fp2Add(a0a,a0b,a1a,a1b); (int s4a,int s4b)=fp2Add(b0a,b0b,b1a,b1b);
    (int p2a,int p2b)=fp2Mul(s3a,s3b,s4a,s4b); (int d3a,int d3b)=fp2Sub(p2a,p2b,t0a,t0b); (int d4a,int d4b)=fp2Sub(d3a,d3b,t1a,t1b);
    (int x2a,int x2b)=fp2MulXi(t2a,t2b); (int c1a,int c1b)=fp2Add(d4a,d4b,x2a,x2b);
    (int s5a,int s5b)=fp2Add(a0a,a0b,a2a,a2b); (int s6a,int s6b)=fp2Add(b0a,b0b,b2a,b2b);
    (int p3a,int p3b)=fp2Mul(s5a,s5b,s6a,s6b); (int d5a,int d5b)=fp2Sub(p3a,p3b,t0a,t0b); (int d6a,int d6b)=fp2Sub(d5a,d5b,t2a,t2b);
    (int c2a,int c2b)=fp2Add(d6a,d6b,t1a,t1b);
    return c0a,c0b,c1a,c1b,c2a,c2b; }`,
  fp6Mul01: `internal function fp6Mul01(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int b0a,int b0b,int b1a,int b1b) returns (int,int,int,int,int,int) {
    (int t0a,int t0b)=fp2Mul(c0a,c0b,b0a,b0b); (int t1a,int t1b)=fp2Mul(c1a,c1b,b1a,b1b);
    (int s12a,int s12b)=fp2Add(c1a,c1b,c2a,c2b); (int m12a,int m12b)=fp2Mul(s12a,s12b,b1a,b1b);
    (int u0a,int u0b)=fp2Sub(m12a,m12b,t1a,t1b); (int xu0a,int xu0b)=fp2MulXi(u0a,u0b); (int r0a,int r0b)=fp2Add(xu0a,xu0b,t0a,t0b);
    (int sba,int sbb)=fp2Add(b0a,b0b,b1a,b1b); (int sca,int scb)=fp2Add(c0a,c0b,c1a,c1b);
    (int m1a,int m1b)=fp2Mul(sba,sbb,sca,scb); (int u1a,int u1b)=fp2Sub(m1a,m1b,t0a,t0b); (int r1a,int r1b)=fp2Sub(u1a,u1b,t1a,t1b);
    (int s02a,int s02b)=fp2Add(c0a,c0b,c2a,c2b); (int m2a,int m2b)=fp2Mul(s02a,s02b,b0a,b0b);
    (int u2a,int u2b)=fp2Sub(m2a,m2b,t0a,t0b); (int r2a,int r2b)=fp2Add(u2a,u2b,t1a,t1b);
    return r0a,r0b,r1a,r1b,r2a,r2b; }`,
  fp12Mul: FP12MUL(),
  fp12Sqr: `internal function fp12Sqr(int A0,int A1,int A2,int A3,int A4,int A5,int A6,int A7,int A8,int A9,int A10,int A11) returns (int,int,int,int,int,int,int,int,int,int,int,int) {
    (int C0,int C1,int C2,int C3,int C4,int C5,int C6,int C7,int C8,int C9,int C10,int C11) = fp12Mul(A0,A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11, A0,A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11);
    return C0,C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11; }`,
  mul034: MUL034(),
  line: LINE(),
  pointDouble: POINTDOUBLE(),
  pointAdd: POINTADD(),
  psi: PSI(),
};

function FP12MUL() {
  return `internal function fp12Mul(
    int A0,int A1,int A2,int A3,int A4,int A5,int A6,int A7,int A8,int A9,int A10,int A11,
    int B0,int B1,int B2,int B3,int B4,int B5,int B6,int B7,int B8,int B9,int B10,int B11) returns (int,int,int,int,int,int,int,int,int,int,int,int) {
    (int t0_0,int t0_1,int t0_2,int t0_3,int t0_4,int t0_5)=fp6Mul(A0,A1,A2,A3,A4,A5,B0,B1,B2,B3,B4,B5);
    (int t1_0,int t1_1,int t1_2,int t1_3,int t1_4,int t1_5)=fp6Mul(A6,A7,A8,A9,A10,A11,B6,B7,B8,B9,B10,B11);
    (int vt_0,int vt_1,int vt_2,int vt_3,int vt_4,int vt_5)=fp6MulByV(t1_0,t1_1,t1_2,t1_3,t1_4,t1_5);
    (int C0,int C1,int C2,int C3,int C4,int C5)=fp6Add(t0_0,t0_1,t0_2,t0_3,t0_4,t0_5,vt_0,vt_1,vt_2,vt_3,vt_4,vt_5);
    (int sa_0,int sa_1,int sa_2,int sa_3,int sa_4,int sa_5)=fp6Add(A0,A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11);
    (int sb_0,int sb_1,int sb_2,int sb_3,int sb_4,int sb_5)=fp6Add(B0,B1,B2,B3,B4,B5,B6,B7,B8,B9,B10,B11);
    (int pr_0,int pr_1,int pr_2,int pr_3,int pr_4,int pr_5)=fp6Mul(sa_0,sa_1,sa_2,sa_3,sa_4,sa_5,sb_0,sb_1,sb_2,sb_3,sb_4,sb_5);
    (int qq_0,int qq_1,int qq_2,int qq_3,int qq_4,int qq_5)=fp6Sub(pr_0,pr_1,pr_2,pr_3,pr_4,pr_5,t0_0,t0_1,t0_2,t0_3,t0_4,t0_5);
    (int C6,int C7,int C8,int C9,int C10,int C11)=fp6Sub(qq_0,qq_1,qq_2,qq_3,qq_4,qq_5,t1_0,t1_1,t1_2,t1_3,t1_4,t1_5);
    return C0,C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11; }`;
}
function MUL034() {
  return `internal function mul034(
    int F0,int F1,int F2,int F3,int F4,int F5,int F6,int F7,int F8,int F9,int F10,int F11,
    int o0a,int o0b,int o3a,int o3b,int o4a,int o4b) returns (int,int,int,int,int,int,int,int,int,int,int,int) {
    (int A0,int A1)=fp2Mul(F0,F1,o0a,o0b); (int A2,int A3)=fp2Mul(F2,F3,o0a,o0b); (int A4,int A5)=fp2Mul(F4,F5,o0a,o0b);
    (int B0,int B1,int B2,int B3,int B4,int B5)=fp6Mul01(F6,F7,F8,F9,F10,F11,o3a,o3b,o4a,o4b);
    (int S0,int S1,int S2,int S3,int S4,int S5)=fp6Add(F0,F1,F2,F3,F4,F5,F6,F7,F8,F9,F10,F11);
    (int qa,int qb)=fp2Add(o0a,o0b,o3a,o3b);
    (int G0,int G1,int G2,int G3,int G4,int G5)=fp6Mul01(S0,S1,S2,S3,S4,S5,qa,qb,o4a,o4b);
    (int VB0,int VB1,int VB2,int VB3,int VB4,int VB5)=fp6MulByV(B0,B1,B2,B3,B4,B5);
    (int C0,int C1,int C2,int C3,int C4,int C5)=fp6Add(VB0,VB1,VB2,VB3,VB4,VB5,A0,A1,A2,A3,A4,A5);
    (int AB0,int AB1,int AB2,int AB3,int AB4,int AB5)=fp6Add(A0,A1,A2,A3,A4,A5,B0,B1,B2,B3,B4,B5);
    (int C6,int C7,int C8,int C9,int C10,int C11)=fp6Sub(G0,G1,G2,G3,G4,G5,AB0,AB1,AB2,AB3,AB4,AB5);
    return C0,C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11; }`;
}
function LINE() {
  return `internal function line(
    int F0,int F1,int F2,int F3,int F4,int F5,int F6,int F7,int F8,int F9,int F10,int F11,
    int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int Px,int Py) returns (int,int,int,int,int,int,int,int,int,int,int,int) {
    int o0a=mulFp(c2a,Py); int o0b=mulFp(c2b,Py); int o3a=mulFp(c1a,Px); int o3b=mulFp(c1b,Px);
    (int r0,int r1,int r2,int r3,int r4,int r5,int r6,int r7,int r8,int r9,int r10,int r11)=
      mul034(F0,F1,F2,F3,F4,F5,F6,F7,F8,F9,F10,F11,o0a,o0b,o3a,o3b,c0a,c0b);
    return r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11; }`;
}
function POINTDOUBLE() {
  return `internal function pointDouble(int Xa,int Xb,int Ya,int Yb,int Za,int Zb) returns (int,int,int,int,int,int,int,int,int,int,int,int) {
    (int t0a,int t0b)=fp2Sqr(Ya,Yb); (int t1a,int t1b)=fp2Sqr(Za,Zb); (int s1a,int s1b)=fp2Scale(t1a,t1b,3);
    (int t2a,int t2b)=fp2MulByB(s1a,s1b); (int t3a,int t3b)=fp2Scale(t2a,t2b,3);
    (int yza,int yzb)=fp2Add(Ya,Yb,Za,Zb); (int sq_a,int sq_b)=fp2Sqr(yza,yzb);
    (int u4a,int u4b)=fp2Sub(sq_a,sq_b,t1a,t1b); (int t4a,int t4b)=fp2Sub(u4a,u4b,t0a,t0b);
    (int c0a,int c0b)=fp2Sub(t2a,t2b,t0a,t0b); (int rxq_a,int rxq_b)=fp2Sqr(Xa,Xb); (int c1a,int c1b)=fp2Scale(rxq_a,rxq_b,3);
    (int c2a,int c2b)=fp2Neg(t4a,t4b); (int da,int db)=fp2Sub(t0a,t0b,t3a,t3b);
    (int dxa,int dxb)=fp2Mul(da,db,Xa,Xb); (int dxya,int dxyb)=fp2Mul(dxa,dxb,Ya,Yb); (int nxa,int nxb)=fp2Half(dxya,dxyb);
    (int sa,int sb)=fp2Add(t0a,t0b,t3a,t3b); (int sha,int shb)=fp2Half(sa,sb); (int sh2a,int sh2b)=fp2Sqr(sha,shb);
    (int t2sa,int t2sb)=fp2Sqr(t2a,t2b); (int t2s3a,int t2s3b)=fp2Scale(t2sa,t2sb,3); (int nya,int nyb)=fp2Sub(sh2a,sh2b,t2s3a,t2s3b);
    (int nza,int nzb)=fp2Mul(t0a,t0b,t4a,t4b);
    return c0a,c0b,c1a,c1b,c2a,c2b,nxa,nxb,nya,nyb,nza,nzb; }`;
}
function POINTADD() {
  return `internal function pointAdd(int Xa,int Xb,int Ya,int Yb,int Za,int Zb,int Qxa,int Qxb,int Qya,int Qyb) returns (int,int,int,int,int,int,int,int,int,int,int,int) {
    (int qyz_a,int qyz_b)=fp2Mul(Qya,Qyb,Za,Zb); (int t0a,int t0b)=fp2Sub(Ya,Yb,qyz_a,qyz_b);
    (int qxz_a,int qxz_b)=fp2Mul(Qxa,Qxb,Za,Zb); (int t1a,int t1b)=fp2Sub(Xa,Xb,qxz_a,qxz_b);
    (int t0qx_a,int t0qx_b)=fp2Mul(t0a,t0b,Qxa,Qxb); (int t1qy_a,int t1qy_b)=fp2Mul(t1a,t1b,Qya,Qyb);
    (int c0a,int c0b)=fp2Sub(t0qx_a,t0qx_b,t1qy_a,t1qy_b); (int c1a,int c1b)=fp2Neg(t0a,t0b); int c2a=t1a; int c2b=t1b;
    (int t2a,int t2b)=fp2Sqr(t1a,t1b); (int t3a,int t3b)=fp2Mul(t2a,t2b,t1a,t1b); (int t4a,int t4b)=fp2Mul(t2a,t2b,Xa,Xb);
    (int t42a,int t42b)=fp2Scale(t4a,t4b,2); (int d35a,int d35b)=fp2Sub(t3a,t3b,t42a,t42b);
    (int t0sa,int t0sb)=fp2Sqr(t0a,t0b); (int t0sza,int t0szb)=fp2Mul(t0sa,t0sb,Za,Zb); (int t5a,int t5b)=fp2Add(d35a,d35b,t0sza,t0szb);
    (int nxa,int nxb)=fp2Mul(t1a,t1b,t5a,t5b); (int d45a,int d45b)=fp2Sub(t4a,t4b,t5a,t5b); (int d45t0a,int d45t0b)=fp2Mul(d45a,d45b,t0a,t0b);
    (int t3rya,int t3ryb)=fp2Mul(t3a,t3b,Ya,Yb); (int nya,int nyb)=fp2Sub(d45t0a,d45t0b,t3rya,t3ryb); (int nza,int nzb)=fp2Mul(Za,Zb,t3a,t3b);
    return c0a,c0b,c1a,c1b,c2a,c2b,nxa,nxb,nya,nyb,nza,nzb; }`;
}
function PSI() {
  return `internal function psi(int xa,int xb,int ya,int yb) returns (int,int,int,int) {
    (int cxa,int cxb)=fp2Conj(xa,xb);
    (int pxa,int pxb)=fp2Mul(cxa,cxb, 21575463638280843010398324269430826099269044274347216827212613867836435027261, 10307601595873709700152284273816112264069230130616436755625194854815875713954);
    (int cya,int cyb)=fp2Conj(ya,yb);
    (int pya,int pyb)=fp2Mul(cya,cyb, 2821565182194536844548159561693502659359617185244120367078079554186484126554, 3505843767911556378687030309984248845540243509899259641013678093033130930403);
    return pxa,pxb,pya,pyb; }`;
}

// dependency closure -> ordered list of DEFS keys needed for a set of roots
const DEPS = {
  addFp: [], subFp: [], mulFp: [],
  fp2Add: ['addFp'], fp2Sub: ['subFp'], fp2Neg: ['subFp'], fp2Mul: ['mulFp', 'addFp', 'subFp'],
  fp2Sqr: ['mulFp', 'addFp', 'subFp'], fp2Scale: ['mulFp'], fp2MulXi: ['mulFp', 'subFp', 'addFp'],
  fp2Conj: ['subFp'], fp2MulByB: ['fp2Mul'], fp2Half: ['mulFp'],
  fp6Add: ['fp2Add'], fp6Sub: ['fp2Sub'], fp6MulByV: ['fp2MulXi'],
  fp6Mul: ['fp2Mul', 'fp2Add', 'fp2Sub', 'fp2MulXi'], fp6Mul01: ['fp2Mul', 'fp2Add', 'fp2Sub', 'fp2MulXi'],
  fp12Mul: ['fp6Mul', 'fp6MulByV', 'fp6Add', 'fp6Sub'], fp12Sqr: ['fp12Mul'],
  mul034: ['fp2Mul', 'fp2Add', 'fp6Mul01', 'fp6Add', 'fp6Sub', 'fp6MulByV'],
  line: ['mulFp', 'mul034'],
  pointDouble: ['fp2Sqr', 'fp2Scale', 'fp2MulByB', 'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Mul', 'fp2Half'],
  pointAdd: ['fp2Mul', 'fp2Sub', 'fp2Neg', 'fp2Sqr', 'fp2Scale', 'fp2Add'],
  psi: ['fp2Conj', 'fp2Mul'],
};

export function closure(root) {
  const seen = new Set();
  const order = [];
  const visit = (k) => {
    if (seen.has(k)) return;
    seen.add(k);
    for (const d of (DEPS[k] || [])) visit(d);
    order.push(k);
  };
  visit(root);
  return order;
}

export function defsFor(root) {
  return closure(root).map((k) => '    ' + DEFS[k]).join('\n');
}

// ---------------------------------------------------------------------------
// TARGETS: arity (#inputs, #outputs) + how to seed real operands + a chained
// call emitter. `inN` ints consumed, `outN` ints produced. The chained micro
// contract keeps a rolling window of WIN ints; each call reads inN of them
// (padded/sliced) and folds outN outputs back in.
// ---------------------------------------------------------------------------
export const TARGETS = {
  mulFp:       { inN: 2,  outN: 1,  call: 'mulFp' },
  addFp:       { inN: 2,  outN: 1,  call: 'addFp' },
  subFp:       { inN: 2,  outN: 1,  call: 'subFp' },
  fp2Mul:      { inN: 4,  outN: 2,  call: 'fp2Mul' },
  fp2Sqr:      { inN: 2,  outN: 2,  call: 'fp2Sqr' },
  fp2MulXi:    { inN: 2,  outN: 2,  call: 'fp2MulXi' },
  fp6Mul:      { inN: 12, outN: 6,  call: 'fp6Mul' },
  fp6Add:      { inN: 12, outN: 6,  call: 'fp6Add' },
  fp6Sub:      { inN: 12, outN: 6,  call: 'fp6Sub' },
  fp6MulByV:   { inN: 6,  outN: 6,  call: 'fp6MulByV' },
  fp12Mul:     { inN: 24, outN: 12, call: 'fp12Mul' },
  fp12Sqr:     { inN: 12, outN: 12, call: 'fp12Sqr' },
  mul034:      { inN: 18, outN: 12, call: 'mul034' },
  line:        { inN: 20, outN: 12, call: 'line' },
  pointDouble: { inN: 6,  outN: 12, call: 'pointDouble' },
  pointAdd:    { inN: 10, outN: 12, call: 'pointAdd' },
  psi:         { inN: 4,  outN: 4,  call: 'psi' },
};

export const TARGET_ORDER = [
  'mulFp', 'addFp', 'subFp',
  'fp2Mul', 'fp2Sqr', 'fp2MulXi',
  'fp6Add', 'fp6Sub', 'fp6MulByV', 'fp6Mul',
  'fp12Mul', 'fp12Sqr',
  'mul034', 'line',
  'pointDouble', 'pointAdd', 'psi',
];
