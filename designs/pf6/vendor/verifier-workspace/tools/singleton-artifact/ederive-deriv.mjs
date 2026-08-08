// Derivation op-sequence for E=(p^12-1)/r. Export buildDeriv() -> [op records].
export function toLEnum(n){let b=[];let v=n;while(v>0n){b.push(Number(v&255n));v>>=8n;}if(b.length===0)b=[0];if(b[b.length-1]&0x80)b.push(0);return Uint8Array.from(b);}
export function buildDeriv(){
  const X=4965661367192848881n;
  const P=(d)=>({data:d});              // data push
  const O=(op)=>({op});                 // opcode
  const num=(n)=>P(toLEnum(BigInt(n))); // literal number push
  const OVER=0x78,MUL=0x95,ADD=0x93,SUB=0x94,DUP=0x76,PICK=0x79,ROT=0x7b,DROP=0x75,SWAP=0x7c,OP1SUB=0x8c,DIV=0x96;
  const OP1=0x51,OP2=0x52,OP6=0x56;
  const s=[];
  s.push(P(toLEnum(X)));                 // [x]
  // Horner p = (((36x+36)x+24)x+6)x+1, keep x at bottom via OVER
  s.push(num(36));                       // [x,36]
  s.push(O(OVER),O(MUL));                // [x,36x]
  s.push(num(36),O(ADD));                // [x,36x+36]
  s.push(O(OVER),O(MUL));
  s.push(num(24),O(ADD));
  s.push(O(OVER),O(MUL));
  s.push(O(OP6),O(ADD));
  s.push(O(OVER),O(MUL));
  s.push(O(OP1),O(ADD));                 // [x,p]
  // r = p - 6*x^2 ; keep p
  s.push(O(DUP));                        // [x,p,p]
  s.push(O(OP2),O(PICK));                // [x,p,p,x]
  s.push(O(DUP),O(MUL));                 // [x,p,p,x2]
  s.push(O(OP6),O(MUL));                 // [x,p,p,6x2]
  s.push(O(SUB));                        // [x,p,r]
  s.push(O(ROT),O(DROP));               // [p,r]  (drop x)
  s.push(O(SWAP));                       // [r,p]
  // p^12
  s.push(O(DUP),O(MUL));                 // [r,p2]
  s.push(O(DUP),O(MUL));                 // [r,p4]
  s.push(O(DUP),O(DUP),O(MUL),O(MUL));   // [r,p12]
  s.push(O(OP1),O(SUB));                 // [r,p12-1]  (OP_1SUB 0x8c not decompiler-supported)
  s.push(O(SWAP),O(DIV));                // [E]
  return s;
}
