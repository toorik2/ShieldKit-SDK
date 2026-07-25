import { bigIntToVmNumber } from '@bitauth/libauth';
import { measureRun, decompose } from '/home/toorik/Projects/LeanBCH/optimizer/cost.mjs';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const N = 12;
// opcodes
const TOALT=0x6b, FROMALT=0x6c, ROLL=0x7a, ADD=0x93, DROP=0x75, OP_1=0x51, DEPTH=0x74, ADD1=0x93;
const pushN=(n)=>{ if(n===0) return [0x00]; if(n>=1&&n<=16) return [0x50+n]; const b=[]; let v=n; while(v>0){b.push(v&0xff); v>>=8;} if(b[b.length-1]&0x80)b.push(0); return [b.length,...b]; };
// unlocking: push 12 near-P field elements (x0 bottom ... x11 top)
const xs = Array.from({length:N},(_,i)=> P - BigInt(1+i*7));
const pushItem=(n)=>{const d=bigIntToVmNumber(n); return [d.length,...d];};
const unlock = Uint8Array.from(xs.flatMap(pushItem)); // x0 pushed first => bottom

// ---- Variant MAIN: left-fold x0..x11 (x0 deepest) using ROLL to fetch each next operand ----
// stack [x0..x11]. Bring x0 (depth 11) up: 11 ROLL -> [x1..x11 x0]. Then repeatedly: the next
// wanted item is at depth 11 (bottom); `11 ROLL` brings it up; ADD with running acc on top.
// Sequence: 11 ROLL (acc=x0 on top, 11 items below). loop 11 times: 11 ROLL (brings next bottom
// item to top), but acc is now buried under it -> need SWAP? Let's do: keep acc at BOTTOM instead.
// Simpler faithful deep-fold: for k=0..10: `<11-k> ... ` hmm. Use the clean canonical:
// acc starts as top (x11). For k=10 downTo 0: bring x_k (currently deepest, depth = k) to top via
// `<k> ROLL`, ADD. After each ADD stack shrinks by 1.  depths: 10,9,...,0 -> but that's SHALLOW.
// To get DEEP (alt best-case) we fold in bottom-first order: acc=x0 needs depth 11 fetches.
// Canonical deep left-fold: rotate bottom to top each step.
function mainFold(){
  const ops=[];
  ops.push(...pushN(N-1), ROLL);             // bring x0 (depth 11) to top: [x1..x11 x0]
  for(let d=N-1; d>=1; d--){                  // depths 11,10,...,1 as stack shrinks
    ops.push(...pushN(d), ROLL);             // bring current-bottom operand to top
    ops.push(ADD);                            // acc += item
  }
  ops.push(DROP, OP_1);                       // succeed
  return Uint8Array.from(ops);
}
// ---- Variant ALT: park all to alt (LIFO), then FROMALT in order and fold ----
function altFold(){
  const ops=[];
  for(let i=0;i<N;i++) ops.push(TOALT);       // pop x11..x0 -> alt top = x0
  ops.push(FROMALT);                          // acc = x0
  for(let k=0;k<N-1;k++){ ops.push(FROMALT, ADD); } // pull x1..x11, add
  ops.push(DROP, OP_1);
  return Uint8Array.from(ops);
}
for(const [tag,fn] of [['MAIN(ROLL)',mainFold],['ALT(park)',altFold]]){
  const bc=fn();
  const r=measureRun(bc,unlock); const d=decompose(r);
  console.log(`${tag.padEnd(12)} lock=${bc.length}B opCost=${String(r.opCost).padStart(7)} instr=${r.instr} push=${r.push} arith=${r.arith}  ok=${r.ok} err=${r.error?r.error.slice(0,30):''}`);
}
