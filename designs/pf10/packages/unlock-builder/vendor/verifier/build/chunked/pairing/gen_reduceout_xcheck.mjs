// Generate a Lean file that runs the reduceOut arithmetic  (x + BIAS) % p  through the LeanBCH VM
// (independent consensus VM) for several worst-case dividends, so we can cross-check OP_ADD/OP_MOD
// semantics + [0,p) landing against the derived overflow bound. Also emits the libauth-side expected.
import { writeFileSync } from 'node:fs';
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BIAS = 202944716560641436058426135953785114602563281282574308384079289034824091685549821404793712422553157789241740953812104359610149043919352694135649979132063988983n;
const mod = (x)=>((x%P)+P)%P;
// libauth bigIntToVmNumber (sign-magnitude little-endian)
function toVmNum(z){ if(z===0n) return []; const neg=z<0n; let n=neg?-z:z; const out=[]; while(n>0n){out.push(Number(n&0xffn)); n>>=8n;} if(out[out.length-1]&0x80){out.push(neg?0x80:0x00);} else if(neg){out[out.length-1]|=0x80;} return out; }
function pushOp(bytes){ const len=bytes.length; if(len===0) return [0x00]; if(len<=75) return [len,...bytes]; if(len<=255) return [0x4c,len,...bytes]; return [0x4d,len&0xff,(len>>8)&0xff,...bytes]; }
const OP_ADD=0x93, OP_MOD=0x97;
function reduceOutBytecode(x){ return [...pushOp(toVmNum(x)), ...pushOp(toVmNum(BIAS)), OP_ADD, ...pushOp(toVmNum(P)), OP_MOD]; }

// Test dividends x (the fp12Sqr pre-reduce limb value). OFFSET (0<OFFSET<p) makes the residue
// discriminating: mod(-k*p^2 + OFFSET) = OFFSET, so the VM must reproduce OFFSET exactly.
const P2=P*P;
const OFFSET = 12345678901234567890123456789n;   // < p, the true residue we expect to recover
const cases = [
  ['zero',                         OFFSET,                    true],
  ['real_reachable_neg_2249p2',   -2249n*P2 + OFFSET,        true],   // observed worst in exact stress
  ['interval_worst_neg_247101p2', -247101n*P2 + OFFSET,      true],   // SOUND interval bound (composed regime)
  ['at_bias_edge_neg_423600p2',   -423600n*P2 + OFFSET,      true],   // bias sizing box worst (== bias margin 0)
  ['just_over_bias_neg_423601p2', -423601n*P2 + OFFSET,      false],  // DANGER: bias short by 1 p^2 -> must break
  ['loose_box_neg_467019p2',      -467019n*P2 + OFFSET,      false],  // uniform-21p box worst -> breaks if reachable
];

let lean = `import LeanBCH.VM.Eval
import LeanBCH.Number
open LeanBCH LeanBCH.VM

def topInt (s : State) : Int :=
  match s.stack with
  | b :: _ => vmNumberToBigInt b
  | [] => -999999999
def okState (s : State) : Bool := s.error.isNone && s.stack.length == 1

`;
const expects = [];
for (const [name, x, shouldBeInRange] of cases){
  const bc = reduceOutBytecode(x);
  const expected = mod(x); // correct residue in [0,p)
  const D = x + BIAS;      // dividend fed to OP_MOD
  lean += `def bc_${name} : List UInt8 := [${bc.join(', ')}]\n`;
  expects.push({name, expectedResidue: expected.toString(), dividendNonNeg: D>=0n, shouldBeInRange});
}
lean += `\ndef main : IO Unit := do\n`;
for (const [name] of cases){
  lean += `  let s_${name} := eval bc_${name}\n`;
  lean += `  IO.println s!"${name} ok={okState s_${name}} top={topInt s_${name}}"\n`;
}
writeFileSync('/tmp/reduceout_xcheck.lean', lean);
writeFileSync('/tmp/reduceout_expects.json', JSON.stringify(expects, null, 2));
console.log('=== reduceOut cross-check plan (expected, libauth-side / math truth) ===');
for (const e of expects){
  console.log(`  ${e.name.padEnd(30)} dividend>=0:${e.dividendNonNeg}  expectedResidue(mod p)=${e.expectedResidue.slice(0,20)}...  [0,p) achievable via bias:${e.shouldBeInRange}`);
}
console.log('\nLean file: /tmp/reduceout_xcheck.lean');
