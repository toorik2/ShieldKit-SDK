// Track B prototype: a GENERATOR that emits HAND-OPTIMIZED Bitcoin Cash Script for
// the SAME 12-frame loop as frame12.cash, tracking the stack model so OP_PICK/ROLL
// indices stay correct. Key technique (the answer to F5/F6): never store a value
// back to a fixed deep slot. Each iter computes all 12 new values on top, then
// swaps the whole frame ONCE via the altstack (12 TOALTSTACK + 12 DROP + 12
// FROMALTSTACK) — restoring frame order, body shape-neutral. Measures the real
// cashc-vs-hand ratio. This is the prototype of the Miller-frame generator.
import { push, measure, O, P } from './asm-measure.mjs';

const N = 30;
const a0 = []; for (let i = 0; i < 12; i++) a0.push((1000003n * BigInt(i + 1) + 7n) % P);
// JS reference: expected frame after N iters of new_i = (a_i + a_{(i+1)%12}) % P
let cur = a0.slice();
for (let k = 0; k < N; k++) cur = cur.map((_, i) => (cur[i] + cur[(i + 1) % 12]) % P);
const expected = cur;

function gen(exp) {
  const code = [];
  const M = []; // stack model, index 0 = top
  const emit = (...b) => b.flat(Infinity).forEach((x) => code.push(x));
  const idx = (name) => { const d = M.indexOf(name); if (d < 0) throw new Error('missing ' + name + ' M=' + M); return d; };
  const pick = (name) => { emit(push(idx(name)), O.OP_PICK); M.unshift(name + '#'); };       // copy to top
  const roll = (name) => { const d = idx(name); emit(push(d), O.OP_ROLL); M.splice(d, 1); M.unshift(name); }; // move to top
  const pv = (v, n) => { emit(push(v)); M.unshift(n); };
  const bin = (opc, n) => { emit(opc); M.shift(); M.shift(); M.unshift(n); };               // pop2 push1

  // init frame: push a0..a11 (a0 deepest, a11 on top)
  for (let i = 0; i < 12; i++) { emit(push(a0[i])); M.unshift('a' + i); }

  for (let iter = 0; iter < N; iter++) {
    // compute n_i = (a_i + a_{(i+1)%12}) % P, leaving 12 new on top of the 12 old
    for (let i = 0; i < 12; i++) {
      pick('a' + i); pick('a' + ((i + 1) % 12)); bin(O.OP_ADD, 'sum'); pv(P, 'P'); bin(O.OP_MOD, 'n' + i);
    }
    // swap the whole frame via altstack (no per-value deep store-back)
    for (let i = 0; i < 12; i++) { emit(O.OP_TOALTSTACK); M.shift(); }  // new -> alt
    for (let i = 0; i < 12; i++) { emit(O.OP_DROP); M.shift(); }        // drop old
    for (let k = 0; k < 12; k++) { emit(O.OP_FROMALTSTACK); M.unshift('a' + k); } // new back as a_k (order restored)
  }

  // final: verify frame == expected, leave [1]
  for (let i = 0; i < 12; i++) { roll('a' + i); pv(exp[i], 'e'); emit(O.OP_NUMEQUAL, O.OP_VERIFY); M.shift(); M.shift(); }
  emit(O.OP_1); M.unshift('(1)');
  return { code: Uint8Array.from(code), endModel: M };
}

const good = gen(expected);
const bad = gen(expected.map((v, i) => (i === 0 ? (v + 1n) % P : v)));
const rGood = measure(good.code);
const rBad = measure(bad.code);
console.log('HAND frame12 (n=30):', JSON.stringify(rGood));
console.log('  end-model (must be just [(1)]):', good.endModel.join(',') || '(empty)');
console.log('  BAD (wrong expected) accepted=', rBad.accepted, '(must be false)');
console.log('  contract bytes:', good.code.length);
// vs cashc baseline
const CASHC = 2743265;
console.log('  cashc frame12 op-cost:', CASHC.toLocaleString(), '| HAND:', rGood.opCost.toLocaleString(),
  '| ratio', (CASHC / rGood.opCost).toFixed(1) + '× cheaper', '| saved', (CASHC - rGood.opCost).toLocaleString());
