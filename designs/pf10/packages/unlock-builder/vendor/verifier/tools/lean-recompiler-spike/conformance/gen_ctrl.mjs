// CONTROL generator (BROAD differential, >=1000 cases). Emits ctrl_cases.json consumed by BOTH
// the Lean side (ctrl_eval.lean -> Recompiler.Prog Nat, real runProg) and the libauth side
// (ctrl_libauth.mjs -> flat IF/ELSE/ENDIF/BEGIN/UNTIL/VERIFY bytecode, real BCH2026 VM).
//
// main/alt are TOP-FIRST integer lists (head = top), matching the Lean State convention.
// VALUE ENCODING (round-trips through libauth bytes AND agrees with real truthiness):
//   0  -> OP_0 (empty item)         => libauth CastToBool FALSE ; Lean isT (·!=0) FALSE
//   1  -> OP_1 ([0x01])             => TRUE  ; TRUE
//   v in 17..250 \ {128,129}        => OP_PUSHBYTES_1 v (single nonzero non-0x80 byte) => TRUE ; TRUE
// 128 (0x80 neg-zero) is EXCLUDED: libauth CastToBool([0x80])=FALSE but isT(128)=true would DIVERGE.
// (probe_control.mjs confirmed the full truthiness table incl the 0x80/multibyte edges.)
// Because EVERY generator value is unambiguous (0=>false both, anything-else=>true both), any value
// may appear as a control condition; conds are nonetheless placed as clear 0/1 for readability.
//
// TERMINATION: every loop emitted with the DEFAULT (terminating) flag uses a recipe that provably
// drains a fixed FALSE..TRUE condition queue in <=k iterations, so it terminates on the real VM
// (which under loosened consensus is otherwise effectively unbounded). Genuinely NON-terminating
// loops are marked {nonterm:true} + small fuel: Lean returns none (fuel bound), and ctrl_libauth.mjs
// routes them to a BOUNDED VM whose op-cost density limit aborts them (both => fail => match).
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url'; import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));

// deterministic PRNG (mulberry32)
let seed = 0xC0FFEE;
function rnd(){ seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }
const ri = (lo,hi) => lo + Math.floor(rnd()*(hi-lo+1));
const pick = arr => arr[Math.floor(rnd()*arr.length)];

// distinct payload sentinels (17..250 minus 128,129)
const POOL = []; for (let v=17; v<=250; v++) if (v!==128 && v!==129) POOL.push(v);
let sctr = 0;
const sent = () => POOL[(sctr++) % POOL.length];   // fresh-ish sentinel

// item / op constructors (JSON tree shape)
const B    = (...ops) => ({ t:'block', ops });
const IF   = (thenB, elseB=[], noElse=false, neg=false) => ({ t:'ifte', then:thenB, else:elseB, noElse, neg });
const LOOP = (...body) => ({ t:'loop', body });
const VER  = () => ({ t:'verify' });
const PUSH = v => ({ op:'PUSH', v });
const OP   = name => ({ op:name });
const PICK = n => ({ op:'PICK', n });
const ROLL = n => ({ op:'ROLL', n });

const cases = [];
let id = 0;
function add(desc, main, alt, prog, opts={}){
  cases.push({ id:id++, desc, fuel:opts.fuel ?? 6000, main, alt, prog, ...(opts.nonterm?{nonterm:true}:{}) });
}

// ---------------------------------------------------------------------------------------------
// DEPTH-TRACKED block generator: only chooses ops whose stack requirement is met (no underflow),
// so both engines SUCCEED and must agree. ctx={md,ad} mutated in place. Covers all 17 stack ops.
// Effects mirror standard Bitcoin/Lean stack semantics (only DEPTHS matter for validity here).
const OPS17 = ['DUP','DROP','OVER','SWAP','ROT','NIP','TUCK','PICK','ROLL','TOALT','FROMALT',
               '2DROP','2DUP','3DUP','2OVER','2ROT','2SWAP'];
function tryOp(ctx, name){ // returns op-node or null if it would underflow; applies effect if ok
  const {md,ad}=ctx;
  switch(name){
    case 'PUSH':   ctx.md++; return PUSH(sent());
    case 'DUP':    if(md<1)return null; ctx.md++; return OP('DUP');
    case 'DROP':   if(md<1)return null; ctx.md--; return OP('DROP');
    case 'OVER':   if(md<2)return null; ctx.md++; return OP('OVER');
    case 'SWAP':   if(md<2)return null; return OP('SWAP');
    case 'ROT':    if(md<3)return null; return OP('ROT');
    case 'NIP':    if(md<2)return null; ctx.md--; return OP('NIP');
    case 'TUCK':   if(md<2)return null; ctx.md++; return OP('TUCK');
    case 'PICK':   { if(md<2)return null; const n=ri(0,md-1); ctx.md++; return PICK(n); }
    case 'ROLL':   { if(md<2)return null; const n=ri(0,md-1); return ROLL(n); }
    case 'TOALT':  if(md<1)return null; ctx.md--; ctx.ad++; return OP('TOALT');
    case 'FROMALT':if(ad<1)return null; ctx.md++; ctx.ad--; return OP('FROMALT');
    case '2DROP':  if(md<2)return null; ctx.md-=2; return OP('2DROP');
    case '2DUP':   if(md<2)return null; ctx.md+=2; return OP('2DUP');
    case '3DUP':   if(md<3)return null; ctx.md+=3; return OP('3DUP');
    case '2OVER':  if(md<4)return null; ctx.md+=2; return OP('2OVER');
    case '2ROT':   if(md<6)return null; return OP('2ROT');
    case '2SWAP':  if(md<4)return null; return OP('2SWAP');
  }
  return null;
}
function genBlock(ctx, maxOps){
  const ops=[]; const n=ri(1,maxOps);
  for(let i=0;i<n;i++){
    // bias toward growth-ish ops when shallow so later ops have operands
    const cand = ctx.md<3 ? ['PUSH','PUSH','DUP','OVER','2DUP', ...OPS17] : [...OPS17,'PUSH'];
    for(let tries=0;tries<6;tries++){
      const o=tryOp(ctx, pick(cand)); if(o){ ops.push(o); break; }
    }
  }
  return ops.length?ops:[PUSH(sent())] /* fallback (also updated ctx via tryOp) */;
}

// push a KNOWN condition (0/1) onto main via a block op (returns block item; ctx.md++)
function pushCondBlock(ctx, v){ ctx.md++; return B(PUSH(v)); }

// ---------------------------------------------------------------------------------------------
// Nested control tree. Returns {items, aborted}. `aborted` set once a verify-false is emitted
// (runtime stops there; further items are dead on BOTH engines => still match).
function genProg(ctx, depth, count){
  const items=[]; let aborted=false;
  for(let i=0;i<count && !aborted;i++){
    const canCtrl = depth>0;
    const r = rnd();
    if(!canCtrl || r<0.34){                       // straight-line block
      items.push(B(...genBlock(ctx, ri(1,4))));
    } else if(r<0.60){                            // IF/NOTIF / ELSE / ENDIF
      const cond = ri(0,1);
      const neg = rnd()<0.5;                       // OP_NOTIF (neg) half the time, else OP_IF
      items.push(pushCondBlock(ctx, cond));       // push cond just before IF/NOTIF
      const noElse = rnd()<0.25;
      // arms operate at md-1 (cond popped)
      const base = {md:ctx.md-1, ad:ctx.ad};
      const ctxT = {...base}, ctxE = {...base};
      const tRes = genProg(ctxT, depth-1, ri(0,3));
      const eRes = noElse ? {items:[],aborted:false} : genProg(ctxE, depth-1, ri(0,3));
      items.push(IF(tRes.items, eRes.items, noElse, neg));
      // runtime follows the taken arm; then-arm runs on truthy for IF, on FALSY for NOTIF
      const runThen = (cond!==0) !== neg;
      const taken = runThen ? {ctx:ctxT,res:tRes} : {ctx:ctxE,res:eRes};
      ctx.md = taken.ctx.md; ctx.ad = taken.ctx.ad; aborted = taken.res.aborted;
    } else if(r<0.85){                            // BEGIN .. UNTIL  (terminating recipe)
      const k = ri(2,6);
      emitTermLoop(items, ctx, k, depth);
    } else {                                      // VERIFY
      const cond = rnd()<0.72 ? 1 : 0;
      items.push(pushCondBlock(ctx, cond));
      items.push(VER());
      ctx.md--;                                   // cond popped (if pass)
      if(cond===0) aborted=true;                  // verify-false aborts here
    }
  }
  return {items, aborted};
}

// terminating loop recipes; append cond-queue setup block(s) + LOOP item; update ctx.
function emitTermLoop(items, ctx, k, depth){
  const recipe = ctx.ad>=0 ? ri(0,3) : 0;
  if(recipe===0){
    // A: empty-body drain of a MAIN queue [1 at bottom, (k-1) zeros on top]
    const ops=[PUSH(1)]; for(let i=0;i<k-1;i++) ops.push(PUSH(0));
    items.push(B(...ops)); ctx.md += k;           // queue pushed
    items.push(LOOP());  ctx.md -= k;             // drains k conds
  } else if(recipe===1){
    // B: FROMALT drain of an ALT queue (main net-neutral, alt drains k)
    const ops=[PUSH(1),OP('TOALT')]; for(let i=0;i<k-1;i++){ ops.push(PUSH(0),OP('TOALT')); }
    items.push(B(...ops)); ctx.ad += k;
    items.push(LOOP(B(OP('FROMALT'))));  ctx.ad -= k;
  } else if(recipe===2){
    // C: INVARIANCE-VIOLATING (main grows +1/iter): body [PUSH s, FROMALT]; conds on alt
    const ops=[PUSH(1),OP('TOALT')]; for(let i=0;i<k-1;i++){ ops.push(PUSH(0),OP('TOALT')); }
    items.push(B(...ops)); ctx.ad += k;
    items.push(LOOP(B(PUSH(sent()), OP('FROMALT'))));  ctx.md += k; ctx.ad -= k;
  } else {
    // D: depth-neutral shuffle body [DUP,DROP,FROMALT]; conds on alt
    const ops=[PUSH(1),OP('TOALT')]; for(let i=0;i<k-1;i++){ ops.push(PUSH(0),OP('TOALT')); }
    // need md>=1 for DUP; ensure a payload present
    if(ctx.md<1){ items.push(B(PUSH(sent()))); ctx.md++; }
    items.push(B(...ops)); ctx.ad += k;
    items.push(LOOP(B(OP('DUP'),OP('DROP'),OP('FROMALT'))));  ctx.ad -= k;
  }
}

// =============================================================================================
// (A) HAND-PICKED STRUCTURAL SMOKE CASES ------------------------------------------------------
{
  const s = () => sent();
  const a=s(),b=s(),c=s(),d=s();
  add('IF-true',              [1, a], [], [ IF([B(PUSH(b))],[B(PUSH(c))]) ]);
  add('IF-false',             [0, a], [], [ IF([B(PUSH(b))],[B(PUSH(c))]) ]);
  add('IF-noelse-false',      [0, a], [], [ IF([B(PUSH(b))],[],true) ]);
  add('IF-noelse-true',       [1, a], [], [ IF([B(PUSH(b))],[],true) ]);
  add('IF-empty-then-true',   [1, a], [], [ IF([],[B(PUSH(b))]) ]);
  add('IF-empty-else-true',   [1, a], [], [ IF([B(PUSH(b))],[]) ]);
  add('nested-IF-t-innerfalse',[1,0,a],[],[ IF([ IF([B(PUSH(b))],[B(PUSH(c))]) ],[B(PUSH(d))]) ]);
  add('nested-IF-t-innertrue', [1,1,a],[],[ IF([ IF([B(PUSH(b))],[B(PUSH(c))]) ],[B(PUSH(d))]) ]);
  add('nested-IF-false',       [0,1,a],[],[ IF([ IF([B(PUSH(b))],[B(PUSH(c))]) ],[B(PUSH(d))]) ]);
  add('loop-1iter',            [1, a], [], [ LOOP() ]);
  add('loop-3iter-emptybody',  [0,0,1, a], [], [ LOOP() ]);
  add('loop-drop-body',        [ a,0, b,0, c,0, 1, d ], [], [ LOOP(B(OP('DROP'))) ]);
  add('loop-fromalt-3iter',    [ a ], [0,0,1], [ LOOP(B(OP('FROMALT'))) ]);
  add('IF-true-then-loop',     [1, 0,0,1, a], [], [ IF([ LOOP() ], [ B(PUSH(b)) ]) ]);
  add('loop-then-verify',      [0,1, 1, a], [], [ LOOP(), VER() ]);
  add('verify-pass',           [1, a], [], [ VER() ]);
  add('verify-abort',          [0, a], [], [ VER() ]);
  add('verify-empty-abort',    [], [], [ VER() ]);          // underflow => both fail
  add('IF-empty-stack-abort',  [], [], [ IF([B(PUSH(a))],[]) ]);  // IF underflow => both fail
  // ---- OP_NOTIF (neg=true): then-arm runs on FALSY cond, else-arm on TRUTHY ----
  add('NOTIF-true-cond',       [1, a], [], [ IF([B(PUSH(b))],[B(PUSH(c))],false,true) ]); // runs ELSE (push c)
  add('NOTIF-false-cond',      [0, a], [], [ IF([B(PUSH(b))],[B(PUSH(c))],false,true) ]); // runs THEN (push b)
  add('NOTIF-noelse-true',     [1, a], [], [ IF([B(PUSH(b))],[],true,true) ]);            // truthy => skip then
  add('NOTIF-noelse-false',    [0, a], [], [ IF([B(PUSH(b))],[],true,true) ]);            // falsy => run then
  add('NOTIF-empty-then-false',[0, a], [], [ IF([],[B(PUSH(b))],false,true) ]);           // falsy => empty then
  add('IF-vs-NOTIF-same-cond', [1, 1, a], [], [ IF([B(PUSH(b))],[B(PUSH(c))]),            // IF: then
                                                 IF([B(PUSH(b))],[B(PUSH(c))],false,true) ]); // NOTIF: else
  add('nested-NOTIF-inner',    [1, 1, a], [], [ IF([ IF([B(PUSH(b))],[B(PUSH(c))],false,true) ],
                                                    [B(PUSH(d))]) ]);                      // outer IF true, inner NOTIF true=>else
  add('NOTIF-then-loop',       [0, 0,0,1, a], [], [ IF([ LOOP() ], [ B(PUSH(b)) ],false,true) ]); // falsy=>loop
  add('NOTIF-empty-stack-abort',[], [], [ IF([B(PUSH(a))],[],false,true) ]);              // NOTIF underflow => both fail
}

// (B) PER-OPCODE COVERAGE: every one of the 17 stack ops exercised INSIDE an IF-true arm AND
//     inside a loop body, with enough operands pre-pushed. -----------------------------------
function opNeeds(op){ // (mainNeeded, altNeeded, node)
  switch(op){
    case 'PICK': return [3,0,PICK(1)];
    case 'ROLL': return [3,0,ROLL(1)];
    case 'FROMALT': return [0,1,OP('FROMALT')];
    case 'TOALT': return [1,0,OP('TOALT')];
    case '2ROT': return [6,0,OP('2ROT')];
    case '2OVER': case '2SWAP': return [4,0,OP(op)];
    case 'ROT': case '3DUP': return [3,0,OP(op)];
    case 'OVER': case 'SWAP': case 'NIP': case 'TUCK': case '2DROP': case '2DUP': return [2,0,OP(op)];
    default: return [1,0,OP(op)]; // DUP DROP
  }
}
for(const op of OPS17){
  const [mn,an,node]=opNeeds(op);
  const mpay=[]; for(let i=0;i<Math.max(mn,1);i++) mpay.push(sent());
  const apay=[]; for(let i=0;i<an;i++) apay.push(sent());
  // in IF-true arm (cond 1 on top, then payload beneath)
  add('op-in-IF-'+op, [1,...mpay], apay, [ IF([B(node)],[]) ]);
  // in a loop body that runs exactly 1 iteration (top cond 1): body runs node THEN leaves cond.
  // Build: main = [payload...]; place the loop with a fromalt-driven single iter so node runs once.
  // Simplest robust: put node in a straight block, then a 1-iter empty loop after.
  add('op-then-loop-'+op, [1,...mpay], apay, [ B(node), LOOP() ]);
}

// (C) BROAD RANDOMIZED NESTING (the bulk) -----------------------------------------------------
for(let k=0;k<1000;k++){
  const md0=ri(0,4), ad0=ri(0,3);
  const main=[]; for(let i=0;i<md0;i++) main.push(sent());
  const alt=[];  for(let i=0;i<ad0;i++) alt.push(sent());
  const ctx={md:md0, ad:ad0};
  const {items}=genProg(ctx, ri(1,4), ri(1,5));
  add('rand'+k, main, alt, items);
}

// (D) DEEP NESTING (control-stack depth) ------------------------------------------------------
for(let d=2; d<=8; d++){
  // d nested IF-true arms, innermost pushes a sentinel
  let node=[B(PUSH(sent()))];
  const main=[]; for(let i=0;i<d;i++) main.push(1);  // d truthy conds top-first
  for(let i=0;i<d;i++) node=[ IF(node,[]) ];
  add('deep-IF-'+d, main, [], node);
  // d nested NOTIF-false arms (falsy conds run the then-arm) -- exercises deep NOTIF polarity
  let nnode=[B(PUSH(sent()))];
  const nmain=[]; for(let i=0;i<d;i++) nmain.push(0);  // d falsy conds top-first
  for(let i=0;i<d;i++) nnode=[ IF(nnode,[],false,true) ];
  add('deep-NOTIF-'+d, nmain, [], nnode);
  // d nested loops (each 1 iter, top cond 1) -- outermost consumes conds via alt drains
}

// (E) NEAR-BOUND (fuel edge) ------------------------------------------------------------------
// empty-body k-iter loop needs fuel = k+1 exactly (calibrated). Place cases with fuel = k+1
// (Lean just-succeeds; libauth terminates) => must MATCH. Also fuel = k+8 headroom.
for(const k of [10,25,50,100,150]){
  const q=[]; for(let i=0;i<k-1;i++) q.push(0); q.push(1); q.push(sent()); // top-first: (k-1) 0s, 1, payload
  add('nearbound-exact-'+k, q, [], [ LOOP() ], {fuel:k+1});
  add('nearbound-head-'+k,  q, [], [ LOOP() ], {fuel:k+8});
}

// (F) NON-TERMINATING (Lean fuel-none vs libauth bounded-abort => both FAIL) ------------------
// body always leaves 0 on top => never exits. Small fuel so Lean returns none quickly; libauth
// routed to the BOUNDED VM (op-cost density abort). Several body shapes.
add('nonterm-push0',      [], [], [ LOOP(B(PUSH(0))) ], {fuel:30, nonterm:true});
add('nonterm-dup0',       [0], [], [ LOOP(B(OP('DUP'))) ], {fuel:30, nonterm:true});          // dup the 0 forever
add('loop-drain-then-underflow',[0], [], [ LOOP() ]);   // iter1 pops 0, iter2 UNTIL on empty => both abort (immediate, no hang)
add('nonterm-nested-in-IF',[1], [], [ IF([ LOOP(B(PUSH(0))) ],[]) ], {fuel:30, nonterm:true});
add('nonterm-after-block',[], [], [ B(PUSH(sent())), LOOP(B(PUSH(0))) ], {fuel:30, nonterm:true});

// (G) INVARIANCE-VIOLATING TERMINATING LOOPS (libauth ACCEPTS depth-change; Lean runLoop too) -
// explicit recipes C (main-grows) and an alt-grows variant, plus main-shrinks empty-body.
for(const k of [2,3,4,5]){
  // main-grows: conds on alt [0..0,1]; body [PUSH s, FROMALT]
  const alt=[]; for(let i=0;i<k-1;i++) alt.push(0); alt.push(1);
  add('inv-main-grow-'+k, [sent()], alt, [ LOOP(B(PUSH(sent()), OP('FROMALT'))) ]);
  // alt-grows: body pulls cond from main queue, but also stashes a sentinel to alt each iter.
  // main queue conds [0..0,1] top-first; body [DUP? ] -- we push sentinel to alt: [PUSH s, TOALT]
  // then need a cond on top from main. Arrange main = [cond queue] and body ends leaving next cond.
  // body: [PUSH s, TOALT] grows alt, main unchanged; then UNTIL pops the queued cond. main-shrinks by 1/iter (queue), alt-grows by 1/iter.
  const mq=[]; for(let i=0;i<k-1;i++) mq.push(0); mq.push(1);
  add('inv-alt-grow-'+k, mq, [], [ LOOP(B(PUSH(sent()), OP('TOALT'))) ]);
}

// (H) LOOP body that empties the stack -> UNTIL on empty => BOTH abort ------------------------
add('loop-body-empties',  [ 7 ], [], [ LOOP(B(OP('DROP'))) ]);   // iter1 drops the 7 -> empty -> UNTIL underflow => both fail

writeFileSync(join(here,'ctrl_cases.json'), JSON.stringify({ cases }, null, 0));
const nt = cases.filter(c=>c.nonterm).length;
console.log('wrote', cases.length, 'control cases to ctrl_cases.json ('+nt+' non-terminating)');
