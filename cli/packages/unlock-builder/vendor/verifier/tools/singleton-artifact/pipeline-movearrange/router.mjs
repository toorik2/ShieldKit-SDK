// Standalone stack-router: given source homes S (array of tokens, bottom->top; some may
// be dead) and target exit (array of {tok} or {const:len}), compute exact emitted BYTES
// for several arrange strategies. Simulate a real stack so results are trustworthy.
// byte model: opcode=1; depth push: 0->1,1..16->1,else data push (1 len + ceil so <=127 =>1) => 2 for 17..127.
function depthBytes(d){ if(d===0||(d>=1&&d<=16)) return 1; return 2; } // for the OP_n depth arg
// but SWAP/ROT/OVER/DUP fold: handled per-strategy.

function pushCost(d){ // cost of a PICK at depth d (with fold): DUP(0)->1, OVER(1)->1, else depthpush+PICK
  if(d===0) return 1; if(d===1) return 1; return depthBytes(d)+1;
}
function rollCost(d){ if(d===0) return 0; if(d===1) return 1; if(d===2) return 1; return depthBytes(d)+1; }

// Strategy: ROLL-move build. Prefix L kept. Drop dead items (not in exit) via ROLL+DROP.
// Then for p=L..N-1 bring exit[p] home to top by ROLL (last-use move). Consts pushed.
export function strat_rollmove(S, exit, encLen){
  // work on a mutable stack of tokens (null for const-produced placeholder). Track homes.
  let st = S.map(x=>x); // tokens, dead ones included; consts in exit are 'K'
  // common prefix
  let L=0; while(L<exit.length && L<st.length && exit[L].tok!==null && exit[L].tok!==undefined && st[L]===exit[L].tok) L++;
  let bytes=0;
  // demand: which tokens are needed (permutation: each once). Build set with multiplicity.
  const need = new Map(); for(const e of exit){ if(e.tok!=null) need.set(e.tok,(need.get(e.tok)||0)+1); }
  // drop dead items above prefix (tokens not needed). Do from shallow: repeatedly find topmost dead, roll to top(if not) drop.
  // simpler: iterate indices above L, if token not needed at all, remove via roll+drop.
  // We'll just filter: for each dead, roll to top and drop.
  const isDead=(tok)=> tok!=null && !need.has(tok);
  // remove deads
  let guard=0;
  while(true){ const idx=st.findIndex((t,i)=>i>=L && isDead(t)); if(idx<0)break; const d=st.length-1-idx; bytes+=rollCost(d); if(d>0){/*roll*/} st.splice(idx,1); st.push('__x'); bytes+=1; st.pop(); if(++guard>1000)break; }
  // now build exit[L..] on top by moving homes (each needed once => move) or pushing consts
  // We keep placed items on top; unplaced homes below. To place exit[p], its home is somewhere in st[L..k] where k excludes already-placed (which sit at top). Actually after moving to top, placed accumulate on top in order.
  // Simulate: maintain st. placedCount on top.
  let placed=0;
  for(let p=L;p<exit.length;p++){
    const e=exit[p];
    if(e.tok==null){ bytes += encLen(e); st.push('K'); placed++; continue; }
    // find home: topmost occurrence NOT in the placed region (placed are top `placed`)
    const limit = st.length-placed; // homes live in [0,limit)
    let idx=-1; for(let i=limit-1;i>=0;i--){ if(st[i]===e.tok){idx=i;break;} }
    if(idx<0){ return {bytes:Infinity, note:'home missing '+e.tok}; }
    const d=st.length-1-idx; bytes+=rollCost(d); const v=st.splice(idx,1)[0]; st.push(v); placed++;
  }
  return {bytes, L, finalLen:st.length};
}

// Strategy: current-like PICK build + delete (to sanity-check vs 255)
export function strat_pickdel(S, exit, encLen){
  let st=S.map(x=>x);
  let L=0; while(L<exit.length && L<st.length && exit[L].tok!=null && st[L]===exit[L].tok) L++;
  let bytes=0; const origLen=st.length;
  for(let p=L;p<exit.length;p++){ const e=exit[p]; if(e.tok==null){bytes+=encLen(e); st.push('K'); continue;} 
    // depth of shallowest home among originals (not the built top)
    let idx=-1; for(let i=Math.min(origLen,st.length)-1;i>=0;i--){ if(i<origLen && st[i]===e.tok){idx=i;break;} }
    // actually pick from any home; use topmost original
    if(idx<0){for(let i=st.length-1;i>=0;i--){if(st[i]===e.tok){idx=i;break;}}}
    const d=st.length-1-idx; bytes+=pushCost(d); st.push(e.tok);
  }
  const q=exit.length-L, m=origLen-L;
  for(let k=0;k<m;k++){ if(q===0)bytes+=1; else if(q===1)bytes+=1; else bytes+=depthBytes(q)+1+1; }
  return {bytes,L};
}

// Strategy: altstack group-reverse for the specific pattern isn't general; instead a
// generic "drain movable to alt, then rebuild by FROMALT/reorder". Provide: drain all
// above L to alt (cost = count), then pop each needed in exit order — but alt is LIFO.
// Generic optimal alt routing is hard; we test a heuristic: park the LARGEST already-
// ordered top run to alt to expose deep items. Skip for now; measured separately.
