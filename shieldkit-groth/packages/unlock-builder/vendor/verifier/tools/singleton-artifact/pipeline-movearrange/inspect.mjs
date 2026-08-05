import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { dissect, probeArity, decompileProgram } from './program.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here,'baseline.json'),'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode||raw.bytecodeHex||raw.hex,'hex'));
const d = dissect(baseline);
const arity = probeArity(d);
const ir = decompileProgram(d, arity, 10);
let maxEntryAlt=0, maxExitAlt=0, nonzeroAltBoundaries=0, totBlocks=0;
let altWithinBlockUsed=0;
const NM={0x6b:'TOALT',0x6c:'FROMALT'};
function scan(items,label){
  for(const it of items){
    if(!it.block) continue;
    totBlocks++;
    const b=it.block;
    if(b.entryAlt>maxEntryAlt)maxEntryAlt=b.entryAlt;
    if(b.exitAlt.length>maxExitAlt)maxExitAlt=b.exitAlt.length;
    if(b.entryAlt!==0||b.exitAlt.length!==0){ nonzeroAltBoundaries++; }
    // does this block internally use alt?
    for(const o of b.rawOps){ if(o.op===0x6b||o.op===0x6c){altWithinBlockUsed++;break;} }
  }
}
for(const id of d.order) scan(ir.bodies.get(id),'def#'+id);
scan(ir.mainItems,'main');
console.log('total blocks',totBlocks);
console.log('maxEntryAlt',maxEntryAlt,'maxExitAlt',maxExitAlt);
console.log('blocks with nonzero alt at boundary',nonzeroAltBoundaries);
console.log('blocks using alt internally',altWithinBlockUsed);
// per-body: does any body have exitAlt!=0 at any boundary?
for(const id of d.order){
  const items=ir.bodies.get(id);
  let bad=0;
  for(const it of items) if(it.block && (it.block.entryAlt!==0||it.block.exitAlt.length!==0)) bad++;
  if(bad) console.log('  def#'+id,'has',bad,'nonzero-alt boundaries');
}
{ let bad=0; for(const it of ir.mainItems) if(it.block&&(it.block.entryAlt!==0||it.block.exitAlt.length!==0)) bad++; if(bad) console.log('  main has',bad,'nonzero-alt boundaries'); }
