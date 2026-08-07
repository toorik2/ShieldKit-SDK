import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const ID=30;
const items = decompile(d.bodies.get(ID), arity, arity[ID].in, { label:'def#'+ID });
const blkidx = Number(process.argv[2]||5);
let bi=0;
for (const it of items){ if(it.ctrl!==undefined)continue; if(bi===blkidx){
  const b=it.block;
  const ops = peephole(scheduleBlock(b, arity, {readyOrder:true,eagerDrop:true}).ops);
  // categorize
  const NAME={0x76:'DUP',0x75:'DROP',0x78:'OVER',0x7c:'SWAP',0x7b:'ROT',0x79:'PICK',0x7a:'ROLL',0x6b:'TOALT',0x6c:'FROMALT',0x77:'NIP',0x8a:'INVOKE'};
  let bytes=0, deep=0, deepcnt=0, pushbytes=0;
  const hist={};
  for(const o of ops){
    const s = o._raw? o._raw : (o.data!==undefined? serialize([o]) : [o.op]);
    bytes+=s.length;
    const nm = o._raw? 'const'+o._raw.length : (o.data!==undefined? 'push'+s.length : (NAME[o.op]||('op'+o.op.toString(16))));
    hist[nm]=(hist[nm]||0)+s.length;
  }
  console.log(`block#${blkidx} entryD=${b.entryDepth} exit=${b.exit.length} total=${bytes} ops=${ops.length}`);
  console.log(Object.entries(hist).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`${k}:${v}`).join('  '));
  // exit token structure
  console.log('exit toks:', b.exit.map(r=>r.k==='out'?('v'+r.node.id+'_'+r.j):r.k==='in'?('i'+r.i):r.k).join(' '));
}
  bi++;
}
