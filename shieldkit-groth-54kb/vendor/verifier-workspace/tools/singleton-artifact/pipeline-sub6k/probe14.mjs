import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize, parse } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
import { scheduleBlock, serializeOps } from './scheduler.mjs';
import { peephole } from './peephole.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
const blocks = mainItems.filter(it=>it.block).map(it=>it.block);
const N = Number(process.argv[2] ?? 14);
const b = blocks[N];
console.log(`blk#${N} entryD=${b.entryDepth} entryAlt=${b.entryAlt} exit=${b.exit.length} exitAlt=${b.exitAlt.length} rawOps=${b.rawOps.length}`);
// count node types via topo
function topoNodes(roots){const order=[];const seen=new Set();const visit=(ref)=>{if(ref.k!=='out')return;const n=ref.node;if(seen.has(n.id))return;seen.add(n.id);for(const inp of n.ins)visit(inp);order.push(n);};for(const r of roots)visit(r);return order;}
const nodes = topoNodes([...b.exit, ...b.exitAlt]);
let prim=0, inv=0; const invById={};
for(const n of nodes){ if(n.k==='prim')prim++; else {inv++; invById[n.invId]=(invById[n.invId]||0)+1;} }
console.log(`nodes=${nodes.length} prim=${prim} invoke=${inv} invokeByType=${JSON.stringify(invById)}`);
// raw op histogram
const rops = parse(b.rawOps.length?serialize(b.rawOps):new Uint8Array());
const rawops = b.rawOps;
let consts=0, constBytes=0; const constHex={};
for(const o of rawops){ if(o.data!==undefined){consts++; const s=serialize([o]); constBytes+=s.length; const h=Buffer.from(o.data).toString('hex'); constHex[h]=(constHex[h]||0)+1;} }
console.log(`raw const pushes=${consts} constBytes=${constBytes} uniqueConsts=${Object.keys(constHex).length}`);
// dup consts
const dups = Object.entries(constHex).filter(([k,v])=>v>1);
console.log(`duplicated consts: ${dups.map(([k,v])=>k.slice(0,8)+'x'+v).join(' ')}`);
// op histogram of raw
const hist={};
for(const o of rawops){ let name; if(o.data!==undefined)name='PUSH'+o.data.length; else name='op'+o.op.toString(16); hist[name]=(hist[name]||0)+1; }
console.log('rawop hist:', JSON.stringify(hist));
// scheduler per-config bytes
const CONFIGS=[{readyOrder:true,eagerDrop:true},{readyOrder:false,eagerDrop:false},{readyOrder:true,eagerDrop:false},{readyOrder:false,eagerDrop:true},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax'},{readyOrder:true,eagerDrop:false,tieBreak:'shallowmax'},{readyOrder:true,eagerDrop:true,tieBreak:'netpop'},{readyOrder:true,eagerDrop:false,tieBreak:'netpop'},{readyOrder:true,eagerDrop:true,tieBreak:'deepfirst'},{readyOrder:true,eagerDrop:false,tieBreak:'deepfirst'},{readyOrder:true,eagerDrop:true,arrange:'move'},{readyOrder:true,eagerDrop:false,arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'shallowmax',arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'netpop',arrange:'move'},{readyOrder:true,eagerDrop:true,tieBreak:'deepfirst',arrange:'move'},{readyOrder:false,eagerDrop:false,arrange:'move'}];
for(let ci=0;ci<CONFIGS.length;ci++){ try{const by=serializeOps(peephole(scheduleBlock(b,arity,CONFIGS[ci]).ops)).length; console.log(`  cfg${ci} ${JSON.stringify(CONFIGS[ci])} => ${by}`);}catch(e){console.log(`  cfg${ci} ERR ${e.message}`);} }
console.log('orig=',serialize(peephole(b.rawOps)).length);
