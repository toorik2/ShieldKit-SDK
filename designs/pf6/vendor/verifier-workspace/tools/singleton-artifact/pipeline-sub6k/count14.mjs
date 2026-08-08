import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { serialize } from './asm.mjs';
import { decompile } from './decompile.mjs';
import { dissect } from './program.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(readFileSync(join(here, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(raw.debug?.bytecode || raw.bytecodeHex || raw.hex, 'hex'));
const d = dissect(baseline);
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
const blocks = mainItems.filter(it=>it.block).map(it=>it.block);
const b = blocks[14];
function topoNodes(roots){const order=[];const seen=new Set();const visit=(ref)=>{if(ref.k!=='out')return;const n=ref.node;if(seen.has(n.id))return;seen.add(n.id);for(const inp of n.ins)visit(inp);order.push(n);};for(const r of roots)visit(r);return order;}
const nodes=topoNodes([...b.exit,...b.exitAlt]);
const ids=nodes.map(n=>n.id);
const idset=new Set(ids);
const deps=new Map(nodes.map(n=>[n.id,[...new Set(n.ins.filter(r=>r.k==='out').map(r=>r.node.id))].filter(x=>idset.has(x))]));
console.log('nodes',ids.length);
for(const n of nodes) console.log(`  node ${n.id} inv#${n.invId} deps=[${deps.get(n.id)}] ins=${n.ins.length}`);
// count linear extensions
const idx=new Map(ids.map((id,i)=>[id,i]));
const predMask=ids.map(id=>{let m=0;for(const p of deps.get(id))m|=(1<<idx.get(p));return m;});
const memo=new Map();
function count(done){ if(done===(1<<ids.length)-1)return 1n; if(memo.has(done))return memo.get(done); let c=0n; for(let i=0;i<ids.length;i++){ if(done&(1<<i))continue; if((predMask[i]&done)===predMask[i]) c+=count(done|(1<<i)); } memo.set(done,c); return c; }
console.log('linear extensions =', count(0).toString());
