import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect } from './program.mjs';

const CANON = '/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/expderiv-blob/optimized.hex';
const bytes = Uint8Array.from(Buffer.from(readFileSync(CANON, 'utf8').trim(), 'hex'));
console.log('canonical bytes:', bytes.length);
const d = dissect(bytes);
console.log('num defines:', d.order.length, 'ids:', d.order.join(','));
console.log('main ops len bytes:', serialize(d.mainOps).length);

// find free ids (not defined)
const defined = new Set(d.order);
const free = [];
for (let n = 1; n <= 60; n++) if (!defined.has(n)) free.push(n);
console.log('free ids (1..60):', free.slice(0,20).join(','));

// p modulus little-endian 32 bytes: from prototype token starts 47 fd 7c ...
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
// little-endian bytes
function toLE(x, n){ const o=new Uint8Array(n); for(let i=0;i<n;i++){o[i]=Number(x&0xffn);x>>=8n;} return o; }
const pLE = toLE(P, 32);
const pHex = Buffer.from(pLE).toString('hex');
console.log('p LE hex:', pHex);

// count occurrences of the 33-byte push token (0x20 + pLE) across all bodies + main
const TOK = Uint8Array.from([0x20, ...pLE]);
function countTok(buf){ let c=0; for(let i=0;i+33<=buf.length;i++){ if(Buffer.from(buf.slice(i,i+33)).equals(Buffer.from(TOK))) c++; } return c; }
let total=0;
for(const id of d.order){ const c=countTok(d.bodies.get(id)); if(c){ console.log('def#'+id, 'p-count', c, 'bodyLen', d.bodies.get(id).length); total+=c; } }
const mc = countTok(serialize(d.mainOps)); if(mc) console.log('main p-count', mc);
total += mc;
console.log('TOTAL p occurrences:', total, '=> baked bytes', total*33);

// duplicate bodies
const byHex = new Map();
for(const id of d.order){ const h=Buffer.from(d.bodies.get(id)).toString('hex'); if(!byHex.has(h)) byHex.set(h,[]); byHex.get(h).push(id); }
for(const [h,ids] of byHex){ if(ids.length>1) console.log('DUP bodies ids', ids.join(','), 'len', h.length/2); }
