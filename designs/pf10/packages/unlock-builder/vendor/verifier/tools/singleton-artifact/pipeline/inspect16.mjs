import { readFileSync } from 'node:fs';
import { parse } from './asm.mjs';
import { dissect, runSubroutine } from './program.mjs';
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function inv(a,m){let[or,r]=[((a%m)+m)%m,m];let[os,s]=[1n,0n];while(r){const q=or/r;[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];}return((os%m)+m)%m;}
const toLE=(x,n)=>{const o=Buffer.alloc(n);for(let i=0;i<n;i++){o[i]=Number(x&0xffn);x>>=8n;}return o;};
const i82=inv(82n,P); const b2c0=(27n*i82)%P, b2c1=((P-3n)*i82)%P;
const b2c0h=Buffer.from(toLE(b2c0,32)).toString('hex'), b2c1h=Buffer.from(toLE(b2c1,32)).toString('hex');
const bytes=Uint8Array.from(Buffer.from(readFileSync('./optimized-pooled-5892.hex','utf8').trim(),'hex'));
const d=dissect(bytes);
// def#5 semantics
const a=987654321098765n%P; const r5=runSubroutine(d,5,[a]);
console.log('def#5 on a:',r5.stack.map(String).join(','),'  (p-a)=',((P-a)%P).toString());
// print op stream of def#16 with coeff markers
function dump(ops,label){ console.log('=== '+label+' ==='); ops.forEach((o,i)=>{ let s; if(o.data){const h=Buffer.from(o.data).toString('hex'); s='PUSH'+o.data.length+' '+(h===b2c0h?'<B2C0>':h===b2c1h?'<B2C1>':(o.data.length<=4?h:h.slice(0,8)+'..'));} else s='OP_0x'+o.op.toString(16); console.log(i,s); }); }
dump(parse(d.bodies.get(16)),'def#16 body');
// main: find window around coeff pushes
const mo=d.mainOps;
mo.forEach((o,i)=>{ if(o.data){const h=Buffer.from(o.data).toString('hex'); if(h===b2c0h||h===b2c1h){ console.log('MAIN idx',i,h===b2c0h?'B2C0':'B2C1','neighbors:', mo.slice(Math.max(0,i-2),i+3).map(x=>x.data?('P'+x.data.length):('0x'+x.op.toString(16))).join(' ')); }}});
