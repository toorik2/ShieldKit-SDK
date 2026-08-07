// Independent hand-check of each atomic identity via a PURE JS stack model (no VM),
// cross-validating the VM oracle. Stack = array bottom..top. Ops per BCH semantics.
function DUP(s){s.push(s[s.length-1]);} function DROP(s){s.pop();}
function OVER(s){s.push(s[s.length-2]);} function SWAP(s){const n=s.length;[s[n-1],s[n-2]]=[s[n-2],s[n-1]];}
function ROT(s){const n=s.length;const a=s[n-3];s[n-3]=s[n-2];s[n-2]=s[n-1];s[n-1]=a;}
function NIP(s){s.splice(s.length-2,1);} function TUCK(s){const n=s.length;const b=s[n-1];s.splice(n-2,0,b);}
function TWODUP(s){const n=s.length;s.push(s[n-2],s[n-1]);} function TWODROP(s){s.pop();s.pop();}
function TWOOVER(s){const n=s.length;s.push(s[n-4],s[n-3]);}
function TWOSWAP(s){const n=s.length;const a=s[n-4],b=s[n-3];s[n-4]=s[n-2];s[n-3]=s[n-1];s[n-2]=a;s[n-1]=b;}
function TWOROT(s){const n=s.length;const a=s[n-6],b=s[n-5];for(let k=n-6;k<n-2;k++)s[k]=s[k+2];s[n-2]=a;s[n-1]=b;}
function PICK(s,k){s.push(s[s.length-1-k]);} function ROLL(s,k){const i=s.length-1-k;const v=s.splice(i,1)[0];s.push(v);}
const OPS={DUP,DROP,OVER,SWAP,ROT,NIP,TUCK,'2DUP':TWODUP,'2DROP':TWODROP,'2OVER':TWOOVER,'2SWAP':TWOSWAP,'2ROT':TWOROT};
function run(seq,depth){let s=Array.from({length:depth},(_,i)=>'v'+i);for(const t of seq){const m=/^<(\d+)>(PICK|ROLL)$/.exec(t);if(m){(m[2]==='PICK'?PICK:ROLL)(s,+m[1]);}else OPS[t](s);}return s.join(',');}
function eq(a,b,label){let ok=true;for(let D=8;D<=12;D++){if(run(a,D)!==run(b,D)){ok=false;console.log(`  MISMATCH D=${D}: ${a}=[${run(a,D)}] vs ${b}=[${run(b,D)}]`);}}console.log(`  ${ok?'OK ':'*** BAD ***'}  ${a.join(' ')}  ==  ${b.join(' ')}   (${label})`);return ok;}
console.log('Independent pure-JS stack-model proof of each atomic fold identity:');
eq(['<5>ROLL','<5>ROLL'],['2ROT'],'rotate top6 by 2');
eq(['<3>ROLL','<3>ROLL'],['2SWAP'],'swap top pairs');
eq(['<3>PICK','<3>PICK'],['2OVER'],'copy pair 2-deep');
eq(['ROT','ROT','ROT'],[],'ROT^3 = id');
eq(['2ROT','2ROT','2ROT'],[],'2ROT^3 = id');
eq(['ROT','<3>ROLL'],['2SWAP','SWAP'],'');
eq(['<4>ROLL','<5>ROLL'],['2ROT','SWAP'],'');
eq(['DUP','<2>PICK'],['2DUP','SWAP'],'');
eq(['<2>PICK','<4>PICK'],['2OVER','SWAP'],'');
eq(['OVER','<2>PICK'],['OVER','DUP'],'');
eq(['ROT','DROP','ROT','DROP'],['2SWAP','2DROP'],'');
eq(['<3>ROLL','DROP','ROT'],['2SWAP','NIP'],'');
