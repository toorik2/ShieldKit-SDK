// P2SH32 canonicity forgery cases exported for BOTH libauth + LeanBCH.
import { writeFileSync } from 'node:fs';
import { commitBin, CATEGORY, TARGET_UNLOCK, le40, compileBytecodeRaw } from './_millermath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE,
  binToHex, hash256, encodeLockingBytecodeP2sh32, encodeTransaction, encodeTransactionOutputs } from '@bitauth/libauth';
import { createHash } from 'node:crypto';

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x)=>((BigInt(x)%P)+P)%P;
const pushInt = (n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const sha256d = (b)=>createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
const commitBytes = (bufs)=> new Uint8Array(sha256d(Buffer.concat(bufs)));
const Pstr = P.toString();

const src = `pragma cashscript ^0.14.0;
contract Canon() {
  function spend(int a, int b, bytes unused zeroPadding) {
    require(tx.inputs[this.activeInputIndex].nftCommitment == hash256(toPaddedBytes(a, 40) + toPaddedBytes(b, 40)));
    int Pmod = ${Pstr};
    int c = (a * b) % Pmod;
    require(tx.outputs[0].nftCommitment == hash256(toPaddedBytes(a % Pmod, 40) + toPaddedBytes(b % Pmod, 40) + toPaddedBytes(c % Pmod, 40)));
    require(tx.outputs[0].tokenCategory == tx.inputs[this.activeInputIndex].tokenCategory);
  }
}`;
const redeem = Uint8Array.from([...compileBytecodeRaw(src)]);
const rpush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem)); // P2SH32
const tok = (cm)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:cm}});
const padBytes = (total)=>{const b=Math.max(2,total);const n=b<=76?b-1:b<=257?b-2:b-3;return encodeDataPush(new Uint8Array(n));};

function buildProg(inCommit, pushLimbs, outCommit){
  const argParts=[...pushLimbs].reverse().map(l=> l.raw?encodeDataPush(l.raw):pushInt(l));
  const argb=Uint8Array.from(argParts.flatMap(x=>[...x]));
  const tail=rpush.length;
  const mkUnlock=(target)=>Uint8Array.from([...padBytes(target-argb.length-tail),...argb,...rpush]);
  const unlocking=mkUnlock(TARGET_UNLOCK);
  return {inputIndex:0,
    sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
    transaction:{version:2,
      inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],
      outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(outCommit)}],locktime:0}};
}
function runLibauth(prog){
  const st=realVm.evaluate(prog);
  const top=st.stack[st.stack.length-1];
  const accepted=st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1;
  return {accepted, op:st.metrics.operationCost, err:st.error??null};
}

const a0=red(0x1234567890abcdefn*999n+7n), b0=red(0xfedcba9876543210n*31337n+11n), c0=(a0*b0)%P;
const honestIn=commitBin([a0,b0]), honestOut=commitBin([a0,b0,c0]);

const CASES=[
  ['honest',        honestIn, [a0,b0], honestOut],
  ['T1_interior',   honestIn, [a0+P,b0+P], honestOut],           // expect REJECT
  ['T2a_2e320',     honestIn, [1n<<320n,b0], honestOut],          // expect REJECT (num2bin)
  ['T3_nonminimal', honestIn, [{raw:Uint8Array.from([...bigIntToVmNumber(a0),0x00])}, b0], honestOut], // REJECT
  ['T4_crafted',    commitBytes([le40(a0+P),le40(b0+P)]), [a0+P,b0+P],
                    commitBin([red(a0+P),red(b0+P),(red(a0+P)*red(b0+P))%P])], // expect ACCEPT, flattens
];

const which = process.env.CASE;
for(const [name,inC,limbs,outC] of CASES){
  if(which && name!==which) continue;
  const prog=buildProg(inC,limbs,outC);
  const r=runLibauth(prog);
  const txHex=binToHex(encodeTransaction(prog.transaction));
  const soHex=binToHex(encodeTransactionOutputs(prog.sourceOutputs));
  if(which){ writeFileSync('/tmp/xcheck_tx.hex',txHex); writeFileSync('/tmp/xcheck_srcouts.hex',soHex); }
  console.log(`[${name}] libauth accepted=${r.accepted} op=${r.op} err=${r.err}`);
}
