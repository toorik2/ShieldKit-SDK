// state-encoding-canonicity forgery harness.
// Tests whether a NON-CANONICAL threaded state can satisfy an INTERIOR covIn
// against a canonical producer commitment, exploiting covIn-raw vs covOut-%P.
import { commitBin, CATEGORY, TARGET_UNLOCK, le40, compileBytecodeRaw } from './_millermath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, binToHex, sha256 as _s } from '@bitauth/libauth';
import { createHash } from 'node:crypto';

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x)=>((BigInt(x)%P)+P)%P;
const pushInt = (n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush = (a,t)=>Uint8Array.from([0x4d,...numberToBinUint16LE(t-a-3),...new Uint8Array(t-a-3)]);
const sha256d = (b)=>createHash('sha256').update(createHash('sha256').update(b).digest()).digest();
// commitBin over EXPLICIT byte-vectors (so we can craft non-canonical encodings)
const commitBytes = (bufs)=> new Uint8Array(sha256d(Buffer.concat(bufs)));

// Minimal faithful covenant using the EXACT covIn/covOut encoding helpers.
// covIn hashes RAW a,b ; body does mod-p mul ; covOut hashes a%P,b%P,c%P.
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
const raw = compileBytecodeRaw(src);
const locking = Uint8Array.from([...raw]);
const tok = (cm)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:cm}});

function runCase(name, inCommit, pushLimbs, expectOut) {
  // pushLimbs: array of {bytes} OR bigint. If bigint, use pushInt(minimal). If {raw:Uint8Array}, push those bytes.
  const argParts = [...pushLimbs].reverse().map(l => l.raw ? encodeDataPush(l.raw) : pushInt(l));
  const argBytes = Uint8Array.from(argParts.flatMap(x=>[...x]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
  const prog = {
    inputIndex:0,
    sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
    transaction:{version:2,
      inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],
      outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(expectOut)}],locktime:0}};
  const st = realVm.evaluate(prog);
  const top = st.stack[st.stack.length-1];
  const accepted = st.error===undefined && st.stack.length===1 && top?.length===1 && top[0]===1;
  console.log(`[${name}] accepted=${accepted} op=${st.metrics.operationCost} err=${st.error??'-'}`);
  return {accepted, err:st.error, prog};
}

// pick a canonical (a0,b0)
const a0 = red(0x1234567890abcdefn * 999n + 7n);
const b0 = red(0xfedcba9876543210n * 31337n + 11n);
const c0 = (a0*b0)%P;
const honestOut = commitBin([a0,b0,c0]);
const honestIn = commitBin([a0,b0]);   // = hash256(NUM2BIN(a0,40)+NUM2BIN(b0,40))

console.log('a0=',a0.toString(16).slice(0,16),'... b0=',b0.toString(16).slice(0,16),'...');
console.log('=== SANITY: honest canonical accepts ===');
runCase('honest', honestIn, [a0,b0], honestOut);

console.log('=== TEST1: interior forgery — feed a0+p,b0+p vs canonical producer commit ===');
// producer honestly committed honestIn = H(NUM2BIN(a0)+NUM2BIN(b0)). Attacker pushes non-canonical a0+p,b0+p.
runCase('T1-noncanon-vs-canonCommit', honestIn, [a0+P, b0+P], honestOut);

console.log('=== TEST2: num2bin fit — feed a limb = 2^320 (41 bytes) ===');
runCase('T2a-2^320', honestIn, [1n<<320n, b0], honestOut);
console.log('=== TEST2b: feed 2^319 (magnitude needs sign bit in 40B) ===');
runCase('T2b-2^319', honestIn, [1n<<319n, b0], honestOut);
console.log('=== TEST2c: feed a0 + k*p that still fits (~2^300), crafted commit to match ===');
const big = a0 + ((1n<<300n)/P)*P; // a0 + k*p, k~2^46, fits 40B
const bigIn = commitBin([big, b0]);
runCase('T2c-akp-fits-craftedCommit', bigIn, [big, b0], commitBin([red(big), b0, (red(big)*b0)%P]));

console.log('=== TEST3: non-minimal number push (trailing 0x00) for a0 ===');
// craft raw bytes of a0 with an extra trailing zero byte (non-minimal VM number)
const a0min = bigIntToVmNumber(a0);
const a0nonmin = Uint8Array.from([...a0min, 0x00]);
runCase('T3-nonminimal-a0', honestIn, [{raw:a0nonmin}, b0], honestOut);

console.log('=== TEST4: crafted-anchor flatten — commit to NON-canonical a0+p, feed a0+p ===');
// A commitment no honest interior producer emits (would require adversary-controlled anchor).
const craftedIn = commitBytes([le40(a0+P), le40(b0+P)]); // H over raw non-canonical LE bytes
const flatOut = commitBin([red(a0+P), red(b0+P), (red(a0+P)*red(b0+P))%P]); // = honest canonical out
const r4 = runCase('T4-crafted-anchor', craftedIn, [a0+P, b0+P], flatOut);
console.log('   flatOut == honestOut ?', binToHex(flatOut)===binToHex(honestOut));

// export the KEY cases for LeanBCH (T1 reject, T4 accept)
export { locking, tok, honestIn, a0, b0, P, red, craftedIn, flatOut };
