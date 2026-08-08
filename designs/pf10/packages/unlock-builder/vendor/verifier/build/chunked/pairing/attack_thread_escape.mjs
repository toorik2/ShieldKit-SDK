import { repoPath as vcRepoPath } from '#repo-paths';
// ADVERSARIAL: covenant-thread-escape.
// Uses the REAL production covenant primitives covIn/covOut from _millermath.mjs.
// Demonstrates that a chunk accepts a covenant tx whose output[0].lockingBytecode is
// an ARBITRARY successor script (not the chunk itself), that extra outputs are allowed,
// and characterizes what IS vs ISN'T enforced. Emits libauth JSON + a decodeProgram
// hex dump for LeanBCH cross-check.
import { writeFileSync } from 'node:fs';
import { covIn, covOut, commitBin, CATEGORY, TARGET_UNLOCK, compileBytecodeRaw, decl } from './_millermath.mjs';
import { createVirtualMachineBch2026, encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, binToHex } from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([0x4d, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };

// Minimal identity pass-through chunk built from the REAL covIn/covOut helpers.
const names = ['a', 'b'];
const src =
  'pragma cashscript ^0.14.0;\n' +
  'contract Thread(){\n' +
  `    function spend(${decl(names)}, bytes unused zeroPadding){\n` +
  covIn(names) + '\n' +
  covOut(names) + '\n' +
  '    }\n' +
  '}\n';
const raw = compileBytecodeRaw(src);
const locking = Uint8Array.from([...raw]);

// disassemble locking: confirm NO OP_OUTPUTBYTECODE(0xcd)/TXOUTPUTCOUNT(0xc4)/ACTIVEBYTECODE(0xc1)
function tally(buf){ let i=0,t={}; while(i<buf.length){ const op=buf[i];
  if(op>=0x01&&op<=0x4b)i+=1+op; else if(op===0x4c)i+=2+buf[i+1];
  else if(op===0x4d)i+=3+(buf[i+1]|(buf[i+2]<<8)); else if(op===0x4e)i+=5+(buf[i+1]|(buf[i+2]<<8)|(buf[i+3]<<16)|(buf[i+4]<<24));
  else { if(op>=0xc0&&op<=0xd3)t[op]=(t[op]||0)+1; i+=1; } } return t; }
const names20={0xc1:"ACTIVEBYTECODE",0xc4:"TXOUTPUTCOUNT",0xc7:"UTXOBYTECODE",0xca:"INPUTBYTECODE",0xcd:"OUTPUTBYTECODE",0xce:"UTXOTOKCAT",0xcf:"UTXOTOKCOMMIT",0xd1:"OUTPUTTOKCAT",0xd2:"OUTPUTTOKCOMMIT"};
const t = tally(locking);
console.log('UNIFIED chunk introspection ops:', Object.entries(t).map(([k,v])=>(names20[+k]||('0x'+(+k).toString(16)))+'x'+v).join(', '));
console.log('  self-pins next lockingBytecode (0xcd present):', !!t[0xcd]);
console.log('  bounds output count (0xc4 present):', !!t[0xc4]);
console.log('  lockingBytes:', locking.length);

// state: a,b in [0,P)
const a = 12345678901234567890n % P, b = 98765432109876543210n % P;
const stateInts = [a, b];
const outLimbs = [a % P, b % P];
const inCommit = commitBin(stateInts);
const outCommit = commitBin(outLimbs);

// unlocking identical to measureCovenantRaw
const argBytes = Uint8Array.from([...stateInts].reverse().flatMap((c) => [...pushInt(c)]));
const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });

function run(outputs, label) {
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs, locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  console.log(`[libauth] ${label}: accepted=${accepted} err=${st.error ?? 'none'}`);
  return accepted;
}

// BASELINE honest: output[0] = same locking (chunk perpetuates itself)
run([{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(outCommit) }], 'BASELINE honest (out.lock=self)');

// ESCAPE 1: output[0].lockingBytecode = OP_1 (0x51) -- token handed to a TRIVIAL/attacker script
const stealLock = Uint8Array.from([0x51]);
run([{ lockingBytecode: stealLock, valueSatoshis: 1000n, token: tok(outCommit) }], 'ESCAPE out.lock=OP_1 (trivial successor)');

// ESCAPE 2: output[0].lockingBytecode = a P2PKH-like 25-byte attacker address (arbitrary)
const p2pkh = Uint8Array.from([0x76,0xa9,0x14,...new Uint8Array(20).fill(0xab),0x88,0xac]);
run([{ lockingBytecode: p2pkh, valueSatoshis: 1000n, token: tok(outCommit) }], 'ESCAPE out.lock=P2PKH attacker (arbitrary successor)');

// ESCAPE 3: EXTRA outputs (split / add outputs) -- output count unchecked
run([
  { lockingBytecode: stealLock, valueSatoshis: 1000n, token: tok(outCommit) },
  { lockingBytecode: p2pkh, valueSatoshis: 1000n },
  { lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 0n },
], 'ESCAPE +extra outputs (out count unchecked)');

// CONTROL: wrong output[0] token category -> MUST reject (category continuity IS enforced)
const wrongCat = new Uint8Array(32).fill(0xee);
run([{ lockingBytecode: stealLock, valueSatoshis: 1000n, token: { amount:0n, category: wrongCat, nft:{capability:'mutable', commitment: outCommit} } }], 'CONTROL wrong category (should REJECT)');

// CONTROL: wrong output[0] nftCommitment -> MUST reject (state binding enforced)
run([{ lockingBytecode: stealLock, valueSatoshis: 1000n, token: tok(commitBin([a+1n, b])) }], 'CONTROL wrong commitment (should REJECT)');

// Export the ESCAPE (out.lock=OP_1) program for LeanBCH decodeProgram cross-check.
// decodeProgram format used by LeanBCH harnesses: we emit locking/unlocking hex + tx context.
const escapeCtx = {
  note: 'covenant-thread-escape: output[0].lockingBytecode=OP_1, chunk still accepts',
  lockingHex: binToHex(locking),
  unlockingHex: binToHex(unlocking),
  inCategoryHex: binToHex(CATEGORY),
  inCommitmentHex: binToHex(inCommit),
  outCommitmentHex: binToHex(outCommit),
  outLockingHex: binToHex(stealLock),
};
writeFileSync(vcRepoPath('build/chunked/pairing/generated/_escape_ctx.json'), JSON.stringify(escapeCtx, null, 2));
console.log('wrote generated/_escape_ctx.json');
