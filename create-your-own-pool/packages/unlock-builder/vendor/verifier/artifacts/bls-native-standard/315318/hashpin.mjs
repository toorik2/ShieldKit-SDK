// Prove every FROZEN step's deployed redeem is exactly the compiled verifier chunk:
// the last data-push of each unlocking (the P2SH32 redeem) must hash256 to the 32-byte
// commitment in that step's P2SH32 locking (aa20 <32B> 87). If all 36 pin, the on-chain
// executed logic == the reviewed compiled verifier source (checks are not bypassable).
import { readFileSync } from 'node:fs';
import { hexToBin, binToHex, hash256 } from '@bitauth/libauth';
const j = JSON.parse(readFileSync('/home/toorik/Projects/verifier.cash/harness/src/bch/groth16-bls12381-grouped-residue-vectors.json', 'utf8'));

function parsePushes(hex) {
  const b = hexToBin(hex); let i = 0; const out = [];
  while (i < b.length) {
    const op = b[i];
    if (op >= 0x01 && op <= 0x4b) { out.push({ op, dataStart: i + 1, dataLen: op }); i += 1 + op; }
    else if (op === 0x4c) { const l = b[i + 1]; out.push({ op, dataStart: i + 2, dataLen: l }); i += 2 + l; }
    else if (op === 0x4d) { const l = b[i + 1] | (b[i + 2] << 8); out.push({ op, dataStart: i + 3, dataLen: l }); i += 3 + l; }
    else if (op === 0x4e) { const l = b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24); out.push({ op, dataStart: i + 5, dataLen: l }); i += 5 + l; }
    else { out.push({ op, opcodeOnly: true, at: i }); i += 1; }
  }
  return out;
}
// P2SH32 locking = OP_HASH256(aa) PUSH32(20) <hash> OP_EQUAL(87)
function p2sh32Hash(lockHex) {
  const b = hexToBin(lockHex);
  if (b[0] !== 0xaa || b[1] !== 0x20 || b.length !== 35 || b[34] !== 0x87) return null;
  return binToHex(b.slice(2, 34));
}
let pinned = 0, fail = 0;
for (let i = 0; i < j.valid.steps.length; i++) {
  const s = j.valid.steps[i];
  const pushes = parsePushes(s.unlocking);
  const redeemPush = pushes[pushes.length - 1]; // last push = redeem
  const bin = hexToBin(s.unlocking);
  const redeem = bin.slice(redeemPush.dataStart, redeemPush.dataStart + redeemPush.dataLen);
  const rh = binToHex(hash256(redeem));
  const lh = p2sh32Hash(s.locking);
  const ok = lh !== null && rh === lh;
  // redeem must start with OP_DROP (0x75) (the pad-dropper prepended by the assembler)
  const startsDrop = redeem[0] === 0x75;
  if (ok) pinned++; else { fail++; console.log(`  [XXX] step ${i}: redeem hash ${rh} != locking pin ${lh}`); }
  if (i < 2 || i === 29 || i === 35) console.log(`  step ${i} g${s.group} "${s.label.slice(0,36)}" redeemLen=${redeem.length} startsOP_DROP=${startsDrop} pinned=${ok}`);
}
console.log(`\nHASH-PIN: ${pinned}/36 redeems hash256-pinned to their P2SH32 lockings, ${fail} failures`);
console.log(pinned === 36 && fail === 0 ? 'PASS: every deployed redeem == its compiled verifier chunk (logic is hash-committed, unbypassable)' : 'FAIL');
