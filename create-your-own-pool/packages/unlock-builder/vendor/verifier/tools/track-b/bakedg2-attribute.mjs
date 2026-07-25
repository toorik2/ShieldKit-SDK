import { repoPath as vcRepoPath } from '#repo-paths';
// E-bakedg2-reloc ATTRIBUTION: per miller_baked chunk, measure
//   (a) baked-G2 line-coeff literal bytes in restBytes (the 6 Fp2 coords/baked line, <P, >=20B)
//   (b) op-cost + op-padding floor ceil(op/800)
//   (c) current witness mass = state args + relocated tower blob
//   (d) HEADROOM = op-pad-floor - current-witness  (>= coeffs ⇒ byte-positive on reloc)
import { readFileSync, readdirSync } from 'node:fs';
import { compileBytecode, splitTowerBytecode, chunkLockingBytes, towerWitnessFor,
  RELOCATE_TOWER, SINGLE_HASH_BIND } from '../../build/chunked/pairing/_millermath.mjs';
const GEN = vcRepoPath('build/chunked/pairing/generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const beToBig = (u8) => { let n = 0n; for (let i = u8.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u8[i]); return n; };
const pushLenAt = (b, i) => { const op = b[i]; if (op >= 1 && op <= 0x4b) return 1 + op; if (op === 0x4c) return 2 + b[i + 1]; if (op === 0x4d) return 3 + (b[i + 1] | (b[i + 2] << 8)); if (op === 0x4e) return 5 + (b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24)); if (op === 0 || op === 0x4f || (op >= 0x51 && op <= 0x60)) return 1; return -1; };
const pushDataAt = (b, i) => { const op = b[i]; if (op >= 1 && op <= 0x4b) return b.slice(i + 1, i + 1 + op); if (op === 0x4c) return b.slice(i + 2, i + 2 + b[i + 1]); if (op === 0x4d) { const L = b[i + 1] | (b[i + 2] << 8); return b.slice(i + 3, i + 3 + L); } if (op === 0) return Uint8Array.from([]); return b.slice(i, i + 1); };

// The manifest tells us how many BAKED line ops (and thus 6-coeff sets) each chunk has.
const man = JSON.parse(readFileSync(`${GEN}/manifest_miller_baked.json`, 'utf8'));
console.log(`RELOCATE_TOWER=${RELOCATE_TOWER} SINGLE_HASH_BIND=${SINGLE_HASH_BIND}`);
console.log(`numOps=${man.numOps} numChunks=${man.numChunks} numPairsLive=${man.numPairsLive}\n`);

const files = readdirSync(GEN).filter((f) => /^miller_baked_\d+\.cash$/.test(f)).sort();
let TOT = { coeffBytes:0, coeffPushes:0, lock:0, op:0, stateArgs:0, towerBlob:0, opPad:0, headroom:0, distinctCoeffsAll:new Set() };
const rows = [];
for (const f of files) {
  const src = readFileSync(`${GEN}/${f}`, 'utf8');
  const inline = compileBytecode(src);
  const { restBytes } = splitTowerBytecode(inline);
  // baked-G2 coeffs = field literals (>=20B, <P) in restBytes. In miller_baked these are
  // ONLY the line-coeff args + the mAB boundary const (last chunk, 12 limbs) + transcript
  // hashes (32B but >=P typically). We classify <P, len>=20 as "field literal"; the line
  // coeffs are the bulk. We separately count exact 6-coeff groupings via manifest baked-op count.
  let i = 0, fieldBytes = 0, fieldPushes = 0; const distinct = new Set();
  while (i < restBytes.length) {
    const l = pushLenAt(restBytes, i); if (l < 0) { i += 1; continue; }
    if (l >= 20) { const data = pushDataAt(restBytes, i); const v = beToBig(data);
      if (v < P) { fieldBytes += l; fieldPushes++; distinct.add(Buffer.from(data).toString('hex')); distinct.forEach(x=>TOT.distinctCoeffsAll.add(x)); } }
    i += l;
  }
  // measure op-cost + locking via the same path the verifier uses
  const locking = chunkLockingBytes(src);
  const blob = towerWitnessFor(src); // SINGLE_HASH_BIND blob (one pushData), reverse-order if per-fn
  // state args: 30 limbs (12 f + 6 R0 + 12 pt) ~ but last chunk differs. Read decl count from spend sig.
  const m = src.match(/function spend\(([^)]*)\)/s);
  const nArgs = m ? m[1].split(',').length : 0;
  rows.push({ f, fieldBytes, fieldPushes, distinct: distinct.size, nArgs, lockLen: locking.length, blobLen: blob.length,
    opLo: man.chunks.find(c=>`miller_baked_${String(c.idx).padStart(2,'0')}.cash`===f)?.opLo,
    opHi: man.chunks.find(c=>`miller_baked_${String(c.idx).padStart(2,'0')}.cash`===f)?.opHi });
  TOT.coeffBytes += fieldBytes; TOT.coeffPushes += fieldPushes; TOT.lock += locking.length; TOT.towerBlob += blob.length;
}
console.log('chunk            fieldB  #push #dist  nArg  lockLen blobLen  ops[lo,hi)');
for (const r of rows) console.log(`${r.f.padEnd(22)} ${String(r.fieldBytes).padStart(6)} ${String(r.fieldPushes).padStart(5)} ${String(r.distinct).padStart(5)} ${String(r.nArgs).padStart(4)} ${String(r.lockLen).padStart(7)} ${String(r.blobLen).padStart(7)}  [${r.opLo},${r.opHi})`);
console.log(`\nTOTALS: baked-field-literal bytes=${TOT.coeffBytes}  pushes=${TOT.coeffPushes}  distinct(all chunks)=${TOT.distinctCoeffsAll.size}  Σlock=${TOT.lock}  Σtower-blob=${TOT.towerBlob}`);
