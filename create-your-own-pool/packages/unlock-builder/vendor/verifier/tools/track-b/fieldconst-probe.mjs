import { repoPath as vcRepoPath } from '#repo-paths';
// Probe the "baked field consts" mass in restBytes: how many DISTINCT 32-byte-ish
// field literals, how often repeated (dedup potential), and which stage.
import { readFileSync, readdirSync } from 'node:fs';
import { compileBytecode, splitTowerBytecode } from '../../build/chunked/pairing/_millermath.mjs';
const GEN = vcRepoPath('build/chunked/pairing/generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const beToBig = (u8) => { let n = 0n; for (let i = u8.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u8[i]); return n; };
const pushLenAt = (b, i) => { const op = b[i]; if (op >= 1 && op <= 0x4b) return 1 + op; if (op === 0x4c) return 2 + b[i + 1]; if (op === 0x4d) return 3 + (b[i + 1] | (b[i + 2] << 8)); if (op === 0x4e) return 5 + (b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24)); if (op === 0 || op === 0x4f || (op >= 0x51 && op <= 0x60)) return 1; return -1; };
const pushDataAt = (b, i) => { const op = b[i]; if (op >= 1 && op <= 0x4b) return b.slice(i + 1, i + 1 + op); if (op === 0x4c) return b.slice(i + 2, i + 2 + b[i + 1]); if (op === 0x4d) { const L = b[i + 1] | (b[i + 2] << 8); return b.slice(i + 3, i + 3 + L); } if (op === 0) return Uint8Array.from([]); return b.slice(i, i + 1); };

for (const stage of ['miller_baked', 'g2check', 'finalexp', 'vkx']) {
  const files = readdirSync(GEN).filter((f) => f.startsWith(stage + '_') && f.endsWith('.cash')).sort();
  const freq = new Map(); // hex -> {count, len, isModulus, isField}
  let totalFieldBytes = 0, totalFieldPushes = 0;
  for (const f of files) {
    const inline = compileBytecode(readFileSync(`${GEN}/${f}`, 'utf8'));
    const { restBytes } = splitTowerBytecode(inline);
    let i = 0;
    while (i < restBytes.length) {
      const l = pushLenAt(restBytes, i); if (l < 0) { i += 1; continue; }
      const data = pushDataAt(restBytes, i);
      if (data.length >= 20) {
        const asInt = beToBig(data);
        if (asInt < P) {
          const hex = Buffer.from(data).toString('hex');
          const e = freq.get(hex) ?? { count: 0, len: l, isMod: asInt === P };
          e.count++; freq.set(hex, e); totalFieldBytes += l; totalFieldPushes++;
        }
      }
      i += l;
    }
  }
  const distinct = freq.size;
  const modEntry = [...freq.entries()].find(([, e]) => e.isMod);
  const modCount = modEntry ? modEntry[1].count : 0;
  // bytes if each distinct literal appeared once (dedup floor, ignoring mechanism)
  let dedupBytes = 0; for (const [, e] of freq) dedupBytes += e.len;
  console.log(`\n[${stage}] ${files.length} chunks`);
  console.log(`  field-const pushes: ${totalFieldPushes}  bytes: ${totalFieldBytes}`);
  console.log(`  DISTINCT literals : ${distinct}   (modulus P appears ${modCount}× across chunks)`);
  console.log(`  bytes if 1×each   : ${dedupBytes}  => cross-chunk repeats waste ${totalFieldBytes - dedupBytes} B (NOT dedup-able: separate locking scripts)`);
  // within-chunk repeats (the only same-script dedup):
  // recompute per-chunk distinct
  let perChunkRepeatWaste = 0, perChunkPushes = 0;
  for (const f of files) {
    const inline = compileBytecode(readFileSync(`${GEN}/${f}`, 'utf8'));
    const { restBytes } = splitTowerBytecode(inline);
    const seen = new Map(); let i = 0;
    while (i < restBytes.length) {
      const l = pushLenAt(restBytes, i); if (l < 0) { i += 1; continue; }
      const data = pushDataAt(restBytes, i);
      if (data.length >= 20 && beToBig(data) < P) {
        const hex = Buffer.from(data).toString('hex');
        if (seen.has(hex)) perChunkRepeatWaste += l; else seen.set(hex, 1);
        perChunkPushes++;
      }
      i += l;
    }
  }
  console.log(`  WITHIN-CHUNK repeat waste (same literal pushed 2+× in one script): ${perChunkRepeatWaste} B  <- the only sound non-witness dedup`);
}
