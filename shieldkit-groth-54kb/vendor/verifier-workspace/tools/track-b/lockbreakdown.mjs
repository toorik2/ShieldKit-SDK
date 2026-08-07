import { repoPath as vcRepoPath } from '#repo-paths';
// ============================================================================
// E-locking-dedup #1 — LOCKING BYTE BREAKDOWN of the SOUND E3 48-chunk verifier.
// Compiles every chunk (compileBytecode), splits the relocated form into:
//   per-fn tower hash-binds (consts + opcodes) | forward-chain hashes
//   | category literals | baked-G2 line coeffs | dispatch/covenant pins | dead
// Quantifies each. NO re-bake of generated/ (read-only over the .cash sources).
// run: node tools/track-b/lockbreakdown.mjs
// ============================================================================
import { readFileSync, readdirSync } from 'node:fs';
import {
  compileBytecode, splitTowerBytecode, buildRelocatedRedeem, chunkLockingBytes,
  RELOCATE_TOWER, CATEGORY_HEX,
} from '../../build/chunked/pairing/_millermath.mjs';

const GEN = vcRepoPath('build/chunked/pairing/generated');
const STAGES = ['g2check', 'vkx', 'miller_baked', 'finalexp'];
const chunkFiles = (stage) =>
  readdirSync(GEN).filter((f) => f.startsWith(stage + '_') && f.endsWith('.cash'))
    .sort().map((f) => `${GEN}/${f}`);

// ---- bytecode push-walk (mirror of _millermath internals, local copy) ----
const pushLenAt = (b, i) => {
  const op = b[i];
  if (op >= 0x01 && op <= 0x4b) return 1 + op;
  if (op === 0x4c) return 2 + b[i + 1];
  if (op === 0x4d) return 3 + (b[i + 1] | (b[i + 2] << 8));
  if (op === 0x4e) return 5 + (b[i + 1] | (b[i + 2] << 8) | (b[i + 3] << 16) | (b[i + 4] << 24));
  if (op === 0x00 || op === 0x4f || (op >= 0x51 && op <= 0x60)) return 1;
  return -1;
};
const pushDataAt = (b, i) => {
  const op = b[i];
  if (op >= 0x01 && op <= 0x4b) return b.slice(i + 1, i + 1 + op);
  if (op === 0x4c) return b.slice(i + 2, i + 2 + b[i + 1]);
  if (op === 0x4d) { const L = b[i + 1] | (b[i + 2] << 8); return b.slice(i + 3, i + 3 + L); }
  if (op === 0x00) return Uint8Array.from([]);
  return b.slice(i, i + 1);
};

// 32-byte BN254 field prime (big-endian) — used to recognise modulus / VK-coeff
// pushes inside the restBytes. cashc pushes integers little-endian minimal.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const beToBig = (u8) => { let n = 0n; for (let i = u8.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u8[i]); return n; }; // little-endian decode
// known small VK/tower scalars that appear as 32B-ish pushes
const KNOWN = new Set([P.toString()]);

// Classify a single push's DATA inside restBytes (the spend body) by heuristics:
//  - 32-byte push that is NOT a field-scalar  => forward-chain hash / T0 / T1 / lock-hash
//  - 32-byte push equal to CATEGORY           => category literal
//  - big-int (>= 20 bytes) reducible mod P     => baked field constant (VK coeff / line coeff / modulus)
function classifyPush(data) {
  const n = data.length;
  if (n === 32) {
    const hex = Buffer.from(data).toString('hex');
    if (hex === CATEGORY_HEX) return 'category';
    // a 32B push that decodes (LE) to < P could be a field elem; but forward-chain
    // hashes are raw 32B (uniform random) -> ~certainly >= P or non-canonical-as-int.
    const asInt = beToBig(data);
    if (asInt < P && n >= 30 && (data[31] & 0x80) === 0) return 'fieldconst32'; // borderline; treat as const
    return 'hash32';
  }
  if (n >= 20) {
    const asInt = beToBig(data);
    if (asInt < P) return 'fieldconst'; // baked VK / line coeff / modulus literal
    return 'bigpush';
  }
  return 'small';
}

let G = {}; // grand totals
const ensure = (k) => (G[k] ??= 0);

console.log('chunk\t#fn\tinlineLk\trelocLk\tlkDelta\tbindBytes\tconstBytes\trestBytes\thash32\tfieldConst\tcatLit\tsmallGlue');
const rows = [];
for (const stage of STAGES) {
  let sInline = 0, sReloc = 0, sBind = 0, sConst = 0, sRest = 0, sHash = 0, sField = 0, sCat = 0, sGlue = 0, sFns = 0, sHash32cnt = 0;
  for (const f of chunkFiles(stage)) {
    const src = readFileSync(f, 'utf8');
    const inline = compileBytecode(src);
    const { blocks, restBytes } = splitTowerBytecode(inline);
    const { redeem: reloc, consts } = buildRelocatedRedeem(inline);
    // inline locking = OP_DROP + inline redeem ; reloc locking = OP_DROP + reloc redeem
    const inlineLk = 1 + inline.length;
    const relocLk = 1 + reloc.length;
    // bind stub bytes (per fn): DUP HASH256 <push32const> EQUALVERIFY idPush DEFINE
    //   = 1 + 1 + (1+32) + 1 + idLen + 1
    let bindBytes = 0, constBytes = 0;
    for (const b of blocks) { bindBytes += 1 + 1 + (1 + 32) + 1 + b.idPush.length + 1; constBytes += 33; }
    // walk restBytes -> classify pushes (this is the SPEND BODY = forward-chain + category + baked consts + dispatch + dead)
    let hash32 = 0, fieldConst = 0, catLit = 0, glue = 0, hash32cnt = 0;
    let i = 0;
    while (i < restBytes.length) {
      const l = pushLenAt(restBytes, i);
      if (l < 0) { glue += 1; i += 1; continue; } // real opcode (dispatch / covenant arithmetic / OP_INVOKE)
      const data = pushDataAt(restBytes, i);
      const cls = classifyPush(data);
      if (cls === 'hash32') { hash32 += l; hash32cnt++; }
      else if (cls === 'category') catLit += l;
      else if (cls === 'fieldconst' || cls === 'fieldconst32') fieldConst += l;
      else glue += l; // small int / bigpush -> dispatch immediates / op glue
      i += l;
    }
    sInline += inlineLk; sReloc += relocLk; sBind += bindBytes; sConst += constBytes;
    sRest += restBytes.length; sHash += hash32; sField += fieldConst; sCat += catLit;
    sGlue += glue; sFns += blocks.length; sHash32cnt += hash32cnt;
    rows.push({ name: f.split('/').pop().replace('.cash', ''), nFn: blocks.length, inlineLk, relocLk });
  }
  console.log(`${stage}\t${sFns}\t${sInline}\t${sReloc}\t${sReloc - sInline}\t${sBind}\t${sConst}\t${sRest}\t${sHash}(${sHash32cnt})\t${sField}\t${sCat}\t${sGlue}`);
  ensure('inline'); G.inline += sInline; ensure('reloc'); G.reloc += sReloc;
  ensure('bind'); G.bind += sBind; ensure('const'); G.const += sConst;
  ensure('rest'); G.rest += sRest; ensure('hash32'); G.hash32 += sHash;
  ensure('field'); G.field += sField; ensure('cat'); G.cat += sCat;
  ensure('glue'); G.glue += sGlue; ensure('fns'); G.fns += sFns; ensure('hash32cnt'); G.hash32cnt += sHash32cnt;
}

console.log('\n===== GRAND TOTALS (48-chunk SOUND E3, RELOCATE_TOWER=' + RELOCATE_TOWER + ') =====');
console.log(`tower fns (DEFINE blocks) total: ${G.fns}`);
console.log(`Σ inline locking  : ${G.inline}`);
console.log(`Σ reloc  locking  : ${G.reloc}   (this is the deployed ~132K)`);
console.log('--- reloc locking attribution ---');
console.log(`  tower hash-binds (DUP/HASH256/EQVERIFY/idPush/DEFINE+const): ${G.bind}`);
console.log(`     of which 32B consts (pushData)                          : ${G.const}`);
console.log(`     of which bind opcodes+idPush                            : ${G.bind - G.const}`);
console.log(`  spend body (restBytes) total                              : ${G.rest}`);
console.log(`     forward-chain/T0/T1/lock hashes (32B pushes, ${G.hash32cnt} of them): ${G.hash32}`);
console.log(`     baked field consts (VK / G2 line coeffs / modulus)     : ${G.field}`);
console.log(`     category literals (32B == C)                           : ${G.cat}`);
console.log(`     dispatch/covenant opcodes + small glue + bigpush       : ${G.glue}`);
console.log(`  +OP_DROP prefix (1/chunk × 48)                            : 48`);
const sum = G.bind + G.rest + 48;
console.log(`  CHECK: bind ${G.bind} + rest ${G.rest} + drop 48 = ${sum} vs reloc ${G.reloc}  (Δ ${G.reloc - sum})`);
