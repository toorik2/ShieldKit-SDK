#!/usr/bin/env node
// Recursive minimal-push canonicalizer for CSE/fold optimizer output.
// The verified passes rebuild the singleton on the LOOSENED VM which does not enforce
// SCRIPT_VERIFY_MINIMALDATA; the consensus scorer VM does. The only non-minimal pushes
// they introduce are single-byte data pushes of values that HAVE a dedicated 1-op minimal
// form: PUSHBYTES_1 v (v in 1..16) -> OP_1..OP_16, and PUSHBYTES_1 0x81 -> OP_1NEGATE.
// Both push the byte-identical stack element => provably semantics-preserving, and 1B smaller.
// We recurse into OP_DEFINE subroutine bodies (pushed as data blobs, executed on INVOKE).
import { parse, serialize } from './pipeline-sub6k/asm.mjs';
import { dissect, rebuild } from './pipeline-sub6k/program.mjs';
import { readFileSync, writeFileSync } from 'node:fs';
import { hexToBin, binToHex } from '@bitauth/libauth';

let FIXES = 0;
function canonFlat(bytes) {
  const ops = parse(bytes);
  const out = ops.map((o) => {
    if (o.op === 1 && o.data && o.data.length === 1) {
      const v = o.data[0];
      if (v >= 1 && v <= 16) { FIXES++; return { op: 0x50 + v }; }
      if (v === 0x81) { FIXES++; return { op: 0x4f }; }
    }
    return o;
  });
  return serialize(out);
}
function canonRec(bytes, depth = 0) {
  const d = dissect(bytes);
  if (d.order.length === 0) return canonFlat(bytes);   // flat program: no define table
  const override = new Map();
  for (const id of d.order) override.set(id, canonRec(d.bodies.get(id), depth + 1));
  const rebuilt = rebuild(d, override, serialize(d.mainOps));
  return canonFlat(rebuilt);   // fixes main pushes + top-level id-pushes; bodies now blobs
}

const bin = hexToBin(readFileSync(process.argv[2], 'utf8').trim());
const out = canonRec(bin);
writeFileSync(process.argv[3], binToHex(out));
console.error(`minpush_canon: ${FIXES} fixes, ${bin.length}B -> ${out.length}B`);
