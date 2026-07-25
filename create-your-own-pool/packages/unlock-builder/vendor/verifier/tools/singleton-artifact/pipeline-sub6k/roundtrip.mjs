// ROUND-TRIP GATE: recompile(decompile(14,641-baseline)) === baseline byte-for-byte.
// Proves the block-DAG IR is a faithful, byte-exact cover of the compiled locking
// bytecode BEFORE any optimization pass. Also exercises the hardening asserts
// (branch-shape, loop-invariance) on all 52 bodies + main and reports construct coverage.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse } from './asm.mjs';
import { CTRL, VALOP, VERIFY_OPS, OPC } from './decompile.mjs';
import { dissect, probeArity, decompileProgram, recompileProgram } from './program.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const BASELINE = process.argv[2] || join(here, 'baseline.json');
const raw = JSON.parse(readFileSync(BASELINE, 'utf8'));
const hex = raw.debug?.bytecode || raw.bytecodeHex || raw.hex;
if (!hex) throw new Error('no raw hex bytecode field (debug.bytecode) in ' + BASELINE);
const baseline = Uint8Array.from(Buffer.from(hex, 'hex'));
console.log(`baseline: ${baseline.length} B  (${raw.contractName || '?'})`);

const d = dissect(baseline);
console.log(`dissected ${d.order.length} subroutines + main (${d.mainOps.length} main ops)`);

console.time('probeArity');
const arity = probeArity(d);
console.timeEnd('probeArity');

console.time('decompile');
const ir = decompileProgram(d, arity, 10);
console.timeEnd('decompile');

console.time('recompile');
const { bytes, perBody, mainExact, mainOrigLen, mainRecLen } = recompileProgram(d, ir, arity);
console.timeEnd('recompile');

// ---- construct coverage census ----
const counts = { IF: 0, NOTIF: 0, ELSE: 0, ENDIF: 0, BEGIN: 0, UNTIL: 0, VERIFY: 0, NUMEQUALVERIFY: 0, EQUALVERIFY: 0, INVOKE: 0, VALOP: 0, blocks: 0, verifyBoundaries: 0 };
const inv = { 0x63: 'IF', 0x64: 'NOTIF', 0x67: 'ELSE', 0x68: 'ENDIF', 0x65: 'BEGIN', 0x66: 'UNTIL', 0x69: 'VERIFY', 0x9d: 'NUMEQUALVERIFY', 0x88: 'EQUALVERIFY' };
const censusItems = (items) => {
  for (const it of items) {
    if (it.ctrl !== undefined) { const n = inv[it.ctrl]; if (n) counts[n]++; if (it.isVerify) counts.verifyBoundaries++; }
    else { counts.blocks++; for (const o of it.block.rawOps) { if (o.op === OPC.INVOKE) counts.INVOKE++; else if (VALOP.has(o.op)) counts.VALOP++; } }
  }
};
for (const id of d.order) censusItems(ir.bodies.get(id));
censusItems(ir.mainItems);

// ---- gate verdicts ----
const bodiesExact = perBody.filter((b) => b.exact).length;
const fullExact = Buffer.from(bytes).equals(Buffer.from(baseline));
const notExact = perBody.filter((b) => !b.exact);

console.log('\n== per-construct coverage (round-tripped through IR) ==');
for (const k of ['IF', 'NOTIF', 'ELSE', 'ENDIF', 'BEGIN', 'UNTIL', 'VERIFY', 'NUMEQUALVERIFY', 'EQUALVERIFY', 'INVOKE', 'VALOP', 'blocks', 'verifyBoundaries'])
  console.log(`  ${k.padEnd(16)} ${counts[k]}`);

console.log('\n== round-trip ==');
console.log(`  bodies byte-exact : ${bodiesExact}/${d.order.length}`);
console.log(`  main byte-exact   : ${mainExact}  (orig ${mainOrigLen} B / rec ${mainRecLen} B)`);
console.log(`  FULL byte-exact   : ${fullExact}  (rec ${bytes.length} B / baseline ${baseline.length} B)`);
if (notExact.length) console.log('  NON-EXACT bodies  :', notExact.map((b) => `def#${b.id}(${b.origLen}->${b.recLen})`).join(', '));

// arity sanity: any zero-in subroutine or absurd arity is a probe artifact worth noting
const arDump = d.order.map((id) => `${id}:${arity[id].in}->${arity[id].out}`).join(' ');
console.log('\n== arity (id:in->out) ==\n  ' + arDump);

const PASS = fullExact && bodiesExact === d.order.length && mainExact;
console.log(`\nGATE: ${PASS ? 'PASS' : 'FAIL'}`);
process.exit(PASS ? 0 : 1);
