// Drive the LeanBCH VERIFIED fold/peephole pass (optimizer/passes/fold.mjs) on a redeem's
// bytecode. Returns the folded bytecode. The pass is the 0-sorry FoldTable: every merge is a
// proven stack-effect identity (OVER OVER->2DUP, <3>ROLL <3>ROLL->2SWAP, SWAP SWAP->delete, ...).
// It merges ONLY within pure-stack-op runs; covenant introspection ops (0xc0/0xcd) are opaque
// barriers it never folds across. Invoked as a subprocess (fold.mjs is a CLI, no exports).
import { execFileSync } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const LEANBCH_ROOT = process.env.LEANBCH_ROOT;
if (!LEANBCH_ROOT) throw new Error('LEANBCH_ROOT is required for the LeanBCH-verified fold pass');
const FOLD = join(LEANBCH_ROOT, 'optimizer/passes/fold.mjs');
const DIR = mkdtempSync(join(tmpdir(), 'foldredeem-'));
let seq = 0;

export function foldRedeem(u8) {
  const inHex = join(DIR, `r${seq}.hex`), outHex = join(DIR, `r${seq}.folded.hex`);
  seq++;
  writeFileSync(inHex, Buffer.from(u8).toString('hex'));
  // no --gate: GATE1 round-trip needs the decompiler to model covenant introspection opcodes
  // (0xc0/0xcd) which it does not; soundness here is enforced by the REAL covenant accept/reject
  // (measureChunk accept + reverify_thread_escape), a stronger A1 check than the generic gate.
  execFileSync('node', [FOLD, inHex, outHex], { encoding: 'utf8' });
  return Uint8Array.from(Buffer.from(readFileSync(outHex, 'utf8').trim(), 'hex'));
}
