// Independently verify the successor-pin BINDING of the actual 32-chunk chain:
// reproduce each chunk's DEPLOYED redeem (rescheduled compile -> foldRedeem -> InvokeCSE on the two
// code-bound cse targets), compute its real P2SH32 spk = P2SH32(hash256(redeem)), and confirm chunk
// i's EMBEDDED pin (the 0x..87 literal in its covOut) == chunk i+1's ACTUAL P2SH32. Any wrong/attacker
// successor -> mismatch. This is a second oracle over the SAME byte pipeline unified_affine.mjs deploys.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileFileBytecode } from './_millermath.mjs';
import { foldRedeem } from './_foldredeem.mjs';
import { hash256, encodeLockingBytecodeP2sh32, binToHex } from '@bitauth/libauth';

const here = dirname(fileURLToPath(import.meta.url));
const G = join(here, 'generated') + '/';
const PEEPHOLE = process.env.PEEPHOLE !== '0';
const T2A_CSE = process.env.T2A_CSE !== '0';
const CSE_MJS = '/home/toorik/Projects/LeanBCH/optimizer/passes/cse.mjs';
const UNDOMINT_MJS = join(here, '../../../intel/validation/T2-A/undomint_equiv.mjs');

// current deployed layout (fnames == unified_affine.mjs plan[].fname; boundaries from its JSON).
// T5-1 DELETED the g2check stage (folded into miller + relocated to vkx genesis); T3-2 REPLACED the
// 8-chunk jacobian vkx MSM with a SINGLE Eagen ECIP certificate chunk (vkx_ecip) — now the root.
const millerBounds = [0, 20, 41, 62, 83, 104, 125, 146, 167, 188, 209, 230, 251, 272, 293, 314, 335, 348];
const millerFnames = millerBounds.slice(0, -1).map((lo, i) => `ml_${lo}_${millerBounds[i + 1]}`);
const chain = [
  'vkx_ecip',
  ...millerFnames,
  'tail',
].map((c) => `_u_${c}`);
// cse targets: the final miller chunk + the tail (must match unified_affine.mjs CSE_FNAMES).
const CSE_TARGETS = new Set([`_u_${millerFnames[millerFnames.length - 1]}`, '_u_tail']);

function deployedRedeem(cName) {
  let redeem = Uint8Array.from([...compileFileBytecode(G + cName + '.cash')]);
  if (PEEPHOLE) redeem = foldRedeem(redeem);
  if (T2A_CSE && CSE_TARGETS.has(cName)) {
    const o = join(G, `_cb_${cName}.orig.hex`), c = join(G, `_cb_${cName}.cse.hex`);
    writeFileSync(o, binToHex(redeem));
    execFileSync('node', [CSE_MJS, o, c], { stdio: ['ignore', 'ignore', 'inherit'] });
    // SAME undomint equivalence gate as unified_affine.mjs cseRedeem: deploy CSE only if byte-exact
    // undo proves it semantics-preserving; otherwise keep the foldRedeem-only redeem (deterministic,
    // so both files agree on which chunks are CSE'd -> the pinned successor spks still match).
    let ok = false;
    try { ok = JSON.parse(execFileSync('node', [UNDOMINT_MJS, o, c], { encoding: 'utf8' }).trim()).byteExactUndo; }
    catch (e) { const s = String(e.stdout ?? '').trim().split('\n')[0]; try { ok = JSON.parse(s).byteExactUndo; } catch { ok = false; } }
    if (ok) redeem = Uint8Array.from(Buffer.from(readFileSync(c, 'utf8').trim(), 'hex'));
  }
  return redeem;
}

// each chunk's real deployed P2SH32 spk
const spk = chain.map((c) => binToHex(encodeLockingBytecodeP2sh32(hash256(deployedRedeem(c)))));
// each chunk's EMBEDDED pin (the successor spk it commits to), or null (terminal tail)
const pin = chain.map((c) => {
  const src = readFileSync(G + c + '.cash', 'utf8');
  const m = src.match(/tx\.outputs\[0\]\.lockingBytecode == 0x([a-f0-9]+)\)/);
  return m ? m[1] : null;
});

let bound = 0, boundaries = 0; const mismatches = [];
for (let i = 0; i < chain.length - 1; i++) {
  boundaries++;
  const want = spk[i + 1], got = pin[i];
  if (got === want) bound++;
  else mismatches.push({ i, chunk: chain[i], pinned: got, actualSuccessor: want });
}
const tailPin = pin[chain.length - 1]; // terminal tail: no successor pin -> null

console.log('chunks =', chain.length, ' boundaries =', boundaries, ' bound =', bound, ' mismatches =', mismatches.length);
if (mismatches.length) console.log('MISMATCHES:', JSON.stringify(mismatches, null, 2));
console.log('tail pin (must be null) =', tailPin);
const ok = bound === boundaries && mismatches.length === 0 && tailPin === null;
console.log('CHAIN-BINDING OK =', ok);
if (!ok) process.exit(1);
