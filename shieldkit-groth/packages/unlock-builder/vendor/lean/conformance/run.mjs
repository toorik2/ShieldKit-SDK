// LeanBCH vmb conformance driver. Streams the official vmb_test corpus through the compiled VM
// via conformance/Runner.lean (runtime hex parsing — no literal-elaboration cost).
// Usage: node conformance/run.mjs <corpusDir> <family1> [family2 …]
import fs from 'node:fs';
import { execSync } from 'node:child_process';
const [corpus, ...families] = process.argv.slice(2);
const lines = [];
let counts = {};
for (const fam of families) {
  // The VM is BCH_2026-specialized, so measure the 2026 corpus (the 2025 variants are
  // epoch-boundary mismatches for the opcodes 2026 changed: functions, INVERT/shifts, 0x65/0x66).
  // standard + nonstandard are both consensus-VALID (verifyInput must accept); only *_invalid rejects.
  // (There is no bch_2026_valid dir on disk; nonstandard = consensus-valid-but-relay-rejected.)
  for (const variant of ['bch_2026_standard', 'bch_2026_nonstandard', 'bch_2026_invalid']) {
    const p = `${corpus}/${variant}/${fam}.vmb_tests.json`;
    if (!fs.existsSync(p)) continue;
    const exp = variant.endsWith('invalid') ? '0' : '1';
    for (const v of JSON.parse(fs.readFileSync(p, 'utf8'))) {
      lines.push(`${exp} ${v[0]} ${v[4]} ${v[5]} ${v[6] ?? 0}`);
      counts[variant.slice(4)] = (counts[variant.slice(4)] || 0) + 1;
    }
  }
}
if (!lines.length) { console.log('no vectors for', families.join(',')); process.exit(0); }
fs.writeFileSync('/tmp/vmb_vectors.txt', lines.join('\n'));
console.log(`${lines.length} vectors (${Object.entries(counts).map(([k,n])=>k+':'+n).join(', ')}) from ${families.length} families`);
const out = execSync('.lake/build/bin/vmbconf < /tmp/vmb_vectors.txt', {
  cwd: process.cwd(), shell: '/bin/bash', encoding: 'utf8',
  env: { ...process.env, PATH: process.env.HOME + '/.elan/bin:' + process.env.PATH }, maxBuffer: 1 << 28 });
console.log(out.trim());
