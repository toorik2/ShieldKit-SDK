// Readiness probe for the residue-build drop-in. Run: node tools/residue-build/CHECK.mjs [dir]
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
const dir = process.argv[2] || 'tools/residue-build';
const want = {
  generators: ['gen_residue.mjs', 'emit_residue_vectors.mjs', 'gen_g2check.mjs', 'assemble_residue_vectors.mjs'],
  scorer: ['export-json.ts'],
};
function walk(d, depth = 0) { let out = []; if (depth > 4) return out;
  for (const e of readdirSync(d)) { const p = join(d, e); if (e === 'node_modules' || e === '.git') continue;
    if (statSync(p).isDirectory()) out.push(...walk(p, depth + 1)); else out.push(p); } return out; }
const files = existsSync(dir) ? walk(dir) : [];
const cash = files.filter(f => f.endsWith('.cash'));
const found = (name) => files.find(f => f.endsWith('/' + name) || f.endsWith(name));
console.log(`scan of ${dir}: ${files.length} files, ${cash.length} .cash sources`);
for (const [k, names] of Object.entries(want)) for (const n of names) console.log(`  ${found(n) ? '✓' : '·'} ${n}${found(n) ? '  -> ' + found(n) : ' (missing)'}`);
console.log(`  .cash sources: ${cash.slice(0, 12).map(f => f.split('/').pop()).join(', ')}${cash.length > 12 ? ' …' : ''}`);
const ready = want.generators.some(found) && cash.length > 0;
console.log(ready ? '\nREADY ENOUGH — I can start (a generator + .cash sources are present).' : '\nNOT YET — drop the residue generators + .cash sources in.');
