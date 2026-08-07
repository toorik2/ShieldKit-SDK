// test/byte-identity.mjs — the P1 acceptance + regression gate.
//
// PUBLIC (always): optimizing test/fixtures/toy-in.hex must produce EXACTLY
// test/fixtures/toy-expected.hex, byte-for-byte. This proves the optimizer runs
// deterministically and that the IR⟂dialect seam refactor is behavior-preserving.
// The toy is a generic reusable-functions contract (test/fixtures/{Lib,Toy}.cash) —
// NOT the competitive verifier.
//
// PRIVATE (opt-in via LEANBCH_CROWN_DIR): if that env var points at the private
// singleton crown fixtures (in verifier.cash), also reproduce the 4,818 -> 4,346
// crown byte-identically — the strong reduction test. Skipped in the public repo.
//
//   node test/byte-identity.mjs
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const OPT = join(HERE, '..', 'optimize.mjs');
const norm = (p) => readFileSync(p, 'utf8').trim().replace(/\s/g, '').toLowerCase();

let fails = 0;
function check(name, inPath, expectPath) {
  const out = join('/tmp', `bi-${name}-${process.pid}.hex`);
  const r = spawnSync('node', [OPT, inPath, out], { encoding: 'utf8' });
  if (r.status !== 0) { console.error(`✗ ${name}: optimizer exited ${r.status}\n${(r.stderr || r.stdout || '').slice(0, 400)}`); fails++; return; }
  const got = norm(out), want = norm(expectPath);
  if (got === want) console.log(`✓ ${name}: byte-identical (${got.length / 2} B)`);
  else { console.error(`✗ ${name}: DIFFERS (got ${got.length / 2} B, want ${want.length / 2} B)`); fails++; }
}

// --- public toy (always) ---
check('toy', join(HERE, 'fixtures', 'toy-in.hex'), join(HERE, 'fixtures', 'toy-expected.hex'));

// --- private crown (opt-in) ---
const crownDir = process.env.LEANBCH_CROWN_DIR;
if (crownDir) {
  const cin = join(crownDir, 'singleton-5177-locking4818-marshcse.hex');
  const cout = join(crownDir, 'singleton-4705-locking4346-foldcse.hex');
  if (existsSync(cin) && existsSync(cout)) check('cse+fold crown-4346', cin, cout);
  else console.log('· cse+fold crown fixtures not found in LEANBCH_CROWN_DIR — skipped');

  // move-arrange crown: dissect the pipeline baseline (12,351 B) with its cached arity -> 5,695 B.
  const pdir = join(crownDir, 'pipeline-movearrange');
  const maCrown = join(crownDir, 'singleton-6054-locking5695-movearrange.hex');
  if (existsSync(join(pdir, 'baseline.json')) && existsSync(join(pdir, 'arity.json')) && existsSync(maCrown)) {
    const base = JSON.parse(readFileSync(join(pdir, 'baseline.json'), 'utf8'));
    const baseHex = base.debug?.bytecode || base.bytecodeHex || base.hex;
    const baseTmp = join('/tmp', `ma-base-${process.pid}.hex`);
    writeFileSync(baseTmp, baseHex);
    const out = join('/tmp', `ma-out-${process.pid}.hex`);
    const r = spawnSync('node', [join(HERE, '..', 'passes', 'movearrange.mjs'), baseTmp, out, '--arity', join(pdir, 'arity.json')], { encoding: 'utf8' });
    if (r.status !== 0) { console.error(`✗ move-arrange crown: exited ${r.status}`); fails++; }
    else if (norm(out) === norm(maCrown)) console.log(`✓ move-arrange crown-5695: byte-identical (${norm(maCrown).length / 2} B)`);
    else { console.error('✗ move-arrange crown-5695: DIFFERS'); fails++; }
  } else console.log('· move-arrange crown fixtures not found — skipped');
} else {
  console.log('· LEANBCH_CROWN_DIR unset — private crown reduction tests skipped (public run)');
}

if (fails) { console.error(`\n${fails} byte-identity FAILURE(s)`); process.exit(1); }
console.log('\nall byte-identity checks passed');
