#!/usr/bin/env node
// tools/health/katcount.mjs — count BUILD-TIME ASSERTIONS (known-answer tests) across the library.
//
// A KAT is any declaration that EXECUTES a check during `lake build`: `#eval` (the kat/wguard/guard
// helpers throw IO.userError on mismatch → build fails), `#guard`, `#check`, and `example … := by
// decide|rfl|native_decide` (an anonymous proof obligation the kernel discharges every build).
//
// Purpose: the KAT-CONSERVATION gate. Extracting KATs from a model file into LeanBCH/Validation/*
// must MOVE them, never DROP them — so this count (over the WHOLE tree, model + validation) must
// never decrease. verify.sh compares it to the committed tools/health/kat-count.txt.
//
//   node tools/health/katcount.mjs           # prints the integer total
//   node tools/health/katcount.mjs --by-file # per-file breakdown (sorted)
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = join(ROOT, 'LeanBCH');

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (e.endsWith('.lean')) out.push(p);
  }
  return out;
}

// Count assertions in a file. Strip block comments /- … -/ and line comments so commented-out
// examples in doc blocks are not counted.
function countFile(text) {
  const noBlock = text.replace(/\/-[\s\S]*?-\//g, '');
  let n = 0;
  for (let line of noBlock.split('\n')) {
    line = line.replace(/--.*$/, '');
    // command-style assertions: #eval / #guard (one per occurrence). #check is DELIBERATELY excluded —
    // it only fails on a type/elaboration error, never encodes a known-answer value check, so counting
    // it would let a real assertion be swapped for a `#check` with the count preserved (red-team).
    n += (line.match(/#(eval|guard)\b/g) || []).length;
    // anonymous proof-obligation KATs: every `example` declaration (counted at its line-start, so a
    // multi-line `example : … \n  := by decide` is caught — the proof method may be on a later line).
    if (/^\s*example\b/.test(line)) n += 1;
  }
  return n;
}

// VACUITY LINT (red-team residual): the conservation count is blind to a KAT being neutered in place.
// Flag the two obvious insider-tautology shapes an `example` can take while still counting as 1 KAT:
//   `example : True := …`         (trivially true — asserts nothing)
//   `example : E = E := …`        (single-line syntactic self-equality — asserts nothing)
// Preventive gate: currently ZERO hits; a new vacuous KAT trips verify.sh. (Multi-line/semantic vacuity
// is not caught — code review + the closure gate remain the backstop; this closes the CHEAP insider attack.)
function lintVacuous(text, rel) {
  const noBlock = text.replace(/\/-[\s\S]*?-\//g, '');
  const hits = [];
  noBlock.split('\n').forEach((raw, i) => {
    const line = raw.replace(/--.*$/, '');
    if (!/^\s*example\b/.test(line)) return;
    if (/^\s*example\s*:\s*True\s*(:=|$)/.test(line)) hits.push(`${rel}:${i + 1}  example : True`);
    const m = line.match(/^\s*example\s*:\s*(.+?)\s*=\s*(.+?)\s*:=/);
    if (m && m[1].trim().length > 0 && m[1].trim() === m[2].trim())
      hits.push(`${rel}:${i + 1}  self-equality  ${m[1].trim().slice(0, 48)}`);
  });
  return hits;
}

const files = walk(SRC).sort();
const rows = files.map(f => [relative(ROOT, f), countFile(readFileSync(f, 'utf8'))]).filter(([, c]) => c > 0);
const total = rows.reduce((a, [, c]) => a + c, 0);

if (process.argv.includes('--lint')) {
  const vac = files.flatMap(f => lintVacuous(readFileSync(f, 'utf8'), relative(ROOT, f)));
  if (vac.length) { console.error(`❌ ${vac.length} vacuous KAT(s):`); vac.forEach(v => console.error('   ' + v)); process.exit(1); }
  console.log('✓ no vacuous KATs (no example:True / self-equality)');
} else if (process.argv.includes('--by-file')) {
  for (const [f, c] of rows.sort((a, b) => b[1] - a[1])) console.log(`${String(c).padStart(4)}  ${f}`);
  console.log(`${String(total).padStart(4)}  TOTAL (${rows.length} files)`);
} else {
  console.log(total);
}
