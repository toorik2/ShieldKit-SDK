import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export function ensureDir(p) {
  mkdirSync(p, { recursive: true });
  return p;
}

export function writeJson(file, obj) {
  ensureDir(path.dirname(file));
  writeFileSync(file, JSON.stringify(obj, null, 2) + '\n');
  return file;
}

export function sha256File(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

export function sha256Buf(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export function containmentAssert() {
  // All tracked package paths under ROOT
  const bad = [];
  function walk(dir) {
    for (const name of readdirSync(dir)) {
      if (name === 'node_modules' || name === '.git') continue;
      const p = path.join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else {
        const rel = path.relative(ROOT, p);
        if (rel.startsWith('..')) bad.push(p);
      }
    }
  }
  walk(ROOT);
  return { ok: bad.length === 0, bad, root: ROOT };
}

export function forbiddenScan() {
  const hits = [];
  const patterns = [
    /mock\s*proof/i,
    /toy\s*proof/i,
    /placeholder\s*proof/i,
    /groth16/i,
    /proof\.system\s*===\s*['"]groth/i,
  ];
  function walk(dir) {
    for (const name of readdirSync(dir)) {
      if (['node_modules', '.git', 'vendor', '.private', 'evidence'].includes(name)) continue;
      const p = path.join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (/\.(mjs|js|ts|py|md)$/.test(name) && !name.includes('FRI_STARK_REPLACEMENT')) {
        const text = readFileSync(p, 'utf8');
        // allow mentions in plan/docs of "no groth"
        for (const re of patterns) {
          if (re.test(text) && !/no groth|forbid|forbidden|never.*groth|Groth fallback/i.test(text)) {
            // product path: packages + scripts only strict
            if (p.includes('/packages/') || p.includes('/scripts/')) {
              if (/groth/i.test(text) && /fallback|proveGroth|zkey|snarkjs/i.test(text)) {
                hits.push({ file: path.relative(ROOT, p), pattern: String(re) });
              }
              if (/mock proof|toy proof|placeholder proof/i.test(text)) {
                hits.push({ file: path.relative(ROOT, p), pattern: String(re) });
              }
            }
          }
        }
      }
    }
  }
  walk(ROOT);
  return { ok: hits.length === 0, hits };
}
