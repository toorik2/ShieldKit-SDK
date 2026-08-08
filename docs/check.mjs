#!/usr/bin/env node

import { existsSync, readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const required = [
  'README.md',
  'SECURITY.md',
  'docs/product/start.md',
  'docs/product/model.md',
  'docs/product/verify.md',
  'docs/lab/README.md',
  'docs/lab/pf6.md',
  'docs/lab/fri.md',
  'docs/record/README.md',
];
const ignoredPrefixes = [
  'designs/pf10/research/',
  'vendor/',
];

const listed = spawnSync('git', ['ls-files', '*.md', '*.mdx'], {
  cwd: root,
  encoding: 'utf8',
});
if (listed.status !== 0) {
  console.error(listed.stderr.trim() || 'git ls-files failed');
  process.exit(1);
}

const failures = [];
for (const relative of required) {
  if (!existsSync(path.join(root, relative))) failures.push(`${relative}: required document is missing`);
}

const tracked = listed.stdout
  .split('\n')
  .filter(Boolean)
  .filter((relative) => existsSync(path.join(root, relative)));
const sources = [...new Set([...tracked, ...required])]
  .filter((relative) => !relative.includes('/vendor/'))
  .filter((relative) => !ignoredPrefixes.some((prefix) => relative.startsWith(prefix)));

for (const relative of sources) {
  const absolute = path.join(root, relative);
  const lines = readFileSync(absolute, 'utf8').split('\n');
  let fenced = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;

    const links = line.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g);
    for (const match of links) {
      let target = match[1].trim();
      if (target.startsWith('<') && target.endsWith('>')) target = target.slice(1, -1);
      target = target.split(/\s+["']/)[0];
      if (!target || target.startsWith('#') || /^(?:https?:|mailto:|data:)/i.test(target)) continue;

      const clean = target.split('#')[0].split('?')[0];
      let decoded;
      try {
        decoded = decodeURIComponent(clean);
      } catch {
        failures.push(`${relative}:${index + 1}: invalid encoded link: ${target}`);
        continue;
      }
      const resolved = path.resolve(path.dirname(absolute), decoded);
      if (!resolved.startsWith(`${root}${path.sep}`) && resolved !== root) {
        failures.push(`${relative}:${index + 1}: link escapes repository: ${target}`);
      } else if (!existsSync(resolved)) {
        failures.push(`${relative}:${index + 1}: missing link target: ${target}`);
      } else {
        statSync(resolved);
      }
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log(`docs: ${required.length} canonical files, ${sources.length} tracked files, links clean`);
