#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const indexPath = fileURLToPath(new URL('../catalogue/INDEX.md', import.meta.url));
const write = process.argv.includes('--write');
const maxClaimWords = 20;

const confidence = new Set(['low', 'med', 'medium', 'high']);
const compactMetadata = (metadata) => {
  const tags = metadata.split('·').map((tag) => tag.trim()).filter(Boolean);
  if (tags.length < 2) return tags[0] ?? 'unknown';
  const confidenceTag = tags.find((tag) => confidence.has(tag.toLowerCase()));
  return `${tags[0]}·${confidenceTag ?? tags[1]}`;
};

const compactEntry = (line) => {
  if (!line.startsWith('- ')) return line;
  const arrow = line.lastIndexOf('→');
  if (arrow === -1) return line;
  const left = line.slice(0, arrow).trimEnd();
  const target = line.slice(arrow + 1).trim();
  const match = left.match(/^-\s+(\S+)\s+\[([^\]]+)\]\s+(.+)$/u);
  if (match === null) return line;
  const [, id, metadata, claim] = match;
  const words = claim.trim().split(/\s+/u);
  const shortClaim = words.length > maxClaimWords
    ? `${words.slice(0, maxClaimWords).join(' ')} …`
    : words.join(' ');
  return `- ${id} [${compactMetadata(metadata)}] ${shortClaim} → ${target}`;
};

const source = readFileSync(indexPath, 'utf8');
const compacted = source.split('\n').map(compactEntry).join('\n');
const changedLines = source.split('\n').reduce(
  (count, line, index) => count + (line === compacted.split('\n')[index] ? 0 : 1),
  0,
);

if (write) {
  writeFileSync(indexPath, compacted);
  console.log(`compacted ${changedLines} INDEX entries`);
} else if (changedLines > 0) {
  console.error(`catalogue/INDEX.md has ${changedLines} non-compact entries; run: node tools/compact-catalogue-index.mjs --write`);
  process.exitCode = 1;
} else {
  console.log('catalogue/INDEX.md is compact');
}
