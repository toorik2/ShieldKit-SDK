// Read-only structural audit for catalogue/SCHEMA.md compliance.
// Historical drift is reported, never auto-rewritten: superseded evidence stays intact.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.env.CATALOGUE_ROOT || 'catalogue';
const specs = {
  empirical: ['id', 'kind', 'component', 'status', 'variant', 'reproduce', 'vm-pin', 'result', 'gap-to-floor', 'links', 'date/commit'],
  research: ['id', 'kind', 'axis', 'status', 'confidence', 'claim', 'detail', 'impact-our-model', 'soundness-obligation', 'provenance', 'links', 'date/commit'],
};
const readDocs = (dir) => readdirSync(join(ROOT, dir)).filter((x) => x.endsWith('.md')).sort().map((name) => {
  const path = join(ROOT, dir, name);
  const text = readFileSync(path, 'utf8');
  const keys = new Set([...text.matchAll(/^([A-Za-z][A-Za-z0-9_/-]*):/gm)].map((m) => m[1]));
  const id = text.match(/^id:\s*(\S+)/m)?.[1] ?? null;
  return { name, path, id, missing: specs[dir].filter((key) => !keys.has(key)) };
});
const docs = Object.fromEntries(Object.keys(specs).map((dir) => [dir, readDocs(dir)]));
const idRows = Object.values(docs).flat().filter((x) => x.id).map((x) => [x.id, x.path]);
const idMap = new Map();
for (const [id, path] of idRows) idMap.set(id, [...(idMap.get(id) ?? []), path]);
const duplicateIds = [...idMap].filter(([, paths]) => paths.length > 1).map(([id, paths]) => ({ id, paths }));
const index = readFileSync(join(ROOT, 'INDEX.md'), 'utf8');
const indexEntryIds = [...index.matchAll(/^[-*]\s+((?:E|R)-[A-Za-z0-9-]+)/gm)].map((m) => m[1]);
const indexEntrySet = new Set(indexEntryIds);
const indexFileRefs = [...index.matchAll(/→\s+((?:empirical|research)\/[^\s]+)/g)].map((m) => m[1].replace(/[).,;]+$/, ''));
const unresolvedIndexFileRefs = indexFileRefs.filter((path) => !path.includes('<')).filter((path) => {
  try { readFileSync(join(ROOT, path)); return false; } catch { return true; }
});
const missingFromIndex = idRows.filter(([id]) => !indexEntrySet.has(id)).map(([id, path]) => ({ id, path }));
const summarize = (rows) => ({
  files: rows.length,
  missing: Object.fromEntries(specs[rows[0]?.path.split('/').slice(-2, -1)[0] ?? 'empirical'].map((key) => [key, rows.filter((x) => x.missing.includes(key)).length])),
  incompleteFiles: rows.filter((x) => x.missing.length).map((x) => ({ name: x.name, missing: x.missing })),
});
const output = {
  schema: 'verifier.cash/catalogue-schema-audit/v1',
  catalogueRoot: ROOT,
  empirical: summarize(docs.empirical),
  research: summarize(docs.research),
  totalFiles: docs.empirical.length + docs.research.length,
  explicitIds: idRows.length,
  duplicateIds,
  indexEntryLines: indexEntryIds.length,
  indexUniqueIds: indexEntrySet.size,
  missingFromIndex,
  unresolvedIndexFileRefs,
  verdict: duplicateIds.length === 0 && unresolvedIndexFileRefs.length === 0 ? 'NO-DUPLICATE-ID-OR-BROKEN-INDEX-FILE-REF' : 'INDEX-INTEGRITY-FAIL',
};
console.log(JSON.stringify(output, null, 2));
