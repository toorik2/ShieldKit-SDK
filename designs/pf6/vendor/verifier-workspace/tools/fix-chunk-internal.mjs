import { repoPath as vcRepoPath } from '#repo-paths';
// Migrate stale chunked/*.cash to the current fork syntax: reusable helpers must
// be declared `internal function` (compiled to OP_DEFINE/OP_INVOKE). Only the
// contract entry-point `spend` stays a plain `function`. Idempotent.
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = vcRepoPath('build/chunked');
const walk = (dir) => readdirSync(dir).flatMap((name) => {
  const p = join(dir, name); const s = statSync(p);
  if (s.isDirectory()) return walk(p);
  return /chunk\d+\.cash$/.test(name) ? [p] : [];
});

let files = 0, marked = 0;
for (const file of walk(ROOT)) {
  let src = readFileSync(file, 'utf8');
  const before = src;
  // mark every top-level helper `function` as internal...
  src = src.replace(/^(\s*)function /gm, (m, ws) => { marked++; return `${ws}internal function `; });
  // ...except the entry point, which must remain a plain function.
  src = src.replace(/^(\s*)internal function spend\(/gm, (m, ws) => { marked--; return `${ws}function spend(`; });
  if (src !== before) { writeFileSync(file, src); files++; }
}
console.log(`internalized helpers in ${files} chunk files (${marked} functions marked internal)`);
