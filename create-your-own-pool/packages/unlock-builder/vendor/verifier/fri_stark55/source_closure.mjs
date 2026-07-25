// Resolve and audit the complete local ES-module closure of a production
// verifier.  A manifest that names only a harmless wrapper must not hide a toy
// verifier or a test-only dependency in an unlisted local import.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, extname, relative, resolve } from 'node:path';

const LOCAL_SPECIFIER = /^\.\.?\//;
const IMPORT_SPECIFIER = /(?:from\s*|import\s*\(\s*|require\s*\(\s*)['"]([^'"]+)['"]/g;

function candidates(pathname) {
  if (extname(pathname)) return [pathname];
  return [pathname, `${pathname}.mjs`, `${pathname}.js`, `${pathname}.json`, resolve(pathname, 'index.mjs'), resolve(pathname, 'index.js')];
}

function resolveLocal(root, importer, specifier) {
  if (!LOCAL_SPECIFIER.test(specifier)) return undefined;
  const base = resolve(dirname(importer), specifier);
  const dependencies = resolve(root, 'node_modules');
  if (base === dependencies || base.startsWith(`${dependencies}/`)) return undefined;
  // A production manifest must not smuggle an out-of-repository verifier file
  // into the audited closure through `../../...` imports.  Report that as a
  // distinct failure instead of hashing/reading an arbitrary host path.
  if (base !== root && !base.startsWith(`${root}/`)) return { outside: base };
  const found = candidates(base).find((candidate) => existsSync(candidate));
  return found === undefined ? { missing: base } : { path: found };
}

/**
 * Return every local source file reachable from `roots`, plus unresolved local
 * imports.  Non-relative imports are intentionally outside this closure and
 * must be pinned through the normal package-lock/toolchain evidence.
 */
export function collectLocalModuleClosure(root, roots) {
  const rootPath = resolve(root);
  const queue = roots.map((entry) => resolve(rootPath, entry));
  const files = new Set();
  const missing = [];
  const outside = [];
  while (queue.length > 0) {
    const current = queue.shift();
    if (files.has(current)) continue;
    if (current !== rootPath && !current.startsWith(`${rootPath}/`)) {
      outside.push(current);
      continue;
    }
    if (!existsSync(current)) { missing.push(current); continue; }
    files.add(current);
    let source;
    try { source = readFileSync(current, 'utf8'); }
    catch { missing.push(current); continue; }
    for (const match of source.matchAll(IMPORT_SPECIFIER)) {
      const resolved = resolveLocal(rootPath, current, match[1]);
      if (resolved?.missing !== undefined) missing.push(resolved.missing);
      else if (resolved?.outside !== undefined) outside.push(resolved.outside);
      else if (resolved?.path !== undefined) queue.push(resolved.path);
    }
  }
  return {
    files: [...files].sort(),
    missing: [...new Set(missing)].sort(),
    outside: [...new Set(outside)].sort(),
    relative: (pathname) => relative(rootPath, pathname),
  };
}
