#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = [];
const kit = path.join(root, 'packages/kit');
for (const f of readdirSync(kit)) {
  if (f.endsWith('.test.mjs')) files.push(path.join(kit, f));
}
const setup = path.join(root, 'packages/profile/setup');
for (const f of readdirSync(setup)) {
  if (f.endsWith('.test.mjs')) files.push(path.join(setup, f));
}
files.push(
  path.join(root, 'packages/action/packet.test.mjs'),
  path.join(root, 'packages/action/context.test.mjs'),
  path.join(root, 'packages/prove/authority.test.mjs'),
);
const r = spawnSync(process.execPath, ['--test', ...files], { cwd: root, stdio: 'inherit' });
process.exit(r.status ?? 1);
