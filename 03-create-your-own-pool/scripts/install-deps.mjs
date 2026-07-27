#!/usr/bin/env node
/**
 * Post-install integrity check only. Dependency resolution is performed exactly once by
 * the root `npm ci` and its tracked workspace lock; this script never invokes npm and
 * never rewrites a manifest or lockfile.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const rootPackage = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const lockPath = path.join(ROOT, 'package-lock.json');
if (!existsSync(lockPath)) {
  throw new Error('root package-lock.json is required; install with npm ci from the repository root');
}
const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
if (lock.lockfileVersion !== 3 || lock.packages?.['']?.version !== rootPackage.version) {
  throw new Error('root package-lock.json does not match package.json');
}

const required = [
  'node_modules/@bitauth/libauth/build/index.js',
  'node_modules/snarkjs/package.json',
  'node_modules/poseidon-lite/package.json',
  'node_modules/.bin/tsx',
];
const missing = required.filter((relative) => !existsSync(path.join(ROOT, relative)));
if (missing.length) {
  throw new Error(`workspace installation is incomplete: ${missing.join(', ')}`);
}
console.log('workspace dependency integrity: ok (root lock, immutable workspace install)');
