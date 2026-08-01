import { randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, lstat, open, rename, rm } from 'node:fs/promises';
import path from 'node:path';

function reject(label) { throw new Error(`${label} is not a private non-symlink path`); }
function absolute(value, label) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) reject(label);
  return value;
}
function ownerAllowed(stat) {
  return typeof process.getuid !== 'function' || stat.uid === process.getuid() || stat.uid === 0;
}
function privateMode(stat) {
  return ownerAllowed(stat) && (stat.mode & 0o022) === 0;
}
async function checked(filename, kind, label, { leaf = false } = {}) {
  const before = await lstat(filename).catch(() => reject(label));
  if (before.isSymbolicLink() || (kind === 'directory' ? !before.isDirectory() : !before.isFile()) || !privateMode(before)) reject(label);
  const flags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | (kind === 'directory' ? fsConstants.O_DIRECTORY : 0);
  const handle = await open(filename, flags).catch(() => reject(label));
  try {
    const after = await handle.stat();
    if ((kind === 'directory' ? !after.isDirectory() : !after.isFile()) || after.dev !== before.dev || after.ino !== before.ino || !privateMode(after) || (leaf && (after.mode & 0o077) !== 0)) reject(label);
  } finally { await handle.close(); }
}
async function privateAncestors(filename, label) {
  const parts = absolute(filename, label).split(path.sep).filter(Boolean); let current = path.sep;
  await checked(current, 'directory', label);
  for (const part of parts.slice(0, -1)) { current = path.join(current, part); await checked(current, 'directory', label); }
}

export async function assertPrivateDirectory(directory, label) {
  await privateAncestors(directory, label); await checked(directory, 'directory', label, { leaf: true }); return directory;
}
export async function assertPrivateFile(filename, label) {
  await privateAncestors(filename, label); await checked(filename, 'file', label, { leaf: true }); return filename;
}
export async function readPrivateUtf8(filename, label) {
  await assertPrivateFile(filename, label);
  const handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(() => reject(label));
  try { const stat = await handle.stat(); if (!stat.isFile() || !privateMode(stat) || (stat.mode & 0o077) !== 0) reject(label); return await handle.readFile({ encoding: 'utf8' }); } finally { await handle.close(); }
}
export async function writePrivateFile(filename, bytes, label) {
  const parent = path.dirname(absolute(filename, label)); await assertPrivateDirectory(parent, label);
  await lstat(filename).then((stat) => { if (!stat.isFile() || stat.isSymbolicLink() || !privateMode(stat) || (stat.mode & 0o077) !== 0) reject(label); }).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
  const temporary = path.join(parent, `.${path.basename(filename)}.${randomUUID()}.tmp`); let handle;
  try {
    handle = await open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600); await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined; await chmod(temporary, 0o600); await assertPrivateDirectory(parent, label); await rename(temporary, filename); await assertPrivateDirectory(parent, label); const parentHandle = await open(parent, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW); try { await parentHandle.sync(); } finally { await parentHandle.close(); }
  } finally { await handle?.close().catch(() => undefined); await rm(temporary, { force: true }).catch(() => undefined); }
}
