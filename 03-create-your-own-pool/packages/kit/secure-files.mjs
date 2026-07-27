import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';

export const PRIVATE_FILE_MODE = 0o600;
export const PRIVATE_DIRECTORY_MODE = 0o700;
export const PUBLIC_FILE_MODE = 0o644;

function ensureParent(filePath, directoryMode) {
  const parent = path.dirname(path.resolve(filePath));
  mkdirSync(parent, { recursive: true, mode: directoryMode });
  return parent;
}

function fsyncDirectory(directory) {
  let fd;
  try {
    fd = openSync(directory, 'r');
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Write a file through a same-directory temporary file, fsync it, and rename it.
 * The final chmod also repairs overly broad permissions on a pre-existing file.
 */
export function atomicWriteFile(
  filePath,
  data,
  { mode = PRIVATE_FILE_MODE, directoryMode = PRIVATE_DIRECTORY_MODE } = {},
) {
  const target = path.resolve(filePath);
  const parent = ensureParent(target, directoryMode);
  const temporary = path.join(
    parent,
    `.${path.basename(target)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`,
  );
  let fd;
  try {
    fd = openSync(temporary, 'wx', mode);
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(fd, bytes, offset);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    chmodSync(temporary, mode);
    renameSync(temporary, target);
    chmodSync(target, mode);
    fsyncDirectory(parent);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(temporary)) unlinkSync(temporary);
    throw error;
  }
}

export function atomicWriteJson(filePath, value, options) {
  atomicWriteFile(filePath, `${JSON.stringify(value, null, 2)}\n`, options);
}

export function readJsonFile(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

/**
 * Append one JSON record durably. Existing permissive files are repaired to mode 0600.
 */
export function appendPrivateJsonLine(filePath, value) {
  const target = path.resolve(filePath);
  const parent = ensureParent(target, PRIVATE_DIRECTORY_MODE);
  const fd = openSync(target, 'a', PRIVATE_FILE_MODE);
  try {
    chmodSync(target, PRIVATE_FILE_MODE);
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(fd, bytes, offset);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  fsyncDirectory(parent);
}

export function repairPrivateFileMode(filePath) {
  if (existsSync(filePath)) chmodSync(filePath, PRIVATE_FILE_MODE);
}
