import { randomBytes } from 'node:crypto';
import {
  constants as fsConstants,
} from 'node:fs';
import {
  lstat,
  open,
  realpath,
  rename,
  unlink,
} from 'node:fs/promises';
import path from 'node:path';

import {
  createV2SecretFile,
} from '../../profile/v2/instance-descriptor.mjs';
import {
  decodeV2PrivateActionRecord,
  encodeV2PrivateActionRecord,
} from './private-action-record.mjs';

const PRIVATE_ACTION_STORE_BRAND = new WeakSet();
const OPERATION_ID = /^v2op:[0-9a-f]{64}$/;

export class V2PrivateActionStoreError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2PrivateActionStoreError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2PrivateActionStoreError(code, message, options);
};

function exact(value, fields, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('PRIVATE_ACTION_STORE_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (
    actual.length !== expected.length
    || actual.some((entry, index) => entry !== expected[index])
  ) {
    fail(
      'PRIVATE_ACTION_STORE_INVALID',
      `${label} has missing or unknown properties`,
    );
  }
}

function operationPath(directory, operationId) {
  if (typeof operationId !== 'string' || !OPERATION_ID.test(operationId)) {
    fail(
      'PRIVATE_ACTION_STORE_INVALID',
      'private action operation ID is invalid',
    );
  }
  return path.join(
    directory,
    `${operationId.slice('v2op:'.length)}.json`,
  );
}

async function syncDirectory(directory) {
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function assertPrivateDirectory(directory) {
  if (
    typeof directory !== 'string'
    || !path.isAbsolute(directory)
    || path.normalize(directory) !== directory
    || directory.includes('\0')
  ) {
    fail(
      'PRIVATE_ACTION_STORE_UNSAFE',
      'private action store directory must be a normalized absolute path',
    );
  }
  const parsed = path.parse(directory);
  const components = path.relative(parsed.root, directory)
    .split(path.sep)
    .filter((component) => component.length !== 0);
  let current = parsed.root;
  for (const component of components) {
    current = path.join(current, component);
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (error) {
      fail(
        'PRIVATE_ACTION_STORE_UNSAFE',
        'private action store ancestry must already exist',
        { cause: error },
      );
    }
    if (
      metadata.isSymbolicLink()
      || !metadata.isDirectory()
      || (metadata.mode & 0o022) !== 0
    ) {
      fail(
        'PRIVATE_ACTION_STORE_UNSAFE',
        'private action store ancestry must contain only non-writable non-symlink directories',
      );
    }
    if (
      current === directory
      && (
        (metadata.mode & 0o077) !== 0
        || (
          typeof process.getuid === 'function'
          && metadata.uid !== process.getuid()
        )
      )
    ) {
      fail(
        'PRIVATE_ACTION_STORE_UNSAFE',
        'private action store must be current-user-owned with mode 0700 or stricter',
      );
    }
  }
  if (await realpath(directory) !== directory) {
    fail(
      'PRIVATE_ACTION_STORE_UNSAFE',
      'private action store must not resolve through a symlink or path alias',
    );
  }
  return directory;
}

async function readSecretFile(filename) {
  let handle;
  try {
    handle = await open(
      filename,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const metadata = await handle.stat();
    if (
      !metadata.isFile()
      || (metadata.mode & 0o777) !== 0o600
      || (
        typeof process.getuid === 'function'
        && metadata.uid !== process.getuid()
      )
    ) {
      fail(
        'PRIVATE_ACTION_STORE_UNSAFE',
        'private action record must be current-user-owned mode-0600 regular file',
      );
    }
    if (await realpath(filename) !== filename) {
      fail(
        'PRIVATE_ACTION_STORE_UNSAFE',
        'private action record must not resolve through a symlink or path alias',
      );
    }
    const bytes = await handle.readFile();
    if (bytes.length !== metadata.size) {
      fail(
        'PRIVATE_ACTION_STORE_UNSAFE',
        'private action record changed while it was being read',
      );
    }
    return bytes;
  } catch (error) {
    if (error instanceof V2PrivateActionStoreError) throw error;
    fail(
      'PRIVATE_ACTION_STORE_READ_FAILED',
      'private action record could not be read safely',
      { cause: error },
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function decodePersisted(bytes, expected) {
  let decoded;
  try {
    decoded = decodeV2PrivateActionRecord(bytes, {
      actionMaterialSha256: expected.actionMaterialSha256,
      expectedActionSequence: expected.expectedActionSequence,
      kind: expected.kind,
      operationId: expected.operationId,
    });
  } catch (error) {
    fail(
      error?.code ?? 'PRIVATE_ACTION_STORE_INVALID',
      error instanceof Error
        ? error.message
        : 'private action record decoding failed',
      { cause: error },
    );
  }
  if (
    expected.privateActionRecordSha256 !== undefined
    && decoded.recordSha256 !== expected.privateActionRecordSha256
  ) {
    fail(
      'PRIVATE_ACTION_RECORD_MISMATCH',
      'private action record hash differs from the durable operation binding',
    );
  }
  return Object.freeze({
    ...decoded,
    privateActionRecordSha256:
      Buffer.from(decoded.recordSha256, 'hex'),
  });
}

class V2PrivateActionStore {
  #directory;

  constructor(directory) {
    this.#directory = directory;
    PRIVATE_ACTION_STORE_BRAND.add(this);
    Object.freeze(this);
  }

  get directory() {
    return this.#directory;
  }

  async create(value) {
    exact(
      value,
      [
        'expectedActionSequence',
        'kind',
        'operationId',
        'output',
        'publicNullifier',
      ],
      'private action create',
    );
    await assertPrivateDirectory(this.#directory);
    const encoded = encodeV2PrivateActionRecord(value);
    const filename = operationPath(this.#directory, value.operationId);
    try {
      await createV2SecretFile(filename, encoded.bytes);
    } catch (error) {
      fail(
        error?.message === 'secret file already exists'
          ? 'PRIVATE_ACTION_RECORD_EXISTS'
          : 'PRIVATE_ACTION_STORE_WRITE_FAILED',
        error instanceof Error
          ? error.message
          : 'private action record creation failed',
        { cause: error },
      );
    }
    return decodePersisted(await readSecretFile(filename), {
      actionMaterialSha256:
        encoded.actionMaterialSha256.toString('hex'),
      expectedActionSequence: value.expectedActionSequence,
      kind: value.kind,
      operationId: value.operationId,
      privateActionRecordSha256: encoded.record.recordSha256,
    });
  }

  async replace(value) {
    exact(
      value,
      [
        'expectedActionSequence',
        'kind',
        'operationId',
        'output',
        'publicNullifier',
      ],
      'private action replacement',
    );
    await assertPrivateDirectory(this.#directory);
    const filename = operationPath(this.#directory, value.operationId);
    // Require an existing safe lineage, but deliberately do not require its
    // old hash: a crash after replacement and before SQLite rebase leaves the
    // new record ahead of the old DB commitment, and retry must remain safe.
    await readSecretFile(filename);
    const encoded = encodeV2PrivateActionRecord(value);
    const temporary = path.join(
      this.#directory,
      `.replace-${value.operationId.slice('v2op:'.length)}-${
        randomBytes(16).toString('hex')
      }.tmp`,
    );
    let published = false;
    try {
      await createV2SecretFile(temporary, encoded.bytes);
      await rename(temporary, filename);
      published = true;
      await syncDirectory(this.#directory);
    } catch (error) {
      fail(
        'PRIVATE_ACTION_STORE_WRITE_FAILED',
        error instanceof Error
          ? error.message
          : 'private action replacement failed',
        { cause: error },
      );
    } finally {
      if (!published) {
        await unlink(temporary).catch((error) => {
          if (error?.code !== 'ENOENT') throw error;
        });
      }
    }
    return decodePersisted(await readSecretFile(filename), {
      actionMaterialSha256:
        encoded.actionMaterialSha256.toString('hex'),
      expectedActionSequence: value.expectedActionSequence,
      kind: value.kind,
      operationId: value.operationId,
      privateActionRecordSha256: encoded.record.recordSha256,
    });
  }

  async load(value) {
    exact(
      value,
      [
        'actionMaterialSha256',
        'expectedActionSequence',
        'kind',
        'operationId',
        'privateActionRecordSha256',
      ],
      'private action load',
    );
    await assertPrivateDirectory(this.#directory);
    return decodePersisted(
      await readSecretFile(
        operationPath(this.#directory, value.operationId),
      ),
      value,
    );
  }
}

export async function createV2PrivateActionStore(value) {
  exact(value, ['directory'], 'private action store options');
  const directory = await assertPrivateDirectory(value.directory);
  return new V2PrivateActionStore(directory);
}

export function assertV2PrivateActionStore(value) {
  if (
    !PRIVATE_ACTION_STORE_BRAND.has(value)
    || typeof value.create !== 'function'
    || typeof value.replace !== 'function'
    || typeof value.load !== 'function'
  ) {
    fail(
      'PRIVATE_ACTION_STORE_REQUIRED',
      'a sealed private action record store is required',
    );
  }
  return value;
}
