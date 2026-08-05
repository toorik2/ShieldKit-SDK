import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  constructDirectV2Output,
  deriveDirectV2Address,
} from '../../action/v2/notes.mjs';
import {
  assertV2PrivateActionStore,
  createV2PrivateActionStore,
  V2PrivateActionStoreError,
} from './private-action-store.mjs';
import { encodeV2PrivateActionRecord } from './private-action-record.mjs';

const fr = (value) => BigInt(value).toString(16).padStart(64, '0');
const PROFILE_ID = '11'.repeat(32);
const INSTANCE_ID = '22'.repeat(32);
const PUBLIC_NULLIFIER = '33'.repeat(32);
const FIXTURE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
);
const USER_NAMESPACE_ARGUMENTS = Object.freeze([
  '--map-users=0:1000:1',
  '--map-users=1:100000:65536',
  '--map-groups=0:1000:1',
  '--map-groups=1:100000:65536',
]);

const rejectCode = (code) => (error) =>
  error instanceof V2PrivateActionStoreError && error.code === code;

function namespaceChown(target, ownership) {
  assert.equal(path.isAbsolute(target), true, 'ownership target must be absolute');
  assert.equal(path.normalize(target), target, 'ownership target must be normalized');
  assert.equal(typeof process.getuid, 'function', 'Linux getuid support is required');
  assert.equal(typeof process.getgid, 'function', 'Linux getgid support is required');
  assert.equal(process.getuid(), 1000, 'qualification user namespace expects outer uid 1000');
  assert.equal(process.getgid(), 1000, 'qualification user namespace expects outer gid 1000');
  const result = spawnSync('/usr/bin/unshare', [
    ...USER_NAMESPACE_ARGUMENTS,
    '--',
    '/usr/bin/chown',
    ownership,
    target,
  ], {
    encoding: 'utf8',
    shell: false,
  });
  assert.ifError(result.error);
  assert.equal(
    result.status,
    0,
    `user-namespace chown failed: ${result.stderr || result.stdout || result.signal}`,
  );
}

function fixedRng() {
  let next = 5n;
  return {
    bytes(length) {
      assert.equal(length, 32);
      const bytes = Buffer.from(fr(next), 'hex');
      next += 1n;
      return Uint8Array.from(bytes);
    },
  };
}

function output(sequence) {
  const address = deriveDirectV2Address({
    networkId: 2,
    profileId: PROFILE_ID,
    instanceId: INSTANCE_ID,
    spendSecret: fr(3),
    incomingViewSecret: fr(4),
  });
  return constructDirectV2Output({
    address,
    postActionSequence: String(sequence + 1),
    rng: fixedRng(),
  });
}

function operationId(value) {
  return `v2op:${BigInt(value).toString(16).padStart(64, '0')}`;
}

function material(kind, sequence = 41, operation = operationId(sequence + 1)) {
  return {
    operationId: operation,
    expectedActionSequence: sequence,
    kind,
    output: kind === 'withdrawal' ? null : output(sequence),
    publicNullifier: kind === 'deposit' ? null : PUBLIC_NULLIFIER,
  };
}

function binding(encoded) {
  return {
    operationId: encoded.record.operationId,
    expectedActionSequence: encoded.record.expectedActionSequence,
    kind: encoded.record.kind,
    actionMaterialSha256: encoded.record.actionMaterialSha256,
    privateActionRecordSha256: encoded.record.recordSha256,
  };
}

function filename(directory, operation) {
  return path.join(directory, `${operation.slice('v2op:'.length)}.json`);
}

async function privateDirectory(t) {
  // /tmp is world-writable and correctly rejected by the store's ancestry
  // validation. Keep the real-FS fixture under this isolated worktree instead.
  const directory = await mkdtemp(path.join(FIXTURE_ROOT, '.private-action-store-'));
  await chmod(directory, 0o700);
  t.after(async () => {
    await rm(directory, { recursive: true, force: true });
  });
  return directory;
}

async function storeFixture(t) {
  const directory = await privateDirectory(t);
  return {
    directory,
    store: await createV2PrivateActionStore({ directory }),
  };
}

test('creates, loads, and replaces canonical private actions using real durable files', async (t) => {
  const { directory, store } = await storeFixture(t);
  assertV2PrivateActionStore(store);
  assert.equal(store.directory, directory);
  assert.equal((await lstat(directory)).mode & 0o777, 0o700);

  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const input = material(kind, 40 + ['deposit', 'transfer', 'withdrawal'].indexOf(kind));
    const encoded = encodeV2PrivateActionRecord(input);
    const created = await store.create(input);
    const pathOnDisk = filename(directory, input.operationId);
    assert.equal((await lstat(pathOnDisk)).isFile(), true);
    assert.equal((await lstat(pathOnDisk)).mode & 0o777, 0o600);
    assert.deepEqual(await readFile(pathOnDisk), encoded.bytes, `${kind} canonical bytes`);
    assert.equal(created.recordSha256, encoded.record.recordSha256);
    assert.deepEqual(created.privateActionRecordSha256, Buffer.from(created.recordSha256, 'hex'));
    assert.deepEqual(await store.load(binding(encoded)), created);
  }
});

test('refuses overwrite and retains the original canonical private action', async (t) => {
  const { directory, store } = await storeFixture(t);
  const input = material('transfer');
  const encoded = encodeV2PrivateActionRecord(input);
  await store.create(input);
  const before = await readFile(filename(directory, input.operationId));
  await assert.rejects(
    store.create(input),
    rejectCode('PRIVATE_ACTION_RECORD_EXISTS'),
  );
  assert.deepEqual(await readFile(filename(directory, input.operationId)), before);
  assert.deepEqual(await store.load(binding(encoded)), await store.load(binding(encoded)));
});

test('replacement is retry-safe across a durable-file/old-DB-hash crash window', async (t) => {
  const { directory, store } = await storeFixture(t);
  const operation = operationId(900);
  const oldInput = material('transfer', 41, operation);
  const newInput = material('transfer', 42, operation);
  const oldEncoded = encodeV2PrivateActionRecord(oldInput);
  const newEncoded = encodeV2PrivateActionRecord(newInput);
  await store.create(oldInput);

  const replaced = await store.replace(newInput);
  assert.deepEqual(
    await readFile(filename(directory, operation)),
    newEncoded.bytes,
    'replacement published the new canonical record',
  );
  await assert.rejects(
    store.load(binding(oldEncoded)),
    rejectCode('PRIVATE_ACTION_RECORD_MISMATCH'),
    'the stale DB record hash must not authorize the replacement',
  );
  assert.deepEqual(await store.load(binding(newEncoded)), replaced);

  const retried = await store.replace(newInput);
  assert.equal(retried.recordSha256, newEncoded.record.recordSha256);
  assert.deepEqual(await store.load(binding(newEncoded)), retried);
});

test('binds persisted bytes to the exact operation, kind, sequence, action hash, and DB record hash', async (t) => {
  const { directory, store } = await storeFixture(t);
  const input = material('transfer');
  const encoded = encodeV2PrivateActionRecord(input);
  await store.create(input);

  for (const [label, changed] of [
    ['kind', { ...binding(encoded), kind: 'deposit' }],
    ['sequence', { ...binding(encoded), expectedActionSequence: input.expectedActionSequence + 1 }],
    ['action hash', { ...binding(encoded), actionMaterialSha256: '44'.repeat(32) }],
    ['record hash', { ...binding(encoded), privateActionRecordSha256: '55'.repeat(32) }],
  ]) {
    await assert.rejects(
      store.load(changed),
      rejectCode('PRIVATE_ACTION_RECORD_MISMATCH'),
      label,
    );
  }

  const other = material('deposit', 42);
  const otherEncoded = encodeV2PrivateActionRecord(other);
  await store.create(other);
  const primaryPath = filename(directory, input.operationId);
  await unlink(primaryPath);
  await writeFile(primaryPath, otherEncoded.bytes, { mode: 0o600 });
  await chmod(primaryPath, 0o600);
  await assert.rejects(
    store.load(binding(encoded)),
    rejectCode('PRIVATE_ACTION_RECORD_MISMATCH'),
    'an operation record substituted into another operation filename',
  );
});

test('rejects missing, corrupt, truncated, symlinked, and non-0600 private action files', async (t) => {
  const { directory, store } = await storeFixture(t);
  const input = material('deposit');
  const encoded = encodeV2PrivateActionRecord(input);
  const pathOnDisk = filename(directory, input.operationId);
  await assert.rejects(
    store.load(binding(encoded)),
    rejectCode('PRIVATE_ACTION_STORE_READ_FAILED'),
    'missing record',
  );

  await store.create(input);
  for (const [label, bytes] of [
    ['corrupt record', Buffer.from('{not-json', 'utf8')],
    ['truncated record', encoded.bytes.subarray(0, encoded.bytes.length - 1)],
  ]) {
    await writeFile(pathOnDisk, bytes);
    await chmod(pathOnDisk, 0o600);
    await assert.rejects(
      store.load(binding(encoded)),
      rejectCode('PRIVATE_ACTION_RECORD_INVALID'),
      label,
    );
  }

  await writeFile(pathOnDisk, encoded.bytes);
  await chmod(pathOnDisk, 0o644);
  await assert.rejects(
    store.load(binding(encoded)),
    rejectCode('PRIVATE_ACTION_STORE_UNSAFE'),
    'non-0600 record',
  );

  const target = path.join(directory, 'symlink-target.json');
  await writeFile(target, encoded.bytes, { mode: 0o600 });
  await chmod(target, 0o600);
  await unlink(pathOnDisk);
  await symlink(target, pathOnDisk);
  await assert.rejects(
    store.load(binding(encoded)),
    rejectCode('PRIVATE_ACTION_STORE_READ_FAILED'),
    'symlinked record',
  );
});

test('rejects symlink, regular-file, loose-mode, and writable-ancestor store directories', async (t) => {
  const root = await privateDirectory(t);
  const safe = path.join(root, 'safe');
  await mkdir(safe, { mode: 0o700 });
  await chmod(safe, 0o700);
  const link = path.join(root, 'safe-link');
  await symlink(safe, link);
  await assert.rejects(
    createV2PrivateActionStore({ directory: link }),
    rejectCode('PRIVATE_ACTION_STORE_UNSAFE'),
  );

  const regular = path.join(root, 'not-a-directory');
  await writeFile(regular, 'not a directory', { mode: 0o600 });
  await chmod(regular, 0o600);
  await assert.rejects(
    createV2PrivateActionStore({ directory: regular }),
    rejectCode('PRIVATE_ACTION_STORE_UNSAFE'),
  );

  const loose = path.join(root, 'loose');
  await mkdir(loose, { mode: 0o700 });
  await chmod(loose, 0o755);
  await assert.rejects(
    createV2PrivateActionStore({ directory: loose }),
    rejectCode('PRIVATE_ACTION_STORE_UNSAFE'),
  );

  const writableAncestor = path.join(root, 'writable-ancestor');
  const nested = path.join(writableAncestor, 'store');
  await mkdir(nested, { recursive: true, mode: 0o700 });
  await chmod(writableAncestor, 0o722);
  await chmod(nested, 0o700);
  await assert.rejects(
    createV2PrivateActionStore({ directory: nested }),
    rejectCode('PRIVATE_ACTION_STORE_UNSAFE'),
  );
});

test('rejects a genuinely foreign-owned store directory', async (t) => {
  const directory = await privateDirectory(t);
  let ownershipChanged = false;
  try {
    // Inner uid/gid 1 maps to outer uid/gid 100000, while inner 0 maps back
    // to this test process's outer uid/gid 1000.
    namespaceChown(directory, '1:1');
    ownershipChanged = true;
    const foreign = await lstat(directory);
    assert.equal(foreign.uid, 100000);
    assert.equal(foreign.gid, 100000);
    await assert.rejects(
      createV2PrivateActionStore({ directory }),
      rejectCode('PRIVATE_ACTION_STORE_UNSAFE'),
    );
  } finally {
    if (ownershipChanged) namespaceChown(directory, '0:0');
  }
  assert.equal((await lstat(directory)).uid, process.getuid());
  assert.equal((await lstat(directory)).gid, process.getgid());
});

test('requires the sealed private-action-store brand', async (t) => {
  const { store } = await storeFixture(t);
  assert.strictEqual(assertV2PrivateActionStore(store), store);
  assert.throws(
    () => assertV2PrivateActionStore({
      create: async () => undefined,
      replace: async () => undefined,
      load: async () => undefined,
    }),
    rejectCode('PRIVATE_ACTION_STORE_REQUIRED'),
  );
  assert.throws(
    () => assertV2PrivateActionStore(null),
    rejectCode('PRIVATE_ACTION_STORE_REQUIRED'),
  );
});
