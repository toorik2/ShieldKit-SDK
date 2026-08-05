import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test, { after, before } from 'node:test';

import {
  authenticateNativeRecoverySnapshotStream,
  nativeRecoveryResultToStoreInstall,
  NativeRecoveryError,
  runNativeRecovery,
  scanNativeRecoveryStream,
} from './recovery-native.mjs';
import {
  parseV2RecoveryScannerArtifact,
  RECOVERY_SCANNER_LINUX_X64_FILENAME,
  RECOVERY_SCANNER_MANIFEST_FILENAME,
} from '../../profile/v2/recovery-scanner-artifact.mjs';
import {
  buildV2RecoveryScanner,
  PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN,
} from '../../../scripts/v2-build-recovery-scanner.mjs';

const crate = resolve(
  import.meta.dirname,
  '../../../crates/shieldkit-v2-recovery',
);
const workspaceRoot = resolve(crate, '../..');
const buildOutputRelative = join(
  '.tmp',
  `recovery-native-test-${process.pid}-${randomBytes(12).toString('hex')}`,
);
const buildOutput = join(workspaceRoot, buildOutputRelative);
let binaryPath;
let attestedBinarySha256;

function sameSourceIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
    && left.mode === right.mode;
}

async function stableSourceFile(filename, relativePath) {
  const before = await lstat(filename, { bigint: true });
  if (
    !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1n
    || await realpath(filename) !== filename
  ) {
    throw new Error(
      `recovery scanner source must be one canonical regular file: ${
        relativePath
      }`,
    );
  }
  const data = await readFile(filename);
  const after = await lstat(filename, { bigint: true });
  if (!sameSourceIdentity(before, after)) {
    throw new Error(
      `recovery scanner source changed while being read: ${relativePath}`,
    );
  }
  return Object.freeze({
    path: relativePath,
    bytes: data.length,
    sha256: createHash('sha256').update(data).digest('hex'),
  });
}

async function sourceTreePin() {
  const files = [];
  async function walk(directory, prefix) {
    const entries = (await readdir(directory, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const filename = join(directory, entry.name);
      const relativePath = prefix.length === 0
        ? entry.name
        : `${prefix}/${entry.name}`;
      if (entry.isSymbolicLink()) {
        throw new Error(
          `recovery scanner source tree contains a symlink: ${relativePath}`,
        );
      }
      if (entry.isDirectory()) {
        await walk(filename, relativePath);
      } else if (entry.isFile()) {
        files.push(await stableSourceFile(filename, relativePath));
      } else {
        throw new Error(
          `recovery scanner source tree contains a special file: ${
            relativePath
          }`,
        );
      }
    }
  }
  for (const name of ['Cargo.lock', 'Cargo.toml']) {
    files.push(await stableSourceFile(join(crate, name), name));
  }
  for (const name of ['src', 'tests']) {
    await walk(join(crate, name), name);
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  return createHash('sha256')
    .update('ShieldKit V2 recovery scanner source tree test pin v1\0')
    .update(JSON.stringify(files))
    .digest('hex');
}

async function buildBinary() {
  assert.equal(
    process.env.SHIELDKIT_V2_RECOVERY_BINARY,
    undefined,
    'portable native recovery tests refuse prebuilt binary substitution',
  );
  await mkdir(join(workspaceRoot, '.tmp'), {
    recursive: true,
    mode: 0o700,
  });
  const beforeSourceTree = await sourceTreePin();
  const built = await buildV2RecoveryScanner({
    workspaceRoot,
    output: buildOutputRelative,
    allowDevelopmentOnly: true,
  });
  assert.equal(
    await sourceTreePin(),
    beforeSourceTree,
    'recovery scanner source tree changed across its fresh build',
  );
  const manifestPath = join(
    built.output,
    RECOVERY_SCANNER_MANIFEST_FILENAME,
  );
  const parsed = parseV2RecoveryScannerArtifact(
    await readFile(manifestPath),
  );
  assert.equal(
    parsed.manifest.rustcVersion.startsWith(
      `rustc ${PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN}`,
    ),
    true,
  );
  assert.equal(
    parsed.manifest.cargoVersion.startsWith(
      `cargo ${PINNED_RECOVERY_SCANNER_RUST_TOOLCHAIN}`,
    ),
    true,
  );
  binaryPath = join(
    built.output,
    RECOVERY_SCANNER_LINUX_X64_FILENAME,
  );
  const binary = await readFile(binaryPath);
  assert.equal(binary.length, parsed.manifest.binaryBytes);
  assert.equal(
    createHash('sha256').update(binary).digest('hex'),
    parsed.manifest.binarySha256,
  );
  attestedBinarySha256 = parsed.manifest.binarySha256;
}

before(buildBinary);
after(async () => {
  await rm(buildOutput, { recursive: true, force: true });
});

async function binaryPin() {
  await access(binaryPath);
  const metadata = await lstat(binaryPath);
  assert.equal(metadata.isFile(), true, [
    'Build the native scanner before this Node test:',
    'cargo +1.97.1 build --locked',
  ].join(' '));
  const current = createHash('sha256')
    .update(await readFile(binaryPath))
    .digest('hex');
  assert.equal(
    current,
    attestedBinarySha256,
    'fresh recovery scanner binary changed after attestation',
  );
  return current;
}

const u32le = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};

const u64le = (value) => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes;
};

function p2pkh(byte) {
  return Buffer.from([
    0x76, 0xa9, 0x14, ...Array(20).fill(byte), 0x88, 0xac,
  ]);
}

function output(value, contents) {
  assert.ok(contents.length < 0xfd);
  return Buffer.concat([u64le(value), Buffer.from([contents.length]), contents]);
}

function genesisOnlyRequest() {
  const profileId = '11'.repeat(32);
  const instance = Buffer.from(
    '000102030405060708090a0b0c0d0e0f'
    + '101112131415161718191a1b1c1d1e1f',
    'hex',
  );
  const state = Buffer.alloc(128);
  state.write('SKS2', 0, 'ascii');
  Buffer.from(profileId, 'hex').copy(state, 4);
  Buffer.from(
    '1b5e3c7f6833e4d1b8f321410d27dcbe'
    + '695474e9a98c25f8976af85378a32c98',
    'hex',
  ).copy(state, 36);
  Buffer.from(
    '1bffbaa6bb28b38e9d7fe374d9b7ba4d'
    + 'f4bb661c8b16aecb4ffe68a22301e6ec',
    'hex',
  ).copy(state, 68);
  state.writeUInt32LE(8, 108);
  const stateTokenPrefix = Buffer.concat([
    Buffer.from([0xef]),
    instance,
    Buffer.from([0x61, 0x80]),
    state,
  ]);
  assert.equal(stateTokenPrefix.length, 163);
  const inputs = Buffer.concat([
    Buffer.from([1]),
    instance,
    u32le(7),
    Buffer.from([1, 0x51]),
    u32le(0xffff_ffff),
  ]);
  const outputs = Buffer.concat([
    Buffer.from([4]),
    output(2_000, Buffer.concat([stateTokenPrefix, Buffer.from([0x52, 0x21, 0x02])])),
    output(1_000, Buffer.from([0x51, 0])),
    output(1_500, Buffer.from([0x53, 0x21])),
    output(7_000, p2pkh(0x20)),
  ]);
  const raw = Buffer.concat([u32le(2), inputs, outputs, u32le(0)]);
  const digest = createHash('sha256')
    .update(createHash('sha256').update(raw).digest())
    .digest();
  const transactionId = Buffer.from(digest).reverse().toString('hex');
  const blockHash = '64'.padStart(64, '0');
  return {
    schema: 'shieldkit-v2-recovery-scan-v2',
    networkId: 2,
    profileId,
    instanceId: instance.toString('hex'),
    denominationSats: '10000000',
    carrierCount: 1,
    runtimeMaterialsSha256: 'a5'.repeat(32),
    genesis: {
      transactionId,
      rawTransaction: raw.toString('hex'),
      height: 100,
      blockHash,
    },
    genesisOutpoint: { transactionId, outputIndex: 0 },
    initialStateHex: state.toString('hex'),
    actions: [],
    fundingPrevouts: [],
    expectedTip: {
      transactionId,
      outputIndex: 0,
      height: 100,
      blockHash,
    },
  };
}

function materialFixture() {
  const request = genesisOnlyRequest();
  return {
    schema: 'shieldkit-v2-recovery-authenticated-material-v2',
    contentSha256: 'ab'.repeat(32),
    binding: {
      profileId: request.profileId,
      instanceId: request.instanceId,
      networkId: request.networkId,
      denominationSats: request.denominationSats,
      carrierCount: request.carrierCount,
      runtimeMaterialsSha256: request.runtimeMaterialsSha256,
    },
    canonical: {
      state: request.initialStateHex,
      outpoint: {
        txid: request.expectedTip.transactionId,
        vout: request.expectedTip.outputIndex,
      },
      actionSequence: 0,
      height: request.expectedTip.height,
      blockHash: request.expectedTip.blockHash,
    },
    noteNodes: [{
      depth: 32,
      nodeIndex: 0,
      nodeHash: request.initialStateHex.slice(72, 136),
    }],
    noteFrontier: [],
    noteLeaves: [],
    nullifierNodes: [{
      depth: 32,
      nodeIndex: 0,
      nodeHash: request.initialStateHex.slice(136, 200),
    }],
    nullifierLeaves: [{
      physicalIndex: 0,
      leafType: 1,
      leafHash: '01'.repeat(32),
      key: '00'.repeat(32),
      successorIndex: 1,
      successorKey: '00'.repeat(32),
    }, {
      physicalIndex: 1,
      leafType: 3,
      leafHash: '02'.repeat(32),
      key: '00'.repeat(32),
      successorIndex: 1,
      successorKey: '00'.repeat(32),
    }],
  };
}

function scanResultFixture(material = materialFixture()) {
  const request = genesisOnlyRequest();
  return {
    schema: 'shieldkit-v2-recovery-scan-result-v2',
    snapshot: {
      schema: 'shieldkit-v2-recovery-snapshot-v2',
      version: 2,
      networkId: request.networkId,
      profileId: request.profileId,
      instanceId: request.instanceId,
      denominationSats: request.denominationSats,
      carrierCount: request.carrierCount,
      runtimeMaterialsSha256: request.runtimeMaterialsSha256,
      poseidonProfile: 'shieldkit-pool-action-v2-direct-poseidon-v1',
      genesis: {},
      tip: {},
      actionCount: '0',
      historySha256: 'cd'.repeat(32),
      stateHex: request.initialStateHex,
      noteTree: {},
      nullifierTree: {},
      actions: [],
      externalAuthenticationBoundary: 'externally authenticated',
      contentSha256: material.contentSha256,
    },
    material,
  };
}

function compactSnapshotForStream(snapshot) {
  return {
    schema: snapshot.schema,
    version: snapshot.version,
    networkId: snapshot.networkId,
    profileId: snapshot.profileId,
    instanceId: snapshot.instanceId,
    denominationSats: snapshot.denominationSats,
    carrierCount: snapshot.carrierCount,
    runtimeMaterialsSha256: snapshot.runtimeMaterialsSha256,
    poseidonProfile: snapshot.poseidonProfile,
    genesis: snapshot.genesis,
    tip: snapshot.tip,
    actionCount: snapshot.actionCount,
    historySha256: snapshot.historySha256,
    stateHex: snapshot.stateHex,
    noteTree: {
      depth: snapshot.noteTree.depth,
      count: snapshot.noteTree.count,
      root: snapshot.noteTree.root,
    },
    nullifierTree: {
      depth: snapshot.nullifierTree.depth,
      count: snapshot.nullifierTree.count,
      root: snapshot.nullifierTree.root,
    },
    externalAuthenticationBoundary: snapshot.externalAuthenticationBoundary,
    contentSha256: snapshot.contentSha256,
  };
}

const clone = (value) => structuredClone(value);

const streamMagic = Buffer.from('SKR2F001', 'ascii');

function framedJson(value) {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  const framed = Buffer.alloc(4 + payload.length);
  framed.writeUInt32BE(payload.length, 0);
  payload.copy(framed, 4);
  return framed;
}

function emptyStreamInput(request) {
  const {
    actions: _actions,
    fundingPrevouts: _fundingPrevouts,
    schema: _schema,
    ...requestHeader
  } = request;
  const header = framedJson({
    schema: 'shieldkit-v2-recovery-stream-input-v2',
    type: 'header',
    actionCount: '0',
    request: requestHeader,
  });
  const digest = createHash('sha256')
    .update(Buffer.from(
      'ShieldKit V2 recovery stream input v2\0',
      'utf8',
    ))
    .update(header)
    .digest('hex');
  return Buffer.concat([
    streamMagic,
    header,
    framedJson({
      schema: 'shieldkit-v2-recovery-stream-input-v2',
      type: 'end',
      actionCount: '0',
      frameCount: '1',
      digest,
    }),
  ]);
}

async function rawStreamResult(request) {
  return new Promise((resolveRaw, rejectRaw) => {
    const child = spawn(binaryPath, ['scan-stream'], {
      cwd: crate,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', rejectRaw);
    child.once('close', (code) => {
      if (code === 0) {
        resolveRaw(Buffer.concat(stdout));
      } else {
        rejectRaw(new Error(Buffer.concat(stderr).toString('utf8')));
      }
    });
    child.stdin.end(emptyStreamInput(request));
  });
}

function splitFramed(bytes) {
  assert.deepEqual(bytes.subarray(0, 8), streamMagic);
  const frames = [];
  let offset = 8;
  while (offset < bytes.length) {
    const length = bytes.readUInt32BE(offset);
    const end = offset + 4 + length;
    assert.ok(end <= bytes.length);
    frames.push({
      bytes: bytes.subarray(offset, end),
      value: JSON.parse(bytes.subarray(offset + 4, end).toString('utf8')),
    });
    offset = end;
  }
  assert.equal(offset, bytes.length);
  return frames;
}

async function fakeStreamBinary(directory, name, output, chunkSize = 64) {
  const path = join(directory, name);
  const source = [
    '#!/usr/bin/env node',
    `const output = Buffer.from(${JSON.stringify(output.toString('base64'))}, 'base64');`,
    `const chunkSize = ${chunkSize};`,
    'process.stdin.resume();',
    'process.stdin.once("end", async () => {',
    '  for (let offset = 0; offset < output.length; offset += chunkSize) {',
    '    if (!process.stdout.write(output.subarray(offset, offset + chunkSize))) {',
    '      await new Promise((resolve) => process.stdout.once("drain", resolve));',
    '    }',
    '  }',
    '});',
    '',
  ].join('\n');
  await writeFile(path, source, { mode: 0o700 });
  await chmod(path, 0o700);
  return {
    path,
    pin: createHash('sha256').update(await readFile(path)).digest('hex'),
  };
}

test('executes the exact pinned Rust scanner and adapts empty raw/authenticated material', async () => {
  const binarySha256 = await binaryPin();
  const request = genesisOnlyRequest();
  const scanResult = await runNativeRecovery({
    binaryPath,
    binarySha256,
    command: 'scan',
    request,
    timeoutMs: 10_000,
  });
  assert.equal(scanResult.schema, 'shieldkit-v2-recovery-scan-result-v2');
  const { snapshot, material } = scanResult;
  assert.equal(snapshot.schema, 'shieldkit-v2-recovery-snapshot-v2');
  assert.equal(snapshot.actionCount, '0');
  assert.equal(snapshot.noteTree.count, '0');
  assert.equal(snapshot.nullifierTree.count, '0');
  assert.match(snapshot.contentSha256, /^[0-9a-f]{64}$/);
  assert.equal(
    material.schema,
    'shieldkit-v2-recovery-authenticated-material-v2',
  );
  assert.equal(material.contentSha256, snapshot.contentSha256);
  assert.equal(material.noteNodes.length, 1);
  assert.deepEqual(material.noteFrontier, []);
  assert.deepEqual(material.noteLeaves, []);
  assert.equal(material.nullifierLeaves.length, 2);
  const rawInstall = nativeRecoveryResultToStoreInstall(scanResult);
  assert.deepEqual(Object.keys(rawInstall), [
    'binding',
    'canonical',
    'noteNodes',
    'noteFrontier',
    'noteLeaves',
    'nullifierNodes',
    'nullifierLeaves',
    'crashAt',
  ]);
  assert.equal(Buffer.isBuffer(rawInstall.binding.profileId), true);
  assert.equal(Buffer.isBuffer(rawInstall.binding.instanceId), true);
  assert.equal(Buffer.isBuffer(rawInstall.canonical.state), true);
  assert.equal(Buffer.isBuffer(rawInstall.canonical.outpoint.txid), true);
  assert.equal(Buffer.isBuffer(rawInstall.canonical.blockHash), true);
  assert.equal(Buffer.isBuffer(rawInstall.noteNodes[0].nodeHash), true);
  assert.equal(
    Buffer.isBuffer(rawInstall.nullifierLeaves[0].successorKey),
    true,
  );
  assert.equal(rawInstall.crashAt, null);
  const authenticated = await runNativeRecovery({
    binaryPath,
    binarySha256,
    command: 'authenticate-snapshot',
    request: {
      schema: 'shieldkit-v2-recovery-authenticate-snapshot-v2',
      networkId: snapshot.networkId,
      profileId: snapshot.profileId,
      instanceId: snapshot.instanceId,
      denominationSats: snapshot.denominationSats,
      carrierCount: snapshot.carrierCount,
      runtimeMaterialsSha256: snapshot.runtimeMaterialsSha256,
      genesis: snapshot.genesis,
      tip: snapshot.tip,
      snapshot,
    },
    timeoutMs: 10_000,
  });
  assert.deepEqual(authenticated, material);
  assert.deepEqual(
    nativeRecoveryResultToStoreInstall(authenticated),
    rawInstall,
  );
  const verified = await runNativeRecovery({
    binaryPath,
    binarySha256,
    command: 'verify-snapshot',
    request: {
      schema: 'shieldkit-v2-recovery-verify-v2',
      scan: request,
      snapshot,
    },
    timeoutMs: 10_000,
  });
  assert.deepEqual(verified, snapshot);

  await assert.rejects(
    runNativeRecovery({
      binaryPath,
      binarySha256,
      command: 'scan',
      request: {},
      timeoutMs: 10_000,
    }),
    (error) => (
      error instanceof NativeRecoveryError
      && /missing field|scan request schema/i.test(error.message)
    ),
  );
});

test('streams pinned raw recovery without monolithic input or output arrays', async () => {
  const binarySha256 = await binaryPin();
  const request = genesisOnlyRequest();
  const monolithic = await runNativeRecovery({
    binaryPath,
    binarySha256,
    command: 'scan',
    request,
    timeoutMs: 10_000,
  });
  const expected = nativeRecoveryResultToStoreInstall(monolithic);
  const {
    actions: _actions,
    fundingPrevouts: _fundingPrevouts,
    schema: _schema,
    ...requestHeader
  } = request;
  const frames = [];
  for await (const frame of scanNativeRecoveryStream({
    binaryPath,
    binarySha256,
    requestHeader,
    actionCount: 0,
    steps: (async function* noSteps() {})(),
    timeoutMs: 10_000,
  })) {
    frames.push(frame);
  }
  assert.equal(frames[0].type, 'header');
  assert.equal(frames[1].type, 'snapshot');
  assert.equal(frames.at(-1).type, 'end');
  assert.deepEqual(frames[0].counts, frames.at(-1).counts);
  assert.equal(frames[0].counts.action, 0);
  assert.equal(frames[0].counts.noteLeaf, 0);
  assert.equal(frames[0].counts.nullifierLeaf, 2);
  assert.equal(
    frames[1].material.contentSha256,
    monolithic.material.contentSha256,
  );
  const streamed = {
    binding: frames[1].material.binding,
    canonical: frames[1].material.canonical,
    noteNodes: frames
      .filter(({ type }) => type === 'note-node')
      .map(({ value }) => value),
    noteFrontier: frames
      .filter(({ type }) => type === 'note-frontier')
      .map(({ value }) => value),
    noteLeaves: frames
      .filter(({ type }) => type === 'note-leaf')
      .map(({ value }) => value),
    nullifierNodes: frames
      .filter(({ type }) => type === 'nullifier-node')
      .map(({ value }) => value),
    nullifierLeaves: frames
      .filter(({ type }) => type === 'nullifier-leaf')
      .map(({ value }) => value),
    crashAt: null,
  };
  assert.deepEqual(streamed, expected);
  assert.equal(
    frames.at(-1).frameCount,
    frames.length - 1,
  );
});

test('streams pinned compact snapshot authentication with monolithic-equivalent material', async () => {
  const binarySha256 = await binaryPin();
  const scanRequest = genesisOnlyRequest();
  const scanResult = await runNativeRecovery({
    binaryPath,
    binarySha256,
    command: 'scan',
    request: scanRequest,
    timeoutMs: 10_000,
  });
  const snapshot = scanResult.snapshot;
  const monolithic = await runNativeRecovery({
    binaryPath,
    binarySha256,
    command: 'authenticate-snapshot',
    request: {
      schema: 'shieldkit-v2-recovery-authenticate-snapshot-v2',
      networkId: snapshot.networkId,
      profileId: snapshot.profileId,
      instanceId: snapshot.instanceId,
      denominationSats: snapshot.denominationSats,
      carrierCount: snapshot.carrierCount,
      runtimeMaterialsSha256: snapshot.runtimeMaterialsSha256,
      genesis: snapshot.genesis,
      tip: snapshot.tip,
      snapshot,
    },
    timeoutMs: 10_000,
  });
  const expected = nativeRecoveryResultToStoreInstall(monolithic);
  const frames = [];
  for await (const frame of authenticateNativeRecoverySnapshotStream({
    binaryPath,
    binarySha256,
    requestHeader: {
      networkId: snapshot.networkId,
      profileId: snapshot.profileId,
      instanceId: snapshot.instanceId,
      denominationSats: snapshot.denominationSats,
      carrierCount: snapshot.carrierCount,
      runtimeMaterialsSha256: snapshot.runtimeMaterialsSha256,
      genesis: snapshot.genesis,
      tip: snapshot.tip,
      snapshot: compactSnapshotForStream(snapshot),
    },
    actionCount: 0,
    actions: [],
    timeoutMs: 10_000,
  })) {
    frames.push(frame);
  }
  assert.equal(frames[0].type, 'header');
  assert.equal(frames[1].type, 'snapshot');
  assert.equal(frames.at(-1).type, 'end');
  assert.equal(
    frames[1].material.contentSha256,
    monolithic.contentSha256,
  );
  assert.deepEqual({
    binding: frames[1].material.binding,
    canonical: frames[1].material.canonical,
    noteNodes: frames
      .filter(({ type }) => type === 'note-node')
      .map(({ value }) => value),
    noteFrontier: frames
      .filter(({ type }) => type === 'note-frontier')
      .map(({ value }) => value),
    noteLeaves: frames
      .filter(({ type }) => type === 'note-leaf')
      .map(({ value }) => value),
    nullifierNodes: frames
      .filter(({ type }) => type === 'nullifier-node')
      .map(({ value }) => value),
    nullifierLeaves: frames
      .filter(({ type }) => type === 'nullifier-leaf')
      .map(({ value }) => value),
    crashAt: null,
  }, expected);
  await assert.rejects(
    async () => {
      for await (const _frame of authenticateNativeRecoverySnapshotStream({
        binaryPath,
        binarySha256,
        requestHeader: {
          networkId: snapshot.networkId,
          profileId: snapshot.profileId,
          instanceId: snapshot.instanceId,
          denominationSats: snapshot.denominationSats,
          carrierCount: snapshot.carrierCount,
          runtimeMaterialsSha256: '5a'.repeat(32),
          genesis: snapshot.genesis,
          tip: snapshot.tip,
          snapshot: compactSnapshotForStream(snapshot),
        },
        actionCount: 0,
        actions: [],
        timeoutMs: 10_000,
      })) {
        // The preflight validator must fail before yielding a frame.
      }
    },
    /runtimeMaterialsSha256 differs/,
  );
  await assert.rejects(
    async () => {
      for await (const _frame of authenticateNativeRecoverySnapshotStream({
        binaryPath,
        binarySha256: '00'.repeat(32),
        requestHeader: {
          networkId: snapshot.networkId,
          profileId: snapshot.profileId,
          instanceId: snapshot.instanceId,
          denominationSats: snapshot.denominationSats,
          carrierCount: snapshot.carrierCount,
          runtimeMaterialsSha256: snapshot.runtimeMaterialsSha256,
          genesis: snapshot.genesis,
          tip: snapshot.tip,
          snapshot: compactSnapshotForStream(snapshot),
        },
        actionCount: 0,
        actions: [],
      })) {
        // A pin mismatch must fail before the first provisional frame.
      }
    },
    /SHA-256 pin mismatch/,
  );
});

test('stream wrapper rejects truncated, duplicated, digest-mismatched, and trailing output', async (t) => {
  const request = genesisOnlyRequest();
  const raw = await rawStreamResult(request);
  const directory = await mkdtemp(join(
    import.meta.dirname,
    '.recovery-stream-wrapper-',
  ));
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(directory, { recursive: true });
  });
  const {
    actions: _actions,
    fundingPrevouts: _fundingPrevouts,
    schema: _schema,
    ...requestHeader
  } = request;
  const invoke = async (binary) => {
    const frames = [];
    for await (const frame of scanNativeRecoveryStream({
      binaryPath: binary.path,
      binarySha256: binary.pin,
      requestHeader,
      actionCount: 0,
      steps: [],
      timeoutMs: 10_000,
    })) {
      frames.push(frame);
    }
    return frames;
  };

  const byteChunks = await fakeStreamBinary(
    directory,
    'valid-byte-chunks',
    raw,
    1,
  );
  assert.equal((await invoke(byteChunks)).at(-1).type, 'end');

  const truncated = await fakeStreamBinary(
    directory,
    'truncated',
    raw.subarray(0, raw.length - 1),
  );
  await assert.rejects(invoke(truncated), /truncated/);

  const badDigestBytes = Buffer.from(raw);
  const marker = Buffer.from('"digest":"', 'utf8');
  const digestOffset = badDigestBytes.lastIndexOf(marker) + marker.length;
  assert.ok(digestOffset >= marker.length);
  badDigestBytes[digestOffset] = badDigestBytes[digestOffset] === 0x30
    ? 0x31
    : 0x30;
  const badDigest = await fakeStreamBinary(
    directory,
    'bad-digest',
    badDigestBytes,
  );
  await assert.rejects(invoke(badDigest), /transcript digest differs/);

  const parsed = splitFramed(raw);
  const nodeIndices = parsed
    .map(({ value }, index) => ({ type: value.type, index }))
    .filter(({ type }) => type === 'nullifier-node')
    .map(({ index }) => index);
  assert.ok(nodeIndices.length >= 2);
  parsed[nodeIndices[1]] = parsed[nodeIndices[0]];
  const duplicatedBytes = Buffer.concat([
    streamMagic,
    ...parsed.map(({ bytes }) => bytes),
  ]);
  const duplicated = await fakeStreamBinary(
    directory,
    'duplicated',
    duplicatedBytes,
  );
  await assert.rejects(invoke(duplicated), /reordered or duplicated/);

  const trailing = await fakeStreamBinary(
    directory,
    'trailing',
    Buffer.concat([raw, framedJson({ type: 'unexpected' })]),
  );
  await assert.rejects(invoke(trailing), /trailing frames/);
});

test('stream input enforces exact counts and the per-frame byte ceiling', async () => {
  const binarySha256 = await binaryPin();
  const request = genesisOnlyRequest();
  const {
    actions: _actions,
    fundingPrevouts: _fundingPrevouts,
    schema: _schema,
    ...requestHeader
  } = request;
  const consume = async (options) => {
    for await (const _frame of scanNativeRecoveryStream(options)) {
      // The terminal frame is required; discard bounded rows in this test.
    }
  };
  await assert.rejects(
    consume({
      binaryPath,
      binarySha256,
      requestHeader,
      actionCount: 1,
      steps: [],
      timeoutMs: 10_000,
    }),
    /steps ended at 0; expected 1/,
  );
  await assert.rejects(
    consume({
      binaryPath,
      binarySha256,
      requestHeader,
      actionCount: 0,
      steps: [{ action: {}, fundingPrevout: {} }],
      timeoutMs: 10_000,
    }),
    /steps exceed declared actionCount 0/,
  );
  await assert.rejects(
    consume({
      binaryPath,
      binarySha256,
      requestHeader: {
        ...requestHeader,
        initialStateHex: '00'.repeat(300_000),
      },
      actionCount: 0,
      steps: [],
      timeoutMs: 10_000,
    }),
    /length must be from 1 to 524288 bytes/,
  );
  const missingRuntimeHeader = { ...requestHeader };
  delete missingRuntimeHeader.runtimeMaterialsSha256;
  await assert.rejects(
    consume({
      binaryPath,
      binarySha256,
      requestHeader: missingRuntimeHeader,
      actionCount: 0,
      steps: [],
      timeoutMs: 10_000,
    }),
    /missing or unknown properties/,
  );
  await assert.rejects(
    consume({
      binaryPath,
      binarySha256,
      requestHeader: {
        ...requestHeader,
        runtimeMaterialsSha256: 'A5'.repeat(32),
      },
      actionCount: 0,
      steps: [],
      timeoutMs: 10_000,
    }),
    /lowercase hexadecimal bytes/,
  );
});

test('strict native material adapter rejects malformed wire contracts', () => {
  const original = materialFixture();
  const converted = nativeRecoveryResultToStoreInstall(original);
  assert.deepEqual(converted.binding.profileId, Buffer.from(
    original.binding.profileId,
    'hex',
  ));
  assert.deepEqual(converted.canonical.state, Buffer.from(
    original.canonical.state,
    'hex',
  ));
  assert.deepEqual(converted.noteNodes[0].nodeHash, Buffer.from(
    original.noteNodes[0].nodeHash,
    'hex',
  ));
  assert.equal(Object.hasOwn(converted, 'contentSha256'), false);

  const rejects = (mutate, pattern) => {
    const value = clone(original);
    mutate(value);
    assert.throws(
      () => nativeRecoveryResultToStoreInstall(value),
      pattern,
    );
  };
  rejects((value) => {
    value.unknown = true;
  }, /missing or unknown properties/);
  rejects((value) => {
    delete value.binding.carrierCount;
  }, /missing or unknown properties/);
  rejects((value) => {
    delete value.binding.runtimeMaterialsSha256;
  }, /missing or unknown properties/);
  rejects((value) => {
    value.binding.runtimeMaterialsSha256 = 'A5'.repeat(32);
  }, /lowercase hexadecimal bytes/);
  rejects((value) => {
    value.binding.profileId = 'AA'.repeat(32);
  }, /lowercase hexadecimal bytes/);
  rejects((value) => {
    value.binding.networkId = 3;
  }, /safe integer range/);
  rejects((value) => {
    value.binding.denominationSats = '01';
  }, /canonical money/);
  rejects((value) => {
    value.canonical.state = value.canonical.state.slice(2);
  }, /exactly 128 lowercase hexadecimal bytes/);
  rejects((value) => {
    value.canonical.actionSequence = Number.MAX_SAFE_INTEGER + 1;
  }, /safe integer range/);
  rejects((value) => {
    value.canonical.actionSequence = 0x2_0000_0000;
  }, /safe integer range/);
  rejects((value) => {
    value.noteNodes[0].nodeIndex = 1;
  }, /safe integer range/);
  rejects((value) => {
    value.noteNodes[0].nodeIndex = Number.MAX_SAFE_INTEGER + 1;
  }, /safe integer range/);
  rejects((value) => {
    value.noteFrontier = [{
      depth: 32,
      nodeHash: '00'.repeat(32),
    }];
  }, /safe integer range/);
  rejects((value) => {
    value.noteLeaves = [{
      noteIndex: 0,
      leafHash: '00'.repeat(32),
      encryptedRecord: '00'.repeat(127),
      actionSequence: 1,
      transactionId: '00'.repeat(32),
    }];
  }, /exactly 128 lowercase hexadecimal bytes/);
  rejects((value) => {
    value.noteLeaves = [{
      noteIndex: 0,
      leafHash: '00'.repeat(32),
      encryptedRecord: '00'.repeat(128),
      actionSequence: 0,
      transactionId: '00'.repeat(32),
    }];
  }, /safe integer range/);
  rejects((value) => {
    value.nullifierLeaves[0].physicalIndex = -1;
  }, /safe integer range/);
  rejects((value) => {
    value.nullifierLeaves[0].leafType = 4;
  }, /safe integer range/);
  rejects((value) => {
    value.nullifierLeaves[0].successorIndex = 0x1_0000_0000;
  }, /safe integer range/);
  rejects((value) => {
    value.contentSha256 = 'AB'.repeat(32);
  }, /contentSha256/);
  rejects((value) => {
    value.schema = 'shieldkit-v2-recovery-authenticated-material-v1';
  }, /result schema is unsupported/);

  const rawUnknown = scanResultFixture();
  rawUnknown.extra = true;
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(rawUnknown),
    /missing or unknown properties/,
  );
  const wrongSnapshotSchema = scanResultFixture();
  wrongSnapshotSchema.snapshot.schema =
    'shieldkit-v2-recovery-snapshot-v1';
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(wrongSnapshotSchema),
    /snapshot schema or version/,
  );
  const missingSnapshotKey = scanResultFixture();
  delete missingSnapshotKey.snapshot.tip;
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(missingSnapshotKey),
    /missing or unknown properties/,
  );
  const missingSnapshotRuntime = scanResultFixture();
  delete missingSnapshotRuntime.snapshot.runtimeMaterialsSha256;
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(missingSnapshotRuntime),
    /missing or unknown properties/,
  );
  const malformedSnapshotRuntime = scanResultFixture();
  malformedSnapshotRuntime.snapshot.runtimeMaterialsSha256 = 'A5'.repeat(32);
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(malformedSnapshotRuntime),
    /lowercase hexadecimal bytes/,
  );
  const mismatchedRuntime = scanResultFixture();
  mismatchedRuntime.material.binding.runtimeMaterialsSha256 = '5a'.repeat(32);
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(mismatchedRuntime),
    /runtimeMaterialsSha256 differs/,
  );
  const mismatchedHash = scanResultFixture();
  mismatchedHash.material.contentSha256 = 'ef'.repeat(32);
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(mismatchedHash),
    /material\.contentSha256 differs from snapshot\.contentSha256/,
  );
  const wrongMaterialSchema = scanResultFixture();
  wrongMaterialSchema.material.schema =
    'shieldkit-v2-recovery-authenticated-material-v1';
  assert.throws(
    () => nativeRecoveryResultToStoreInstall(wrongMaterialSchema),
    /material schema is unsupported/,
  );
});

test('fails before execution for a wrong pin, symlink, relative path, or command', async (t) => {
  const binarySha256 = await binaryPin();
  await assert.rejects(
    runNativeRecovery({
      binaryPath,
      binarySha256: '00'.repeat(32),
      command: 'scan',
      request: {},
    }),
    /SHA-256 pin mismatch/,
  );

  const directory = await mkdtemp(join(import.meta.dirname, '.recovery-wrapper-'));
  t.after(async () => {
    const { rm } = await import('node:fs/promises');
    await rm(directory, { recursive: true });
  });
  const linked = join(directory, 'scanner');
  await symlink(binaryPath, linked);
  await assert.rejects(
    runNativeRecovery({
      binaryPath: linked,
      binarySha256,
      command: 'scan',
      request: {},
    }),
    /regular, non-symlink/,
  );
  await assert.rejects(
    runNativeRecovery({
      binaryPath: './scanner',
      binarySha256,
      command: 'scan',
      request: {},
    }),
    /absolute path/,
  );
  await assert.rejects(
    runNativeRecovery({
      binaryPath,
      binarySha256,
      command: 'scan; touch should-not-exist',
      request: {},
    }),
    /command must be/,
  );
});
