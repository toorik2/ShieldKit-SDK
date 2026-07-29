import assert from 'node:assert/strict';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import {
  createV2ChainConfig,
  loadV2ChainConfig,
  parseV2ChainConfig,
  V2_CHAIN_CONFIG_SCHEMA,
} from './chain-config.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';

const certificateSha256 = 'ab'.repeat(32);

function config() {
  return {
    schema: V2_CHAIN_CONFIG_SCHEMA,
    protocol: 'v2-direct',
    network: 'chipnet',
    endpoint: {
      url: 'https://node.example.com/rpc',
      network: 'chipnet',
      tls: {
        certificateSha256,
        minVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        serverName: 'node.example.com',
      },
      allowRedirects: false,
    },
    confirmationDepth: 6,
    requestTimeoutMs: 15_000,
  };
}

async function privateDirectory(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-chain-config-'));
  t.after(async () => {
    await rm(directory, {
      recursive: true,
      force: true,
    });
  });
  return directory;
}

test('parses and atomically persists one exact non-secret chipnet configuration', async (t) => {
  const directory = await privateDirectory(t);
  const filename = path.join(directory, 'chain.json');
  const written = await createV2ChainConfig({ filename, config: config() });
  assert.equal(written.endpoint.url, 'https://node.example.com/rpc');
  assert.equal((await lstat(filename)).mode & 0o777, 0o600);
  assert.deepEqual(await loadV2ChainConfig(filename), written);
  assert.equal(
    (await readFile(filename, 'utf8')),
    canonicalizeJcs(written),
  );
});

test('rejects missing or unknown fields and every non-chipnet configuration', () => {
  const missing = config();
  delete missing.confirmationDepth;
  assert.throws(
    () => parseV2ChainConfig(missing),
    (error) => error?.code === 'CHAIN_CONFIG_INVALID',
  );
  assert.throws(
    () => parseV2ChainConfig({ ...config(), extra: true }),
    (error) => error?.code === 'CHAIN_CONFIG_INVALID',
  );
  const mainnet = config();
  mainnet.network = 'mainnet';
  mainnet.endpoint.network = 'mainnet';
  assert.throws(
    () => parseV2ChainConfig(mainnet),
    (error) => error?.code === 'V2_MAINNET_OUTSIDE_PLAN',
  );
  const endpointMainnet = config();
  endpointMainnet.endpoint.network = 'mainnet';
  assert.throws(
    () => parseV2ChainConfig(endpointMainnet),
    (error) => error?.code === 'V2_MAINNET_OUTSIDE_PLAN',
  );
  for (const [field, value] of [
    ['confirmationDepth', 0],
    ['confirmationDepth', 101],
    ['requestTimeoutMs', 999],
    ['requestTimeoutMs', 60_001],
  ]) {
    const invalid = config();
    invalid[field] = value;
    assert.throws(
      () => parseV2ChainConfig(invalid),
      (error) => error?.code === 'CHAIN_CONFIG_INVALID',
    );
  }
});

test('rejects endpoint credentials, TLS downgrade/pin/name drift, and redirects', () => {
  for (const mutate of [
    (value) => { value.endpoint.url = 'https://user:pass@node.example.com/rpc'; },
    (value) => { value.endpoint.tls.rejectUnauthorized = false; },
    (value) => { value.endpoint.tls.minVersion = 'TLSv1.1'; },
    (value) => { value.endpoint.tls.serverName = 'other.example.com'; },
    (value) => { value.endpoint.tls.certificateSha256 = '00'; },
    (value) => { value.endpoint.allowRedirects = true; },
  ]) {
    const invalid = config();
    mutate(invalid);
    assert.throws(
      () => parseV2ChainConfig(invalid),
      (error) => error?.code === 'CHAIN_CONFIG_INVALID',
    );
  }
});

test('rejects symlinked input, noncanonical bytes, and existing targets', async (t) => {
  const directory = await privateDirectory(t);
  const real = path.join(directory, 'real.json');
  const linked = path.join(directory, 'linked.json');
  await writeFile(real, canonicalizeJcs(config()));
  await symlink(real, linked);
  await assert.rejects(
    () => loadV2ChainConfig(linked),
    (error) => error?.code === 'CHAIN_CONFIG_PATH_INVALID',
  );

  const noncanonical = path.join(directory, 'noncanonical.json');
  await writeFile(noncanonical, `${JSON.stringify(config(), null, 2)}\n`);
  await assert.rejects(
    () => loadV2ChainConfig(noncanonical),
    (error) => error?.code === 'CHAIN_CONFIG_INVALID',
  );

  const outputDirectory = path.join(directory, 'output');
  await mkdir(outputDirectory);
  const output = path.join(outputDirectory, 'chain.json');
  await createV2ChainConfig({ filename: output, config: config() });
  const original = await readFile(output);
  await assert.rejects(
    () => createV2ChainConfig({ filename: output, config: config() }),
    (error) => error?.code === 'CHAIN_CONFIG_EXISTS',
  );
  assert.deepEqual(await readFile(output), original);
});
