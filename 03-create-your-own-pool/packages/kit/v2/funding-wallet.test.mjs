import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  createV2ChipnetFundingWallet,
  deriveV2ChipnetFundingWallet,
  importV2ChipnetFundingWallet,
  loadV2ChipnetFundingWallet,
  projectV2FundingWalletPublic,
  V2FundingWalletError,
} from './funding-wallet.mjs';

const PRIVATE_KEY_HEX = `${'0'.repeat(63)}1`;

async function privateDirectory(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-v2-funding-'));
  await chmod(directory, 0o700);
  t.after(async () => {
    await import('node:fs/promises').then(({ rm }) => rm(directory, {
      recursive: true,
      force: true,
    }));
  });
  return directory;
}

const rejectCode = (code) => (error) =>
  error instanceof V2FundingWalletError && error.code === code;

test('derives a canonical Chipnet P2PKH funding wallet and secret-free projection', () => {
  const wallet = deriveV2ChipnetFundingWallet({ privateKeyHex: PRIVATE_KEY_HEX });
  assert.equal(wallet.networkId, 2);
  assert.equal(wallet.cashAddress.startsWith('bchtest:'), true);
  assert.match(wallet.compressedPublicKeyHex, /^(?:02|03)[0-9a-f]{64}$/);
  assert.match(wallet.lockingBytecodeHex, /^76a914[0-9a-f]{40}88ac$/);
  const projected = projectV2FundingWalletPublic(wallet);
  assert.equal(Object.hasOwn(projected, 'privateKeyHex'), false);
  assert.equal(JSON.stringify(projected).includes(PRIVATE_KEY_HEX), false);
  assert.equal(projected.cashAddress, wallet.cashAddress);
});

test('atomically creates a 0600 funding wallet without overwrite', async (t) => {
  const directory = await privateDirectory(t);
  const filename = path.join(directory, 'funding-wallet.json');
  const wallet = await createV2ChipnetFundingWallet({ filename }, {
    randomBytes: () => Buffer.from(PRIVATE_KEY_HEX, 'hex'),
  });
  const stat = await lstat(filename);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.deepEqual(await loadV2ChipnetFundingWallet({ filename }), wallet);
  await assert.rejects(
    createV2ChipnetFundingWallet({ filename }, { randomBytes }),
    rejectCode('FUNDING_WALLET_EXISTS'),
  );
  assert.deepEqual(await loadV2ChipnetFundingWallet({ filename }), wallet);
});

test('rejects invalid private scalars and invalid CSPRNG output', async (t) => {
  assert.throws(
    () => deriveV2ChipnetFundingWallet({ privateKeyHex: '00'.repeat(32) }),
    rejectCode('FUNDING_WALLET_INVALID'),
  );
  const directory = await privateDirectory(t);
  await assert.rejects(
    createV2ChipnetFundingWallet(
      { filename: path.join(directory, 'funding-wallet.json') },
      { randomBytes: () => new Uint8Array(31) },
    ),
    rejectCode('FUNDING_WALLET_CSPRNG_FAILURE'),
  );
});

test('imports only one exact owner-private regular key file and does not alter it', async (t) => {
  const directory = await privateDirectory(t);
  const keyFile = path.join(directory, 'funding.key');
  const filename = path.join(directory, 'funding-wallet.json');
  await writeFile(keyFile, PRIVATE_KEY_HEX, { mode: 0o600 });
  await chmod(keyFile, 0o600);
  const before = await import('node:fs/promises').then(({ readFile }) => readFile(keyFile));
  const imported = await importV2ChipnetFundingWallet({ filename, keyFile });
  const after = await import('node:fs/promises').then(({ readFile }) => readFile(keyFile));
  assert.deepEqual(after, before);
  assert.equal(imported.privateKeyHex, PRIVATE_KEY_HEX);

  const loose = path.join(directory, 'loose.key');
  await writeFile(loose, PRIVATE_KEY_HEX, { mode: 0o600 });
  await chmod(loose, 0o644);
  await assert.rejects(
    importV2ChipnetFundingWallet({ filename: path.join(directory, 'loose.json'), keyFile: loose }),
    rejectCode('FUNDING_KEY_FILE_UNSAFE'),
  );
  const malformed = path.join(directory, 'malformed.key');
  await writeFile(malformed, `${PRIVATE_KEY_HEX}\n`, { mode: 0o600 });
  await chmod(malformed, 0o600);
  await assert.rejects(
    importV2ChipnetFundingWallet({ filename: path.join(directory, 'malformed.json'), keyFile: malformed }),
    rejectCode('FUNDING_KEY_FILE_INVALID'),
  );
  const target = path.join(directory, 'target.key');
  const link = path.join(directory, 'link.key');
  await writeFile(target, PRIVATE_KEY_HEX, { mode: 0o600 });
  await chmod(target, 0o600);
  await symlink(target, link);
  await assert.rejects(
    importV2ChipnetFundingWallet({ filename: path.join(directory, 'link.json'), keyFile: link }),
    rejectCode('FUNDING_KEY_FILE_UNSAFE'),
  );
});

test('rejects malformed, extra, mismatched, wrong-network, and noncanonical wallet records', async (t) => {
  const directory = await privateDirectory(t);
  const filename = path.join(directory, 'funding-wallet.json');
  const wallet = deriveV2ChipnetFundingWallet({ privateKeyHex: PRIVATE_KEY_HEX });
  const cases = [
    {
      name: 'extra',
      value: { ...wallet, extra: true },
    },
    {
      name: 'mismatch',
      value: { ...wallet, compressedPublicKeyHex: `02${'00'.repeat(32)}` },
    },
    {
      name: 'wrong-network',
      value: { ...wallet, networkId: 1 },
    },
  ];
  for (const entry of cases) {
    await writeFile(filename, canonicalizeJcs(entry.value), { mode: 0o600 });
    await chmod(filename, 0o600);
    await assert.rejects(
      loadV2ChipnetFundingWallet({ filename }),
      rejectCode('FUNDING_WALLET_INVALID'),
      entry.name,
    );
  }
  await writeFile(filename, JSON.stringify(wallet, null, 2), { mode: 0o600 });
  await chmod(filename, 0o600);
  await assert.rejects(
    loadV2ChipnetFundingWallet({ filename }),
    rejectCode('FUNDING_WALLET_INVALID'),
  );
});

test('requires an owner-private parent directory', async (t) => {
  const directory = await privateDirectory(t);
  await chmod(directory, 0o755);
  await assert.rejects(
    createV2ChipnetFundingWallet(
      { filename: path.join(directory, 'funding-wallet.json') },
      { randomBytes: () => Buffer.from(PRIVATE_KEY_HEX, 'hex') },
    ),
    rejectCode('FUNDING_WALLET_UNSAFE_PATH'),
  );
});
