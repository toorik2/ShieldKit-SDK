import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertDirectV2PacketPublicInputs,
  directV2PacketPublicInputs,
  loadPinnedShieldDirectV2Packet,
  SHIELD_DIRECT_V2_PACKET_BYTES,
  SHIELD_DIRECT_V2_PACKET_PUSH_HEADER,
} from '../src/c7/shield-direct-v2-packet-input.mjs';

const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');

const packet = () => {
  const bytes = Buffer.alloc(SHIELD_DIRECT_V2_PACKET_BYTES);
  bytes.write('SDA2', 0, 'ascii');
  return bytes;
};

test('pins only the exact V2 Direct SDA2 ABI and derives u128x2 inputs', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shield-direct-v2-'));
  try {
    const bytes = packet();
    const filename = path.join(directory, 'action.packet');
    await writeFile(filename, bytes, { mode: 0o600 });
    const loaded = loadPinnedShieldDirectV2Packet({
      path: filename,
      sha256: sha256(bytes),
    });
    assert.deepEqual(Buffer.from(loaded.bytes), bytes);
    assert.deepEqual(
      [...SHIELD_DIRECT_V2_PACKET_PUSH_HEADER],
      [0x4d, 0x28, 0x02],
    );
    const limbs = directV2PacketPublicInputs(loaded.digest);
    assert.deepEqual(
      assertDirectV2PacketPublicInputs(
        loaded.digest,
        limbs.map(String),
      ),
      limbs,
    );
    assert.throws(
      () => assertDirectV2PacketPublicInputs(loaded.digest, ['0', '0']),
      /digest limbs do not match/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects legacy, wrong-size, wrong-domain, unpinned, and symlink inputs', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'shield-direct-v2-'));
  try {
    const legacy = Buffer.alloc(752);
    legacy.write('SCAR', 0, 'ascii');
    const legacyPath = path.join(directory, 'legacy.packet');
    await writeFile(legacyPath, legacy, { mode: 0o600 });
    assert.throws(
      () => loadPinnedShieldDirectV2Packet({
        path: legacyPath,
        sha256: sha256(legacy),
      }),
      /exactly 552 bytes/,
    );

    const wrongDomain = packet();
    wrongDomain.write('SCAR', 0, 'ascii');
    const wrongDomainPath = path.join(directory, 'wrong-domain.packet');
    await writeFile(wrongDomainPath, wrongDomain, { mode: 0o600 });
    assert.throws(
      () => loadPinnedShieldDirectV2Packet({
        path: wrongDomainPath,
        sha256: sha256(wrongDomain),
      }),
      /canonical SDA2 domain/,
    );

    const valid = packet();
    const validPath = path.join(directory, 'valid.packet');
    await writeFile(validPath, valid, { mode: 0o600 });
    assert.throws(
      () => loadPinnedShieldDirectV2Packet({
        path: validPath,
        sha256: '0'.repeat(64),
      }),
      /SHA256 mismatch/,
    );
    assert.throws(
      () => loadPinnedShieldDirectV2Packet({
        path: path.relative(process.cwd(), validPath),
        sha256: sha256(valid),
      }),
      /path must be absolute/,
    );

    const link = path.join(directory, 'packet-link');
    await symlink(validPath, link);
    assert.throws(
      () => loadPinnedShieldDirectV2Packet({
        path: link,
        sha256: sha256(valid),
      }),
      /regular non-symlink/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
