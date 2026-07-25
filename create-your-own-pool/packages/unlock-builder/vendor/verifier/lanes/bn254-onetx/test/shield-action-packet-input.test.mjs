import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  actionDigestPublicInputs,
  assertActionDigestPublicInputs,
  loadPinnedShieldActionPacket,
  SHIELD_ACTION_PACKET_BYTES,
} from '../src/c7/shield-action-packet-input.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const scar = () => {
  const bytes = Buffer.alloc(SHIELD_ACTION_PACKET_BYTES);
  bytes.set(Buffer.from('SCAR'));
  for (let index = 4; index < bytes.length; index++) bytes[index] = (index * 73 + 19) & 0xff;
  return bytes;
};

test('pinned SCAR ingress accepts only the exact regular-file bytes and pin', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-shield-action-'));
  try {
    const bytes = scar();
    const filename = path.join(directory, 'action.packet');
    await writeFile(filename, bytes);
    const loaded = loadPinnedShieldActionPacket({ path: filename, sha256: sha256(bytes) });
    assert.deepEqual(Buffer.from(loaded.bytes), bytes);
    assert.equal(loaded.sha256, sha256(bytes));
    assert.deepEqual(Buffer.from(loaded.digest), createHash('sha256').update(bytes).digest());

    assert.throws(
      () => loadPinnedShieldActionPacket({ path: filename, sha256: '0'.repeat(64) }),
      /SHA256 mismatch/,
    );
    assert.throws(
      () => loadPinnedShieldActionPacket({ path: path.relative(process.cwd(), filename), sha256: sha256(bytes) }),
      /path must be absolute/,
    );
    const link = path.join(directory, 'link.packet');
    await symlink(filename, link);
    assert.throws(
      () => loadPinnedShieldActionPacket({ path: link, sha256: sha256(bytes) }),
      /regular non-symlink/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('pinned SCAR ingress rejects wrong length and non-SCAR domains', async () => {
  const directory = await mkdtemp(path.join(here, '.tmp-shield-action-'));
  try {
    const short = scar().subarray(0, SHIELD_ACTION_PACKET_BYTES - 1);
    const shortPath = path.join(directory, 'short.packet');
    await writeFile(shortPath, short);
    assert.throws(
      () => loadPinnedShieldActionPacket({ path: shortPath, sha256: sha256(short) }),
      /exactly 752 bytes/,
    );

    const wrongDomain = scar();
    wrongDomain[0] ^= 1;
    const wrongDomainPath = path.join(directory, 'wrong-domain.packet');
    await writeFile(wrongDomainPath, wrongDomain);
    assert.throws(
      () => loadPinnedShieldActionPacket({ path: wrongDomainPath, sha256: sha256(wrongDomain) }),
      /canonical SCAR domain/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('digest limbs are exact unsigned BE-u128 values, including high-bit inputs', () => {
  const digest = Uint8Array.from([
    0xdb, 0x6e, 0xb2, 0xe2, 0x7e, 0xb6, 0x0f, 0x95, 0xdd, 0xf4, 0xd7, 0x44, 0x14, 0xb6, 0x59, 0x8e,
    0xe5, 0x56, 0x2e, 0x98, 0x70, 0x48, 0x9f, 0x9c, 0xed, 0x07, 0x94, 0x32, 0x5e, 0x8e, 0x38, 0x4a,
  ]);
  const limbs = actionDigestPublicInputs(digest);
  assert.equal(limbs[0], 0xdb6eb2e27eb60f95ddf4d74414b6598en);
  assert.equal(limbs[1], 0xe5562e9870489f9ced0794325e8e384an);
  assert.deepEqual(assertActionDigestPublicInputs(digest, limbs), limbs);
  assert.throws(
    () => assertActionDigestPublicInputs(digest, [limbs[0] + 1n, limbs[1]]),
    /do not match adapter public inputs/,
  );
  assert.throws(() => actionDigestPublicInputs(digest.subarray(1)), /exactly 32 bytes/);
});
