import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { ENCRYPTED_RECORD_BYTES, NETWORK_CHIPNET, ZERO_32_HEX } from '../constants.mjs';
import {
  actionPacketPublicLimbsV2,
  digestActionPacketV2,
  encodeActionPacketV2,
} from '../packet.mjs';
import { emptyGenesisStateFields } from '../state.mjs';
import { emptyNullifierRoot } from '../trees/indexed-nullifier.mjs';
import { emptyNoteRoot } from '../trees/note-tree.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const rustDir = path.resolve(here, '../rust');
const katBin = path.join(rustDir, 'target/debug/v2-direct-kat');

const profileId = createHash('sha256').update('cross-lang-profile').digest('hex');
const instanceId = createHash('sha256').update('cross-lang-instance').digest('hex');

function samplePacket() {
  const pre = emptyGenesisStateFields({
    profileId,
    noteRoot: emptyNoteRoot(),
    nullifierRoot: emptyNullifierRoot(),
    maximumLiveNotes: 32,
  });
  const post = {
    ...pre,
    noteCount: '1',
    reserveSats: '10000000',
    actionSequence: '1',
    noteRoot: '0'.repeat(63) + '1',
  };
  return encodeActionPacketV2({
    networkId: NETWORK_CHIPNET,
    kind: 'deposit',
    flags: 0,
    instanceId,
    preState: pre,
    postState: post,
    publicNullifier: ZERO_32_HEX,
    outputNoteLeaf: '0'.repeat(63) + '2',
    encryptedRecord: Buffer.alloc(ENCRYPTED_RECORD_BYTES, 3),
    withdrawalLockingBytecodeHash: ZERO_32_HEX,
    transactionContextHash: createHash('sha256').update('xlang').digest('hex'),
  });
}

describe('cross-language KATs (TS + Rust)', () => {
  it('builds rust kat binary when cargo is available', () => {
    execFileSync('cargo', ['build', '--quiet'], {
      cwd: rustDir,
      env: { ...process.env, PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH}` },
      stdio: 'pipe',
    });
    assert.ok(existsSync(katBin));
  });

  it('matches digest and public-input limbs', () => {
    if (!existsSync(katBin)) {
      execFileSync('cargo', ['build', '--quiet'], {
        cwd: rustDir,
        env: { ...process.env, PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH}` },
      });
    }
    const packet = samplePacket();
    const tsDigest = digestActionPacketV2(packet).toString('hex');
    const tsLimbs = actionPacketPublicLimbsV2(packet);
    const raw = execFileSync(katBin, ['--packet-hex', packet.toString('hex')], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH}` },
    });
    const rust = JSON.parse(raw);
    assert.equal(rust.digest, tsDigest);
    assert.equal(rust.publicInputs[0], tsLimbs[0]);
    assert.equal(rust.publicInputs[1], tsLimbs[1]);
  });
});
