/**
 * Structural regression: payout lock ↔ packet hash must stay coupled.
 * Offline — no Chipnet. Fails if CLI hashes cashaddr text again.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  resolveWithdrawalPayout,
  assertPacketMatchesPayoutLock,
  WithdrawPayoutError,
} from './withdraw-payout.mjs';
import { createAccountKeys, freshOutputNote, frFromHex, shieldAddress } from '../crypto/note.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { NETWORK_CHIPNET, ZERO_32_HEX } from '../constants.mjs';
import { encodeActionPacketV2 } from '../packet.mjs';

// Hot ops locking bytecode (P2PKH) — same as codex chipnet hot
const HOT_LOCK = Buffer.from(
  '76a914233c0f9b7593aecb09dca11931965a16b90548c288ac',
  'hex',
);
const HOT_ADDR = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';

describe('resolveWithdrawalPayout (lock ↔ hash invariant)', () => {
  it('default path: hashHex === sha256(defaultLockingBytecode)', () => {
    const p = resolveWithdrawalPayout({ defaultLockingBytecode: HOT_LOCK });
    assert.equal(p.source, 'default');
    assert.equal(
      p.hashHex,
      createHash('sha256').update(HOT_LOCK).digest('hex'),
    );
    assert.deepEqual(Buffer.from(p.lockingBytecode), HOT_LOCK);
  });

  it('cashaddr path: hashHex === sha256(decoded lock), not sha256(address text)', () => {
    const p = resolveWithdrawalPayout({
      toCashAddr: HOT_ADDR,
      defaultLockingBytecode: HOT_LOCK,
    });
    assert.equal(p.source, 'cashaddr');
    const lockHash = createHash('sha256').update(Buffer.from(p.lockingBytecode)).digest('hex');
    assert.equal(p.hashHex, lockHash);
    // Anti-regression: hashing cashaddr text must NOT equal covenant hash
    const textHash = createHash('sha256').update(HOT_ADDR).digest('hex');
    assert.notEqual(p.hashHex, textHash);
    // Default lock for this address matches decoded lock
    assert.deepEqual(Buffer.from(p.lockingBytecode), HOT_LOCK);
  });

  it('refuses raw 64-char hex as --to (would reintroduce hash-as-lock confusion)', () => {
    assert.throws(
      () => resolveWithdrawalPayout({
        toCashAddr: createHash('sha256').update('x').digest('hex'),
        defaultLockingBytecode: HOT_LOCK,
      }),
      (e) => e instanceof WithdrawPayoutError && /cashaddr/i.test(e.message),
    );
  });

  it('refuses bad cashaddr', () => {
    assert.throws(
      () => resolveWithdrawalPayout({
        toCashAddr: 'not-a-cashaddr',
        defaultLockingBytecode: HOT_LOCK,
      }),
      WithdrawPayoutError,
    );
  });

  it('sentinel string default-payout is not a valid path (must use bytecode)', () => {
    const bad = createHash('sha256').update('default-payout').digest('hex');
    const good = resolveWithdrawalPayout({ defaultLockingBytecode: HOT_LOCK });
    assert.notEqual(good.hashHex, bad);
  });
});

describe('packet field matches payout lock (engine withdraw)', () => {
  it('engine.withdraw packet[488:520] === sha256(payout lock)', () => {
    const payout = resolveWithdrawalPayout({ defaultLockingBytecode: HOT_LOCK });
    const profileId = createHash('sha256').update('wd-payout-profile').digest('hex');
    const instanceId = createHash('sha256').update('wd-payout-instance').digest('hex');
    const account = createAccountKeys();
    const eng = createPoolEngineV2({
      profileId,
      instanceId,
      networkId: NETWORK_CHIPNET,
      maximumLiveNotes: 8,
      noteDepth: 8,
      nullifierDepth: 8,
    });
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account,
    });
    const n = freshOutputNote({
      profileId, instanceId, authority: addr.authority,
      postActionSequence: 1,
      viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
    });
    eng.deposit({
      outputNoteLeaf: n.outputNoteLeaf,
      encryptedRecord: n.encryptedRecord,
    });
    const wd = eng.withdraw({
      spendSk: account.sk,
      spendRho: n.rho,
      spendCm: n.cm,
      withdrawalLockingBytecodeHash: payout.hashHex,
      transactionContextHash: createHash('sha256').update('wd-payout').digest('hex'),
    });
    assertPacketMatchesPayoutLock(wd.packet, payout.lockingBytecode);
    // Negative: text-hash would not match settle lock
    const textHash = createHash('sha256').update(HOT_ADDR).digest('hex');
    assert.notEqual(
      Buffer.from(wd.packet).subarray(488, 520).toString('hex'),
      textHash,
    );
  });

  it('assertPacketMatchesPayoutLock rejects lock that does not match packet', () => {
    const good = resolveWithdrawalPayout({ defaultLockingBytecode: HOT_LOCK });
    const other = Buffer.from(
      '76a914000000000000000000000000000000000000000088ac',
      'hex',
    );
    // Minimal fake 552-byte packet with good hash at 488
    const pkt = Buffer.alloc(552, 0);
    Buffer.from(good.hashHex, 'hex').copy(pkt, 488);
    assert.throws(
      () => assertPacketMatchesPayoutLock(pkt, other),
      WithdrawPayoutError,
    );
    assert.equal(assertPacketMatchesPayoutLock(pkt, good.lockingBytecode), true);
  });
});
