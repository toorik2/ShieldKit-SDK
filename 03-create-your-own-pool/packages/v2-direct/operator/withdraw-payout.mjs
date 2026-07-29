/**
 * Single owner of withdraw payout lock ↔ packet hash invariant.
 *
 * CashScript ShieldStateV2Direct requires:
 *   sha256(outputs[9].lockingBytecode) == packet.withdrawalLockingBytecodeHash
 *
 * NEVER hash cashaddr text or sentinel strings — always sha256(lockingBytecode).
 */
import { createHash } from 'node:crypto';
import { cashAddressToLockingBytecode, binToHex } from '@bitauth/libauth';

export class WithdrawPayoutError extends Error {
  constructor(message) {
    super(message);
    this.name = 'WithdrawPayoutError';
  }
}

/**
 * @param {object} args
 * @param {string} [args.toCashAddr] — BCH cashaddr (e.g. bchtest:q…)
 * @param {Uint8Array|Buffer} args.defaultLockingBytecode — used when toCashAddr omitted
 * @returns {{ lockingBytecode: Uint8Array, hashHex: string, source: 'cashaddr'|'default' }}
 */
export function resolveWithdrawalPayout({
  toCashAddr,
  defaultLockingBytecode,
} = {}) {
  let lockingBytecode;
  let source;

  if (toCashAddr != null && String(toCashAddr).trim() !== '') {
    const raw = String(toCashAddr).trim();
    // Refuse hashing address text or bare 64-char digests as if they were locks.
    if (/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new WithdrawPayoutError(
        'WITHDRAW_PAYOUT_INVALID: --to must be a cashaddr, not a raw hash. '
        + 'Packet field is sha256(lockingBytecode); pass the payout address.',
      );
    }
    const decoded = cashAddressToLockingBytecode(raw);
    if (typeof decoded === 'string') {
      throw new WithdrawPayoutError(`WITHDRAW_PAYOUT_INVALID: bad cashaddr (${decoded})`);
    }
    lockingBytecode = Uint8Array.from(decoded.bytecode);
    source = 'cashaddr';
  } else {
    if (!defaultLockingBytecode || defaultLockingBytecode.length < 1) {
      throw new WithdrawPayoutError(
        'WITHDRAW_PAYOUT_INVALID: defaultLockingBytecode required when --to omitted',
      );
    }
    lockingBytecode = Uint8Array.from(defaultLockingBytecode);
    source = 'default';
  }

  const hashHex = createHash('sha256').update(lockingBytecode).digest('hex');
  return Object.freeze({
    lockingBytecode,
    hashHex,
    source,
    lockingBytecodeHex: binToHex(lockingBytecode),
  });
}

/**
 * Assert packet field at offset 488 matches sha256(payoutLock).
 * @param {Buffer|Uint8Array} packetBytes — 552-byte SDA2
 * @param {Uint8Array|Buffer} payoutLockingBytecode
 */
export function assertPacketMatchesPayoutLock(packetBytes, payoutLockingBytecode) {
  const pkt = Buffer.from(packetBytes);
  if (pkt.length !== 552) {
    throw new WithdrawPayoutError(`packet length ${pkt.length} != 552`);
  }
  const field = pkt.subarray(488, 520).toString('hex');
  const expected = createHash('sha256').update(Buffer.from(payoutLockingBytecode)).digest('hex');
  if (field !== expected) {
    throw new WithdrawPayoutError(
      `packet withdrawal hash mismatch: packet=${field} sha256(lock)=${expected}`,
    );
  }
  return true;
}
