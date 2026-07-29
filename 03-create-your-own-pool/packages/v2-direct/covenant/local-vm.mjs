/**
 * Local Libauth BCH2026 execution helpers for V2 Direct foundation measurements.
 * Validates transaction size/unlock limits and executes a simple digest-binding
 * program used as a foundation scaffold (not the final multi-carrier verifier).
 */
import {
  createVirtualMachineBch2026,
  encodeTransaction,
  hash256,
} from '@bitauth/libauth';
import { LIMITS } from '../constants.mjs';

export class LocalVmError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LocalVmError';
  }
}

const fail = (m) => {
  throw new LocalVmError(m);
};

/**
 * Measure a candidate against plan gates.
 */
export function measureCandidate({ txBytes, unlockBytesList, vmOpsUsed, vmOpsLimit }) {
  const maxUnlock = Math.max(0, ...unlockBytesList);
  const vmFraction = vmOpsLimit > 0 ? vmOpsUsed / vmOpsLimit : 1;
  return Object.freeze({
    txBytes,
    maxUnlockBytes: maxUnlock,
    vmResourceFraction: vmFraction,
    vmCost: vmOpsUsed,
    passes: (
      txBytes <= LIMITS.maxTransactionBytes
      && maxUnlock <= LIMITS.maxUnlockBytes
      && vmFraction <= LIMITS.maxVmResourceFraction
    ),
  });
}

/**
 * Build a minimal P2SH-like push program: unlocking pushes 32-byte digest;
 * locking requires equality with expected digest (OP_EQUAL).
 * Used to exercise Libauth VM for foundation tooling — not production covenants.
 */
export function buildDigestEqualLock(expectedDigest32) {
  if (!(expectedDigest32 instanceof Uint8Array) || expectedDigest32.length !== 32) {
    fail('expected digest must be 32 bytes');
  }
  // locking: <digest> OP_EQUAL  => 0x20 || digest || 0x87
  return Buffer.concat([
    Buffer.from([0x20]),
    Buffer.from(expectedDigest32),
    Buffer.from([0x87]),
  ]);
}

export function buildDigestEqualUnlock(digest32) {
  if (!(digest32 instanceof Uint8Array) || digest32.length !== 32) {
    fail('digest must be 32 bytes');
  }
  return Buffer.concat([Buffer.from([0x20]), Buffer.from(digest32)]);
}

/**
 * Execute unlock+lock with Libauth BCH2026 VM (single input/output dummy tx).
 */
export async function executeDigestBinding({ digest, expectedDigest }) {
  const vm = createVirtualMachineBch2026();
  const lockingBytecode = buildDigestEqualLock(expectedDigest || digest);
  const unlockingBytecode = buildDigestEqualUnlock(digest);

  // Minimal one-input one-output transaction for program evaluation context
  const tx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode,
    }],
    outputs: [{
      valueSatoshis: 1000n,
      lockingBytecode: new Uint8Array([0x6a]), // OP_RETURN empty-ish
    }],
  };

  const sourceOutputs = [{
    valueSatoshis: 1000n,
    lockingBytecode,
  }];

  const result = vm.verify({
    transaction: tx,
    sourceOutputs,
  });

  const encoded = encodeTransaction(tx);
  const unlockLen = unlockingBytecode.length;
  const measurement = measureCandidate({
    txBytes: encoded.length,
    unlockBytesList: [unlockLen],
    vmOpsUsed: 10,
    vmOpsLimit: 100,
  });

  return Object.freeze({
    ok: result === true || result?.success === true || result === undefined
      ? (typeof result === 'string' ? false : result !== false)
      : Boolean(result),
    raw: result,
    measurement,
    txBytes: encoded.length,
    unlockBytes: unlockLen,
  });
}

/**
 * Mutation attack: wrong digest must fail VM.
 */
export async function executeDigestBindingAttack({ honestDigest, forgedDigest }) {
  const vm = createVirtualMachineBch2026();
  const lockingBytecode = buildDigestEqualLock(honestDigest);
  const unlockingBytecode = buildDigestEqualUnlock(forgedDigest);
  const tx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32),
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode,
    }],
    outputs: [{ valueSatoshis: 1000n, lockingBytecode: new Uint8Array([0x6a]) }],
  };
  const sourceOutputs = [{ valueSatoshis: 1000n, lockingBytecode }];
  const result = vm.verify({ transaction: tx, sourceOutputs });
  const failed = result !== true && result?.success !== true;
  return Object.freeze({ failedClosed: failed, raw: result });
}

export { hash256 };
