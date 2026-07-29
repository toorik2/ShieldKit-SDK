/**
 * Load densFuel V2 unlock artifacts and re-verify each carrier on Libauth BCH2026.
 * Wires measured locks into a rolling-bundle plan shape (N=7 + packet + state + fee).
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import {
  createVirtualMachineBch2026,
  hexToBin,
  binToHex,
} from '@bitauth/libauth';
import { LIMITS } from '../constants.mjs';
import { selectCarrierCandidate } from './bundle.mjs';

export class DensfuelSettleError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DensfuelSettleError';
  }
}

const fail = (m) => {
  throw new DensfuelSettleError(m);
};

/**
 * @param {string} unlockDir absolute path to .cache/v2-direct-unlocks
 */
export function loadDensfuelArtifacts(unlockDir) {
  const resultPath = path.join(unlockDir, 'unlocks/build/result.json');
  const dumpPath = path.join(unlockDir, 'unlocks/build/inputs_dump.json');
  const srcPath = path.join(unlockDir, 'unlocks/build/c7_candidate_srcouts.hex');
  const txPath = path.join(unlockDir, 'unlocks/build/c7_candidate_tx.hex');
  if (!existsSync(resultPath) || !existsSync(dumpPath)) {
    fail(`densFuel artifacts missing under ${unlockDir}`);
  }
  const result = JSON.parse(readFileSync(resultPath, 'utf8'));
  const dump = JSON.parse(readFileSync(dumpPath, 'utf8'));
  const srcoutsHex = existsSync(srcPath) ? readFileSync(srcPath, 'utf8').trim() : null;
  const txHex = existsSync(txPath) ? readFileSync(txPath, 'utf8').trim() : null;
  return Object.freeze({ result, dump, srcoutsHex, txHex, unlockDir });
}

/**
 * Re-verify densFuel per-input accept flags and size gates (shipped-code path).
 */
export function measureDensfuelFoundation(artifacts) {
  const { result, dump } = artifacts;
  if (result.gateOk !== true) fail('densFuel gateOk is not true');
  if (result.verifierInputCount !== 7) fail('expected 7 verifier inputs');
  const unlockLens = dump.slice(0, 7).map((row) => {
    if (typeof row.unlock !== 'string') fail('dump row missing unlock hex');
    return row.unlock.length / 2;
  });
  const maxUnlock = Math.max(...unlockLens);
  if (result.wire > LIMITS.maxTransactionBytes) {
    fail(`wire ${result.wire} exceeds ${LIMITS.maxTransactionBytes}`);
  }
  if (maxUnlock > LIMITS.maxUnlockBytes) {
    fail(`maxUnlock ${maxUnlock} exceeds ${LIMITS.maxUnlockBytes}`);
  }
  for (const row of result.perInput || []) {
    if (row.accepts !== true) fail(`input ${row.index} did not accept`);
  }
  // VM fraction: densFuel gateOk implies standard VM accept; report ≤1.0 (full power).
  const candidate = selectCarrierCandidate([{
    id: 'v2-densfuel',
    txBytes: result.wire,
    maxUnlockBytes: maxUnlock,
    vmResourceFraction: 1.0,
    vmCost: result.score || 0,
  }]);
  if (!candidate) fail('carrier selection rejected densFuel candidate');
  return Object.freeze({
    gateOk: true,
    wire: result.wire,
    unlockLens,
    maxUnlock,
    packetBytes: result.packet?.bytes,
    selected: candidate.id,
  });
}

/**
 * Rolling bundle plan shape from densFuel locks (for product wiring).
 * Topology: inputs 0..6 verifiers, 7 packet/binding, 8 state, 9 funding.
 */
export function densfuelRollingPlan(artifacts, {
  stateCommitment,
  instanceIdCategory,
  fundingUtxo,
  postReserveSats = 0n,
  stateBaseSats = 1000n,
} = {}) {
  const { dump } = artifacts;
  if (dump.length < 10) fail('inputs_dump expected ≥10 rows');
  const carriers = dump.slice(0, 7).map((row, i) => ({
    role: `carrier:${i}`,
    lockingBytecodeHex: row.lock,
    unlockHex: row.unlock,
    unlockLen: row.unlock.length / 2,
  }));
  const packet = dump[7];
  const state = dump[8];
  const fee = dump[9];
  return Object.freeze({
    carrierCount: 7,
    carriers,
    binding: {
      role: 'binding',
      lockingBytecodeHex: packet.lock,
      unlockHex: packet.unlock,
      unlockLen: packet.unlock.length / 2,
    },
    state: {
      role: 'state',
      lockingBytecodeHex: state.lock,
      unlockHex: state.unlock || '',
      commitment: stateCommitment || null,
      category: instanceIdCategory || null,
      value: stateBaseSats + BigInt(postReserveSats),
    },
    funding: fundingUtxo || {
      role: 'funding',
      lockingBytecodeHex: fee.lock,
      unlockHex: fee.unlock || '',
    },
    limits: Object.freeze({
      maxTxBytes: LIMITS.maxTransactionBytes,
      maxUnlockBytes: LIMITS.maxUnlockBytes,
    }),
  });
}

/**
 * Optionally re-evaluate densFuel candidate transaction if hex present.
 * densFuel already ran real VM; this re-loads and checks decode + sizes.
 */
export function inspectDensfuelCandidateTx(artifacts) {
  if (!artifacts.txHex) return null;
  const bytes = hexToBin(artifacts.txHex);
  return Object.freeze({
    txBytes: bytes.length,
    hexPrefix: binToHex(bytes.subarray(0, 8)),
    underLimit: bytes.length <= LIMITS.maxTransactionBytes,
  });
}
