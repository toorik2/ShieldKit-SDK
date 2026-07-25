// FRI-STARK55 research-fixture build and VM harness.
//
// This file deliberately constructs a synthetic transaction so the verifier
// logic can be measured. It is not a production transaction builder: the
// category, outpoints, values, and recipient below are fixture data and are
// rejected by verifier-bench/release_gate for production use.
//
// This module contains only deployment plumbing. The proof system and verifier
// arithmetic are imported from the repaired QM31/L2 implementation in fri_stark/;
// no alternate or shortened verifier is introduced here.
import {
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  hash256,
} from '../node_modules/@bitauth/libauth/build/index.js';
import { initRefs } from '../fri_stark/verifier_vm.mjs';
import { Asm } from '../fri_stark/asm.mjs';
import { qStarkProve } from '../fri_stark/qstark.mjs';
import { qRecomputeChallenges, qStarkVerify } from '../fri_stark/qstark_verify.mjs';
import {
  buildSplitLeaderLocking,
  buildSplitFollowerLockingTemplate,
  buildQStarkWitnessCapture,
  inputUnlocking,
  sharedDigest,
  initSplitRefs,
} from '../fri_stark/build_qstark_split.mjs';
import { functionTableBodies } from '../fri_stark/qfuncs.mjs';
import {
  splitTopLevelBytecode,
  makeLibraryItems,
  buildLibraryArtifact,
  buildDynamicRedeem,
  makeWitnessItems,
} from './dynamic_library.mjs';

export const LOGN = 3;
export const LOG_BLOWUP = 3;
// Five queries are retained for the research regression profile.  This is not
// a production security setting, but it must not be reduced merely to fit a
// byte target; the release gate requires the real protocol/security profile.
export const NUM_QUERIES = 5;
export const MIN_RESEARCH_QUERIES = 5;
// The crown target is strict: the complete script package and serialized
// transaction must remain below 45,000 bytes.  A research build that only fits
// the older 55-kB envelope is not eligible for promotion.
export const MAX_TOTAL_BYTES = 45_000;
export const MAX_STANDARD_TX_BYTES = 100_000;
export const MAX_STANDARD_SCRIPT_BYTES = 10_000;
export const MAX_STANDARD_LOCKING_BYTES = 201;

// The nested QM31 multiplier is byte-smaller than the inline multiplier.  It is the same
// arithmetic, and the verifier bench measures the resulting VM operation cost; keeping this
// deterministic (rather than an environment switch) prevents a build from being byte-cheap in
// one environment and a different program elsewhere.
export const INLINE_QMUL = false;

// A deterministic test deployment category. Production funding replaces this
// with the one-time genesis transaction's category ID.
export const CATEGORY = hash256(new TextEncoder().encode('verifier.cash/fri-stark55/category/v1'));
// BCH's OP_*TOKENCATEGORY opcodes expose the category in reverse byte order
// (plus the capability byte). The fixture UTXO uses CATEGORY; the bytecode
// comparison constant therefore uses the exact VM-visible ordering.
export const SCRIPT_CATEGORY = Uint8Array.from(CATEGORY).reverse();

let initialized = false;
export async function init() {
  if (initialized) return;
  await initRefs();
  await initSplitRefs();
  initialized = true;
}

const p2sh32 = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));

function leaderUnlocking(prove, patch, opts = {}) {
  if (opts.sharedWitness === true) return new Uint8Array();
  const witness = buildQStarkWitnessCapture(prove, patch);
  const firstQuery = witness.names.findIndex((name) => /^q\d+_/.test(name));
  if (firstQuery < 0) throw new Error('leader witness has no query boundary');
  const asm = new Asm();
  for (const item of witness.items.slice(0, firstQuery)) asm.raw(item.bytes);
  return asm.bytecode();
}

function cloneBytes(bytes) {
  return Uint8Array.from(bytes);
}

function standardOutput() {
  // A deterministic dummy P2PKH output for the research VM context.
  const hash160 = new Uint8Array(20).fill(0x55);
  return Uint8Array.from([0x76, 0xa9, 0x14, ...hash160, 0x88, 0xac]);
}

function tokenInput() {
  return {
    amount: 0n,
    category: CATEGORY,
    nft: { capability: 'mutable', commitment: new Uint8Array(0) },
  };
}

function tokenOutput(commitment) {
  return {
    amount: 0n,
    category: CATEGORY,
    nft: { capability: 'none', commitment },
  };
}

/**
 * Build one complete *synthetic* P2SH32 research transaction. `patch` is
 * applied to witness values only and exists for the red-team; all locking
 * programs remain fixed for the resulting proof instance. The transaction
 * must not be funded or used as deployment provenance.
 */
export function buildBundle(prove, patch = (name, value) => value, opts = {}) {
  if (NUM_QUERIES < MIN_RESEARCH_QUERIES) {
    throw new Error(`FRI-STARK55 research query floor is ${MIN_RESEARCH_QUERIES}; do not lower security to fit bytes`);
  }
  if (opts.sharedWitness === true) {
    // The shared-witness experiment is intentionally fail-closed: its loader
    // is not part of the measured release artifact and must not be selected by
    // an adapter or an environment flag until it has its own full bench,
    // consensus-budget proof, and production provenance.
    throw new Error('shared-witness prototype is disabled; use the measured per-input witness path');
  }
  const queryCount = qRecomputeChallenges(prove).queries.length;
  if (queryCount !== NUM_QUERIES) {
    throw new Error(`FRI-STARK55 requires exactly ${NUM_QUERIES} queries, got ${queryCount}`);
  }

  const sharedWitness = opts.sharedWitness === true;
  // Keep the leader and query positions unchanged (leader=0, followers=1..K).  The committed
  // verifier library is a separate final input, so it cannot alter the coverage mapping.  When
  // sharedWitness is enabled, the authenticated witness input precedes the code library.
  const witnessIndex = sharedWitness ? queryCount + 1 : undefined;
  const libraryIndex = queryCount + (sharedWitness ? 2 : 1);
  const totalInputs = queryCount + (sharedWitness ? 3 : 2);

  let witness;
  let sharedWitnessItems;
  if (sharedWitness) {
    const witnessCapture = buildQStarkWitnessCapture(prove);
    const firstQuery = witnessCapture.names.findIndex((name) => /^q\d+_/.test(name));
    if (firstQuery < 0) throw new Error('shared witness has no query boundary');
    sharedWitnessItems = makeWitnessItems(witnessCapture.items.slice(0, firstQuery).map((item) => item.bytes));
    // The witness artifact is built before the verifier programs so both leader and followers can
    // pin its exact P2SH32 locking hash without a circular dependency.
    witness = buildLibraryArtifact(sharedWitnessItems, {
      inputIndex: witnessIndex,
      totalInputs,
      p2sh: p2sh32,
    });
  }
  const leaderRedeem = buildSplitLeaderLocking(prove, queryCount, {
    cat: SCRIPT_CATEGORY,
    inlineQMul: INLINE_QMUL,
    totalInputs,
    inputIndex: 0,
    ...(sharedWitness ? {
      sharedWitnessItems,
      sharedWitnessInputIndex: witnessIndex,
      sharedWitnessLockHash: hash256(witness.locking),
    } : {}),
  }).locking;
  const leaderLocking = p2sh32(leaderRedeem);
  // The follower's leader-provenance hash must bind the deployed P2SH32 script,
  // not the bare redeem (OP_INPUTBYTECODE sees the spent locking bytecode).
  const followerTemplate = buildSplitFollowerLockingTemplate(prove, queryCount, {
    cat: SCRIPT_CATEGORY,
    inlineQMul: INLINE_QMUL,
    totalInputs,
    leaderLockHash: hash256(leaderLocking),
    ...(sharedWitness ? { sharedWitnessItems } : {}),
  });
  // Dynamic bodies are exactly the static follower suffix, re-encoded only at balanced control
  // boundaries.  Their IDs and the arithmetic table bodies are committed in the library input;
  // followers hash-pin that input before defining or invoking anything.
  const chunks = splitTopLevelBytecode(followerTemplate.program);
  const definitions = functionTableBodies({
    deepTerm: false,
    deepTerm2: true,
    mhashStep: true,
    chalq: true,
    inlineQMul: INLINE_QMUL,
  });
  const libraryItems = makeLibraryItems(definitions, chunks);
  const library = buildLibraryArtifact(libraryItems, {
    inputIndex: libraryIndex,
    totalInputs,
    p2sh: p2sh32,
  });
  const followerRedeem = buildDynamicRedeem({
    items: libraryItems,
    libraryInputIndex: libraryIndex,
    libraryLockHash: hash256(library.locking),
    prologue: followerTemplate.prologue,
    chunkCount: chunks.length,
    ...(sharedWitness ? {
      witnessItems: sharedWitnessItems,
      witnessInputIndex: witnessIndex,
      witnessLockHash: hash256(witness.locking),
    } : {}),
  });
  const followerLocking = p2sh32(followerRedeem);
  const redeems = [leaderRedeem, ...Array.from({ length: queryCount }, () => followerRedeem)];
  const lockings = [leaderLocking, ...Array.from({ length: queryCount }, () => followerLocking)];
  if (sharedWitness) {
    redeems.push(witness.redeem);
    lockings.push(witness.locking);
  }
  redeems.push(library.redeem);
  lockings.push(library.locking);

  const bareUnlockings = [
    leaderUnlocking(prove, patch, { sharedWitness }),
    ...Array.from({ length: queryCount }, (_, k) => inputUnlocking(prove, k, patch, { sharedWitness })),
  ];
  if (sharedWitness) {
    // `bareUnlockings` receives the redeem push in the common map below.  The
    // library artifact already contains its redeem push, so strip exactly that
    // suffix here to avoid a duplicate redeem in the witness input.
    const witnessRedeemPush = encodeDataPush(witness.redeem);
    bareUnlockings.push(witness.unlocking.slice(0, -witnessRedeemPush.length));
  }
  const unlockings = bareUnlockings.map((unlocking, i) =>
    new Uint8Array([...unlocking, ...encodeDataPush(redeems[i])]),
  );
  unlockings.push(library.unlocking);

  const H = sharedDigest(prove);
  // Synthetic source outputs/outpoints: these are intentionally useful only
  // for local VM evaluation and must never be funded or called mainnet data.
  const sourceOutputs = lockings.map((lockingBytecode, inputIndex) => ({
    lockingBytecode,
    valueSatoshis: 1_000n,
    ...(inputIndex === libraryIndex || inputIndex === witnessIndex ? {} : { token: tokenInput() }),
  }));
  const inputs = unlockings.map((unlockingBytecode, i) => ({
    outpointTransactionHash: new Uint8Array(32).fill(i + 1),
    outpointIndex: 0,
    sequenceNumber: 0,
    unlockingBytecode,
  }));
  const transaction = {
    version: 2,
    inputs,
    outputs: [{
      lockingBytecode: standardOutput(),
      valueSatoshis: 900n,
      token: tokenOutput(H),
    }],
    locktime: 0,
  };
  return {
    prove,
    queryCount,
    H,
    redeems,
    lockings,
    unlockings,
    sourceOutputs,
    transaction,
    serializedTransaction: encodeTransaction(transaction),
    leaderIndex: 0,
    queryInputIndices: Array.from({ length: queryCount }, (_, i) => i + 1),
    ...(sharedWitness ? {
      witnessIndex,
      witnessLibrary: {
        digest: witness.digest,
        items: sharedWitnessItems,
        locking: witness.locking,
        redeem: witness.redeem,
        unlocking: witness.unlocking,
      },
    } : {}),
    libraryIndex,
    library: {
      digest: library.digest,
      items: libraryItems,
      chunks,
      definitions,
      table: followerTemplate.table,
      prologue: followerTemplate.prologue,
      program: followerTemplate.program,
      locking: library.locking,
      redeem: library.redeem,
      unlocking: library.unlocking,
    },
  };
}

export function accepted(state) {
  const top = state.stack?.[state.stack.length - 1];
  return state.error === undefined &&
    state.stack.length === 1 &&
    top !== undefined && top.length === 1 && top[0] === 1;
}

export function evaluateBundle(bundle, standard = true) {
  const vm = createVirtualMachineBch2026(standard);
  // Red-team callers intentionally mutate the bundle's byte arrays. Mirror the
  // current unlocking values into the encoded transaction before evaluation so
  // the VM sees exactly the bytes being measured.
  const transaction = {
    ...bundle.transaction,
    inputs: bundle.unlockings.map((unlockingBytecode, i) => ({
      ...bundle.transaction.inputs[i],
      unlockingBytecode,
    })),
  };
  return bundle.lockings.map((_, inputIndex) => vm.evaluate({
    inputIndex,
    sourceOutputs: bundle.sourceOutputs,
    transaction,
  }));
}

export function metrics(bundle, states) {
  const rows = states.map((state, i) => {
    const operationCost = state.metrics?.operationCost ?? 0;
    const budget = (41 + bundle.unlockings[i].length) * 800;
    return {
      inputIndex: i,
      accepted: accepted(state),
      error: state.error,
      operationCost,
      budget,
      budgetRatio: operationCost / budget,
      lockingBytes: bundle.lockings[i].length,
      redeemBytes: bundle.redeems[i].length,
      unlockingBytes: bundle.unlockings[i].length,
    };
  });
  const scriptBytes = rows.reduce((sum, row) => sum + row.lockingBytes + row.unlockingBytes, 0);
  return {
    rows,
    scriptBytes,
    serializedTransactionBytes: bundle.serializedTransaction.length,
    maxUnlockingBytes: Math.max(...rows.map((row) => row.unlockingBytes)),
    maxRedeemBytes: Math.max(...rows.map((row) => row.redeemBytes)),
    maxOperationCost: Math.max(...rows.map((row) => row.operationCost)),
  };
}

export function assertStandard(metricsValue) {
  if (metricsValue.scriptBytes >= MAX_TOTAL_BYTES) {
    throw new Error(`script bytes ${metricsValue.scriptBytes} >= ${MAX_TOTAL_BYTES}`);
  }
  if (metricsValue.serializedTransactionBytes >= MAX_TOTAL_BYTES) {
    throw new Error(`serialized tx ${metricsValue.serializedTransactionBytes} >= ${MAX_TOTAL_BYTES}`);
  }
  if (metricsValue.serializedTransactionBytes > MAX_STANDARD_TX_BYTES) {
    throw new Error(`serialized tx ${metricsValue.serializedTransactionBytes} > standard tx cap`);
  }
  for (const row of metricsValue.rows) {
    if (row.lockingBytes > MAX_STANDARD_LOCKING_BYTES) {
      throw new Error(`input ${row.inputIndex} locking ${row.lockingBytes} > standard ${MAX_STANDARD_LOCKING_BYTES}`);
    }
    if (row.redeemBytes > MAX_STANDARD_SCRIPT_BYTES) {
      throw new Error(`input ${row.inputIndex} redeem ${row.redeemBytes} > consensus script cap`);
    }
    if (row.unlockingBytes > MAX_STANDARD_SCRIPT_BYTES) {
      throw new Error(`input ${row.inputIndex} unlocking ${row.unlockingBytes} > standard ${MAX_STANDARD_SCRIPT_BYTES}`);
    }
    if (row.operationCost > row.budget) {
      throw new Error(`input ${row.inputIndex} operation budget ${row.operationCost} > ${row.budget}`);
    }
  }
}

export function allAccepted(states) {
  return states.every(accepted);
}

export function jsResult(prove) {
  const witness = buildQStarkWitnessCapture(prove);
  return qStarkVerify(prove, witness.openings);
}

export { cloneBytes, p2sh32, hash256 };
