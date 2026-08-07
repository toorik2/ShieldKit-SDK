/**
 * Product tip lifecycle helpers — createPool birth + state@0 action packet.
 *
 * Offline combined Libauth (state@0 + FRI roles@1..19) is green under
 * VC_ROLE_INDEX_BASE=1 — see evidence/production/COMBINED_TIP_*.json and
 * LIFECYCLE_TOPOLOGY.md. Chipnet one-tip journey still open.
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import {
  compileStateCovenant,
  buildStateScriptSig,
  hashSfc1ProductStructuralHex,
  ROLE_COUNT,
  DEFAULT_NETWORK_ID,
  DENOMINATION_SATS,
} from './state-covenant.mjs';
import { createPoolLocal, loadRoleLockingsFromAssembly, ROLE_DUST_SATS, STATE_CARRIER_BASE_SATS } from './create-pool.mjs';
import { encodeState } from '../core/codecs/state.mjs';
import { encodePacket, KIND, PACKET_BYTES } from '../core/codecs/packet.mjs';
import { applyTransition } from '../core/codecs/transition.mjs';
import { digest4ToHex, h4, ZERO_DIGEST4_HEX } from '../core/crypto/h4.mjs';

/** FRI roles sit at vin/vout 1..roleCount when state is @0. */
export const ROLE_INPUT_BASE = 1;

export function buildTipGenesisLocal(opts = {}) {
  const local = createPoolLocal(opts);
  const covenant = compileStateCovenant({
    roleCount: opts.roleCount ?? ROLE_COUNT,
    networkId: opts.networkId ?? DEFAULT_NETWORK_ID,
    bindSfc1: opts.bindSfc1 !== false,
  });
  return {
    ...local,
    covenant,
    roleInputBase: ROLE_INPUT_BASE,
    topology: {
      stateIndex: 0,
      roleBase: ROLE_INPUT_BASE,
      roleCount: covenant.roleCount,
      note: 'FRI absolute indices must be recompiled with roleBase=1 for combined tip spend',
    },
  };
}

/**
 * Build SFP1 packet for a kind transition on an existing pre-state.
 */
export function buildActionPacket({
  kind,
  preState,
  categoryHex,
  nextNoteRoot,
  nextNullifierRoot,
  publicNullifier = ZERO_DIGEST4_HEX,
  outputNoteLeaf = null,
  withdrawalLockingBytecodeHash = '0'.repeat(64),
  networkId = DEFAULT_NETWORK_ID,
}) {
  const k = Number(kind);
  if (![KIND.DEPOSIT, KIND.TRANSFER, KIND.WITHDRAWAL].includes(k)) {
    throw new Error(`bad kind ${kind}`);
  }
  const postState = applyTransition(preState, {
    kind: k,
    nextNoteRoot:
      nextNoteRoot ??
      (k === KIND.WITHDRAWAL ? preState.noteRoot : digest4ToHex(h4('NOTE', [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]))),
    nextNullifierRoot:
      nextNullifierRoot ??
      (k === KIND.DEPOSIT
        ? preState.nullifierRoot
        : digest4ToHex(h4('NULLIFIER', [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]))),
  });
  const preHex = encodeState(preState).toString('hex');
  const postHex = encodeState(postState).toString('hex');
  const transactionContextHash = hashSfc1ProductStructuralHex({
    categoryHex,
    preCommitmentHex: preHex,
    postCommitmentHex: postHex,
    kind: k,
    networkId,
  });
  const leaf =
    outputNoteLeaf ??
    (k === KIND.WITHDRAWAL
      ? ZERO_DIGEST4_HEX
      : nextNoteRoot ?? digest4ToHex(h4('NOTE', [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])));
  const packet = {
    networkId,
    kind: k,
    flags: 0,
    instanceId: categoryHex,
    preState,
    postState,
    publicNullifier,
    outputNoteLeaf: leaf,
    withdrawalLockingBytecodeHash,
    transactionContextHash,
  };
  const buf = encodePacket(packet);
  if (buf.length !== PACKET_BYTES) throw new Error(`bad packet size ${buf.length}`);
  return {
    packet,
    packetHex: buf.toString('hex'),
    packetBytes: buf,
    preHex,
    postHex,
    preState,
    postState,
    kind: k,
    statementDigest: createHash('sha256').update(buf).digest('hex'),
  };
}

/**
 * Product state unlock for tip action: packet + redeem.
 */
export function buildStateUnlock({ covenant, packetHex }) {
  return {
    unlockingHex: buildStateScriptSig(covenant.redeemHex, packetHex),
    lockingHex: covenant.lockingHex,
    redeemBytes: covenant.redeemBytes,
  };
}

/**
 * Describe tip spend skeleton; reports combined-ready when assembly has roleIndexBase=1.
 */
export function describeTipActionSpend({
  assemblyPath,
  kind = KIND.DEPOSIT,
  categoryHex = null,
} = {}) {
  const tip = buildTipGenesisLocal();
  const cat =
    categoryHex ||
    createHash('sha256').update(`tip-lifecycle-${tip.profileId}`).digest('hex');
  const action = buildActionPacket({
    kind,
    preState: tip.state,
    categoryHex: cat,
  });
  const stateUnlock = buildStateUnlock({
    covenant: tip.covenant,
    packetHex: action.packetHex,
  });
  let roleLocks = null;
  let friCombinedReady = false;
  let friNote = 'no assembly';
  let inputBase = null;
  if (assemblyPath && existsSync(assemblyPath)) {
    try {
      const roles = loadRoleLockingsFromAssembly(assemblyPath);
      roleLocks = roles.roleLockingHexes;
      const art = JSON.parse(readFileSync(assemblyPath, 'utf8'));
      inputBase = art.inputBase ?? art.roleIndexBase ?? art.meta?.input_base ?? null;
      const allAccept = art.vm?.allAccept === true;
      friCombinedReady = Number(inputBase) === ROLE_INPUT_BASE && allAccept && roleLocks?.length === ROLE_COUNT;
      friNote = friCombinedReady
        ? `roleBase=${inputBase} allAccept; offline combined tip green (see COMBINED_TIP_*.json)`
        : `assembly loaded inputBase=${inputBase} allAccept=${allAccept}; need roleBase=1 + allAccept`;
    } catch (e) {
      friNote = String(e.message || e);
    }
  }
  const stateValueIn = STATE_CARRIER_BASE_SATS + BigInt(tip.state.reserveSats || 0);
  const stateValueOut =
    STATE_CARRIER_BASE_SATS + BigInt(action.postState.reserveSats || tip.state.reserveSats || 0);
  return {
    schema: 'shieldkit-fri-tip-action-skeleton-v1',
    ok: true,
    combinedFriAllAcceptReady: friCombinedReady,
    profileId: tip.profileId,
    categoryHex: cat,
    kind: action.kind,
    topology: tip.topology,
    state: {
      lockingHex: tip.covenant.lockingHex,
      redeemBytes: tip.covenant.redeemBytes,
      bindsSfc1: tip.covenant.bindsSfc1,
      operatorKeySpendable: false,
      unlockingHexBytes: stateUnlock.unlockingHex.length / 2,
      valueIn: stateValueIn.toString(),
      valueOut: stateValueOut.toString(),
      preCommitmentHex: action.preHex,
      postCommitmentHex: action.postHex,
    },
    packet: {
      bytes: PACKET_BYTES,
      statementDigest: action.statementDigest,
      kind: action.kind,
    },
    roles: {
      count: ROLE_COUNT,
      dustSats: ROLE_DUST_SATS.toString(),
      lockingHexes: roleLocks,
      inputBase: ROLE_INPUT_BASE,
      assemblyInputBase: inputBase,
    },
    denominationSats: DENOMINATION_SATS.toString(),
    friNote,
    blockers: friCombinedReady ? [] : ['FRI_ROLE_INDEX_BASE_1_ASSEMBLY', 'ONE_TIP_COMBINED_LIBAUTH'],
  };
}
