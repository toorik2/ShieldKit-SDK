/**
 * Product tip action spend — state@0 + FRI roles@1..19 (+ optional funding).
 * Offline Libauth + live Chipnet assemble shape (fee = size+1 at broadcast layer).
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import {
  createVirtualMachineBch2026,
  hexToBin,
  encodeTransaction,
  encodeDataPush,
  flattenBinArray,
  secp256k1,
  hash256,
  generateSigningSerializationBch,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import {
  compileStateCovenant,
  buildStateScriptSig,
  ROLE_COUNT,
  DENOMINATION_SATS,
} from './state-covenant.mjs';
import { buildActionPacket, ROLE_INPUT_BASE } from './tip-lifecycle.mjs';
import { materializeAssembly } from '../settlement/settlement.mjs';
import { KIND } from '../core/codecs/packet.mjs';
import { encodeState } from '../core/codecs/state.mjs';
import { applyTransition } from '../core/codecs/transition.mjs';
import { digest4ToHex, h4, ZERO_DIGEST4_HEX } from '../core/crypto/h4.mjs';

export const STATE_CARRIER_BASE = 2000n;
export const ROLE_DUST = 1000n;

const vm = createVirtualMachineBch2026();

export function loadMaterializedAssembly(pathOrObj) {
  const raw =
    typeof pathOrObj === 'string'
      ? JSON.parse(readFileSync(pathOrObj, 'utf8'))
      : pathOrObj;
  return raw.roleHex?.length ? raw : materializeAssembly(raw);
}

export function kindCode(kind) {
  const k = String(kind).toLowerCase();
  if (k === 'deposit' || k === '1') return KIND.DEPOSIT;
  if (k === 'transfer' || k === '2') return KIND.TRANSFER;
  if (k === 'withdrawal' || k === 'withdraw' || k === '3') return KIND.WITHDRAWAL;
  throw new Error(`bad kind ${kind}`);
}

/**
 * Build unsigned multi-input action tx (scriptSigs for state+roles filled; funding unlock empty).
 */
export function buildTipActionTx({
  kind,
  categoryHex,
  preState,
  assemblyPath,
  stateOutpoint, // { txid, vout, valueSats, commitmentHex }
  roleOutpoints, // [{ txid, vout, valueSats, lockingHex }]
  funding = null, // { txid, vout, valueSats, lockingHex } optional
  payoutLockingHex = null,
  feeSats = 2500n,
  networkId = 2,
}) {
  const mat = loadMaterializedAssembly(assemblyPath);
  if ((mat.inputBase ?? mat.roleIndexBase) !== 1) {
    throw new Error(`assembly must have roleIndexBase=1, got ${mat.inputBase ?? mat.roleIndexBase}`);
  }
  if (!mat.roleHex || mat.roleHex.length !== ROLE_COUNT) {
    throw new Error(`expected ${ROLE_COUNT} roleHex`);
  }
  if (!roleOutpoints || roleOutpoints.length !== ROLE_COUNT) {
    throw new Error(`expected ${ROLE_COUNT} role outpoints`);
  }

  const k = kindCode(kind);
  const covenant = compileStateCovenant({ roleCount: ROLE_COUNT, networkId, bindSfc1: true });
  const action = buildActionPacket({
    kind: k,
    preState,
    categoryHex,
  });
  const stateUnlockHex = buildStateScriptSig(covenant.redeemHex, action.packetHex);

  const preRes = BigInt(preState.reserveSats || 0);
  const postRes = BigInt(action.postState.reserveSats || 0);
  const stateValueIn = BigInt(stateOutpoint.valueSats);
  // Keep carrier base constant: value = base + reserve
  const stateValueOut = STATE_CARRIER_BASE + postRes;
  // Covenant: in - preRes == out - postRes
  const left = stateValueIn - preRes;
  const right = stateValueOut - postRes;
  if (left !== right) {
    throw new Error(`carrier invariant prep fail left=${left} right=${right}`);
  }

  const roleLocks = mat.roleHex.map((r) => r.lockingHex.toLowerCase());
  for (let i = 0; i < ROLE_COUNT; i += 1) {
    if (roleOutpoints[i].lockingHex.toLowerCase() !== roleLocks[i]) {
      throw new Error(`role ${i} lock mismatch tip vs assembly`);
    }
  }

  const inputs = [
    {
      outpointTransactionHash: hexToBin(stateOutpoint.txid),
      outpointIndex: Number(stateOutpoint.vout),
      sequenceNumber: 0xfffffffe,
      unlockingBytecode: hexToBin(stateUnlockHex),
    },
  ];
  for (let i = 0; i < ROLE_COUNT; i += 1) {
    inputs.push({
      outpointTransactionHash: hexToBin(roleOutpoints[i].txid),
      outpointIndex: Number(roleOutpoints[i].vout),
      sequenceNumber: 0xfffffffe,
      unlockingBytecode: hexToBin(mat.roleHex[i].scriptSigHex),
    });
  }

  let fundingValue = 0n;
  if (funding) {
    fundingValue = BigInt(funding.valueSats);
    inputs.push({
      outpointTransactionHash: hexToBin(funding.txid),
      outpointIndex: Number(funding.vout),
      sequenceNumber: 0xfffffffe,
      unlockingBytecode: new Uint8Array(0), // signed later
    });
  }

  const outputs = [
    {
      lockingBytecode: hexToBin(covenant.lockingHex),
      valueSatoshis: stateValueOut,
      token: {
        category: hexToBin(categoryHex),
        amount: 0n,
        nft: { capability: 'mutable', commitment: hexToBin(action.postHex) },
      },
    },
  ];
  for (let i = 0; i < ROLE_COUNT; i += 1) {
    outputs.push({
      lockingBytecode: hexToBin(roleLocks[i]),
      valueSatoshis: ROLE_DUST,
    });
  }

  // Value accounting for funding / payout
  const roleIn = roleOutpoints.reduce((s, r) => s + BigInt(r.valueSats), 0n);
  const roleOut = ROLE_DUST * BigInt(ROLE_COUNT);
  let payout = 0n;
  if (k === KIND.WITHDRAWAL && postRes < preRes) {
    payout = preRes - postRes; // denomination released
    if (!payoutLockingHex) throw new Error('withdrawal needs payoutLockingHex');
    outputs.push({
      lockingBytecode: hexToBin(payoutLockingHex),
      valueSatoshis: payout,
    });
  }

  const totalIn = stateValueIn + roleIn + fundingValue;
  const totalOutFixed = stateValueOut + roleOut + payout + BigInt(feeSats);
  const change = totalIn - totalOutFixed;
  if (funding) {
    if (change < 0n) throw new Error(`underfunded change=${change}`);
    if (change >= 546n) {
      outputs.push({
        lockingBytecode: hexToBin(funding.lockingHex),
        valueSatoshis: change,
      });
    } else if (change !== 0n) {
      throw new Error(`funding change dust ${change}`);
    }
  } else if (change !== 0n) {
    throw new Error(`no funding but imbalance ${change}`);
  }

  const tx = { version: 2, inputs, outputs, locktime: 0 };
  return {
    tx,
    covenant,
    action,
    mat,
    kind: k,
    categoryHex,
    stateValueIn,
    stateValueOut,
    feeSats: BigInt(feeSats),
    fundingIndex: funding ? ROLE_COUNT + 1 : null,
    postState: action.postState,
    postCommitmentHex: action.postHex,
    packetHex: action.packetHex,
    roleLocks,
    statementDigest: action.statementDigest,
  };
}

/**
 * Libauth evaluate all inputs (funding unlock may still be empty → skip that index).
 */
export function evaluateTipActionTx(built, { skipFunding = true } = {}) {
  const { tx, covenant, mat, fundingIndex, categoryHex, action } = built;
  const n = tx.inputs.length;
  const sourceOutputs = [];
  // Reconstruct sourceOutputs from tx shape is incomplete — caller should pass via built.sourceOutputs
  // Prefer built.sourceOutputs if present
  if (!built.sourceOutputs) {
    throw new Error('evaluateTipActionTx requires built.sourceOutputs');
  }
  const sourceOutputs2 = built.sourceOutputs;
  const perInput = [];
  for (let i = 0; i < n; i += 1) {
    if (skipFunding && fundingIndex != null && i === fundingIndex) {
      perInput.push({ idx: i, role: 'funding', ok: null, skipped: true });
      continue;
    }
    const tr = vm.debug({
      inputIndex: i,
      sourceOutputs: sourceOutputs2,
      transaction: tx,
    });
    const last = tr[tr.length - 1];
    const top = last.stack?.length ? last.stack[last.stack.length - 1] : undefined;
    const ok =
      !last.error &&
      top &&
      top.length > 0 &&
      !(top.length === 1 && top[0] === 0);
    perInput.push({
      idx: i,
      role: i === 0 ? 'state' : i <= ROLE_COUNT ? mat.roleHex[i - 1].role : 'funding',
      ok,
      error: last.error ? String(last.error).slice(0, 200) : null,
      unlockBytes: tx.inputs[i].unlockingBytecode.length,
    });
  }
  const checked = perInput.filter((p) => p.ok !== null);
  const nOk = checked.filter((p) => p.ok).length;
  return {
    allAccept: nOk === checked.length,
    nOk,
    nChecked: checked.length,
    perInput,
    fails: perInput.filter((p) => p.ok === false),
  };
}

/**
 * Attach sourceOutputs for VM + signing context.
 */
export function withSourceOutputs(built, {
  stateOutpoint,
  roleOutpoints,
  funding = null,
  categoryHex,
  preCommitmentHex,
  stateLockingHex,
}) {
  const sourceOutputs = [
    {
      lockingBytecode: hexToBin(stateLockingHex),
      valueSatoshis: BigInt(stateOutpoint.valueSats),
      token: {
        category: hexToBin(categoryHex),
        amount: 0n,
        nft: { capability: 'mutable', commitment: hexToBin(preCommitmentHex) },
      },
    },
  ];
  for (const r of roleOutpoints) {
    sourceOutputs.push({
      lockingBytecode: hexToBin(r.lockingHex),
      valueSatoshis: BigInt(r.valueSats),
    });
  }
  if (funding) {
    sourceOutputs.push({
      lockingBytecode: hexToBin(funding.lockingHex),
      valueSatoshis: BigInt(funding.valueSats),
    });
  }
  return { ...built, sourceOutputs };
}

/**
 * Sign funding P2PKH input in-place (sighash ALL|FORKID = 0x41).
 * State + FRI inputs already carry complete scriptSigs.
 */
export function signFundingInput(built, { privateKeyHex, publicKeyHex }) {
  if (built.fundingIndex == null) return built;
  if (!built.sourceOutputs) throw new Error('signFundingInput needs sourceOutputs');
  const i = built.fundingIndex;
  const priv = hexToBin(privateKeyHex);
  let pub;
  if (publicKeyHex != null) {
    pub = hexToBin(publicKeyHex);
  } else {
    const p = secp256k1.derivePublicKeyCompressed(priv);
    if (typeof p === 'string') throw new Error(p);
    pub = p;
  }

  const tx = {
    version: built.tx.version,
    inputs: built.tx.inputs.map((inp) => ({
      outpointTransactionHash: inp.outpointTransactionHash,
      outpointIndex: inp.outpointIndex,
      sequenceNumber: inp.sequenceNumber,
      unlockingBytecode: inp.unlockingBytecode,
    })),
    outputs: built.tx.outputs.map((o) => ({
      lockingBytecode: o.lockingBytecode,
      valueSatoshis: o.valueSatoshis,
      token: o.token,
    })),
    locktime: built.tx.locktime,
  };

  const coveredBytecode = built.sourceOutputs[i].lockingBytecode;
  const ser = generateSigningSerializationBch(
    {
      transaction: tx,
      sourceOutputs: built.sourceOutputs,
      inputIndex: i,
    },
    {
      coveredBytecode,
      signingSerializationType: new Uint8Array([SigningSerializationTypeBch.allOutputs]),
    },
  );
  if (typeof ser === 'string') throw new Error(`signing serialization: ${ser}`);
  const sighash = hash256(ser);
  const sig = secp256k1.signMessageHashDER(priv, sighash);
  if (typeof sig === 'string') throw new Error(sig);
  const sigWithType = Uint8Array.from([...sig, SigningSerializationTypeBch.allOutputs]);
  const sigPush = encodeDataPush(sigWithType);
  const pkPush = encodeDataPush(pub);
  if (typeof sigPush === 'string' || typeof pkPush === 'string') {
    throw new Error('encodeDataPush failed');
  }
  tx.inputs[i].unlockingBytecode = flattenBinArray([sigPush, pkPush]);
  return { ...built, tx };
}

export function estimateSignedHexSize(built, fundingScriptSigBytes = 110) {
  const parts = [];
  for (let i = 0; i < built.tx.inputs.length; i += 1) {
    let ub = built.tx.inputs[i].unlockingBytecode;
    if (built.fundingIndex === i && ub.length === 0) {
      ub = new Uint8Array(fundingScriptSigBytes);
    }
    parts.push(ub.length);
  }
  // rough: use encode with dummy funding unlock
  const tx = {
    ...built.tx,
    inputs: built.tx.inputs.map((inp, i) => {
      if (built.fundingIndex === i && inp.unlockingBytecode.length === 0) {
        return { ...inp, unlockingBytecode: new Uint8Array(fundingScriptSigBytes) };
      }
      return inp;
    }),
  };
  const enc = encodeTransaction(tx);
  if (typeof enc === 'string') throw new Error(enc);
  return enc.length;
}
