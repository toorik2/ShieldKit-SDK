/**
 * Product single-tx settle: densFuel(0-6) + binding(7) + CashScript state(8) + P2PKH funding(9).
 * Shared by CLI --broadcast and live Chipnet scripts. No V2_SETTLE_HEX theater.
 */
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
  binToHex,
  createVirtualMachineBch2026,
} from '@bitauth/libauth';
import { createHash } from 'node:crypto';
import { DENOMINATION_SATS } from '../constants.mjs';
import { encodePoolStateV2 } from '../state.mjs';
import {
  productBindingLock,
  packetUnlockFromSda2,
  evaluateBindingUnlock,
  evaluateStateTransition,
} from '../covenant/binding-state.mjs';
import { createStateCovenant } from '../covenant/state-covenant.mjs';
import { N_VERIFIERS, SOURCE_VALUE } from './densfuel-build.mjs';
import { assertPacketMatchesPayoutLock } from './withdraw-payout.mjs';

export class ProductSettleError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProductSettleError';
  }
}

const STATE_BASE = 10_000n;
const CARRIER_BASE = SOURCE_VALUE;
const BINDING_BASE = SOURCE_VALUE;

/**
 * @param {object} wallet { privateKey, publicKey, lockingBytecode }
 */
export async function signP2pkhInput(tx, inputIndex, sourceOutputs, wallet) {
  const secp = await instantiateSecp256k1();
  const ser = generateSigningSerializationBch(
    { inputIndex, sourceOutputs, transaction: tx },
    {
      coveredBytecode: Uint8Array.from(wallet.lockingBytecode),
      signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputsAllUtxos),
    },
  );
  const sig = secp.signMessageHashSchnorr(wallet.privateKey, hash256(ser));
  const sigWith = Buffer.concat([Buffer.from(sig), Buffer.from([0x61])]);
  return Buffer.concat([
    Buffer.from([sigWith.length]), sigWith,
    Buffer.from([wallet.publicKey.length]), wallet.publicKey,
  ]);
}

/**
 * Assemble, sign (state CashScript + funding P2PKH), local-VM verify, return hex+txid prep.
 *
 * @param {object} args
 * @param {'deposit'|'transfer'|'withdrawal'} args.kind
 * @param {object} args.engineAction — pool engine result with packet, preState, postState
 * @param {{ densLocks: Buffer[], densUnlocks: Buffer[] }} args.dens
 * @param {object} args.bundle — { carriers[{txid,vout,value,lock}], binding, state }
 * @param {object} args.wallet — signing wallet
 * @param {{txid,vout,valueSats}} args.feeUtxo
 * @param {Buffer|Uint8Array} args.category — 32-byte token category (UI/BE)
 * @param {string} args.profileId
 * @param {Uint8Array|Buffer} [args.withdrawalLockingBytecode] — payout lock for withdrawal
 *   (must satisfy sha256(lock) == packet.withdrawalLockingBytecodeHash)
 * @param {string} [args.withdrawalHashHex] — optional; asserted equal to sha256(lock) if both set
 */
export async function assembleProductSettle({
  kind,
  engineAction,
  dens,
  bundle,
  wallet,
  feeUtxo,
  category,
  profileId,
  withdrawalLockingBytecode,
  withdrawalHashHex,
}) {
  if (!bundle?.carriers || bundle.carriers.length !== N_VERIFIERS) {
    throw new ProductSettleError('bundle.carriers must have 7 entries');
  }
  if (!dens?.densLocks || dens.densLocks.length !== N_VERIFIERS) {
    throw new ProductSettleError('densFuel locks incomplete');
  }

  // Withdraw payout: DENOMINATION goes to this lock, not hard-coded hot wallet.
  let payoutLock = null;
  if (kind === 'withdrawal') {
    payoutLock = withdrawalLockingBytecode
      ? Uint8Array.from(withdrawalLockingBytecode)
      : Uint8Array.from(wallet.lockingBytecode);
    const lockHash = createHash('sha256').update(Buffer.from(payoutLock)).digest('hex');
    if (withdrawalHashHex && withdrawalHashHex !== lockHash) {
      throw new ProductSettleError(
        `withdrawalHashHex ${withdrawalHashHex} != sha256(payoutLock) ${lockHash}`,
      );
    }
    try {
      assertPacketMatchesPayoutLock(engineAction.packet, payoutLock);
    } catch (e) {
      throw new ProductSettleError(e.message);
    }
  }

  const bindingLock = productBindingLock();
  const packetUnlock = packetUnlockFromSda2(engineAction.packet);
  const bindEv = evaluateBindingUnlock(packetUnlock, engineAction.packet);
  if (!bindEv.ok) throw new ProductSettleError(`binding eval: ${bindEv.reason}`);

  const post = engineAction.postState;
  const pre = engineAction.preState;
  const postCommitment = encodePoolStateV2(post);
  const preCommitment = encodePoolStateV2(pre);
  const postStateValue = STATE_BASE + BigInt(post.reserveSats);
  const preStateValue = BigInt(bundle.state.value);

  const stEv = evaluateStateTransition({
    preCommitment,
    postCommitment,
    preValue: preStateValue,
    postValue: postStateValue,
    stateBaseSats: STATE_BASE,
    packetBytes: engineAction.packet,
  });
  if (!stEv.ok) throw new ProductSettleError(`state eval: ${stEv.reason}`);

  const cat = Buffer.from(category);
  const stateCov = await createStateCovenant({
    bindingLock,
    profileId,
    instanceIdCategory: cat,
    stateBaseSats: STATE_BASE,
    carrierCount: N_VERIFIERS,
  });

  const need = kind === 'deposit' ? DENOMINATION_SATS + 200_000n : 200_000n;
  if (BigInt(feeUtxo.valueSats) < need) {
    throw new ProductSettleError(`fee UTXO ${feeUtxo.valueSats} < need ${need}`);
  }

  const estBytes = 58_000n;
  const feeSats = estBytes * 2n;
  const inSum = CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE
    + preStateValue + BigInt(feeUtxo.valueSats);
  let outFixed = postStateValue + CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE;
  if (kind === 'withdrawal') outFixed += DENOMINATION_SATS;
  const change = inSum - outFixed - feeSats;
  if (change < 546n) throw new ProductSettleError(`change dust ${change}`);

  const settleOutputs = [
    ...dens.densLocks.map((lock) => ({
      valueSatoshis: CARRIER_BASE,
      lockingBytecode: Uint8Array.from(lock),
    })),
    {
      valueSatoshis: BINDING_BASE,
      lockingBytecode: Uint8Array.from(bindingLock),
    },
    {
      valueSatoshis: postStateValue,
      lockingBytecode: Uint8Array.from(stateCov.lockingBytecode),
      token: {
        category: Uint8Array.from(cat),
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: Uint8Array.from(postCommitment),
        },
      },
    },
  ];
  if (kind === 'withdrawal') {
    settleOutputs.push({
      valueSatoshis: DENOMINATION_SATS,
      lockingBytecode: Uint8Array.from(payoutLock),
    });
  }
  settleOutputs.push({
    valueSatoshis: change,
    lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
  });

  const settleTx = {
    version: 2,
    locktime: 0,
    inputs: [
      ...dens.densUnlocks.map((unlock, i) => ({
        outpointTransactionHash: Uint8Array.from(Buffer.from(bundle.carriers[i].txid, 'hex')),
        outpointIndex: bundle.carriers[i].vout,
        sequenceNumber: 0,
        unlockingBytecode: Uint8Array.from(unlock),
      })),
      {
        outpointTransactionHash: Uint8Array.from(Buffer.from(bundle.binding.txid, 'hex')),
        outpointIndex: bundle.binding.vout,
        sequenceNumber: 0,
        unlockingBytecode: Uint8Array.from(packetUnlock),
      },
      {
        outpointTransactionHash: Uint8Array.from(Buffer.from(bundle.state.txid, 'hex')),
        outpointIndex: bundle.state.vout,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(),
      },
      {
        outpointTransactionHash: Uint8Array.from(Buffer.from(feeUtxo.txid, 'hex')),
        outpointIndex: feeUtxo.vout,
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(),
      },
    ],
    outputs: settleOutputs,
  };

  const sourceOutputs = [
    ...bundle.carriers.map((c) => ({
      valueSatoshis: BigInt(c.value),
      lockingBytecode: Uint8Array.from(c.lock),
    })),
    {
      valueSatoshis: BigInt(bundle.binding.value),
      lockingBytecode: Uint8Array.from(bindingLock),
    },
    {
      valueSatoshis: preStateValue,
      lockingBytecode: Uint8Array.from(stateCov.lockingBytecode),
      token: {
        category: Uint8Array.from(cat),
        amount: 0n,
        nft: {
          capability: 'mutable',
          commitment: Uint8Array.from(bundle.state.commitment),
        },
      },
    },
    {
      valueSatoshis: BigInt(feeUtxo.valueSats),
      lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
    },
  ];

  settleTx.inputs[8].unlockingBytecode = Uint8Array.from(
    await stateCov.generateAdvanceUnlock({
      transaction: settleTx,
      sourceOutputs,
      inputIndex: 8,
    }),
  );
  settleTx.inputs[9].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(settleTx, 9, sourceOutputs, wallet),
  );

  const vm = createVirtualMachineBch2026(false);
  const local = vm.verify({ sourceOutputs, transaction: settleTx });
  if (local !== true) {
    throw new ProductSettleError(`local VM failed: ${String(local).slice(0, 400)}`);
  }

  const encoded = encodeTransaction(settleTx);
  const hex = binToHex(encoded);
  return Object.freeze({
    kind,
    hex,
    wire: encoded.length,
    change,
    changeVout: settleOutputs.length - 1,
    postCommitment: Buffer.from(postCommitment).toString('hex'),
    stateLockingBytecode: Buffer.from(stateCov.lockingBytecode).toString('hex'),
    densLocks: dens.densLocks.map((l) => l.toString('hex')),
    bindingLockHex: Buffer.from(bindingLock).toString('hex'),
    localVm: true,
    bindingEval: true,
    stateEval: true,
    withdrawalHashHex: payoutLock
      ? createHash('sha256').update(Buffer.from(payoutLock)).digest('hex')
      : (withdrawalHashHex || null),
    withdrawalLockingBytecodeHex: payoutLock
      ? Buffer.from(payoutLock).toString('hex')
      : null,
  });
}

/**
 * Next tip bundle after a successful settle.
 */
export function rollBundleAfterSettle({
  settleTxid,
  densLocks,
  bindingLockHex,
  stateLockingBytecode,
  postCommitment,
  postStateValue,
  carrierBase = CARRIER_BASE,
  bindingBase = BINDING_BASE,
}) {
  return {
    carriers: densLocks.map((lockHex, i) => ({
      txid: settleTxid,
      vout: i,
      value: carrierBase,
      lock: Buffer.from(lockHex, 'hex'),
    })),
    binding: {
      txid: settleTxid,
      vout: N_VERIFIERS,
      value: bindingBase,
      lock: Buffer.from(bindingLockHex, 'hex'),
    },
    state: {
      txid: settleTxid,
      vout: N_VERIFIERS + 1,
      value: postStateValue,
      lock: Buffer.from(stateLockingBytecode, 'hex'),
      commitment: Buffer.from(postCommitment, 'hex'),
    },
  };
}

export {
  STATE_BASE, CARRIER_BASE, BINDING_BASE, N_VERIFIERS,
};
