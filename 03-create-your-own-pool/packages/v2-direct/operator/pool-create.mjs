/**
 * On-chain V2 Direct pool genesis (product path).
 *
 * - Category parent must be vout=0 (CashToken mint rule); splits non-zero vouts.
 * - densFuel carrier locks from a dry-run empty-tip deposit densFuel (VK-stable pin).
 * - Writes SKS2 empty state NFT + 7 carriers + binding + change.
 * - Caller persists liveTip / pool descriptor.
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  encodeTransaction, binToHex,
} from '@bitauth/libauth';
import { NETWORK_CHIPNET, ZERO_32_HEX } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import { encodePoolStateV2 } from '../state.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { productBindingLock } from '../covenant/binding-state.mjs';
import { createStateCovenant } from '../covenant/state-covenant.mjs';
import { CIRCUIT_TREE_DEPTH } from '../prove/witness.mjs';
import { buildDensfuelForPacket, N_VERIFIERS, SOURCE_VALUE } from './densfuel-build.mjs';
import {
  signP2pkhInput, STATE_BASE, CARRIER_BASE, BINDING_BASE,
} from './product-settle.mjs';

export class PoolCreateError extends Error {
  constructor(message, code = 'POOL_CREATE') {
    super(message);
    this.name = 'PoolCreateError';
    this.code = code;
  }
}

/**
 * Ensure category mint parent is vout=0; if not, build a pure-P2PKH split.
 * @returns {{ utxo: {txid,vout,valueSats}, splitTxHex: string|null }}
 */
export async function ensureCategoryVout0(utxo, fundingWallet) {
  if (utxo.vout === 0) return { utxo, splitTxHex: null };
  const fee = 1000n;
  if (utxo.valueSats <= fee + 546n) {
    throw new PoolCreateError('category UTXO too small to force vout=0', 'CATEGORY_DUST');
  }
  const keep = utxo.valueSats - fee;
  const tx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(utxo.txid, 'hex')),
      outpointIndex: utxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [{
      valueSatoshis: keep,
      lockingBytecode: Uint8Array.from(fundingWallet.lockingBytecode),
    }],
  };
  tx.inputs[0].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(tx, 0, [{
      valueSatoshis: utxo.valueSats,
      lockingBytecode: Uint8Array.from(fundingWallet.lockingBytecode),
    }], fundingWallet),
  );
  return {
    utxo: { txid: null, vout: 0, valueSats: keep }, // txid filled after broadcast
    splitTxHex: binToHex(encodeTransaction(tx)),
    splitKeep: keep,
  };
}

/**
 * Build genesis transaction hex + densFuel pin locks for an empty pool.
 *
 * @param {{
 *   profileId: string,
 *   categoryUtxo: { txid: string, vout: number, valueSats: bigint },
 *   fundingWallet: { privateKey, publicKey, lockingBytecode },
 *   networkId?: number,
 *   maximumLiveNotes?: number,
 *   workDir: string,
 * }} args
 */
export async function buildPoolGenesis({
  profileId,
  categoryUtxo,
  fundingWallet,
  networkId = NETWORK_CHIPNET,
  maximumLiveNotes = 32,
  workDir,
}) {
  if (categoryUtxo.vout !== 0) {
    throw new PoolCreateError('category UTXO must be vout=0 before genesis', 'CATEGORY_VOUT');
  }
  const category = Buffer.from(categoryUtxo.txid, 'hex');
  if (category.length !== 32) {
    throw new PoolCreateError('category txid must be 32 bytes', 'CATEGORY_TXID');
  }
  const instanceId = category.toString('hex');
  const bindingLock = productBindingLock();

  // Dry-run deposit densFuel to obtain pin-stable densFuel locks for genesis carriers.
  const account = createAccountKeys();
  const addr = shieldAddress({
    networkId, profileId, instanceId, account,
  });
  const pre = createPoolEngineV2({
    profileId,
    instanceId,
    networkId,
    maximumLiveNotes,
    noteDepth: CIRCUIT_TREE_DEPTH,
    nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const note = freshOutputNote({
    profileId,
    instanceId,
    authority: addr.authority,
    postActionSequence: 1,
    viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
  });
  const preview = pre.deposit({
    outputNoteLeaf: note.outputNoteLeaf,
    encryptedRecord: note.encryptedRecord,
    transactionContextHash: createHash('sha256').update(`pool-create-${profileId.slice(0, 16)}`).digest('hex'),
  });
  const dens0 = await buildDensfuelForPacket({
    packetBytes: preview.packet,
    expanded: {
      note: {
        authority: addr.authority, rho: note.rho, r: note.r, cm: note.cm,
      },
      path: { index: preview.noteAppend.index, siblings: preview.noteAppend.path.siblings },
      encryption: {
        esk: note.esk,
        viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
        encryptedRecord: note.encryptedRecord,
      },
      recordCommitmentHex: note.recordCommitment,
      preNoteRoot: preview.preState.noteRoot,
      postNoteRoot: preview.postState.noteRoot,
      preNullifierRoot: preview.preState.nullifierRoot,
      postNullifierRoot: preview.postState.nullifierRoot,
    },
    workDir,
    maxAttempts: 1,
    pinSeed: `pool-create-${profileId.slice(0, 16)}`,
  });

  const stateCov = await createStateCovenant({
    bindingLock,
    profileId,
    instanceIdCategory: category,
    stateBaseSats: STATE_BASE,
    carrierCount: N_VERIFIERS,
  });
  const empty = createPoolEngineV2({
    profileId,
    instanceId,
    networkId,
    maximumLiveNotes,
    noteDepth: CIRCUIT_TREE_DEPTH,
    nullifierDepth: CIRCUIT_TREE_DEPTH,
  });
  const commitment0 = encodePoolStateV2(empty.tip());
  const genFee = 3000n;
  const genFixed = CARRIER_BASE * BigInt(N_VERIFIERS) + BINDING_BASE + STATE_BASE + genFee;
  if (categoryUtxo.valueSats < genFixed + 546n) {
    throw new PoolCreateError(
      `category UTXO ${categoryUtxo.valueSats} < genesis need ${genFixed + 546n}`,
      'CATEGORY_TOO_SMALL',
    );
  }
  const genChange = categoryUtxo.valueSats - genFixed;
  const genesisTx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(categoryUtxo.txid, 'hex')),
      outpointIndex: categoryUtxo.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      ...dens0.densLocks.map((lock) => ({
        valueSatoshis: CARRIER_BASE,
        lockingBytecode: Uint8Array.from(lock),
      })),
      { valueSatoshis: BINDING_BASE, lockingBytecode: Uint8Array.from(bindingLock) },
      {
        valueSatoshis: STATE_BASE,
        lockingBytecode: Uint8Array.from(stateCov.lockingBytecode),
        token: {
          category: Uint8Array.from(category),
          amount: 0n,
          nft: { capability: 'mutable', commitment: Uint8Array.from(commitment0) },
        },
      },
      {
        valueSatoshis: genChange,
        lockingBytecode: Uint8Array.from(fundingWallet.lockingBytecode),
      },
    ],
  };
  genesisTx.inputs[0].unlockingBytecode = Uint8Array.from(
    await signP2pkhInput(genesisTx, 0, [{
      valueSatoshis: categoryUtxo.valueSats,
      lockingBytecode: Uint8Array.from(fundingWallet.lockingBytecode),
    }], fundingWallet),
  );

  const liveTipTemplate = {
    carriers: dens0.densLocks.map((lock, k) => ({
      vout: k,
      value: String(CARRIER_BASE),
      lockHex: Buffer.from(lock).toString('hex'),
    })),
    binding: {
      vout: N_VERIFIERS,
      value: String(BINDING_BASE),
      lockHex: Buffer.from(bindingLock).toString('hex'),
    },
    state: {
      vout: N_VERIFIERS + 1,
      value: String(STATE_BASE),
      lockHex: Buffer.from(stateCov.lockingBytecode).toString('hex'),
      commitmentHex: Buffer.from(commitment0).toString('hex'),
    },
    changeVout: N_VERIFIERS + 2,
    changeValueSats: String(genChange),
  };

  return {
    profileId,
    instanceId,
    networkId,
    maximumLiveNotes,
    categoryHex: category.toString('hex'),
    genesisHex: binToHex(encodeTransaction(genesisTx)),
    densFuelGateOk: dens0.result?.gateOk === true,
    pinBind: dens0.pinBind,
    liveTipTemplate,
    stateBaseSats: STATE_BASE,
    carrierBaseSats: CARRIER_BASE,
    bindingBaseSats: BINDING_BASE,
    sourceValueSats: SOURCE_VALUE,
    commitment0Hex: Buffer.from(commitment0).toString('hex'),
    // Not settled; materials discarded (locks only used for genesis carriers).
    dryRunNoteLeaf: note.outputNoteLeaf,
  };
}

export function randomProfileId() {
  return createHash('sha256').update(randomBytes(32)).digest('hex');
}

export { N_VERIFIERS, STATE_BASE, CARRIER_BASE, BINDING_BASE };
