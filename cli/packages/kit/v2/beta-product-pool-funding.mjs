/**
 * Read-only Chipnet funding preparation for the unqualified V2 beta product.
 *
 * This is deliberately a pre-deployment stage. It creates only private local
 * configuration and a funding wallet. A signed bootstrap transaction remains
 * sealed inside a branded in-memory capability: it is neither persisted,
 * returned, nor broadcast.
 */
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { secp256k1 } from '@bitauth/libauth';

import {
  assertBchnChipnetRpc,
  createPublicChipnetFulcrumRpc,
} from '../chipnet-rpc.mjs';
import {
  buildV2BetaChipnetBootstrapFunding,
  V2BetaChipnetFundingError,
} from '../../profile/v2/beta-chipnet-funding.mjs';
import {
  finalizeV2Genesis,
  prepareV2Genesis,
  V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
  V2_GENESIS_INTENT_SCHEMA,
} from '../../profile/v2/genesis.mjs';
import {
  createV2BetaProductConfig,
  loadV2BetaProductConfig,
} from './beta-product-config.mjs';
import {
  createV2ChipnetFundingWallet,
  loadV2ChipnetFundingWallet,
  persistV2ChipnetFundingWallet,
  projectV2FundingWalletPublic,
} from './funding-wallet.mjs';
import {
  assertV2BetaProductWallet,
  openV2BetaProductWallet,
} from './beta-product-wallet.mjs';
import { inspectV2FundingUtxos } from './funding-utxo-selector.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
  V2_MAX_TRANSACTION_BYTES,
} from './transaction-policy.mjs';

export const V2_BETA_PRODUCT_POOL_FUNDING_SCHEMA =
  'shieldkit-v2-beta-product-pool-funding-v2';
export const V2_BETA_PRODUCT_BOOTSTRAP_BINDING_SCHEMA =
  'shieldkit-v2-beta-product-bootstrap-binding-v2';
export const V2_BETA_PRODUCT_FUNDING_DIRECTORYNAME = 'funding';
export const V2_BETA_PRODUCT_FUNDING_WALLET_FILENAME = 'funding-wallet.json';
export const V2_BETA_PRODUCT_BOOTSTRAP_GENESIS_SOURCE_SATS = '2000000';
export const V2_BETA_PRODUCT_ACTION_MAXIMUM_FEE_SATS =
  String(V2_MAX_TRANSACTION_BYTES);
export const V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS = '546';
export const V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS = String(
  10_000_000n
  + BigInt(V2_BETA_PRODUCT_ACTION_MAXIMUM_FEE_SATS)
  + BigInt(V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS),
);
export const V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS = String(
  BigInt(V2_BETA_PRODUCT_ACTION_MAXIMUM_FEE_SATS)
  + BigInt(V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS),
);

const MINIMUM_BOOTSTRAP_VALUE_BEFORE_SIGNATURE =
  BigInt(V2_BETA_PRODUCT_BOOTSTRAP_GENESIS_SOURCE_SATS)
  + (BigInt(V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS) * 5n)
  + (BigInt(V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS) * 5n)
  + BigInt(V2_BETA_PRODUCT_ACTION_MINIMUM_CHANGE_SATS);

const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const HEX = /^[0-9a-f]+$/u;
const CAPABILITIES = new WeakSet();
const POOL_CREATE_RPCS = new WeakMap();

export const V2_BETA_PRODUCT_POOL_CREATE_RPC_SCHEMA =
  'shieldkit-v2-beta-product-pool-create-rpc-v1';

export class V2BetaProductPoolFundingError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductPoolFundingError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductPoolFundingError(code, message, options);
};

const hash256Hex = (bytes) => createHash('sha256')
  .update(createHash('sha256').update(bytes).digest()).digest('hex');

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('POOL_FUNDING_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('POOL_FUNDING_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function privateDirectory(directory, label) {
  let stat;
  try { stat = lstatSync(directory); }
  catch (error) { fail('POOL_FUNDING_PATH_REJECTED', `${label} is unavailable`, { cause: error }); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700) {
    fail('POOL_FUNDING_PATH_REJECTED', `${label} must be a private 0700 directory`);
  }
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    fail('POOL_FUNDING_PATH_REJECTED', `${label} is not owned by the current user`);
  }
  if (realpathSync(directory) !== directory) {
    fail('POOL_FUNDING_PATH_REJECTED', `${label} must not resolve through a symlink`);
  }
  return directory;
}

function fundingPaths(config) {
  const dataDirectory = privateDirectory(config.dataDirectory, 'product data directory');
  const directory = path.join(dataDirectory, V2_BETA_PRODUCT_FUNDING_DIRECTORYNAME);
  try { mkdirSync(directory, { mode: 0o700 }); }
  catch (error) {
    if (error?.code !== 'EEXIST') {
      fail('POOL_FUNDING_PATH_REJECTED', 'funding wallet directory cannot be created', { cause: error });
    }
  }
  privateDirectory(directory, 'funding wallet directory');
  return Object.freeze({
    directory,
    walletPath: path.join(directory, V2_BETA_PRODUCT_FUNDING_WALLET_FILENAME),
  });
}

function createOrLoadConfig(configOptions, dependencies) {
  try {
    return dependencies.createConfig(configOptions);
  } catch (error) {
    if (error?.code !== 'BETA_PRODUCT_CONFIG_EXISTS') throw error;
    return dependencies.loadConfig(configOptions);
  }
}

async function createOrLoadWallet(walletPath, dependencies) {
  try {
    lstatSync(walletPath);
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      fail('POOL_FUNDING_PATH_REJECTED', 'funding wallet path cannot be inspected safely', { cause: error });
    }
    try { return await dependencies.createWallet({ filename: walletPath }); }
    catch (createError) {
      if (createError?.code !== 'FUNDING_WALLET_EXISTS') throw createError;
    }
  }
  return dependencies.loadWallet({ filename: walletPath });
}

async function persistUserWalletForRecovery(walletPath, wallet, dependencies) {
  try {
    lstatSync(walletPath);
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      fail('POOL_FUNDING_PATH_REJECTED', 'product funding custody path cannot be inspected safely', { cause: error });
    }
    try {
      return await dependencies.persistWallet({ filename: walletPath, wallet });
    } catch (persistError) {
      if (persistError?.code !== 'FUNDING_WALLET_EXISTS') throw persistError;
    }
  }
  const retained = await dependencies.loadWallet({ filename: walletPath });
  if (retained.privateKeyHex !== wallet.privateKeyHex
    || retained.lockingBytecodeHex !== wallet.lockingBytecodeHex) {
    fail('POOL_FUNDING_CUSTODY_CONFLICT', 'product recovery store is already bound to a different funding wallet');
  }
  return retained;
}

function scanEntry(value, index) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || !HASH.test(value.txid) || !Number.isSafeInteger(value.vout)
    || value.vout < 0 || value.vout > 0xffff_ffff
    || !Number.isSafeInteger(value.sats) || value.sats <= 0
    || BigInt(value.sats) > 2_100_000_000_000_000n) {
    return null;
  }
  return Object.freeze({ txid: value.txid, vout: value.vout, valueSats: String(value.sats), index });
}

function observedSats(value) {
  if (typeof value?.valueSatoshis === 'string' && DECIMAL.test(value.valueSatoshis)) {
    return value.valueSatoshis;
  }
  if (typeof value?.value === 'number' && Number.isFinite(value.value) && value.value >= 0) {
    const sats = Math.round(value.value * 1e8);
    if (Number.isSafeInteger(sats) && Math.abs((sats / 1e8) - value.value) < 1e-12) return String(sats);
  }
  return null;
}

function observedToken(value) {
  return value?.tokenData ?? value?.token ?? null;
}

async function authenticateCandidate(rpc, candidate, wallet) {
  let observed;
  let raw;
  try {
    [observed, raw] = await Promise.all([
      rpc.gettxout(candidate.txid, candidate.vout),
      rpc.getrawtransaction(candidate.txid, false),
    ]);
  } catch {
    return null;
  }
  if (observed === null || typeof observed !== 'object'
    || observedToken(observed) !== null
    || observedSats(observed) !== candidate.valueSats
    || observed.scriptPubKey?.hex !== wallet.lockingBytecodeHex
    || typeof raw !== 'string') return null;
  let transaction;
  try { transaction = parseV2RawTransaction(raw); }
  catch { return null; }
  const output = transaction.outputs[candidate.vout];
  let sourceOutput;
  try { sourceOutput = output === undefined ? undefined : parseSerializedSourceOutput(output.serializedHex); }
  catch { return null; }
  if (transaction.txid !== candidate.txid || sourceOutput === undefined
    || sourceOutput.token !== null || sourceOutput.valueSatoshis.toString() !== candidate.valueSats
    || sourceOutput.lockingBytecodeHex !== wallet.lockingBytecodeHex) return null;
  return Object.freeze({
    lockingBytecodeHex: wallet.lockingBytecodeHex,
    token: null,
    txid: candidate.txid,
    valueSats: candidate.valueSats,
    vout: candidate.vout,
  });
}

function parseExactOutpoint(value) {
  if (typeof value !== 'string') {
    fail('POOL_FUNDING_OUTPOINT_INVALID', 'fundingUtxo must be txid:vout');
  }
  const match = /^([0-9a-f]{64}):(0|[1-9][0-9]{0,9})$/u.exec(value);
  if (match === null) {
    fail('POOL_FUNDING_OUTPOINT_INVALID', 'fundingUtxo must be a lowercase txid and canonical uint32 vout');
  }
  const vout = Number(match[2]);
  if (!Number.isSafeInteger(vout) || vout > 0xffff_ffff) {
    fail('POOL_FUNDING_OUTPOINT_INVALID', 'fundingUtxo vout exceeds uint32');
  }
  return Object.freeze({ txid: match[1], vout });
}

/** Authenticate exactly one user-selected outpoint; this path never scans. */
async function authenticateExactOutpoint(rpc, outpoint, wallet) {
  let raw;
  try { raw = await rpc.getrawtransaction(outpoint.txid, false); }
  catch { return null; }
  if (typeof raw !== 'string') return null;
  let transaction;
  try { transaction = parseV2RawTransaction(raw); }
  catch { return null; }
  if (transaction.txid !== outpoint.txid) return null;
  const output = transaction.outputs[outpoint.vout];
  let sourceOutput;
  try { sourceOutput = output === undefined ? undefined : parseSerializedSourceOutput(output.serializedHex); }
  catch { return null; }
  if (sourceOutput === undefined || sourceOutput.token !== null
    || sourceOutput.lockingBytecodeHex !== wallet.lockingBytecodeHex) return null;
  let observed;
  try { observed = await rpc.gettxout(outpoint.txid, outpoint.vout); }
  catch { return null; }
  if (observed === null || typeof observed !== 'object'
    || observedToken(observed) !== null
    || observedSats(observed) !== sourceOutput.valueSatoshis.toString()
    || observed.scriptPubKey?.hex !== wallet.lockingBytecodeHex) return null;
  return Object.freeze({
    lockingBytecodeHex: wallet.lockingBytecodeHex,
    token: null,
    txid: outpoint.txid,
    valueSats: sourceOutput.valueSatoshis.toString(),
    vout: outpoint.vout,
  });
}

/**
 * Authenticate one explicitly supplied Chipnet transaction without scanning or
 * waiting for confirmation. Raw bytes establish the txid and source output;
 * gettxout's include-mempool view establishes that the exact output remains
 * spendable now. Only raw-tokenless outputs to this generated wallet enter the
 * selector.
 */
async function authenticateHintedCandidates(rpc, txid, wallet) {
  let raw;
  try { raw = await rpc.getrawtransaction(txid, false); }
  catch { return Object.freeze([]); }
  if (typeof raw !== 'string') return Object.freeze([]);
  let transaction;
  try { transaction = parseV2RawTransaction(raw); }
  catch { return Object.freeze([]); }
  if (transaction.txid !== txid) return Object.freeze([]);
  const authenticated = [];
  for (const [vout, output] of transaction.outputs.entries()) {
    let sourceOutput;
    try { sourceOutput = parseSerializedSourceOutput(output.serializedHex); }
    catch { continue; }
    if (sourceOutput.token !== null
      || sourceOutput.lockingBytecodeHex !== wallet.lockingBytecodeHex) continue;
    let observed;
    try { observed = await rpc.gettxout(txid, vout); }
    catch { continue; }
    if (observed === null || typeof observed !== 'object'
      || observedToken(observed) !== null
      || observedSats(observed) !== sourceOutput.valueSatoshis.toString()
      || observed.scriptPubKey?.hex !== sourceOutput.lockingBytecodeHex) continue;
    authenticated.push(Object.freeze({
      lockingBytecodeHex: sourceOutput.lockingBytecodeHex,
      token: null,
      txid,
      valueSats: sourceOutput.valueSatoshis.toString(),
      vout,
    }));
  }
  return Object.freeze(authenticated);
}

function publicRequired() {
  return Object.freeze({
    genesisSourceSats: V2_BETA_PRODUCT_BOOTSTRAP_GENESIS_SOURCE_SATS,
    depositReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS,
    depositOutputs: 5,
    withdrawalReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS,
    withdrawalOutputs: 5,
    feePolicy: 'one-sat-per-byte with dust-safe change',
  });
}

function fundingRequired(configPath, wallet) {
  return Object.freeze({
    schema: V2_BETA_PRODUCT_POOL_FUNDING_SCHEMA,
    status: 'funding-required',
    configPath,
    fundingWallet: projectV2FundingWalletPublic(wallet),
    required: publicRequired(),
  });
}

function signingRequest(value, kind, expectedPublicKeyHex) {
  const keys = kind === 'genesis'
    ? ['algorithm', 'digestHex', 'inputIndex', 'publicKeyHex', 'sighashContract', 'sighashType', 'signingSerializationHex']
    : ['algorithm', 'contextHash', 'digestHex', 'fundingInputIndex', 'publicKeyHex', 'sighashContract', 'sighashType', 'signingSerializationHex'];
  exact(value, keys, `${kind} funding signing request`);
  const inputIndex = kind === 'genesis' ? value.inputIndex : value.fundingInputIndex;
  if (value.algorithm !== 'BCH_SCHNORR_SECP256K1'
    || value.publicKeyHex !== expectedPublicKeyHex
    || value.sighashContract !== 'SIGHASH_ALL|UTXOS|FORKID'
    || value.sighashType !== 0x61
    || !Number.isSafeInteger(inputIndex) || inputIndex < 0
    || !HASH.test(value.digestHex)
    || typeof value.signingSerializationHex !== 'string'
    || value.signingSerializationHex.length === 0
    || value.signingSerializationHex.length % 2 !== 0
    || !HEX.test(value.signingSerializationHex)
    || (kind === 'action' && !HASH.test(value.contextHash))) {
    fail('POOL_FUNDING_SIGNING_REJECTED', `${kind} funding signing request is not the exact BCH 0x61 contract`);
  }
  if (hash256Hex(Buffer.from(value.signingSerializationHex, 'hex')) !== value.digestHex) {
    fail('POOL_FUNDING_SIGNING_REJECTED', `${kind} funding signing digest does not bind its supplied serialization`);
  }
  return value;
}

function signatureFor(wallet, request, kind) {
  signingRequest(request, kind, wallet.compressedPublicKeyHex);
  const signature = secp256k1.signMessageHashSchnorr(
    Buffer.from(wallet.privateKeyHex, 'hex'),
    Buffer.from(request.digestHex, 'hex'),
  );
  if (!(signature instanceof Uint8Array) || signature.length !== 64
    || !secp256k1.verifySignatureSchnorr(
      signature,
      Buffer.from(wallet.compressedPublicKeyHex, 'hex'),
      Buffer.from(request.digestHex, 'hex'),
    )) {
    fail('POOL_FUNDING_SIGNING_FAILED', 'funding signature could not be verified against the exact requested digest');
  }
  return Buffer.from(signature);
}

function createBootstrapReadyCapability(wallet, bootstrap) {
  const preparedGenesis = new WeakMap();
  const expectedFunding = projectV2FundingWalletPublic(wallet);
  const capability = Object.freeze({
    bootstrapBinding() {
      let transaction;
      let output;
      try {
        transaction = parseV2RawTransaction(bootstrap.rawTransactionHex);
        output = parseSerializedSourceOutput(transaction.outputs[0]?.serializedHex);
      } catch (error) {
        fail('POOL_FUNDING_BOOTSTRAP_REJECTED', 'sealed bootstrap transaction cannot be re-derived exactly', { cause: error });
      }
      const input = transaction.inputs[0];
      if (transaction.txid !== bootstrap.transactionId
        || transaction.inputs.length !== 1
        || input.outpoint.txid !== bootstrap.input.transactionId
        || input.outpoint.vout !== bootstrap.input.outputIndex
        || output.token !== null
        || output.valueSatoshis.toString() !== bootstrap.sourceOutput.valueSats
        || output.lockingBytecodeHex !== expectedFunding.lockingBytecodeHex
        || bootstrap.sourceOutput.outputIndex !== 0
        || bootstrap.sourceOutput.lockingBytecodeHex !== expectedFunding.lockingBytecodeHex) {
        fail('POOL_FUNDING_BOOTSTRAP_REJECTED', 'sealed bootstrap transaction differs from its exact public funding binding');
      }
      const sourceTransactionId = transaction.txid;
      return Object.freeze({
        schema: V2_BETA_PRODUCT_BOOTSTRAP_BINDING_SCHEMA,
        sourceTransactionId,
        instanceId: Buffer.from(sourceTransactionId, 'hex').reverse().toString('hex'),
        rawTransactionSha256: createHash('sha256').update(transaction.bytes).digest('hex'),
        sourceFundingOutpoint: Object.freeze({
          transactionId: input.outpoint.txid,
          outputIndex: input.outpoint.vout,
        }),
        output0: Object.freeze({
          serializedOutputSha256: output.sha256,
          valueSats: output.valueSatoshis.toString(),
          lockingBytecodeHex: output.lockingBytecodeHex,
        }),
        fundingWallet: expectedFunding,
      });
    },

    openProductWallet(value = {}) {
      exact(value, ['databasePath', 'instanceId', 'profileId'], 'product wallet open request');
      let productWallet;
      try {
        productWallet = openV2BetaProductWallet({
          databasePath: value.databasePath,
          profileId: value.profileId,
          instanceId: value.instanceId,
          // The key crosses only this closure-to-constructor boundary. The
          // wallet module persists it in its already-audited private SQLite
          // keyring and exposes no private projection.
          fundingPrivateKeyHex: wallet.privateKeyHex,
        });
        assertV2BetaProductWallet(productWallet);
        const matched = productWallet.fundingWallets().find((entry) =>
          entry.compressedPublicKeyHex === expectedFunding.compressedPublicKeyHex
          && entry.lockingBytecodeHex === expectedFunding.lockingBytecodeHex
          && entry.cashAddress === expectedFunding.cashAddress,
        );
        if (matched === undefined) {
          fail('POOL_FUNDING_WALLET_REJECTED', 'opened product wallet lacks the exact sealed funding identity');
        }
        return productWallet;
      } catch (error) {
        try { productWallet?.close(); } catch { /* best effort cleanup */ }
        throw error;
      }
    },

    provisionProductWallet(value = {}) {
      exact(value, ['wallet'], 'product wallet provisioning request');
      const productWallet = assertV2BetaProductWallet(value.wallet);
      if (typeof productWallet.addFundingWallet !== 'function'
        || typeof productWallet.fundingWallets !== 'function') {
        fail('POOL_FUNDING_WALLET_REJECTED', 'branded product wallet lacks the required funding-keyring operations');
      }
      const existing = productWallet.fundingWallets().find((entry) =>
        entry.compressedPublicKeyHex === expectedFunding.compressedPublicKeyHex
        && entry.lockingBytecodeHex === expectedFunding.lockingBytecodeHex
        && entry.cashAddress === expectedFunding.cashAddress,
      );
      const provisioned = existing ?? productWallet.addFundingWallet({
        privateKeyHex: wallet.privateKeyHex,
      });
      if (provisioned?.compressedPublicKeyHex !== expectedFunding.compressedPublicKeyHex
        || provisioned.lockingBytecodeHex !== expectedFunding.lockingBytecodeHex
        || provisioned.cashAddress !== expectedFunding.cashAddress) {
        fail('POOL_FUNDING_WALLET_REJECTED', 'product wallet did not retain the exact sealed funding identity');
      }
      return Object.freeze({
        walletId: provisioned.walletId,
        ...expectedFunding,
      });
    },

    prepareGenesis(value = {}) {
      exact(value, ['changeLockingBytecodeHex', 'maximumLiveNotes', 'profileCore', 'runtime'], 'genesis preparation request');
      const prepared = prepareV2Genesis({
        schema: V2_GENESIS_INTENT_SCHEMA,
        profileCore: value.profileCore,
        maximumLiveNotes: value.maximumLiveNotes,
        fundingPublicKeyHex: wallet.compressedPublicKeyHex,
        changeLockingBytecodeHex: value.changeLockingBytecodeHex,
        feeRateSatsPerByte: V2_GENESIS_FEE_RATE_SATS_PER_BYTE,
        // The sole source is output zero of the sealed signed bootstrap. It
        // never leaves this capability, but prepareV2Genesis authenticates it.
        sourceTransactionHex: bootstrap.rawTransactionHex,
      }, value.runtime);
      signingRequest(prepared.signingRequest, 'genesis', wallet.compressedPublicKeyHex);
      preparedGenesis.set(prepared, Object.freeze({ runtime: value.runtime }));
      return prepared;
    },

    finalizeGenesis(value = {}) {
      exact(value, ['prepared'], 'genesis finalization request');
      const context = preparedGenesis.get(value.prepared);
      if (context === undefined) {
        fail('POOL_FUNDING_GENESIS_REJECTED', 'genesis must be prepared by this exact bootstrap capability');
      }
      const signature = signatureFor(wallet, value.prepared.signingRequest, 'genesis');
      return finalizeV2Genesis(value.prepared, signature, context.runtime);
    },

    signActionFunding(value = {}) {
      return signatureFor(wallet, value, 'action');
    },
  });
  CAPABILITIES.add(capability);
  return capability;
}

function recoverExactBootstrap(wallet, rawTransactionHex) {
  if (typeof rawTransactionHex !== 'string' || rawTransactionHex.length === 0
    || rawTransactionHex.length % 2 !== 0 || !HEX.test(rawTransactionHex)) {
    fail('POOL_FUNDING_RECOVERY_REJECTED', 'recovery requires exact lowercase bootstrap transaction hex');
  }
  let transaction;
  try { transaction = parseV2RawTransaction(rawTransactionHex); }
  catch (error) {
    fail('POOL_FUNDING_RECOVERY_REJECTED', 'persisted bootstrap transaction cannot be parsed', { cause: error });
  }
  if (transaction.version !== 2 || transaction.locktime !== 0
    || transaction.inputs.length !== 1 || transaction.outputs.length !== 12
    || transaction.inputs[0].sequence !== 0xffff_ffff) {
    fail('POOL_FUNDING_RECOVERY_REJECTED', 'persisted bootstrap transaction has an unexpected envelope');
  }
  const expectedActionValues = [
    ...Array(5).fill(V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS),
    ...Array(5).fill(V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS),
  ];
  if (transaction.outputs.slice(1, 11).some(
    (output, index) => output.valueSatoshis.toString() !== expectedActionValues[index],
  )) {
    fail(
      'POOL_FUNDING_LAYOUT_INCOMPATIBLE',
      'persisted bootstrap predates the full-cap action funding layout; this unqualified beta pool cannot be resumed and must be recreated',
    );
  }
  const outputSats = transaction.outputs.reduce(
    (total, output) => total + output.valueSatoshis,
    0n,
  );
  // The bootstrap constructor fixes exactly one satoshi per serialized byte.
  // Rebuilding locally re-verifies the source signature, complete output
  // layout, reserve values, change, and BCH_2026_STANDARD VM verdict.
  const sourceValueSats = outputSats + BigInt(transaction.sizeBytes);
  let rebuilt;
  try {
    rebuilt = buildV2BetaChipnetBootstrapFunding({
      depositReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS,
      fundingPrivateKeyHex: wallet.privateKeyHex,
      fundingPublicKeyHex: wallet.compressedPublicKeyHex,
      genesisSourceSats: V2_BETA_PRODUCT_BOOTSTRAP_GENESIS_SOURCE_SATS,
      source: {
        lockingBytecodeHex: wallet.lockingBytecodeHex,
        outputIndex: transaction.inputs[0].outpoint.vout,
        token: null,
        transactionId: transaction.inputs[0].outpoint.txid,
        valueSats: sourceValueSats.toString(),
      },
      walletLockingBytecodeHex: wallet.lockingBytecodeHex,
      withdrawalReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS,
    });
  } catch (error) {
    fail('POOL_FUNDING_RECOVERY_REJECTED', 'persisted bootstrap transaction does not rebuild under the retained funding key', { cause: error });
  }
  if (rebuilt.rawTransactionHex !== rawTransactionHex
    || rebuilt.transactionId !== transaction.txid) {
    fail('POOL_FUNDING_RECOVERY_REJECTED', 'persisted bootstrap transaction is not byte-identical to its authenticated reconstruction');
  }
  return Object.freeze({
    bootstrap: rebuilt,
    source: Object.freeze({
      lockingBytecodeHex: wallet.lockingBytecodeHex,
      token: null,
      txid: transaction.inputs[0].outpoint.txid,
      valueSats: sourceValueSats.toString(),
      vout: transaction.inputs[0].outpoint.vout,
    }),
  });
}

/** Require an opaque capability returned by a bootstrap-ready product funding stage. */
export function assertV2BetaProductPoolFundingCapability(value) {
  if (!CAPABILITIES.has(value)
    || typeof value.bootstrapBinding !== 'function'
    || typeof value.openProductWallet !== 'function'
    || typeof value.provisionProductWallet !== 'function'
    || typeof value.prepareGenesis !== 'function'
    || typeof value.finalizeGenesis !== 'function'
    || typeof value.signActionFunding !== 'function') {
    fail('POOL_FUNDING_CAPABILITY_REQUIRED', 'a branded bootstrap-ready pool funding capability is required');
  }
  return value;
}

async function prepare(value, dependencies) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).some((key) => !['dataHome', 'fundingTxid', 'fundingUtxo', 'fundingWalletPath'].includes(key))) {
    fail('POOL_FUNDING_INVALID', 'pool funding options has unknown properties');
  }
  if (value.fundingTxid !== undefined && !HASH.test(value.fundingTxid)) {
    fail('POOL_FUNDING_INVALID', 'fundingTxid must be exactly 64 lowercase hexadecimal characters');
  }
  const directFunding = value.fundingWalletPath !== undefined || value.fundingUtxo !== undefined;
  if (directFunding && (typeof value.fundingWalletPath !== 'string' || value.fundingUtxo === undefined)) {
    fail('POOL_FUNDING_USER_WALLET_REQUIRED', 'one-invocation pool creation requires fundingWalletPath and fundingUtxo together');
  }
  if (directFunding && value.fundingTxid !== undefined) {
    fail('POOL_FUNDING_INVALID', 'fundingTxid cannot be combined with direct user funding');
  }
  const configOptions = value.dataHome === undefined ? {} : { dataHome: value.dataHome };
  const created = createOrLoadConfig(configOptions, dependencies);
  const paths = fundingPaths(created.config);
  const requestedOutpoint = directFunding ? parseExactOutpoint(value.fundingUtxo) : undefined;
  const userWallet = directFunding
    ? await dependencies.loadWallet({ filename: value.fundingWalletPath })
    : undefined;
  const wallet = userWallet ?? await createOrLoadWallet(paths.walletPath, dependencies);
  const ownsRpc = dependencies.sharedRpc === undefined;
  const rpc = ownsRpc
    ? dependencies.assertRpc(await dependencies.createRpc())
    : dependencies.assertRpc(dependencies.sharedRpc);
  try {
    let authenticated;
    if (directFunding) {
      const exact = await authenticateExactOutpoint(rpc, requestedOutpoint, wallet);
      if (exact === null) {
        fail('POOL_FUNDING_USER_UTXO_REJECTED', 'the exact user-owned funding outpoint is absent, spent, token-bearing, or does not match the supplied wallet');
      }
      authenticated = [exact];
    } else if (value.fundingTxid !== undefined) {
      authenticated = await authenticateHintedCandidates(rpc, value.fundingTxid, wallet);
    } else {
      let scanned;
      try { scanned = await rpc.scanAddress(wallet.cashAddress); }
      catch (error) { fail('POOL_FUNDING_SCAN_FAILED', 'Chipnet product funding scan failed', { cause: error }); }
      if (!Array.isArray(scanned)) fail('POOL_FUNDING_SCAN_FAILED', 'Chipnet product funding scan returned a non-array observation');
      const candidates = scanned.map(scanEntry).filter((entry) => entry !== null);
      authenticated = [];
      for (const candidate of candidates) {
        const checked = await authenticateCandidate(rpc, candidate, wallet);
        if (checked !== null) authenticated.push(checked);
      }
    }
    let inspected;
    try {
      inspected = inspectV2FundingUtxos({
        fundingLockingBytecodeHex: wallet.lockingBytecodeHex,
        utxos: Object.freeze(authenticated),
      });
    } catch (error) {
      fail('POOL_FUNDING_AUTHENTICATION_FAILED', 'Chipnet product funding observations could not be authenticated', { cause: error });
    }
    for (const source of inspected) {
      try {
        if (directFunding && BigInt(source.valueSats) < MINIMUM_BOOTSTRAP_VALUE_BEFORE_SIGNATURE) {
          fail('POOL_FUNDING_USER_UTXO_INSUFFICIENT', 'the exact user-owned funding outpoint cannot meet fixed bootstrap reserves and dust-safe change');
        }
        // The copied private wallet is durable before the first signature. It
        // lets recovery reconstruct only this exact bootstrap after any crash.
        const signingWallet = directFunding
          ? await persistUserWalletForRecovery(paths.walletPath, wallet, dependencies)
          : wallet;
        const bootstrap = buildV2BetaChipnetBootstrapFunding({
          depositReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_DEPOSIT_RESERVE_SATS,
          fundingPrivateKeyHex: signingWallet.privateKeyHex,
          fundingPublicKeyHex: signingWallet.compressedPublicKeyHex,
          genesisSourceSats: V2_BETA_PRODUCT_BOOTSTRAP_GENESIS_SOURCE_SATS,
          source: {
            lockingBytecodeHex: source.lockingBytecodeHex,
            outputIndex: source.vout,
            token: null,
            transactionId: source.txid,
            valueSats: source.valueSats,
          },
          walletLockingBytecodeHex: signingWallet.lockingBytecodeHex,
          withdrawalReserveSats: V2_BETA_PRODUCT_BOOTSTRAP_WITHDRAWAL_RESERVE_SATS,
        });
        if (JSON.stringify(bootstrap).includes(signingWallet.privateKeyHex)) {
          fail('POOL_FUNDING_INTERNAL', 'bootstrap record unexpectedly contains funding private-key material');
        }
        const capability = createBootstrapReadyCapability(signingWallet, bootstrap);
        return Object.freeze({
          schema: V2_BETA_PRODUCT_POOL_FUNDING_SCHEMA,
          status: 'bootstrap-ready',
          configPath: created.configPath,
          fundingWallet: projectV2FundingWalletPublic(signingWallet),
          source,
          capability,
        });
      } catch (error) {
        if (!(error instanceof V2BetaChipnetFundingError)
          || error.code !== 'BOOTSTRAP_FUNDING_INSUFFICIENT') throw error;
      }
    }
    if (directFunding) {
      fail('POOL_FUNDING_USER_UTXO_INSUFFICIENT', 'the exact user-owned funding outpoint cannot fund the required bootstrap and fee');
    }
    return fundingRequired(created.configPath, wallet);
  } finally {
    if (ownsRpc) {
      try { await rpc?.close?.(); } catch { /* preserve the funding result/error */ }
    }
  }
}

/** Create/load local private prerequisites and prepare one in-memory bootstrap. */
export async function createV2BetaProductPoolFunding(value = {}) {
  return prepare(value, Object.freeze({
    assertRpc: assertBchnChipnetRpc,
    createConfig: createV2BetaProductConfig,
    createRpc: createPublicChipnetFulcrumRpc,
    createWallet: createV2ChipnetFundingWallet,
    loadConfig: loadV2BetaProductConfig,
    loadWallet: loadV2ChipnetFundingWallet,
    persistWallet: persistV2ChipnetFundingWallet,
  }));
}

async function createPoolCreateRpc(createRpc) {
  let rpc;
  try { rpc = assertBchnChipnetRpc(await createRpc()); }
  catch (error) {
    fail('POOL_FUNDING_RPC_CAPABILITY_REQUIRED', 'pool-create RPC construction did not yield a fixed-route genesis-checked Chipnet product capability', { cause: error });
  }
  const capability = Object.freeze({
    schema: V2_BETA_PRODUCT_POOL_CREATE_RPC_SCHEMA,
    backend: rpc.backend,
    network: rpc.network,
  });
  POOL_CREATE_RPCS.set(capability, rpc);
  return capability;
}

/** Create one fixed-route, genesis-checked Chipnet product capability for pool creation. */
export async function createV2BetaProductPoolCreateRpc() {
  return createPoolCreateRpc(createPublicChipnetFulcrumRpc);
}

/** Test-only fixed-capability constructor; production never accepts an RPC seam. */
export async function createV2BetaProductPoolCreateRpcForTest({ createRpc } = {}) {
  if (typeof createRpc !== 'function') {
    fail('POOL_FUNDING_INVALID', 'test pool-create RPC constructor is required');
  }
  return createPoolCreateRpc(createRpc);
}

/** Consume only a capability made by the production or explicit test constructor. */
export function consumeV2BetaProductPoolCreateRpc(value) {
  const rpc = POOL_CREATE_RPCS.get(value);
  if (rpc === undefined) {
    fail('POOL_FUNDING_RPC_CAPABILITY_REQUIRED', 'a branded fixed-route pool-create Chipnet product capability is required');
  }
  return assertBchnChipnetRpc(rpc);
}

async function createFundingWithPoolCreateRpc(value, poolCreateRpc, dependencies) {
  return prepare(value, Object.freeze({
    ...dependencies,
    sharedRpc: consumeV2BetaProductPoolCreateRpc(poolCreateRpc),
  }));
}

/** Reuse the exact branded pool-create Chipnet product connection for funding discovery. */
export async function createV2BetaProductPoolFundingWithPoolCreateRpc(value = {}, poolCreateRpc) {
  return createFundingWithPoolCreateRpc(value, poolCreateRpc, Object.freeze({
    assertRpc: assertBchnChipnetRpc,
    createConfig: createV2BetaProductConfig,
    createRpc: createPublicChipnetFulcrumRpc,
    createWallet: createV2ChipnetFundingWallet,
    loadConfig: loadV2BetaProductConfig,
    loadWallet: loadV2ChipnetFundingWallet,
    persistWallet: persistV2ChipnetFundingWallet,
  }));
}

/** Test-only shared-RPC funding seam; the supplied RPC must still be branded. */
export async function createV2BetaProductPoolFundingWithPoolCreateRpcForTest(value = {}, poolCreateRpc, seam = {}) {
  exact(seam, ['assertRpc', 'createWallet', 'loadWallet', 'persistWallet'], 'pool funding shared RPC test seam');
  for (const name of ['assertRpc', 'createWallet', 'loadWallet', 'persistWallet']) {
    if (typeof seam[name] !== 'function') fail('POOL_FUNDING_INVALID', `pool funding shared RPC test seam ${name} must be a function`);
  }
  return createFundingWithPoolCreateRpc(value, poolCreateRpc, Object.freeze({
    ...seam,
    createConfig: createV2BetaProductConfig,
    createRpc: () => { throw new Error('shared pool-create RPC must be reused'); },
    loadConfig: loadV2BetaProductConfig,
  }));
}

/**
 * Recover the sealed funding capability from coordinator-retained exact bytes.
 * This path performs no scan and no network call; it is intended only after a
 * staged deployment has made ordinary UTXO discovery insufficient.
 */
export async function recoverV2BetaProductPoolFunding(value = {}) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || !Object.hasOwn(value, 'sourceFundingRawTxHex')
    || Object.keys(value).some((key) => !['dataHome', 'sourceFundingRawTxHex'].includes(key))) {
    fail('POOL_FUNDING_INVALID', 'pool funding recovery options has missing or unknown properties');
  }
  const { dataHome = undefined, sourceFundingRawTxHex } = value;
  const configOptions = dataHome === undefined ? {} : { dataHome };
  const loaded = loadV2BetaProductConfig(configOptions);
  const paths = fundingPaths(loaded.config);
  let wallet;
  try { wallet = await loadV2ChipnetFundingWallet({ filename: paths.walletPath }); }
  catch (error) {
    fail('POOL_FUNDING_RECOVERY_REJECTED', 'retained private funding wallet is unavailable', { cause: error });
  }
  const recovered = recoverExactBootstrap(wallet, sourceFundingRawTxHex);
  const capability = createBootstrapReadyCapability(wallet, recovered.bootstrap);
  return Object.freeze({
    schema: V2_BETA_PRODUCT_POOL_FUNDING_SCHEMA,
    status: 'bootstrap-ready',
    recovered: true,
    configPath: loaded.configPath,
    fundingWallet: projectV2FundingWalletPublic(wallet),
    source: recovered.source,
    capability,
  });
}

/** Test-only transport and deterministic-wallet seam; production has no injected dependencies. */
export async function createV2BetaProductPoolFundingForTest(value = {}, seam = {}) {
  exact(seam, ['assertRpc', 'createRpc', 'createWallet', 'loadWallet', 'persistWallet'], 'pool funding test seam');
  for (const name of ['assertRpc', 'createRpc', 'createWallet', 'loadWallet', 'persistWallet']) {
    if (typeof seam[name] !== 'function') fail('POOL_FUNDING_INVALID', `pool funding test seam ${name} must be a function`);
  }
  return prepare(value, Object.freeze({
    ...seam,
    createConfig: createV2BetaProductConfig,
    loadConfig: loadV2BetaProductConfig,
  }));
}
