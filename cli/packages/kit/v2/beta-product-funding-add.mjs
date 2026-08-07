import { performance } from 'node:perf_hooks';

import { openV2BetaProductContext } from './beta-product-context.mjs';
import {
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from './transaction-policy.mjs';

export const V2_BETA_PRODUCT_FUNDING_ADD_SCHEMA =
  'shieldkit-v2-beta-product-funding-add-v1';

const DECIMAL = /^(0|[1-9][0-9]*)$/u;

export class V2BetaProductFundingAddError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductFundingAddError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductFundingAddError(code, message, options);
};

function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_FUNDING_ADD_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_FUNDING_ADD_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function parseOutpoint(value) {
  if (typeof value !== 'string') {
    fail('BETA_FUNDING_ADD_OUTPOINT_REJECTED', 'fundingUtxo must be txid:vout');
  }
  const match = /^([0-9a-f]{64}):(0|[1-9][0-9]{0,9})$/u.exec(value);
  const vout = match === null ? Number.NaN : Number(match[2]);
  if (match === null || !Number.isSafeInteger(vout) || vout > 0xffff_ffff) {
    fail(
      'BETA_FUNDING_ADD_OUTPOINT_REJECTED',
      'fundingUtxo must be a lowercase txid and canonical uint32 vout',
    );
  }
  return Object.freeze({ txid: match[1], vout });
}

function rawHex(value, expectedTxid) {
  if (typeof value === 'string') return value;
  if (value !== null && typeof value === 'object' && !Array.isArray(value)
    && value.txid === expectedTxid && typeof value.hex === 'string') return value.hex;
  fail('BETA_FUNDING_ADD_RAW_REJECTED', 'provider did not return exact raw transaction bytes');
}

function observedSats(value) {
  if (typeof value?.valueSatoshis === 'string' && DECIMAL.test(value.valueSatoshis)) {
    return value.valueSatoshis;
  }
  if (typeof value?.value === 'number' && Number.isFinite(value.value) && value.value >= 0) {
    const sats = Math.round(value.value * 1e8);
    if (Number.isSafeInteger(sats) && Math.abs((sats / 1e8) - value.value) < 1e-12) {
      return String(sats);
    }
  }
  return null;
}

function observedToken(value) {
  return value?.tokenData ?? value?.token ?? null;
}

function ownsExactOutput(wallets, lockingBytecodeHex, outpoint, valueSats) {
  return wallets.some((wallet) => wallet.lockingBytecodeHex === lockingBytecodeHex
    && (wallet.source === 'funding-keyring'
      || (wallet.source === 'attached-change'
        && wallet.attachedOutpoint?.txid === outpoint.txid
        && wallet.attachedOutpoint?.vout === outpoint.vout
        && wallet.attachedValueSats === valueSats)));
}

function dependenciesForTest(value) {
  exact(value, ['now', 'openContext', 'parseOutput', 'parseRaw'], 'funding-add test dependencies');
  for (const [name, dependency] of Object.entries(value)) {
    if (typeof dependency !== 'function') {
      fail('BETA_FUNDING_ADD_INVALID', `${name} test dependency must be a function`);
    }
  }
  return Object.freeze({ ...value });
}

const productionDependencies = Object.freeze({
  now: () => performance.now(),
  openContext: openV2BetaProductContext,
  parseOutput: parseSerializedSourceOutput,
  parseRaw: parseV2RawTransaction,
});

async function addFunding(value, dependencies) {
  exact(value, ['config', 'fundingUtxo', 'rpc'], 'funding-add options');
  const started = dependencies.now();
  const outpoint = parseOutpoint(value.fundingUtxo);
  const contextStarted = dependencies.now();
  const context = await dependencies.openContext({ config: value.config, rpc: value.rpc });
  const contextOpenMs = dependencies.now() - contextStarted;
  try {
    const active = context.store.activeOperation();
    if (active !== null) {
      fail(
        'BETA_FUNDING_ADD_OPERATION_ACTIVE',
        `funding inventory cannot change while operation ${active.operationId} is active`,
      );
    }
    const tip = context.store.optimisticTip().outpoint;
    if (Buffer.from(tip.txid).toString('hex') === outpoint.txid && tip.vout === outpoint.vout) {
      fail('BETA_FUNDING_ADD_TIP_REJECTED', 'the current pool state tip cannot be a funding UTXO');
    }

    const readStarted = dependencies.now();
    let rawValue; let observed;
    try {
      [rawValue, observed] = await Promise.all([
        context.rpc.getrawtransaction(outpoint.txid, true),
        context.rpc.gettxout(outpoint.txid, outpoint.vout),
      ]);
    } catch (error) {
      fail('BETA_FUNDING_ADD_READ_FAILED', 'exact funding outpoint readback failed', { cause: error });
    }
    let transaction; let sourceOutput;
    try {
      transaction = dependencies.parseRaw(rawHex(rawValue, outpoint.txid));
      const output = transaction.outputs[outpoint.vout];
      sourceOutput = output === undefined
        ? undefined
        : dependencies.parseOutput(output.serializedHex);
    } catch (error) {
      if (error instanceof V2BetaProductFundingAddError) throw error;
      fail('BETA_FUNDING_ADD_RAW_REJECTED', 'funding source transaction is not canonical BCH bytes', { cause: error });
    }
    const valueSats = sourceOutput?.valueSatoshis?.toString();
    if (transaction.txid !== outpoint.txid || sourceOutput === undefined
      || !DECIMAL.test(valueSats ?? '') || sourceOutput.token !== null
      || observed === null || typeof observed !== 'object'
      || observedToken(observed) !== null
      || observedSats(observed) !== valueSats
      || observed.scriptPubKey?.hex !== sourceOutput.lockingBytecodeHex) {
      fail(
        'BETA_FUNDING_ADD_SOURCE_REJECTED',
        'funding outpoint is spent, token-bearing, or differs from exact provider bytes',
      );
    }
    const wallets = context.wallet.spendableFundingWallets();
    if (!ownsExactOutput(wallets, sourceOutput.lockingBytecodeHex, outpoint, valueSats)) {
      fail(
        'BETA_FUNDING_ADD_OWNERSHIP_REJECTED',
        'funding outpoint is not spendable by this pool wallet',
      );
    }
    const readbackMs = dependencies.now() - readStarted;

    const commitStarted = dependencies.now();
    let admission;
    try {
      admission = context.store.admitAvailableFundingUtxo({
        txid: Buffer.from(outpoint.txid, 'hex'),
        vout: outpoint.vout,
        valueSats,
      });
    } catch (error) {
      fail(
        'BETA_FUNDING_ADD_COMMIT_REJECTED',
        'funding admission lost an active-operation race or conflicts with durable inventory',
        { cause: error },
      );
    }
    const localCommitMs = dependencies.now() - commitStarted;
    return Object.freeze({
      schema: V2_BETA_PRODUCT_FUNDING_ADD_SCHEMA,
      status: admission.added
        ? 'funding-utxo-registered-beta-unqualified'
        : 'funding-utxo-already-registered-beta-unqualified',
      profileId: context.identity.profileId,
      instanceId: context.identity.instanceId,
      network: 'chipnet',
      fundingUtxo: Object.freeze({ ...outpoint, valueSats }),
      broadcasted: false,
      confirmed: false,
      productionQualified: false,
      timingsMs: Object.freeze({
        contextOpen: contextOpenMs,
        readback: readbackMs,
        localCommit: localCommitMs,
        commandTotal: dependencies.now() - started,
      }),
    });
  } finally {
    context.close();
  }
}

export async function addV2BetaProductFundingUtxo(value) {
  return addFunding(value, productionDependencies);
}

export async function addV2BetaProductFundingUtxoForTest(value, dependencies) {
  return addFunding(value, dependenciesForTest(dependencies));
}
