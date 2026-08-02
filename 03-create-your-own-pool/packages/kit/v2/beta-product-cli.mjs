import path from 'node:path';

import { createLayer1BchnChipnetRpc } from '../chipnet-rpc.mjs';
import {
  loadV2BetaProductConfig,
  toV2BetaProductContextConfig,
} from './beta-product-config.mjs';
import {
  executeV2BetaProductDeposit,
  executeV2BetaProductExactRebroadcastRecovery,
  inspectV2BetaProductRecovery,
  executeV2BetaProductWithdrawal,
} from './beta-product-commands.mjs';

export const V2_BETA_PRODUCT_CLI_SCHEMA =
  'shieldkit-v2-beta-product-cli-result-v1';

export class V2BetaProductCliError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaProductCliError';
    this.code = code;
    this.exitCode = options?.exitCode ?? 2;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaProductCliError(code, message, options);
};

const VALUE_OPTIONS = new Set([
  'attempt-token', 'data-home', 'funding-txid', 'funding-utxo', 'funding-wallet', 'note', 'operation-id', 'to',
]);
const BOOLEAN_OPTIONS = new Set(['acknowledge-exact-rebroadcast', 'human', 'json']);

function parse(tokens) {
  if (!Array.isArray(tokens) || tokens.some((entry) => typeof entry !== 'string')) {
    fail('BETA_CLI_INVALID', 'CLI tokens must be strings');
  }
  const positionals = [];
  const options = Object.create(null);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith('--')) { positionals.push(token); continue; }
    if (token === '--' || token.includes('=')) {
      fail('BETA_CLI_INVALID', 'options require exact --name value syntax');
    }
    const name = token.slice(2);
    if (!VALUE_OPTIONS.has(name) && !BOOLEAN_OPTIONS.has(name)) {
      fail('BETA_CLI_UNKNOWN_OPTION', `unknown beta product option: --${name}`);
    }
    if (Object.hasOwn(options, name)) {
      fail('BETA_CLI_DUPLICATE_OPTION', `--${name} may be supplied only once`);
    }
    if (BOOLEAN_OPTIONS.has(name)) { options[name] = true; continue; }
    const value = tokens[index + 1];
    if (value === undefined || value.startsWith('--')) {
      fail('BETA_CLI_OPTION_VALUE_REQUIRED', `--${name} requires one value`);
    }
    options[name] = value;
    index += 1;
  }
  if (options.human === true && options.json === true) {
    fail('BETA_CLI_FORMAT_CONFLICT', '--human and --json are mutually exclusive');
  }
  let command;
  if (positionals.length === 2 && positionals[0] === 'pool'
    && positionals[1] === 'create') {
    command = 'pool-create';
  } else if (positionals.length === 2 && positionals[0] === 'pool'
    && positionals[1] === 'refresh-runtime') {
    command = 'pool-refresh-runtime';
  } else if (positionals.length === 1 && ['deposit', 'withdraw'].includes(positionals[0])) {
    command = positionals[0];
  } else if (positionals.length === 2
    && positionals[0] === 'recovery' && positionals[1] === 'rebroadcast') {
    command = 'recover-exact-rebroadcast';
  } else if (positionals.length === 2
    && positionals[0] === 'recovery' && positionals[1] === 'inspect') {
    command = 'recovery-inspect';
  } else {
    fail('BETA_CLI_UNKNOWN_COMMAND', 'expected pool create, pool refresh-runtime, deposit, withdraw, recovery inspect, or recovery rebroadcast');
  }
  const allowed = command === 'withdraw'
    ? new Set(['data-home', 'human', 'json', 'note', 'operation-id', 'to'])
    : command === 'deposit'
      ? new Set(['data-home', 'human', 'json', 'operation-id'])
      : command === 'pool-create'
        ? new Set(['data-home', 'funding-txid', 'funding-utxo', 'funding-wallet', 'human', 'json'])
        : command === 'pool-refresh-runtime'
          ? new Set(['data-home', 'human', 'json'])
        : command === 'recovery-inspect'
          ? new Set(['data-home', 'human', 'json', 'operation-id'])
          : new Set([
          'acknowledge-exact-rebroadcast', 'attempt-token', 'data-home',
          'human', 'json', 'operation-id',
        ]);
  for (const name of Object.keys(options)) {
    if (!allowed.has(name)) fail('BETA_CLI_OPTION_NOT_ALLOWED', `--${name} is not allowed for ${command}`);
  }
  if (command === 'withdraw' && options.to === undefined) {
    fail('BETA_WITHDRAWAL_ADDRESS_REQUIRED', 'withdraw requires --to <bchtest P2PKH cash address>');
  }
  if (command === 'recover-exact-rebroadcast') {
    if (options['acknowledge-exact-rebroadcast'] !== true) {
      fail(
        'BETA_EXACT_REBROADCAST_ACK_REQUIRED',
        'recovery rebroadcast requires --acknowledge-exact-rebroadcast',
      );
    }
    if (options['operation-id'] === undefined) {
      fail('BETA_EXACT_REBROADCAST_OPERATION_REQUIRED', 'recovery rebroadcast requires --operation-id');
    }
    if (options['attempt-token'] === undefined
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
        .test(options['attempt-token'])) {
      fail('BETA_EXACT_REBROADCAST_TOKEN_INVALID', 'recovery rebroadcast requires the current --attempt-token UUID');
    }
  }
  if (command === 'recovery-inspect' && options['operation-id'] === undefined) {
    fail('BETA_RECOVERY_INSPECT_OPERATION_REQUIRED', 'recovery inspect requires --operation-id');
  }
  if (options['data-home'] !== undefined
    && (!path.isAbsolute(options['data-home'])
      || path.normalize(options['data-home']) !== options['data-home'])) {
      fail('BETA_CLI_DATA_HOME_REJECTED', '--data-home must be a normalized absolute path');
  }
  if (options['funding-txid'] !== undefined
    && !/^[0-9a-f]{64}$/u.test(options['funding-txid'])) {
    fail('BETA_CLI_FUNDING_TXID_REJECTED', '--funding-txid must be exactly 64 lowercase hexadecimal characters');
  }
  const directFunding = options['funding-wallet'] !== undefined || options['funding-utxo'] !== undefined;
  if (directFunding && (options['funding-wallet'] === undefined || options['funding-utxo'] === undefined)) {
    fail('BETA_CLI_USER_FUNDING_REQUIRED', 'pool create requires both --funding-wallet and --funding-utxo');
  }
  if (directFunding && options['funding-txid'] !== undefined) {
    fail('BETA_CLI_FUNDING_AMBIGUOUS', '--funding-txid cannot be combined with direct user funding');
  }
  if (options['funding-wallet'] !== undefined
    && (!path.isAbsolute(options['funding-wallet'])
      || path.normalize(options['funding-wallet']) !== options['funding-wallet']
      || options['funding-wallet'].includes('\0'))) {
    fail('BETA_CLI_FUNDING_WALLET_REJECTED', '--funding-wallet must be a normalized absolute private wallet path');
  }
  if (options['funding-utxo'] !== undefined
    && !/^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/u.test(options['funding-utxo'])) {
    fail('BETA_CLI_FUNDING_UTXO_REJECTED', '--funding-utxo must be txid:vout with lowercase txid and canonical uint32 vout');
  }
  if (options['funding-utxo'] !== undefined && Number(options['funding-utxo'].slice(65)) > 0xffff_ffff) {
    fail('BETA_CLI_FUNDING_UTXO_REJECTED', '--funding-utxo vout exceeds uint32');
  }
  return Object.freeze({
    command,
    format: options.human === true ? 'human' : 'json',
    options: Object.freeze({ ...options }),
  });
}

export function isV2BetaProductCliInvocation(tokens) {
  if (!Array.isArray(tokens)) return false;
  return (tokens[0] === 'pool' && tokens[1] === 'create')
    || (tokens[0] === 'pool' && tokens[1] === 'refresh-runtime')
    || (tokens[0] === 'recovery' && tokens[1] === 'rebroadcast')
    || (tokens[0] === 'recovery' && tokens[1] === 'inspect')
    || (['deposit', 'withdraw'].includes(tokens[0])
      && !tokens.includes('--protocol'));
}

function productionDependencies() {
  return Object.freeze({
    createRpc: createLayer1BchnChipnetRpc,
    loadConfig: loadV2BetaProductConfig,
    toContextConfig: toV2BetaProductContextConfig,
    deposit: executeV2BetaProductDeposit,
    inspectRecovery: inspectV2BetaProductRecovery,
    recovery: executeV2BetaProductExactRebroadcastRecovery,
    withdrawal: executeV2BetaProductWithdrawal,
    poolCreate: async (value) => {
      const module = await import('./beta-product-pool-create.mjs');
      return module.createV2BetaProductPool(value);
    },
    refreshRuntime: async (value) => {
      const module = await import('./beta-product-runtime-refresh.mjs');
      return module.refreshV2BetaProductRuntime(value);
    },
  });
}

function dependenciesForTest(value) {
  const names = [
    'createRpc', 'deposit', 'inspectRecovery', 'loadConfig', 'poolCreate', 'recovery',
    'refreshRuntime',
    'toContextConfig', 'withdrawal',
  ];
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== [...names].sort().join(',')
    || names.some((name) => typeof value[name] !== 'function')) {
    fail('BETA_CLI_INVALID', 'test dependencies must provide the exact CLI function set');
  }
  return Object.freeze({ ...value });
}

async function execute(tokens, dependencies) {
  const request = parse(tokens);
  const dataHome = request.options['data-home'];
  let result;
  if (request.command === 'pool-create') {
    result = await dependencies.poolCreate(
      Object.freeze({
        ...(dataHome === undefined ? {} : { dataHome }),
        ...(request.options['funding-txid'] === undefined
          ? {} : { fundingTxid: request.options['funding-txid'] }),
        ...(request.options['funding-wallet'] === undefined
          ? {} : { fundingWalletPath: request.options['funding-wallet'] }),
        ...(request.options['funding-utxo'] === undefined
          ? {} : { fundingUtxo: request.options['funding-utxo'] }),
      }),
    );
  } else if (request.command === 'pool-refresh-runtime') {
    result = await dependencies.refreshRuntime(Object.freeze({
      ...(dataHome === undefined ? {} : { dataHome }),
    }));
  } else {
    const [loaded, rpc] = await Promise.all([
      dependencies.loadConfig(dataHome === undefined ? {} : { dataHome }),
      dependencies.createRpc(),
    ]);
    const config = dependencies.toContextConfig(loaded.config);
    result = request.command === 'deposit'
      ? await dependencies.deposit({
        config,
        rpc,
        ...(request.options['operation-id'] === undefined
          ? {} : { operationId: request.options['operation-id'] }),
      })
      : request.command === 'withdraw'
        ? await dependencies.withdrawal({
          config,
          rpc,
          toCashAddress: request.options.to,
          ...(request.options.note === undefined ? {} : { noteId: request.options.note }),
          ...(request.options['operation-id'] === undefined
            ? {} : { operationId: request.options['operation-id'] }),
        })
        : request.command === 'recovery-inspect'
          ? await dependencies.inspectRecovery({
            config,
            operationId: request.options['operation-id'],
            rpc,
          })
          : await dependencies.recovery({
          acknowledgedExactRebroadcast: true,
          config,
          operationId: request.options['operation-id'],
          priorAttemptToken: request.options['attempt-token'],
          rpc,
        });
  }
  return Object.freeze({
    schema: V2_BETA_PRODUCT_CLI_SCHEMA,
    format: request.format,
    command: request.command,
    result,
  });
}

export async function executeV2BetaProductCli(tokens) {
  return execute(tokens, productionDependencies());
}

export async function executeV2BetaProductCliForTest(tokens, dependencies) {
  return execute(tokens, dependenciesForTest(dependencies));
}

export function v2BetaProductCliErrorResult(error) {
  const known = error instanceof V2BetaProductCliError;
  return Object.freeze({
    exitCode: known ? error.exitCode : 1,
    body: Object.freeze({
      ok: false,
      product: 'shieldkit-v2-beta-chipnet',
      productionQualified: false,
      error: Object.freeze({
        code: typeof error?.code === 'string'
          ? error.code : known ? 'BETA_CLI_ERROR' : 'BETA_CLI_UNCAUGHT',
        message: error instanceof Error ? error.message : String(error),
      }),
    }),
  });
}

export function renderV2BetaProductCliHuman(envelope) {
  const result = envelope.result;
  if (envelope.command === 'pool-create') {
    return [
      `ShieldKit V2 beta pool: ${result.status}`,
      result.fundingAddress ?? result.instanceId ?? '',
      ...(typeof result.rerunCommand === 'string'
        ? [`rerun: ${result.rerunCommand}`]
        : []),
    ].filter(Boolean).join('\n');
  }
  if (envelope.command === 'pool-refresh-runtime') {
    return [
      `ShieldKit V2 beta runtime: ${result.status}`,
      `instance: ${result.instanceId}`,
      `cache installed: ${String(result.cacheInstalled)}`,
      `total: ${Number(result.timingsMs?.commandTotal).toFixed(1)} ms`,
    ].join('\n');
  }
  if (envelope.command === 'recovery-inspect') {
    const recovery = result.recovery;
    return [
      `ShieldKit V2 beta recovery: ${result.status}`,
      `operation: ${result.operationId}`,
      `exact rebroadcast available: ${String(recovery.exactRebroadcastAvailable)}`,
      ...(recovery.delivery === null ? [] : [`attempt token: ${recovery.delivery.attemptToken}`]),
    ].join('\n');
  }
  return [
    `ShieldKit V2 beta ${envelope.command}: ${result.status}`,
    `transaction: ${result.transactionId}`,
    `zero-conf accepted; confirmed: false; production qualified: false`,
    `total: ${Number(result.timingsMs?.commandTotal).toFixed(1)} ms`,
  ].join('\n');
}
