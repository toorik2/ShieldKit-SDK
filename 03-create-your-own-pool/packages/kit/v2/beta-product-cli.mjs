import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { createPublicChipnetFulcrumRpc } from '../chipnet-rpc.mjs';
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
  'attempt-token', 'data-home', 'funding-utxo', 'funding-wallet', 'note', 'operation-id', 'to',
]);
const BOOLEAN_OPTIONS = new Set(['acknowledge-exact-rebroadcast', 'human', 'json', 'resume']);
const AUTOMATIC_READ_ONLY_RECOVERY_ATTEMPTS = 4;
const TRANSIENT_READBACK_ERRORS = new Set([
  'ADMISSION_RAW_READBACK_FAILED',
  'ADMISSION_STATE_READBACK_FAILED',
]);

function withRecoveryIdentity(error, operationId, transactionId) {
  if (error?.operationId === operationId
    && (transactionId === undefined || error?.transactionId === transactionId)) return error;
  const wrapped = new V2BetaProductCliError(
    typeof error?.code === 'string' ? error.code : 'BETA_READ_ONLY_RECOVERY_FAILED',
    error instanceof Error ? error.message : String(error),
    { cause: error, exitCode: 1 },
  );
  wrapped.operationId = operationId;
  if (typeof transactionId === 'string') wrapped.transactionId = transactionId;
  return wrapped;
}

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
        ? new Set(['data-home', 'funding-utxo', 'funding-wallet', 'human', 'json', 'resume'])
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
  const directFunding = options['funding-wallet'] !== undefined || options['funding-utxo'] !== undefined;
  if (directFunding && (options['funding-wallet'] === undefined || options['funding-utxo'] === undefined)) {
    fail('BETA_CLI_USER_FUNDING_REQUIRED', 'pool create requires both --funding-wallet and --funding-utxo');
  }
  const resumePoolCreate = options.resume === true;
  if (command === 'pool-create' && resumePoolCreate && directFunding) {
    fail('BETA_CLI_FUNDING_AMBIGUOUS', 'pool create --resume cannot accept a new funding wallet or outpoint');
  }
  if (command === 'pool-create' && !resumePoolCreate && !directFunding) {
    fail('BETA_CLI_USER_FUNDING_REQUIRED', 'new pool creation requires --funding-wallet and --funding-utxo in the same invocation; use --resume only for an existing durable create operation');
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
    createRpc: createPublicChipnetFulcrumRpc,
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
  const commandStarted = performance.now();
  const request = parse(tokens);
  const dataHome = request.options['data-home'];
  let result;
  if (request.command === 'pool-create') {
    result = await dependencies.poolCreate(
      Object.freeze({
        ...(dataHome === undefined ? {} : { dataHome }),
        ...(request.options['funding-wallet'] === undefined
          ? {} : { fundingWalletPath: request.options['funding-wallet'] }),
        ...(request.options['funding-utxo'] === undefined
          ? {} : { fundingUtxo: request.options['funding-utxo'] }),
        ...(request.options.resume === true ? { resume: true } : {}),
      }),
    );
  } else if (request.command === 'pool-refresh-runtime') {
    result = await dependencies.refreshRuntime(Object.freeze({
      ...(dataHome === undefined ? {} : { dataHome }),
    }));
  } else {
    // Validate the local product boundary before opening sockets. The initial
    // capability owns the only possible send. Bounded recovery capabilities
    // are fresh read-only connections and every capability is always closed.
    const loaded = await dependencies.loadConfig(dataHome === undefined ? {} : { dataHome });
    const config = dependencies.toContextConfig(loaded.config);
    let rpc = await dependencies.createRpc();
    const executeNetworkCommand = async (operationIdOverride = undefined) => request.command === 'deposit'
      ? dependencies.deposit({
        config,
        rpc,
        ...((operationIdOverride ?? request.options['operation-id']) === undefined
          ? {} : { operationId: operationIdOverride ?? request.options['operation-id'] }),
      })
      : request.command === 'withdraw'
        ? dependencies.withdrawal({
          config,
          rpc,
          toCashAddress: request.options.to,
          ...(request.options.note === undefined ? {} : { noteId: request.options.note }),
          ...((operationIdOverride ?? request.options['operation-id']) === undefined
            ? {} : { operationId: operationIdOverride ?? request.options['operation-id'] }),
        })
        : request.command === 'recovery-inspect'
          ? dependencies.inspectRecovery({
            config,
            operationId: request.options['operation-id'],
            rpc,
          })
          : dependencies.recovery({
            acknowledgedExactRebroadcast: true,
            config,
            operationId: request.options['operation-id'],
            priorAttemptToken: request.options['attempt-token'],
            rpc,
          });
    try {
      try {
        result = await executeNetworkCommand();
      } catch (error) {
        const recoverableAction = ['deposit', 'withdraw'].includes(request.command)
          && error?.code === 'ADMISSION_SEND_INDETERMINATE'
          && typeof error?.operationId === 'string';
        if (!recoverableAction) throw error;
        // The original lifecycle already durably recorded its one send. Close
        // every first-pass socket, open a fresh set of the same pinned public
        // providers, and resume the exact operation. Resume is read-only for
        // an indeterminate delivery record and can never broadcast again.
        let lastError = error;
        for (let attempt = 0; attempt < AUTOMATIC_READ_ONLY_RECOVERY_ATTEMPTS; attempt += 1) {
          try { await rpc?.close?.(); } catch { /* recovery opens an independent capability */ }
          rpc = await dependencies.createRpc();
          try {
            const recovered = await executeNetworkCommand(error.operationId);
            result = Object.freeze({
              ...recovered,
              timingsMs: Object.freeze({
                ...recovered.timingsMs,
                commandTotal: performance.now() - commandStarted,
              }),
            });
            break;
          } catch (recoveryError) {
            lastError = recoveryError;
            if (!TRANSIENT_READBACK_ERRORS.has(recoveryError?.code)) {
              throw withRecoveryIdentity(
                recoveryError,
                error.operationId,
                error.transactionId,
              );
            }
          }
        }
        if (result === undefined) {
          throw withRecoveryIdentity(
            lastError,
            error.operationId,
            error.transactionId,
          );
        }
      }
    } finally {
      try { await rpc?.close?.(); } catch { /* preserve the command result/error */ }
    }
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
        ...(typeof error?.operationId === 'string'
          ? {
            operationId: error.operationId,
            ...(typeof error?.transactionId === 'string'
              ? { transactionId: error.transactionId } : {}),
            recovery: 'rerun the same action with --operation-id; it reconciles read-only and never automatically resends',
          }
          : {}),
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
