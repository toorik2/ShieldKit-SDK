/**
 * PF10 compatibility adapter — routes new grammar into the complete existing
 * PF10 product lifecycle (shieldkit-groth-94kb/scripts/shieldkit.mjs).
 *
 * Does not reimplement prove/admit/send. No parallel send path.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildResultEnvelope } from '../contracts/envelopes.mjs';
import { ERROR_CODES, cliFail } from '../contracts/errors.mjs';
import { NETWORKS } from '../contracts/identity.mjs';
import { capabilitiesForDesign } from '../registry/designs.mjs';
import { readLegacyPf10Pointer } from '../home/resolve.mjs';

const SDK_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PF10_CLI = path.join(SDK_ROOT, 'shieldkit-groth-94kb/scripts/shieldkit.mjs');
const HASH = /^[0-9a-f]{64}$/u;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PRODUCT_BACKENDS = new Set([
  'bchn-chipnet-jsonrpc',
  'layer1-bchn-chipnet',
  'public-chipnet-fulcrum-tls',
]);
const RPC_METHODS = Object.freeze([
  'getblockhash', 'getrawtransaction', 'gettxout', 'scantxoutset',
  'sendrawtransaction', 'testmempoolaccept',
]);
const PUBLIC_RPC_METHODS = Object.freeze([
  'server.features', 'server.version', 'blockchain.transaction.broadcast',
  'blockchain.transaction.get', 'blockchain.utxo.get_info',
  'blockchain.scripthash.listunspent',
]);
const ADMISSION_ROUTES = Object.freeze({
  'fresh-single-pass': Object.freeze({ raw: 1, state: 1, send: 1 }),
  'fresh-reconciled-after-indeterminate-send': Object.freeze({ raw: 2, state: 2, send: 1 }),
  'read-only-reconciliation': Object.freeze({ raw: 1, state: 1, send: 0 }),
  'explicit-rebroadcast-precheck-visible': Object.freeze({ raw: 1, state: 1, send: 0 }),
  'explicit-rebroadcast-single-pass': Object.freeze({ raw: 2, state: 1, send: 1 }),
  'explicit-rebroadcast-reconciled-after-indeterminate-send': Object.freeze({ raw: 3, state: 2, send: 1 }),
});
const ACTION_ROUTES = new Set([
  'fresh-single-pass',
  'fresh-reconciled-after-indeterminate-send',
  'read-only-reconciliation',
]);
const REBROADCAST_ROUTES = new Set([
  'explicit-rebroadcast-precheck-visible',
  'explicit-rebroadcast-single-pass',
  'explicit-rebroadcast-reconciled-after-indeterminate-send',
]);

function exactObject(value, keys) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function exactClaims(value) {
  return exactObject(value, ['broadcasted', 'confirmed', 'mined', 'productionQualified'])
    && value.broadcasted === true
    && value.confirmed === false
    && value.mined === false
    && value.productionQualified === false;
}

function exactAdmissionObservation(value, route, routeMode) {
  const profile = ADMISSION_ROUTES[route];
  const allowed = routeMode === 'rebroadcast' ? REBROADCAST_ROUTES : ACTION_ROUTES;
  if (profile === undefined || !allowed.has(route)
    || !exactObject(value, value?.backend === 'public-chipnet-fulcrum-tls'
      ? ['backend', 'genesis', 'methodCounts', 'physicalMethodCounts']
      : ['backend', 'genesis', 'methodCounts'])
    || !PRODUCT_BACKENDS.has(value.backend)
    || value.genesis !== NETWORKS.chipnet.genesisHash
    || !exactObject(value.methodCounts, RPC_METHODS)) return false;
  const counts = value.methodCounts;
  if (counts.getblockhash !== 0
    || counts.getrawtransaction !== profile.raw
    || counts.gettxout !== profile.state
    || counts.scantxoutset !== 0
    || counts.sendrawtransaction !== profile.send
    || counts.testmempoolaccept !== 0) return false;
  if (value.backend !== 'public-chipnet-fulcrum-tls') {
    return value.physicalMethodCounts === undefined;
  }
  const physical = value.physicalMethodCounts;
  return exactObject(physical, PUBLIC_RPC_METHODS)
    && physical['server.features'] === 0
    && physical['server.version'] === 0
    && physical['blockchain.transaction.broadcast'] === profile.send
    && physical['blockchain.transaction.get'] === profile.raw
    && physical['blockchain.utxo.get_info'] === profile.state
    && physical['blockchain.scripthash.listunspent'] === 0;
}

export function isExactPf10ActionResult(action, kind = null, {
  expectedInstanceId = null,
  expectedOperationId = null,
  routeMode = 'action',
} = {}) {
  const expectedKind = kind === null ? null : (kind === 'withdraw' ? 'withdrawal' : kind);
  const expectedCategoryWire = HASH.test(expectedInstanceId || '')
    ? Buffer.from(expectedInstanceId, 'hex').reverse().toString('hex')
    : null;
  const acceptedKinds = routeMode === 'rebroadcast'
    ? ['deposit', 'withdrawal']
    : ['deposit', 'transfer', 'withdrawal'];
  return exactObject(action, [
    'admissionRoute', 'cache', 'claims', 'kind', 'operationId', 'proof', 'readback',
    'rpcObservation', 'schema', 'status', 'telemetry', 'timingsMs', 'transaction',
    'transactionId', 'vm',
  ])
    && action.schema === 'shieldkit-v2-beta-product-action-result-v3'
    && action?.status === 'accepted-zero-conf-beta-unqualified'
    && (expectedKind === null
      ? acceptedKinds.includes(action?.kind)
      : action?.kind === expectedKind)
    && OPERATION_ID.test(action?.operationId || '')
    && (expectedOperationId === null || action.operationId === expectedOperationId)
    && exactClaims(action.claims)
    && HASH.test(action?.transactionId || '')
    && exactObject(action.cache, ['runtimeManifestSha256', 'runtimeMaterialSha256'])
    && HASH.test(action.cache.runtimeManifestSha256 || '')
    && HASH.test(action.cache.runtimeMaterialSha256 || '')
    && action?.proof?.verified === true
    && action.proof.nativeBackend === 'rapidsnark'
    && HASH.test(action.proof.resultSha256 || '')
    && HASH.test(action.proof.nativeProverSha256 || '')
    && exactObject(action.vm, ['acceptedInputCount', 'allInputsAccepted', 'evidenceHash', 'inputCount'])
    && HASH.test(action.vm.evidenceHash || '')
    && Number.isSafeInteger(action.vm.inputCount)
    && action.vm.inputCount > 0
    && action?.vm?.allInputsAccepted === true
    && action?.vm?.acceptedInputCount === action?.vm?.inputCount
    && exactObject(action.readback, [
      'rawTransactionSha256', 'stateCategoryWire', 'stateCommitmentSha256', 'stateOutpoint',
    ])
    && HASH.test(action?.readback?.rawTransactionSha256 || '')
    && HASH.test(action?.readback?.stateCategoryWire || '')
    && action.readback.stateCategoryWire === expectedCategoryWire
    && HASH.test(action?.readback?.stateCommitmentSha256 || '')
    && exactObject(action.readback.stateOutpoint, ['txid', 'vout'])
    && action?.readback?.stateOutpoint?.txid === action.transactionId
    && action?.readback?.stateOutpoint?.vout === 0
    && exactAdmissionObservation(action.rpcObservation, action.admissionRoute, routeMode)
    && action.telemetry?.schema === 'shieldkit-v2-beta-product-action-telemetry-v1'
    && Number.isFinite(action.timingsMs?.total)
    && action.timingsMs.total >= 0;
}

export function isExactPf10ProductCommandResult(result, kind = null, options = {}) {
  const routeMode = options.routeMode || 'action';
  const expectedCommand = routeMode === 'rebroadcast'
    ? 'recover-exact-rebroadcast'
    : kind;
  const action = result?.action;
  return exactObject(result, [
    'action', 'claims', 'command', 'operationId', 'runtimeWork', 'schema', 'status',
    'telemetry', 'timingsMs', 'transactionId',
  ])
    && result.schema === 'shieldkit-v2-beta-product-command-result-v3'
    && result.command === expectedCommand
    && result.status === 'accepted-zero-conf-beta-unqualified'
    && result.operationId === action?.operationId
    && result.transactionId === action?.transactionId
    && exactClaims(result.claims)
    && JSON.stringify(result.claims) === JSON.stringify(action?.claims)
    && JSON.stringify(result.telemetry) === JSON.stringify(action?.telemetry)
    && isExactPf10ActionResult(action, kind, options);
}

function isExactPoolCreateRpcObservation(value, backend, { resume = false } = {}) {
  if (!exactObject(value, value?.backend === 'public-chipnet-fulcrum-tls'
    ? ['backend', 'genesis', 'methodCounts', 'physicalMethodCounts']
    : ['backend', 'genesis', 'methodCounts'])
    || value.backend !== backend
    || !PRODUCT_BACKENDS.has(value.backend)
    || value.genesis !== NETWORKS.chipnet.genesisHash
    || !exactObject(value.methodCounts, RPC_METHODS)
    || !RPC_METHODS.every((name) => Number.isSafeInteger(value.methodCounts[name])
      && value.methodCounts[name] >= 0)) return false;
  if (!resume) {
    const expectedTma = backend === 'public-chipnet-fulcrum-tls' ? 0 : 2;
    if (value.methodCounts.getblockhash !== 0
      || value.methodCounts.getrawtransaction !== 2
      || value.methodCounts.gettxout !== 1
      || value.methodCounts.scantxoutset !== 0
      || value.methodCounts.sendrawtransaction !== 2
      || value.methodCounts.testmempoolaccept !== expectedTma) return false;
  }
  if (backend !== 'public-chipnet-fulcrum-tls') {
    return value.physicalMethodCounts === undefined;
  }
  const physical = value.physicalMethodCounts;
  if (!exactObject(physical, PUBLIC_RPC_METHODS)
    || !PUBLIC_RPC_METHODS.every((name) => Number.isSafeInteger(physical[name])
      && physical[name] >= 0)) return false;
  return resume
    || (physical['server.features'] === 0
      && physical['server.version'] === 0
      && physical['blockchain.transaction.broadcast'] === 2
      && physical['blockchain.transaction.get'] === 2
      && physical['blockchain.utxo.get_info'] === 1
      && physical['blockchain.scripthash.listunspent'] === 0);
}

export function isExactPf10PoolCreateResult(created, home = null, { resume = false } = {}) {
  const evidence = created?.acceptance?.evidence;
  const source = created?.transactions?.source;
  const genesis = created?.transactions?.genesis;
  return exactObject(created, [
    'acceptance', 'actionFundingOutputs', 'actionFundingSetSha256', 'capacity',
    'claims', 'command', 'genesisTransactionId', 'instanceId', 'operationId',
    'profileId', 'rpcBackend', 'rpcObservation', 'runtimeLinkedDuringCommand',
    'runtimeManifestSha256', 'runtimeMaterialSha256', 'runtimeWork', 'schema',
    'sourceTransactionId', 'status', 'timingsMs', 'transactions',
    'zeroConfEvidenceSha256',
  ])
    && created.schema === 'shieldkit-v2-beta-product-pool-create-result-v1'
    && created?.status === 'accepted-zero-conf-beta-unqualified'
    && created.command === 'pool-create'
    && HASH.test(created?.profileId || '')
    && HASH.test(created?.instanceId || '')
    && OPERATION_ID.test(created?.operationId || '')
    && created.capacity === '100000'
    && HASH.test(created?.sourceTransactionId || '')
    && HASH.test(created?.genesisTransactionId || '')
    && created.sourceTransactionId !== created.genesisTransactionId
    && created.instanceId === Buffer.from(created.sourceTransactionId, 'hex').reverse().toString('hex')
    && HASH.test(created?.zeroConfEvidenceSha256 || '')
    && exactObject(created.transactions, ['genesis', 'source'])
    && exactObject(source, ['rawTransactionSha256', 'serializedBytes', 'transactionId'])
    && source.transactionId === created.sourceTransactionId
    && HASH.test(source.rawTransactionSha256 || '')
    && Number.isSafeInteger(source.serializedBytes)
    && source.serializedBytes > 0
    && exactObject(genesis, [
      'bch2026StandardVmAccepted', 'feeRateSatsPerByte', 'feeSats', 'inputMetrics',
      'serializedBytes', 'transactionId',
    ])
    && genesis.transactionId === created.genesisTransactionId
    && genesis.bch2026StandardVmAccepted === true
    && Number.isSafeInteger(genesis.serializedBytes)
    && genesis.serializedBytes > 0
    && Array.isArray(genesis.inputMetrics)
    && genesis.inputMetrics.length > 0
    && genesis.inputMetrics.every((input) => input?.accepted === true)
    && created?.acceptance?.accepted === true
    && created?.acceptance?.status === 'accepted-zero-conf'
    && created.acceptance.rpcBackend === created.rpcBackend
    && (resume || created.acceptance.operationId === created.operationId)
    && exactObject(evidence, [
      'claims', 'eligibility', 'evidenceSha256', 'genesis', 'instanceId',
      'profileId', 'schema', 'source', 'stateOutput', 'status',
    ])
    && evidence.schema === 'shieldkit-v2-beta-chipnet-deployment-v1-zero-conf-acceptance'
    && evidence.status === 'accepted-zero-conf-beta-unqualified'
    && evidence.profileId === created.profileId
    && evidence.instanceId === created.instanceId
    && evidence.evidenceSha256 === created.zeroConfEvidenceSha256
    && exactClaims(evidence.claims)
    && exactObject(evidence.source, ['rawTransactionSha256', 'transactionId'])
    && evidence.source.transactionId === created.sourceTransactionId
    && evidence.source.rawTransactionSha256 === source.rawTransactionSha256
    && exactObject(evidence.genesis, ['rawTransactionSha256', 'transactionId'])
    && evidence.genesis.transactionId === created.genesisTransactionId
    && HASH.test(evidence.genesis.rawTransactionSha256 || '')
    && exactObject(evidence.stateOutput, ['amount', 'capability', 'category', 'commitmentSha256'])
    && evidence.stateOutput.category === created.sourceTransactionId
    && evidence.stateOutput.amount === '0'
    && evidence.stateOutput.capability === 'mutable'
    && HASH.test(evidence.stateOutput.commitmentSha256 || '')
    && exactClaims(created.claims)
    && created.rpcBackend === created.rpcObservation?.backend
    && isExactPoolCreateRpcObservation(created.rpcObservation, created.rpcBackend, { resume })
    && HASH.test(created.runtimeManifestSha256 || '')
    && HASH.test(created.runtimeMaterialSha256 || '')
    && typeof created.runtimeLinkedDuringCommand === 'boolean'
    && created.actionFundingOutputs === 10
    && HASH.test(created.actionFundingSetSha256 || '')
    && Number.isFinite(created.timingsMs?.commandTotal)
    && created.timingsMs.commandTotal >= 0
    && (!home || (home.profileId === created.profileId && home.instanceId === created.instanceId));
}

export const PF10_BACKEND_ID = 'pf10-v2-beta';

/**
 * Complete product lifecycle verbs the adapter must be able to reach.
 * Grammar mapping → product CLI argv prefix.
 */
export const PF10_LIFECYCLE_VERBS = Object.freeze({
  'design doctor': Object.freeze(['pool', 'doctor']),
  'pool doctor': Object.freeze(['pool', 'doctor']),
  'pool create': Object.freeze(['pool', 'create']),
  'pool create --resume': Object.freeze(['pool', 'create', '--resume']),
  'action deposit': Object.freeze(['pool', 'deposit']),
  'action transfer': Object.freeze(['pool', 'transfer']),
  'action withdraw': Object.freeze(['pool', 'withdraw']),
  'operation rebroadcast': Object.freeze(['pool', 'recover', 'rebroadcast']),
  'operation inspect': Object.freeze(['pool', 'recover', 'inspect']),
  'pool add-funding': Object.freeze(['pool', 'add-funding']),
  'pool refresh-runtime': Object.freeze(['pool', 'refresh-runtime']),
});

/**
 * Re-open the authority-bearing legacy deployment immediately before each
 * PF10 delegation. The immutable unified home is only a binding; the mutable
 * legacy tree remains the product authority until PF10 is natively migrated.
 */
async function deriveCurrentPf10Receipt(value) {
  // Keep design listing and no-instance doctor usable from the packed CLI
  // without eagerly loading the product's proof/runtime dependency graph.
  const { derivePf10LegacyMigrationReceipt } = await import('../home/pf10-context-bridge.mjs');
  return derivePf10LegacyMigrationReceipt(value);
}

export async function revalidatePf10ProductHome(ctx, {
  readPointer = readLegacyPf10Pointer,
  deriveReceipt = deriveCurrentPf10Receipt,
} = {}) {
  if (!ctx.home?.path) return null;
  const pointer = readPointer(ctx.home);
  if (pointer === null) {
    cliFail(
      ERROR_CODES.MIGRATION_REQUIRED,
      'bound PF10 home has no validated legacy product authority; delegation refused',
    );
  }
  const receipt = await deriveReceipt({
    dataHome: pointer.legacyDataHome,
    design: ctx.design,
  });
  const receiptMatches = receipt?.schema === 'shieldkit-pf10-legacy-migration-receipt/v1'
    && receipt.backendId === pointer.backendId
    && receipt.designId === pointer.designId
    && receipt.profileId === pointer.profileId
    && receipt.instanceId === pointer.instanceId
    && receipt.network === pointer.network
    && receipt.genesisDescriptorHash === pointer.genesisDescriptorHash
    && exactObject(receipt.genesisOutpoint, ['txid', 'vout'])
    && receipt.genesisOutpoint.txid === pointer.genesisOutpoint.txid
    && receipt.genesisOutpoint.vout === pointer.genesisOutpoint.vout
    && receipt.sourceDataHome === pointer.legacyDataHome
    && receipt.sourceDataDirectory === pointer.sourceDataDirectory
    && receipt.backendId === ctx.home.backendId
    && receipt.designId === ctx.home.designId
    && receipt.profileId === ctx.home.profileId
    && receipt.instanceId === ctx.home.instanceId
    && receipt.network === ctx.home.network
    && receipt.genesisDescriptorHash === ctx.home.genesisDescriptorHash;
  if (!receiptMatches) {
    cliFail(
      ERROR_CODES.MIGRATION_REQUIRED,
      'PF10 legacy authority changed since this unified home was imported; delegation refused before any product or network call',
    );
  }
  return Object.freeze({
    dataHome: pointer.legacyDataHome,
    pointer,
    receipt,
  });
}

export async function productDataHomeFromContext(ctx, dependencies = {}) {
  return (await revalidatePf10ProductHome(ctx, dependencies))?.dataHome ?? null;
}

/**
 * Invoke the real PF10 product CLI. Always the shipped binary path.
 */
export function runPf10Cli(args, { env = process.env } = {}) {
  if (!existsSync(PF10_CLI)) {
    return {
      ok: false,
      code: ERROR_CODES.INTERNAL,
      error: 'PF10 product CLI missing',
      status: 2,
      argv: args,
      cliPath: PF10_CLI,
    };
  }
  const result = spawnSync(process.execPath, [PF10_CLI, ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...env },
  });
  let envelope = null;
  try {
    envelope = JSON.parse(result.stdout || '{}');
  } catch {
    envelope = {
      ok: false,
      error: result.stderr?.slice(0, 800) || result.stdout?.slice(0, 800) || `exit ${result.status}`,
    };
  }
  return {
    ok: envelope.ok === true,
    envelope,
    status: result.status,
    stderr: result.stderr,
    stdout: result.stdout,
    argv: args,
    cliPath: PF10_CLI,
    delegated: true,
    parallelSendPath: false,
  };
}

function identityFromCtx(ctx, extra = {}) {
  const identity = {
    backendId: PF10_BACKEND_ID,
    instanceId: extra.instanceId ?? ctx.home?.instanceId ?? null,
    homeId: ctx.home?.homeId ?? null,
    operationId: extra.operationId ?? null,
    network: ctx.design.network,
  };
  const profileId = extra.profileId ?? ctx.home?.profileId ?? ctx.design?.profileId;
  if (typeof profileId === 'string') {
    identity.profileId = profileId;
    identity.profileStatus = 'frozen';
  } else {
    identity.profileStatus = ctx.design?.profileStatus || 'unselected';
  }
  return identity;
}

/**
 * Always delegates to product `pool doctor` (local-ok without data-home).
 */
export async function pf10Doctor(ctx, command = 'design doctor', dependencies = {}) {
  if (command === 'pool doctor' && !ctx.home) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: 'pool doctor requires a validated PF10 --home; use design doctor for a no-instance wiring check',
      command,
      identity: identityFromCtx(ctx),
      result: { delegated: false, instanceObserved: false },
    });
  }
  const { run = runPf10Cli, ...authorityDependencies } = dependencies;
  const caps = capabilitiesForDesign(ctx.design);
  const dataHome = await productDataHomeFromContext(ctx, authorityDependencies);
  const args = ['pool', 'doctor', '--json'];
  if (dataHome) args.push('--data-home', dataHome);
  const product = run(args, { env: ctx.env || process.env });
  return buildResultEnvelope({
    ok: product.ok,
    code: product.ok ? null : (product.envelope?.code || ERROR_CODES.INTERNAL),
    error: product.ok ? null : (product.envelope?.error || product.error || 'doctor failed'),
    command,
    identity: identityFromCtx(ctx),
    result: {
      backend: PF10_BACKEND_ID,
      capabilities: caps,
      productDoctor: product.envelope,
      dataHome,
      delegated: true,
      delegatedArgv: product.argv,
      cliPath: product.cliPath,
      parallelSendPath: false,
      lifecycleVerb: command,
      notes: command === 'design doctor'
        ? 'PF10 design doctor delegates to the product local wiring check'
        : 'PF10 pool doctor delegates through the bound-home legacy pointer',
    },
  });
}

/**
 * The product has no instance-status command. Never relabel its local doctor as
 * an on-chain pool observation.
 */
export async function pf10PoolStatus(ctx, dependencies = {}) {
  const dataHome = await productDataHomeFromContext(ctx, dependencies);
  if (!dataHome) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: 'pool status requires a bound --home with a validated PF10 legacy pointer; design doctor is the no-instance check',
      command: 'pool status',
      identity: identityFromCtx(ctx),
      result: { delegated: false, instanceObserved: false },
    });
  }
  return buildResultEnvelope({
    ok: false,
    code: ERROR_CODES.CAPABILITY_BLOCKED,
    error: 'PF10 pool status is blocked until canonical instance observation is implemented; pool doctor is only a local wiring check',
    command: 'pool status',
    identity: identityFromCtx(ctx),
    result: {
      dataHome,
      delegated: false,
      instanceObserved: false,
      parallelSendPath: false,
      capabilities: capabilitiesForDesign(ctx.design),
    },
    deprecation: ctx.deprecation,
  });
}

/**
 * Mutating actions always spawn the product CLI through a freshly revalidated
 * migrated home. Missing or stale authority fails before delegation.
 */
export async function pf10Action(ctx, kind, dependencies = {}) {
  const { run = runPf10Cli, ...authorityDependencies } = dependencies;
  const dataHome = await productDataHomeFromContext(ctx, authorityDependencies);
  if (!dataHome) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: `PF10 action ${kind} requires a validated migrated --home (no synthetic accept and no direct legacy data-home)`,
      command: `action ${kind}`,
      identity: identityFromCtx(ctx),
      result: {
        delegated: false,
        reason: 'missing data-home',
        wouldDelegateArgv: PF10_LIFECYCLE_VERBS[`action ${kind}`],
        parallelSendPath: false,
      },
    });
  }

  const args = ['pool', kind, '--data-home', dataHome, '--json'];
  if (ctx.flags.operationId) args.push('--operation-id', ctx.flags.operationId);
  if (kind === 'withdraw' && ctx.flags.to) args.push('--to', ctx.flags.to);
  if ((kind === 'transfer' || kind === 'withdraw') && ctx.flags.note) {
    args.push('--note', ctx.flags.note);
  }

  const r = run(args, { env: ctx.env || process.env });
  const productResult = r.envelope?.result;
  const action = productResult?.action;
  const txid = action?.transactionId ?? action?.acceptedTxid ?? null;
  const operationId = action?.operationId ?? null;
  const exactZeroConf = r.ok && isExactPf10ProductCommandResult(productResult, kind, {
    expectedInstanceId: ctx.home.instanceId,
    expectedOperationId: ctx.flags.operationId ?? null,
    routeMode: 'action',
  });

  return buildResultEnvelope({
    ok: exactZeroConf,
    code: exactZeroConf ? null : (r.envelope?.code || r.envelope?.error?.code || ERROR_CODES.INTERNAL),
    error: exactZeroConf ? null : (r.ok
      ? 'PF10 backend returned success without its exact accepted-zero-conf result contract'
      : (r.envelope?.error?.message || r.envelope?.error || 'action failed')),
    command: `action ${kind}`,
    identity: identityFromCtx(ctx, { operationId }),
    operationState: exactZeroConf ? 'accepted-zero-conf' : null,
    result: {
      dataHome,
      transactionId: txid,
      product: r.envelope,
      delegated: true,
      delegatedArgv: r.argv,
      cliPath: r.cliPath,
      parallelSendPath: false,
      lifecycleVerb: `action ${kind}`,
    },
    deprecation: ctx.deprecation,
  });
}

export function pf10PoolCreate(ctx, { run = runPf10Cli } = {}) {
  if (ctx.home) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.CAPABILITY_BLOCKED,
      error: 'pool create cannot run through an existing bound home; new and resumed transitional creates require an explicit legacy --data-home',
      command: 'pool create',
      identity: identityFromCtx(ctx),
      result: { delegated: false, newHomeBindingRequired: true },
    });
  }
  if (ctx.flags.home && !ctx.home) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: 'pool create will not reinterpret a new --home as legacy PF10 --data-home; migrate or bind a home explicitly first',
      command: 'pool create',
      identity: identityFromCtx(ctx),
      result: { delegated: false, newHomeBindingRequired: true },
    });
  }
  const dataHome = ctx.flags?.dataHome ? path.resolve(ctx.flags.dataHome) : null;
  if (!dataHome) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: 'pool create requires an explicit legacy --data-home; it never creates or resumes through a bound unified home',
      command: 'pool create',
      identity: identityFromCtx(ctx),
      result: { delegated: false, newHomeBindingRequired: true },
    });
  }
  const args = ['pool', 'create', '--json'];
  args.push('--data-home', path.resolve(dataHome));
  if (ctx.flags.fundingWallet) args.push('--funding-wallet', ctx.flags.fundingWallet);
  if (ctx.flags.fundingUtxo) args.push('--funding-utxo', ctx.flags.fundingUtxo);
  if (ctx.flags.resume) args.push('--resume');

  // Without funding inputs product will fail closed — still real delegation
  const r = run(args, { env: ctx.env || process.env });
  const created = r.envelope?.result;
  const exactZeroConf = r.ok && isExactPf10PoolCreateResult(created, null, {
    resume: ctx.flags.resume === true,
  });
  return buildResultEnvelope({
    ok: exactZeroConf,
    code: exactZeroConf ? null : (r.envelope?.error?.code || ERROR_CODES.INTERNAL),
    error: exactZeroConf ? null : (r.ok
      ? 'PF10 backend returned success outside its exact accepted-zero-conf pool-create contract'
      : (r.envelope?.error?.message || r.envelope?.error || 'create failed')),
    command: 'pool create',
    identity: identityFromCtx(ctx, exactZeroConf ? {
      profileId: created.profileId,
      instanceId: created.instanceId,
      operationId: created.operationId,
    } : {}),
    operationState: exactZeroConf ? 'accepted-zero-conf' : null,
    result: {
      transactionId: created?.genesisTransactionId ?? null,
      product: r.envelope,
      delegated: true,
      delegatedArgv: r.argv,
      cliPath: r.cliPath,
      parallelSendPath: false,
      lifecycleVerb: 'pool create',
    },
  });
}

/**
 * Recover/inspect/rebroadcast — product pool recover * path.
 */
export async function pf10Operation(ctx, command, dependencies = {}) {
  const { run = runPf10Cli, ...authorityDependencies } = dependencies;
  const dataHome = await productDataHomeFromContext(ctx, authorityDependencies);
  if (!dataHome) {
    return buildResultEnvelope({
      ok: false,
      code: ERROR_CODES.HOME_NOT_FOUND,
      error: `PF10 operation ${command} requires a validated migrated --home`,
      command: `operation ${command}`,
      identity: identityFromCtx(ctx),
      result: {
        wouldDelegateArgv: PF10_LIFECYCLE_VERBS[`operation ${command}`] || null,
        delegated: false,
        parallelSendPath: false,
      },
    });
  }
  const args = ['pool', 'recover', command, '--data-home', dataHome, '--json'];
  if (command === 'rebroadcast') {
    if (ctx.flags.acknowledgeRebroadcast) {
      args.push('--acknowledge-exact-rebroadcast');
    }
    if (ctx.flags.casToken) args.push('--attempt-token', ctx.flags.casToken);
    if (ctx.flags.operationId) args.push('--operation-id', ctx.flags.operationId);
  }
  if (ctx.flags.operationId && command === 'inspect') {
    args.push('--operation-id', ctx.flags.operationId);
  }
  const r = run(args, { env: ctx.env || process.env });
  const productResult = r.envelope?.result;
  const operationId = productResult?.operationId ?? ctx.flags.operationId ?? null;
  const operationMatches = OPERATION_ID.test(operationId || '')
    && operationId === ctx.flags.operationId;
  const action = productResult?.action;
  const rebroadcastAccepted = command === 'rebroadcast'
    && r.ok
    && operationMatches
    && isExactPf10ProductCommandResult(productResult, null, {
      expectedInstanceId: ctx.home.instanceId,
      expectedOperationId: operationId,
      routeMode: 'rebroadcast',
    })
    && action?.operationId === operationId
    && productResult?.transactionId === action.transactionId;
  const inspectAccepted = command === 'inspect'
    && r.ok
    && operationMatches
    && productResult?.status === 'recovery-inspected-beta-unqualified'
    && productResult?.recovery?.operationId === operationId;
  const exactResult = inspectAccepted || rebroadcastAccepted;
  return buildResultEnvelope({
    ok: exactResult,
    code: exactResult ? null : (r.envelope?.error?.code || ERROR_CODES.INTERNAL),
    error: exactResult ? null : (r.ok
      ? `PF10 backend returned success outside its exact ${command} contract`
      : (r.envelope?.error?.message || r.envelope?.error || 'operation failed')),
    command: `operation ${command}`,
    identity: identityFromCtx(ctx, { operationId: operationMatches ? operationId : null }),
    operationState: rebroadcastAccepted ? 'accepted-zero-conf' : null,
    result: {
      product: r.envelope,
      delegated: true,
      delegatedArgv: r.argv,
      parallelSendPath: false,
    },
  });
}

/** Structural: every lifecycle verb has a product argv mapping. */
export function listDelegatedLifecycleVerbs() {
  return Object.freeze(
    Object.entries(PF10_LIFECYCLE_VERBS).map(([grammar, argv]) => Object.freeze({
      grammar,
      productArgv: argv,
      cliPath: PF10_CLI,
      cliExists: existsSync(PF10_CLI),
    })),
  );
}
