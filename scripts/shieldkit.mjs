#!/usr/bin/env node
/**
 * ShieldKit CLI — verbs: init | deposit | transfer | withdraw | recover | doctor
 * Fail-closed: missing required inputs → ok:false, exit ≠ 0 (no false success).
 * Single --mode flag (setupMode). JSON errors only (no raw stacks to users).
 */
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertBroadcastAllowed,
  defaultNetworkName,
  explorerTxUrl,
  resolveNetwork,
  AppKitNetworkError,
  PRODUCT_STATUS,
  productWarnings,
} from '../packages/kit/network.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function flag(name) {
  return process.argv.includes(`--${name}`);
}

/** Single setup mode flag. --setup-mode is a deprecated alias. */
function resolveMode() {
  const mode = arg('mode');
  const legacy = arg('setup-mode');
  if (mode !== undefined && legacy !== undefined && mode !== legacy) {
    failJson('MODE_CONFLICT', 'use only --mode (not both --mode and --setup-mode)', 2, {
      mode,
      setupMode: legacy,
    });
  }
  const value = mode ?? legacy ?? 'development-only';
  if (value !== 'development-only' && value !== 'ceremony-production') {
    failJson('INVALID_MODE', 'mode must be development-only or ceremony-production', 2, { mode: value });
  }
  return {
    mode: value,
    deprecatedSetupModeFlag: legacy !== undefined && mode === undefined,
  };
}

function peekMode() {
  const mode = arg('mode');
  const legacy = arg('setup-mode');
  const value = mode ?? legacy ?? 'development-only';
  if (value !== 'development-only' && value !== 'ceremony-production') return 'development-only';
  return value;
}

function okJson(body, code = 0) {
  const network = arg('network', defaultNetworkName());
  console.log(JSON.stringify({
    ok: true,
    productStatus: PRODUCT_STATUS,
    warnings: productWarnings({ network, setupMode: body.setupMode ?? body.mode ?? peekMode() }),
    ...body,
  }, null, 2));
  process.exit(code);
}

function failJson(code, message, exitCode = 1, extra = {}) {
  console.log(JSON.stringify({
    ok: false,
    productStatus: PRODUCT_STATUS,
    error: { code, message },
    ...extra,
  }, null, 2));
  process.exit(exitCode);
}

function usage() {
  console.log(`ShieldKit — offline BCH shielded pool toolkit

${PRODUCT_STATUS.status}

Verbs (fail-closed without required inputs):
  init       --config <init.json>   run profile.init (dev|ceremony)
  deposit    --bundle <dir> --request <prep.json>
  transfer   --bundle <dir> --request <prep.json>
  withdraw   --bundle <dir> --request <prep.json>
  recover    --bundle <dir> --history <json> --seed-hex <64hex>
  doctor     network / mode / honesty / broadcast gates

Helpers:
  config-check   Offline mainnet broadcast gates
  explorer       --txid <64hex>
  profile-info   --bundle <dir>
  help

Flags:
  --network chipnet|mainnet     (mainnet = one config change; Unaudited WIP)
  --mode development-only|ceremony-production
  --bundle <profile-dir>
  --config <init-config.json>   for init
  --request <prep-request.json> for deposit|transfer|withdraw
  --history <history.json> --seed-hex <64hex>  for recover
  --i-understand-mainnet
  --allow-development-on-mainnet   (lab only)
  --profile-id / --instance-id     optional overrides for profile-info / act

Mainnet: set --network mainnet (+ ceremony mode for production claims).
Broadcast still requires --i-understand-mainnet.

Architecture: packages/{kit,profile,action,prove,recover}
Demo: examples/demo-profile/README.md
`);
}

async function loadJsonFile(filePath, label) {
  if (!filePath) failJson('INPUT_REQUIRED', `${label} is required`, 2);
  const abs = path.resolve(filePath);
  let text;
  try {
    text = await readFile(abs, 'utf8');
  } catch {
    failJson('INPUT_UNREADABLE', `cannot read ${label}: ${abs}`, 2);
  }
  try {
    return JSON.parse(text);
  } catch {
    failJson('INPUT_JSON', `${label} must be valid JSON: ${abs}`, 2);
  }
}

async function openKit() {
  const network = arg('network', defaultNetworkName());
  try {
    resolveNetwork(network);
  } catch (e) {
    failJson(e.code || 'UNKNOWN_NETWORK', e.message, 2);
  }
  const bundle = arg('bundle');
  if (!bundle) failJson('BUNDLE_REQUIRED', '--bundle <profile-bundle-dir> is required', 2);
  const { createKit } = await import('../packages/kit/kit.mjs');
  const { loadVerifierProfileBundle } = await import('../packages/profile/load.mjs');
  const abs = path.resolve(bundle);
  let loaded;
  try {
    loaded = await loadVerifierProfileBundle(abs);
  } catch (e) {
    failJson(e.code || 'BUNDLE_INVALID', e.message || String(e), 2);
  }
  const expectedNetwork = arg('network', loaded.manifest?.network?.name || network);
  try {
    const kit = await createKit({
      network: expectedNetwork,
      bundleDirectory: abs,
      expectedProfile: {
        network: expectedNetwork,
        profileId: arg('profile-id', loaded.profileId),
        instanceId: arg('instance-id', loaded.instanceId),
      },
      mainnetAcknowledged: flag('i-understand-mainnet'),
      allowDevelopmentOnMainnet: flag('allow-development-on-mainnet'),
    });
    return { kit, loaded, network: expectedNetwork };
  } catch (e) {
    failJson(e.code || e.name || 'KIT_ERROR', e.message || String(e), 2);
  }
}

function cmdConfigCheck() {
  let net;
  const network = arg('network', defaultNetworkName());
  try {
    net = resolveNetwork(network);
  } catch (e) {
    failJson(e.code || 'UNKNOWN_NETWORK', e.message, 2);
  }
  const { mode, deprecatedSetupModeFlag } = resolveMode();
  const mainnetAcknowledged = flag('i-understand-mainnet');
  const allowDevelopmentOnMainnet = flag('allow-development-on-mainnet');
  const out = {
    network: net.name,
    networkId: net.networkId,
    cashAddrPrefix: net.cashAddrPrefix,
    explorerTemplate: net.explorerTxTemplate,
    mode,
    setupMode: mode,
    mainnetAcknowledged,
    allowDevelopmentOnMainnet,
    ...(deprecatedSetupModeFlag ? { deprecation: '--setup-mode is deprecated; use --mode' } : {}),
  };
  try {
    const gate = assertBroadcastAllowed({
      network: net.name,
      setupMode: mode,
      mainnetAcknowledged,
      allowDevelopmentOnMainnet,
    });
    okJson({ broadcastAllowed: true, gate, ...out, setupMode: mode });
  } catch (e) {
    failJson(e.code || 'GATE', e.message, e instanceof AppKitNetworkError ? 2 : 1, {
      broadcastAllowed: false,
      ...out,
    });
  }
}

function cmdDoctor() {
  let net;
  try {
    net = resolveNetwork(arg('network', defaultNetworkName()));
  } catch (e) {
    failJson(e.code || 'UNKNOWN_NETWORK', e.message, 2);
  }
  const { mode, deprecatedSetupModeFlag } = resolveMode();
  const report = {
    verbs: ['init', 'deposit', 'transfer', 'withdraw', 'recover', 'doctor'],
    domains: ['kit', 'profile', 'action', 'prove', 'recover', 'mobile'],
    network: net.name,
    mode,
    setupMode: mode,
    honesty: {
      developmentOnlyIsNotProductionPrivacy: true,
      ceremonyRequiredForProductionClaims: true,
      newSetupImpliesNewProfileAndGenesis: true,
      hotSwapForbidden: true,
      mainnetIsOneConfigChange: true,
      mainnetUnauditedWip: true,
    },
    feeSatPerByte: 1,
    unlockMaxBytes: 10000,
    settlementMaxBytes: 59000,
    ...(deprecatedSetupModeFlag ? { deprecation: '--setup-mode is deprecated; use --mode' } : {}),
  };
  let ok = true;
  try {
    assertBroadcastAllowed({
      network: net.name,
      setupMode: mode,
      mainnetAcknowledged: flag('i-understand-mainnet') || net.name !== 'mainnet',
      allowDevelopmentOnMainnet: flag('allow-development-on-mainnet'),
    });
    report.broadcastGate = 'pass-with-current-flags';
  } catch (e) {
    ok = false;
    report.broadcastGate = { code: e.code, message: e.message };
  }
  if (net.name === 'mainnet' && mode === 'development-only' && !flag('allow-development-on-mainnet')) {
    ok = false;
    report.developmentOnMainnet = 'refused without lab override (not production privacy)';
  }
  if (ok) okJson(report);
  else failJson('DOCTOR_FAIL', 'configuration does not pass honesty/broadcast gates', 2, report);
}

function cmdExplorer() {
  const network = arg('network', defaultNetworkName());
  const txid = arg('txid');
  if (!txid) failJson('TXID_REQUIRED', 'required: --txid <64hex>', 2);
  try {
    const url = explorerTxUrl(network, txid);
    // plain URL for scripting convenience
    console.log(url);
    process.exit(0);
  } catch (e) {
    failJson(e.code || 'EXPLORER', e.message, 2);
  }
}

async function cmdProfileInfo() {
  const { kit } = await openKit();
  okJson({
    network: kit.network.name,
    profileId: kit.profile.profileId,
    instanceId: kit.profile.instanceId,
    setupMode: kit.profile.setupMode,
    qualification: kit.qualification,
    methods: [
      'planAction / planCompletePreparation',
      'preparationSigningRequest',
      'finalizeCompletePreparation',
      'planWitnessBoundSettlements',
      'recoverAuthenticatedHistory',
      'broadcastRaw (gated)',
    ],
  });
}

async function cmdInit() {
  const { mode, deprecatedSetupModeFlag } = resolveMode();
  const configPath = arg('config');
  if (!configPath) {
    failJson(
      'CONFIG_REQUIRED',
      'init requires --config <init.json> that matches profile.init input ({ mode, setup, bundle?, load? })',
      2,
      {
        mode,
        api: "import { init } from './packages/profile/init.mjs'",
        example: 'examples/demo-profile/init.example.json',
        note: 'new setup ⇒ new profile + new genesis; no hot-swap',
        ...(deprecatedSetupModeFlag ? { deprecation: '--setup-mode is deprecated; use --mode' } : {}),
      },
    );
  }
  const input = await loadJsonFile(configPath, '--config');
  if (!input.mode) input.mode = mode;
  if (input.mode !== mode && arg('mode')) {
    failJson('MODE_MISMATCH', 'CLI --mode must match config.mode when both set', 2, {
      cliMode: mode,
      configMode: input.mode,
    });
  }
  try {
    const { init } = await import('../packages/profile/init.mjs');
    const result = await init(input);
    okJson({
      verb: 'init',
      mode: result.mode,
      setupDirectory: result.setupDirectory,
      bundleDirectory: result.bundleDirectory,
      profileId: result.profileId,
      instanceId: result.instanceId,
      loaded: Boolean(result.loaded),
    });
  } catch (e) {
    failJson(e.name || 'INIT_FAILED', e.message || String(e), 1);
  }
}

async function cmdAct(verb) {
  const kind = verb; // deposit | transfer | withdrawal mapping
  const requestKind = verb === 'withdraw' ? 'withdrawal' : verb;
  const requestPath = arg('request');
  if (!arg('bundle') || !requestPath) {
    failJson(
      'INPUT_REQUIRED',
      `${verb} requires --bundle <profile-dir> and --request <prep-request.json>`,
      2,
      {
        verb,
        kind: requestKind,
        requestShape: {
          kind: requestKind,
          bindingCarrierBaseValueSatoshis: 'string',
          bindingLockingBytecode: 'hex',
          fundingOutpointIndex: 'string',
          fundingOutpointTransactionHashWire: 'hex',
          fundingPublicKey: 'hex',
          fundingSourceValueSatoshis: 'string',
          settlementFeeFundingSatoshis: 'string',
        },
        next: 'sign preparationSigningRequest.digest; finalizeCompletePreparation; prove; assemble settlement; broadcast via your RPC',
      },
    );
  }
  const { kit } = await openKit();
  const request = await loadJsonFile(requestPath, '--request');
  if (request.kind && request.kind !== requestKind) {
    failJson('KIND_MISMATCH', `request.kind must be ${requestKind} for ${verb}`, 2, {
      requestKind: request.kind,
      expected: requestKind,
    });
  }
  const planInput = { ...request, kind: requestKind };
  try {
    const plan = await kit.planCompletePreparation(planInput);
    const signing = await kit.preparationSigningRequest(planInput);
    okJson({
      verb,
      kind: requestKind,
      network: kit.network.name,
      setupMode: kit.profile.setupMode,
      profileId: kit.profile.profileId,
      instanceId: kit.profile.instanceId,
      plan: {
        // keep output bounded
        keys: plan && typeof plan === 'object' ? Object.keys(plan) : [],
      },
      signingRequest: {
        algorithm: signing.algorithm,
        digestHex: signing.digestHex,
        label: signing.label,
      },
      next: [
        'Sign signingRequest.digestHex with fee key (Schnorr); do not give kit the private key',
        'kit.finalizeCompletePreparation(request, signatureHex)',
        'Local prove (packages/prove) + PF7 unlocks',
        'Assemble settlement (packages/action assembleCompleteSettlement)',
        'kit.broadcastRaw(hex) only after assertCanBroadcast',
      ],
    });
  } catch (e) {
    failJson(e.code || e.name || 'ACT_FAILED', e.message || String(e), 1, { verb });
  }
}

async function cmdRecover() {
  const historyPath = arg('history');
  const seedHex = arg('seed-hex');
  if (!arg('bundle') || !historyPath || !seedHex) {
    failJson(
      'INPUT_REQUIRED',
      'recover requires --bundle <dir> --history <json> --seed-hex <64 hex bytes>',
      2,
      {
        verb: 'recover',
        note: 'seed stays local; kit does not store it',
      },
    );
  }
  if (!/^[0-9a-f]{64}$/i.test(seedHex)) {
    failJson('SEED_FORMAT', '--seed-hex must be 32 bytes lowercase/uppercase hex', 2);
  }
  const { kit } = await openKit();
  const history = await loadJsonFile(historyPath, '--history');
  try {
    const accountSeed = Buffer.from(seedHex.toLowerCase(), 'hex');
    const recovered = await kit.recoverAuthenticatedHistory({
      accountSeed,
      history,
    });
    okJson({
      verb: 'recover',
      network: kit.network.name,
      profileId: kit.profile.profileId,
      instanceId: kit.profile.instanceId,
      resultKeys: recovered && typeof recovered === 'object' ? Object.keys(recovered) : [],
    });
  } catch (e) {
    failJson(e.code || e.name || 'RECOVER_FAILED', e.message || String(e), 1);
  }
}

const cmd = process.argv[2];
if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
  usage();
  process.exit(0);
}

const map = {
  'config-check': cmdConfigCheck,
  explorer: cmdExplorer,
  'profile-info': cmdProfileInfo,
  doctor: cmdDoctor,
  init: cmdInit,
  deposit: () => cmdAct('deposit'),
  transfer: () => cmdAct('transfer'),
  withdraw: () => cmdAct('withdraw'),
  recover: cmdRecover,
};

if (!map[cmd]) {
  failJson('UNKNOWN_COMMAND', `unknown command: ${cmd}`, 64, {
    commands: Object.keys(map).concat(['help']),
  });
}

Promise.resolve(map[cmd]()).catch((e) => {
  failJson(e.code || e.name || 'UNCAUGHT', e.message || String(e), 1);
});
