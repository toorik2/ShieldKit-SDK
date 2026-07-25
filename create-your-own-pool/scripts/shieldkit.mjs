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
import { TOOLKIT_VERSION, toolkitIdentity } from '../version.mjs';

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
    toolkitVersion: TOOLKIT_VERSION,
    productStatus: PRODUCT_STATUS,
    warnings: productWarnings({ network, setupMode: body.setupMode ?? body.mode ?? peekMode() }),
    ...body,
  }, null, 2));
  process.exit(code);
}

function failJson(code, message, exitCode = 1, extra = {}) {
  console.log(JSON.stringify({
    ok: false,
    toolkitVersion: TOOLKIT_VERSION,
    productStatus: PRODUCT_STATUS,
    error: { code, message },
    ...extra,
  }, null, 2));
  process.exit(exitCode);
}

function usage() {
  console.log(`ShieldKit toolkit v${TOOLKIT_VERSION} — create and run your own BCH shielded pool

${PRODUCT_STATUS.status} · maturity: ${PRODUCT_STATUS.maturityLabel}
${PRODUCT_STATUS.note}

Product tree: create-your-own-pool/  (kit · profile · CLI)
Optional demo: use-chipnet-demo-pool/   (live Chipnet instance)

  # Create and operate your pool
  init --config create-your-own-pool/templates/init.development.json
  request-template --kind deposit --bundle <profile-dir>
  genesis-plan --bundle <dir> --category-input <json>
  genesis-finalize --bundle <dir> --category-input <json> --signature <64hex>
  deposit|transfer|withdraw --bundle <your-pool> --request <prep.json>
  recover --bundle <your-pool> --history <json> --seed-hex <64hex>
  doctor | profile-info | config-check | explorer

  # Optional live demo
  playground doctor|profile-info|request-template|deposit|transfer|withdraw|recover
  (npm run fetch-playground-bundle  or  SHIELDKIT_PLAYGROUND_BUNDLE)

Flags:
  --version
  --network chipnet|mainnet
  --mode development-only|ceremony-production
  --bundle <profile-dir>
  --config / --request / --history / --seed-hex / --kind / --category-input / --signature
  --verify-ptau   (init) force full snarkjs powersoftau verify; default may hash-only trusted Hermez pin
  --i-understand-mainnet
  --allow-development-on-mainnet

Docs: create-your-own-pool/docs/VERSIONING.md · PROFILES.md · CHARTER.md
`);
}

/** When true, openKit uses use-chipnet-demo-pool instance. */
function playgroundMode() {
  return process.argv[2] === 'playground' || flag('playground');
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
  const { createKit } = await import('../packages/kit/kit.mjs');
  const extra = {
    mainnetAcknowledged: flag('i-understand-mainnet'),
    allowDevelopmentOnMainnet: flag('allow-development-on-mainnet'),
  };

  if (playgroundMode()) {
    try {
      const { loadInstance, instanceToKitConfig } = await import('../packages/profile/instance.mjs');
      const instance = await loadInstance('use-chipnet-demo-pool', {
        bundleDirectory: arg('bundle') || undefined,
      });
      const kit = await createKit(instanceToKitConfig(instance, extra));
      return {
        kit,
        loaded: instance.loaded,
        network: instance.network,
        instance,
      };
    } catch (e) {
      failJson(e.code || e.name || 'PLAYGROUND_ERROR', e.message || String(e), 2, {
        hint: 'npm run fetch-playground-bundle  or  SHIELDKIT_PLAYGROUND_BUNDLE',
        docs: 'use-chipnet-demo-pool/README.md',
      });
    }
  }

  const network = arg('network', defaultNetworkName());
  try {
    resolveNetwork(network);
  } catch (e) {
    failJson(e.code || 'UNKNOWN_NETWORK', e.message, 2);
  }
  const bundle = arg('bundle');
  if (!bundle) {
    failJson('BUNDLE_REQUIRED', '--bundle <profile-bundle-dir> is required (or: shieldkit playground …)', 2);
  }
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
      ...extra,
    });
    return { kit, loaded, network: expectedNetwork };
  } catch (e) {
    failJson(e.code || e.name || 'KIT_ERROR', e.message || String(e), 2);
  }
}

async function cmdPlaygroundDoctor() {
  try {
    const { loadInstance } = await import('../packages/profile/instance.mjs');
    const instance = await loadInstance('use-chipnet-demo-pool', {
      loadBundle: false,
    });
    let bundleOk = false;
    let bundleError = null;
    let kitInfo = null;
    try {
      const full = await loadInstance('use-chipnet-demo-pool', {
        bundleDirectory: arg('bundle') || undefined,
      });
      bundleOk = true;
      const { createKit } = await import('../packages/kit/kit.mjs');
      const { instanceToKitConfig } = await import('../packages/profile/instance.mjs');
      const kit = await createKit(instanceToKitConfig(full, {
        mainnetAcknowledged: flag('i-understand-mainnet'),
        allowDevelopmentOnMainnet: flag('allow-development-on-mainnet'),
      }));
      kitInfo = {
        profileId: kit.profile.profileId,
        instanceId: kit.profile.instanceId,
        setupMode: kit.profile.setupMode,
        network: kit.network.name,
      };
    } catch (e) {
      bundleError = { code: e.code || e.name, message: e.message };
    }
    const body = {
      ...toolkitIdentity(),
      story: 'ShieldKit creates shielded pools. Demo is use-chipnet-demo-pool/; product is create-your-own-pool/.',
      product: 'create-your-own-pool/',
      playgroundRole: 'optional-demo-not-hosted-service',
      maturityDisclaimer: [
        'Unaudited — Work In Progress',
        'development-only demo is not production privacy',
        'toolkitVersion does not certify profile or instance',
      ],
      instance: {
        id: instance.id,
        network: instance.network,
        profileId: instance.profileId,
        instanceId: instance.instanceId,
        setupMode: instance.setupMode,
        role: instance.role,
        stateNftCategory: instance.stateNftCategory,
      },
      bundleOk,
      bundleError,
      kit: kitInfo,
      next: bundleOk
        ? [
          'optional: playground deposit --request prep.json (learn the flow)',
          'product: create-your-own-pool/ — init + genesis',
          'You supply RPC, fees, proofs, broadcast',
        ]
        : [
          'npm run fetch-playground-bundle  (or SHIELDKIT_PLAYGROUND_BUNDLE)',
          'or skip demo: create-your-own-pool/ — init template',
        ],
    };
    if (bundleOk) okJson(body);
    else failJson('PLAYGROUND_BUNDLE_MISSING', bundleError?.message || 'bundle not loaded', 2, body);
  } catch (e) {
    failJson(e.code || e.name || 'PLAYGROUND_ERROR', e.message || String(e), 2);
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
    ...toolkitIdentity(),
    verbs: ['init', 'deposit', 'transfer', 'withdraw', 'recover', 'doctor'],
    domains: ['kit', 'profile', 'action', 'prove', 'recover'],
    network: net.name,
    mode,
    setupMode: mode,
    maturityDisclaimer: [
      'Unaudited — Work In Progress',
      'toolkitVersion is code only — not profile/instance identity or privacy qualification',
      'maturity labels are charter claims, never inferred from semver',
    ],
    honesty: {
      developmentOnlyIsNotProductionPrivacy: true,
      ceremonyRequiredForProductionClaims: true,
      newSetupImpliesNewProfileAndGenesis: true,
      hotSwapForbidden: true,
      mainnetIsOneConfigChange: true,
      mainnetUnauditedWip: true,
      toolkitVersionIsNotProfileMatch: true,
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
    ...toolkitIdentity(),
    network: kit.network.name,
    profileId: kit.profile.profileId,
    instanceId: kit.profile.instanceId,
    setupMode: kit.profile.setupMode,
    qualification: kit.qualification,
    maturityDisclaimer: [
      'Unaudited — Work In Progress',
      'profileId/instanceId are content hashes — independent of toolkitVersion',
      'setupMode development-only is not production privacy',
    ],
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
        api: "import { init } from './create-your-own-pool/packages/profile/init.mjs'",
        template: 'create-your-own-pool/templates/init.development.json',
        note: 'new setup ⇒ new profile + new genesis; no hot-swap',
        path: 'create-your-own-pool/',
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
  // Force full snarkjs powersoftau verify (slow). Default development path may hash-only trusted Hermez pins.
  if (flag('verify-ptau')) {
    if (!input.setup || typeof input.setup !== 'object') {
      failJson('SETUP_REQUIRED', '--verify-ptau requires config.setup object', 2);
    }
    input.setup = { ...input.setup, verifyPtau: true };
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
      ptauVerification: result.setupMetadata?.inputs?.ptau?.verification
        ?? result.setupMetadata?.setup?.material?.phase1?.verification
        ?? null,
    });
  } catch (e) {
    failJson(e.name || 'INIT_FAILED', e.message || String(e), 1);
  }
}

async function cmdAct(verb) {
  const kind = verb; // deposit | transfer | withdrawal mapping
  const requestKind = verb === 'withdraw' ? 'withdrawal' : verb;
  const requestPath = arg('request');
  const hasPool = playgroundMode() || arg('bundle');
  if (!hasPool || !requestPath) {
    failJson(
      'INPUT_REQUIRED',
      playgroundMode()
        ? `${verb} requires --request <prep-request.json> (playground instance; set SHIELDKIT_PLAYGROUND_BUNDLE)`
        : `${verb} requires --bundle <profile-dir> and --request <prep-request.json> (or: playground ${verb})`,
      2,
      {
        verb,
        kind: requestKind,
        path: playgroundMode() ? 'optional-example-playground' : 'your-pool',
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
  // Accept common aliases: withdraw → withdrawal
  const rawKind = request.kind;
  const normalizedKind = rawKind === 'withdraw' ? 'withdrawal' : rawKind;
  if (normalizedKind && normalizedKind !== requestKind) {
    failJson('KIND_MISMATCH', `request.kind must be ${requestKind} for ${verb} (alias: withdraw→withdrawal)`, 2, {
      requestKind: rawKind,
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
  if ((!playgroundMode() && !arg('bundle')) || !historyPath || !seedHex) {
    failJson(
      'INPUT_REQUIRED',
      playgroundMode()
        ? 'recover requires --history <json> --seed-hex <64 hex> (playground; fetch-playground-bundle or SHIELDKIT_PLAYGROUND_BUNDLE)'
        : 'recover requires --bundle <dir> --history <json> --seed-hex <64 hex bytes>',
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

/**
 * Emit a prep-request skeleton with binding lock filled from the loaded profile.
 * Usage: request-template --kind deposit|transfer|withdrawal [--bundle … | playground]
 */
async function cmdRequestTemplate() {
  const kindRaw = arg('kind', 'deposit');
  const kind = kindRaw === 'withdraw' ? 'withdrawal' : kindRaw;
  if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) {
    failJson('KIND_REQUIRED', '--kind must be deposit|transfer|withdrawal (alias withdraw)', 2);
  }
  if (!playgroundMode() && !arg('bundle')) {
    failJson('BUNDLE_REQUIRED', 'request-template needs --bundle <dir> or playground mode', 2);
  }
  try {
    const { kit } = await openKit();
    // binding lock from PF7 verifier set in profile bundle
    const { readFile } = await import('node:fs/promises');
    const pathMod = await import('node:path');
    const bundleDir = kit.profile.bundleDirectory;
    if (!bundleDir) {
      failJson('BUNDLE_PATH', 'cannot resolve profile bundle directory for request-template', 1);
    }
    const vsPath = pathMod.default.join(bundleDir, 'artifacts/verifier-set.bin');
    // fallback: profile may expose via authority path
    let bindingLockingBytecode;
    let bindingCarrierBaseValueSatoshis = '1000';
    try {
      const raw = await readFile(vsPath, 'utf8');
      const { parsePf7CarrierAuthority } = await import('../packages/prove/authority.mjs');
      const authority = parsePf7CarrierAuthority(JSON.parse(raw));
      bindingLockingBytecode = authority.settlementKernel.bindingLock.toString('hex');
      bindingCarrierBaseValueSatoshis = authority.settlementKernel.artifact.constants.bindingCarrierBaseSatoshis;
    } catch (e) {
      failJson('TEMPLATE_BIND', `cannot load binding lock from profile: ${e.message}`, 1);
    }
    const template = {
      kind,
      bindingCarrierBaseValueSatoshis,
      bindingLockingBytecode,
      fundingOutpointIndex: '0',
      fundingOutpointTransactionHashWire: '00'.repeat(32),
      fundingPublicKey: '02' + '00'.repeat(32),
      fundingSourceValueSatoshis: kind === 'deposit' ? '20100000' : '20100000',
      settlementFeeFundingSatoshis: '100000',
      _comment: 'Replace funding* with your fee UTXO + compressed pubkey. Sign with fee key — never pass private keys to the kit.',
    };
    okJson({
      verb: 'request-template',
      kind,
      profileId: kit.profile.profileId,
      instanceId: kit.profile.instanceId,
      template,
      writeHint: 'Save template JSON and fill funding fields, then: deposit|transfer|withdraw --request …',
    });
  } catch (e) {
    failJson(e.code || e.name || 'TEMPLATE_FAILED', e.message || String(e), 1);
  }
}

/**
 * Offline genesis plan (no keys). Requires --bundle or playground + --category-input <json>.
 * category-input shape: { lockingBytecode, outpointIndex, outpointTransactionHashWire, publicKey, token, valueSatoshis }
 */
async function cmdGenesisPlan() {
  const catPath = arg('category-input');
  if ((!playgroundMode() && !arg('bundle')) || !catPath) {
    failJson(
      'INPUT_REQUIRED',
      'genesis plan requires --bundle <dir> (or playground) and --category-input <json>',
      2,
      {
        categoryInputShape: {
          lockingBytecode: '25-byte p2pkh hex',
          outpointIndex: '0',
          outpointTransactionHashWire: '32-byte txid wire hex',
          publicKey: '33-byte compressed hex',
          token: null,
          valueSatoshis: 'decimal string',
        },
        note: 'category outpoint must match profile genesis (vout 0). Kit never accepts private keys.',
      },
    );
  }
  try {
    const { kit } = await openKit();
    const categoryInput = await loadJsonFile(catPath, '--category-input');
    const plan = await kit.planGenesis({ categoryInput });
    okJson({
      verb: 'genesis-plan',
      profileId: kit.profile.profileId,
      instanceId: kit.profile.instanceId,
      plan: {
        schema: plan.schema,
        qualification: plan.qualification,
        signingDigestHex: plan.signing?.signingDigestHex,
        measurements: plan.measurements,
        profile: plan.profile,
      },
      next: [
        'Sign signingDigestHex with category-input key (Schnorr BCH ALL|FORKID)',
        'genesis-finalize --category-input … --signature <64-byte hex>',
        'Broadcast resulting transactionHex via your Chipnet RPC',
      ],
    });
  } catch (e) {
    failJson(e.code || e.name || 'GENESIS_PLAN_FAILED', e.message || String(e), 1);
  }
}

async function cmdGenesisFinalize() {
  const catPath = arg('category-input');
  const signature = arg('signature');
  if ((!playgroundMode() && !arg('bundle')) || !catPath || !signature) {
    failJson(
      'INPUT_REQUIRED',
      'genesis finalize requires --bundle (or playground), --category-input <json>, --signature <64hex>',
      2,
    );
  }
  try {
    const { kit } = await openKit();
    const categoryInput = await loadJsonFile(catPath, '--category-input');
    const finalized = await kit.finalizeGenesis({ categoryInput }, signature);
    okJson({
      verb: 'genesis-finalize',
      profileId: kit.profile.profileId,
      instanceId: kit.profile.instanceId,
      transactionId: finalized.transactionId,
      transactionHex: finalized.transactionHex,
      measurements: finalized.measurements,
      qualification: finalized.qualification,
      next: ['Broadcast transactionHex on Chipnet (e.g. sendrawtransaction)', 'Then operate with deposit/transfer/withdraw against this instance'],
    });
  } catch (e) {
    failJson(e.code || e.name || 'GENESIS_FINALIZE_FAILED', e.message || String(e), 1);
  }
}

const cmd = process.argv[2];
if (cmd === '--version' || cmd === '-V' || cmd === 'version') {
  console.log(JSON.stringify({ ok: true, ...toolkitIdentity() }, null, 2));
  process.exit(0);
}
if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
  usage();
  process.exit(0);
}

// playground <sub>  →  bind official Chipnet instance, run sub-verb
if (cmd === 'playground') {
  const sub = process.argv[3] || 'doctor';
  const playgroundMap = {
    doctor: cmdPlaygroundDoctor,
    'profile-info': cmdProfileInfo,
    'request-template': cmdRequestTemplate,
    deposit: () => cmdAct('deposit'),
    transfer: () => cmdAct('transfer'),
    withdraw: () => cmdAct('withdraw'),
    recover: cmdRecover,
    help: () => {
      usage();
      process.exit(0);
    },
  };
  if (!playgroundMap[sub]) {
    failJson('UNKNOWN_COMMAND', `unknown playground command: ${sub}`, 64, {
      commands: Object.keys(playgroundMap),
    });
  }
  Promise.resolve(playgroundMap[sub]()).catch((e) => {
    failJson(e.code || e.name || 'UNCAUGHT', e.message || String(e), 1);
  });
} else {
  const map = {
    'config-check': cmdConfigCheck,
    explorer: cmdExplorer,
    'profile-info': cmdProfileInfo,
    doctor: cmdDoctor,
    init: cmdInit,
    'request-template': cmdRequestTemplate,
    'genesis-plan': cmdGenesisPlan,
    'genesis-finalize': cmdGenesisFinalize,
    deposit: () => cmdAct('deposit'),
    transfer: () => cmdAct('transfer'),
    withdraw: () => cmdAct('withdraw'),
    recover: cmdRecover,
    playground: cmdPlaygroundDoctor,
  };

  if (!map[cmd]) {
    failJson('UNKNOWN_COMMAND', `unknown command: ${cmd}`, 64, {
      commands: Object.keys(map).concat(['help', 'playground doctor']),
    });
  }

  Promise.resolve(map[cmd]()).catch((e) => {
    failJson(e.code || e.name || 'UNCAUGHT', e.message || String(e), 1);
  });
}
