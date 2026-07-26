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

Product tree: 03-create-your-own-pool/  (kit · profile · CLI)
Optional demo: 02-use-chipnet-demo-pool/   (live Chipnet instance)

  # Create and operate your pool
  init --config 03-create-your-own-pool/templates/init.development.json
  request-template --kind deposit --bundle <profile-dir>
  genesis-plan --bundle <dir> --category-input <json>
  genesis-finalize --bundle <dir> --category-input <json> --signature <64hex>
  # Full act (prove + verifier unlocks + assemble)
  deposit|transfer|withdraw --pool <pool-dir> --wallets <json> [--broadcast]
  # Offline prep-only (legacy)
  deposit|transfer|withdraw --bundle <profile-dir> --request <prep.json>
  recover --bundle <your-pool> --history <json> --seed-hex <64hex>
  doctor [--pool <dir>] | profile-info | config-check | explorer

  # Pin circuit artifacts (~450MB) for create-pool
  npm run fetch-pin-artifacts
  npm run create-pool -- --out ./my-pool
  npm run create-pool -- --out ./new --with-genesis --fund-txid … --broadcast

  # Optional live demo (CLI only — not a web wallet)
  npm install && npm run fetch-playground-bundle
  playground doctor|tip|profile-info|request-template
  playground deposit|transfer|withdraw --wallets <json> [--scan-fees] [--broadcast] [--refresh-tip]
  (RPC: public Chipnet Fulcrum by default; tip auto-discovered from chain when missing)

Flags:
  --version
  --network chipnet|mainnet
  --mode development-only|ceremony-production
  --pool <pool-dir>   (full act / doctor preflight)
  --bundle <profile-dir>
  --wallets / --broadcast / --scan-fees / --funding-txid / --state-txid
  --config / --request / --history / --seed-hex / --kind / --category-input / --signature
  --verify-ptau   (init) force full snarkjs powersoftau verify; default may hash-only trusted Hermez pin
  --i-understand-mainnet
  --allow-development-on-mainnet

Fee keys: policy A feePrivateKey (desktop) · policy B feePublicKey+feeSignature
Docs: 03-create-your-own-pool/docs/VERSIONING.md · UX_ADVERSARIAL_REDTEAM.md · CHARTER.md
`);
}

/** When true, openKit uses 02-use-chipnet-demo-pool instance. */
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
      const instance = await loadInstance('02-use-chipnet-demo-pool', {
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
        docs: '02-use-chipnet-demo-pool/README.md',
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

/**
 * Resolve live State NFT tip for playground (or --pool) from chain.
 * Tip is not a constant — it moves every SETTLE; local state.json only caches it.
 */
async function cmdTip() {
  try {
    const monorepoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const poolDir = arg('pool')
      ? path.resolve(arg('pool'))
      : path.join(monorepoRoot, '02-use-chipnet-demo-pool');
    const { existsSync, readFileSync, writeFileSync } = await import('node:fs');
    const instancePath = path.join(poolDir, 'instance.json');
    const bundleDir = path.join(poolDir, 'bundle');
    const statePath = path.join(poolDir, 'state.json');
    if (!existsSync(instancePath) || !existsSync(bundleDir)) {
      failJson('POOL_MISSING', 'need 02-use-chipnet-demo-pool/ (or --pool) with instance.json + bundle/', 2);
    }
    const instance = JSON.parse(readFileSync(instancePath, 'utf8'));
    const { createChipnetRpc } = await import('../packages/kit/chipnet-rpc.mjs');
    const { discoverStateTip } = await import('../packages/kit/state-tip.mjs');
    const { parsePf7CarrierAuthority } = await import('../packages/prove/authority.mjs');
    const rpc = await createChipnetRpc();
    const vs = JSON.parse(readFileSync(path.join(bundleDir, 'artifacts/verifier-set.bin'), 'utf8'));
    const authority = parsePf7CarrierAuthority(vs);
    const prev = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {};
    const preferred = typeof prev.stateTxid === 'string' && /^[0-9a-f]{64}$/i.test(prev.stateTxid)
      ? prev.stateTxid.toLowerCase()
      : null;
    const tip = await discoverStateTip({
      rpc,
      stateLockingBytecode: authority.settlementKernel.stateLock,
      stateNftCategory: instance.stateNftCategory,
      instanceId: instance.instanceId,
      preferredStateTxid: preferred || undefined,
    });
    // Never clobber a strictly newer local tip (e.g. just-broadcast settle not yet in Fulcrum).
    const localSeq = prev.tipMeta?.actionSequence;
    const discoveredSeq = tip.actionSequence;
    let useTip = tip;
    if (
      preferred
      && localSeq != null
      && BigInt(localSeq) > BigInt(discoveredSeq)
      && !flag('force-tip')
    ) {
      useTip = {
        stateTxid: preferred,
        vout: prev.tipMeta?.vout ?? 0,
        height: prev.tipMeta?.height ?? -1,
        actionSequence: String(localSeq),
        valueSatoshis: tip.valueSatoshis,
        source: 'local-newer-than-discovery',
        unspentMatches: tip.unspentMatches,
      };
    }
    const next = {
      ...prev,
      stateTxid: useTip.stateTxid,
      tipMeta: {
        vout: useTip.vout,
        height: useTip.height,
        actionSequence: useTip.actionSequence,
        discoveredAt: new Date().toISOString(),
        source: useTip.source || tip.source || 'chain-discover',
      },
      feeUtxos: prev.feeUtxos || [],
      history: prev.history || [],
      openNotes: prev.openNotes || [],
    };
    if (!flag('no-write')) {
      writeFileSync(statePath, JSON.stringify(next, null, 2));
    }
    okJson({
      verb: 'tip',
      pool: poolDir,
      backend: rpc.backend,
      label: rpc.label,
      stateTxid: useTip.stateTxid,
      vout: useTip.vout,
      height: useTip.height,
      actionSequence: useTip.actionSequence,
      source: useTip.source || tip.source,
      unspentMatches: tip.unspentMatches,
      scanned: tip.scanned,
      wrote: !flag('no-write') ? statePath : null,
      note: 'Tip moves every settle. Re-run tip / --refresh-tip before acting if others used the pool.',
    });
  } catch (e) {
    failJson(e.code || e.name || 'TIP_FAILED', e.message || String(e), 1);
  }
}

async function cmdPlaygroundDoctor() {
  try {
    const { loadInstance } = await import('../packages/profile/instance.mjs');
    const instance = await loadInstance('02-use-chipnet-demo-pool', {
      loadBundle: false,
    });
    let bundleOk = false;
    let bundleError = null;
    let kitInfo = null;
    try {
      const full = await loadInstance('02-use-chipnet-demo-pool', {
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
      story: 'ShieldKit creates shielded pools. Demo is 02-use-chipnet-demo-pool/; product is 03-create-your-own-pool/.',
      product: '03-create-your-own-pool/',
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
          'product: 03-create-your-own-pool/ — init + genesis',
          'You supply RPC, fees, proofs, broadcast',
        ]
        : [
          'npm run fetch-playground-bundle  (or SHIELDKIT_PLAYGROUND_BUNDLE)',
          'or skip demo: 03-create-your-own-pool/ — init template',
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

async function cmdDoctor() {
  // Pool preflight (UX red team doctor --pool)
  if (arg('pool')) {
    const { spawnSync } = await import('node:child_process');
    const script = path.join(__dirname, 'pool-doctor.mjs');
    const r = spawnSync(process.execPath, [script, ...process.argv.slice(3)], {
      encoding: 'utf8', stdio: 'inherit',
    });
    process.exit(r.status ?? 1);
  }
  let net;
  try {
    net = resolveNetwork(arg('network', defaultNetworkName()));
  } catch (e) {
    failJson(e.code || 'UNKNOWN_NETWORK', e.message, 2);
  }
  const { mode, deprecatedSetupModeFlag } = resolveMode();
  const report = {
    ...toolkitIdentity(),
    verbs: ['init', 'deposit', 'transfer', 'withdraw', 'recover', 'doctor', 'create-pool'],
    domains: ['kit', 'profile', 'action', 'prove', 'unlock-builder', 'recover'],
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
        api: "import { init } from './03-create-your-own-pool/packages/profile/init.mjs'",
        template: '03-create-your-own-pool/templates/init.development.json',
        note: 'new setup ⇒ new profile + new genesis; no hot-swap',
        path: '03-create-your-own-pool/',
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
  // Full act spine: --pool … or playground + --wallets (pool-act)
  const playgroundFullAct = playgroundMode() && (arg('wallets') || flag('broadcast') || flag('scan-fees'));
  if (arg('pool') || playgroundFullAct) {
    const { spawnSync } = await import('node:child_process');
    const { existsSync } = await import('node:fs');
    const monorepoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const script = path.join(__dirname, 'pool-act.mjs');
    const poolDir = arg('pool')
      ? path.resolve(arg('pool'))
      : path.join(monorepoRoot, '02-use-chipnet-demo-pool');
    if (!existsSync(path.join(poolDir, 'bundle'))) {
      failJson('POOL_BUNDLE', 'pool missing bundle/ — for playground: npm run fetch-playground-bundle', 2, {
        pool: poolDir,
      });
    }
    // Forward user flags except the leading "playground" token and verb aliases.
    const skip = new Set(['playground', verb, 'deposit', 'transfer', 'withdraw', 'withdrawal']);
    const forwarded = [];
    const argv = process.argv.slice(2);
    for (let i = 0; i < argv.length; i++) {
      const a = argv[i];
      if (skip.has(a)) continue;
      if (a === '--pool') { i += 1; continue; } // we set pool explicitly
      forwarded.push(a);
    }
    const poolActArgv = [
      script,
      requestKind === 'withdrawal' ? 'withdraw' : requestKind,
      '--pool', poolDir,
      ...forwarded,
    ];
    const r = spawnSync(process.execPath, poolActArgv, { encoding: 'utf8', stdio: 'inherit' });
    process.exit(r.status ?? 1);
  }
  const requestPath = arg('request');
  const hasPool = playgroundMode() || arg('bundle');
  if (!hasPool || !requestPath) {
    failJson(
      'INPUT_REQUIRED',
      playgroundMode()
        ? `${verb} needs --wallets <json> [--broadcast] for full act, or --request <prep.json> for prep-only`
        : `${verb} requires --pool <dir> --wallets … [--broadcast]  OR  --bundle + --request (prep-only)`,
      2,
      {
        verb,
        kind: requestKind,
        fullAct: 'npm run shieldkit -- playground deposit --wallets ./wallets.json --scan-fees --broadcast',
        prepOnly: 'playground deposit --request prep.json',
        feeNote: 'Deposit needs a fee UTXO ≳ 11.5M sats (0.1 BCH + carriers + fee). See 02-use-chipnet-demo-pool/README.md',
        rpc: 'Public Chipnet Fulcrum used by default; override with SHIELDKIT_RPC_URL or SHIELDKIT_ELECTRUM',
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
        'Local prove (packages/prove) + build verifier unlocks',
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
    // binding lock from verifier set in profile bundle
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
    tip: cmdTip,
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
