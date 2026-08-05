#!/usr/bin/env node
/**
 * ShieldKit CLI — V2 beta product, quarantined V1, and a hidden V2 developer surface.
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

const V1_LINKABILITY_WARNING = [
  'V1_LINKABILITY_WARNING',
  'V1 mutation may be linkable and does not provide V2 Direct privacy; V1 artifacts and state cannot migrate to V2.',
];

function legacyProtocolWarnings() {
  return arg('protocol') === 'v1-legacy'
    ? [V1_LINKABILITY_WARNING[1]]
    : [];
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
  if (value !== 'development-only' && value !== 'local-contribution-simulation') {
    failJson('INVALID_MODE', 'mode must be development-only or local-contribution-simulation', 2, { mode: value });
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
  if (value !== 'development-only' && value !== 'local-contribution-simulation') return 'development-only';
  return value;
}

function okJson(body, code = 0) {
  const network = arg('network', defaultNetworkName());
  console.log(JSON.stringify({
    ok: true,
    toolkitVersion: TOOLKIT_VERSION,
    productStatus: PRODUCT_STATUS,
    warnings: [
      ...productWarnings({
        network,
        setupMode: body.setupMode ?? body.mode ?? peekMode(),
      }),
      ...legacyProtocolWarnings(),
    ],
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

function poolUsage(topic = 'pool') {
  const sections = {
    pool: `ShieldKit-Groth Beta v${TOOLKIT_VERSION} — pool commands (Chipnet-only, unaudited)

  shieldkit pool create --funding-wallet <abs-wallet> --funding-utxo <txid:vout> [--data-home <abs-dir>]
  shieldkit pool create --resume [--data-home <abs-dir>]
  shieldkit pool refresh-runtime | add-funding | deposit | withdraw | doctor
  shieldkit pool recover inspect|rebroadcast ...
  Zero-conf only. No automatic resend, sponsor, faucet, or mining wait.
`,
    create: `shieldkit pool create — create a fresh Chipnet PF10 pool

  --funding-wallet <absolute-canonical-private-wallet-path>
  --funding-utxo <64-lowercase-hex-txid:vout>
  --resume
  --data-home <abs-dir>
  --human | --json
`,
    deposit: `shieldkit pool deposit — deposit one fixed denomination note

  --data-home <abs-dir>  --operation-id <id>  --human|--json
`,
    withdraw: `shieldkit pool withdraw — withdraw one note to Chipnet P2PKH

  --to <bchtest-p2pkh-address>  --data-home <abs-dir>  --note <id>  --operation-id <id>
`,
    recover: `shieldkit pool recover — inspect or exact-byte rebroadcast

  recover inspect --operation-id <id>
  recover rebroadcast --operation-id <id> --attempt-token <token> --acknowledge-exact-rebroadcast
`,
    doctor: `shieldkit pool doctor — local product/runtime health (no broadcast)

  --data-home <abs-dir>  --human|--json
`,
  };
  console.log(sections[topic] || sections.pool);
}

function usage() {
  console.log(`ShieldKit-Groth Beta v${TOOLKIT_VERSION} — create and run your own BCH shielded pool

${PRODUCT_STATUS.status} · maturity: ${PRODUCT_STATUS.maturityLabel}
${PRODUCT_STATUS.note}

Product root: shieldkit-groth/  (kit · profile · PF10 CLI)
Optional demo: 02-use-chipnet-demo-pool/   (legacy research instance)

  # Create and operate your pool (ShieldKit-Groth Beta / PF10 / Chipnet)
  pool create --funding-wallet <absolute-canonical-private-wallet-path> --funding-utxo <64-lowercase-hex-txid:vout> [--data-home <absolute-directory>] [--human|--json]
  pool create --resume [--data-home <absolute-directory>] [--human|--json]  # only an existing durable create operation
  pool refresh-runtime [--data-home <absolute-directory>] [--human|--json]
  pool add-funding --funding-utxo <64-lowercase-hex-txid:vout> [--data-home <absolute-directory>] [--human|--json]  # register an already-owned live UTXO; never sends; keep two independent fee UTXOs for consecutive actions
  pool deposit | deposit [--data-home <absolute-directory>] [--operation-id <id>] [--human|--json]
  pool withdraw | withdraw --to <bchtest-p2pkh-address> [--data-home <absolute-directory>] [--note <id>] [--operation-id <id>] [--human|--json]
  pool recover inspect | recovery inspect --operation-id <id> [--data-home <absolute-directory>] [--human|--json]
  pool recover rebroadcast | recovery rebroadcast --operation-id <id> --attempt-token <current-token> --acknowledge-exact-rebroadcast [--data-home <absolute-directory>] [--human|--json]
  pool doctor [--data-home <absolute-directory>] [--human|--json]
  (ShieldKit-Groth Beta Chipnet: one user-funded invocation; wallet must be a canonical owner-private 0600 JSON file and every funding UTXO must be unspent, tokenless P2PKH owned by that retained wallet. pool add-funding authenticates and registers one exact existing UTXO; it never scans or sends. Because the next fee input must come from a transaction other than the current pool tip, continuous operation requires two alternating independent fee UTXOs. A crash-resume is explicit and cannot substitute new funding. No sponsor, faucet, RPC account, API key, custom endpoint, or SSH. The sole action send goes to one pinned public provider; exact zero-conf completion requires an identical transaction/state readback quorum from any two of three independently operated pinned providers—never confirmation or mining. Capacity 100000; explicitly unqualified. Public providers can observe the client IP and queried transactions/outpoints. After a ShieldKit source upgrade, run pool refresh-runtime locally before actions; it never proves or contacts a network provider.)

  # Legacy tools
  init  # V1 legacy creation is quarantined; use the attested V2 pipeline
  request-template --kind deposit --bundle <profile-dir>
  genesis-plan --bundle <dir> --category-input <json>
  genesis-finalize --bundle <dir> --category-input <json> --signature <64hex>
  # Full act (prove + verifier unlocks + assemble)
  deposit|transfer|withdraw --protocol v1-legacy --pool <pool-dir> --wallets <json> [--broadcast]
  # Offline prep-only (legacy)
  deposit|transfer|withdraw --protocol v1-legacy --bundle <profile-dir> --request <prep.json>
  recover --bundle <your-pool> --history <json> --seed-hex <64hex>
  doctor [--pool <dir>] | profile-info | config-check | explorer

  # Optional live demo (CLI only — not a web wallet)
  npm ci && npm run fetch-playground-bundle && npm run unlock-builder:setup
  playground doctor|tip|profile-info|request-template
  playground deposit|transfer|withdraw --protocol v1-legacy --wallets <json> [--broadcast] [--refresh-tip]
  (RPC: public Chipnet Fulcrum by default; tip auto-discovered from chain when missing)

Flags:
  --version
  --protocol v1-legacy  (legacy mutation commands only)
  --network chipnet|mainnet
  --mode development-only|local-contribution-simulation
  --pool <pool-dir>   (full act / doctor preflight)
  --bundle <profile-dir>
  --wallets / --broadcast / --scan-fees / --state-txid
  --config / --request / --history / --seed-hex / --kind / --category-input / --signature
  --verify-ptau   (init) force full snarkjs powersoftau verify; default may hash-only trusted Hermez pin
  --i-understand-mainnet
  --allow-development-on-mainnet

Fee keys: policy A feePrivateKey (desktop) · policy B feePublicKey+feeSignature
Developer-only internals are intentionally omitted. Run: shieldkit dev --help
Docs: shieldkit-groth/docs/VERSIONING.md · CHARTER.md
`);
}

function developerUsage() {
  console.log(`ShieldKit-Groth developer surface — low-level PF10 / Direct internals

Explicitly unqualified · Chipnet only · not an end-user workflow
The dev namespace implies protocol v2-direct; --protocol is forbidden here.

  shieldkit dev wallet create|receive
  shieldkit dev pool add <descriptor>
  shieldkit dev sync|recover|status|doctor
  shieldkit dev deposit|transfer|withdraw ... --broadcast
  shieldkit dev operation resume <id> [--broadcast]
  shieldkit dev operation reconcile <id>
  shieldkit dev operation rebroadcast <id> --broadcast --attempt-token <prior-token> --acknowledgement resubmit-exact-persisted-transaction
  shieldkit dev operation confirm <id>
  shieldkit dev operation rebase <id>
  shieldkit dev operation abandon <id> --reason <printable-text>

No automatic resend, sponsor, faucet, or batching. Final qualification is blocked.
Use the normal product commands for pool create, deposit, and withdraw.
`);
}

/** Normalize product CLI tokens: pool deposit|withdraw|recover → flat beta verbs. */
function normalizeBetaProductTokens(tokens) {
  if (!Array.isArray(tokens) || tokens.length === 0) return tokens;
  if (tokens[0] !== 'pool') return tokens;
  if (tokens[1] === 'deposit') return ['deposit', ...tokens.slice(2)];
  if (tokens[1] === 'withdraw') return ['withdraw', ...tokens.slice(2)];
  if (tokens[1] === 'recover' && tokens[2] === 'inspect') {
    return ['recovery', 'inspect', ...tokens.slice(3)];
  }
  if (tokens[1] === 'recover' && tokens[2] === 'rebroadcast') {
    return ['recovery', 'rebroadcast', ...tokens.slice(3)];
  }
  if (tokens[1] === 'recovery' && (tokens[2] === 'inspect' || tokens[2] === 'rebroadcast')) {
    return ['recovery', tokens[2], ...tokens.slice(3)];
  }
  return tokens;
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
    const { existsSync, readFileSync } = await import('node:fs');
    const { atomicWriteJson, repairPrivateFileMode } = await import('../packages/kit/secure-files.mjs');
    const instancePath = path.join(poolDir, 'instance.json');
    const bundleDir = path.join(poolDir, 'bundle');
    const statePath = path.join(poolDir, 'state.json');
    if (!existsSync(instancePath) || !existsSync(bundleDir)) {
      failJson('POOL_MISSING', 'need 02-use-chipnet-demo-pool/ (or --pool) with instance.json + bundle/', 2);
    }
    const instance = JSON.parse(readFileSync(instancePath, 'utf8'));
    const manifest = JSON.parse(readFileSync(path.join(bundleDir, 'manifest.json'), 'utf8'));
    const stateNftCategory = instance.stateNftCategory
      || manifest.genesis?.stateNftCategory
      || instance.categoryTxid;
    const network = instance.network === 'mainnet' ? 'mainnet' : 'chipnet';
    const { createChainRpc } = await import('../packages/kit/chipnet-rpc.mjs');
    const { discoverStateTip } = await import('../packages/kit/state-tip.mjs');
    failJson('LEGACY_AUTHORITY_MOVED', 'legacy seven-carrier authority helpers moved to legacy-research/v1-seven-carrier/', 2);
    const {
      fetchSettlementLogFromTip,
      settlementLogLooksComplete,
      applySettlementLog,
      syncTipForestFromSettlementLog,
    } = await import('../packages/pool/index.mjs');
    const {
      decodeTransaction, hexToBin, binToHex,
    } = await import('@bitauth/libauth');
    const rpc = await createChainRpc({ network });
    const vs = JSON.parse(readFileSync(path.join(bundleDir, 'artifacts/verifier-set.bin'), 'utf8'));
    const authority = parsePf7CarrierAuthority(vs);
    const prev = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {};
    repairPrivateFileMode(statePath);
    const preferred = typeof prev.stateTxid === 'string' && /^[0-9a-f]{64}$/i.test(prev.stateTxid)
      ? prev.stateTxid.toLowerCase()
      : null;
    const tip = await discoverStateTip({
      rpc,
      stateLockingBytecode: authority.settlementKernel.stateLock,
      stateNftCategory,
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
      settlementLog: prev.settlementLog || null,
      tipForest: prev.tipForest || null,
      publicTip: prev.publicTip || null,
    };

    // Blank join: walk tip→genesis and rebuild public tipForest (no private note secrets).
    let settlementLog = next.settlementLog;
    let tipForestMeta = null;
    const tipSeq = String(useTip.actionSequence);
    const skipLog = flag('no-fetch-settlement-log');
    if (!skipLog && instance.genesisTxid && useTip.stateTxid) {
      const forestSeq = next.tipForest?.state?.actionSequence != null
        ? String(next.tipForest.state.actionSequence)
        : null;
      const needFetch = !settlementLogLooksComplete(settlementLog, tipSeq)
        || (tipSeq !== '0' && forestSeq !== tipSeq);
      if (needFetch) {
        try {
          const fetched = await fetchSettlementLogFromTip({
            rpc,
            tipTxid: useTip.stateTxid,
            genesisTxid: instance.genesisTxid,
            decodeTransaction,
            binToHex,
          });
          applySettlementLog(next, fetched);
          settlementLog = next.settlementLog;
        } catch (e) {
          // Soft on tip verb: still write tip cache; act path will fail closed if needed.
          next.settlementLogFetchError = String(e.message || e).slice(0, 200);
        }
      }
    }

    if (
      settlementLog?.genesisHex
      && Array.isArray(settlementLog.settles)
      && settlementLog.settles.length > 0
    ) {
      try {
        let tipNftCommitmentHex;
        const raw = await rpc._electrumCall?.('blockchain.transaction.get', [useTip.stateTxid, false]);
        if (typeof raw === 'string') {
          const tipTx = decodeTransaction(hexToBin(raw));
          if (typeof tipTx !== 'string' && tipTx.outputs?.[0]?.token?.nft?.commitment) {
            tipNftCommitmentHex = binToHex(tipTx.outputs[0].token.nft.commitment);
          }
        }
        const synced = await syncTipForestFromSettlementLog({
          genesisTransactionId: settlementLog.genesisTxid || instance.genesisTxid,
          genesisTransactionHex: settlementLog.genesisHex,
          settleTransactionHexes: settlementLog.settles,
          profileId: (instance.profileId || '').replace(/^sha256:/, ''),
          instanceId: (instance.instanceId || '').replace(/^sha256:/, ''),
          stateNftCategory: (instance.stateNftCategory || '').toLowerCase(),
          stateLockingBytecodeHex: Buffer.from(authority.settlementKernel.stateLock).toString('hex'),
          stateCarrierBaseSatoshis: '1080',
          tipNftCommitmentHex,
          myOpenNotes: next.openNotes || [],
          secretMetaByIndex: {},
        });
        next.tipForest = synced.tipForest;
        next.publicTip = synced.publicTip;
        tipForestMeta = {
          liveNoteCount: synced.publicTip.state.liveNoteCount,
          actionSequence: synced.publicTip.state.actionSequence,
          eventCount: synced.publicTip.eventCount,
        };
      } catch (e) {
        next.tipForestRebuildError = String(e.message || e).slice(0, 200);
      }
    }

    if (!flag('no-write')) {
      atomicWriteJson(statePath, next);
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
      settlementLogDepth: settlementLog?.depth ?? settlementLog?.settles?.length ?? null,
      tipForest: tipForestMeta,
      wrote: !flag('no-write') ? statePath : null,
      note: 'Tip moves every settle. settlementLog + public tipForest rebuilt from chain when needed (blank join).',
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
      story: 'ShieldKit creates shielded pools. Demo is 02-use-chipnet-demo-pool/; product is shieldkit-groth/.',
      product: 'shieldkit-groth/',
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
          'optional: playground deposit --protocol v1-legacy --request prep.json (learn the flow)',
          'product: shieldkit-groth/ — init + genesis',
          'You supply RPC, fees, proofs, broadcast',
        ]
        : [
          'npm run fetch-playground-bundle  (or SHIELDKIT_PLAYGROUND_BUNDLE)',
          'or skip demo: shieldkit-groth/ — init template',
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
  failJson(
    'LEGACY_PROFILE_CREATION_QUARANTINED',
    'shieldkit init created the V1 legacy shielded-action-v2 profile and is quarantined; use the attested V2 Direct setup and development-profile pipeline',
    64,
    {
      setupCommand:
        'node shieldkit-groth/packages/profile/setup/development-cli.mjs --input <attested-v2-setup.json>',
      profileCommand:
        'node shieldkit-groth/scripts/v2-development-profile.mjs <all pinned artifact arguments>',
      note: 'V1 artifacts cannot be relabeled or migrated into V2 Direct',
    },
  );
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
    failJson('LEGACY_POOL_ACT_MOVED', 'legacy seven-carrier pool-act moved to legacy-research/v1-seven-carrier/; use shieldkit pool deposit|withdraw for PF10', 2);
    const script = null;
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
        fullAct: 'npm run shieldkit -- playground deposit --protocol v1-legacy --wallets ./wallets.json --scan-fees --broadcast',
        prepOnly: 'playground deposit --protocol v1-legacy --request prep.json',
        feeNote: 'Legacy playground deposit needs a large fee UTXO; transfer/withdraw ~71k. See 02-use-chipnet-demo-pool/README.md',
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
      failJson('LEGACY_AUTHORITY_MOVED', 'legacy seven-carrier authority helpers moved to legacy-research/v1-seven-carrier/', 2);
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
      writeHint: 'Save template JSON and fill funding fields, then use the matching V1 action with --protocol v1-legacy --request …',
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
  console.log(JSON.stringify({
    ok: true,
    product: 'ShieldKit-Groth',
    release: 'ShieldKit-Groth Beta',
    ...toolkitIdentity(),
  }, null, 2));
  process.exit(0);
}
if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
  usage();
  process.exit(0);
}

// Product pool help surfaces (must not fall through to UNKNOWN_COMMAND).
if (cmd === 'pool') {
  const sub = process.argv[3];
  const topic = process.argv[4];
  if (!sub || sub === 'help' || sub === '--help' || sub === '-h') {
    poolUsage('pool');
    process.exit(0);
  }
  if (['create', 'deposit', 'withdraw', 'recover', 'doctor'].includes(sub)
    && (topic === 'help' || topic === '--help' || topic === '-h'
      || process.argv.includes('--help') || process.argv.includes('-h'))) {
    poolUsage(sub === 'recover' ? 'recover' : sub);
    process.exit(0);
  }
  if (sub === 'doctor') {
    // Local-only doctor for beta product data-home (no chain broadcast).
    const dataHome = arg('data-home');
    okJson({
      verb: 'pool-doctor',
      product: 'ShieldKit-Groth',
      release: 'ShieldKit-Groth Beta',
      network: 'chipnet',
      productionQualified: false,
      dataHome: dataHome ?? null,
      status: 'local-ok',
      notes: [
        'pool doctor checks local CLI wiring only; run pool create/deposit/withdraw for live operations',
        'zero-conf Chipnet only; no mainnet product claim',
      ],
    });
  }
}

const rawCliArguments = process.argv.slice(2);
const developerInvocation = cmd === 'dev';
if (
  developerInvocation
  && (
    rawCliArguments.length === 1
    || ['help', '--help', '-h'].includes(rawCliArguments[1])
  )
) {
  developerUsage();
  process.exit(0);
}
if (developerInvocation && rawCliArguments.includes('--protocol')) {
  failJson(
    'DEV_PROTOCOL_OPTION_FORBIDDEN',
    'shieldkit dev already selects the low-level v2-direct protocol; remove --protocol',
    2,
  );
}
const cliArguments = developerInvocation
  ? [...rawCliArguments.slice(1), '--protocol', 'v2-direct']
  : rawCliArguments;
const protocolOptionIndexes = cliArguments
  .map((value, index) => value === '--protocol' ? index : -1)
  .filter((index) => index !== -1);
if (protocolOptionIndexes.length > 1) {
  failJson(
    'DUPLICATE_OPTION',
    '--protocol may be supplied only once',
    2,
  );
}
const protocolIndex = protocolOptionIndexes[0];
const explicitProtocol = protocolIndex === undefined
  ? undefined
  : cliArguments[protocolIndex + 1];
const betaProductOptionNames = new Set([
  '--acknowledge-exact-rebroadcast', '--attempt-token', '--data-home',
  '--funding-utxo', '--funding-wallet', '--human', '--json', '--note',
  '--operation-id', '--to',
]);
const hasOnlyBetaProductOptions = cliArguments.slice(1).every((value) => (
  !value.startsWith('--') || betaProductOptionNames.has(value)
));
const poolSub = process.argv[3];
const betaProductInvocation = (
  (cmd === 'pool' && ['create', 'refresh-runtime', 'add-funding', 'deposit', 'withdraw'].includes(poolSub))
  || (cmd === 'pool' && poolSub === 'recover' && ['inspect', 'rebroadcast'].includes(process.argv[4]))
  || (cmd === 'pool' && poolSub === 'recovery' && ['inspect', 'rebroadcast'].includes(process.argv[4]))
  || (cmd === 'recovery' && ['inspect', 'rebroadcast'].includes(process.argv[3]))
  || (
    ['deposit', 'withdraw'].includes(cmd)
    && explicitProtocol === undefined
    && hasOnlyBetaProductOptions
  )
);
if (
  protocolIndex !== undefined
  && (
    explicitProtocol === undefined
    || explicitProtocol.startsWith('--')
  )
) {
  failJson('OPTION_VALUE_REQUIRED', '--protocol requires one value', 2);
}
const formerTopLevelV2Invocation = !developerInvocation && (
  ['wallet', 'sync', 'status', 'operation'].includes(cmd)
  || (cmd === 'pool' && process.argv[3] === 'add')
  || explicitProtocol === 'v2-direct'
);
if (formerTopLevelV2Invocation && !betaProductInvocation) {
  failJson(
    'DEV_NAMESPACE_REQUIRED',
    'low-level V2 Direct commands moved behind shieldkit dev; run shieldkit dev --help',
    2,
  );
}
const directMutation = ['deposit', 'transfer', 'withdraw'].includes(cmd);
const playgroundMutation = cmd === 'playground'
  && ['deposit', 'transfer', 'withdraw'].includes(process.argv[3]);
const legacyMutation = directMutation || playgroundMutation;
if (legacyMutation && explicitProtocol === undefined && !betaProductInvocation) {
  failJson(
    'PROTOCOL_REQUIRED',
    'legacy mutation commands require --protocol v1-legacy; low-level V2 Direct commands require shieldkit dev',
    2,
    {
      protocols: ['v1-legacy'],
      developerNamespace: 'shieldkit dev',
      v2Qualification: 'blocked',
    },
  );
}
if (
  legacyMutation
  && !betaProductInvocation
  && !['v1-legacy', 'v2-direct'].includes(explicitProtocol)
) {
  failJson(
    'UNSUPPORTED_PROTOCOL',
    `unsupported mutation protocol: ${explicitProtocol}`,
    2,
  );
}
if (legacyMutation && explicitProtocol === 'v1-legacy') {
  console.error(JSON.stringify({
    warning: {
      code: V1_LINKABILITY_WARNING[0],
      message: V1_LINKABILITY_WARNING[1],
    },
  }));
}

async function dispatchV2Cli() {
  const {
    executeV2Cli,
    isV2CliInvocation,
    v2CliErrorResult,
  } = await import('../packages/kit/v2/cli.mjs');
  if (!isV2CliInvocation(cliArguments)) return false;
  try {
    const result = await executeV2Cli(cliArguments);
    console.log(JSON.stringify({
      toolkitVersion: TOOLKIT_VERSION,
      ...result,
    }, null, 2));
    process.exit(0);
  } catch (error) {
    const rendered = v2CliErrorResult(error);
    console.log(JSON.stringify({
      toolkitVersion: TOOLKIT_VERSION,
      ...rendered.body,
    }, null, 2));
    process.exit(rendered.exitCode);
  }
}

async function dispatchV2BetaProductCli() {
  const {
    executeV2BetaProductCli,
    renderV2BetaProductCliHuman,
    v2BetaProductCliErrorResult,
  } = await import('../packages/kit/v2/beta-product-cli.mjs');
  try {
    const envelope = await executeV2BetaProductCli(normalizeBetaProductTokens(cliArguments));
    if (envelope.format === 'human') {
      console.log(renderV2BetaProductCliHuman(envelope));
    } else {
      console.log(JSON.stringify({
        ok: true,
        toolkitVersion: TOOLKIT_VERSION,
        product: 'shieldkit-v2-beta-chipnet',
        productionQualified: false,
        confirmed: false,
        mined: false,
        ...envelope,
      }, null, 2));
    }
    process.exit(0);
  } catch (error) {
    const rendered = v2BetaProductCliErrorResult(error);
    console.log(JSON.stringify({ toolkitVersion: TOOLKIT_VERSION, ...rendered.body }, null, 2));
    process.exit(rendered.exitCode);
  }
}

const v2Dispatch = developerInvocation;

// playground <sub>  →  bind official Chipnet instance, run sub-verb
if (betaProductInvocation) {
  Promise.resolve(dispatchV2BetaProductCli()).catch((e) => {
    failJson(e.code || e.name || 'V2_BETA_PRODUCT_CLI_UNCAUGHT', e.message || String(e), 1);
  });
} else if (v2Dispatch) {
  Promise.resolve(dispatchV2Cli()).catch((e) => {
    failJson(e.code || e.name || 'V2_CLI_UNCAUGHT', e.message || String(e), 1);
  });
} else if (cmd === 'playground') {
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
