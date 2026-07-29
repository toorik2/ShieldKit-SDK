#!/usr/bin/env node
/**
 * V2 Direct CLI surface (plan §3 + publish gates):
 *   wallet create | wallet receive | wallet set-funding
 *   pool create | pool add <descriptor>
 *   sync | deposit | transfer | withdraw | recover | status | doctor
 *
 * No faucet. No hard-coded agent wallet paths.
 * Dev circuit keys only until Phase D ceremony — see Protocol-design-v2/.
 */
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, statSync, copyFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  NETWORK_CHIPNET, NETWORK_MAINNET, DENOMINATION_SATS, PLAYGROUND_MAXIMUM_LIVE_NOTES, ZERO_32_HEX,
} from '../constants.mjs';
import { frFromHex } from '../crypto/fr.mjs';
import { freshOutputNote, shieldAddress } from '../crypto/note.mjs';
import { createLiveNetworkGate } from '../operator/chipnet-rpc.mjs';
import { CIRCUIT_TREE_DEPTH, provePoolAction } from '../operator/prove-local.mjs';
import { buildDensfuelForPacket } from '../operator/densfuel-build.mjs';
import {
  assembleProductSettle,
  rollBundleAfterSettle,
  STATE_BASE,
} from '../operator/product-settle.mjs';
import { resolveWithdrawalPayout } from '../operator/withdraw-payout.mjs';
import {
  loadFundingWallet,
  selectFundingUtxoFromList,
  resolveFundingWalletPath,
  generateFundingWalletMaterial,
  saveFundingWalletJson,
  mergeFundingUtxos,
} from '../operator/funding-wallet.mjs';
import {
  buildPoolGenesis,
  ensureCategoryVout0,
  randomProfileId,
} from '../operator/pool-create.mjs';
import { createPoolEngineV2 } from '../transition.mjs';
import { createJournal } from '../wallet/journal.mjs';
import { createNoteWallet } from '../wallet/notes.mjs';
import { atomicWriteJson, PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE } from '../../kit/secure-files.mjs';

const MATURITY_BANNER = [
  '══════════════════════════════════════════════════════════════════',
  '  Protocol-design-v2 · DEV KEYS ONLY — not for real-money privacy',
  '  Unaudited WIP · Chipnet-first · Mainnet gated until Phase D',
  '  Ceremony incomplete · Do not treat as production privacy software',
  '══════════════════════════════════════════════════════════════════',
].join('\n');

function printBanner() {
  if (process.env.V2_QUIET_BANNER === '1') return;
  console.error(MATURITY_BANNER);
}

function assertNetworkAllowed(networkId, flags = {}) {
  if (networkId === NETWORK_MAINNET) {
    const allow = process.env.V2_ALLOW_MAINNET === '1'
      && (flags.iUnderstandMainnet === true || process.env.V2_I_UNDERSTAND_MAINNET === '1');
    if (!allow) {
      const err = new Error(
        'MAINNET_GATED: mainnet disabled until independent audits + Phase D ceremony. '
          + 'Chipnet only. Override only with V2_ALLOW_MAINNET=1 and '
          + '--i-understand-mainnet (still not a privacy/security qualification).',
      );
      err.code = 'MAINNET_GATED';
      throw err;
    }
  }
}

/** Transparent funding/signing wallet — blank-machine paths only. */
function loadTransparentWallet(home, explicitPath) {
  return loadFundingWallet({ home, path: explicitPath });
}

function loadLiveBundle(pool, home) {
  if (pool.liveTip?.carriers?.length === 7 && pool.liveTip?.state?.txid) {
    return {
      carriers: pool.liveTip.carriers.map((c) => ({
        txid: c.txid,
        vout: c.vout,
        value: BigInt(c.value),
        lock: Buffer.from(c.lockHex, 'hex'),
      })),
      binding: {
        txid: pool.liveTip.binding.txid,
        vout: pool.liveTip.binding.vout,
        value: BigInt(pool.liveTip.binding.value),
        lock: Buffer.from(pool.liveTip.binding.lockHex, 'hex'),
      },
      state: {
        txid: pool.liveTip.state.txid,
        vout: pool.liveTip.state.vout,
        value: BigInt(pool.liveTip.state.value),
        lock: Buffer.from(pool.liveTip.state.lockHex, 'hex'),
        commitment: Buffer.from(pool.liveTip.state.commitmentHex, 'hex'),
      },
    };
  }
  const tipPath = process.env.V2_LIVE_TIP_JSON
    || path.join(home, 'live-tip.json');
  if (existsSync(tipPath)) {
    const tip = JSON.parse(readFileSync(tipPath, 'utf8'));
    return loadLiveBundle({ liveTip: tip }, home);
  }
  return null;
}

function saveLiveBundle(home, pool, bundle) {
  const liveTip = {
    carriers: bundle.carriers.map((c) => ({
      txid: c.txid,
      vout: c.vout,
      value: String(c.value),
      lockHex: Buffer.from(c.lock).toString('hex'),
    })),
    binding: {
      txid: bundle.binding.txid,
      vout: bundle.binding.vout,
      value: String(bundle.binding.value),
      lockHex: Buffer.from(bundle.binding.lock).toString('hex'),
    },
    state: {
      txid: bundle.state.txid,
      vout: bundle.state.vout,
      value: String(bundle.state.value),
      lockHex: Buffer.from(bundle.state.lock).toString('hex'),
      commitmentHex: Buffer.from(bundle.state.commitment).toString('hex'),
    },
  };
  pool.liveTip = liveTip;
  savePool(home, pool);
  atomicWriteJson(path.join(home, 'live-tip.json'), liveTip, { mode: PRIVATE_FILE_MODE });
}

function pickFeeUtxo(wallet, need) {
  const fund = wallet.selectFundingUtxo(need, 'live-settle');
  return {
    txid: fund.txid || fund.outpoint?.split(':')[0],
    vout: fund.vout ?? Number(fund.outpoint?.split(':')[1] || 0),
    valueSats: BigInt(fund.value),
  };
}

/**
 * Full product path: densFuel unlocks + CashScript state + funding sign + live broadcast.
 * No V2_SETTLE_HEX — builds the settlement in-process.
 */
async function liveProductBroadcast({
  home, pool, wallet, kind, engineAction, expanded, proveWork, journal, op,
  withdrawalLockingBytecode = null,
  withdrawalHashHex = null,
  fundingWalletPath = null,
  feeUtxoOverride = null,
}) {
  assertNetworkAllowed(pool.networkId || NETWORK_CHIPNET);
  const live = await createLiveNetworkGate({
    network: pool.networkId === NETWORK_MAINNET ? 'mainnet' : 'chipnet',
  });
  const bundle = loadLiveBundle(pool, home);
  if (!bundle) {
    const err = new Error(
      'LIVE_TIP_REQUIRED: pool.liveTip or V2_LIVE_TIP_JSON required for densFuel+state settle',
    );
    err.code = 'LIVE_TIP_REQUIRED';
    throw err;
  }
  const transparent = loadTransparentWallet(home, fundingWalletPath);
  const need = kind === 'deposit' ? DENOMINATION_SATS + 200_000n : 200_000n;
  let feeUtxo = feeUtxoOverride;
  if (!feeUtxo) {
    // Prefer explicit funding-wallet utxos; fall back to note-wallet UTXO list
    try {
      if (transparent.utxos?.length) {
        feeUtxo = selectFundingUtxoFromList(transparent, need, kind);
      } else {
        feeUtxo = pickFeeUtxo(wallet, need);
      }
    } catch (e) {
      if (e.code === 'FUNDING_UTXO_REQUIRED' || /FUNDING_UTXO_REQUIRED/.test(e.message)) {
        feeUtxo = pickFeeUtxo(wallet, need);
      } else throw e;
    }
  }
  const dens = await buildDensfuelForPacket({
    packetBytes: engineAction.packet,
    expanded,
    workDir: path.join(proveWork, 'densfuel'),
    pinSeed: `${kind}-${op.id}`,
  });
  // Pin-compatible bind may rewrite transactionContextHash — settle MUST use bound packet.
  const boundAction = {
    ...engineAction,
    packet: dens.packetBytes || engineAction.packet,
  };
  // Pin locks against tip if carriers already committed
  for (let i = 0; i < dens.densLocks.length; i += 1) {
    if (bundle.carriers[i].lock.length && !dens.densLocks[i].equals(bundle.carriers[i].lock)) {
      throw new Error(`carrier lock drift at ${i}`);
    }
  }
  const settled = await assembleProductSettle({
    kind,
    engineAction: boundAction,
    dens,
    bundle,
    wallet: transparent,
    feeUtxo,
    category: Buffer.from(pool.instanceId, 'hex'),
    profileId: pool.profileId,
    withdrawalLockingBytecode: kind === 'withdrawal'
      ? (withdrawalLockingBytecode || transparent.lockingBytecode)
      : undefined,
    withdrawalHashHex: kind === 'withdrawal' ? withdrawalHashHex : undefined,
  });
  journal.transition(op.id, 'signed', { wire: settled.wire });
  journal.transition(op.id, 'broadcast');
  const txid = await live.broadcastRawTransaction(settled.hex);
  journal.transition(op.id, 'mempool', { txid });
  const postReserve = BigInt(engineAction.postState.reserveSats);
  const next = rollBundleAfterSettle({
    settleTxid: txid,
    densLocks: settled.densLocks,
    bindingLockHex: settled.bindingLockHex,
    stateLockingBytecode: settled.stateLockingBytecode,
    postCommitment: settled.postCommitment,
    postStateValue: STATE_BASE + postReserve,
  });
  saveLiveBundle(home, pool, next);
  return {
    txid,
    wire: settled.wire,
    densFuelGateOk: dens.result?.gateOk === true,
    pinBind: dens.pinBind || null,
    packetBound: dens.pinBind?.changed === true,
    withdrawalLockingBytecodeHex: settled.withdrawalLockingBytecodeHex,
    withdrawalHashHex: settled.withdrawalHashHex,
  };
}

const ROOT_FLAG = '--home';

function usage() {
  return `shieldkit-v2 — Protocol-design-v2 (one CLI: create pools + interact)

${MATURITY_BANNER}

Blank-machine story (Chipnet):
  1) init                         → home + shielded wallet + transparent funding address
  2) fund the printed address     → Chipnet faucet / peer (out-of-band)
  3) wallet funding-scan          → pull UTXOs from public Fulcrum (no bitcoind required)
  4) pool create --broadcast --category-utxo <txid:vout>
  5) deposit|transfer|withdraw --broadcast
  6) pool join <descriptor.json>  → interact with an existing live pool

Usage:
  shieldkit-v2 [--home <dir>] init
  shieldkit-v2 [--home <dir>] wallet create
  shieldkit-v2 [--home <dir>] wallet receive
  shieldkit-v2 [--home <dir>] wallet funding-create
  shieldkit-v2 [--home <dir>] wallet funding-scan
  shieldkit-v2 [--home <dir>] wallet set-funding <funding-wallet.json>
  shieldkit-v2 [--home <dir>] pool create --broadcast --category-utxo <txid:vout>
  shieldkit-v2 [--home <dir>] pool join|add <descriptor.json>
  shieldkit-v2 [--home <dir>] sync | status | doctor
  shieldkit-v2 [--home <dir>] deposit --broadcast
  shieldkit-v2 [--home <dir>] transfer --note <id> --broadcast
  shieldkit-v2 [--home <dir>] withdraw --note <id> [--to <cashaddr>] --broadcast
  shieldkit-v2 [--home <dir>] recover

Chain access (blank machine default = public Chipnet Fulcrum TLS):
  V2_CHIPNET_LIVE=1                 required for any --broadcast
  SHIELDKIT_ELECTRUM=host:port      optional override
  SHIELDKIT_RPC_URL=https://…       optional JSON-RPC
  (lab) SSH layer1-node used only if Fulcrum/RPC unavailable

Mainnet: refused unless V2_ALLOW_MAINNET=1 and --i-understand-mainnet
Docs: Protocol-design-v2/README.md · GOLDEN_PATH.md · PRIVACY.md · MATURITY.md
`;
}

function parseArgs(argv) {
  const args = [...argv];
  let home = path.resolve(process.cwd(), '.shieldkit-v2');
  const out = { _: [] };
  while (args.length) {
    const a = args.shift();
    if (a === ROOT_FLAG) home = path.resolve(args.shift());
    else if (a === '--broadcast') out.broadcast = true;
    else if (a === '--note') out.note = args.shift();
    else if (a === '--to') out.to = args.shift();
    else if (a === '--funding-wallet') out.fundingWallet = args.shift();
    else if (a === '--category-utxo') out.categoryUtxo = args.shift();
    else if (a === '--max-live') out.maxLive = Number(args.shift());
    else if (a === '--profile-id') out.profileId = args.shift();
    else if (a === '--i-understand-mainnet') out.iUnderstandMainnet = true;
    else if (a === '--network') out.network = args.shift();
    else if (a === '--help' || a === '-h') out.help = true;
    else out._.push(a);
  }
  out.home = home;
  return out;
}

function ensureHome(home) {
  mkdirSync(home, { recursive: true, mode: PRIVATE_DIRECTORY_MODE });
}

function poolPath(home) {
  return path.join(home, 'pool.json');
}

function loadPool(home) {
  const p = poolPath(home);
  if (!existsSync(p)) throw new Error('no pool configured; run pool add');
  return JSON.parse(readFileSync(p, 'utf8'));
}

function savePool(home, pool) {
  atomicWriteJson(poolPath(home), pool, { mode: PRIVATE_FILE_MODE });
}

function engineFromPool(pool, home) {
  const enginePath = path.join(home, 'engine-snapshot.json');
  // Always match production circuit depth (plan pin = CIRCUIT_TREE_DEPTH = 32).
  const depth = CIRCUIT_TREE_DEPTH;
  const engine = createPoolEngineV2({
    profileId: pool.profileId,
    instanceId: pool.instanceId,
    networkId: pool.networkId || NETWORK_CHIPNET,
    maximumLiveNotes: pool.maximumLiveNotes || PLAYGROUND_MAXIMUM_LIVE_NOTES,
    noteDepth: depth,
    nullifierDepth: depth,
  });
  // Replay history if present
  if (existsSync(enginePath)) {
    const snap = JSON.parse(readFileSync(enginePath, 'utf8'));
    // Re-exec deposits from stored actions for durable tip (simplified)
    for (const act of snap.actions || []) {
      if (act.kind === 'deposit') {
        engine.deposit({
          outputNoteLeaf: act.outputNoteLeaf,
          encryptedRecord: Buffer.from(act.encryptedRecordHex, 'hex'),
          transactionContextHash: act.transactionContextHash,
        });
      } else if (act.kind === 'transfer') {
        engine.transfer({
          spendSk: act.spendSk,
          spendRho: act.spendRho,
          spendCm: act.spendCm,
          outputNoteLeaf: act.outputNoteLeaf,
          encryptedRecord: Buffer.from(act.encryptedRecordHex, 'hex'),
          transactionContextHash: act.transactionContextHash,
        });
      } else if (act.kind === 'withdrawal') {
        engine.withdraw({
          spendSk: act.spendSk,
          spendRho: act.spendRho,
          spendCm: act.spendCm,
          withdrawalLockingBytecodeHash: act.withdrawalLockingBytecodeHash,
          transactionContextHash: act.transactionContextHash,
        });
      }
    }
  }
  return engine;
}

function saveEngineActions(home, actions) {
  atomicWriteJson(path.join(home, 'engine-snapshot.json'), { actions }, { mode: PRIVATE_FILE_MODE });
}

function loadActions(home) {
  const p = path.join(home, 'engine-snapshot.json');
  if (!existsSync(p)) return [];
  return JSON.parse(readFileSync(p, 'utf8')).actions || [];
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  printBanner();
  if (args.help || args._.length === 0) {
    console.log(usage());
    return 0;
  }
  const [cmd, sub] = args._;
  ensureHome(args.home);

  if (cmd === 'init') {
    // One-shot blank-machine bootstrap: shielded wallet + transparent funding key.
    const wallet = createNoteWallet(path.join(args.home, 'wallet'), {
      networkId: NETWORK_CHIPNET,
      profileId: createHash('sha256').update('pending-profile').digest('hex'),
      instanceId: createHash('sha256').update('pending-instance').digest('hex'),
    });
    const fundingPath = path.join(args.home, 'funding-wallet.json');
    let funding;
    if (!existsSync(fundingPath)) {
      const material = await generateFundingWalletMaterial({ networkId: NETWORK_CHIPNET });
      saveFundingWalletJson(fundingPath, material);
      funding = material;
    } else {
      funding = loadFundingWallet({ home: args.home });
    }
    console.log(JSON.stringify({
      ok: true,
      command: 'init',
      home: args.home,
      // Transparent Chipnet address to fund (P2PKH). Shielded notes use secrets under wallet/.
      fundingAddress: funding.address,
      fundingWalletPath: fundingPath,
      noteWalletSecrets: wallet.secretsPath,
      next: [
        '1. Fund fundingAddress on Chipnet (≥ ~0.2 BCH for pool create + first deposit)',
        '2. V2_CHIPNET_LIVE=1 shieldkit-v2 --home <home> wallet funding-scan',
        '3. pick a pure-P2PKH UTXO (prefer vout 0) as --category-utxo',
        '4. V2_CHIPNET_LIVE=1 … pool create --broadcast --category-utxo <txid:vout>',
        '5. … deposit --broadcast  |  pool join <descriptor.json> for an existing pool',
      ],
      maturity: 'dev-keys-only-not-for-real-money-privacy',
    }, null, 2));
    return 0;
  }

  if (cmd === 'wallet' && sub === 'create') {
    const wallet = createNoteWallet(path.join(args.home, 'wallet'), {
      networkId: NETWORK_CHIPNET,
      profileId: createHash('sha256').update('pending-profile').digest('hex'),
      instanceId: createHash('sha256').update('pending-instance').digest('hex'),
    });
    console.log(JSON.stringify({
      ok: true,
      home: args.home,
      secretsPath: wallet.secretsPath,
      secretsMode: (statSync(wallet.secretsPath).mode & 0o777).toString(8),
      address: wallet.address,
    }, null, 2));
    return 0;
  }

  if (cmd === 'wallet' && sub === 'funding-create') {
    const dest = path.join(args.home, 'funding-wallet.json');
    if (existsSync(dest) && process.env.V2_FORCE_FUNDING_CREATE !== '1') {
      throw new Error(`funding-wallet.json already exists at ${dest} (set V2_FORCE_FUNDING_CREATE=1 to overwrite)`);
    }
    const material = await generateFundingWalletMaterial({ networkId: NETWORK_CHIPNET });
    saveFundingWalletJson(dest, material);
    console.log(JSON.stringify({
      ok: true,
      fundingWalletPath: dest,
      address: material.address,
      next: [
        'Fund this Chipnet address (faucet/peer).',
        'Then: wallet funding-scan',
      ],
      maturity: 'dev-keys-only-not-for-real-money-privacy',
    }, null, 2));
    return 0;
  }

  if (cmd === 'wallet' && sub === 'funding-scan') {
    const fw = loadFundingWallet({ home: args.home, path: args.fundingWallet });
    if (!fw.address) throw new Error('funding wallet missing address field');
    // Scan does not require V2_CHIPNET_LIVE (read-only), but uses same RPC stack.
    const { createChipnetRpc } = await import('../operator/chipnet-rpc.mjs');
    const rpc = await createChipnetRpc({ network: 'chipnet' });
    const listed = await rpc.scanAddress(fw.address, fw.lockingBytecode.toString('hex'));
    const scanned = (listed || []).map((u) => ({
      txid: u.txid,
      vout: u.vout,
      valueSats: BigInt(u.sats ?? u.valueSats ?? 0),
    })).filter((u) => u.valueSats > 0n);
    const merged = mergeFundingUtxos(fw.path, scanned);
    const total = merged.reduce((a, u) => a + BigInt(u.valueSats), 0n);
    console.log(JSON.stringify({
      ok: true,
      backend: rpc.backend,
      label: rpc.label,
      address: fw.address,
      utxoCount: merged.length,
      totalSats: total.toString(),
      utxos: merged.map((u) => ({
        outpoint: `${u.txid}:${u.vout}`,
        valueSats: String(u.valueSats),
        vout0: Number(u.vout) === 0,
      })),
      hint: 'Use a vout0 pure-P2PKH outpoint for pool create --category-utxo (or let CLI split).',
    }, null, 2));
    return 0;
  }

  if (cmd === 'wallet' && sub === 'receive') {
    const walletDir = path.join(args.home, 'wallet');
    if (!existsSync(path.join(walletDir, 'secrets.json'))) {
      throw new Error('wallet missing; run wallet create');
    }
    const secrets = JSON.parse(readFileSync(path.join(walletDir, 'secrets.json'), 'utf8'));
    const address = shieldAddress({
      networkId: secrets.networkId,
      profileId: secrets.profileId,
      instanceId: secrets.instanceId,
      account: secrets.account,
    });
    // No faucet — only show address, required UTXO size, observed balance
    const utxos = existsSync(path.join(walletDir, 'utxos.json'))
      ? JSON.parse(readFileSync(path.join(walletDir, 'utxos.json'), 'utf8')).utxos
      : [];
    const balance = utxos.reduce((a, u) => a + BigInt(u.value), 0n);
    let funding = null;
    try {
      const fw = loadFundingWallet({ home: args.home, path: args.fundingWallet });
      funding = {
        path: fw.path,
        address: fw.address,
        utxoCount: fw.utxos.length,
        mode: fw.mode !== null ? fw.mode.toString(8) : null,
      };
    } catch {
      funding = {
        path: resolveFundingWalletPath({ home: args.home, path: args.fundingWallet }),
        note: 'not configured — wallet set-funding <json>',
      };
    }
    console.log(JSON.stringify({
      shieldAddress: address,
      requiredFundingSats: (DENOMINATION_SATS + 50_000n).toString(),
      observedNoteWalletUtxoSats: balance.toString(),
      fundingWallet: funding,
      note: 'Fund transparent keys out-of-band. No faucet. Dev keys only — not real-money privacy.',
    }, null, 2));
    return 0;
  }

  if (cmd === 'wallet' && sub === 'set-funding') {
    const src = args._[2] || args.fundingWallet;
    if (!src) throw new Error('wallet set-funding requires path to funding-wallet.json');
    const srcPath = path.resolve(src);
    // Validate format
    loadFundingWallet({ path: srcPath });
    const dest = path.join(args.home, 'funding-wallet.json');
    copyFileSync(srcPath, dest);
    try {
      const { chmodSync } = await import('node:fs');
      chmodSync(dest, 0o600);
    } catch { /* best effort */ }
    const fw = loadFundingWallet({ home: args.home });
    console.log(JSON.stringify({
      ok: true,
      fundingWalletPath: fw.path,
      address: fw.address,
      utxoCount: fw.utxos.length,
      mode: fw.mode !== null ? fw.mode.toString(8) : null,
      note: 'chmod 600 recommended; never commit this file',
    }, null, 2));
    return 0;
  }

  if (cmd === 'pool' && sub === 'create') {
    assertNetworkAllowed(
      args.network === 'mainnet' ? NETWORK_MAINNET : NETWORK_CHIPNET,
      { iUnderstandMainnet: args.iUnderstandMainnet },
    );
    if (!args.broadcast) {
      throw new Error('pool create requires --broadcast (on-chain genesis; no offline fake pool)');
    }
    if (!args.categoryUtxo || !/^[0-9a-fA-F]{64}:\d+$/.test(args.categoryUtxo)) {
      throw new Error('pool create requires --category-utxo <txid:vout> (P2PKH parent for CashToken mint)');
    }
    const [catTxid, catVoutStr] = args.categoryUtxo.split(':');
    const funding = loadTransparentWallet(args.home, args.fundingWallet);
    // Resolve category UTXO value from funding list or require value in env
    let catUtxo = funding.utxos.find(
      (u) => u.txid === catTxid.toLowerCase() && u.vout === Number(catVoutStr),
    );
    if (!catUtxo && process.env.V2_CATEGORY_VALUE_SATS) {
      catUtxo = {
        txid: catTxid.toLowerCase(),
        vout: Number(catVoutStr),
        valueSats: BigInt(process.env.V2_CATEGORY_VALUE_SATS),
      };
    }
    if (!catUtxo) {
      throw new Error(
        'category UTXO not in funding-wallet.json utxos[]; add it or set V2_CATEGORY_VALUE_SATS',
      );
    }
    const live = await createLiveNetworkGate({ network: 'chipnet' });
    // Force vout=0 for CashToken category mint
    let working = { ...catUtxo };
    if (working.vout !== 0) {
      const split = await ensureCategoryVout0(working, funding);
      if (split.splitTxHex) {
        const splitTxid = await live.broadcastRawTransaction(split.splitTxHex);
        working = { txid: splitTxid, vout: 0, valueSats: split.splitKeep };
        console.error(JSON.stringify({
          phase: 'category-vout0-split', txid: splitTxid, backend: live.backend, label: live.label,
        }));
      }
    }
    const profileId = args.profileId || randomProfileId();
    const maximumLiveNotes = args.maxLive || PLAYGROUND_MAXIMUM_LIVE_NOTES;
    const workDir = path.join(args.home, 'prove', `pool-create-${Date.now().toString(36)}`);
    mkdirSync(workDir, { recursive: true });
    const built = await buildPoolGenesis({
      profileId,
      categoryUtxo: working,
      fundingWallet: funding,
      networkId: NETWORK_CHIPNET,
      maximumLiveNotes,
      workDir,
    });
    const genesisTxid = await live.broadcastRawTransaction(built.genesisHex);
    const liveTip = {
      carriers: built.liveTipTemplate.carriers.map((c) => ({
        ...c,
        txid: genesisTxid,
      })),
      binding: { ...built.liveTipTemplate.binding, txid: genesisTxid },
      state: { ...built.liveTipTemplate.state, txid: genesisTxid },
    };
    const pool = {
      profileId: built.profileId,
      instanceId: built.instanceId,
      networkId: built.networkId,
      maximumLiveNotes: built.maximumLiveNotes,
      genesisTxid,
      genesisVout: 0,
      noteDepth: CIRCUIT_TREE_DEPTH,
      nullifierDepth: CIRCUIT_TREE_DEPTH,
      liveTip,
      maturity: 'dev-keys-only-not-for-real-money-privacy',
    };
    savePool(args.home, pool);
    atomicWriteJson(path.join(args.home, 'live-tip.json'), liveTip, { mode: PRIVATE_FILE_MODE });
    saveEngineActions(args.home, []);
    // Bind shielded wallet profile/instance
    const secretsPath = path.join(args.home, 'wallet', 'secrets.json');
    if (existsSync(secretsPath)) {
      const secrets = JSON.parse(readFileSync(secretsPath, 'utf8'));
      secrets.profileId = pool.profileId;
      secrets.instanceId = pool.instanceId;
      secrets.networkId = pool.networkId;
      atomicWriteJson(secretsPath, secrets, { mode: PRIVATE_FILE_MODE });
    }
    console.log(JSON.stringify({
      ok: true,
      command: 'pool create',
      genesisTxid,
      profileId: pool.profileId,
      instanceId: pool.instanceId,
      categoryHex: built.categoryHex,
      densFuelGateOk: built.densFuelGateOk,
      pinBind: built.pinBind,
      liveTipWritten: true,
      home: args.home,
      banner: 'DEV KEYS ONLY — not for real-money privacy',
    }, null, 2));
    return 0;
  }

  if (cmd === 'pool' && (sub === 'add' || sub === 'join')) {
    const descPath = args._[2];
    if (!descPath) throw new Error(`pool ${sub} requires descriptor path`);
    const descriptor = JSON.parse(readFileSync(descPath, 'utf8'));
    assertNetworkAllowed(descriptor.networkId || NETWORK_CHIPNET, {
      iUnderstandMainnet: args.iUnderstandMainnet,
    });
    const pool = {
      profileId: descriptor.profileId,
      instanceId: descriptor.instanceId,
      networkId: descriptor.networkId || NETWORK_CHIPNET,
      maximumLiveNotes: descriptor.maximumLiveNotes || PLAYGROUND_MAXIMUM_LIVE_NOTES,
      genesisTxid: descriptor.genesisTxid || null,
      genesisVout: descriptor.genesisVout ?? 0,
      noteDepth: CIRCUIT_TREE_DEPTH,
      nullifierDepth: CIRCUIT_TREE_DEPTH,
      liveTip: descriptor.liveTip || null,
      maturity: 'dev-keys-only-not-for-real-money-privacy',
    };
    savePool(args.home, pool);
    if (pool.liveTip) {
      atomicWriteJson(path.join(args.home, 'live-tip.json'), pool.liveTip, { mode: PRIVATE_FILE_MODE });
    }
    // Rebind wallet profile/instance if present
    const secretsPath = path.join(args.home, 'wallet', 'secrets.json');
    if (existsSync(secretsPath)) {
      const secrets = JSON.parse(readFileSync(secretsPath, 'utf8'));
      secrets.profileId = pool.profileId;
      secrets.instanceId = pool.instanceId;
      atomicWriteJson(secretsPath, secrets, { mode: PRIVATE_FILE_MODE });
    }
    console.log(JSON.stringify({ ok: true, pool }, null, 2));
    return 0;
  }

  if (cmd === 'sync' || cmd === 'status') {
    const pool = loadPool(args.home);
    const engine = engineFromPool(pool, args.home);
    const tip = engine.tip();
    console.log(JSON.stringify({
      command: cmd,
      instanceId: pool.instanceId,
      tip: {
        noteCount: tip.noteCount,
        nullifierCount: tip.nullifierCount,
        liveNoteCount: tip.liveNoteCount,
        reserveSats: tip.reserveSats,
        actionSequence: tip.actionSequence,
        noteRoot: tip.noteRoot,
        nullifierRoot: tip.nullifierRoot,
      },
      historyLength: loadActions(args.home).length,
    }, null, 2));
    return 0;
  }

  if (cmd === 'doctor') {
    const issues = [];
    const warnings = [
      'DEV KEYS ONLY — not for real-money privacy',
      'Mainnet gated until Phase D / audits',
    ];
    if (!existsSync(poolPath(args.home))) issues.push('missing pool');
    const secretsPath = path.join(args.home, 'wallet', 'secrets.json');
    if (!existsSync(secretsPath)) issues.push('missing wallet secrets');
    else {
      const mode = statSync(secretsPath).mode & 0o777;
      if (mode !== 0o600) issues.push(`secrets mode ${mode.toString(8)} (want 600)`);
    }
    const fwPath = resolveFundingWalletPath({ home: args.home, path: args.fundingWallet });
    if (!fwPath) warnings.push('no funding-wallet.json (required for pool create / live broadcast)');
    else {
      try {
        const fw = loadFundingWallet({ home: args.home, path: args.fundingWallet });
        if (fw.mode !== null && fw.mode !== 0o600) {
          warnings.push(`funding wallet mode ${fw.mode.toString(8)} (prefer 600)`);
        }
      } catch (e) {
        issues.push(`funding wallet: ${e.message}`);
      }
    }
    if (existsSync(poolPath(args.home))) {
      const pool = loadPool(args.home);
      assertNetworkAllowed(pool.networkId || NETWORK_CHIPNET, {
        iUnderstandMainnet: args.iUnderstandMainnet,
      });
      const engine = engineFromPool(pool, args.home);
      const tip = engine.tip();
      if (BigInt(tip.reserveSats) !== BigInt(tip.liveNoteCount) * DENOMINATION_SATS) {
        issues.push('reserve/live mismatch');
      }
      if (!pool.liveTip && !existsSync(path.join(args.home, 'live-tip.json'))) {
        warnings.push('no liveTip — deposit --broadcast will fail until pool create or tip import');
      }
    }
    console.log(JSON.stringify({
      ok: issues.length === 0,
      issues,
      warnings,
      home: args.home,
      maturity: 'dev-keys-only-not-for-real-money-privacy',
    }, null, 2));
    return issues.length === 0 ? 0 : 1;
  }

  if (cmd === 'deposit') {
    const pool = loadPool(args.home);
    const wallet = createNoteWallet(path.join(args.home, 'wallet'), {
      networkId: pool.networkId,
      profileId: pool.profileId,
      instanceId: pool.instanceId,
    });
    const journal = createJournal(path.join(args.home, 'journal'));
    const op = journal.createOperation({ kind: 'deposit' });

    // Funding check BEFORE prove
    try {
      wallet.selectFundingUtxo(DENOMINATION_SATS + 20_000n, op.id);
    } catch (error) {
      if (error.code === 'FUNDING_UTXO_REQUIRED' || /FUNDING_UTXO_REQUIRED/.test(error.message)) {
        console.error(JSON.stringify({ ok: false, error: 'FUNDING_UTXO_REQUIRED', beforeProve: true }));
        return 2;
      }
      throw error;
    }
    journal.transition(op.id, 'funding_selected');
    journal.transition(op.id, 'tip_synced');

    const engine = engineFromPool(pool, args.home);
    const account = wallet.getAccount();
    const addr = shieldAddress({
      networkId: pool.networkId,
      profileId: pool.profileId,
      instanceId: pool.instanceId,
      account,
    });
    const postSeq = BigInt(engine.tip().actionSequence) + 1n;
    const out = freshOutputNote({
      profileId: pool.profileId,
      instanceId: pool.instanceId,
      authority: addr.authority,
      postActionSequence: postSeq,
      viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
    });
    journal.transition(op.id, 'proving');
    const result = engine.deposit({
      outputNoteLeaf: out.outputNoteLeaf,
      encryptedRecord: out.encryptedRecord,
      transactionContextHash: createHash('sha256').update(`deposit-${op.id}`).digest('hex'),
    });
    // Real Groth16 prove (depth-32) — never mark proved without circuit verification.
    const proveWork = path.join(args.home, 'prove', op.id);
    const expanded = {
      note: {
        authority: addr.authority, rho: out.rho, r: out.r, cm: out.cm,
      },
      path: { index: result.noteAppend.index, siblings: result.noteAppend.path.siblings },
      encryption: {
        esk: out.esk,
        viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
        encryptedRecord: out.encryptedRecord,
      },
      recordCommitmentHex: out.recordCommitment,
      preNoteRoot: result.preState.noteRoot,
      postNoteRoot: result.postState.noteRoot,
      preNullifierRoot: result.preState.nullifierRoot,
      postNullifierRoot: result.postState.nullifierRoot,
    };
    const proved = await provePoolAction({
      packetBytes: result.packet,
      workDir: proveWork,
      expanded,
    });
    const noteId = `note-${result.postState.actionSequence}`;
    wallet.addNote({
      id: noteId,
      cm: out.cm,
      rho: out.rho,
      r: out.r,
      outputNoteLeaf: out.outputNoteLeaf,
      sk: account.sk,
      esk: out.esk,
      encryptedRecordHex: out.encryptedRecord.toString('hex'),
      recordCommitment: out.recordCommitment,
    });
    const actions = loadActions(args.home);
    actions.push({
      kind: 'deposit',
      outputNoteLeaf: out.outputNoteLeaf,
      encryptedRecordHex: out.encryptedRecord.toString('hex'),
      transactionContextHash: createHash('sha256').update(`deposit-${op.id}`).digest('hex'),
      noteId,
      digest: result.digest,
      proved: true,
      treeDepth: proved.treeDepth,
      proveMs: proved.ms,
    });
    saveEngineActions(args.home, actions);
    journal.transition(op.id, 'proved', {
      packetHex: result.packet.toString('hex'),
      publicSignals: proved.publicSignals,
      proveMs: proved.ms,
    });

    let txid = null;
    let settleMeta = null;
    if (args.broadcast) {
      try {
        settleMeta = await liveProductBroadcast({
          home: args.home,
          pool,
          wallet,
          kind: 'deposit',
          engineAction: result,
          expanded,
          proveWork,
          journal,
          op,
          fundingWalletPath: args.fundingWallet,
        });
        txid = settleMeta.txid;
      } catch (e) {
        console.error(JSON.stringify({
          ok: false,
          error: e.code
            || (e.name === 'ChipnetRpcError' ? 'CHIPNET_LIVE_REQUIRED' : 'BROADCAST_FAILED'),
          message: e.message,
          proved: true,
          proveMs: proved.ms,
          treeDepth: proved.treeDepth,
        }));
        return 3;
      }
    }

    console.log(JSON.stringify({
      ok: true,
      kind: 'deposit',
      noteId,
      digest: result.digest,
      publicInputs: result.publicInputs,
      publicSignals: proved.publicSignals,
      proveMs: proved.ms,
      treeDepth: proved.treeDepth,
      tip: engine.tip(),
      txid,
      broadcast: Boolean(args.broadcast),
      broadcastLive: Boolean(txid),
      densFuelGateOk: settleMeta?.densFuelGateOk ?? null,
      pinBind: settleMeta?.pinBind ?? null,
      wire: settleMeta?.wire ?? null,
    }, null, 2));
    return 0;
  }

  if (cmd === 'transfer') {
    const pool = loadPool(args.home);
    const wallet = createNoteWallet(path.join(args.home, 'wallet'), {
      networkId: pool.networkId,
      profileId: pool.profileId,
      instanceId: pool.instanceId,
    });
    const noteId = args.note;
    if (!noteId) throw new Error('--note required');
    const notes = wallet.listNotes();
    const note = notes.find((n) => n.id === noteId && n.status === 'unspent');
    if (!note) throw new Error('note not found or spent');

    const journal = createJournal(path.join(args.home, 'journal'));
    const op = journal.createOperation({ kind: 'transfer', noteId });
    try {
      wallet.selectFundingUtxo(20_000n, op.id);
    } catch (error) {
      if (/FUNDING_UTXO_REQUIRED/.test(error.message)) {
        console.error(JSON.stringify({ ok: false, error: 'FUNDING_UTXO_REQUIRED', beforeProve: true }));
        return 2;
      }
      throw error;
    }
    wallet.reserveNote(noteId, op.id);
    journal.transition(op.id, 'funding_selected');
    journal.transition(op.id, 'tip_synced');
    journal.transition(op.id, 'proving');

    const engine = engineFromPool(pool, args.home);
    const account = wallet.getAccount();
    // Self-transfer to same authority for CLI simplicity
    const addr = shieldAddress({
      networkId: pool.networkId,
      profileId: pool.profileId,
      instanceId: pool.instanceId,
      account,
    });
    const out = freshOutputNote({
      profileId: pool.profileId,
      instanceId: pool.instanceId,
      authority: addr.authority,
      postActionSequence: BigInt(engine.tip().actionSequence) + 1n,
      viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
    });
    const result = engine.transfer({
      spendSk: note.sk || account.sk,
      spendRho: note.rho,
      spendCm: note.cm,
      outputNoteLeaf: out.outputNoteLeaf,
      encryptedRecord: out.encryptedRecord,
      transactionContextHash: createHash('sha256').update(`transfer-${op.id}`).digest('hex'),
    });
    const proveWork = path.join(args.home, 'prove', op.id);
    const expanded = {
      note: {
        authority: addr.authority,
        rho: note.rho, r: note.r, cm: note.cm,
        sk: note.sk || account.sk,
        spentOutputLeaf: note.outputNoteLeaf,
        create: {
          authority: addr.authority, rho: out.rho, r: out.r, cm: out.cm,
        },
      },
      path: { index: result.noteAppend.index, siblings: result.noteAppend.path.siblings },
      nullifierInsert: result.nullifierInsert,
      encryption: {
        esk: out.esk,
        viewPoint: [frFromHex(account.V[0]), frFromHex(account.V[1])],
        encryptedRecord: out.encryptedRecord,
      },
      recordCommitmentHex: out.recordCommitment,
      preNoteRoot: result.preState.noteRoot,
      postNoteRoot: result.postState.noteRoot,
      preNullifierRoot: result.preState.nullifierRoot,
      postNullifierRoot: result.postState.nullifierRoot,
    };
    const proved = await provePoolAction({
      packetBytes: result.packet,
      workDir: proveWork,
      expanded,
    });
    wallet.markSpent(noteId);
    const newId = `note-${result.postState.actionSequence}`;
    wallet.addNote({
      id: newId,
      cm: out.cm,
      rho: out.rho,
      r: out.r,
      outputNoteLeaf: out.outputNoteLeaf,
      sk: account.sk,
      esk: out.esk,
      encryptedRecordHex: out.encryptedRecord.toString('hex'),
      recordCommitment: out.recordCommitment,
    });
    const actions = loadActions(args.home);
    actions.push({
      kind: 'transfer',
      spendSk: note.sk || account.sk,
      spendRho: note.rho,
      spendCm: note.cm,
      outputNoteLeaf: out.outputNoteLeaf,
      encryptedRecordHex: out.encryptedRecord.toString('hex'),
      transactionContextHash: createHash('sha256').update(`transfer-${op.id}`).digest('hex'),
      digest: result.digest,
      proved: true,
      treeDepth: proved.treeDepth,
      proveMs: proved.ms,
    });
    saveEngineActions(args.home, actions);
    journal.transition(op.id, 'proved', {
      packetHex: result.packet.toString('hex'),
      publicSignals: proved.publicSignals,
      proveMs: proved.ms,
    });
    let txid = null;
    let settleMeta = null;
    if (args.broadcast) {
      try {
        settleMeta = await liveProductBroadcast({
          home: args.home,
          pool,
          wallet,
          kind: 'transfer',
          engineAction: result,
          expanded,
          proveWork,
          journal,
          op,
          fundingWalletPath: args.fundingWallet,
        });
        txid = settleMeta.txid;
      } catch (e) {
        console.error(JSON.stringify({
          ok: false,
          error: e.code
            || (e.name === 'ChipnetRpcError' ? 'CHIPNET_LIVE_REQUIRED' : 'BROADCAST_FAILED'),
          message: e.message,
          proved: true,
          proveMs: proved.ms,
        }));
        return 3;
      }
    }
    console.log(JSON.stringify({
      ok: true,
      kind: 'transfer',
      noteId: newId,
      digest: result.digest,
      publicSignals: proved.publicSignals,
      proveMs: proved.ms,
      treeDepth: proved.treeDepth,
      txid,
      tip: engine.tip(),
      densFuelGateOk: settleMeta?.densFuelGateOk ?? null,
      wire: settleMeta?.wire ?? null,
    }, null, 2));
    return 0;
  }

  if (cmd === 'withdraw') {
    const pool = loadPool(args.home);
    const wallet = createNoteWallet(path.join(args.home, 'wallet'), {
      networkId: pool.networkId,
      profileId: pool.profileId,
      instanceId: pool.instanceId,
    });
    const noteId = args.note;
    if (!noteId) throw new Error('--note required');
    const note = wallet.listNotes().find((n) => n.id === noteId && n.status === 'unspent');
    if (!note) throw new Error('note not found or spent');
    // Single owner of payout lock ↔ packet hash (never sha256(cashaddr text)).
    // Offline prove with --to does not need a funding wallet; broadcast/default does.
    let defaultLock = null;
    if (!args.to || args.broadcast) {
      try {
        const transparentDefault = loadTransparentWallet(args.home, args.fundingWallet);
        defaultLock = transparentDefault.lockingBytecode;
      } catch (e) {
        if (args.broadcast || !args.to) {
          console.error(JSON.stringify({
            ok: false,
            error: e.code || 'FUNDING_WALLET',
            message: e.message,
          }));
          return 2;
        }
      }
    }
    let payout;
    try {
      payout = resolveWithdrawalPayout({
        toCashAddr: args.to,
        defaultLockingBytecode: defaultLock,
      });
    } catch (e) {
      console.error(JSON.stringify({
        ok: false,
        error: e.name === 'WithdrawPayoutError' ? 'WITHDRAW_PAYOUT_INVALID' : 'WITHDRAW_PAYOUT',
        message: e.message,
      }));
      return 2;
    }
    const withdrawalHash = payout.hashHex;

    const journal = createJournal(path.join(args.home, 'journal'));
    const op = journal.createOperation({ kind: 'withdrawal', noteId });
    try {
      wallet.selectFundingUtxo(20_000n, op.id);
    } catch (error) {
      if (/FUNDING_UTXO_REQUIRED/.test(error.message)) {
        console.error(JSON.stringify({ ok: false, error: 'FUNDING_UTXO_REQUIRED', beforeProve: true }));
        return 2;
      }
      throw error;
    }
    wallet.reserveNote(noteId, op.id);
    journal.transition(op.id, 'funding_selected');
    journal.transition(op.id, 'tip_synced');
    journal.transition(op.id, 'proving');
    const engine = engineFromPool(pool, args.home);
    const account = wallet.getAccount();
    const addr = shieldAddress({
      networkId: pool.networkId,
      profileId: pool.profileId,
      instanceId: pool.instanceId,
      account,
    });
    const result = engine.withdraw({
      spendSk: note.sk || account.sk,
      spendRho: note.rho,
      spendCm: note.cm,
      withdrawalLockingBytecodeHash: withdrawalHash,
      transactionContextHash: createHash('sha256').update(`withdraw-${op.id}`).digest('hex'),
    });
    // Membership path for spent note leaf (index from history / note metadata)
    const spentIndex = note.treeIndex ?? String(BigInt(result.preState.noteCount) - 1n);
    const spentPath = engine.noteTree.membershipPath(String(spentIndex));
    const proveWork = path.join(args.home, 'prove', op.id);
    const expanded = {
      note: {
        authority: addr.authority,
        rho: note.rho, r: note.r, cm: note.cm,
        sk: note.sk || account.sk,
        spentOutputLeaf: note.outputNoteLeaf,
      },
      path: { index: spentPath.index ?? spentIndex, siblings: spentPath.siblings },
      nullifierInsert: result.nullifierInsert,
      recordCommitmentHex: ZERO_32_HEX,
      preNoteRoot: result.preState.noteRoot,
      postNoteRoot: result.postState.noteRoot,
      preNullifierRoot: result.preState.nullifierRoot,
      postNullifierRoot: result.postState.nullifierRoot,
    };
    const proved = await provePoolAction({
      packetBytes: result.packet,
      workDir: proveWork,
      expanded,
    });
    wallet.markSpent(noteId);
    const actions = loadActions(args.home);
    actions.push({
      kind: 'withdrawal',
      spendSk: note.sk || account.sk,
      spendRho: note.rho,
      spendCm: note.cm,
      withdrawalLockingBytecodeHash: withdrawalHash,
      transactionContextHash: createHash('sha256').update(`withdraw-${op.id}`).digest('hex'),
      digest: result.digest,
      proved: true,
      treeDepth: proved.treeDepth,
      proveMs: proved.ms,
    });
    saveEngineActions(args.home, actions);
    journal.transition(op.id, 'proved', {
      packetHex: result.packet.toString('hex'),
      publicSignals: proved.publicSignals,
      proveMs: proved.ms,
    });
    let txid = null;
    let settleMeta = null;
    if (args.broadcast) {
      try {
        settleMeta = await liveProductBroadcast({
          home: args.home,
          pool,
          wallet,
          kind: 'withdrawal',
          engineAction: result,
          expanded,
          proveWork,
          journal,
          op,
          withdrawalLockingBytecode: payout.lockingBytecode,
          withdrawalHashHex: payout.hashHex,
          fundingWalletPath: args.fundingWallet,
        });
        txid = settleMeta.txid;
      } catch (e) {
        console.error(JSON.stringify({
          ok: false,
          error: e.code
            || (e.name === 'ChipnetRpcError' ? 'CHIPNET_LIVE_REQUIRED' : 'BROADCAST_FAILED'),
          message: e.message,
          proved: true,
          proveMs: proved.ms,
        }));
        return 3;
      }
    }
    console.log(JSON.stringify({
      ok: true,
      kind: 'withdrawal',
      digest: result.digest,
      publicSignals: proved.publicSignals,
      proveMs: proved.ms,
      treeDepth: proved.treeDepth,
      payoutSats: DENOMINATION_SATS.toString(),
      payoutSource: payout.source,
      withdrawalHashHex: payout.hashHex,
      withdrawalLockingBytecodeHex: payout.lockingBytecodeHex,
      txid,
      tip: engine.tip(),
      densFuelGateOk: settleMeta?.densFuelGateOk ?? null,
      wire: settleMeta?.wire ?? null,
    }, null, 2));
    return 0;
  }

  if (cmd === 'recover') {
    const pool = loadPool(args.home);
    const actions = loadActions(args.home);
    // Rebuild from genesis lineage stored locally (packets on disk stand in for chain)
    const genesis = {
      txid: pool.genesisTxid || '0'.repeat(64),
      vout: pool.genesisVout ?? 0,
    };
    const engine = createPoolEngineV2({
      profileId: pool.profileId,
      instanceId: pool.instanceId,
      networkId: pool.networkId,
      maximumLiveNotes: pool.maximumLiveNotes,
      noteDepth: CIRCUIT_TREE_DEPTH,
      nullifierDepth: CIRCUIT_TREE_DEPTH,
    });
    // wipe and replay
    for (const act of actions) {
      if (act.kind === 'deposit') {
        engine.deposit({
          outputNoteLeaf: act.outputNoteLeaf,
          encryptedRecord: Buffer.from(act.encryptedRecordHex, 'hex'),
          transactionContextHash: act.transactionContextHash,
        });
      } else if (act.kind === 'transfer') {
        engine.transfer({
          spendSk: act.spendSk,
          spendRho: act.spendRho,
          spendCm: act.spendCm,
          outputNoteLeaf: act.outputNoteLeaf,
          encryptedRecord: Buffer.from(act.encryptedRecordHex, 'hex'),
          transactionContextHash: act.transactionContextHash,
        });
      } else if (act.kind === 'withdrawal') {
        engine.withdraw({
          spendSk: act.spendSk,
          spendRho: act.spendRho,
          spendCm: act.spendCm,
          withdrawalLockingBytecodeHash: act.withdrawalLockingBytecodeHash,
          transactionContextHash: act.transactionContextHash,
        });
      }
    }
    console.log(JSON.stringify({
      ok: true,
      recoveredFrom: genesis,
      actions: actions.length,
      tip: engine.tip(),
    }, null, 2));
    return 0;
  }

  console.error(usage());
  throw new Error(`unknown command: ${args._.join(' ')}`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().then((code) => process.exit(code ?? 0)).catch((error) => {
    console.error(error.message || error);
    process.exit(1);
  });
}

export { main, usage };
