#!/usr/bin/env node
/**
 * Full act against a pool directory: deposit | transfer | withdraw.
 * Uses completeAction + Chipnet RPC (public Electrum / JSON-RPC / lab layer1).
 *
 * Usage:
 *   node 03-create-your-own-pool/scripts/pool-act.mjs deposit --pool ./my-pool \
 *     --wallets ./wallets.json [--broadcast]
 *
 * Product defaults (hide fee/UTXO/ECIP pain):
 *   - auto tip discovery
 *   - auto fee UTXO scan (unless --no-scan-fees)
 *   - auto consolidate small hot UTXOs when none ≥ need (unless --no-auto-consolidate)
 *   - ECIP/fee retries inside completeAction
 *   - quiet progress unless --verbose or SHIELDKIT_VERBOSE=1
 *
 * Funding override: --funding-txid/--funding-vout
 * RPC: SHIELDKIT_RPC_URL | SHIELDKIT_ELECTRUM | public Fulcrum | layer1-node SSH.
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  decodeTransaction,
  hexToBin,
  binToHex,
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '../packages/action/node_modules/@bitauth/libauth/build/index.js';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import { completeAction, PIN_LENS } from '../packages/kit/complete-action.mjs';
import { createChainRpc } from '../packages/kit/chipnet-rpc.mjs';
import { discoverStateTip } from '../packages/kit/state-tip.mjs';
import { parsePf7CarrierAuthority } from '../packages/prove/authority.mjs';
import { resolveUnlockRoot } from '../packages/unlock-builder/index.mjs';
import {
  syncTipForestFromSettlementLog,
  assertNoGlobalOpenSetGate,
  ownedNoteFromOpenMeta,
  fetchSettlementLogFromTip,
  settlementLogLooksComplete,
  applySettlementLog,
} from '../packages/pool/index.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ZERO32 = '00'.repeat(32);
const VERBOSE = process.env.SHIELDKIT_VERBOSE === '1'
  || process.argv.includes('--verbose');

/** @type {Awaited<ReturnType<typeof createChainRpc>> | null} */
let rpc = null;
/** @type {{ address?: string, lockingBytecodeHex?: string, privateKeyHex?: string, publicKeyHex?: string }} */
let hotCtx = {};

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

/** Product-facing progress (always). Internal phases only when VERBOSE. */
function productLog(msg) {
  console.error(typeof msg === 'string' ? msg : JSON.stringify(msg));
}
function debugLog(obj) {
  if (VERBOSE) console.error(JSON.stringify(obj));
}

async function bchnSendHex(hex) {
  return rpc.sendrawtransaction(hex);
}

async function bchnTestMempool(hex) {
  return rpc.testmempoolaccept(hex);
}

async function gettxout(txid, vout) {
  // Electrum path: re-check against hot wallet UTXO set when available.
  if (rpc.backend === 'electrum' && (hotCtx.lockingBytecodeHex || hotCtx.address)) {
    const list = await rpc.scanAddress(hotCtx.address, hotCtx.lockingBytecodeHex);
    const hit = list.find((u) => u.txid === txid && Number(u.vout) === Number(vout));
    if (!hit) return null;
    return { value: hit.sats / 1e8, confirmations: 1 };
  }
  const u = await rpc.gettxout(txid, vout);
  if (!u) return null;
  if (u._partial && u.value == null) {
    // Unknown spent-status on partial backend — treat as live only if scan finds it.
    if (hotCtx.lockingBytecodeHex || hotCtx.address) {
      const list = await rpc.scanAddress(hotCtx.address, hotCtx.lockingBytecodeHex);
      const hit = list.find((x) => x.txid === txid && Number(x.vout) === Number(vout));
      if (!hit) return null;
      return { value: hit.sats / 1e8, confirmations: 1 };
    }
  }
  return u;
}

async function scantxoutsetAddr(address) {
  const unspents = await rpc.scanAddress(address, hotCtx.lockingBytecodeHex);
  return {
    unspents: unspents.map((u) => ({
      txid: u.txid,
      vout: u.vout,
      amount: u.sats / 1e8,
    })),
  };
}

/**
 * Fee-input value floor for prep (not fee *rate* — rate is always 1 sat/B).
 *
 * Prep exact need (packages/action/prep.mjs deriveCompletePlan):
 *   PF7 carriers + bindingBase [+ denom if deposit] + settlementFeeFunding + prepWireFee
 *   + dust change
 * settlementFeeFunding must cover settle wire (≤59k B @ 1 sat/B) + dust change.
 * Pin PF7 = 7×1000; bindingBase = 1000. Prep wire pad is scan threshold only;
 * actual fee = exact wire size.
 */
const DENOMINATION_SATS_NUM = 10_000_000;
const PF7_CARRIER_TOTAL_PIN = 7_000;
const BINDING_BASE = 1_000;
const SETTLE_WIRE_LIMIT = 59_000;
const P2PKH_DUST = 546;
/** Default settlement fee-funding output (must cover max settle @ 1 sat/B + dust). */
const SETTLEMENT_FEE_FUNDING = SETTLE_WIRE_LIMIT + P2PKH_DUST;
/** Prep tx ~10 outs; pad for scan only (actual fee = wire bytes). */
const PREP_WIRE_PAD = 3_000;

function minSats(kind) {
  const base = PF7_CARRIER_TOTAL_PIN + BINDING_BASE + SETTLEMENT_FEE_FUNDING
    + PREP_WIRE_PAD + P2PKH_DUST;
  return kind === 'deposit' ? base + DENOMINATION_SATS_NUM : base;
}

function pushFee(state, u) {
  if (!u?.txid || u.vout === undefined || !u.sats) return;
  state.feeUtxos = state.feeUtxos || [];
  if (!state.feeUtxos.some((x) => x.txid === u.txid && x.vout === u.vout)) {
    state.feeUtxos.push({ txid: u.txid, vout: Number(u.vout), sats: Number(u.sats) });
  }
}

/**
 * priorCycles = completed cycles only.
 * Strip legacy `kind` / unknown keys; drop in-flight resumeSeed rows (nullifier collide).
 */
function priorCyclesFromState(state) {
  const resume = state.resumeSeed || null;
  const out = [];
  for (const h of state.history || []) {
    if (!h?.witnessSeed || !h?.transactionContextDigests) continue;
    if (resume && h.witnessSeed === resume) continue;
    const dig = h.transactionContextDigests;
    if (!dig.deposit || !dig.transfer || !dig.withdrawal) continue;
    // Incomplete mid-cycle rows (zeros in later digests) must not be priorCycles.
    if (dig.transfer === ZERO32 || dig.withdrawal === ZERO32) continue;
    const row = {
      witnessSeed: h.witnessSeed,
      transactionContextDigests: {
        deposit: dig.deposit,
        transfer: dig.transfer,
        withdrawal: dig.withdrawal,
      },
    };
    if (h.transferHops === 0 || h.transferHops === 1) row.transferHops = h.transferHops;
    out.push(row);
  }
  return out;
}

function loadStab(kind) {
  const p = path.join(ROOT, `.cache/stabilize-pf7-${kind}/build/inputs_dump.json`);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

/**
 * Refresh fee inventory from hot wallet.
 * Always gettxout-verifies (scantxoutset can return spent phantoms).
 * Prunes dead entries already in state.feeUtxos.
 * @returns {{ added: number, stale: number, pruned: number, feeCount: number, large: number }}
 */
async function scanFeesIntoState(state, hotAddress, minKeep = minSats('withdrawal')) {
  let pruned = 0;
  const kept = [];
  for (const u of state.feeUtxos || []) {
    if (await gettxout(u.txid, u.vout)) kept.push(u);
    else pruned++;
  }
  state.feeUtxos = kept;

  const scan = await scantxoutsetAddr(hotAddress);
  const rows = (scan.unspents || [])
    .map((u) => ({
      txid: u.txid,
      vout: Number(u.vout),
      scanSats: Math.round(Number(u.amount) * 1e8),
    }))
    .filter((u) => u.scanSats >= minKeep)
    .sort((a, b) => b.scanSats - a.scanSats);

  let added = 0;
  let stale = 0;
  for (const cand of rows) {
    const u = await gettxout(cand.txid, cand.vout);
    if (!u) {
      stale++;
      continue;
    }
    const sats = Math.round(Number(u.value) * 1e8);
    if (sats < minKeep) {
      stale++;
      continue;
    }
    const before = (state.feeUtxos || []).length;
    pushFee(state, { txid: cand.txid, vout: cand.vout, sats });
    if ((state.feeUtxos || []).length > before) added++;
  }
  const feeCount = (state.feeUtxos || []).length;
  const large = (state.feeUtxos || []).filter((u) => u.sats >= minKeep).length;
  return { added, stale, pruned, feeCount, large };
}

async function countLiveFees(state, need, rejected) {
  let n = 0;
  for (const u of state.feeUtxos || []) {
    if (u.sats < need || rejected.has(`${u.txid}:${u.vout}`)) continue;
    if (await gettxout(u.txid, u.vout)) n += 1;
  }
  return n;
}

/**
 * Merge small hot UTXOs into one ≥ needSats output (hides UTXO gymnastics).
 * Returns funding {txid,vout,sats} or null if already have large UTXO / insufficient.
 */
async function autoConsolidateHot(hot, needSats) {
  const unspents = await rpc.scanAddress(hot.address, hot.lockingBytecodeHex);
  unspents.sort((a, b) => b.sats - a.sats);
  const large = unspents.find((u) => u.sats >= needSats);
  if (large) return { txid: large.txid, vout: large.vout, sats: large.sats };

  const selected = [];
  let sum = 0n;
  for (const u of unspents) {
    selected.push(u);
    sum += BigInt(u.sats);
    if (sum >= BigInt(needSats) + 500_000n) break;
  }
  if (sum < BigInt(needSats) + 50_000n) return null;

  const lock = hexToBin(hot.lockingBytecodeHex);
  const priv = hexToBin(hot.privateKeyHex);
  const pub = hexToBin(hot.publicKeyHex);
  const secp = await instantiateSecp256k1();
  const sourceOutputs = selected.map((u) => ({
    lockingBytecode: lock,
    valueSatoshis: BigInt(u.sats),
  }));

  const build = (fee) => {
    const change = Number(sum) - needSats - fee;
    const outputs = [{ lockingBytecode: lock, valueSatoshis: BigInt(needSats) }];
    if (change >= 546) outputs.push({ lockingBytecode: lock, valueSatoshis: BigInt(change) });
    const tx = {
      version: 2,
      locktime: 0,
      inputs: selected.map((u) => ({
        outpointTransactionHash: hexToBin(u.txid),
        outpointIndex: Number(u.vout),
        sequenceNumber: 0xffffffff,
        unlockingBytecode: new Uint8Array(0),
      })),
      outputs,
    };
    for (let i = 0; i < selected.length; i++) {
      const ss = generateSigningSerializationBch({
        inputIndex: i,
        sourceOutputs,
        transaction: tx,
      }, {
        coveredBytecode: lock,
        signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
      });
      const sig = secp.signMessageHashSchnorr(priv, hash256(ss));
      if (typeof sig === 'string') throw new Error(sig);
      const sigWithType = new Uint8Array([...sig, 0x41]);
      const unlock = new Uint8Array(1 + sigWithType.length + 1 + pub.length);
      unlock[0] = sigWithType.length;
      unlock.set(sigWithType, 1);
      unlock[1 + sigWithType.length] = pub.length;
      unlock.set(pub, 2 + sigWithType.length);
      tx.inputs[i].unlockingBytecode = unlock;
    }
    return tx;
  };

  let fee = 400 + selected.length * 150;
  let tx = build(fee);
  let hex = binToHex(encodeTransaction(tx));
  const wire = hex.length / 2;
  if (fee < wire) {
    fee = wire;
    tx = build(fee);
    hex = binToHex(encodeTransaction(tx));
  }
  productLog(`Preparing coins (merged ${selected.length} UTXOs → ${needSats} sats)…`);
  const txid = await rpc.sendrawtransaction(hex);
  debugLog({ phase: 'auto-consolidate', txid, needSats, inputs: selected.length });
  await new Promise((r) => setTimeout(r, 2500));
  return { txid, vout: 0, sats: needSats };
}

async function main() {
  const verb = process.argv[2];
  const kind = verb === 'withdraw' ? 'withdrawal' : verb;
  if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) {
    throw new Error('usage: pool-act.mjs deposit|transfer|withdraw --pool <dir> …');
  }

  const pool = path.resolve(arg('pool', ''));
  if (!pool || !existsSync(pool)) throw new Error('--pool <dir> required');
  const walletsPath = path.resolve(arg('wallets', path.join(ROOT, '.cache/e2e-full-20260725/local-wallets.json')));
  if (!existsSync(walletsPath)) throw new Error(`wallets missing: ${walletsPath}`);

  const instancePath = path.join(pool, 'instance.json');
  const statePath = path.join(pool, 'state.json');
  const bundleDir = path.join(pool, 'bundle');
  if (!existsSync(instancePath) || !existsSync(bundleDir)) {
    throw new Error('pool must contain instance.json and bundle/');
  }

  const instance = JSON.parse(readFileSync(instancePath, 'utf8'));
  const network = instance.network === 'mainnet' ? 'mainnet' : 'chipnet';
  rpc = await createChainRpc({ network });
  debugLog({ phase: 'rpc', backend: rpc.backend, label: rpc.label, network });
  productLog(`Connecting (${network} · ${rpc.label || rpc.backend})…`);

  const state = existsSync(statePath)
    ? JSON.parse(readFileSync(statePath, 'utf8'))
    : { stateTxid: null, feeUtxos: [], history: [], openNotes: [] };

  const wallets = JSON.parse(readFileSync(walletsPath, 'utf8'));
  const hot = wallets.hot;
  if (!hot?.privateKeyHex || !hot?.publicKeyHex || !hot?.lockingBytecodeHex) {
    throw new Error('wallets.hot needs privateKeyHex, publicKeyHex, lockingBytecodeHex, address');
  }
  hotCtx = {
    address: hot.address,
    lockingBytecodeHex: hot.lockingBytecodeHex,
    privateKeyHex: hot.privateKeyHex,
    publicKeyHex: hot.publicKeyHex,
  };
  const feePrivateKey = Buffer.from(hot.privateKeyHex, 'hex');
  const loaded = await loadVerifierProfileBundle(bundleDir);
  const expectedProfile = {
    profileId: instance.profileId || loaded.manifest.identity.profileId,
    instanceId: instance.instanceId || loaded.manifest.genesis.instanceId,
    network,
  };

  // Tip: CLI override → state.json cache → chain discovery (moves every settle).
  let stateTxid = arg('state-txid', state.stateTxid || null);
  const wantRefresh = hasFlag('refresh-tip') || !stateTxid;
  if (wantRefresh) {
    const vsPath = path.join(bundleDir, 'artifacts/verifier-set.bin');
    if (!existsSync(vsPath)) throw new Error('bundle missing artifacts/verifier-set.bin for tip discovery');
    const authority = parsePf7CarrierAuthority(JSON.parse(readFileSync(vsPath, 'utf8')));
    const category = (instance.stateNftCategory || loaded.manifest?.genesis?.stateNftCategory || '').toLowerCase();
    const preferred = typeof stateTxid === 'string' && /^[0-9a-f]{64}$/i.test(stateTxid)
      ? stateTxid.toLowerCase()
      : null;
    const tip = await discoverStateTip({
      rpc,
      stateLockingBytecode: authority.settlementKernel.stateLock,
      stateNftCategory: category,
      instanceId: expectedProfile.instanceId,
      preferredStateTxid: preferred || undefined,
    });
    // Keep local tip if it is strictly newer than discovery (broadcast lag).
    const localSeq = state.tipMeta?.actionSequence;
    if (
      preferred
      && localSeq != null
      && BigInt(localSeq) > BigInt(tip.actionSequence)
    ) {
      stateTxid = preferred;
      debugLog({
        phase: 'tip-discover',
        keptLocal: true,
        stateTxid: preferred,
        localActionSequence: localSeq,
        discoveredActionSequence: tip.actionSequence,
      });
    } else {
      stateTxid = tip.stateTxid;
      state.stateTxid = tip.stateTxid;
      state.tipMeta = {
        vout: tip.vout,
        height: tip.height,
        actionSequence: tip.actionSequence,
        discoveredAt: new Date().toISOString(),
        source: tip.source || 'chain-discover',
      };
    }
    writeFileSync(statePath, JSON.stringify(state, null, 2));
    productLog(`Tip ready (seq ${state.tipMeta?.actionSequence ?? tip.actionSequence})`);
    debugLog({
      phase: 'tip-discover',
      stateTxid,
      vout: state.tipMeta?.vout ?? tip.vout,
      height: state.tipMeta?.height ?? tip.height,
      actionSequence: state.tipMeta?.actionSequence ?? tip.actionSequence,
      source: state.tipMeta?.source ?? tip.source,
      unspentMatches: tip.unspentMatches,
      scanned: tip.scanned,
    });
  }
  if (!stateTxid) {
    throw new Error('stateTxid missing after discovery — pass --state-txid explicitly');
  }

  // Optional / auto hot-wallet scan into fee inventory (RPC-verified).
  if (hasFlag('scan-fees') || hasFlag('scan-fees-always')) {
    const n = await scanFeesIntoState(state, hot.address, minSats(kind));
    debugLog({ phase: 'scan-fees', ...n });
  }

  const need = minSats(kind);
  let fixedFunding = null;
  {
    const fTx = arg('funding-txid');
    if (fTx) {
      fixedFunding = {
        txid: fTx,
        vout: Number(arg('funding-vout', '0')),
        sats: Number(arg('funding-sats', '0')),
        publicKeyHex: hot.publicKeyHex,
      };
      const u = await gettxout(fixedFunding.txid, fixedFunding.vout);
      if (!u) throw new Error(`funding UTXO missing/spent on chain ${fixedFunding.txid}:${fixedFunding.vout}`);
      fixedFunding.sats = Math.round(u.value * 1e8);
    }
  }

  // Ensure inventory once up front when using feeUtxos path.
  // Prefer ≥2 live fees ≥ need (exact prep floor @ 1 sat/B economics).
  if (!fixedFunding && !hasFlag('no-scan-fees')) {
    productLog('Checking coin inventory…');
    const liveLarge = await countLiveFees(state, need, new Set());
    if (liveLarge < 2) {
      try {
        const n = await scanFeesIntoState(state, hot.address, need);
        debugLog({
          phase: 'scan-fees-auto',
          reason: liveLarge === 0 ? 'no-live-fee' : 'fee-diversity',
          need,
          beforeLarge: liveLarge,
          ...n,
        });
      } catch (e) {
        debugLog({ phase: 'scan-fees-auto-fail', error: String(e.message || e).slice(0, 160) });
      }
    }
  }

  // Auto-merge fragmented hot UTXOs when none ≥ need (product: hide UTXO gymnastics).
  if (!fixedFunding && !hasFlag('no-auto-consolidate')) {
    const liveLarge = await countLiveFees(state, need, new Set());
    if (liveLarge === 0) {
      try {
        const merged = await autoConsolidateHot(hot, need);
        if (merged) {
          pushFee(state, merged);
          writeFileSync(statePath, JSON.stringify(state, null, 2));
          productLog('Coins ready for deposit/withdraw.');
        }
      } catch (e) {
        debugLog({ phase: 'auto-consolidate-fail', error: String(e.message || e).slice(0, 200) });
      }
    }
  }

  // Withdrawal payout lock: optional --withdraw-to <cashaddr> or wallets.withdraw.lockingBytecodeHex
  // Fee signing still uses wallets.hot.
  let withdrawLockHex = hot.lockingBytecodeHex;
  const withdrawTo = arg('withdraw-to', null) || wallets.withdraw?.address || null;
  if (wallets.withdraw?.lockingBytecodeHex) {
    withdrawLockHex = wallets.withdraw.lockingBytecodeHex;
  } else if (withdrawTo) {
    const { decodeCashAddress: dec } = await import(
      '../packages/action/node_modules/@bitauth/libauth/build/index.js'
    );
    const decoded = dec(withdrawTo);
    if (typeof decoded === 'string') throw new Error(`--withdraw-to invalid: ${decoded}`);
    const payload = decoded.payload;
    if (!payload || payload.length !== 20) {
      throw new Error('--withdraw-to must be a P2PKH cashaddr (20-byte payload)');
    }
    withdrawLockHex = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      Buffer.from(payload),
      Buffer.from([0x88, 0xac]),
    ]).toString('hex');
    debugLog({ phase: 'withdraw-to', address: withdrawTo });
  }
  const wsh = createHash('sha256').update(Buffer.from(withdrawLockHex, 'hex')).digest('hex');
  // Shared multi-user model:
  //   openNotes = *my* private note secrets only (never required to equal global liveNoteCount).
  //   tipForest = rebuilt from public settlement log when available, else residual cache.
  // OPEN_SET_DESYNC (myNotes.length === tipLive) is removed by construction.
  state.openNotes = Array.isArray(state.openNotes) ? state.openNotes : [];
  state.settlementLog = state.settlementLog || null; // { genesisTxid, genesisHex, settles: hex[] }

  // Product invariant: my note count may be << global live set.
  assertNoGlobalOpenSetGate(state.openNotes.length, Number(state.tipForest?.state?.liveNoteCount || 0) || 0);

  let tipNftCommitmentHex = null;
  let tipSeqFromNft = state.tipMeta?.actionSequence != null
    ? String(state.tipMeta.actionSequence)
    : null;
  if (stateTxid) {
    try {
      const raw = await rpc._electrumCall?.('blockchain.transaction.get', [stateTxid, false]);
      if (typeof raw === 'string') {
        const tipTx = decodeTransaction(hexToBin(raw));
        if (typeof tipTx !== 'string' && tipTx.outputs?.[0]?.token?.nft?.commitment) {
          tipNftCommitmentHex = binToHex(tipTx.outputs[0].token.nft.commitment);
          tipSeqFromNft = BigInt(
            `0x${Buffer.from(tipNftCommitmentHex.slice(144, 160), 'hex').reverse().toString('hex')}`,
          ).toString();
          const forestSeq = state.tipForest?.state?.actionSequence;
          if (forestSeq != null && forestSeq !== tipSeqFromNft) {
            debugLog({
              phase: 'tip-forest-stale',
              tipActionSequence: tipSeqFromNft,
              forestSeq,
              note: 'rebuilding public tip from settlementLog / chain walk',
            });
          }
        }
      }
    } catch {
      // soft
    }
  }

  // Blank join / multi-history tip: walk tip→genesis on Electrum and fill settlementLog.
  const forestSeqNow = state.tipForest?.state?.actionSequence != null
    ? String(state.tipForest.state.actionSequence)
    : null;
  const forestMatchesTip = tipSeqFromNft != null && forestSeqNow === tipSeqFromNft;
  const logComplete = settlementLogLooksComplete(state.settlementLog, tipSeqFromNft);
  if (
    !hasFlag('no-fetch-settlement-log')
    && instance.genesisTxid
    && stateTxid
    && (!logComplete || !forestMatchesTip)
  ) {
    const needWalk = !logComplete
      || (tipSeqFromNft != null && tipSeqFromNft !== '0' && !forestMatchesTip);
    if (needWalk) {
      productLog('Rebuilding pool tip from chain history…');
      try {
        const fetched = await fetchSettlementLogFromTip({
          rpc,
          tipTxid: stateTxid,
          genesisTxid: instance.genesisTxid,
          decodeTransaction,
          binToHex,
        });
        applySettlementLog(state, fetched);
        writeFileSync(statePath, JSON.stringify(state, null, 2));
        productLog(
          fetched.depth === 0
            ? 'Tip is genesis (empty live set).'
            : `Public tip history ready (${fetched.depth} settle${fetched.depth === 1 ? '' : 's'}).`,
        );
        debugLog({
          phase: 'settlement-log-fetch',
          depth: fetched.depth,
          settleTxids: fetched.settleTxids,
        });
      } catch (e) {
        debugLog({
          phase: 'settlement-log-fetch-fail',
          err: String(e.message || e).slice(0, 220),
        });
        if (tipSeqFromNft && tipSeqFromNft !== '0' && !forestMatchesTip) {
          throw new Error(
            `Cannot rebuild tip from chain (${e.message || e}). `
            + 'Need Electrum access to walk settles tip→genesis, or a residual tipForest in state.json.',
          );
        }
      }
    }
  }

  // Chain-as-log tip rebuild when we have genesis + settles (or residual complete log)
  if (
    state.settlementLog?.genesisHex
    && Array.isArray(state.settlementLog.settles)
    && (state.settlementLog.settles.length > 0 || tipSeqFromNft === '0')
  ) {
    if (state.settlementLog.settles.length > 0) {
      try {
        const vsPath = path.join(bundleDir, 'artifacts/verifier-set.bin');
        const vs = JSON.parse(readFileSync(vsPath, 'utf8'));
        const auth = parsePf7CarrierAuthority(vs);
        // Prefer full secrets already on openNotes (wallet path); residual tipForest only fills gaps.
        const secretMetaByIndex = {};
        for (const m of state.tipForest?.openNoteMeta || []) {
          if (m?.noteIndex != null && m?.note1) secretMetaByIndex[Number(m.noteIndex)] = m;
        }
        const myOpenNotes = state.openNotes.map((n, i) => {
          // Prefer notes that already carry note1/key1/nfLeaf1 from deposit write
          if (n.note1 && n.key1 != null && n.nfLeaf1) {
            return {
              noteIndex: n.noteIndex != null ? n.noteIndex : i,
              leaf: n.leaf,
              key1: String(n.key1),
              nfLeaf1: n.nfLeaf1,
              note1: n.note1,
              witnessSeed: n.witnessSeed,
              depositDigest: n.depositDigest,
            };
          }
          return {
            noteIndex: n.noteIndex != null ? n.noteIndex : i,
            leaf: n.leaf,
            witnessSeed: n.witnessSeed,
            depositDigest: n.depositDigest,
            key1: n.key1,
            nfLeaf1: n.nfLeaf1,
            note1: n.note1,
          };
        });
        const synced = await syncTipForestFromSettlementLog({
          genesisTransactionId: state.settlementLog.genesisTxid || instance.genesisTxid,
          genesisTransactionHex: state.settlementLog.genesisHex,
          settleTransactionHexes: state.settlementLog.settles,
          profileId: (instance.profileId || '').replace(/^sha256:/, ''),
          instanceId: (instance.instanceId || '').replace(/^sha256:/, ''),
          stateNftCategory: (instance.categoryTxid || instance.stateNftCategory || '').toLowerCase(),
          stateLockingBytecodeHex: Buffer.from(auth.settlementKernel.stateLock).toString('hex'),
          stateCarrierBaseSatoshis: '1080',
          tipNftCommitmentHex: tipNftCommitmentHex || undefined,
          myOpenNotes,
          // Only residual fill-in when openNotes still lack secrets (legacy state.json)
          secretMetaByIndex,
        });
        state.tipForest = synced.tipForest;
        state.publicTip = synced.publicTip;
        writeFileSync(statePath, JSON.stringify(state, null, 2));
        productLog(
          `Tip forest ready (live ${synced.publicTip.state.liveNoteCount}, seq ${synced.publicTip.state.actionSequence}).`,
        );
        debugLog({
          phase: 'tip-rebuild-from-log',
          events: synced.publicTip.eventCount,
          liveNoteCount: synced.publicTip.state.liveNoteCount,
          actionSequence: synced.publicTip.state.actionSequence,
          myOpenNotes: state.openNotes.length,
        });
      } catch (e) {
        debugLog({
          phase: 'tip-rebuild-from-log-fail',
          err: String(e.message || e).slice(0, 200),
        });
        // Fall through to residual tipForest if rebuild fails (e.g. incomplete log)
        if (tipSeqFromNft && tipSeqFromNft !== '0' && !forestMatchesTip) {
          throw new Error(
            `tip rebuild from settlement log failed: ${e.message || e}`,
          );
        }
      }
    }
  }
  const digests = {
    deposit: ZERO32, transfer: ZERO32, withdrawal: ZERO32,
  };
  // Deposit always uses a fresh seed and stacks onto openNotes.
  // Transfer/withdraw act on LIFO open note (seed = that note's deposit seed).
  let witnessSeed;
  let priorOpenNotes = [];
  const mapOpen = (n) => ({
    witnessSeed: n.witnessSeed,
    depositDigest: n.depositDigest,
    ...(n.phase === 'transfer' ? { phase: 'transfer', transferDigest: n.transferDigest } : { phase: 'deposit' }),
  });
  if (kind === 'deposit') {
    witnessSeed = randomBytes(32).toString('hex');
    priorOpenNotes = state.openNotes.map(mapOpen);
  } else if (kind === 'transfer' || kind === 'withdrawal') {
    if (state.openNotes.length === 0) {
      throw new Error(`${kind} requires openNotes (deposit first to grow the live set)`);
    }
    const target = state.openNotes[state.openNotes.length - 1];
    witnessSeed = target.witnessSeed;
    // Rebuild all open notes including the one we spend (LIFO).
    priorOpenNotes = state.openNotes.map(mapOpen);
  } else {
    witnessSeed = randomBytes(32).toString('hex');
  }
  const priorCycles = priorCyclesFromState(state);
  const unlockRoot = resolveUnlockRoot();
  const stabilizeUnlockTemplate = loadStab(kind) || undefined;

  // Extra attempts when fee diversity + rescan can clear intermittent OP_VERIFY.
  const MAX_ATTEMPTS = 6;
  const rejected = new Set();
  let result = null;
  let funding = null;
  let workDir = null;
  let lastErr = null;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      if (fixedFunding) {
        // Re-verify fixed funding each attempt (mempool races).
        const u = await gettxout(fixedFunding.txid, fixedFunding.vout);
        if (!u) throw new Error(`funding UTXO missing/spent ${fixedFunding.txid}:${fixedFunding.vout}`);
        funding = {
          ...fixedFunding,
          sats: Math.round(u.value * 1e8),
        };
      } else {
        // park rejected fees
        const parked = [];
        state.feeUtxos = (state.feeUtxos || []).filter((u) => {
          const k = `${u.txid}:${u.vout}`;
          if (rejected.has(k)) { parked.push(u); return false; }
          return true;
        });
        const sorted = [...(state.feeUtxos || [])].sort((a, b) => b.sats - a.sats);
        let pick = null;
        for (const u of sorted) {
          if (u.sats < need) continue;
          if (await gettxout(u.txid, u.vout)) { pick = u; break; }
        }
        for (const u of parked) pushFee(state, u);
        if (!pick) {
          throw new Error(
            `Need ≥ ${need} sats in one coin on hot wallet ${hot.address || ''}. `
            + 'Fund that address on Chipnet (deposit needs ~0.11 BCH; withdraw ~0.01 BCH), then retry. '
            + 'Fees and coin selection are automatic.',
          );
        }
        funding = { ...pick, publicKeyHex: hot.publicKeyHex };
        state.feeUtxos = state.feeUtxos.filter((u) => !(u.txid === pick.txid && u.vout === pick.vout));
      }

      workDir = path.join(pool, 'runs', `${kind}-a${attempt}-${Date.now()}`);
      mkdirSync(workDir, { recursive: true });
      if (attempt === 1) {
        productLog(
          kind === 'deposit'
            ? 'Depositing (prove + unlock — often 30–90s)…'
            : kind === 'withdrawal'
              ? 'Withdrawing (prove + unlock — often 30–90s)…'
              : `${kind} in progress (prove + unlock)…`,
        );
      } else {
        productLog(`Retrying ${kind} (attempt ${attempt}/${MAX_ATTEMPTS})…`);
      }
      debugLog({
        phase: 'pool-act-start',
        kind,
        attempt,
        pool,
        stateTxid,
        unlockRoot,
        priorCycles: priorCycles.length,
        resume: !!state.resumeSeed,
        funding: { txid: funding.txid.slice(0, 16), vout: funding.vout, sats: funding.sats },
        liveLargeFees: fixedFunding ? null : await countLiveFees(state, need, rejected),
      });

      result = await completeAction({
        kind,
        bundleDirectory: bundleDir,
        expectedProfile,
        stateTxid,
        feePrivateKey,
        funding,
        workDir,
        witnessSeed,
        withdrawalScriptHash: wsh,
        withdrawalLockingBytecode: Buffer.from(withdrawLockHex, 'hex'),
        priorCycles,
        priorOpenNotes,
        tipForest: state.tipForest || null,
        actionKind: kind,
        transferHops: 0,
        digests,
        stabilizeUnlockTemplate,
      });

      if (JSON.stringify(result.lens) !== JSON.stringify(PIN_LENS)) {
        throw new Error(`pin lens mismatch ${JSON.stringify(result.lens)}`);
      }

      // Fail closed before broadcast: packet preState must match live tip NFT commitment.
      // Offline Libauth uses synthesized tip from preState and can pass while chain rejects OP_VERIFY.
      if (result.preState?.stateCommitment) {
        const tipU = await gettxout(stateTxid, 0);
        if (tipU?._partial === undefined && tipU?.value != null) {
          // Prefer raw tip decode when electrum has full gettx
        }
        try {
          const raw = await rpc._electrumCall?.('blockchain.transaction.get', [stateTxid, false]);
          if (typeof raw === 'string') {
            const tipTx = decodeTransaction(hexToBin(raw));
            if (typeof tipTx !== 'string' && tipTx.outputs?.[0]?.token?.nft?.commitment) {
              const cmt = binToHex(tipTx.outputs[0].token.nft.commitment);
              const tipCommit = cmt.slice(80, 144);
              if (tipCommit !== result.preState.stateCommitment) {
                throw new Error(
                  `TIP_PRESTATE_MISMATCH: packet preState.stateCommitment≠chain tip NFT `
                  + `(pre.seq=${result.preState.actionSequence} live=${result.preState.liveNoteCount} `
                  + `next=${result.preState.nextLeafIndex}). `
                  + 'After any withdraw, state.json must retain tipForest (not openNotes alone). '
                  + 'Rebuild from openNotes omits nullifiers/extra leaves → offline gateOk, chain OP_VERIFY fail.',
                );
              }
            }
          }
        } catch (e) {
          if (String(e.message || e).includes('TIP_PRESTATE_MISMATCH')) throw e;
          debugLog({
            phase: 'tip-prestate-check-soft-fail',
            error: String(e.message || e).slice(0, 160),
          });
        }
      }

      lastErr = null;
      break;
    } catch (e) {
      lastErr = e;
      const errText = String(e.message || e) + String(e.code || '');
      // Do not retry missing toolchain (SPAWN_FAIL/ENOENT/tsx) — re-prove is pure waste.
      const fatalToolchain = /SPAWN_FAIL|ENOENT|tsx not found|unlock toolchain/i.test(errText);
      const retriable = !fatalToolchain
        && /gateOk|OP_VERIFY|GATE_FAIL|BUILD_EXIT|unlock build|libauth|pin lens/i
          .test(errText);
      const gateClass = /gateOk|OP_VERIFY|GATE_FAIL/i.test(errText);

      // Return fee to inventory for possible retry; park if we will try alternate.
      if (funding && !fixedFunding) {
        const k = `${funding.txid}:${funding.vout}`;
        rejected.add(k);

        // On GATE_FAIL: rescan hot wallet for fee diversity (not only when inventory empty).
        // Intermittent genesis OP_VERIFY often clears with a different funding UTXO.
        if (retriable && !hasFlag('no-scan-fees') && attempt < MAX_ATTEMPTS) {
          try {
            const n = await scanFeesIntoState(state, hot.address, need);
            debugLog({
              phase: 'scan-fees-on-retry',
              attempt,
              reason: gateClass ? 'GATE_FAIL-fee-diversity' : 'retry-fee-refresh',
              need,
              rejected: rejected.size,
              ...n,
            });
          } catch (scanErr) {
            debugLog({
              phase: 'scan-fees-on-retry-fail',
              error: String(scanErr.message || scanErr).slice(0, 160),
            });
          }
        }

        let otherLarge = (await countLiveFees(state, need, rejected)) > 0;
        if (!otherLarge) {
          // No alternate: put fee back and optionally rotate witness (not mid-cycle).
          rejected.delete(k);
          pushFee(state, { txid: funding.txid, vout: funding.vout, sats: funding.sats });
          if (!state.resumeSeed) {
            witnessSeed = randomBytes(32).toString('hex');
            debugLog({
              phase: 'rotate-witness',
              attempt,
              reason: 'no-alternate-fee',
            });
          }
        }
        // else: keep rejected; next attempt picks a different live fee
      }

      debugLog({
        phase: 'attempt_fail',
        kind,
        attempt,
        error: String(e.message || e).slice(0, 200),
        code: e.code || null,
        gateClass,
        rejectedFees: rejected.size,
      });
      if (!retriable || attempt === MAX_ATTEMPTS) throw e;
    }
  }
  if (!result) throw lastErr || new Error(`${kind} failed after ${MAX_ATTEMPTS} attempts`);

  const doBroadcast = hasFlag('broadcast');
  if (doBroadcast) {
    const prepA = await bchnTestMempool(result.prepHex);
    if (prepA?.[0] && prepA[0].allowed === false) {
      throw new Error(`prep mempool reject ${JSON.stringify(prepA)}`);
    }
    await bchnSendHex(result.prepHex);
    const setA = await bchnTestMempool(result.settleHex);
    if (setA?.[0] && setA[0].allowed === false) {
      throw new Error(`settle mempool reject ${JSON.stringify(setA)}`);
    }
    await bchnSendHex(result.settleHex);
    // Harvest settle change + prep change (prep leftover is usually next fee).
    for (let i = 0; i < result.complete.transaction.outputs.length; i++) {
      const o = result.complete.transaction.outputs[i];
      if (Buffer.from(o.lockingBytecode).toString('hex') === hot.lockingBytecodeHex) {
        pushFee(state, { txid: result.settleTxid, vout: i, sats: Number(o.valueSatoshis) });
      }
    }
    if (Array.isArray(result.prepHotChange)) {
      for (const u of result.prepHotChange) pushFee(state, u);
    }
  }

  state.stateTxid = result.settleTxid;
  state.history = state.history || [];
  // Clear legacy mid-cycle resume fields (openNotes is the live-set model).
  delete state.resumeSeed;
  delete state.resumeDigests;

  const dig = result.digests || {};
  if (kind === 'deposit') {
    // Persist full spend secrets from act residual openNoteMeta into openNotes
    // so backup / tip-rebuild can withdraw without residual tipForest.
    const metas = result.tipForest?.openNoteMeta || [];
    const myMeta = metas.find((m) => m.witnessSeed === witnessSeed) || metas[metas.length - 1];
    let owned = null;
    if (myMeta?.note1 && myMeta.key1 != null && myMeta.nfLeaf1) {
      try {
        owned = ownedNoteFromOpenMeta(myMeta, {
          witnessSeed,
          depositDigest: dig.deposit || ZERO32,
          createdSeq: result.tipForest?.state?.actionSequence,
        });
      } catch (e) {
        debugLog({ phase: 'wallet-secret-capture-fail', err: String(e.message || e).slice(0, 160) });
      }
    }
    if (owned) {
      state.openNotes.push({
        ...owned,
        phase: 'deposit',
        settleTxid: result.settleTxid,
      });
    } else {
      // Legacy fallback — withdraw will fail without residual tipForest openNoteMeta
      state.openNotes.push({
        witnessSeed,
        depositDigest: dig.deposit,
        phase: 'deposit',
        settleTxid: result.settleTxid,
      });
    }
  } else if (kind === 'transfer') {
    // LIFO spend + replace with transfer-output note (same seed, phase=transfer).
    if (state.openNotes.length === 0) throw new Error('transfer with empty openNotes');
    const prev = state.openNotes[state.openNotes.length - 1];
    state.openNotes = state.openNotes.slice(0, -1);
    state.openNotes.push({
      witnessSeed,
      depositDigest: prev.depositDigest,
      transferDigest: dig.transfer,
      phase: 'transfer',
      settleTxid: result.settleTxid,
    });
  } else if (kind === 'withdrawal') {
    if (state.openNotes.length === 0) throw new Error('withdrawal with empty openNotes');
    state.openNotes = state.openNotes.slice(0, -1);
  }

  // Persist tip forest after every successful act (required after withdraw residual).
  if (result.tipForest) {
    state.tipForest = result.tipForest;
  }
  if (result.postState) {
    state.tipMeta = {
      ...(state.tipMeta || {}),
      actionSequence: result.postState.actionSequence,
      liveNoteCount: result.postState.liveNoteCount,
      nextLeafIndex: result.postState.nextLeafIndex,
      stateCommitment: result.postState.stateCommitment,
      updatedAt: new Date().toISOString(),
      source: doBroadcast ? 'post-broadcast-act' : 'post-act-offline',
    };
  }

  // Append public settlement log (chain-as-log tip rebuild source)
  state.settlementLog = state.settlementLog || {
    genesisTxid: instance.genesisTxid,
    genesisHex: state.settlementLog?.genesisHex || null,
    settles: [],
  };
  if (!state.settlementLog.genesisHex && instance.genesisTxid) {
    try {
      const gHex = await rpc._electrumCall?.('blockchain.transaction.get', [instance.genesisTxid, false]);
      if (typeof gHex === 'string') state.settlementLog.genesisHex = gHex;
    } catch { /* soft */ }
  }
  if (result.settleHex) {
    state.settlementLog.settles = state.settlementLog.settles || [];
    state.settlementLog.settles.push(result.settleHex);
  } else if (result.settleTxid && doBroadcast) {
    try {
      const sHex = await rpc._electrumCall?.('blockchain.transaction.get', [result.settleTxid, false]);
      if (typeof sHex === 'string') {
        state.settlementLog.settles = state.settlementLog.settles || [];
        state.settlementLog.settles.push(sHex);
      }
    } catch { /* soft */ }
  }

  writeFileSync(statePath, JSON.stringify(state, null, 2));
  appendFileSync(path.join(pool, 'ledger.jsonl'), `${JSON.stringify({
    ts: new Date().toISOString(), kind, prepTxid: result.prepTxid, settleTxid: result.settleTxid,
    wire: result.wire, unlockMs: result.unlockMs, broadcast: doBroadcast,
    openNotes: state.openNotes.length,
  })}\n`);

  productLog(
    doBroadcast
      ? `${kind} settled ${result.settleTxid}`
      : `${kind} built offline (not broadcast)`,
  );
  console.log(JSON.stringify({
    ok: true,
    kind,
    pool,
    prepTxid: result.prepTxid,
    settleTxid: result.settleTxid,
    wire: result.wire,
    proveMs: result.proveMs,
    unlockMs: result.unlockMs,
    broadcast: doBroadcast,
    openNotes: state.openNotes.length,
    // private open-note count only — not global live set
  }, null, 2));
  process.exit(0);
}

main().catch((e) => {
  productLog(`Error: ${e.message || e}`);
  if (VERBOSE && e.stack) console.error(e.stack);
  process.exit(1);
});
