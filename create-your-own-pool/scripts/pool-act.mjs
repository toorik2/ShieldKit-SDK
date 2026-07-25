#!/usr/bin/env node
/**
 * Full act against a pool directory: deposit | transfer | withdraw.
 * Uses completeAction + Chipnet RPC (public Electrum / JSON-RPC / lab layer1).
 *
 * Usage:
 *   node create-your-own-pool/scripts/pool-act.mjs deposit --pool ./my-pool \
 *     --wallets ./wallets.json [--broadcast] [--scan-fees]
 *
 * Funding: --funding-txid/--funding-vout or first eligible state.feeUtxos entry.
 * RPC: SHIELDKIT_RPC_URL | SHIELDKIT_ELECTRUM | public Fulcrum | layer1-node SSH.
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import { completeAction, PIN_LENS } from '../packages/kit/complete-action.mjs';
import { createChipnetRpc } from '../packages/kit/chipnet-rpc.mjs';
import { resolveUnlockRoot } from '../packages/unlock-builder/index.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ZERO32 = '00'.repeat(32);

/** @type {Awaited<ReturnType<typeof createChipnetRpc>> | null} */
let rpc = null;
/** @type {{ address?: string, lockingBytecodeHex?: string }} */
let hotCtx = {};

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function hasFlag(name) {
  return process.argv.includes(`--${name}`);
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

function minSats(kind) {
  return kind === 'deposit' ? 11_500_000 : 1_500_000;
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
async function scanFeesIntoState(state, hotAddress, minKeep = 1_500_000) {
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

  rpc = await createChipnetRpc();
  console.error(JSON.stringify({ phase: 'rpc', backend: rpc.backend, label: rpc.label }));

  const instance = JSON.parse(readFileSync(instancePath, 'utf8'));
  const state = existsSync(statePath)
    ? JSON.parse(readFileSync(statePath, 'utf8'))
    : { stateTxid: null, feeUtxos: [], history: [] };

  const stateTxid = arg('state-txid', state.stateTxid);
  if (!stateTxid) {
    throw new Error(
      'stateTxid missing — set state.json or --state-txid to the current State NFT tip txid '
      + '(genesis settle or last settle). Explorer: chipnet.chaingraph.cash',
    );
  }

  const wallets = JSON.parse(readFileSync(walletsPath, 'utf8'));
  const hot = wallets.hot;
  if (!hot?.privateKeyHex || !hot?.publicKeyHex || !hot?.lockingBytecodeHex) {
    throw new Error('wallets.hot needs privateKeyHex, publicKeyHex, lockingBytecodeHex, address');
  }
  hotCtx = { address: hot.address, lockingBytecodeHex: hot.lockingBytecodeHex };
  const feePrivateKey = Buffer.from(hot.privateKeyHex, 'hex');
  const loaded = await loadVerifierProfileBundle(bundleDir);
  const expectedProfile = {
    profileId: instance.profileId || loaded.manifest.identity.profileId,
    instanceId: instance.instanceId || loaded.manifest.genesis.instanceId,
    network: instance.network || 'chipnet',
  };

  // Optional / auto hot-wallet scan into fee inventory (RPC-verified).
  if (hasFlag('scan-fees') || hasFlag('scan-fees-always')) {
    const n = await scanFeesIntoState(state, hot.address, 1_500_000);
    console.error(JSON.stringify({ phase: 'scan-fees', ...n }));
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
  // Prefer ≥2 live fees ≥ need (deposit needs 11.5M; T/W need 1.5M).
  if (!fixedFunding && !hasFlag('no-scan-fees')) {
    const liveLarge = await countLiveFees(state, need, new Set());
    if (liveLarge < 2) {
      try {
        const n = await scanFeesIntoState(state, hot.address, need);
        console.error(JSON.stringify({
          phase: 'scan-fees-auto',
          reason: liveLarge === 0 ? 'no-live-fee' : 'fee-diversity',
          need,
          beforeLarge: liveLarge,
          ...n,
        }));
      } catch (e) {
        console.error(JSON.stringify({ phase: 'scan-fees-auto-fail', error: String(e.message || e).slice(0, 160) }));
      }
    }
  }

  const wsh = createHash('sha256').update(Buffer.from(hot.lockingBytecodeHex, 'hex')).digest('hex');
  // Multi-note open set (live anonymity). Each entry: { witnessSeed, depositDigest }.
  state.openNotes = Array.isArray(state.openNotes) ? state.openNotes : [];
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
        if (!pick) throw new Error(`no fee UTXO ≥ ${need} in state.json (pass --funding-txid or --scan-fees)`);
        funding = { ...pick, publicKeyHex: hot.publicKeyHex };
        state.feeUtxos = state.feeUtxos.filter((u) => !(u.txid === pick.txid && u.vout === pick.vout));
      }

      workDir = path.join(pool, 'runs', `${kind}-a${attempt}-${Date.now()}`);
      mkdirSync(workDir, { recursive: true });
      console.error(JSON.stringify({
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
      }));

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
        withdrawalLockingBytecode: Buffer.from(hot.lockingBytecodeHex, 'hex'),
        priorCycles,
        priorOpenNotes,
        actionKind: kind,
        transferHops: 0,
        digests,
        stabilizeUnlockTemplate,
      });

      if (JSON.stringify(result.lens) !== JSON.stringify(PIN_LENS)) {
        throw new Error(`pin lens mismatch ${JSON.stringify(result.lens)}`);
      }
      lastErr = null;
      break;
    } catch (e) {
      lastErr = e;
      const errText = String(e.message || e) + String(e.code || '');
      const retriable = /gateOk|OP_VERIFY|GATE_FAIL|BUILD_EXIT|unlock build|libauth|pin lens/i
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
            console.error(JSON.stringify({
              phase: 'scan-fees-on-retry',
              attempt,
              reason: gateClass ? 'GATE_FAIL-fee-diversity' : 'retry-fee-refresh',
              need,
              rejected: rejected.size,
              ...n,
            }));
          } catch (scanErr) {
            console.error(JSON.stringify({
              phase: 'scan-fees-on-retry-fail',
              error: String(scanErr.message || scanErr).slice(0, 160),
            }));
          }
        }

        let otherLarge = (await countLiveFees(state, need, rejected)) > 0;
        if (!otherLarge) {
          // No alternate: put fee back and optionally rotate witness (not mid-cycle).
          rejected.delete(k);
          pushFee(state, { txid: funding.txid, vout: funding.vout, sats: funding.sats });
          if (!state.resumeSeed) {
            witnessSeed = randomBytes(32).toString('hex');
            console.error(JSON.stringify({
              phase: 'rotate-witness',
              attempt,
              reason: 'no-alternate-fee',
            }));
          }
        }
        // else: keep rejected; next attempt picks a different live fee
      }

      console.error(JSON.stringify({
        phase: 'attempt_fail',
        kind,
        attempt,
        error: String(e.message || e).slice(0, 200),
        code: e.code || null,
        gateClass,
        rejectedFees: rejected.size,
      }));
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
    state.openNotes.push({
      witnessSeed,
      depositDigest: dig.deposit,
      phase: 'deposit',
      settleTxid: result.settleTxid,
    });
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

  writeFileSync(statePath, JSON.stringify(state, null, 2));
  appendFileSync(path.join(pool, 'ledger.jsonl'), `${JSON.stringify({
    ts: new Date().toISOString(), kind, prepTxid: result.prepTxid, settleTxid: result.settleTxid,
    wire: result.wire, unlockMs: result.unlockMs, broadcast: doBroadcast,
    openNotes: state.openNotes.length,
  })}\n`);

  console.log(JSON.stringify({
    ok: true,
    kind,
    pool,
    prepTxid: result.prepTxid,
    settleTxid: result.settleTxid,
    wire: result.wire,
    maxUnlock: result.maxUnlock,
    proveMs: result.proveMs,
    unlockMs: result.unlockMs,
    lens: result.lens,
    unlockRoot: result.unlockRoot,
    broadcast: doBroadcast,
    workDir,
    feeUtxos: (state.feeUtxos || []).length,
    openNotes: state.openNotes.length,
    liveAnonymitySet: state.openNotes.length,
  }, null, 2));
  process.exit(0);
}

main().catch((e) => {
  console.error('FAIL', e.message || e);
  process.exit(1);
});
