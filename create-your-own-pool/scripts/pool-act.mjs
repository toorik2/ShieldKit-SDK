#!/usr/bin/env node
/**
 * Full act against a pool directory: deposit | transfer | withdraw.
 * Uses completeAction + optional BCHN broadcast (layer1-node).
 *
 * Usage:
 *   node create-your-own-pool/scripts/pool-act.mjs deposit --pool ./my-pool \
 *     --wallets .cache/e2e-full-20260725/local-wallets.json [--broadcast] [--scan-fees]
 *
 * Funding: --funding-txid/--funding-vout or first eligible state.feeUtxos entry.
 * State machine (matches standalone-e2e-chipnet):
 *   - mid-cycle: update resumeDigests/resumeSeed only (no history push)
 *   - after full D→T→W digests: push { witnessSeed, transactionContextDigests } once
 *   - harvest settle hot outs + prepHotChange into feeUtxos
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import { completeAction, PIN_LENS } from '../packages/kit/complete-action.mjs';
import { resolveUnlockRoot } from '../packages/unlock-builder/index.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SSH_OPTS = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=20'];
const ZERO32 = '00'.repeat(32);

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

function bchnSendHex(hex) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `cat > /tmp/sk-pool-act.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf sendrawtransaction "$(cat /tmp/sk-pool-act.hex)" true`], {
    encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`sendraw: ${r.stderr || r.stdout}`);
  return (r.stdout || '').trim();
}

function bchnTestMempool(hex) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `cat > /tmp/sk-pool-act.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf testmempoolaccept "[\\"$(cat /tmp/sk-pool-act.hex)\\"]"`], {
    encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`testmempool: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout);
}

function gettxout(txid, vout) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf gettxout ${txid} ${vout} true`], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  const t = (r.stdout || '').trim();
  if (!t || t === 'null') return null;
  try { return JSON.parse(t); } catch { return null; }
}

/** Parse first top-level JSON object from bitcoin-cli / mixed stdout. */
function parseFirstJsonObject(raw) {
  const start = raw.indexOf('{');
  if (start < 0) throw new Error('no JSON object in output');
  let depth = 0;
  for (let i = start; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return JSON.parse(raw.slice(start, i + 1));
    }
  }
  throw new Error('unterminated JSON object');
}

function scantxoutsetAddr(address) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf scantxoutset start '["addr(${address})"]'`], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`scantxoutset: ${r.stderr || r.stdout}`);
  return parseFirstJsonObject(r.stdout || '');
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
function scanFeesIntoState(state, hotAddress, minKeep = 1_500_000) {
  let pruned = 0;
  state.feeUtxos = (state.feeUtxos || []).filter((u) => {
    if (gettxout(u.txid, u.vout)) return true;
    pruned++;
    return false;
  });

  const scan = scantxoutsetAddr(hotAddress);
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
    const u = gettxout(cand.txid, cand.vout);
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

function countLiveFees(state, need, rejected) {
  return (state.feeUtxos || []).filter((u) => u.sats >= need
    && !rejected.has(`${u.txid}:${u.vout}`)
    && gettxout(u.txid, u.vout)).length;
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
  const state = existsSync(statePath)
    ? JSON.parse(readFileSync(statePath, 'utf8'))
    : { stateTxid: null, feeUtxos: [], history: [] };

  const stateTxid = arg('state-txid', state.stateTxid);
  if (!stateTxid) throw new Error('stateTxid missing — set state.json or --state-txid (U-03)');

  const wallets = JSON.parse(readFileSync(walletsPath, 'utf8'));
  const hot = wallets.hot;
  const feePrivateKey = Buffer.from(hot.privateKeyHex, 'hex');
  const loaded = await loadVerifierProfileBundle(bundleDir);
  const expectedProfile = {
    profileId: instance.profileId || loaded.manifest.identity.profileId,
    instanceId: instance.instanceId || loaded.manifest.genesis.instanceId,
    network: instance.network || 'chipnet',
  };

  // Optional / auto hot-wallet scan into fee inventory (BCHN SSH, gettxout-verified).
  if (hasFlag('scan-fees') || hasFlag('scan-fees-always')) {
    const n = scanFeesIntoState(state, hot.address, 1_500_000);
    console.error(JSON.stringify({ phase: 'scan-fees', ...n }));
  }

  const need = minSats(kind);
  const fixedFunding = (() => {
    const fTx = arg('funding-txid');
    if (!fTx) return null;
    const funding = {
      txid: fTx,
      vout: Number(arg('funding-vout', '0')),
      sats: Number(arg('funding-sats', '0')),
      publicKeyHex: hot.publicKeyHex,
    };
    const u = gettxout(funding.txid, funding.vout);
    if (!u) throw new Error(`funding UTXO missing/spent on chain ${funding.txid}:${funding.vout}`);
    funding.sats = Math.round(u.value * 1e8);
    return funding;
  })();

  // Ensure inventory once up front when using feeUtxos path.
  // Prefer ≥2 large live fees so GATE_FAIL retries have diversity.
  if (!fixedFunding && !hasFlag('no-scan-fees')) {
    const liveLarge = countLiveFees(state, need, new Set());
    if (liveLarge < 2) {
      try {
        const n = scanFeesIntoState(state, hot.address, 1_500_000);
        console.error(JSON.stringify({
          phase: 'scan-fees-auto',
          reason: liveLarge === 0 ? 'no-live-fee' : 'fee-diversity',
          beforeLarge: liveLarge,
          ...n,
        }));
      } catch (e) {
        console.error(JSON.stringify({ phase: 'scan-fees-auto-fail', error: String(e.message || e).slice(0, 160) }));
      }
    }
  }

  const wsh = createHash('sha256').update(Buffer.from(hot.lockingBytecodeHex, 'hex')).digest('hex');
  const digests = state.resumeDigests || {
    deposit: ZERO32, transfer: ZERO32, withdrawal: ZERO32,
  };
  let witnessSeed = state.resumeSeed || randomBytes(32).toString('hex');
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
        const u = gettxout(fixedFunding.txid, fixedFunding.vout);
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
        const pick = sorted.find((u) => u.sats >= need && gettxout(u.txid, u.vout));
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
        liveLargeFees: fixedFunding ? null : countLiveFees(state, need, rejected),
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
        transferHops: 1,
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
        if (gateClass && !hasFlag('no-scan-fees') && attempt < MAX_ATTEMPTS) {
          try {
            const n = scanFeesIntoState(state, hot.address, 1_500_000);
            console.error(JSON.stringify({
              phase: 'scan-fees-on-retry',
              attempt,
              reason: 'GATE_FAIL-fee-diversity',
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

        let otherLarge = countLiveFees(state, need, rejected) > 0;
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
    const prepA = bchnTestMempool(result.prepHex);
    if (!prepA[0]?.allowed) throw new Error(`prep mempool reject ${JSON.stringify(prepA)}`);
    bchnSendHex(result.prepHex);
    const setA = bchnTestMempool(result.settleHex);
    if (!setA[0]?.allowed) throw new Error(`settle mempool reject ${JSON.stringify(setA)}`);
    bchnSendHex(result.settleHex);
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
  state.resumeDigests = result.digests;
  state.resumeSeed = witnessSeed;
  state.history = state.history || [];

  // Full cycle only: push priorCycles row without extra keys. Mid-cycle: digests only.
  const dig = result.digests || {};
  const cycleDone = dig.deposit && dig.deposit !== ZERO32
    && dig.transfer && dig.transfer !== ZERO32
    && dig.withdrawal && dig.withdrawal !== ZERO32;
  if (kind === 'withdrawal' && cycleDone) {
    if (!state.history.some((h) => h.witnessSeed === witnessSeed)) {
      state.history.push({
        witnessSeed,
        transactionContextDigests: {
          deposit: dig.deposit,
          transfer: dig.transfer,
          withdrawal: dig.withdrawal,
        },
      });
    }
    // Next cycle gets a fresh seed.
    delete state.resumeSeed;
    delete state.resumeDigests;
  }

  writeFileSync(statePath, JSON.stringify(state, null, 2));
  appendFileSync(path.join(pool, 'ledger.jsonl'), `${JSON.stringify({
    ts: new Date().toISOString(), kind, prepTxid: result.prepTxid, settleTxid: result.settleTxid,
    wire: result.wire, unlockMs: result.unlockMs, broadcast: doBroadcast,
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
    historyLen: (state.history || []).length,
    cycleDone: !!(kind === 'withdrawal' && cycleDone),
  }, null, 2));
  process.exit(0);
}

main().catch((e) => {
  console.error('FAIL', e.message || e);
  process.exit(1);
});
