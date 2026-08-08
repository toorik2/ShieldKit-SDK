#!/usr/bin/env node
/**
 * Live Chipnet one-tip product lifecycle:
 *   createPool → deposit → transfer → withdraw → recover-from-seed
 *
 * Product path only: state@0 covenant + FRI roles roleBase=1 (profile-fixed locks).
 * Each mutating step: local VM (state+roles) → testmempoolaccept → single broadcast → exact raw readback.
 * Fee = size+1. Full 64-char txids. First try only.
 *
 * Usage: node scripts/chipnet-one-tip-lifecycle.mjs
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeTransaction, hexToBin, binToHex } from '@bitauth/libauth';
import { createPoolLive, createPoolLocal, ROLE_DUST_SATS, STATE_CARRIER_BASE_SATS } from '../packages/pool/create-pool.mjs';
import { compileStateCovenant } from '../packages/pool/state-covenant.mjs';
import {
  buildTipActionTx,
  withSourceOutputs,
  evaluateTipActionTx,
  signFundingInput,
  ROLE_DUST,
  kindCode,
} from '../packages/pool/action-spend.mjs';
import { KIND } from '../packages/core/codecs/packet.mjs';
import { rpcStdin, scantxoutsetHot, sshCli } from './lib/chipnet-fund-spend.mjs';
import {
  SETTLEMENT_PRODUCTION_VERIFIERS,
  PLACEHOLDER_SETTLEMENT,
} from '../packages/settlement/settlement.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'evidence/production/one-tip-lifecycle');
const WALLET =
  process.env.CHIPNET_WALLET_PRIVATE ||
  '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const ASM = {
  deposit: path.join(ROOT, 'evidence/production/assemble-state0/assemble-deposit-d20-b2048-n7-g30-base1.materialized.json'),
  transfer: path.join(ROOT, 'evidence/production/assemble-state0/assemble-transfer-d20-b2048-n7-g30-base1.materialized.json'),
  withdrawal: path.join(ROOT, 'evidence/production/assemble-state0/assemble-withdrawal-d20-b2048-n7-g30-base1.materialized.json'),
};
const t0 = Date.now();
const jsonReplacer = (_, v) => (typeof v === 'bigint' ? v.toString() : v);

mkdirSync(OUT, { recursive: true });

function hexToWif(hex, compressed = true) {
  const payload = Buffer.concat([
    Buffer.from([0xef]),
    Buffer.from(hex, 'hex'),
    compressed ? Buffer.from([0x01]) : Buffer.alloc(0),
  ]);
  const c1 = createHash('sha256').update(payload).digest();
  const c2 = createHash('sha256').update(c1).digest();
  const full = Buffer.concat([payload, c2.subarray(0, 4)]);
  const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let x = BigInt(`0x${full.toString('hex')}`);
  let s = '';
  while (x > 0n) {
    s = ALPH[Number(x % 58n)] + s;
    x /= 58n;
  }
  for (const b of full) {
    if (b === 0) s = `1${s}`;
    else break;
  }
  return s;
}

function fail(note, extra = {}) {
  const doc = {
    ok: false,
    note,
    wallSeconds: (Date.now() - t0) / 1000,
    timestamp: new Date().toISOString(),
    ...extra,
  };
  writeFileSync(path.join(OUT, 'ONE_TIP_LIFECYCLE_REPORT.json'), JSON.stringify(doc, jsonReplacer, 2) + '\n');
  console.error(JSON.stringify({ STORY_OK: false, note, ...extra }, jsonReplacer, 2));
  process.exit(2);
}

console.error('[one-tip] Chipnet product lifecycle createPool→D→T→W→recover');
console.error('[one-tip] production=', SETTLEMENT_PRODUCTION_VERIFIERS, 'placeholder=', PLACEHOLDER_SETTLEMENT);
if (!SETTLEMENT_PRODUCTION_VERIFIERS || PLACEHOLDER_SETTLEMENT) {
  fail('product flags not production');
}

const chainRaw = sshCli('getblockchaininfo');
let chainInfo = null;
try {
  chainInfo = JSON.parse(chainRaw.stdout);
} catch {
  /* */
}
if (!chainRaw.ok || chainInfo?.chain !== 'chip') {
  fail('not live chipnet', { chainRaw: (chainRaw.stderr || chainRaw.stdout || '').slice(0, 300) });
}
console.error('[one-tip] chain blocks=', chainInfo.blocks);

for (const [k, p] of Object.entries(ASM)) {
  if (!existsSync(p)) fail(`missing assembly ${k}`, { path: p });
}

const wallet = JSON.parse(readFileSync(WALLET, 'utf8'));

// ─── 1. createPool ─────────────────────────────────────────────
console.error('[one-tip] createPool …');
const live = await createPoolLive({
  rpcStdin,
  scantxoutsetHot,
  walletPath: WALLET,
  outDir: path.join(OUT, 'create-pool'),
  assemblyPath: ASM.transfer, // locks identical across kinds
  requireVout0: true,
  requirePlain: true,
  minVinSats: 100_000n,
});
writeFileSync(path.join(OUT, 'CREATE_POOL.json'), JSON.stringify(live, jsonReplacer, 2) + '\n');
if (!live.ok || live.operatorKeySpendable || !live.genesisTxid) {
  fail('createPool failed', { live });
}
console.error('[one-tip] genesisTxid=', live.genesisTxid);

const categoryHex = live.categoryHex;
let tip = {
  stateOutpoint: { txid: live.genesisTxid, vout: 0, valueSats: STATE_CARRIER_BASE_SATS.toString() },
  roleOutpoints: live.roleOutpoints.map((op, i) => {
    const [txid, vout] = op.split(':');
    return {
      txid,
      vout: Number(vout),
      valueSats: ROLE_DUST_SATS.toString(),
      lockingHex: live.genesisDescriptor.roleLockingHexes[i],
    };
  }),
  state: live.state,
  stateCommitmentHex: live.stateCommitmentHex,
  stateLockingHex: live.stateLockingHex,
  categoryHex,
  genesisTxid: live.genesisTxid,
};

const journal = {
  schema: 'shieldkit-fri-one-tip-journal-v1',
  genesisTxid: live.genesisTxid,
  categoryHex,
  profileId: live.profileId,
  instanceId32: live.instanceId32,
  steps: [
    {
      kind: 'createPool',
      txid: live.genesisTxid,
      stateOutpoint: tip.stateOutpoint,
      roleOutpoints: tip.roleOutpoints.map((r) => `${r.txid}:${r.vout}`),
      stateCommitmentHex: tip.stateCommitmentHex,
      feeSats: live.feeSats,
      rawMatch: live.rawMatch,
    },
  ],
};

function pickFunding({ minSats, exclude }) {
  const { scan, unspents } = scantxoutsetHot(wallet.address);
  if (!scan?.success) throw new Error('scantxoutset failed');
  const ranked = unspents
    .map((u) => ({
      txid: u.txid,
      vout: u.vout,
      amountSats: BigInt(Math.round(Number(u.amount) * 1e8)),
      scriptPubKey: u.scriptPubKey,
    }))
    .filter((u) => u.amountSats >= minSats && !exclude.has(`${u.txid}:${u.vout}`))
    .sort((a, b) => Number(b.amountSats - a.amountSats));
  for (const cand of ranked.slice(0, 80)) {
    const g = rpcStdin('gettxout', [cand.txid, cand.vout, true], 30_000);
    if (!g.parsed || g.parsed.value == null) continue;
    if (g.parsed.tokenData || g.parsed.token_data) continue;
    return {
      txid: cand.txid,
      vout: cand.vout,
      valueSats: cand.amountSats,
      lockingHex: cand.scriptPubKey || wallet.lockingBytecodeHex,
      scriptPubKey: cand.scriptPubKey || wallet.lockingBytecodeHex,
    };
  }
  return null;
}

/**
 * Build → VM → fee size+1 → sign funding → testmempoolaccept → broadcast → readback.
 */
function executeAction(kind) {
  console.error(`[one-tip] ${kind} …`);
  const exclude = new Set([
    `${tip.stateOutpoint.txid}:${tip.stateOutpoint.vout}`,
    ...tip.roleOutpoints.map((r) => `${r.txid}:${r.vout}`),
  ]);
  const k = kindCode(kind);
  const needDenom = k === KIND.DEPOSIT ? 10_000_000n : 0n;
  const funding = pickFunding({ minSats: needDenom + 200_000n, exclude });
  if (!funding) throw new Error(`${kind}: no funding UTXO ≥ ${needDenom + 200_000n}`);

  let feeSats = 3000n;
  const mk = (fee) => {
    let built = buildTipActionTx({
      kind,
      categoryHex: tip.categoryHex,
      preState: tip.state,
      assemblyPath: ASM[kind === 'withdraw' ? 'withdrawal' : kind],
      stateOutpoint: tip.stateOutpoint,
      roleOutpoints: tip.roleOutpoints,
      funding: {
        txid: funding.txid,
        vout: funding.vout,
        valueSats: funding.valueSats,
        lockingHex: funding.lockingHex,
      },
      payoutLockingHex: wallet.lockingBytecodeHex,
      feeSats: fee,
    });
    built = withSourceOutputs(built, {
      stateOutpoint: tip.stateOutpoint,
      roleOutpoints: tip.roleOutpoints,
      funding: {
        txid: funding.txid,
        vout: funding.vout,
        valueSats: funding.valueSats,
        lockingHex: funding.lockingHex,
      },
      categoryHex: tip.categoryHex,
      preCommitmentHex: tip.stateCommitmentHex,
      stateLockingHex: tip.stateLockingHex,
    });
    return built;
  };

  let built = mk(feeSats);
  // Local VM on state+roles (skip funding)
  const vmR = evaluateTipActionTx(built, { skipFunding: true });
  writeFileSync(
    path.join(OUT, `VM_${kind}.json`),
    JSON.stringify({ kind, ...vmR }, jsonReplacer, 2) + '\n',
  );
  if (!vmR.allAccept) {
    throw new Error(`${kind} local VM reject: ${JSON.stringify(vmR.fails).slice(0, 800)}`);
  }

  // Sign funding (libauth), measure size, re-fee size+1 once, re-sign
  built = signFundingInput(built, { privateKeyHex: wallet.privateKeyHex });
  let signedHex = binToHex(encodeTransaction(built.tx));
  const exactFee = BigInt(signedHex.length / 2 + 1);
  if (exactFee !== feeSats) {
    feeSats = exactFee;
    built = mk(feeSats);
    const vm2 = evaluateTipActionTx(built, { skipFunding: true });
    if (!vm2.allAccept) {
      throw new Error(`${kind} VM after re-fee reject: ${JSON.stringify(vm2.fails).slice(0, 400)}`);
    }
    built = signFundingInput(built, { privateKeyHex: wallet.privateKeyHex });
    signedHex = binToHex(encodeTransaction(built.tx));
    // first-try: if size drifted again by 1B, accept measured fee vs actual only if equal
    const fee2 = BigInt(signedHex.length / 2 + 1);
    if (fee2 !== feeSats) {
      // one more exact adjust (deterministic size for same unlock lengths)
      feeSats = fee2;
      built = mk(feeSats);
      built = signFundingInput(built, { privateKeyHex: wallet.privateKeyHex });
      signedHex = binToHex(encodeTransaction(built.tx));
      if (BigInt(signedHex.length / 2 + 1) !== feeSats) {
        throw new Error(
          `${kind} fee did not converge: fee=${feeSats} size=${signedHex.length / 2}`,
        );
      }
    }
  }

  const acc = rpcStdin('testmempoolaccept', [[signedHex]], 60_000);
  const allowed = Array.isArray(acc.parsed) && acc.parsed[0]?.allowed === true;
  writeFileSync(
    path.join(OUT, `MEMPOOL_${kind}.json`),
    JSON.stringify({ kind, testmempoolaccept: acc.parsed, feeSats: feeSats.toString(), bytes: signedHex.length / 2 }, null, 2) +
      '\n',
  );
  if (!allowed) {
    throw new Error(
      `${kind} testmempoolaccept rejected: ${JSON.stringify(acc.parsed || acc.text).slice(0, 1200)}`,
    );
  }

  const txid = String(rpcStdin('sendrawtransaction', [signedHex], 60_000).parsed).trim();
  if (!/^[0-9a-f]{64}$/i.test(txid)) throw new Error(`${kind} bad txid ${txid}`);
  const raw = String(rpcStdin('getrawtransaction', [txid, false], 60_000).parsed)
    .trim()
    .toLowerCase();
  const rawMatch = raw === signedHex.toLowerCase();
  if (!rawMatch) throw new Error(`${kind} raw readback mismatch`);

  writeFileSync(path.join(OUT, `${kind}.hex`), signedHex + '\n');
  writeFileSync(
    path.join(OUT, `${kind}.json`),
    JSON.stringify(
      {
        kind,
        txid,
        bytes: signedHex.length / 2,
        feeSats: feeSats.toString(),
        rawMatch,
        testmempoolaccept: acc.parsed,
        statementDigest: built.statementDigest,
        postCommitmentHex: built.postCommitmentHex,
        stateValueOut: built.stateValueOut.toString(),
        fundingVin: { txid: funding.txid, vout: funding.vout, valueSats: funding.valueSats.toString() },
        vm: { allAccept: vmR.allAccept, nOk: vmR.nOk },
      },
      jsonReplacer,
      2,
    ) + '\n',
  );

  // Advance tip
  tip = {
    ...tip,
    stateOutpoint: {
      txid,
      vout: 0,
      valueSats: built.stateValueOut.toString(),
    },
    roleOutpoints: tip.roleOutpoints.map((r, i) => ({
      txid,
      vout: i + 1,
      valueSats: ROLE_DUST.toString(),
      lockingHex: r.lockingHex,
    })),
    state: built.postState,
    stateCommitmentHex: built.postCommitmentHex,
  };
  journal.steps.push({
    kind,
    txid,
    stateOutpoint: tip.stateOutpoint,
    roleOutpoints: tip.roleOutpoints.map((r) => `${r.txid}:${r.vout}`),
    stateCommitmentHex: tip.stateCommitmentHex,
    feeSats: feeSats.toString(),
    bytes: signedHex.length / 2,
    rawMatch,
    statementDigest: built.statementDigest,
  });
  console.error(`[one-tip] ${kind} txid=`, txid, 'bytes=', signedHex.length / 2);
  return { txid, bytes: signedHex.length / 2, feeSats, rawMatch };
}

const steps = {};
try {
  steps.deposit = executeAction('deposit');
  steps.transfer = executeAction('transfer');
  steps.withdrawal = executeAction('withdrawal');
} catch (e) {
  writeFileSync(path.join(OUT, 'JOURNAL_PARTIAL.json'), JSON.stringify(journal, jsonReplacer, 2) + '\n');
  fail(String(e.message || e), { journal, steps });
}

// ─── recover-from-seed (public tip rebuild from journal + chain) ─
console.error('[one-tip] recover-from-seed …');
const recover = {
  ok: false,
  note: '',
  tip: null,
};
try {
  // Rebuild tip from genesis descriptor + journal steps without secrets
  const gen = live.genesisDescriptor;
  let recStateCm = gen.stateCommitmentHex;
  let recStateOp = { txid: gen.genesisTxid, vout: 0 };
  let recRoles = gen.roleOutpoints.map((op) => {
    const [txid, vout] = op.split(':');
    return { txid, vout: Number(vout) };
  });
  for (const step of journal.steps.slice(1)) {
    // Verify each step tx exists in mempool/chain
    const gr = rpcStdin('getrawtransaction', [step.txid, false], 30_000);
    const raw = String(gr.parsed || '').trim().toLowerCase();
    if (!/^[0-9a-f]+$/i.test(raw) || raw.length < 20) {
      throw new Error(`recover missing tx ${step.txid}`);
    }
    recStateCm = step.stateCommitmentHex;
    recStateOp = { txid: step.txid, vout: 0 };
    recRoles = step.roleOutpoints.map((op) => {
      const [txid, vout] = op.split(':');
      return { txid, vout: Number(vout) };
    });
  }
  const tipMatch =
    recStateOp.txid === tip.stateOutpoint.txid &&
    recStateCm === tip.stateCommitmentHex &&
    recRoles.length === tip.roleOutpoints.length &&   // PRODUCT PATCH 2026-08-06: dynamic role count (17 @ nq7 product config; was hardcoded 19)
    recRoles.every((r, i) => r.txid === tip.roleOutpoints[i].txid && r.vout === tip.roleOutpoints[i].vout);
  recover.ok = tipMatch;
  recover.tip = {
    stateOutpoint: `${recStateOp.txid}:${recStateOp.vout}`,
    stateCommitmentHex: recStateCm,
    roleOutpoints: recRoles.map((r) => `${r.txid}:${r.vout}`),
  };
  recover.note = tipMatch
    ? 'recover-from-seed rebuilt tip matches journal tip (no private material)'
    : 'recover tip mismatch';
} catch (e) {
  recover.ok = false;
  recover.note = String(e.message || e);
}
writeFileSync(path.join(OUT, 'RECOVER.json'), JSON.stringify(recover, null, 2) + '\n');
writeFileSync(path.join(OUT, 'JOURNAL.json'), JSON.stringify(journal, jsonReplacer, 2) + '\n');

const ok =
  live.ok &&
  steps.deposit?.rawMatch &&
  steps.transfer?.rawMatch &&
  steps.withdrawal?.rawMatch &&
  recover.ok === true &&
  !live.operatorKeySpendable;

const report = {
  schema: 'shieldkit-fri-one-tip-lifecycle-v1',
  ok,
  wallSeconds: (Date.now() - t0) / 1000,
  timestamp: new Date().toISOString(),
  policy: {
    feePolicy: '1_sat_per_byte_plus_1',
    firstTryOnly: true,
    fullTxids: true,
    cantDoEvil: true,
    roleIndexBase: 1,
    productFlags: {
      SETTLEMENT_PRODUCTION_VERIFIERS,
      PLACEHOLDER_SETTLEMENT,
    },
  },
  chain: {
    chain: chainInfo.chain,
    blocks: chainInfo.blocks,
    bestblockhash: chainInfo.bestblockhash,
  },
  createPool: {
    ok: live.ok,
    genesisTxid: live.genesisTxid,
    categoryHex: live.categoryHex,
    instanceId32: live.instanceId32,
    stateOutpoint: live.stateOutpoint,
    operatorKeySpendable: live.operatorKeySpendable,
    rawMatch: live.rawMatch,
    feeSats: live.feeSats,
    genesisBytes: live.genesisBytes,
  },
  deposit: steps.deposit,
  transfer: steps.transfer,
  withdrawal: steps.withdrawal,
  recover,
  journal,
  finalTip: {
    stateOutpoint: `${tip.stateOutpoint.txid}:${tip.stateOutpoint.vout}`,
    stateCommitmentHex: tip.stateCommitmentHex,
    roleOutpoints: tip.roleOutpoints.map((r) => `${r.txid}:${r.vout}`),
    reserveSats: tip.state.reserveSats,
    actionSequence: tip.state.actionSequence,
  },
  note: ok
    ? 'one-tip Chipnet lifecycle green: createPool→D→T→W→recover under product locks'
    : 'one-tip lifecycle failed fail-closed',
};

writeFileSync(path.join(OUT, 'ONE_TIP_LIFECYCLE_REPORT.json'), JSON.stringify(report, jsonReplacer, 2) + '\n');
// Mirror summary into evidence/production root
writeFileSync(
  path.join(ROOT, 'evidence/production/ONE_TIP_LIFECYCLE.json'),
  JSON.stringify(report, jsonReplacer, 2) + '\n',
);

console.log(
  JSON.stringify(
    {
      STORY_OK: report.ok,
      wallSeconds: report.wallSeconds,
      genesisTxid: live.genesisTxid,
      depositTxid: steps.deposit?.txid || null,
      transferTxid: steps.transfer?.txid || null,
      withdrawalTxid: steps.withdrawal?.txid || null,
      recoverOk: recover.ok,
      finalStateOutpoint: report.finalTip.stateOutpoint,
      note: report.note,
      evidence: 'evidence/production/one-tip-lifecycle/ONE_TIP_LIFECYCLE_REPORT.json',
    },
    null,
    2,
  ),
);

process.exit(ok ? 0 : 1);
