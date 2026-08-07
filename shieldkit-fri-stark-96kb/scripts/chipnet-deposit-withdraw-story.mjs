#!/usr/bin/env node
/**
 * Live Chipnet e2e: deposit-on-chain + withdraw-on-chain
 * (fund 19 FRI locks → multi-input spend for each kind).
 *
 * Uses production sound assemblies (d4/b32 measured-green), not PLACEHOLDER toys.
 * Fee 1 sat/byte+1. First try only. Full 64-char txids.
 *
 * Usage: node scripts/chipnet-deposit-withdraw-story.mjs
 */
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SETTLEMENT_PRODUCTION_VERIFIERS,
  PLACEHOLDER_SETTLEMENT,
} from '../packages/settlement/settlement.mjs';
import { fundAndSpendKind, sshCli } from './lib/chipnet-fund-spend.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'evidence/blank-machine-chipnet');
const t0 = Date.now();

mkdirSync(OUT, { recursive: true });

console.error('[chipnet-DW] deposit-on-chain + withdraw-on-chain story');
console.error(
  '[chipnet-DW] production=',
  SETTLEMENT_PRODUCTION_VERIFIERS,
  'placeholder=',
  PLACEHOLDER_SETTLEMENT,
);

const chainRaw = sshCli('getblockchaininfo');
let chainInfo = null;
try {
  chainInfo = JSON.parse(chainRaw.stdout);
} catch {
  /* */
}
if (!chainRaw.ok || chainInfo?.chain !== 'chip') {
  console.error('[chipnet-DW] FAIL: not live chipnet', chainRaw.stderr || chainRaw.stdout);
  process.exit(2);
}
console.error('[chipnet-DW] chain tip blocks=', chainInfo.blocks);

const kinds = [
  {
    kind: 'deposit',
    artifact: path.join(ROOT, 'evidence/settlement-prod/assemble-deposit-d4-b32.json'),
  },
  {
    kind: 'withdrawal',
    artifact: path.join(ROOT, 'evidence/settlement-prod/assemble-withdrawal-d4-b32.json'),
  },
];

const usedOutpoints = new Set();
const rows = [];

for (const { kind, artifact } of kinds) {
  if (!existsSync(artifact)) {
    rows.push({ ok: false, kind, note: `missing artifact ${artifact}` });
    console.error(`[chipnet-DW] missing ${artifact}`);
    continue;
  }
  console.error(`[chipnet-DW] starting ${kind} fund+spend …`);
  const r = fundAndSpendKind({
    kind,
    artifactPath: artifact,
    outDir: OUT,
    excludeOutpoints: usedOutpoints,
  });
  rows.push(r);
  if (r.fundingVin) {
    usedOutpoints.add(`${r.fundingVin.txid}:${r.fundingVin.vout}`);
  }
  // fund change is a new outpoint we don't need to exclude for next scan (rescans)
  console.error(
    JSON.stringify({
      kind: r.kind,
      ok: r.ok,
      fundTxid: r.fundTxid,
      spendTxid: r.spendTxid,
      spendBytes: r.spendBytes,
      feeSats: r.feeSats,
      rawMatch: r.rawMatch,
      note: r.note,
    }),
  );
  // First-try policy: stop entire story if one kind fails (do not partial-green)
  if (!r.ok) {
    break;
  }
}

const deposit = rows.find((r) => r.kind === 'deposit');
const withdrawal = rows.find((r) => r.kind === 'withdrawal');
const ok =
  SETTLEMENT_PRODUCTION_VERIFIERS === true &&
  PLACEHOLDER_SETTLEMENT === false &&
  deposit?.ok === true &&
  withdrawal?.ok === true &&
  deposit.rawMatch === true &&
  withdrawal.rawMatch === true;

const report = {
  schema: 'shieldkit-fri-chipnet-deposit-withdraw-story-v1',
  name: 'chipnet-deposit-withdraw-on-chain',
  ok,
  wallSeconds: (Date.now() - t0) / 1000,
  timestamp: new Date().toISOString(),
  chain: {
    chain: chainInfo.chain,
    blocks: chainInfo.blocks,
    bestblockhash: chainInfo.bestblockhash,
  },
  settlementPolicy: {
    SETTLEMENT_PRODUCTION_VERIFIERS,
    PLACEHOLDER_SETTLEMENT,
    feePolicy: '1_sat_per_byte_plus_1',
    hardRule: 'never broadcast PLACEHOLDER as product',
  },
  gates: {
    liveChipnetTip: true,
    depositOnChain: !!deposit?.ok,
    withdrawOnChain: !!withdrawal?.ok,
    productionVerifiers: SETTLEMENT_PRODUCTION_VERIFIERS,
    placeholder: PLACEHOLDER_SETTLEMENT,
  },
  deposit: deposit || null,
  withdrawal: withdrawal || null,
  note: ok
    ? 'Both deposit and withdrawal multi-input FRI settlements admitted on live Chipnet (fund locks → spend). Not full create-pool product journey.'
    : 'One or both kinds failed — fail-closed (first try).',
};

writeFileSync(
  path.join(OUT, 'DEPOSIT_WITHDRAW_STORY_REPORT.json'),
  JSON.stringify(report, null, 2) + '\n',
);

console.log(
  JSON.stringify(
    {
      STORY_OK: report.ok,
      wallSeconds: report.wallSeconds,
      deposit: deposit && {
        ok: deposit.ok,
        fundTxid: deposit.fundTxid,
        spendTxid: deposit.spendTxid,
        spendBytes: deposit.spendBytes,
        feeSats: deposit.feeSats,
        rawMatch: deposit.rawMatch,
      },
      withdrawal: withdrawal && {
        ok: withdrawal.ok,
        fundTxid: withdrawal.fundTxid,
        spendTxid: withdrawal.spendTxid,
        spendBytes: withdrawal.spendBytes,
        feeSats: withdrawal.feeSats,
        rawMatch: withdrawal.rawMatch,
      },
      evidence: path.relative(ROOT, path.join(OUT, 'DEPOSIT_WITHDRAW_STORY_REPORT.json')),
    },
    null,
    2,
  ),
);

process.exit(ok ? 0 : 1);
