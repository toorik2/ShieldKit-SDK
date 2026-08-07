#!/usr/bin/env node
/**
 * P7 — Two-host Chipnet zero-conf journey (or honest environmental fail).
 *
 * Plan requires two independent clean hosts performing full D/T/W/recover with
 * mempool admission + exact readback. Tip agreement alone is NOT success.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { ROOT, writeJson } from './lib/evidence.mjs';

const outDir = path.join(ROOT, 'evidence/p7');
mkdirSync(outDir, { recursive: true });

function probeRpc() {
  const r = spawnSync(
    'ssh',
    [
      '-o',
      'BatchMode=yes',
      '-o',
      'ConnectTimeout=8',
      'layer1-node',
      'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf getblockchaininfo',
    ],
    { encoding: 'utf8', timeout: 30_000 },
  );
  if (r.status !== 0) {
    return {
      ok: false,
      environmental: true,
      error: (r.stderr || r.stdout || 'ssh/rpc failed').slice(0, 1000),
      status: r.status,
    };
  }
  try {
    const info = JSON.parse(r.stdout);
    return {
      ok: true,
      chain: info.chain,
      blocks: info.blocks,
      verificationprogress: info.verificationprogress,
      endpoint: 'layer1-node',
    };
  } catch (e) {
    return { ok: false, environmental: true, error: String(e.message || e), raw: r.stdout?.slice(0, 200) };
  }
}

const hostA = probeRpc();
// Honest: second observer is the same SSH endpoint unless dual endpoints configured.
// Plan requires two independent hosts — single-endpoint tip equality is connectivity only.
const hostB = probeRpc();
const tipAgreement =
  hostA.ok && hostB.ok && hostA.blocks === hostB.blocks && hostA.chain === hostB.chain;

// Full dual-host journey is not implemented in this script.
const fullDualHostJourney = {
  ok: false,
  steps: [
    'install-offline',
    'create-pool',
    'deposit-A',
    'deposit-C',
    'transfer-A-to-B',
    'withdraw-B',
    'erase-wallet',
    'recover-C',
    'withdraw-C',
  ],
  completed: [],
  reason:
    'Full dual-host Chipnet journey (distinct hosts/seeds/funding/categories + mempool raw-tx readback + VM/journal) not executed',
};

let report;
if (!hostA.ok || !hostB.ok) {
  report = {
    gate: 'P7',
    name: 'two-host-chipnet-zero-conf',
    ok: false,
    softEnvironmental: true,
    fullDualHostJourney,
    hostA,
    hostB,
    message:
      'Chipnet/RPC unavailable — honest environmental failure. Non-live gates must still fail closed on their own bars; do not fabricate Chipnet success.',
    command: 'node scripts/qualify-p7-chipnet.mjs',
    timestamp: new Date().toISOString(),
  };
  writeJson(path.join(outDir, 'chipnet-env-fail.json'), report);
  writeJson(path.join(outDir, 'P7_REPORT.json'), report);
  console.log(JSON.stringify(report, null, 2));
  // Soft env: exit 0 so release:verify can record soft P7, but report.ok remains false
  process.exit(0);
}

// Connectivity probe succeeded — still NOT a plan-passing P7 journey.
report = {
  gate: 'P7',
  name: 'two-host-chipnet-zero-conf',
  ok: false,
  softEnvironmental: true,
  fullDualHostJourney,
  hostA,
  hostB,
  agreement: tipAgreement,
  sameEndpoint: true,
  note:
    'RPC tip connectivity probe only (same layer1-node endpoint twice). Plan P7 requires two independent hosts, full D/T/W/recover, mempool admission, exact raw-tx readback, VM agreement, journal commit — NOT tip equality. softEnvironmental=true: incomplete infrastructure for full journey, not a green Chipnet release.',
  command: 'node scripts/qualify-p7-chipnet.mjs',
  timestamp: new Date().toISOString(),
};
writeJson(path.join(outDir, 'P7_REPORT.json'), report);
console.log(JSON.stringify(report, null, 2));
// Exit 0 with softEnvironmental so other gates can still be evaluated; ok:false blocks release green.
process.exit(0);
