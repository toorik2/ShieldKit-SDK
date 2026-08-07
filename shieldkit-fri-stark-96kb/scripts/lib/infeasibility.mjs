/**
 * Plan-required infeasibility package helpers.
 * Never green-wash placeholders / SLA misses / incomplete Chipnet journeys.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ROOT, writeJson, sha256File } from './evidence.mjs';

export const PROVER_SLA_P95_SECONDS = 60;
export const PROVER_SLA_PEAK_RSS_GIB = 4;

export function hostPin() {
  return {
    hostname: os.hostname(),
    platform: `${os.platform()}/${os.arch()}`,
    release: os.release(),
    cpus: os.cpus().map((c) => c.model),
    cpuModel: os.cpus()[0]?.model ?? 'unknown',
    logicalCores: os.cpus().length,
    totalMemGiB: Math.round((os.totalmem() / (1024 ** 3)) * 100) / 100,
    freeMemGiB: Math.round((os.freemem() / (1024 ** 3)) * 100) / 100,
    loadavg: os.loadavg(),
  };
}

export function readJsonSafe(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/** Collect measured production prove meta from evidence/p1/proof-*.json */
export function collectProductionProveMeta() {
  const dir = path.join(ROOT, 'evidence/p1');
  const kinds = ['deposit', 'transfer', 'withdrawal'];
  const rows = [];
  for (const kind of kinds) {
    const f = path.join(dir, `proof-${kind}.json`);
    if (!existsSync(f)) {
      rows.push({ kind, present: false });
      continue;
    }
    const d = readJsonSafe(f);
    rows.push({
      kind,
      present: true,
      path: path.relative(ROOT, f),
      verifyOk: d?.verifyOk === true,
      depth: d?.depth,
      proveSeconds: d?.proveSeconds,
      proofBlobSha256: d?.proofBlobSha256,
      friParams: d?.friParams,
      slaP95Seconds: PROVER_SLA_P95_SECONDS,
      slaExceeded: typeof d?.proveSeconds === 'number' && d.proveSeconds > PROVER_SLA_P95_SECONDS,
    });
  }
  return rows;
}

export function assessProverSla(rows = collectProductionProveMeta()) {
  const measured = rows.filter((r) => r.present && typeof r.proveSeconds === 'number');
  const times = measured.map((r) => r.proveSeconds).sort((a, b) => a - b);
  const p95 = times.length ? times[Math.min(times.length - 1, Math.ceil(times.length * 0.95) - 1)] : null;
  const max = times.length ? Math.max(...times) : null;
  const allOkVerify = measured.length === 3 && measured.every((r) => r.verifyOk);
  const slaOk = p95 != null && p95 <= PROVER_SLA_P95_SECONDS;
  return {
    id: 'PROVER_SLA',
    planBar: { p95Seconds: PROVER_SLA_P95_SECONDS, peakRssGiB: PROVER_SLA_PEAK_RSS_GIB },
    samples: measured,
    p95Seconds: p95,
    maxSeconds: max,
    allThreeKindsVerifyOk: allOkVerify,
    ok: allOkVerify && slaOk,
    constraint: slaOk
      ? null
      : `pure-Python depth-20/blowup-2048 prove  // AMENDED p95=${p95}s > plan bar ${PROVER_SLA_P95_SECONDS}s (samples n=${times.length})`,
    attemptedAlternatives: [
      'One-at-a-time proves with OMP_NUM_THREADS=4 (no ProcessPool emit beside prove)',
      'Absolute --out paths; preflight MemAvailable gate in pool_prove.py',
      'safe-prove.sh MemoryMax=24G wrapper available',
    ],
    notes:
      'Peak RSS was observed ~20–22 GiB during live prove (journal OOM history); plan bar is 4 GiB. Native Rust prover port required for SLA; not present on product path.',
  };
}

export function assessPlaceholderSettlement() {
  // Product settlement currently builds tag-hash preimage redeems (OP_PUSH32 EQUALVERIFY 1), not FRI AIR verifiers.
  const settlementPath = path.join(ROOT, 'packages/settlement/settlement.mjs');
  const text = readFileSync(settlementPath, 'utf8');
  const toy = /roleTag\(|0x88,\s*0x51|PLACEHOLDER|tag-hash preimage|OP_PUSH32/.test(text)
    && !/native_ct_.*cash|friFold|deepQAt/.test(text);
  // Explicit flag from module if present
  let modFlag = null;
  try {
    // dynamic import avoided in sync helper — structural text check is source of truth
    modFlag = /export const SETTLEMENT_PRODUCTION_VERIFIERS\s*=\s*false/.test(text)
      || /productionVerifiers:\s*false/.test(text)
      || /placeholder:\s*true/.test(text)
      || /PLACEHOLDER_SETTLEMENT/.test(text);
  } catch {
    modFlag = null;
  }
  const isPlaceholder = toy || modFlag === true;
  return {
    id: 'PLACEHOLDER_SETTLEMENT',
    ok: !isPlaceholder,
    constraint: isPlaceholder
      ? 'packages/settlement/settlement.mjs productRedeems are tag-hash preimage toys (~35B redeem OP_PUSH32 EQUALVERIFY OP_1), not production 17-role FRI verifier locks from vendor CashScript/AIR'
      : null,
    evidence: {
      settlementSha256: sha256File(settlementPath),
      estimatedHonestTxBytesFromGates: 2188,
      planRequires: '17 role locks + exact assembler + fully signed standard BCH FRI settlement',
    },
    attemptedAlternatives: [
      'Vendor pin has native_ct_verifier_tx.py + cashscript/native_shard — not yet wired into packages/settlement product path',
      'Structural P2SH32 checks only validate preimage form, not FRI soundness',
    ],
  };
}

export function assessP2Corpus() {
  const rep = readJsonSafe(path.join(ROOT, 'evidence/p2/P2_REPORT.json'));
  const digests = rep?.uniqueDigests;
  const packetOnly = rep?.corpusPerKind === 256 && !rep?.realProofsPerKind;
  return {
    id: 'P2_REAL_PROOF_CORPUS',
    ok: rep?.realProofsPerKind === 256 && rep?.realTxPerKind === 256,
    planBar: { proofsPerAction: 256, actions: 3, total: 768, multiOracle: true },
    measured: {
      packetDigestsPerKind: digests,
      realProofsPerKind: rep?.realProofsPerKind ?? 0,
      note: rep?.notes ?? 'packet encode/decode uniqueness only',
    },
    constraint: packetOnly || !rep?.realProofsPerKind
      ? 'P2 currently measures 256 packet digests/kind (encode/decode), not 768 distinct real proofs+transactions with multi-oracle execution'
      : null,
    attemptedAlternatives: [
      // AMENDED 2026-08-06: product config depth-20
      'Three production depth-20 proves exist (deposit/transfer/withdrawal) as P1 samples only',
      'Full 768×~70min pure-Python proves is multi-month wall time on this host — not executed',
    ],
  };
}

export function assessP3P4() {
  const p3 = readJsonSafe(path.join(ROOT, 'evidence/p3/P3_REPORT.json'));
  const p4 = readJsonSafe(path.join(ROOT, 'evidence/p4/P4_REPORT.json'));
  const bchn = readJsonSafe(path.join(ROOT, 'evidence/p3/bchn-probe.json'));
  const hasMempoolAccept = p3?.bchnTestMempoolAccept?.ok === true;
  const hasMined = p3?.regtestMined?.ok === true;
  const crashInject = p4?.crashInjection?.ok === true;
  return {
    id: 'P3_P4_INDEPENDENT_EXECUTION',
    ok: hasMempoolAccept && hasMined && crashInject,
    measured: { p3, p4, bchn },
    constraint:
      !hasMempoolAccept || !hasMined || !crashInject
        ? 'P3/P4 lack BCHN testmempoolaccept+mempool+mined execution of real FRI settlement bytes and crash-injection lifecycle/seed recovery bars'
        : null,
    attemptedAlternatives: [
      'BCHN SSH probe (getblockchaininfo / echo) recorded where available',
      'Libauth structural smoke only until production redeems exist',
    ],
  };
}

export function assessP5() {
  const rep = readJsonSafe(path.join(ROOT, 'evidence/p5/P5_REPORT.json'));
  const sla = assessProverSla();
  const proofsPerAction = rep?.measuredProofsPerAction ?? 0;
  const ratio = rep?.stateTransitions?.ratioVs1k;
  const ratioOk = typeof ratio === 'number' && ratio <= 1.1;
  const storeOk = rep?.stateTransitions?.perEventMs <= 250;
  return {
    id: 'P5_PERF_SCALE',
    ok: proofsPerAction >= 32 && sla.ok && ratioOk && storeOk && rep?.eightInstances?.ok,
    planBar: {
      warmups: 3,
      measuredProofsPerAction: 32,
      p95Seconds: 60,
      peakRssGiB: 4,
      events100kRatio: 1.1,
      stateP95Ms: 250,
    },
    measured: {
      proofsPerAction,
      stateTransitions: rep?.stateTransitions,
      eightInstances: rep?.eightInstances?.ok,
      proverSla: sla,
    },
    constraint:
      proofsPerAction < 32 || !sla.ok
        ? `P5 missing 32 measured proofs/action (have ${proofsPerAction}); prover SLA ${sla.ok ? 'ok' : 'FAILED'}: ${sla.constraint ?? ''}`
        : !ratioOk
          ? `100k/1k ratio ${ratio} > 1.10`
          : null,
    attemptedAlternatives: [
      '100k store/transition campaign implemented (storage-only; must not be sold as proof samples)',
      'Three production proves reused as SLA samples — insufficient for 32×3 campaign',
    ],
  };
}

export function assessP6() {
  const rep = readJsonSafe(path.join(ROOT, 'evidence/p6/P6_REPORT.json'));
  const dual = rep?.dualCleanHost?.ok === true;
  const sbom = rep?.sbom?.ok === true;
  const sigs = (rep?.releaseSignatures?.count ?? 0) >= 2;
  return {
    id: 'P6_REPRO_PACKAGE',
    ok: dual && sbom && sigs,
    measured: rep,
    constraint:
      !dual || !sbom || !sigs
        ? 'P6 lacks dual independent clean-host rebuild identity, CycloneDX SBOM, and 2-of-3 Ed25519 release signatures'
        : null,
    attemptedAlternatives: [
      'Single-host inventory hash + vendor pin + plan sha recorded',
    ],
  };
}

export function assessP7() {
  const rep = readJsonSafe(path.join(ROOT, 'evidence/p7/P7_REPORT.json'));
  const fullJourney = rep?.fullDualHostJourney?.ok === true;
  const soft = rep?.softEnvironmental === true;
  const tipOnly = rep?.agreement === true && !fullJourney;
  return {
    id: 'P7_CHIPNET_DUAL_HOST',
    ok: fullJourney === true,
    softEnvironmental: soft,
    measured: rep,
    constraint: fullJourney
      ? null
      : tipOnly || soft
        ? 'P7 full dual-host Chipnet D/T/W/recover journey not completed (tip agreement or env-fail only is insufficient for release claim)'
        : 'P7 failed or missing',
    attemptedAlternatives: [
      'SSH layer1-node getblockchaininfo tip equality as connectivity probe',
      'Full funded dual-host journey requires two clean hosts + packed artifacts + authorized fee keys',
    ],
  };
}

/** Build full plan-ordered infeasibility report from current tree measurements. */
export function buildInfeasibilityReport({ gateResults = [] } = {}) {
  const findings = [
    assessPlaceholderSettlement(),
    assessProverSla(),
    assessP2Corpus(),
    assessP3P4(),
    assessP5(),
    assessP6(),
    assessP7(),
  ];
  const blocking = findings.filter((f) => f.ok === false);
  const report = {
    schema: 'shieldkit-fri-stark-infeasibility-v1',
    releaseBlocking: blocking.length > 0,
    ok: false,
    claimForbidden: true,
    message:
      'Hard plan gates are not satisfied on the product path. This package records measured failures and stop conditions — it is NOT a release green and must not be presented as local release readiness.',
    host: hostPin(),
    planAuthority: 'FRI_STARK_REPLACEMENT_PLAN.md',
    planSha256: existsSync(path.join(ROOT, 'FRI_STARK_REPLACEMENT_PLAN.md'))
      ? sha256File(path.join(ROOT, 'FRI_STARK_REPLACEMENT_PLAN.md'))
      : null,
    findings,
    blockingIds: blocking.map((f) => f.id),
    gateCommandResults: gateResults,
    paretoNotes: {
      proverSla: {
        observedP95Seconds: assessProverSla().p95Seconds,
        planBarSeconds: PROVER_SLA_P95_SECONDS,
        overageFactor:
          assessProverSla().p95Seconds != null
            ? Math.round((assessProverSla().p95Seconds / PROVER_SLA_P95_SECONDS) * 10) / 10
            : null,
        responsibleConstraint:
          'Pure-Python Goldilocks DEEP-ALI FRI at depth=20 blowup=2048 on this host; plan requires p95<=60s and peak RSS<=4GiB — needs native prover port + production covenant packing',
      },
    },
    timestamp: new Date().toISOString(),
  };
  const outDir = path.join(ROOT, 'evidence/infeasibility');
  writeJson(path.join(outDir, 'INFEASIBILITY_REPORT.json'), report);
  return report;
}
