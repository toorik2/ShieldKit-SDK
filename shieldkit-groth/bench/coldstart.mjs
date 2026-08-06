/**
 * Blank-machine / cold-start story for ShieldKit bench.
 * Optional pre-steps before S0/S1/S2 — separate from per-act pipeline.
 */
export const COLDSTART_SCHEMA = 'shieldkit-bench-coldstart-v1';

/**
 * Canonical blank-machine ladder (what a first-time operator pays once).
 * Not all steps are timed every run; runners fill ms/bytes when measured.
 */
export const COLDSTART_STEPS = Object.freeze([
  Object.freeze({
    n: 1,
    id: 'clone',
    label: 'Download / clone repo',
    why: 'source bytes + git history over network',
  }),
  Object.freeze({
    n: 2,
    id: 'npm_ci',
    label: 'Install JS deps (npm ci + postinstall)',
    why: 'node_modules + vendored cashc build',
  }),
  Object.freeze({
    n: 3,
    id: 'native_prover',
    label: 'Native prover binary (rapidsnark install)',
    why: 'compile or pin-verify host prover; not in npm pack alone',
  }),
  Object.freeze({
    n: 4,
    id: 'artifact_install',
    label: 'Install PF10 / ceremony / proof artifacts',
    why: 'zkey/r1cs/wasm/runtime ~GBs; pin-authenticated offline install',
  }),
  Object.freeze({
    n: 5,
    id: 'runtime_link',
    label: 'First pool runtime link / specialization',
    why: 'linked runtime cache for instance (after pool create or first act)',
  }),
  Object.freeze({
    n: 6,
    id: 'first_prove_cold',
    label: 'First prove (cold caches)',
    why: 'disk/page-cache cold; often slower than steady S0',
  }),
  Object.freeze({
    n: 7,
    id: 'second_prove_warm',
    label: 'Second prove (warm)',
    why: 'steady-state prove cost ≈ S0',
  }),
  Object.freeze({
    n: 8,
    id: 'disk_footprint',
    label: 'Disk footprint (repo + deps + artifacts)',
    why: 'blank machine capacity planning',
  }),
]);

/** Extra blank-machine costs (document; optional later timers). */
export const COLDSTART_OPTIONAL = Object.freeze([
  'Rust toolchain + cargo for recovery/codec crates (if you build from source tests)',
  'OS packages: build-essential, cmake, etc. for native prover',
  'First pool create (genesis/source + bootstrap fanout) on Chipnet',
  'Funding / UTXO prep (wallet + independent fee UTXOs)',
  'Public Fulcrum / RPC latency baseline (network path only)',
  'Doctor / config-check smoke after install',
]);

/**
 * Standard fairness lines for machine cold-start.
 * Always printed so machine mode is 100% fair by disclosure:
 * what is timed vs what is reused is explicit in the output.
 */
export const MACHINE_COLDSTART_FAIRNESS = Object.freeze([
  'Artifact source is the live tree (local install/verify/copy ~1.4 GiB), not a CDN download.',
  'Still a real first-time install cost into an empty data-home.',
  'Prove uses the live pool session (no pool create). Runtime-link cache is not rebuilt.',
  'Timed: clone + npm ci + empty-data-home artifact/prover install + cold/warm prove.',
  'Not timed as network download: zkey/runtime/native source bytes (already on disk as live tree).',
]);

export const TOOL_COLDSTART_FAIRNESS = Object.freeze([
  'Artifact source / prover: reused from live data-home (not reinstalled, not timed).',
  'Still times clean clone + npm ci + prove against live pool.',
  'Fair claim: tool cold-start only — not machine artifact-install cost (use --machine for that).',
]);

/** Resolve fairness lines: explicit list wins; else mode defaults (always for machine/tool). */
export function resolveFairness({ mode = null, fairness = [] } = {}) {
  const explicit = Array.isArray(fairness)
    ? fairness.filter((line) => typeof line === 'string' && line.length > 0)
    : [];
  if (explicit.length > 0) return explicit;
  if (mode === 'machine-cold-start') return [...MACHINE_COLDSTART_FAIRNESS];
  if (mode === 'tool-cold-start') return [...TOOL_COLDSTART_FAIRNESS];
  return [];
}

export function buildColdstartReport({
  design = 'pf10-baseline',
  commit = null,
  mode = null,
  steps = [],
  totals = {},
  fairness = [],
  notes = '',
} = {}) {
  const byId = new Map(steps.map((s) => [s.id, s]));
  const rows = COLDSTART_STEPS.map((def) => {
    const hit = byId.get(def.id) || {};
    return Object.freeze({
      n: def.n,
      id: def.id,
      label: def.label,
      why: def.why,
      ms: typeof hit.ms === 'number' && Number.isFinite(hit.ms) ? hit.ms : null,
      bytes: typeof hit.bytes === 'number' && Number.isFinite(hit.bytes) ? hit.bytes : null,
      ok: hit.ok === true ? true : hit.ok === false ? false : null,
      detail: typeof hit.detail === 'string' ? hit.detail : '',
    });
  });
  const fairnessLines = resolveFairness({ mode, fairness });
  return Object.freeze({
    schema: COLDSTART_SCHEMA,
    design,
    commit,
    mode: typeof mode === 'string' ? mode : null,
    rows,
    optionalNotes: COLDSTART_OPTIONAL,
    fairness: Object.freeze([...fairnessLines]),
    totals: Object.freeze({
      timedMs: typeof totals.timedMs === 'number' ? totals.timedMs : null,
      diskBytes: typeof totals.diskBytes === 'number' ? totals.diskBytes : null,
    }),
    notes: typeof notes === 'string' ? notes : '',
  });
}

export function formatColdstartTable(report) {
  const lines = [];
  const title = report.mode === 'machine-cold-start'
    ? 'Machine cold-start story (sandbox + empty artifact install + live prove)'
    : report.mode === 'tool-cold-start'
      ? 'Tool cold-start story (sandbox clone/npm + live prove)'
      : 'Blank-machine cold-start story (optional pre-steps)';
  lines.push(title);
  lines.push(`design=${report.design} commit=${report.commit ?? 'n/a'}${report.mode ? ` mode=${report.mode}` : ''}`);
  lines.push('');
  for (const row of report.rows) {
    const time = row.ms === null ? 'n/a' : `~${formatDuration(row.ms)}`;
    const size = row.bytes === null ? '' : `  disk=${formatBytes(row.bytes)}`;
    const ok = row.ok === true ? '  ok' : row.ok === false ? '  FAIL' : '';
    const detail = row.detail ? `  (${row.detail})` : '';
    lines.push(
      `${String(row.n).padStart(2)}. ${row.label.padEnd(42)} ${time.padStart(12)}${size}${ok}${detail}`,
    );
  }
  lines.push('');
  if (report.totals.timedMs != null) {
    lines.push(`timed steps total: ~${formatDuration(report.totals.timedMs)}`);
  }
  if (report.totals.diskBytes != null) {
    lines.push(`disk footprint:    ${formatBytes(report.totals.diskBytes)}`);
  }
  // Always show fairness for machine/tool modes (100% fair by disclosure).
  const fairnessLines = resolveFairness({
    mode: report.mode,
    fairness: report.fairness,
  });
  if (fairnessLines.length > 0) {
    lines.push('');
    lines.push('Fairness note (in the output):');
    for (const line of fairnessLines) {
      lines.push(`  - ${line}`);
    }
  }
  lines.push('');
  lines.push('Also consider (not always timed):');
  for (const note of report.optionalNotes) {
    lines.push(`  - ${note}`);
  }
  if (report.notes) {
    lines.push('');
    lines.push(`notes: ${report.notes}`);
  }
  lines.push('');
  lines.push('After cold-start, run S0/S1 (steady prove) and pipeline/S2 (full act).');
  return lines.join('\n');
}

function formatDuration(ms) {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60_000).toFixed(1)} min`;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  return `${(n / 1024 ** 3).toFixed(2)} GiB`;
}

export { formatDuration, formatBytes };
