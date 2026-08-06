/**
 * Human + machine pipeline breakdown for one product act
 * (tip read → … → admission/mempool → commit).
 */
export const PIPELINE_SCHEMA = 'shieldkit-bench-pipeline-v1';

/** Ordered steps matching operator-facing labels. */
export const PIPELINE_STEPS = Object.freeze([
  Object.freeze({
    n: 1,
    key: 'stateRead',
    label: 'Look up tip on network',
    short: 'stateRead',
  }),
  Object.freeze({
    n: 2,
    key: 'fundingRead',
    label: 'Find fee coin',
    short: 'fundingRead',
  }),
  Object.freeze({
    n: 3,
    key: 'treeAndPreparation',
    label: 'Prep trees',
    short: 'treeAndPrep',
  }),
  Object.freeze({
    n: 4,
    key: 'witnessCalculation',
    label: 'Build witness',
    short: 'witnessCalc',
  }),
  Object.freeze({
    n: 5,
    key: 'proofGeneration',
    label: 'Make ZK proof',
    short: 'proofGen',
    note: 'bench S0/S1',
  }),
  Object.freeze({
    n: 6,
    key: 'proofVerification',
    label: 'Check proof',
    short: 'proofVerify',
  }),
  Object.freeze({
    n: 7,
    key: 'witnessAssembly',
    label: 'Build big unlock scripts',
    short: 'witnessAssembly',
  }),
  Object.freeze({
    n: 8,
    key: 'signingAndVm',
    label: 'Sign + Libauth VM',
    short: 'signing/localVm',
    localDone: true,
  }),
  Object.freeze({
    n: 9,
    key: 'admission',
    label: 'Broadcast + mempool/readback',
    short: 'admission',
  }),
  Object.freeze({
    n: 10,
    key: 'commit',
    label: 'Save local state',
    short: 'commit',
  }),
]);

function num(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  return null;
}

/**
 * Normalize product action.timingsMs (+ optional CLI wrapper timings).
 */
export function extractPipelineTimings(source = {}) {
  const action = source.actionTimingsMs
    ?? source.timingsMs
    ?? source.action?.timingsMs
    ?? {};
  const cli = source.cliTimingsMs ?? source.commandTimingsMs ?? {};
  const steps = Object.freeze(Object.fromEntries(
    PIPELINE_STEPS.map((step) => [step.key, num(action[step.key])]),
  ));
  return Object.freeze({
    steps,
    proofTotal: num(action.proofTotal),
    localVm: num(action.localVm),
    actionTotal: num(action.total),
    sessionOpen: num(cli.sessionOpen ?? source.sessionOpen),
    commandTotal: num(cli.commandTotal ?? source.commandTotal),
    // localVm is nested inside signingAndVm wall in product code; surface both.
  });
}

/**
 * Build a structured pipeline report.
 */
export function buildPipelineReport({
  design = 'pf10-baseline',
  commit = null,
  kind = null,
  transactionId = null,
  operationId = null,
  source = {},
  notes = '',
} = {}) {
  const extracted = extractPipelineTimings(source);
  const rows = PIPELINE_STEPS.map((step) => Object.freeze({
    n: step.n,
    key: step.key,
    label: step.label,
    short: step.short,
    ms: extracted.steps[step.key],
    note: step.note ?? null,
  }));

  const localKeys = [
    'stateRead', 'fundingRead', 'treeAndPreparation',
    'proofTotal', 'witnessAssembly', 'signingAndVm',
  ];
  let localSum = 0;
  let localComplete = true;
  for (const key of localKeys) {
    const v = key === 'proofTotal'
      ? extracted.proofTotal
      : extracted.steps[key];
    if (v === null) localComplete = false;
    else localSum += v;
  }

  const admission = extracted.steps.admission;
  const commitMs = extracted.steps.commit;
  const wall = extracted.commandTotal
    ?? extracted.actionTotal
    ?? null;

  return Object.freeze({
    schema: PIPELINE_SCHEMA,
    design,
    commit,
    kind,
    transactionId,
    operationId,
    rows,
    sums: Object.freeze({
      localWorkMs: localComplete ? localSum : null,
      admissionMs: admission,
      commitMs,
      actionTotalMs: extracted.actionTotal,
      sessionOpenMs: extracted.sessionOpen,
      commandTotalMs: wall,
      proofGenerationMs: extracted.steps.proofGeneration,
      proofTotalMs: extracted.proofTotal,
      localVmMs: extracted.localVm,
    }),
    notes: typeof notes === 'string' ? notes : '',
  });
}

/**
 * Operator-facing table (ELI5 step list).
 */
export function formatPipelineTable(report) {
  const lines = [];
  lines.push('Pipeline timings (start → mempool acceptance)');
  if (report.kind || report.transactionId) {
    lines.push(
      `kind=${report.kind ?? '?'} txid=${report.transactionId ?? 'n/a'}`,
    );
  }
  lines.push('');

  for (const row of report.rows) {
    const ms = row.ms === null ? 'n/a' : `~${Math.round(row.ms)}`;
    const note = row.note ? `   ← ${row.note}` : '';
    const line = `${String(row.n).padStart(2)}. ${row.label.padEnd(32)} ${row.short.padEnd(16)} ${ms.padStart(8)} ms${note}`;
    lines.push(line);
    if (row.n === 8) {
      const local = report.sums.localWorkMs;
      const localTxt = local === null ? 'n/a' : `~${(local / 1000).toFixed(1)} s`;
      lines.push(`   -------- local work done (${localTxt}) --------`);
    }
  }

  lines.push('');
  const total = report.sums.commandTotalMs ?? report.sums.actionTotalMs;
  const totalTxt = total === null ? 'n/a' : `~${(total / 1000).toFixed(1)} s (${Math.round(total)} ms)`;
  lines.push(`   -------- total ${totalTxt} --------`);

  if (report.sums.admissionMs === null) {
    lines.push('note: admission/commit missing in this source (store pre-admission artifact); use live CLI for full chain.');
  }
  if (report.notes) lines.push(`notes: ${report.notes}`);
  return lines.join('\n');
}

/**
 * Extract timingsMs from a CLI product JSON envelope or bare action result.
 */
export function pipelineSourceFromCliResult(envelope) {
  if (envelope === null || typeof envelope !== 'object') {
    throw new Error('CLI result must be an object');
  }
  const result = envelope.result ?? envelope;
  const action = result.action ?? result;
  return {
    actionTimingsMs: action.timingsMs ?? result.timingsMs ?? {},
    cliTimingsMs: result.timingsMs && result.action
      ? result.timingsMs
      : {},
    kind: action.kind ?? result.command ?? null,
    transactionId: action.transactionId ?? result.transactionId ?? null,
    operationId: action.operationId ?? result.operationId ?? null,
  };
}
