/**
 * Plan-normative outcome classes for shieldkit-action-benchmark-run/v2.
 * @see BENCHMARK_PLAN.md § Outcome Semantics
 */

export const OUTCOME_CLASSES = Object.freeze([
  'accepted',
  'design_failure',
  'timeout',
  'indeterminate_after_send',
  'infrastructure_invalid',
  'accepted_commit_failed',
]);

const OUTCOME_SET = new Set(OUTCOME_CLASSES);

export function isOutcomeClass(value) {
  return typeof value === 'string' && OUTCOME_SET.has(value);
}

/**
 * Normalize an outcome object. Latency fields may only appear when accepted
 * (or accepted_commit_failed for intent-to-accept; commit may be null).
 */
export function buildOutcome({
  class: outcomeClass,
  reason = null,
  intentToAcceptedMs = null,
  commandToAcceptedMs = null,
  localPreparationMs = null,
  admissionMs = null,
  acceptedToReadyMs = null,
  commandCompletionMs = null,
} = {}) {
  if (!isOutcomeClass(outcomeClass)) {
    throw new Error(
      `outcome class must be one of: ${OUTCOME_CLASSES.join(', ')}`,
    );
  }
  const acceptedLike = outcomeClass === 'accepted'
    || outcomeClass === 'accepted_commit_failed';
  if (!acceptedLike) {
    return Object.freeze({
      class: outcomeClass,
      reason: reason === null || reason === undefined ? null : String(reason),
      intentToAcceptedMs: null,
      commandToAcceptedMs: null,
      localPreparationMs: finiteOrNull(localPreparationMs, 'localPreparationMs'),
      admissionMs: null,
      acceptedToReadyMs: null,
      commandCompletionMs: finiteOrNull(commandCompletionMs, 'commandCompletionMs'),
    });
  }
  return Object.freeze({
    class: outcomeClass,
    reason: reason === null || reason === undefined ? null : String(reason),
    intentToAcceptedMs: finiteOrNull(intentToAcceptedMs, 'intentToAcceptedMs'),
    commandToAcceptedMs: finiteOrNull(commandToAcceptedMs, 'commandToAcceptedMs'),
    localPreparationMs: finiteOrNull(localPreparationMs, 'localPreparationMs'),
    admissionMs: finiteOrNull(admissionMs, 'admissionMs'),
    acceptedToReadyMs: outcomeClass === 'accepted'
      ? finiteOrNull(acceptedToReadyMs, 'acceptedToReadyMs')
      : null,
    commandCompletionMs: finiteOrNull(commandCompletionMs, 'commandCompletionMs'),
  });
}

function finiteOrNull(value, label) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be a finite number >= 0 or null`);
  }
  return value;
}

/** Reliability gate: accepted / attempted (non-infrastructure rows only by default). */
export function reliabilityGate(runs, { excludeInfrastructure = true } = {}) {
  if (!Array.isArray(runs)) throw new Error('runs must be an array');
  let attempted = 0;
  let accepted = 0;
  for (const run of runs) {
    const c = run?.outcome?.class ?? run?.outcomeClass;
    if (!isOutcomeClass(c)) continue;
    if (excludeInfrastructure && c === 'infrastructure_invalid') continue;
    attempted += 1;
    if (c === 'accepted' || c === 'accepted_commit_failed') accepted += 1;
  }
  return Object.freeze({
    accepted,
    attempted,
    rate: attempted === 0 ? null : accepted / attempted,
  });
}
