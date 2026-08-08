/**
 * Canonical operation state vocabulary — CLI_ARCHITECTURE_PLAN.md § Shared lifecycle kernel
 */

export const OPERATION_STATES = Object.freeze([
  'preparing',
  'prepared-durable',
  'send-attempted',
  'accepted-zero-conf',
  'rejected',
  'send-indeterminate',
  'local-commit-pending',
  'committed',
  'safe-pre-send-failure',
]);

const STATE_SET = new Set(OPERATION_STATES);

export function isOperationState(value) {
  return typeof value === 'string' && STATE_SET.has(value);
}

export function assertOperationState(value) {
  if (!isOperationState(value)) {
    throw new Error(`invalid operation state: ${value}`);
  }
  return value;
}

/** States before any network mutation. */
export function isPreSend(state) {
  return state === 'preparing'
    || state === 'prepared-durable'
    || state === 'safe-pre-send-failure';
}

/** After send attempt; absence of evidence ≠ rejection. */
export function isPostSend(state) {
  return state === 'send-attempted'
    || state === 'accepted-zero-conf'
    || state === 'rejected'
    || state === 'send-indeterminate'
    || state === 'local-commit-pending'
    || state === 'committed';
}

/**
 * Legal transitions for the shared coordinator (strict subset).
 */
export const LEGAL_TRANSITIONS = Object.freeze({
  preparing: Object.freeze(['prepared-durable', 'safe-pre-send-failure']),
  'prepared-durable': Object.freeze(['send-attempted', 'safe-pre-send-failure']),
  'send-attempted': Object.freeze([
    'accepted-zero-conf',
    'rejected',
    'send-indeterminate',
  ]),
  'accepted-zero-conf': Object.freeze(['local-commit-pending', 'committed']),
  'local-commit-pending': Object.freeze(['committed']),
  rejected: Object.freeze([]),
  'send-indeterminate': Object.freeze([]), // requires explicit inspection/rebroadcast handling
  committed: Object.freeze([]),
  'safe-pre-send-failure': Object.freeze([]),
});

export function canTransition(from, to) {
  assertOperationState(from);
  assertOperationState(to);
  return (LEGAL_TRANSITIONS[from] || []).includes(to);
}

export function assertTransition(from, to) {
  if (!canTransition(from, to)) {
    throw new Error(`illegal operation state transition: ${from} → ${to}`);
  }
  return to;
}
