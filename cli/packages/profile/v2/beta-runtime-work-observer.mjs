import { AsyncLocalStorage } from 'node:async_hooks';

export const V2_BETA_RUNTIME_WORK_OBSERVATION_SCHEMA =
  'shieldkit-v2-beta-runtime-work-observation-v1';

const TYPES = Object.freeze([
  'linked-runtime-cache-load',
  'cold-runtime-build',
  'full-runtime-verification',
  'compiler-child-spawn',
  'instance-specialization',
]);
const FORBIDDEN_WARM = Object.freeze([
  'cold-runtime-build', 'full-runtime-verification',
  'compiler-child-spawn', 'instance-specialization',
]);
const storage = new AsyncLocalStorage();

export class V2BetaRuntimeWorkObserverError extends Error {
  constructor(code, message) { super(message); this.name = 'V2BetaRuntimeWorkObserverError'; this.code = code; }
}

const fail = (code, message) => { throw new V2BetaRuntimeWorkObserverError(code, message); };

const isPlainRecord = (value) => value !== null && !Array.isArray(value)
  && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;

function snapshot(events) {
  const counts = Object.fromEntries(TYPES.map((type) => [type, 0]));
  for (const event of events) counts[event.type] += 1;
  return Object.freeze({
    schema: V2_BETA_RUNTIME_WORK_OBSERVATION_SCHEMA,
    counts: Object.freeze({ ...counts }),
    events: Object.freeze(events.map((event) => Object.freeze({ type: event.type }))),
  });
}

/** Record an allowlisted runtime-work boundary when an action observation is active. */
export function recordV2BetaRuntimeWork(value) {
  if (!isPlainRecord(value)
    || Object.keys(value).length !== 1 || typeof value.type !== 'string' || !TYPES.includes(value.type)) {
    fail('BETA_RUNTIME_WORK_EVENT_INVALID', 'runtime work event must contain one allowlisted type');
  }
  const context = storage.getStore();
  if (context === undefined) return false;
  context.events.push(Object.freeze({ type: value.type }));
  return true;
}

/** Run one scoped operation and return its exact runtime-work observation. */
export async function observeV2BetaRuntimeWork(run) {
  if (typeof run !== 'function') fail('BETA_RUNTIME_WORK_RUN_INVALID', 'runtime work observer requires a function');
  return storage.run({ events: [] }, async () => {
    const value = await run();
    return Object.freeze({ value, observation: snapshot(storage.getStore().events) });
  });
}

/** Backward-compatible semantic alias for warm deposit/withdraw observations. */
export const observeV2BetaActionRuntimeWork = observeV2BetaRuntimeWork;

function validatedObservation(value) {
  if (!isPlainRecord(value)
    || value.schema !== V2_BETA_RUNTIME_WORK_OBSERVATION_SCHEMA
    || !isPlainRecord(value.counts) || !Array.isArray(value.events)) {
    fail('BETA_RUNTIME_WORK_OBSERVATION_INVALID', 'runtime work observation is malformed');
  }
  const countKeys = Object.keys(value.counts);
  if (countKeys.length !== TYPES.length || TYPES.some((type) => !Object.hasOwn(value.counts, type))) {
    fail('BETA_RUNTIME_WORK_OBSERVATION_INVALID', 'runtime work observation has unknown or missing counts');
  }
  const eventCounts = Object.fromEntries(TYPES.map((type) => [type, 0]));
  for (const event of value.events) {
    if (!isPlainRecord(event) || Object.keys(event).length !== 1
      || typeof event.type !== 'string' || !TYPES.includes(event.type)) {
      fail('BETA_RUNTIME_WORK_OBSERVATION_INVALID', 'runtime work observation has an invalid event');
    }
    eventCounts[event.type] += 1;
  }
  for (const type of TYPES) {
    if (!Number.isSafeInteger(value.counts[type]) || value.counts[type] < 0) {
      fail('BETA_RUNTIME_WORK_OBSERVATION_INVALID', `runtime work count ${type} is invalid`);
    }
    if (value.counts[type] !== eventCounts[type]) {
      fail('BETA_RUNTIME_WORK_OBSERVATION_INVALID', `runtime work count ${type} does not match events`);
    }
  }
  return value;
}

/** Require the linked warm-cache-only contract before any successful action result is exposed. */
export function assertV2BetaWarmActionRuntimeWork(value) {
  validatedObservation(value);
  if (value.counts['linked-runtime-cache-load'] < 1) {
    fail('BETA_RUNTIME_WARM_CACHE_REQUIRED', 'successful beta actions require at least one linked runtime cache load');
  }
  const forbidden = FORBIDDEN_WARM.filter((type) => value.counts[type] !== 0);
  if (forbidden.length !== 0) {
    fail('BETA_RUNTIME_WARM_WORK_FORBIDDEN', `successful beta actions forbids runtime work: ${forbidden.join(', ')}`);
  }
  return value;
}

/**
 * Pool creation may perform one measured deterministic fixed-width instance
 * relocation because the instance ID is created by the pool's bootstrap
 * transaction. It may never rebuild/fully verify the runtime or invoke a
 * compiler. A cache-hit restart performs no relocation.
 */
export function assertV2BetaPoolCreateRuntimeWork(value, { linkedDuringCommand } = {}) {
  validatedObservation(value);
  if (typeof linkedDuringCommand !== 'boolean') {
    fail('BETA_RUNTIME_WORK_OBSERVATION_INVALID', 'pool-create linkedDuringCommand must be boolean');
  }
  const expectedEvents = linkedDuringCommand
    ? ['instance-specialization', 'linked-runtime-cache-load']
    : ['linked-runtime-cache-load'];
  if (value.counts['linked-runtime-cache-load'] !== 1
    || value.counts['cold-runtime-build'] !== 0
    || value.counts['full-runtime-verification'] !== 0
    || value.counts['compiler-child-spawn'] !== 0
    || value.counts['instance-specialization'] !== (linkedDuringCommand ? 1 : 0)
    || value.events.length !== expectedEvents.length
    || value.events.some((event, index) => event.type !== expectedEvents[index])) {
    fail(
      'BETA_POOL_CREATE_RUNTIME_WORK_FORBIDDEN',
      'pool create must relocate once before its one linked cache load on a miss, or only load that cache on a hit; it may never build, fully verify, or compile runtime material',
    );
  }
  return value;
}
