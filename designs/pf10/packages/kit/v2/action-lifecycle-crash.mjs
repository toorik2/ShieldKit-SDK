export const V2_ACTION_LIFECYCLE_CRASH_STAGES = Object.freeze([
  'prove.after_transition',
  'prove.after_proof',
  'prove.after_artifacts',
  'prove.after_proved',
  'sign.after_refresh',
  'sign.after_signature',
  'sign.after_artifacts',
  'sign.after_signed',
]);

export class V2ActionLifecycleCrash extends Error {
  constructor(stage) {
    super(`injected V2 action lifecycle crash at ${stage}`);
    this.name = 'V2ActionLifecycleCrash';
    this.stage = stage;
  }
}
