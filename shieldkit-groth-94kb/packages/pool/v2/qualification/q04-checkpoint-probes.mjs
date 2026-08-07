import { createHash } from "node:crypto";

import { Q04PersistentStoreError } from "./persistent-nullifier-store.mjs";
import { Q04_FR_MODULUS } from "./q04-schedule.mjs";

/**
 * Deterministic, adversarial checkpoint probes for Q-04 persistence
 * qualification. This module deliberately has no clock, process, filesystem,
 * or environment inputs: a checkpoint is completely determined by its store
 * state, the last accepted key, and the six deliberately-mutated alias buffers.
 */
export const Q04_CHECKPOINT_PROBE_SCHEMA =
  "shieldkit-v2-direct/q04-checkpoint-probes/v1";

export const Q04_ALIAS_EVIDENCE_FIELDS = Object.freeze([
  "inputKey",
  "expectedRootInput",
  "stateRootResult",
  "writeRootResult",
  "mutationLeafKeyResult",
  "membershipRootResult",
]);

export const Q04_CHECKPOINT_PROBE_CASES = Object.freeze([
  Object.freeze({
    id: "q04-checkpoint-duplicate-v1",
    kind: "duplicate",
    expectedOutcome: "reject",
    errorCode: "Q04_DUPLICATE",
  }),
  Object.freeze({
    id: "q04-checkpoint-ordering-v1",
    kind: "ordering",
    expectedOutcome: "reject",
    errorCode: "Q04_ORDERING",
  }),
  Object.freeze({
    id: "q04-checkpoint-successor-pointer-v1",
    kind: "successor-pointer",
    expectedOutcome: "reject",
    errorCode: "Q04_SUCCESSOR_POINTER",
  }),
  Object.freeze({
    id: "q04-checkpoint-alias-v1",
    kind: "alias",
    expectedOutcome: "reject",
    errorCode: "Q04_ALIAS",
  }),
  Object.freeze({
    id: "q04-checkpoint-noncanonical-field-v1",
    kind: "noncanonical-field",
    expectedOutcome: "reject",
    errorCode: "Q04_NONCANONICAL_FIELD",
  }),
]);

export const Q04_CHECKPOINT_PROBE_COUNT = Q04_CHECKPOINT_PROBE_CASES.length;
export const Q04_CHECKPOINT_PROBE_RESULT_FIELDS = Object.freeze([
  "caseId",
  "caseSha256",
  "kind",
  "expectedOutcome",
  "accepted",
  "stateUnchanged",
  "errorCode",
  "inputSha256",
  "preStateSha256",
  "postStateSha256",
  "rejection",
]);

export class Q04CheckpointProbeError extends Error {
  constructor(message) {
    super(message);
    this.name = "Q04CheckpointProbeError";
  }
}

const fail = (message) => {
  throw new Q04CheckpointProbeError(message);
};
const sha256 = (...parts) => {
  const digest = createHash("sha256");
  for (const part of parts) digest.update(part);
  return digest.digest("hex");
};
const exactKeys = (value, expected, label) => {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) fail(`${label} has missing or unknown properties`);
  return value;
};
const digestCanonical = (label, value) => sha256(
  Q04_CHECKPOINT_PROBE_SCHEMA,
  "\0",
  label,
  "\0",
  JSON.stringify(value),
);
const canonicalCase = (definition) => ({
  id: definition.id,
  kind: definition.kind,
  expectedOutcome: definition.expectedOutcome,
  errorCode: definition.errorCode,
});
const caseByKind = new Map(
  Q04_CHECKPOINT_PROBE_CASES.map((definition) => [definition.kind, definition]),
);
const canonicalDefinition = (definition) => {
  exactKeys(definition, ["id", "kind", "expectedOutcome", "errorCode"],
    "Q-04 checkpoint probe case");
  const canonical = Q04_CHECKPOINT_PROBE_CASES.find((candidate) =>
    candidate.id === definition.id &&
    candidate.kind === definition.kind &&
    candidate.expectedOutcome === definition.expectedOutcome &&
    candidate.errorCode === definition.errorCode,
  );
  if (canonical === undefined) fail("Q-04 checkpoint probe case is not canonical");
  return canonical;
};

export function q04CheckpointProbeCaseDigest(definition) {
  return digestCanonical("case", canonicalCase(canonicalDefinition(definition)));
}

export function q04CheckpointProbeResultDigest(value) {
  exactKeys(
    value,
    Q04_CHECKPOINT_PROBE_RESULT_FIELDS,
    "Q-04 checkpoint probe result",
  );
  return digestCanonical("result", value);
}

const assertion = (condition, message) => {
  if (!condition) fail(message);
};
const auditDigest = (audit, label) => {
  if (
    audit === null ||
    typeof audit !== "object" ||
    typeof audit.logicalDigestSha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(audit.logicalDigestSha256)
  ) fail(`${label} audit lacks a canonical logical digest`);
  return audit.logicalDigestSha256;
};
const storeSurface = (store) => {
  if (
    store === null || typeof store !== "object" ||
    typeof store.audit !== "function" ||
    typeof store.state !== "function" ||
    typeof store.insert !== "function" ||
    typeof store.corruptionProbe !== "function"
  ) fail("Q-04 checkpoint probes require a persistent store surface");
  return store;
};
const buffer32 = (value, label) => {
  if (!Buffer.isBuffer(value) || value.length !== 32) {
    fail(`${label} must be exactly 32 bytes`);
  }
  return value;
};
const validateAliasEvidence = (value) => {
  exactKeys(value, Q04_ALIAS_EVIDENCE_FIELDS, "Q-04 alias evidence");
  for (const field of Q04_ALIAS_EVIDENCE_FIELDS) {
    const buffer = buffer32(value[field], `Q-04 alias evidence.${field}`);
    if (!buffer.every((byte) => byte === 0xff)) {
      fail("Q-04 alias source/result mutation did not occur");
    }
  }
  return value;
};
const rejection = (definition, { inputSha256, before, after, error }) => {
  const preStateSha256 = auditDigest(before, `Q-04 ${definition.kind} pre`);
  const postStateSha256 = auditDigest(after, `Q-04 ${definition.kind} post`);
  if (preStateSha256 !== postStateSha256) {
    fail(`Q-04 ${definition.kind} probe changed persistent state`);
  }
  const result = {
    caseId: definition.id,
    caseSha256: q04CheckpointProbeCaseDigest(definition),
    kind: definition.kind,
    expectedOutcome: definition.expectedOutcome,
    accepted: false,
    stateUnchanged: true,
    errorCode: definition.errorCode,
    inputSha256,
    preStateSha256,
    postStateSha256,
    rejection: error instanceof Error ? error.message : String(error),
  };
  return Object.freeze({
    ...result,
    resultSha256: q04CheckpointProbeResultDigest(result),
  });
};
const attemptedInsert = (store, key, unexpectedAcceptance) => {
  try {
    const current = store.state();
    store.insert({
      expectedCount: current.normalCount,
      expectedRoot: current.root,
      key: Buffer.from(key),
    });
    fail(unexpectedAcceptance);
  } catch (error) {
    if (error instanceof Q04CheckpointProbeError) throw error;
    if (!(error instanceof Q04PersistentStoreError)) throw error;
    return error;
  }
};
const malformedFieldCandidates = () => Object.freeze([
  Buffer.alloc(31),
  Buffer.alloc(33),
  Buffer.from(Q04_FR_MODULUS.toString(16).padStart(64, "0"), "hex"),
  Buffer.from((Q04_FR_MODULUS + 1n).toString(16).padStart(64, "0"), "hex"),
  Buffer.alloc(32, 0xff),
]);

/**
 * Execute every canonical Q-04 checkpoint probe and return immutable,
 * self-identifying results. The returned digests bind case definition, input,
 * outcome, state digests, and rejection text.
 */
export function runQ04CheckpointProbes({ store, lastKey, aliasEvidence }) {
  storeSurface(store);
  buffer32(lastKey, "Q-04 checkpoint last key");
  validateAliasEvidence(aliasEvidence);

  const results = [];
  const duplicate = caseByKind.get("duplicate");
  const duplicateBefore = store.audit();
  const duplicateError = attemptedInsert(
    store,
    lastKey,
    "Q-04 duplicate probe was unexpectedly accepted",
  );
  results.push(rejection(duplicate, {
    inputSha256: sha256(lastKey),
    before: duplicateBefore,
    after: store.audit(),
    error: duplicateError,
  }));

  for (const kind of ["ordering", "successor-pointer"]) {
    const definition = caseByKind.get(kind);
    const before = store.audit();
    const corruption = store.corruptionProbe(kind);
    assertion(
      corruption !== null && corruption.rejected === true &&
        typeof corruption.rejection === "string",
      `Q-04 ${kind} corruption probe did not report rejection`,
    );
    results.push(rejection(definition, {
      inputSha256: sha256(kind, Buffer.from(auditDigest(before, `Q-04 ${kind} pre`), "hex")),
      before,
      after: store.audit(),
      error: new Error(corruption.rejection),
    }));
  }

  const alias = caseByKind.get("alias");
  const aliasBefore = store.audit();
  const aliasError = attemptedInsert(
    store,
    lastKey,
    "Q-04 value-alias probe was unexpectedly accepted",
  );
  results.push(rejection(alias, {
    inputSha256: sha256("alias", lastKey, ...Q04_ALIAS_EVIDENCE_FIELDS.map((field) => aliasEvidence[field])),
    before: aliasBefore,
    after: store.audit(),
    error: aliasError,
  }));

  const noncanonical = caseByKind.get("noncanonical-field");
  const malformed = malformedFieldCandidates();
  const malformedBefore = store.audit();
  const messages = [];
  for (const candidate of malformed) {
    messages.push(attemptedInsert(
      store,
      candidate,
      "Q-04 noncanonical-field probe was unexpectedly accepted",
    ).message);
    if (auditDigest(store.audit(), "Q-04 noncanonical-field subprobe") !==
      auditDigest(malformedBefore, "Q-04 noncanonical-field pre")) {
      fail("Q-04 noncanonical-field subprobe changed persistent state");
    }
  }
  results.push(rejection(noncanonical, {
    inputSha256: sha256(...malformed),
    before: malformedBefore,
    after: store.audit(),
    error: new Error(messages.join(" | ")),
  }));

  if (results.length !== Q04_CHECKPOINT_PROBE_COUNT) {
    fail("Q-04 checkpoint probe count differs from canonical cases");
  }
  return Object.freeze(results);
}
