import assert from "node:assert/strict";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  Q04_ALIAS_EVIDENCE_FIELDS,
  Q04_CHECKPOINT_PROBE_CASES,
  Q04_CHECKPOINT_PROBE_COUNT,
  Q04CheckpointProbeError,
  q04CheckpointProbeCaseDigest,
  runQ04CheckpointProbes,
} from "./q04-checkpoint-probes.mjs";
import { openQ04PersistentNullifierStore } from "./persistent-nullifier-store.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const workspace = resolve(here, "../../../../..");
const temporaryRoot = join(workspace, ".tmp");
const field = (value) => Buffer.from(
  BigInt(value).toString(16).padStart(64, "0"),
  "hex",
);

function fixture(t) {
  mkdirSync(temporaryRoot, { recursive: true, mode: 0o700 });
  const parent = mkdtempSync(join(temporaryRoot, "q04-checkpoint-probes-"));
  chmodSync(parent, 0o700);
  const store = openQ04PersistentNullifierStore({
    path: join(parent, "store.sqlite"),
    create: true,
    historyIndex: 0,
    seed: field(0x99n),
  });
  t.after(() => {
    store.close();
    rmSync(parent, { recursive: true, force: true });
  });
  for (const key of [field(0x30n), field(0x10n), field(0x20n)]) {
    const state = store.state();
    store.insert({
      expectedCount: state.normalCount,
      expectedRoot: state.root,
      key,
    });
  }
  return store;
}

const aliasEvidence = () => Object.fromEntries(
  Q04_ALIAS_EVIDENCE_FIELDS.map((fieldName) => [fieldName, Buffer.alloc(32, 0xff)]),
);

test("Q-04 checkpoint probes have five canonical, self-identifying deterministic cases", (t) => {
  const store = fixture(t);
  const input = {
    store,
    lastKey: field(0x20n),
    aliasEvidence: aliasEvidence(),
  };
  const first = runQ04CheckpointProbes(input);
  const second = runQ04CheckpointProbes(input);

  assert.equal(Q04_CHECKPOINT_PROBE_COUNT, 5);
  assert.equal(first.length, Q04_CHECKPOINT_PROBE_COUNT);
  assert.deepEqual(first, second);
  assert.deepEqual(
    first.map((probe) => probe.kind),
    Q04_CHECKPOINT_PROBE_CASES.map((definition) => definition.kind),
  );
  for (const [index, probe] of first.entries()) {
    const definition = Q04_CHECKPOINT_PROBE_CASES[index];
    assert.equal(probe.caseId, definition.id);
    assert.equal(probe.caseSha256, q04CheckpointProbeCaseDigest(definition));
    assert.match(probe.caseSha256, /^[0-9a-f]{64}$/u);
    assert.match(probe.resultSha256, /^[0-9a-f]{64}$/u);
    assert.equal(probe.expectedOutcome, "reject");
    assert.equal(probe.accepted, false);
    assert.equal(probe.stateUnchanged, true);
    assert.equal(probe.preStateSha256, probe.postStateSha256);
    assert.equal(probe.errorCode, definition.errorCode);
    assert.equal(typeof probe.rejection, "string");
  }
});

test("Q-04 checkpoint probe invocation rejects non-mutated alias evidence before touching durable state", (t) => {
  const store = fixture(t);
  const before = store.audit().logicalDigestSha256;
  const evidence = aliasEvidence();
  evidence.inputKey[0] = 0;
  assert.throws(
    () => runQ04CheckpointProbes({
      store,
      lastKey: field(0x20n),
      aliasEvidence: evidence,
    }),
    Q04CheckpointProbeError,
  );
  assert.equal(store.audit().logicalDigestSha256, before);
});
