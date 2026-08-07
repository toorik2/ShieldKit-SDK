import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDepth4SymbolicCertificate,
  inspectDepth4SemanticCorePolicy,
  Q04_DEPTH4_SYMBOLIC_CERTIFICATE_SCHEMA,
  verifyDepth4SymbolicCertificate,
} from "./depth4-symbolic-certificate.mjs";

let certificate;
const built = () => {
  certificate ??= buildDepth4SymbolicCertificate();
  return certificate;
};

test("depth-4 symbolic templates execute the exact opaque production kernel",
  () => {
    const value = built();
    assert.equal(value.schema, Q04_DEPTH4_SYMBOLIC_CERTIFICATE_SCHEMA);
    assert.equal(value.status, "machine-checked-symbolic-template-evidence");
    assert.equal(value.definition.controlSkeletons, 911);
    assert.equal(
      value.definition.representedConcreteRankStateGapTransitions,
      "93928268313",
    );
    assert.equal(value.definition.quotientClaim, false);
    assert.equal(value.definition.universalTemplateClaim, true);
    assert.equal("checker" in value, false);
    assert.equal(value.cases.length, 911);
    for (const entry of value.cases) {
      assert.equal("mutationSha256" in entry, false);
      assert.equal("traceSha256" in entry, false);
    }
    assert.deepEqual(
      [...new Set(value.cases.map(({ normalCount }) => normalCount))],
      Array.from({ length: 14 }, (_, index) => index),
    );
    assert.deepEqual(
      value.cases.map(({ normalCount }) => normalCount)
        .reduce((counts, normalCount) => {
          counts[normalCount] = (counts[normalCount] ?? 0) + 1;
          return counts;
        }, {}),
      Object.fromEntries(
        Array.from({ length: 14 }, (_, normalCount) => [
          normalCount,
          normalCount === 0 ? 1 : normalCount * (normalCount + 1),
        ]),
      ),
    );
    const result = verifyDepth4SymbolicCertificate(value);
    assert.equal(result.status, "verified-symbolic-template-evidence");
    assert.equal(result.controlSkeletons, 911);
    assert.equal(result.formalTheoremClaim, false);
  });

test("depth-4 symbolic checker rejects a self-consistent-looking case tamper",
  () => {
    const value = built();
    const tamperedCases = value.cases.map((entry, index) =>
      index === 417
        ? {
          ...entry,
          canonicalPostRootSha256: "00".repeat(32),
          statementSha256: "11".repeat(32),
        }
        : entry
    );
    assert.throws(
      () => verifyDepth4SymbolicCertificate({
        ...value,
        cases: tamperedCases,
        casesSha256: "22".repeat(32),
        certificateSha256: "33".repeat(32),
      }),
      /differs from fresh exact-kernel re-execution/u,
    );
  });

test("semantic-core manifest covers every opaque-value helper", () => {
  const policy = inspectDepth4SemanticCorePolicy();
  assert.equal(
    policy.policy,
    "opaque-field-and-hash-values-may-only-cross-the-semantic-algebra-v1",
  );
  assert.deepEqual(
    policy.functions.map(({ name }) => name),
    [
      "validateLeaf",
      "readStoredNode",
      "pathFromStore",
      "pathFromSiblings",
      "witnessLeaf",
      "runPersistentIndexedNullifierSemanticKernel",
    ],
  );
  for (const hash of [
    policy.productionSourceSha256,
    policy.manifestSha256,
    ...policy.functions.map(({ sha256 }) => sha256),
  ]) assert.match(hash, /^[0-9a-f]{64}$/u);
});
