import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { parseStrictJson } from "../packages/profile/load.mjs";
import { writeQ07SingleHistoryDataset } from "./v2-q07-dataset.mjs";
import {
  Q07_STORE_WORKER_SCHEMA,
  Q07_STORE_WORKER_OUTPUT_SCHEMA,
  runQ07StoreWorker,
} from "./v2-q07-store-worker.mjs";

function privateDir() {
  const path = mkdtempSync(join(tmpdir(), "q07-store-worker-"));
  chmodSync(path, 0o700);
  return path;
}

function base(root, dataset, mode, endOrdinal, databasePath, resultName) {
  return {
    schema: Q07_STORE_WORKER_SCHEMA,
    mode,
    historyIndex: 0,
    dataset: {
      mainCount: dataset.mainCount,
      path: dataset.path,
      sha256: dataset.sha256,
      transcriptSha256: dataset.transcriptSha256,
    },
    endOrdinal,
    databasePath,
    resultPath: join(root, resultName),
  };
}

function expected(result) {
  const { normalCount, root, transcriptChainSha256, logicalDigestSha256 } = result.finalAudit;
  return { normalCount, root, transcriptChainSha256, logicalDigestSha256 };
}

test("Q-07 worker uses the shared dataset and writes nonqualifying indexed-store records", () => {
  const root = privateDir();
  try {
    // The dataset's reserved ordinals 1 (zero) and 2 (Fr-1) are deliberately
    // exercised here through the real store, never filtered by the worker.
    const dataset = writeQ07SingleHistoryDataset({ outputDirectory: root, testOnlyMainCount: 4 });
    const prepared3 = join(root, "prepared-three.sqlite");
    const prepared4 = join(root, "prepared-four.sqlite");
    const built3 = runQ07StoreWorker(base(root, dataset, "full-history-build", 3, prepared3, "built3.json"));
    const built4 = runQ07StoreWorker(base(root, dataset, "full-history-build", 4, prepared4, "built4.json"));
    assert.equal(built4.schema, Q07_STORE_WORKER_OUTPUT_SCHEMA);
    assert.equal(built4.qualification, "not-qualified");
    assert.equal(built4.qualificationBoundary, "indexed-nullifier-store-microbenchmark-only");
    assert.equal(built4.finalAudit.normalCount, 4);
    assert.equal(built4.fixedDepthOperationCounts.productionMutationNodeHashCalls, 128);
    const persisted = parseStrictJson(readFileSync(join(root, "built4.json")));
    assert.equal(persisted.dataset.sha256, dataset.sha256);
    assert.equal(persisted.finalAudit.root, built4.finalAudit.root);

    const reference = runQ07StoreWorker({
      ...base(root, dataset, "reference-insert", 5, join(root, "reference.sqlite"), "reference.json"),
      preparedStorePath: prepared4,
      expectedPreparedState: expected(built4),
      preparedDatabaseSha256: built4.database.closedFileBytes.sha256,
    });
    assert.equal(
      reference.preparation.scope,
      "indexed-nullifier-reference-insert-and-full-audit-not-a-performance-sample",
    );

    const warm = runQ07StoreWorker({
      ...base(root, dataset, "warm-insert", 5, join(root, "warm.sqlite"), "warm.json"),
      preparedStorePath: prepared4,
      expectedPreparedState: expected(built4),
      expectedPostState: expected(reference),
      preparedDatabaseSha256: built4.database.closedFileBytes.sha256,
    });
    assert.equal(warm.measurement.scope, "indexed-nullifier-warm-insert-derive-commit-only");
    assert.equal(warm.postState.normalCount, 5);

    const suffix = runQ07StoreWorker({
      ...base(root, dataset, "suffix-insert", 4, join(root, "suffix.sqlite"), "suffix.json"),
      preparedStorePath: prepared3,
      expectedPreparedState: expected(built3),
      expectedPostState: expected(built4),
      preparedDatabaseSha256: built3.database.closedFileBytes.sha256,
      startOrdinal: 4,
    });
    assert.equal(suffix.measurement.inserted, 1);
    assert.equal(suffix.postState.normalCount, 4);

    const audit = runQ07StoreWorker({
      ...base(root, dataset, "full-store-audit", 4, prepared4, "audit.json"),
      expectedPreparedState: expected(built4),
    });
    assert.equal(audit.measurement.scope, "indexed-nullifier-full-store-audit");
    assert.equal(audit.finalAudit.logicalDigestSha256, built4.finalAudit.logicalDigestSha256);

    const reopened = runQ07StoreWorker({
      ...base(root, dataset, "reopened-handle-path", 4, join(root, "reopened.sqlite"), "reopened.json"),
      preparedStorePath: prepared4,
      expectedPreparedState: expected(built4),
      preparedDatabaseSha256: built4.database.closedFileBytes.sha256,
      readPhysicalIndex: 2,
    });
    assert.equal(reopened.reopenedHandleTelemetry.osCacheEvictionAttempted, false);
    assert.equal(reopened.reopenedHandleTelemetry.pathTreeDepth, 32);
    assert.equal(reopened.fixedDepthOperationCounts.productionPostMembershipNodeReads, 32);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Q-07 worker fails closed when the config does not bind the verified dataset", () => {
  const root = privateDir();
  try {
    const dataset = writeQ07SingleHistoryDataset({ outputDirectory: root, testOnlyMainCount: 3 });
    assert.throws(() => runQ07StoreWorker({
      ...base(root, dataset, "full-history-build", 3, join(root, "bad.sqlite"), "bad.json"),
      dataset: { mainCount: dataset.mainCount, path: dataset.path, sha256: "00".repeat(32), transcriptSha256: dataset.transcriptSha256 },
    }), /dataset SHA-256/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
