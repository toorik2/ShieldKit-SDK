import assert from "node:assert/strict";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runQ04History } from "./v2-q04-history-runner.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");
const workspaceRoot = resolve(packageRoot, "..");
const temporaryRoot = join(packageRoot, ".tmp");
const parameterSourcePath = resolve(
  workspaceRoot,
  "node_modules/circomlib/circuits/poseidon_constants.circom",
);

test("Q-04 nonqualifying history self-test uses fresh checkpoint writer processes and exact oracle comparisons", async (t) => {
  mkdirSync(temporaryRoot, { recursive: true, mode: 0o700 });
  const parent = mkdtempSync(join(temporaryRoot, "q04-history-self-test-"));
  chmodSync(parent, 0o700);
  const outputDirectory = join(parent, "history-0");
  mkdirSync(outputDirectory, { mode: 0o700 });
  const configPath = join(parent, "history-config.json");
  writeFileSync(configPath, `${JSON.stringify({
    schema: "shieldkit-v2-direct/q04-history-config/v1",
    historyIndex: 0,
    entryCount: 20,
    checkpointInterval: 10,
    outputDirectory,
    parameterSourcePath,
    qualifying: false,
  }, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  t.after(() => rmSync(parent, { recursive: true, force: true }));

  const result = await runQ04History(configPath);
  assert.equal(result.schema, "shieldkit-v2-direct/q04-history-result/v3");
  assert.match(result.configSha256, /^[0-9a-f]{64}$/u);
  assert.equal(result.qualifying, false);
  assert.equal(result.acceptedEntries, 20);
  assert.deepEqual(result.comparisons, {
    transitions: 20,
    predecessorMembershipPaths: 20,
    emptyAppendNonMembershipPaths: 20,
    postInsertionMembershipPaths: 20,
    discrepancies: 0,
  });
  assert.equal(result.checkpoints.length, 2);
  const processIds = result.checkpoints.flatMap((checkpoint) => [
    checkpoint.workerPid,
    checkpoint.reopenPid,
  ]);
  assert.equal(new Set(processIds).size, processIds.length);
  assert.ok(result.checkpoints.every((checkpoint) =>
    checkpoint.closeExitCode === 0 &&
    checkpoint.reopenExitCode === 0 &&
    checkpoint.workerPid !== checkpoint.reopenPid &&
    checkpoint.storage.segmentPreClose.totalFileBytes > 0 &&
    checkpoint.storage.segmentPostClose.totalFileBytes > 0 &&
    checkpoint.storage.reopenPreClose.totalFileBytes > 0 &&
    checkpoint.storage.reopenPostClose.totalFileBytes > 0 &&
    checkpoint.segmentMeasurement.wallMs >= 0 &&
    checkpoint.reopenMeasurement.wallMs >= 0 &&
    checkpoint.probes.length === 5 &&
    checkpoint.probes.every((probe) =>
      probe.accepted === false &&
      probe.stateUnchanged === true &&
      probe.preStateSha256 === probe.postStateSha256
    )
  ));
  assert.equal(
    result.checkpoints.at(-1).storage.reopenPostClose.fileBytes.database,
    result.measurements.databaseBytes,
  );
  assert.equal(result.measurements.walBytes, 0);
  assert.equal(result.measurements.shmBytes, 0);
  assert.equal(result.finalActualRoot, result.finalOracleRoot);
  assert.equal(
    result.actualTranscriptSha256,
    result.oracleTranscriptSha256,
  );
  assert.equal(
    readFileSync(result.transitionArtifact.path, "utf8")
      .trim()
      .split("\n").length,
    20,
  );
  const firstTransition = JSON.parse(
    readFileSync(result.transitionArtifact.path, "utf8").trim().split("\n")[0],
  );
  assert.deepEqual(firstTransition.actual.operationCounts, {
    productionLeafHashCalls: 3,
    productionPredecessorValidationLeafHashCalls: 1,
    productionMutationLeafHashCalls: 2,
    productionMutationNodeHashCalls: 128,
    productionLogicalPathSiblingLookups: 64,
    productionPathOverrideHits: 1,
    productionPathAdapterNodeReads: 63,
    productionRootAdapterNodeReads: 1,
    productionTotalAdapterNodeReads: 64,
    productionLeafReads: 2,
    productionOrderLookups: 2,
    productionPostMembershipNodeHashCalls: 32,
    productionPostMembershipNodeReads: 32,
  });
  assert.equal(lstatSync(result.transitionArtifact.path).mode & 0o777, 0o600);
  assert.equal(lstatSync(join(outputDirectory, "store.sqlite")).mode & 0o777, 0o600);
  for (const checkpoint of [10, 20]) {
    const suffix = String(checkpoint).padStart(5, "0");
    assert.equal(
      lstatSync(join(outputDirectory, `segment-${suffix}.json`)).mode &
        0o777,
      0o600,
    );
    assert.equal(
      lstatSync(join(outputDirectory, `reopen-${suffix}.json`)).mode &
        0o777,
      0o600,
    );
  }
});

test("Q-04 history runner rejects a non-private outer config before work", async (t) => {
  mkdirSync(temporaryRoot, { recursive: true, mode: 0o700 });
  const parent = mkdtempSync(join(temporaryRoot, "q04-history-mode-test-"));
  chmodSync(parent, 0o700);
  const outputDirectory = join(parent, "history-0");
  mkdirSync(outputDirectory, { mode: 0o700 });
  const configPath = join(parent, "history-config.json");
  writeFileSync(configPath, `${JSON.stringify({
    schema: "shieldkit-v2-direct/q04-history-config/v1",
    historyIndex: 0,
    entryCount: 1,
    checkpointInterval: 1,
    outputDirectory,
    parameterSourcePath,
    qualifying: false,
  })}\n`, { mode: 0o600, flag: "wx" });
  chmodSync(configPath, 0o644);
  t.after(() => rmSync(parent, { recursive: true, force: true }));

  await assert.rejects(
    runQ04History(configPath),
    /mode-0600 regular file/u,
  );
  assert.equal(
    lstatSync(outputDirectory).mode & 0o777,
    0o700,
  );
});
