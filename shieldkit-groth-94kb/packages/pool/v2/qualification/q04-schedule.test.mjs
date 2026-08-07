import assert from "node:assert/strict";
import test from "node:test";

import {
  generateQ04HistoryKeys,
  Q04_CHECKPOINTS_PER_HISTORY,
  Q04_EDGE_SCHEDULE,
  Q04_ENTRIES_PER_HISTORY,
  Q04_FR_MODULUS,
  Q04_HISTORY_COUNT,
  Q04_HISTORY_SEED_HEX,
  Q04_TOTAL_ENTRIES,
  q04HistorySeed,
  q04ScheduleMetadata,
} from "./q04-schedule.mjs";

const field = (value) =>
  BigInt(`0x${Buffer.from(value).toString("hex")}`);

test("Q-04 history seeds and exact edge positions are frozen", () => {
  assert.deepEqual(
    Array.from({ length: Q04_HISTORY_COUNT }, (_, historyIndex) =>
      q04HistorySeed(historyIndex).toString("hex")
    ),
    Q04_HISTORY_SEED_HEX,
  );
  const histories = Array.from(
    { length: Q04_HISTORY_COUNT },
    (_, historyIndex) =>
      generateQ04HistoryKeys({
        historyIndex,
        entryCount: Q04_ENTRIES_PER_HISTORY,
      }),
  );
  for (let historyIndex = 0; historyIndex < histories.length; historyIndex += 1) {
    for (const [ordinal, expected] of Object.entries(
      Q04_EDGE_SCHEDULE[historyIndex],
    )) {
      assert.equal(field(histories[historyIndex][Number(ordinal) - 1]), expected);
    }
  }
});

test("Q-04 qualifying histories contain exactly 100,000 unique canonical keys", () => {
  let total = 0;
  for (let historyIndex = 0; historyIndex < Q04_HISTORY_COUNT; historyIndex += 1) {
    const first = generateQ04HistoryKeys({
      historyIndex,
      entryCount: Q04_ENTRIES_PER_HISTORY,
    });
    const second = generateQ04HistoryKeys({
      historyIndex,
      entryCount: Q04_ENTRIES_PER_HISTORY,
    });
    assert.deepEqual(first, second);
    assert.equal(new Set(first.map((key) => key.toString("hex"))).size, first.length);
    assert.ok(first.every((key) => field(key) < Q04_FR_MODULUS));
    total += first.length;
  }
  assert.equal(total, Q04_TOTAL_ENTRIES);
});

test("Q-04 schedule metadata cannot overclaim a single 100k history", () => {
  assert.deepEqual(
    {
      historyCount: q04ScheduleMetadata().historyCount,
      entriesPerHistory: q04ScheduleMetadata().entriesPerHistory,
      checkpointsPerHistory: q04ScheduleMetadata().checkpointsPerHistory,
      totalEntries: q04ScheduleMetadata().totalEntries,
    },
    {
      historyCount: 4,
      entriesPerHistory: 25_000,
      checkpointsPerHistory: Q04_CHECKPOINTS_PER_HISTORY,
      totalEntries: 100_000,
    },
  );
});

test("Q-04 schedule rejects unknown fields and out-of-range counts", () => {
  assert.throws(
    () => generateQ04HistoryKeys({
      historyIndex: 0,
      entryCount: 1,
      seed: Buffer.alloc(32),
    }),
    /missing or unknown/,
  );
  assert.throws(
    () => generateQ04HistoryKeys({ historyIndex: 0, entryCount: 0 }),
    /entry count/,
  );
  assert.throws(
    () => generateQ04HistoryKeys({
      historyIndex: 0,
      entryCount: Q04_ENTRIES_PER_HISTORY + 1,
    }),
    /entry count/,
  );
});
