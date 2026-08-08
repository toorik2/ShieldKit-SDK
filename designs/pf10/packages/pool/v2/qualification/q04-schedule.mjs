import { createHash } from "node:crypto";

export const Q04_HISTORY_COUNT = 4;
export const Q04_ENTRIES_PER_HISTORY = 25_000;
export const Q04_CHECKPOINT_INTERVAL = 1_000;
export const Q04_CHECKPOINTS_PER_HISTORY =
  Q04_ENTRIES_PER_HISTORY / Q04_CHECKPOINT_INTERVAL;
export const Q04_TOTAL_ENTRIES =
  Q04_HISTORY_COUNT * Q04_ENTRIES_PER_HISTORY;
export const Q04_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const Q04_SEED_DOMAIN =
  "shieldkit-v2-q04-nullifier-history-v1";
export const Q04_KEY_DOMAIN =
  "shieldkit-v2-q04-nullifier-key-v1";

export const Q04_HISTORY_SEED_HEX = Object.freeze([
  "8e5d9a4520a6598c2afe5904e3d0db5a50f3d110eff811319b8690c38dac2a99",
  "a9d9fd22e18d7b38004a8c470055439a1a9827eca3ac62780c4966b045085b28",
  "7297823284ef95acfdf81160f470c017f36279a27c61343fef7fdbb375f0d594",
  "2e6f78cd79e340a1eda10939dc15977b103760bed09dbca4baddcd994a757a6f",
]);

export const Q04_EDGE_SCHEDULE = Object.freeze([
  Object.freeze({ 1: 0n, 2: Q04_FR_MODULUS - 1n }),
  Object.freeze({ 1: Q04_FR_MODULUS - 1n, 1000: 0n }),
  Object.freeze({ 1000: 0n, 1001: Q04_FR_MODULUS - 1n }),
  Object.freeze({
    24999: 0n,
    25000: Q04_FR_MODULUS - 1n,
  }),
]);

export class Q04ScheduleError extends Error {
  constructor(message) {
    super(message);
    this.name = "Q04ScheduleError";
  }
}

const fail = (message) => {
  throw new Q04ScheduleError(message);
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
const integer = (value, low, high, label) => {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(`${label} must be an integer from ${low} through ${high}`);
  }
  return value;
};
const u32be = (value) => {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
};
const u64be = (value) => {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
};
const encodedFr = (value) =>
  Buffer.from(value.toString(16).padStart(64, "0"), "hex");

export function q04HistorySeed(historyIndex) {
  integer(historyIndex, 0, Q04_HISTORY_COUNT - 1, "Q-04 history index");
  const seed = createHash("sha256")
    .update(Q04_SEED_DOMAIN, "ascii")
    .update(u32be(historyIndex))
    .digest();
  if (seed.toString("hex") !== Q04_HISTORY_SEED_HEX[historyIndex]) {
    fail(`Q-04 history ${historyIndex} seed derivation differs`);
  }
  return seed;
}

export function generateQ04HistoryKeys(value) {
  const input = exactKeys(
    value,
    ["entryCount", "historyIndex"],
    "Q-04 history generation",
  );
  const historyIndex = integer(
    input.historyIndex,
    0,
    Q04_HISTORY_COUNT - 1,
    "Q-04 history index",
  );
  const entryCount = integer(
    input.entryCount,
    1,
    Q04_ENTRIES_PER_HISTORY,
    "Q-04 entry count",
  );
  const seed = q04HistorySeed(historyIndex);
  const scheduled = Q04_EDGE_SCHEDULE[historyIndex];
  const seen = new Set();
  const keys = [];
  for (let ordinal = 1; ordinal <= entryCount; ordinal += 1) {
    let selected = scheduled[ordinal];
    if (selected === undefined) {
      for (let attempt = 0; attempt <= 0xffff_ffff; attempt += 1) {
        const digest = createHash("sha256")
          .update(Q04_KEY_DOMAIN, "ascii")
          .update(seed)
          .update(u64be(ordinal))
          .update(u32be(attempt))
          .digest();
        const candidate = BigInt(`0x${digest.toString("hex")}`);
        if (
          candidate < Q04_FR_MODULUS &&
          candidate !== 0n &&
          candidate !== Q04_FR_MODULUS - 1n &&
          !seen.has(candidate.toString())
        ) {
          selected = candidate;
          break;
        }
      }
      if (selected === undefined) {
        fail(`Q-04 key derivation exhausted at ordinal ${ordinal}`);
      }
    }
    if (
      selected < 0n ||
      selected >= Q04_FR_MODULUS ||
      seen.has(selected.toString())
    ) fail(`Q-04 scheduled key at ordinal ${ordinal} is invalid or duplicate`);
    seen.add(selected.toString());
    keys.push(encodedFr(selected));
  }
  return Object.freeze(keys);
}

export function q04ScheduleMetadata() {
  return Object.freeze({
    historyCount: Q04_HISTORY_COUNT,
    entriesPerHistory: Q04_ENTRIES_PER_HISTORY,
    totalEntries: Q04_TOTAL_ENTRIES,
    checkpointInterval: Q04_CHECKPOINT_INTERVAL,
    checkpointsPerHistory: Q04_CHECKPOINTS_PER_HISTORY,
    seedDerivation:
      "SHA256(ASCII(shieldkit-v2-q04-nullifier-history-v1) || history_u32be)",
    keyDerivation:
      "SHA256(ASCII(shieldkit-v2-q04-nullifier-key-v1) || seed32 || " +
      "ordinal_u64be || attempt_u32be), rejection-sampled into Fr, " +
      "deduplicated, and excluding reserved edge values",
    seeds: Object.freeze([...Q04_HISTORY_SEED_HEX]),
    edgeSchedule: Object.freeze(Q04_EDGE_SCHEDULE.map((schedule) =>
      Object.freeze(Object.fromEntries(
        Object.entries(schedule).map(([ordinal, key]) => [
          ordinal,
          key.toString(16).padStart(64, "0"),
        ]),
      ))
    )),
  });
}
