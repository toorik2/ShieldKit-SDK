import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
} from "../../../action/v2/poseidon.mjs";
import {
  createDepth4PersistentIndexedNullifierQualificationKernel,
  PERSISTENT_NULLIFIER_FR_MODULUS,
  PERSISTENT_NULLIFIER_LEAF_TYPES,
} from "../persistent-indexed-nullifier.mjs";
import {
  createIndependentPoseidonOracle,
} from "./independent-poseidon-oracle.mjs";
import {
  openDepth4PersistentNullifierQualificationStore,
} from "./persistent-nullifier-store.mjs";
import {
  buildDepth4SymbolicCertificate,
  verifyDepth4SymbolicCertificate,
} from "./depth4-symbolic-certificate.mjs";

export const Q04_DEPTH4_DEPTH = 4;
export const Q04_DEPTH4_CAPACITY = 16;
export const Q04_DEPTH4_OCCUPANCY_STATES = 65_536;

const FR = PERSISTENT_NULLIFIER_FR_MODULUS;
const ZERO = "00".repeat(32);
const encode = (value) => value.toString(16).padStart(64, "0");
const keyBytes = (value) => Buffer.from(encode(value), "hex");
const exactKeys = (value, expected, label) => {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new TypeError(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) throw new TypeError(`${label} has missing or unknown properties`);
  return value;
};
const freeze = (value) => Object.freeze(value);

function createHashPair(oracle) {
  let comparisons = 0;
  let discrepancies = 0;
  const leafCache = new Map();
  const nodeCache = new Map();
  const digest = createHash("sha256")
    .update(
      "ShieldKit/PoolActionV2Direct/Q04/depth4/hash-comparisons/v1\0",
      "ascii",
    );
  const independentLeaf = (inputs) => {
    const key = inputs.map(encode).join(":");
    if (!leafCache.has(key)) {
      leafCache.set(key, oracle.hashIndexedNullifierLeaf(inputs));
    }
    return leafCache.get(key);
  };
  const independentNode = (left, right) => {
    const key = `${encode(left)}:${encode(right)}`;
    if (!nodeCache.has(key)) {
      nodeCache.set(key, oracle.hashIndexedNullifierNode(left, right));
    }
    return nodeCache.get(key);
  };
  const compare = (kind, production, independent, inputs) => {
    comparisons += 1;
    if (production !== independent) {
      discrepancies += 1;
      throw new Error(
        `depth-4 ${kind} production/independent Poseidon discrepancy`,
      );
    }
    digest.update(kind, "ascii");
    inputs.forEach((input) =>
      digest.update(Buffer.from(encode(input), "hex"))
    );
    digest.update(Buffer.from(encode(production), "hex"));
    return production;
  };
  return freeze({
    production: freeze({
      hashLeaf: (inputs) => hashIndexedNullifierLeaf(inputs),
      hashNode: (left, right) => hashIndexedNullifierNode(left, right),
    }),
    independent: freeze({
      hashLeaf: independentLeaf,
      hashNode: independentNode,
    }),
    compared: freeze({
      hashLeaf: (inputs) => compare(
        "leaf",
        hashIndexedNullifierLeaf(inputs),
        independentLeaf(inputs),
        inputs,
      ),
      hashNode: (left, right) => compare(
        "node",
        hashIndexedNullifierNode(left, right),
        independentNode(left, right),
        [left, right],
      ),
    }),
    recorded: freeze({
      hashLeaf: (production, inputs) => compare(
        "recorded-leaf",
        production,
        independentLeaf(inputs),
        inputs,
      ),
      hashNode: (production, left, right) => compare(
        "recorded-node",
        production,
        independentNode(left, right),
        [left, right],
      ),
    }),
    evidence: () => freeze({
      comparisons,
      discrepancies,
      independentLeafCacheEntries: leafCache.size,
      independentNodeCacheEntries: nodeCache.size,
      digestSha256: digest.copy().digest("hex"),
    }),
    finish: () => freeze({
      comparisons,
      discrepancies,
      independentLeafCacheEntries: leafCache.size,
      independentNodeCacheEntries: nodeCache.size,
      digestSha256: digest.digest("hex"),
    }),
  });
}

function occupancyLeafInputs(index, occupied) {
  if (!occupied) return [0n, 0n, 0n, 0n, 0n];
  if (index === 0) return [1n, 0n, 0n, 1n, 0n];
  if (index === 1) return [3n, 1n, 0n, 1n, 0n];
  return [2n, BigInt(index), BigInt(index - 1), 1n, 0n];
}

function exhaustiveOccupancyHashes(hashPair, evidenceDigest) {
  let positions = Array.from(
    { length: Q04_DEPTH4_CAPACITY },
    (_, index) => [
      hashPair.compared.hashLeaf(occupancyLeafInputs(index, false)),
      hashPair.compared.hashLeaf(occupancyLeafInputs(index, true)),
    ],
  );
  let subtreeComparisons = 0;
  for (let depth = 1; depth <= Q04_DEPTH4_DEPTH; depth += 1) {
    const next = [];
    for (let position = 0; position < positions.length; position += 2) {
      const left = positions[position];
      const right = positions[position + 1];
      const halfBits = 2 ** (depth - 1);
      const halfStates = 2 ** halfBits;
      const stateCount = halfStates ** 2;
      const roots = new Array(stateCount);
      for (let mask = 0; mask < stateCount; mask += 1) {
        const leftMask = mask % halfStates;
        const rightMask = Math.floor(mask / halfStates);
        roots[mask] = hashPair.compared.hashNode(
          left[leftMask],
          right[rightMask],
        );
        subtreeComparisons += 1;
      }
      next.push(roots);
    }
    positions = next;
  }
  if (
    positions.length !== 1 ||
    positions[0].length !== Q04_DEPTH4_OCCUPANCY_STATES
  ) throw new Error("depth-4 occupancy table cardinality differs");
  positions[0].forEach((root, mask) => {
    evidenceDigest.update(Buffer.from([
      mask & 0xff,
      (mask >>> 8) & 0xff,
    ]));
    evidenceDigest.update(Buffer.from(encode(root), "hex"));
  });
  return freeze({
    statesChecked: positions[0].length,
    leafStateHashesChecked: Q04_DEPTH4_CAPACITY * 2,
    subtreeHashComparisons: subtreeComparisons,
    rootsSha256: createHash("sha256")
      .update(
        Buffer.concat(
          positions[0].map((root) => Buffer.from(encode(root), "hex")),
        ),
      )
      .digest("hex"),
  });
}

const emptyLeaf = (index) => ({
  type: "empty",
  index,
  key: ZERO,
  successorIndex: 0,
  successorKey: ZERO,
});
const maxLeaf = () => ({
  type: "max",
  index: 1,
  key: ZERO,
  successorIndex: 1,
  successorKey: ZERO,
});
const minLeaf = (successorIndex, successorValue) => ({
  type: "min",
  index: 0,
  key: ZERO,
  successorIndex,
  successorKey: encode(successorValue),
});
const normalLeaf = (index, value, successorIndex, successorValue) => ({
  type: "normal",
  index,
  key: encode(value),
  successorIndex,
  successorKey: encode(successorValue),
});
const leafInputs = (leaf) =>
  leaf.type === "empty"
    ? [0n, 0n, 0n, 0n, 0n]
    : [
      leaf.type === "min" ? 1n : leaf.type === "normal" ? 2n : 3n,
      BigInt(leaf.index),
      BigInt(`0x${leaf.key}`),
      BigInt(leaf.successorIndex),
      BigInt(`0x${leaf.successorKey}`),
    ];

function referenceBuild(entries, hashes) {
  const sorted = [...entries].sort((left, right) =>
    left.value < right.value ? -1 : left.value > right.value ? 1 : 0
  );
  const successor = new Map(
    sorted.map((entry, index) => [entry.index, sorted[index + 1] ?? null]),
  );
  const leaves = Array.from(
    { length: Q04_DEPTH4_CAPACITY },
    (_, index) => emptyLeaf(index),
  );
  const first = sorted[0] ?? null;
  leaves[0] = minLeaf(first?.index ?? 1, first?.value ?? 0n);
  leaves[1] = maxLeaf();
  for (const entry of entries) {
    const next = successor.get(entry.index);
    leaves[entry.index] = normalLeaf(
      entry.index,
      entry.value,
      next?.index ?? 1,
      next?.value ?? 0n,
    );
  }
  const levels = [leaves.map((leaf) => hashes.hashLeaf(leafInputs(leaf)))];
  for (let depth = 0; depth < Q04_DEPTH4_DEPTH; depth += 1) {
    const prior = levels[depth];
    levels.push(Array.from(
      { length: prior.length / 2 },
      (_, index) => hashes.hashNode(
        prior[index * 2],
        prior[(index * 2) + 1],
      ),
    ));
  }
  const paths = Array.from(
    { length: Q04_DEPTH4_CAPACITY },
    (_, physicalIndex) => {
      let cursor = physicalIndex;
      const siblings = [];
      for (let depth = 0; depth < Q04_DEPTH4_DEPTH; depth += 1) {
        siblings.push(levels[depth][cursor ^ 1]);
        cursor = Math.floor(cursor / 2);
      }
      return siblings;
    },
  );
  return freeze({
    entries: freeze(entries.map((entry) => freeze({ ...entry }))),
    leaves: freeze(leaves.map((leaf) => freeze(leaf))),
    levels: freeze(levels.map((level) => freeze(level))),
    paths: freeze(paths.map((path) => freeze(path))),
    root: levels[Q04_DEPTH4_DEPTH][0],
    sorted: freeze(sorted.map((entry) => freeze({ ...entry }))),
  });
}

function referenceInsert(before, value, hashes) {
  if (typeof value !== "bigint" || value < 0n || value >= FR) {
    throw new TypeError("reference key must be canonical BN254 Fr");
  }
  if (before.entries.length >= Q04_DEPTH4_CAPACITY - 2) {
    throw new RangeError("reference depth-4 tree is full");
  }
  if (before.entries.some((entry) => entry.value === value)) {
    throw new Error("reference nullifier key already exists");
  }
  const predecessor =
    [...before.sorted].reverse().find((entry) => entry.value < value) ??
      { index: 0, value: 0n };
  const appendIndex = before.entries.length + 2;
  const intermediateEntries = before.entries.map((entry) => ({ ...entry }));
  const intermediateLeaves = before.leaves.map((leaf) => ({ ...leaf }));
  intermediateLeaves[predecessor.index] = predecessor.index === 0
    ? minLeaf(appendIndex, value)
    : normalLeaf(
      predecessor.index,
      predecessor.value,
      appendIndex,
      value,
    );
  const intermediateLevels = [
    intermediateLeaves.map((leaf) => hashes.hashLeaf(leafInputs(leaf))),
  ];
  for (let depth = 0; depth < Q04_DEPTH4_DEPTH; depth += 1) {
    const prior = intermediateLevels[depth];
    intermediateLevels.push(Array.from(
      { length: prior.length / 2 },
      (_, index) => hashes.hashNode(
        prior[index * 2],
        prior[(index * 2) + 1],
      ),
    ));
  }
  const intermediatePath = [];
  let cursor = appendIndex;
  for (let depth = 0; depth < Q04_DEPTH4_DEPTH; depth += 1) {
    intermediatePath.push(intermediateLevels[depth][cursor ^ 1]);
    cursor = Math.floor(cursor / 2);
  }
  const after = referenceBuild([
    ...intermediateEntries,
    { index: appendIndex, value },
  ], hashes);
  return freeze({
    after,
    witness: freeze({
      depth: Q04_DEPTH4_DEPTH,
      key: encode(value),
      preRoot: before.root,
      intermediateRoot: intermediateLevels[Q04_DEPTH4_DEPTH][0],
      postRoot: after.root,
      predecessor: freeze({ ...before.leaves[predecessor.index] }),
      updatedPredecessor:
        freeze({ ...intermediateLeaves[predecessor.index] }),
      predecessorPath: before.paths[predecessor.index],
      append: freeze({
        index: appendIndex,
        emptyLeaf: freeze({ ...before.leaves[appendIndex] }),
        newLeaf: freeze({ ...after.leaves[appendIndex] }),
        path: freeze(intermediatePath),
      }),
    }),
  });
}

function adjacentOrders(normalIndices) {
  if (normalIndices.length === 0) {
    return [freeze({
      predecessorIndex: 0,
      successorIndex: 1,
      order: freeze([]),
    })];
  }
  const cases = [];
  for (const successor of normalIndices) {
    cases.push(freeze({
      predecessorIndex: 0,
      successorIndex: successor,
      order: freeze([
        successor,
        ...normalIndices.filter((index) => index !== successor),
      ]),
    }));
  }
  for (const predecessor of normalIndices) {
    cases.push(freeze({
      predecessorIndex: predecessor,
      successorIndex: 1,
      order: freeze([
        ...normalIndices.filter((index) => index !== predecessor),
        predecessor,
      ]),
    }));
    for (const successor of normalIndices) {
      if (successor === predecessor) continue;
      cases.push(freeze({
        predecessorIndex: predecessor,
        successorIndex: successor,
        order: freeze([
          ...normalIndices.filter(
            (index) => index !== predecessor && index !== successor,
          ),
          predecessor,
          successor,
        ]),
      }));
    }
  }
  return cases;
}

function compareWitness(actual, expected, label) {
  const fields = [
    "depth",
    "key",
    "preRoot",
    "intermediateRoot",
    "postRoot",
    "predecessor",
    "updatedPredecessor",
    "predecessorPath",
    "append",
  ];
  for (const field of fields) {
    if (JSON.stringify(
      actual[field],
      (_, value) => typeof value === "bigint" ? encode(value) : value,
    ) !== JSON.stringify(
      expected[field],
      (_, value) => typeof value === "bigint" ? encode(value) : value,
    )) throw new Error(`${label} witness.${field} differs`);
  }
}

const decodeHex = (value) => BigInt(`0x${value}`);
const traceHash = (value) =>
  createHash("sha256")
    .update(
      "ShieldKit/PoolActionV2Direct/Q04/depth4/control-trace/v2\0",
      "ascii",
    )
    .update(JSON.stringify(value), "utf8")
    .digest("hex");

function normalizedLeafResult(leaf) {
  if (leaf === null) return null;
  return {
    physicalIndex: leaf.physicalIndex,
    leafType: leaf.leafType,
    leafHash: "field",
    key: leaf.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.normal
      ? `key:${leaf.physicalIndex}`
      : "sentinel-key",
    successorIndex: leaf.successorIndex,
    successorKey: leaf.successorIndex >= 2
      ? `key:${leaf.successorIndex}`
      : "sentinel-key",
  };
}

function normalizeKernelTrace(trace) {
  if (
    trace?.schema !==
      "shieldkit-v2-direct/persistent-nullifier-kernel-trace/v2"
  ) throw new Error("depth-4 production mutation trace schema differs");
  const adapterCalls = trace.adapterCalls.map((entry) => {
    let args = entry.arguments;
    let result = entry.result;
    if (entry.method === "readNode") {
      result = result === null ? null : "field";
    } else if (
      entry.method === "hasNormalKey" ||
      entry.method === "predecessorIndex"
    ) {
      args = { key: "new-key" };
    } else if (entry.method === "readLeaf") {
      result = normalizedLeafResult(result);
    }
    return {
      sequence: entry.sequence,
      phase: entry.phase,
      method: entry.method,
      arguments: args,
      result,
    };
  });
  const branchFacts = Object.fromEntries(
    Object.entries(trace.branchFacts).filter(([key]) =>
      key !== "keyIsZero" && key !== "keyIsFrMinusOne"
    ),
  );
  const normalized = {
    outcome: trace.outcome,
    adapterCalls,
    guards: trace.guards.map((entry) => ({
      sequence: entry.sequence,
      phase: entry.phase,
      code: entry.code,
      passed: entry.passed,
      details: entry.details,
    })),
    nodeAddresses: trace.nodeAddresses,
    symbolicHashes: trace.symbolicHashes.map((entry) => ({
      sequence: entry.sequence,
      phase: entry.phase,
      kind: entry.kind,
      symbolicInputs: entry.symbolicInputs,
      outputSymbol: entry.outputSymbol,
    })),
    branchFacts,
  };
  return freeze({
    normalized: freeze(normalized),
    sha256: traceHash(normalized),
  });
}

function verifyRecordedPoseidon(trace, hashPair, label) {
  if (trace.symbolicHashes.length !== 3 + (4 * Q04_DEPTH4_DEPTH)) {
    throw new Error(`${label} production Poseidon trace count differs`);
  }
  let leafCalls = 0;
  let nodeCalls = 0;
  for (const entry of trace.symbolicHashes) {
    const output = decodeHex(entry.concreteOutput);
    if (entry.kind === "leaf") {
      const value = entry.concreteInputs;
      hashPair.recorded.hashLeaf(output, [
        BigInt(value.leafType),
        BigInt(value.physicalIndex),
        decodeHex(value.key),
        BigInt(value.successorIndex),
        decodeHex(value.successorKey),
      ]);
      leafCalls += 1;
    } else if (entry.kind === "node") {
      if (
        !Array.isArray(entry.concreteInputs) ||
        entry.concreteInputs.length !== 2
      ) throw new Error(`${label} recorded node inputs differ`);
      hashPair.recorded.hashNode(
        output,
        decodeHex(entry.concreteInputs[0]),
        decodeHex(entry.concreteInputs[1]),
      );
      nodeCalls += 1;
    } else {
      throw new Error(`${label} recorded Poseidon kind is unsupported`);
    }
  }
  if (leafCalls !== 3 || nodeCalls !== 16) {
    throw new Error(`${label} recorded Poseidon operation split differs`);
  }
  return freeze({ leafCalls, nodeCalls });
}

function comparePersistentTransition({
  mutation,
  expected,
  hashPair,
  label,
}) {
  compareWitness(mutation.witness, expected.witness, label);
  if (decodeHex(mutation.root.toString("hex")) !== expected.after.root) {
    throw new Error(`${label} production persistent root differs`);
  }
  if (
    mutation.metrics.treeDepth !== Q04_DEPTH4_DEPTH ||
    mutation.metrics.leafHashCalls !== 3 ||
    mutation.metrics.nodeHashCalls !== 16 ||
    mutation.metrics.logicalPathSiblingLookups !== 8 ||
    mutation.metrics.pathOverrideHits !== 1 ||
    mutation.metrics.pathAdapterNodeReads !== 7 ||
    mutation.metrics.rootAdapterNodeReads !== 1 ||
    mutation.metrics.nodeReads !== 8
  ) throw new Error(`${label} production operation counts differ`);
  const recorded = verifyRecordedPoseidon(
    mutation.qualificationTrace,
    hashPair,
    label,
  );
  return freeze({
    recorded,
    controlTrace: normalizeKernelTrace(mutation.qualificationTrace),
  });
}

const classId = (normalCount, predecessorIndex, successorIndex) =>
  `n${normalCount}:p${predecessorIndex}:s${successorIndex}`;
const rankValue = (rank, variant) =>
  variant === 0
    ? BigInt(rank * 2)
    : 1_000_003n + (BigInt(rank) * 104_729n);
const targetForCase = (localCase, valueByIndex) =>
  localCase.predecessorIndex === 0
    ? 0n
    : localCase.successorIndex === 1
    ? FR - 1n
    : valueByIndex.get(localCase.predecessorIndex) + 1n;

function runSchedule({
  state,
  localCase,
  normalCount,
  variant,
  hashPair,
  label,
}) {
  const physical = Array.from(
    { length: normalCount },
    (_, index) => index + 2,
  );
  const valueByIndex = new Map(
    localCase.order.map((physicalIndex, rank) => [
      physicalIndex,
      rankValue(rank + 1, variant),
    ]),
  );
  let reference = referenceBuild([], hashPair.independent);
  let setupTransitions = 0;
  let recordedLeafCalls = 0;
  let recordedNodeCalls = 0;
  for (const physicalIndex of physical) {
    const value = valueByIndex.get(physicalIndex);
    const expected = referenceInsert(reference, value, hashPair.independent);
    const mutation = state.insert(value);
    const checked = comparePersistentTransition({
      mutation,
      expected,
      hashPair,
      label: `${label} setup physical=${physicalIndex}`,
    });
    recordedLeafCalls += checked.recorded.leafCalls;
    recordedNodeCalls += checked.recorded.nodeCalls;
    reference = expected.after;
    setupTransitions += 1;
  }
  const target = targetForCase(localCase, valueByIndex);
  const expected = referenceInsert(reference, target, hashPair.independent);
  const mutation = state.insert(target);
  const checked = comparePersistentTransition({
    mutation,
    expected,
    hashPair,
    label: `${label} target`,
  });
  recordedLeafCalls += checked.recorded.leafCalls;
  recordedNodeCalls += checked.recorded.nodeCalls;
  if (
    mutation.witness.predecessor.index !== localCase.predecessorIndex ||
    mutation.witness.predecessor.successorIndex !== localCase.successorIndex
  ) throw new Error(`${label} local predecessor/successor class differs`);
  return freeze({
    target,
    mutation,
    controlTrace: checked.controlTrace,
    setupTransitions,
    recordedLeafCalls,
    recordedNodeCalls,
  });
}

const bufferHex = (value) => Buffer.from(value).toString("hex");

function durableStoreCheckpoint(state, audit, label) {
  if (
    state.historyIndex !== audit.historyIndex ||
    state.normalCount !== audit.normalCount ||
    bufferHex(state.root) !== bufferHex(audit.root) ||
    bufferHex(state.transcriptChainSha256) !==
      bufferHex(audit.transcriptChainSha256) ||
    audit.integrityCheck !== "ok" ||
    audit.foreignKeyViolations !== 0
  ) throw new Error(`${label} state/audit checkpoint differs`);
  return freeze({
    historyIndex: audit.historyIndex,
    normalCount: audit.normalCount,
    root: bufferHex(audit.root),
    transcriptChainSha256: bufferHex(audit.transcriptChainSha256),
    leafCount: audit.leafCount,
    nodeCount: audit.nodeCount,
    orderCount: audit.orderCount,
    logicalDigestSha256: audit.logicalDigestSha256,
    integrityCheck: audit.integrityCheck,
    foreignKeyViolations: audit.foreignKeyViolations,
  });
}

function runSqliteSchedule({
  scratch,
  id,
  lane,
  localCase,
  normalCount,
  variant,
  hashPair,
  afterSchedule = null,
}) {
  const caseDirectory = mkdtempSync(join(scratch, `${lane}-`));
  const path = join(caseDirectory, "tree.sqlite");
  const seed = createHash("sha256")
    .update("ShieldKit/Q04/depth4/sqlite-lane-seed/v1\0", "ascii")
    .update(id, "ascii")
    .update("\0", "ascii")
    .update(lane, "ascii")
    .digest();
  let store = null;
  try {
    store = openDepth4PersistentNullifierQualificationStore({
      path,
      create: true,
      historyIndex: 0,
      seed,
    });
    const schedule = runSchedule({
      state: {
        insert(value) {
          const state = store.state();
          return store.insert({
            expectedCount: state.normalCount,
            expectedRoot: state.root,
            key: keyBytes(value),
          }).mutation;
        },
      },
      localCase,
      normalCount,
      variant,
      hashPair,
      label: `depth4 class ${id} ${lane}`,
    });
    const afterResult = afterSchedule === null
      ? null
      : afterSchedule(store, schedule);
    const beforeClose = durableStoreCheckpoint(
      store.state(),
      store.audit(),
      `depth4 class ${id} ${lane} before close`,
    );
    store.close();
    store = openDepth4PersistentNullifierQualificationStore({
      path,
      create: false,
      historyIndex: 0,
      seed,
    });
    const afterReopen = durableStoreCheckpoint(
      store.state(),
      store.audit(),
      `depth4 class ${id} ${lane} after reopen`,
    );
    if (JSON.stringify(afterReopen) !== JSON.stringify(beforeClose)) {
      throw new Error(
        `depth4 class ${id} ${lane} durable reopen checkpoint differs`,
      );
    }
    return freeze({
      schedule,
      afterResult,
      persistence: freeze({
        beforeClose,
        afterReopen,
        exactReopenMatch: true,
      }),
    });
  } finally {
    if (store !== null) store.close();
    rmSync(caseDirectory, { recursive: true, force: false });
  }
}

function nonlocalPermutation(localCase) {
  const fixed = new Set([
    localCase.predecessorIndex,
    localCase.successorIndex,
  ]);
  fixed.delete(0);
  fixed.delete(1);
  const movable = localCase.order.filter((index) => !fixed.has(index));
  if (movable.length < 2) return null;
  const reversed = [...movable].reverse();
  const order = localCase.predecessorIndex === 0
    ? [localCase.successorIndex, ...reversed]
    : localCase.successorIndex === 1
    ? [...reversed, localCase.predecessorIndex]
    : [
      ...reversed,
      localCase.predecessorIndex,
      localCase.successorIndex,
    ];
  if (order.every((value, index) => value === localCase.order[index])) {
    throw new Error("depth-4 nonlocal permutation did not change rank order");
  }
  return freeze({
    predecessorIndex: localCase.predecessorIndex,
    successorIndex: localCase.successorIndex,
    order: freeze(order),
  });
}

function permutations(values) {
  if (values.length === 0) return [[]];
  const result = [];
  for (let index = 0; index < values.length; index += 1) {
    const head = values[index];
    const tail = [...values.slice(0, index), ...values.slice(index + 1)];
    for (const suffix of permutations(tail)) result.push([head, ...suffix]);
  }
  return result;
}

function exhaustiveEmbeddedDepth3({
  controlTraceByClass,
  hashPair,
  evidenceDigest,
  scratch,
}) {
  let states = 0;
  let setupTransitions = 0;
  let targetTransitions = 0;
  let fullStates = 0;
  let controlTraceMismatches = 0;
  let recordedLeafCalls = 0;
  let recordedNodeCalls = 0;
  let durableReopenChecks = 0;
  for (let normalCount = 0; normalCount <= 6; normalCount += 1) {
    for (
      const ranksByPhysical of permutations(
        Array.from({ length: normalCount }, (_, index) => index + 1),
      )
    ) {
      states += 1;
      const caseDirectory = mkdtempSync(join(scratch, "depth3-state-"));
      const path = join(caseDirectory, "tree.sqlite");
      const seed = createHash("sha256")
        .update("ShieldKit/Q04/depth4/embedded-depth3-seed/v1\0", "ascii")
        .update(Buffer.from([normalCount]))
        .update(ranksByPhysical.join(","), "ascii")
        .digest();
      let store = null;
      try {
        store = openDepth4PersistentNullifierQualificationStore({
          path,
          create: true,
          historyIndex: 0,
          seed,
        });
        let reference = referenceBuild([], hashPair.independent);
        for (let offset = 0; offset < ranksByPhysical.length; offset += 1) {
          const value = rankValue(ranksByPhysical[offset], 0);
          const expected = referenceInsert(
            reference,
            value,
            hashPair.independent,
          );
          const state = store.state();
          const mutation = store.insert({
            expectedCount: state.normalCount,
            expectedRoot: state.root,
            key: keyBytes(value),
          }).mutation;
          const checked = comparePersistentTransition({
            mutation,
            expected,
            hashPair,
            label: `embedded-depth3 state=${states} setup=${offset}`,
          });
          recordedLeafCalls += checked.recorded.leafCalls;
          recordedNodeCalls += checked.recorded.nodeCalls;
          reference = expected.after;
          setupTransitions += 1;
        }
        const beforeClose = durableStoreCheckpoint(
          store.state(),
          store.audit(),
          `embedded-depth3 state=${states} before close`,
        );
        store.close();
        store = openDepth4PersistentNullifierQualificationStore({
          path,
          create: false,
          historyIndex: 0,
          seed,
        });
        const afterReopen = durableStoreCheckpoint(
          store.state(),
          store.audit(),
          `embedded-depth3 state=${states} after reopen`,
        );
        if (JSON.stringify(afterReopen) !== JSON.stringify(beforeClose)) {
          throw new Error(
            `embedded-depth3 state=${states} durable reopen differs`,
          );
        }
        durableReopenChecks += 1;
        evidenceDigest
          .update(Buffer.from(afterReopen.logicalDigestSha256, "hex"));
        if (normalCount === 6) {
          fullStates += 1;
          continue;
        }
        const orderedPhysical = ranksByPhysical
          .map((rank, offset) => ({ rank, physicalIndex: offset + 2 }))
          .sort((left, right) => left.rank - right.rank)
          .map(({ physicalIndex }) => physicalIndex);
        const valueByIndex = new Map(
          ranksByPhysical.map((rank, offset) => [
            offset + 2,
            rankValue(rank, 0),
          ]),
        );
        for (let gap = 0; gap <= normalCount; gap += 1) {
          const localCase = {
            predecessorIndex: gap === 0 ? 0 : orderedPhysical[gap - 1],
            successorIndex:
              gap === normalCount ? 1 : orderedPhysical[gap],
          };
          const target = targetForCase(localCase, valueByIndex);
          const expected = referenceInsert(
            reference,
            target,
            hashPair.independent,
          );
          const state = store.state();
          const mutation = store.deriveInsertion({
            expectedCount: state.normalCount,
            expectedRoot: state.root,
            key: keyBytes(target),
          });
          const checked = comparePersistentTransition({
            mutation,
            expected,
            hashPair,
            label: `embedded-depth3 state=${states} gap=${gap}`,
          });
          recordedLeafCalls += checked.recorded.leafCalls;
          recordedNodeCalls += checked.recorded.nodeCalls;
          targetTransitions += 1;
          const expectedControlTrace = controlTraceByClass.get(classId(
            normalCount,
            localCase.predecessorIndex,
            localCase.successorIndex,
          ));
          if (
            expectedControlTrace === undefined ||
            checked.controlTrace.sha256 !== expectedControlTrace
          ) controlTraceMismatches += 1;
          evidenceDigest
            .update(Buffer.from([normalCount, gap]))
            .update(Buffer.from(checked.controlTrace.sha256, "hex"));
        }
      } finally {
        if (store !== null) store.close();
        rmSync(caseDirectory, { recursive: true, force: false });
      }
    }
  }
  if (
    states !== 874 ||
    setupTransitions !== 5_039 ||
    targetTransitions !== 873 ||
    fullStates !== 720 ||
    durableReopenChecks !== states ||
    controlTraceMismatches !== 0
  ) {
    throw new Error(
      "embedded depth-3 exhaustive control-trace counters differ",
    );
  }
  return freeze({
    definition:
      "all sum(n!, n=0..6)=874 rank permutations embedded in the first " +
      "eight physical leaves of the fixed depth-4 production kernel; all " +
      "873 valid next insertion gaps at counts 0..5",
    states,
    setupTransitions,
    targetTransitions,
    fullStates,
    sqliteStates: states,
    durableReopenChecks,
    controlTraceMismatches,
    recordedLeafCalls,
    recordedNodeCalls,
  });
}

function indexedControlSkeletons(hashPair, evidenceDigest) {
  const qualification =
    createDepth4PersistentIndexedNullifierQualificationKernel();
  const scratch = mkdtempSync(join(tmpdir(), "shieldkit-q04-depth4-"));
  const controlTraceByClass = new Map();
  let classes = 0;
  let setupTransitions = 0;
  let alphaRenamedSetupTransitions = 0;
  let targetTransitions = 0;
  let alphaRenamedTargetTransitions = 0;
  let alphaRenamingMismatches = 0;
  let nonlocalPermutationClasses = 0;
  let nonlocalPermutationSetupTransitions = 0;
  let nonlocalPermutationTargetTransitions = 0;
  let nonlocalPermutationMismatches = 0;
  let sqliteScheduleLanes = 0;
  let durableReopenChecks = 0;
  let duplicateAttempts = 0;
  let semanticDuplicateRejections = 0;
  let terminalCapacityPrecedenceRejections = 0;
  let recordedLeafCalls = 0;
  let recordedNodeCalls = 0;
  const classBreakdown = [];
  try {
    for (let normalCount = 0; normalCount <= 13; normalCount += 1) {
      let countClasses = 0;
      let countSetupTransitions = 0;
      let countTargetTransitions = 0;
      let countNonlocalPermutationClasses = 0;
      let countNonlocalPermutationSetupTransitions = 0;
      let countNonlocalPermutationTargetTransitions = 0;
      let countDuplicateAttempts = 0;
      let countSemanticDuplicateRejections = 0;
      let countTerminalCapacityPrecedenceRejections = 0;
      const physical = Array.from(
        { length: normalCount },
        (_, index) => index + 2,
      );
      for (const localCase of adjacentOrders(physical)) {
        const id = classId(
          normalCount,
          localCase.predecessorIndex,
          localCase.successorIndex,
        );
        if (controlTraceByClass.has(id)) {
          throw new Error(
            `depth-4 control skeleton ${id} is duplicated`,
          );
        }
        classes += 1;
        countClasses += 1;
        const primaryRun = runSqliteSchedule({
          scratch,
          id,
          lane: "primary",
          localCase,
          normalCount,
          variant: 0,
          hashPair,
          afterSchedule(store, schedule) {
            const after = store.state();
            try {
              store.insert({
                expectedCount: after.normalCount,
                expectedRoot: after.root,
                key: keyBytes(schedule.target),
              });
              throw new Error(
                "depth-4 duplicate retry was unexpectedly accepted",
              );
            } catch (error) {
              if (normalCount === Q04_DEPTH4_CAPACITY - 3) {
                if (!/normalCount must be an integer from 0 through 13/.test(
                  error.message,
                )) throw error;
                return "terminal-capacity-precedence";
              }
              if (!/already exists/.test(error.message)) throw error;
              return "semantic-duplicate";
            }
          },
        });
        const primary = primaryRun.schedule;
        sqliteScheduleLanes += 1;
        durableReopenChecks += 1;
        setupTransitions += primary.setupTransitions;
        countSetupTransitions += primary.setupTransitions;
        targetTransitions += 1;
        countTargetTransitions += 1;
        recordedLeafCalls += primary.recordedLeafCalls;
        recordedNodeCalls += primary.recordedNodeCalls;
        controlTraceByClass.set(id, primary.controlTrace.sha256);
        evidenceDigest
          .update(id, "ascii")
          .update(Buffer.from(primary.controlTrace.sha256, "hex"))
          .update(primary.mutation.root)
          .update(
            Buffer.from(
              primaryRun.persistence.afterReopen.logicalDigestSha256,
              "hex",
            ),
          );

        duplicateAttempts += 1;
        countDuplicateAttempts += 1;
        if (primaryRun.afterResult === "terminal-capacity-precedence") {
          terminalCapacityPrecedenceRejections += 1;
          countTerminalCapacityPrecedenceRejections += 1;
        } else if (primaryRun.afterResult === "semantic-duplicate") {
          semanticDuplicateRejections += 1;
          countSemanticDuplicateRejections += 1;
        } else {
          throw new Error("depth-4 duplicate rejection category differs");
        }

        const alternateRun = runSqliteSchedule({
          scratch,
          id,
          lane: "alpha",
          localCase,
          normalCount,
          variant: 1,
          hashPair,
        });
        const alternate = alternateRun.schedule;
        sqliteScheduleLanes += 1;
        durableReopenChecks += 1;
        alphaRenamedSetupTransitions += alternate.setupTransitions;
        alphaRenamedTargetTransitions += 1;
        recordedLeafCalls += alternate.recordedLeafCalls;
        recordedNodeCalls += alternate.recordedNodeCalls;
        evidenceDigest.update(
          Buffer.from(
            alternateRun.persistence.afterReopen.logicalDigestSha256,
            "hex",
          ),
        );
        if (
          alternate.controlTrace.sha256 !== primary.controlTrace.sha256
        ) {
          alphaRenamingMismatches += 1;
        }

        const permutedCase = nonlocalPermutation(localCase);
        if (permutedCase !== null) {
          const permutedRun = runSqliteSchedule({
            scratch,
            id,
            lane: "nonlocal",
            localCase: permutedCase,
            normalCount,
            variant: 0,
            hashPair,
          });
          const permuted = permutedRun.schedule;
          sqliteScheduleLanes += 1;
          durableReopenChecks += 1;
          nonlocalPermutationClasses += 1;
          countNonlocalPermutationClasses += 1;
          nonlocalPermutationSetupTransitions += permuted.setupTransitions;
          countNonlocalPermutationSetupTransitions +=
            permuted.setupTransitions;
          nonlocalPermutationTargetTransitions += 1;
          countNonlocalPermutationTargetTransitions += 1;
          recordedLeafCalls += permuted.recordedLeafCalls;
          recordedNodeCalls += permuted.recordedNodeCalls;
          evidenceDigest.update(
            Buffer.from(
              permutedRun.persistence.afterReopen.logicalDigestSha256,
              "hex",
            ),
          );
          if (
            permuted.controlTrace.sha256 !== primary.controlTrace.sha256
          ) {
            nonlocalPermutationMismatches += 1;
          }
        }
      }
      classBreakdown.push(freeze({
        normalCount,
        classes: countClasses,
        setupTransitions: countSetupTransitions,
        targetTransitions: countTargetTransitions,
        nonlocalPermutationClasses: countNonlocalPermutationClasses,
        nonlocalPermutationSetupTransitions:
          countNonlocalPermutationSetupTransitions,
        nonlocalPermutationTargetTransitions:
          countNonlocalPermutationTargetTransitions,
        duplicateAttempts: countDuplicateAttempts,
        semanticDuplicateRejections: countSemanticDuplicateRejections,
        terminalCapacityPrecedenceRejections:
          countTerminalCapacityPrecedenceRejections,
      }));
    }
  } finally {
    rmSync(scratch, { recursive: true, force: false });
  }

  let adapterCalls = 0;
  const fullAdapter = {
    hasNormalKey() {
      adapterCalls += 1;
      return false;
    },
    predecessorIndex() {
      adapterCalls += 1;
      return 0;
    },
    readLeaf() {
      adapterCalls += 1;
      return null;
    },
    readNode() {
      adapterCalls += 1;
      return null;
    },
  };
  let capacityRejected = false;
  try {
    qualification.derive({
      adapter: fullAdapter,
      expectedPreRoot: Buffer.alloc(32),
      key: keyBytes(FR - 2n),
      normalCount: 14,
    });
  } catch (error) {
    capacityRejected =
      /normalCount must be an integer from 0 through 13/.test(error.message);
  }
  const depth3Scratch = mkdtempSync(
    join(tmpdir(), "shieldkit-q04-depth4-depth3-"),
  );
  let depth3;
  try {
    depth3 = exhaustiveEmbeddedDepth3({
      controlTraceByClass,
      hashPair,
      evidenceDigest,
      scratch: depth3Scratch,
    });
  } finally {
    rmSync(depth3Scratch, { recursive: true, force: false });
  }
  recordedLeafCalls += depth3.recordedLeafCalls;
  recordedNodeCalls += depth3.recordedNodeCalls;
  if (
    classes !== 911 ||
    controlTraceByClass.size !== classes ||
    alphaRenamedSetupTransitions !== setupTransitions ||
    alphaRenamedTargetTransitions !== targetTransitions ||
    alphaRenamingMismatches !== 0 ||
    nonlocalPermutationClasses === 0 ||
    nonlocalPermutationTargetTransitions !== nonlocalPermutationClasses ||
    nonlocalPermutationMismatches !== 0 ||
    sqliteScheduleLanes !==
      (classes * 2) + nonlocalPermutationClasses ||
    durableReopenChecks !== sqliteScheduleLanes ||
    duplicateAttempts !== targetTransitions ||
    semanticDuplicateRejections + terminalCapacityPrecedenceRejections !==
      duplicateAttempts ||
    !capacityRejected ||
    adapterCalls !== 0
  ) {
    throw new Error(
      "depth-4 persistent control-skeleton coverage counters differ",
    );
  }
  return freeze({
    classes,
    controlSkeletonIds: controlTraceByClass.size,
    setupTransitions,
    alphaRenamedSetupTransitions,
    targetTransitions,
    alphaRenamedTargetTransitions,
    alphaRenamingMismatches,
    nonlocalPermutationClasses,
    nonlocalPermutationSetupTransitions,
    nonlocalPermutationTargetTransitions,
    nonlocalPermutationMismatches,
    sqliteScheduleLanes,
    durableReopenChecks,
    duplicateAttempts,
    semanticDuplicateRejections,
    terminalCapacityPrecedenceRejections,
    failClosedDuplicateAttempts: duplicateAttempts,
    capacityRejected,
    capacityRejectedBeforeAdapterReads: adapterCalls === 0,
    allocatedCountsCovered: 14,
    minimumKeyCovered: true,
    maximumKeyCovered: true,
    productionPersistentKernel: true,
    qualificationSqliteAdapter: true,
    recordedLeafCalls,
    recordedNodeCalls,
    depth3,
    controlTraceDigestSha256: traceHash(
      [...controlTraceByClass.entries()].sort(([left], [right]) =>
        left.localeCompare(right)
      ),
    ),
    classBreakdown: freeze(classBreakdown),
  });
}

export function runProductionDepth4StateSpace(value) {
  const input = exactKeys(
    value,
    ["parameterSourcePath"],
    "production depth-4 qualification",
  );
  const startedAt = process.hrtime.bigint();
  const oracle = createIndependentPoseidonOracle({
    parameterSourcePath: input.parameterSourcePath,
  });
  const hashPair = createHashPair(oracle);
  const evidenceDigest = createHash("sha256")
    .update(
      "ShieldKit/PoolActionV2Direct/Q04/depth4/evidence/v1\0",
      "ascii",
    );
  const occupancy = exhaustiveOccupancyHashes(hashPair, evidenceDigest);
  const indexed = indexedControlSkeletons(hashPair, evidenceDigest);
  const symbolicCertificate = buildDepth4SymbolicCertificate();
  const symbolicVerification =
    verifyDepth4SymbolicCertificate(symbolicCertificate);
  evidenceDigest.update(
    Buffer.from(symbolicCertificate.certificateSha256, "hex"),
  );
  const hashEvidence = hashPair.finish();
  if (hashEvidence.discrepancies !== 0) {
    throw new Error("depth-4 production/oracle hash discrepancies are nonzero");
  }
  return freeze({
    schema:
      "shieldkit-v2-direct/q04-depth4-production-state-space/v3",
    status: "pass",
    definition: freeze({
      depth: Q04_DEPTH4_DEPTH,
      capacity: Q04_DEPTH4_CAPACITY,
      authenticatedOccupancyDefinition:
        "all 2^16 empty/nonempty physical-leaf occupancy masks; " +
        "sentinel-shaped leaves at 0/1 and index-distinct normal-shaped " +
        "leaves at 2..15",
      indexedControlSkeletonDefinition:
        "one deterministic SQLite-backed control skeleton for every " +
        "allocated count 0..13 and physically distinct valid adjacent " +
        "predecessor/successor pair, with append at count+2; paired numeric " +
        "embeddings and every eligible nonlocal rank permutation close, " +
        "reopen, audit, and preserve the same normalized target trace",
      symbolicTemplateDefinition:
        "one exact shared-kernel symbolic template for each of 911 local " +
        "control skeletons; untouched allocated leaf hashes remain free " +
        "terms and predecessor/target/successor keys remain order-constrained " +
        "variables",
    }),
    claims: freeze({
      productionPoseidon: true,
      independentPoseidonImplementation: true,
      authenticatedOccupancyStateSpaceExhaustive: true,
      indexedControlSkeletonsEnumerated: true,
      indexedControlSkeletonsAreStateQuotient: false,
      pairedNumericEmbeddingsUseSharedSqlite: true,
      nonlocalRankPermutationsUseSharedSqlite: true,
      everySqliteLaneReopenedAndAudited: true,
      sharedKernelSymbolicTemplatesChecked: true,
      sharedKernelSymbolicFormalTheorem: false,
      externalProofCheckerRequired: true,
      fullCapacityBoundaryCovered: true,
      terminalCapacityPrecedenceCovered: true,
      exhaustiveOverBn254Field: false,
      enumeratesAllFourteenKeyHistories: false,
      enumeratesAllDepth4IndexedHistories: false,
      largerDepthClaim: false,
    }),
    occupancy,
    indexed,
    symbolic: freeze({
      certificate: symbolicCertificate,
      verification: symbolicVerification,
    }),
    hashes: hashEvidence,
    oracle: oracle.metadata,
    discrepancies: 0,
    elapsedMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
    evidenceDigestSha256: evidenceDigest.digest("hex"),
  });
}
