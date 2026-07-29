import { createHash } from "node:crypto";

import {
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
} from "../../action/v2/poseidon.mjs";

export const PERSISTENT_NULLIFIER_TREE_DEPTH = 32;
export const PERSISTENT_NULLIFIER_TREE_CAPACITY =
  2 ** PERSISTENT_NULLIFIER_TREE_DEPTH;
export const PERSISTENT_NULLIFIER_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const PERSISTENT_NULLIFIER_LEAF_TYPES = Object.freeze({
  minimum: 1,
  normal: 2,
  maximum: 3,
});

const MAX_U32 = 0xffff_ffff;
const ZERO = Buffer.alloc(32);

export class PersistentIndexedNullifierError extends Error {
  constructor(message, {
    cause = undefined,
    code = "PERSISTENT_NULLIFIER_INVALID",
  } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PersistentIndexedNullifierError";
    this.code = code;
  }
}

const fail = (message, code = "PERSISTENT_NULLIFIER_INVALID") => {
  throw new PersistentIndexedNullifierError(message, { code });
};
const freeze = (value) => Object.freeze(value);
const same = (left, right) =>
  Buffer.from(left).equals(Buffer.from(right));
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
const frBytes = (value, label) => {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    fail(`${label} must contain exactly 32 bytes`);
  }
  const copy = Buffer.from(value);
  if (BigInt(`0x${copy.toString("hex")}`) >= PERSISTENT_NULLIFIER_FR_MODULUS) {
    fail(`${label} must be a canonical BN254 Fr`);
  }
  return copy;
};
const frBigInt = (value, label) =>
  BigInt(`0x${frBytes(value, label).toString("hex")}`);
const encodedFr = (value, label) => {
  if (
    typeof value !== "bigint" ||
    value < 0n ||
    value >= PERSISTENT_NULLIFIER_FR_MODULUS
  ) fail(`${label} must be a canonical BN254 Fr bigint`);
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
};
const traceValue = (value) => {
  if (typeof value === "bigint") return value.toString(10);
  if (value instanceof Uint8Array) return Buffer.from(value).toString("hex");
  if (Array.isArray(value)) return value.map(traceValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, traceValue(entry)]),
    );
  }
  return value;
};
const traceDigest = (domain, value) =>
  createHash("sha256")
    .update(domain, "ascii")
    .update(JSON.stringify(value), "utf8")
    .digest("hex");

function createQualificationTraceRecorder() {
  const adapterCalls = [];
  const guards = [];
  const nodeAddresses = [];
  const symbolicHashes = [];
  let sequence = 0;
  const entry = (collection, value) => {
    const recorded = freeze({
      sequence,
      ...traceValue(value),
    });
    sequence += 1;
    collection.push(recorded);
    return recorded;
  };
  return freeze({
    adapter({ phase, method, arguments: args, result }) {
      return entry(adapterCalls, {
        phase,
        method,
        arguments: args,
        result,
      });
    },
    guard({ phase, code, passed, details = {} }) {
      return entry(guards, {
        phase,
        code,
        passed,
        details,
      });
    },
    address(value) {
      return entry(nodeAddresses, value);
    },
    hash({ phase, kind, symbolicInputs, concreteInputs, concreteOutput }) {
      const outputSymbol = `h${symbolicHashes.length}`;
      entry(symbolicHashes, {
        phase,
        kind,
        symbolicInputs,
        concreteInputs,
        outputSymbol,
        concreteOutput,
      });
      return outputSymbol;
    },
    finish(branchFacts, {
      outcome = "accept",
      rejection = null,
    } = {}) {
      const transcript = {
        outcome,
        rejection: traceValue(rejection),
        adapterCalls,
        guards,
        nodeAddresses,
        symbolicHashes,
        branchFacts: traceValue(branchFacts),
      };
      return freeze({
        schema:
          "shieldkit-v2-direct/persistent-nullifier-kernel-trace/v2",
        outcome,
        rejection: traceValue(rejection),
        adapterCalls: freeze(adapterCalls),
        guards: freeze(guards),
        nodeAddresses: freeze(nodeAddresses),
        symbolicHashes: freeze(symbolicHashes),
        branchFacts: freeze(traceValue(branchFacts)),
        adapterCallsSha256: traceDigest(
          "ShieldKit/Q04/adapter-calls/v1\0",
          adapterCalls,
        ),
        guardsSha256: traceDigest(
          "ShieldKit/Q04/guards/v1\0",
          guards,
        ),
        nodeAddressesSha256: traceDigest(
          "ShieldKit/Q04/node-addresses/v1\0",
          nodeAddresses,
        ),
        symbolicHashesSha256: traceDigest(
          "ShieldKit/Q04/symbolic-hashes/v1\0",
          symbolicHashes,
        ),
        transcriptSha256: traceDigest(
          "ShieldKit/Q04/kernel-trace/v1\0",
          transcript,
        ),
      });
    },
  });
}

function callAdapter(trace, phase, method, args, operation) {
  let result;
  try {
    result = operation();
  } catch (cause) {
    trace?.adapter({
      phase,
      method,
      arguments: args,
      result: {
        threw: true,
        name: cause instanceof Error ? cause.name : typeof cause,
        message: cause instanceof Error ? cause.message : String(cause),
      },
    });
    throw new PersistentIndexedNullifierError(
      `persistent indexed-nullifier adapter.${method} threw`,
      {
        cause,
        code: `PERSISTENT_ADAPTER_${
          method.replace(/([a-z])([A-Z])/gu, "$1_$2").toUpperCase()
        }_THREW`,
      },
    );
  }
  trace?.adapter({
    phase,
    method,
    arguments: args,
    result,
  });
  return result;
}

function requireGuard(trace, {
  code,
  details = {},
  message,
  passed,
  phase,
}) {
  trace?.guard({ phase, code, passed, details });
  if (!passed) fail(message, code);
}

function inferredFailureCode(error) {
  if (
    error instanceof PersistentIndexedNullifierError &&
    error.code !== "PERSISTENT_NULLIFIER_INVALID"
  ) return error.code;
  const message = error instanceof Error ? error.message : String(error);
  for (const [pattern, code] of [
    [/adapter.*missing or unknown properties/u, "PERSISTENT_ADAPTER_SHAPE"],
    [/adapter\..*must be a function/u, "PERSISTENT_ADAPTER_METHOD"],
    [/insertion.*missing or unknown properties/u, "PERSISTENT_INPUT_SHAPE"],
    [/normalCount must be an integer/u, "PERSISTENT_COUNT_OR_CAPACITY"],
    [/key must contain exactly 32 bytes/u, "PERSISTENT_KEY_LENGTH"],
    [/key must be a canonical BN254 Fr/u, "PERSISTENT_KEY_NONCANONICAL"],
    [/expectedPreRoot must contain exactly 32 bytes/u,
      "PERSISTENT_EXPECTED_ROOT_LENGTH"],
    [/expectedPreRoot must be a canonical BN254 Fr/u,
      "PERSISTENT_EXPECTED_ROOT_NONCANONICAL"],
    [/predecessor index must be an integer/u,
      "PERSISTENT_PREDECESSOR_INDEX"],
    [/stored indexed-nullifier predecessor/u,
      "PERSISTENT_PREDECESSOR_LEAF_INVALID"],
    [/stored nullifier (?:node|root)/u, "PERSISTENT_NODE_INVALID"],
    [/path has the wrong depth/u, "PERSISTENT_PATH_DEPTH"],
    [/operation counts differ/u, "PERSISTENT_OPERATION_COUNT"],
  ]) {
    if (pattern.test(message)) return code;
  }
  return "PERSISTENT_NULLIFIER_INVALID";
}

export function persistentNullifierLeafHash(value) {
  const input = exactKeys(value, [
    "physicalIndex",
    "leafType",
    "key",
    "successorIndex",
    "successorKey",
  ], "persistent nullifier leaf hash");
  const leafType = integer(
    input.leafType,
    1,
    3,
    "persistent nullifier leaf hash.leafType",
  );
  const physicalIndex = integer(
    input.physicalIndex,
    0,
    MAX_U32,
    "persistent nullifier leaf hash.physicalIndex",
  );
  const key = frBytes(input.key, "persistent nullifier leaf hash.key");
  const successorIndex = integer(
    input.successorIndex,
    0,
    MAX_U32,
    "persistent nullifier leaf hash.successorIndex",
  );
  const successorKey = frBytes(
    input.successorKey,
    "persistent nullifier leaf hash.successorKey",
  );
  return encodedFr(
    hashIndexedNullifierLeaf([
      BigInt(leafType),
      BigInt(physicalIndex),
      frBigInt(key, "persistent nullifier leaf key"),
      BigInt(successorIndex),
      frBigInt(successorKey, "persistent nullifier successor key"),
    ]),
    "profile-pinned indexed-nullifier leaf hash",
  );
}

const concreteNodeHash = (left, right) =>
  encodedFr(
    hashIndexedNullifierNode(
      frBigInt(left, "left persistent nullifier node"),
      frBigInt(right, "right persistent nullifier node"),
    ),
    "persistent nullifier parent",
  );

const CONCRETE_SEMANTIC_ALGEBRA = freeze({
  name: "bn254-fr-buffer-poseidon-v1",
  zero: ZERO,
  field(value, label) {
    return frBytes(value, label);
  },
  fromWitnessField(value, label) {
    return encodedFr(value, label);
  },
  witnessField(value, label) {
    return frBigInt(value, label);
  },
  witnessHex(value, label) {
    return frBytes(value, label).toString("hex");
  },
  equal(left, right) {
    return same(left, right);
  },
  compare(left, right, leftLabel, rightLabel) {
    const leftValue = frBigInt(left, leftLabel);
    const rightValue = frBigInt(right, rightLabel);
    return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
  },
  hashLeaf(value) {
    return persistentNullifierLeafHash(value);
  },
  hashEmptyLeaf() {
    return encodedFr(
      hashIndexedNullifierLeaf([0n, 0n, 0n, 0n, 0n]),
      "empty indexed-nullifier leaf",
    );
  },
  hashNode(left, right) {
    return concreteNodeHash(left, right);
  },
  isFrMinusOne(value, label) {
    return frBigInt(value, label) ===
      PERSISTENT_NULLIFIER_FR_MODULUS - 1n;
  },
  copy(value, label) {
    return frBytes(value, label);
  },
});

function validateSemanticAlgebra(value) {
  const algebra = exactKeys(value, [
    "name",
    "zero",
    "field",
    "fromWitnessField",
    "witnessField",
    "witnessHex",
    "equal",
    "compare",
    "hashLeaf",
    "hashEmptyLeaf",
    "hashNode",
    "isFrMinusOne",
    "copy",
  ], "persistent indexed-nullifier semantic algebra");
  if (typeof algebra.name !== "string" || algebra.name.length === 0) {
    fail("persistent indexed-nullifier semantic algebra.name is invalid");
  }
  for (const name of [
    "field",
    "fromWitnessField",
    "witnessField",
    "witnessHex",
    "equal",
    "compare",
    "hashLeaf",
    "hashEmptyLeaf",
    "hashNode",
    "isFrMinusOne",
    "copy",
  ]) {
    if (typeof algebra[name] !== "function") {
      fail(
        `persistent indexed-nullifier semantic algebra.${name} ` +
          "must be a function",
      );
    }
  }
  algebra.field(algebra.zero, "persistent semantic algebra zero");
  return algebra;
}

function validateLeaf(
  kernel,
  value,
  label,
  { hashAlreadyComputed = false, recordHash = null } = {},
) {
  const input = exactKeys(value, [
    "physicalIndex",
    "leafType",
    "leafHash",
    "key",
    "successorIndex",
    "successorKey",
  ], label);
  const physicalIndex = integer(
    input.physicalIndex,
    0,
    kernel.maximumPhysicalIndex,
    `${label}.physicalIndex`,
  );
  const leafType = integer(input.leafType, 1, 3, `${label}.leafType`);
  const leafHash = kernel.algebra.field(
    input.leafHash,
    `${label}.leafHash`,
  );
  const key = kernel.algebra.field(input.key, `${label}.key`);
  const successorIndex = integer(
    input.successorIndex,
    0,
    kernel.maximumPhysicalIndex,
    `${label}.successorIndex`,
  );
  const successorKey = kernel.algebra.field(
    input.successorKey,
    `${label}.successorKey`,
  );
  if (
    (
      leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.minimum &&
      (
        physicalIndex !== 0 ||
        !kernel.algebra.equal(key, kernel.algebra.zero) ||
        successorIndex === 0 ||
        (
          successorIndex === 1 &&
          !kernel.algebra.equal(successorKey, kernel.algebra.zero)
        )
      )
    ) ||
    (
      leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.maximum &&
      (
        physicalIndex !== 1 ||
        !kernel.algebra.equal(key, kernel.algebra.zero) ||
        successorIndex !== 1 ||
        !kernel.algebra.equal(successorKey, kernel.algebra.zero)
      )
    ) ||
    (
      leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.normal &&
      (
        physicalIndex < 2 ||
        successorIndex === 0 ||
        successorIndex === physicalIndex ||
        (
          successorIndex === 1 &&
          !kernel.algebra.equal(successorKey, kernel.algebra.zero)
        )
      )
    )
  ) fail(`${label} violates indexed-nullifier sentinel encoding`);
  if (
    leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.normal &&
    successorIndex >= 2 &&
    kernel.algebra.compare(
      successorKey,
      key,
      `${label}.successorKey`,
      `${label}.key`,
    ) <= 0
  ) fail(`${label} normal successor must have a strictly greater key`);
  if (!hashAlreadyComputed) {
    const expectedHash = kernel.algebra.hashLeaf({
      physicalIndex,
      leafType,
      key,
      successorIndex,
      successorKey,
    });
    recordHash?.({
      physicalIndex,
      leafType,
      key,
      successorIndex,
      successorKey,
      leafHash: expectedHash,
    });
    if (!kernel.algebra.equal(leafHash, expectedHash)) {
      fail(`${label}.leafHash differs from profile-pinned Poseidon`);
    }
  }
  return freeze({
    physicalIndex,
    leafType,
    leafHash,
    key,
    successorIndex,
    successorKey,
  });
}

function createDefaults(treeDepth, algebra) {
  const emptyLeaf = algebra.hashEmptyLeaf();
  const defaults = [emptyLeaf];
  for (
    let level = 0;
    level < treeDepth;
    level += 1
  ) {
    defaults.push(algebra.hashNode(defaults[level], defaults[level]));
  }
  return freeze(defaults);
}

function createKernel(treeDepth, {
  algebra = CONCRETE_SEMANTIC_ALGEBRA,
  qualificationTrace = false,
} = {}) {
  const depth = integer(
    treeDepth,
    2,
    PERSISTENT_NULLIFIER_TREE_DEPTH,
    "persistent indexed-nullifier kernel depth",
  );
  const capacity = 2 ** depth;
  const validatedAlgebra = validateSemanticAlgebra(algebra);
  return freeze({
    depth,
    capacity,
    maximumPhysicalIndex: capacity - 1,
    maximumNormalCount: capacity - 2,
    maximumPreInsertionNormalCount: capacity - 3,
    defaults: createDefaults(depth, validatedAlgebra),
    algebra: validatedAlgebra,
    qualificationTrace,
    validMutations: new WeakSet(),
  });
}

const PRODUCTION_KERNEL = createKernel(PERSISTENT_NULLIFIER_TREE_DEPTH);
const DEFAULTS = PRODUCTION_KERNEL.defaults;

export function persistentNullifierDefaults() {
  return freeze(DEFAULTS.map((value, index) =>
    PRODUCTION_KERNEL.algebra.copy(
      value,
      `persistent nullifier default ${index}`,
    )
  ));
}

function leafHashWithTrace(value, {
  kernel,
  trace,
  phase,
  symbolicInputs,
}) {
  const nodeHash = kernel.algebra.hashLeaf(value);
  const symbol = trace?.hash({
    phase,
    kind: "leaf",
    symbolicInputs,
    concreteInputs: {
      leafType: value.leafType,
      physicalIndex: value.physicalIndex,
      key: value.key,
      successorIndex: value.successorIndex,
      successorKey: value.successorKey,
    },
    concreteOutput: nodeHash,
  }) ?? null;
  return freeze({ nodeHash, symbol });
}

function nodeHashWithTrace({
  kernel,
  left,
  right,
  trace,
  phase,
  leftSymbol,
  rightSymbol,
  outputDepth,
  outputIndex,
  cursor,
  side,
}) {
  const parent = kernel.algebra.hashNode(left, right);
  const symbol = trace?.hash({
    phase,
    kind: "node",
    symbolicInputs: [leftSymbol, rightSymbol],
    concreteInputs: [left, right],
    concreteOutput: parent,
  }) ?? null;
  trace?.address({
    phase,
    operation: "hash-parent",
    depth: outputDepth,
    nodeIndex: outputIndex,
    cursor,
    side,
    source: "computed",
  });
  return freeze({ nodeHash: parent, symbol });
}

function assertNodeAddress(kernel, depth, nodeIndex, label) {
  integer(depth, 0, kernel.depth, `${label}.depth`);
  integer(
    nodeIndex,
    0,
    2 ** (kernel.depth - depth) - 1,
    `${label}.nodeIndex`,
  );
}

function readStoredNode(
  kernel,
  adapter,
  depth,
  nodeIndex,
  overrides,
  symbolOverrides,
  metrics,
  trace,
  phase,
  cursor,
  side,
) {
  assertNodeAddress(kernel, depth, nodeIndex, "persistent node read");
  metrics.logicalPathSiblingLookups += 1;
  const overridden = overrides?.get(`${depth}:${nodeIndex}`);
  if (overridden !== undefined) {
    metrics.pathOverrideHits += 1;
    trace?.address({
      phase,
      operation: "resolve-override",
      depth,
      nodeIndex,
      cursor,
      side,
      source: "override",
    });
    return freeze({
      nodeHash: overridden.nodeHash,
      symbol: symbolOverrides?.get(`${depth}:${nodeIndex}`) ??
        `override:${depth}:${nodeIndex}`,
    });
  }
  metrics.nodeReads += 1;
  metrics.pathAdapterNodeReads += 1;
  const observed = callAdapter(
    trace,
    phase,
    "readNode",
    { depth, nodeIndex },
    () => adapter.readNode(depth, nodeIndex),
  );
  trace?.address({
    phase,
    operation: "read",
    depth,
    nodeIndex,
    cursor,
    side,
    source: "adapter",
  });
  if (observed === null) {
    trace?.address({
      phase,
      operation: "resolve-default",
      depth,
      nodeIndex,
      cursor,
      side,
      source: "default",
    });
    return freeze({
      nodeHash: kernel.defaults[depth],
      symbol: `default:${depth}`,
    });
  }
  return freeze({
    nodeHash: kernel.algebra.field(
      observed,
      `stored nullifier node ${depth}:${nodeIndex}`,
    ),
    symbol: `stored:${depth}:${nodeIndex}`,
  });
}

function pathFromStore({
  kernel,
  adapter,
  index,
  leafHash,
  leafSymbol = null,
  overrides = null,
  symbolOverrides = null,
  record = false,
  metrics,
  trace = null,
  phase,
}) {
  let cursor = index;
  let node = kernel.algebra.field(leafHash, "path leaf");
  let nodeSymbol = leafSymbol;
  const siblings = [];
  const siblingSymbols = [];
  if (record) {
    overrides.set(`0:${cursor}`, freeze({
      depth: 0,
      nodeIndex: cursor,
      nodeHash: node,
    }));
    symbolOverrides?.set(`0:${cursor}`, nodeSymbol);
    trace?.address({
      phase,
      operation: "record-write",
      depth: 0,
      nodeIndex: cursor,
      cursor,
      side: (cursor & 1) === 0 ? "left" : "right",
      source: "computed",
    });
  }
  for (
    let depth = 0;
    depth < kernel.depth;
    depth += 1
  ) {
    const side = (cursor & 1) === 0 ? "left" : "right";
    const siblingSide = side === "left" ? "right" : "left";
    const sibling = readStoredNode(
      kernel,
      adapter,
      depth,
      cursor ^ 1,
      overrides,
      symbolOverrides,
      metrics,
      trace,
      phase,
      cursor,
      siblingSide,
    );
    siblings.push(
      kernel.algebra.witnessField(
        sibling.nodeHash,
        `path sibling ${depth}`,
      ),
    );
    siblingSymbols.push(sibling.symbol);
    const outputIndex = Math.floor(cursor / 2);
    const parent = side === "left"
      ? nodeHashWithTrace({
        kernel,
        left: node,
        right: sibling.nodeHash,
        trace,
        phase,
        leftSymbol: nodeSymbol,
        rightSymbol: sibling.symbol,
        outputDepth: depth + 1,
        outputIndex,
        cursor,
        side,
      })
      : nodeHashWithTrace({
        kernel,
        left: sibling.nodeHash,
        right: node,
        trace,
        phase,
        leftSymbol: sibling.symbol,
        rightSymbol: nodeSymbol,
        outputDepth: depth + 1,
        outputIndex,
        cursor,
        side,
      });
    node = parent.nodeHash;
    nodeSymbol = parent.symbol;
    metrics.nodeHashCalls += 1;
    cursor = outputIndex;
    if (record) {
      overrides.set(`${depth + 1}:${cursor}`, freeze({
        depth: depth + 1,
        nodeIndex: cursor,
        nodeHash: node,
      }));
      symbolOverrides?.set(`${depth + 1}:${cursor}`, nodeSymbol);
      trace?.address({
        phase,
        operation: "record-write",
        depth: depth + 1,
        nodeIndex: cursor,
        cursor,
        side: (cursor & 1) === 0 ? "left" : "right",
        source: "computed",
      });
    }
  }
  return freeze({
    root: node,
    rootSymbol: nodeSymbol,
    siblings: freeze(siblings),
    siblingSymbols: freeze(siblingSymbols),
  });
}

function pathFromSiblings({
  kernel,
  index,
  leafHash,
  leafSymbol = null,
  siblings,
  siblingSymbols = null,
  overrides = null,
  symbolOverrides = null,
  record = false,
  metrics,
  trace = null,
  phase,
}) {
  if (
    !Array.isArray(siblings) ||
    siblings.length !== kernel.depth
  ) fail("persistent nullifier path has the wrong depth");
  if (
    trace !== null &&
    (
      !Array.isArray(siblingSymbols) ||
      siblingSymbols.length !== kernel.depth
    )
  ) fail("persistent nullifier symbolic path has the wrong depth");
  let cursor = index;
  let node = kernel.algebra.field(leafHash, "path leaf");
  let nodeSymbol = leafSymbol;
  if (record) {
    overrides.set(`0:${cursor}`, freeze({
      depth: 0,
      nodeIndex: cursor,
      nodeHash: node,
    }));
    symbolOverrides?.set(`0:${cursor}`, nodeSymbol);
    trace?.address({
      phase,
      operation: "record-write",
      depth: 0,
      nodeIndex: cursor,
      cursor,
      side: (cursor & 1) === 0 ? "left" : "right",
      source: "computed",
    });
  }
  for (
    let depth = 0;
    depth < kernel.depth;
    depth += 1
  ) {
    const sibling = kernel.algebra.fromWitnessField(
      siblings[depth],
      `persistent nullifier sibling ${depth}`,
    );
    const siblingSymbol = siblingSymbols?.[depth] ?? null;
    const side = (cursor & 1) === 0 ? "left" : "right";
    const outputIndex = Math.floor(cursor / 2);
    const parent = side === "left"
      ? nodeHashWithTrace({
        kernel,
        left: node,
        right: sibling,
        trace,
        phase,
        leftSymbol: nodeSymbol,
        rightSymbol: siblingSymbol,
        outputDepth: depth + 1,
        outputIndex,
        cursor,
        side,
      })
      : nodeHashWithTrace({
        kernel,
        left: sibling,
        right: node,
        trace,
        phase,
        leftSymbol: siblingSymbol,
        rightSymbol: nodeSymbol,
        outputDepth: depth + 1,
        outputIndex,
        cursor,
        side,
      });
    node = parent.nodeHash;
    nodeSymbol = parent.symbol;
    metrics.nodeHashCalls += 1;
    cursor = outputIndex;
    if (record) {
      overrides.set(`${depth + 1}:${cursor}`, freeze({
        depth: depth + 1,
        nodeIndex: cursor,
        nodeHash: node,
      }));
      symbolOverrides?.set(`${depth + 1}:${cursor}`, nodeSymbol);
      trace?.address({
        phase,
        operation: "record-write",
        depth: depth + 1,
        nodeIndex: cursor,
        cursor,
        side: (cursor & 1) === 0 ? "left" : "right",
        source: "computed",
      });
    }
  }
  return freeze({ root: node, rootSymbol: nodeSymbol });
}

function witnessLeaf(kernel, leaf) {
  const type = leaf.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.minimum
    ? "min"
    : leaf.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.normal
    ? "normal"
    : leaf.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.maximum
    ? "max"
    : fail("persistent nullifier leaf type is unsupported");
  return freeze({
    type,
    index: leaf.physicalIndex,
    key: kernel.algebra.witnessHex(
      leaf.key,
      "persistent witness leaf key",
    ),
    successorIndex: leaf.successorIndex,
    successorKey: kernel.algebra.witnessHex(
      leaf.successorKey,
      "persistent witness leaf successor key",
    ),
  });
}

function runPersistentIndexedNullifierSemanticKernel(kernel, value, trace) {
  const input = exactKeys(value, [
    "adapter",
    "expectedPreRoot",
    "key",
    "normalCount",
  ], "persistent indexed-nullifier insertion");
  const adapter = exactKeys(input.adapter, [
    "hasNormalKey",
    "predecessorIndex",
    "readLeaf",
    "readNode",
  ], "persistent indexed-nullifier adapter");
  for (const name of Object.keys(adapter)) {
    if (typeof adapter[name] !== "function") {
      fail(`persistent indexed-nullifier adapter.${name} must be a function`);
    }
  }
  const normalCount = integer(
    input.normalCount,
    0,
    kernel.maximumPreInsertionNormalCount,
    "persistent indexed-nullifier normalCount",
  );
  const key = kernel.algebra.field(
    input.key,
    "persistent indexed-nullifier key",
  );
  const expectedPreRoot = kernel.algebra.field(
    input.expectedPreRoot,
    "persistent indexed-nullifier expectedPreRoot",
  );
  const metrics = {
    leafHashCalls: 0,
    predecessorValidationLeafHashCalls: 0,
    mutationLeafHashCalls: 0,
    nodeHashCalls: 0,
    predecessorMembershipNodeHashCalls: kernel.depth,
    predecessorUpdateNodeHashCalls: kernel.depth,
    appendNonMembershipNodeHashCalls: kernel.depth,
    appendUpdateNodeHashCalls: kernel.depth,
    nodeReads: 0,
    rootAdapterNodeReads: 0,
    pathAdapterNodeReads: 0,
    logicalPathSiblingLookups: 0,
    pathOverrideHits: 0,
    leafReads: 0,
    orderLookups: 0,
    treeDepth: kernel.depth,
  };
  assertNodeAddress(kernel, kernel.depth, 0, "persistent root read");
  const storedRoot = callAdapter(
    trace,
    "root-read",
    "readNode",
    { depth: kernel.depth, nodeIndex: 0 },
    () => adapter.readNode(kernel.depth, 0),
  );
  metrics.nodeReads += 1;
  metrics.rootAdapterNodeReads += 1;
  trace?.address({
    phase: "root-read",
    operation: "read",
    depth: kernel.depth,
    nodeIndex: 0,
    cursor: 0,
    side: "left",
    source: "adapter",
  });
  const storedRootMatches = storedRoot !== null &&
    kernel.algebra.equal(
      kernel.algebra.field(storedRoot, "stored nullifier root"),
      expectedPreRoot,
    );
  requireGuard(trace, {
    phase: "root-read",
    code: "PERSISTENT_ROOT_MISMATCH",
    passed: storedRootMatches,
    message: "stored root differs from expected indexed-nullifier pre-root",
    details: { storedRootPresent: storedRoot !== null },
  });
  const duplicate = callAdapter(
    trace,
    "duplicate-check",
    "hasNormalKey",
    { key },
    () => adapter.hasNormalKey(key),
  );
  metrics.orderLookups += 1;
  requireGuard(trace, {
    phase: "duplicate-check",
    code: "PERSISTENT_DUPLICATE_RESULT_TYPE",
    passed: typeof duplicate === "boolean",
    message:
      "persistent indexed-nullifier adapter.hasNormalKey must return boolean",
    details: { resultType: typeof duplicate },
  });
  requireGuard(trace, {
    phase: "duplicate-check",
    code: "PERSISTENT_DUPLICATE",
    passed: duplicate === false,
    message: "persistent indexed nullifier already exists",
  });
  const observedPredecessorIndex = callAdapter(
    trace,
    "predecessor-search",
    "predecessorIndex",
    { key },
    () => adapter.predecessorIndex(key),
  );
  metrics.orderLookups += 1;
  const predecessorIndex = integer(
    observedPredecessorIndex,
    0,
    normalCount + 1,
    "persistent indexed-nullifier predecessor index",
  );
  const predecessorRaw = callAdapter(
    trace,
    "predecessor-leaf-read",
    "readLeaf",
    { physicalIndex: predecessorIndex },
    () => adapter.readLeaf(predecessorIndex),
  );
  metrics.leafReads += 1;
  let predecessorValidationSymbol = null;
  const predecessor = validateLeaf(
    kernel,
    predecessorRaw,
    "stored indexed-nullifier predecessor",
    {
      recordHash: trace === null
        ? null
        : (hashed) => {
          predecessorValidationSymbol = trace.hash({
            phase: "predecessor-validation",
            kind: "leaf",
            symbolicInputs: [
              "predecessor.leafType",
              "predecessor.physicalIndex",
              "predecessor.key",
              "predecessor.successorIndex",
              "predecessor.successorKey",
            ],
            concreteInputs: {
              leafType: hashed.leafType,
              physicalIndex: hashed.physicalIndex,
              key: hashed.key,
              successorIndex: hashed.successorIndex,
              successorKey: hashed.successorKey,
            },
            concreteOutput: hashed.leafHash,
          });
        },
    },
  );
  metrics.leafHashCalls += 1;
  metrics.predecessorValidationLeafHashCalls += 1;
  const predecessorBracketed = !(
    predecessor.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.maximum ||
    (
      predecessor.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.normal &&
      kernel.algebra.compare(
        predecessor.key,
        key,
        "predecessor key",
        "new key",
      ) >= 0
    ) ||
    (
      predecessor.successorIndex >= 2 &&
      kernel.algebra.compare(
        predecessor.successorKey,
        key,
        "predecessor successor key",
        "new key",
      ) <= 0
    )
  );
  requireGuard(trace, {
    phase: "predecessor-bracket",
    code: "PERSISTENT_PREDECESSOR_NOT_BRACKETING",
    passed: predecessorBracketed,
    message:
      "persistent indexed-nullifier predecessor does not bracket the key",
    details: {
      predecessorIndex: predecessor.physicalIndex,
      successorIndex: predecessor.successorIndex,
    },
  });

  const appendIndex = normalCount + 2;
  const appendLeaf = callAdapter(
    trace,
    "append-leaf-read",
    "readLeaf",
    { physicalIndex: appendIndex },
    () => adapter.readLeaf(appendIndex),
  );
  metrics.leafReads += 1;
  requireGuard(trace, {
    phase: "append-leaf-read",
    code: "PERSISTENT_APPEND_OCCUPIED",
    passed: appendLeaf === null,
    message:
      "persistent indexed-nullifier append position is already occupied",
    details: { appendIndex },
  });
  const prePath = pathFromStore({
    kernel,
    adapter,
    index: predecessor.physicalIndex,
    leafHash: predecessor.leafHash,
    leafSymbol: predecessorValidationSymbol,
    metrics,
    trace,
    phase: "predecessor-membership",
  });
  requireGuard(trace, {
    phase: "predecessor-membership",
    code: "PERSISTENT_PREDECESSOR_MEMBERSHIP_ROOT",
    passed: kernel.algebra.equal(prePath.root, expectedPreRoot),
    message:
      "stored predecessor membership path does not prove the pre-root",
  });

  const predecessorUpdateBase = {
    physicalIndex: predecessor.physicalIndex,
    leafType: predecessor.leafType,
    key: predecessor.key,
    successorIndex: appendIndex,
    successorKey: key,
  };
  const predecessorUpdateHashed = leafHashWithTrace(
    predecessorUpdateBase,
    {
      kernel,
      trace,
      phase: "predecessor-update",
      symbolicInputs: [
        "predecessor.leafType",
        "predecessor.physicalIndex",
        "predecessor.key",
        "appendIndex",
        "newKey",
      ],
    },
  );
  const predecessorUpdate = validateLeaf(kernel, {
    ...predecessorUpdateBase,
    leafHash: predecessorUpdateHashed.nodeHash,
  }, "updated indexed-nullifier predecessor", {
    hashAlreadyComputed: true,
  });
  metrics.leafHashCalls += 1;
  metrics.mutationLeafHashCalls += 1;

  const appendedBase = {
    physicalIndex: appendIndex,
    leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.normal,
    key,
    successorIndex: predecessor.successorIndex,
    successorKey: predecessor.successorKey,
  };
  const appendedHashed = leafHashWithTrace(appendedBase, {
    kernel,
    trace,
    phase: "append",
    symbolicInputs: [
      "normalLeafType",
      "appendIndex",
      "newKey",
      "predecessor.successorIndex",
      "predecessor.successorKey",
    ],
  });
  const appended = validateLeaf(kernel, {
    ...appendedBase,
    leafHash: appendedHashed.nodeHash,
  }, "appended indexed-nullifier leaf", {
    hashAlreadyComputed: true,
  });
  metrics.leafHashCalls += 1;
  metrics.mutationLeafHashCalls += 1;

  const overrides = new Map();
  const symbolOverrides = trace === null ? null : new Map();
  const intermediatePath = pathFromSiblings({
    kernel,
    index: predecessorUpdate.physicalIndex,
    leafHash: predecessorUpdate.leafHash,
    leafSymbol: predecessorUpdateHashed.symbol,
    siblings: prePath.siblings,
    siblingSymbols: prePath.siblingSymbols,
    overrides,
    symbolOverrides,
    record: true,
    metrics,
    trace,
    phase: "predecessor-update-path",
  });
  const intermediateRoot = intermediatePath.root;
  const appendEmptyPath = pathFromStore({
    kernel,
    adapter,
    index: appendIndex,
    leafHash: kernel.defaults[0],
    leafSymbol: "default:0",
    overrides,
    symbolOverrides,
    metrics,
    trace,
    phase: "append-empty-membership",
  });
  requireGuard(trace, {
    phase: "append-empty-membership",
    code: "PERSISTENT_APPEND_NONMEMBERSHIP_ROOT",
    passed: kernel.algebra.equal(
      appendEmptyPath.root,
      intermediateRoot,
    ),
    message:
      "append non-membership path does not prove the intermediate root",
  });
  const postPath = pathFromSiblings({
    kernel,
    index: appendIndex,
    leafHash: appended.leafHash,
    leafSymbol: appendedHashed.symbol,
    siblings: appendEmptyPath.siblings,
    siblingSymbols: appendEmptyPath.siblingSymbols,
    overrides,
    symbolOverrides,
    record: true,
    metrics,
    trace,
    phase: "append-update-path",
  });
  const postRoot = postPath.root;
  const nodes = [...overrides.values()].sort((left, right) =>
    left.depth - right.depth || left.nodeIndex - right.nodeIndex
  );
  const operationCountsExact = (
    metrics.leafHashCalls !== 3 ||
    metrics.predecessorValidationLeafHashCalls !== 1 ||
    metrics.mutationLeafHashCalls !== 2 ||
    metrics.nodeHashCalls !== kernel.depth * 4 ||
    metrics.logicalPathSiblingLookups !== kernel.depth * 2 ||
    metrics.pathOverrideHits !== 1 ||
    metrics.pathAdapterNodeReads !== kernel.depth * 2 - 1 ||
    metrics.nodeReads !==
      metrics.rootAdapterNodeReads + metrics.pathAdapterNodeReads ||
    metrics.leafReads !== 2 ||
    metrics.orderLookups !== 2
  ) === false;
  requireGuard(trace, {
    phase: "operation-counts",
    code: "PERSISTENT_OPERATION_COUNT",
    passed: operationCountsExact,
    message: "persistent indexed-nullifier operation counts differ",
    details: metrics,
  });
  const qualificationTrace = trace?.finish({
    treeDepth: kernel.depth,
    normalCount,
    appendIndex,
    predecessorIndex,
    predecessorPhysicalIndex: predecessor.physicalIndex,
    predecessorLeafType: predecessor.leafType,
    predecessorIsMinimum:
      predecessor.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.minimum,
    predecessorSuccessorIndex: predecessor.successorIndex,
    predecessorSuccessorIsMaximum: predecessor.successorIndex === 1,
    predecessorSuccessorIsNormal: predecessor.successorIndex >= 2,
    keyIsZero: kernel.algebra.equal(key, kernel.algebra.zero),
    keyIsFrMinusOne: kernel.algebra.isFrMinusOne(
      key,
      "qualification trace key",
    ),
    rootMatched: true,
    duplicateRejected: false,
    predecessorBracketed: true,
    appendPositionEmpty: true,
    predecessorMembershipRootSymbol: prePath.rootSymbol,
    intermediateRootSymbol: intermediatePath.rootSymbol,
    appendEmptyRootSymbol: appendEmptyPath.rootSymbol,
    postRootSymbol: postPath.rootSymbol,
  }) ?? null;
  const mutationValue = {
    nullifierNodes: freeze(nodes),
    nullifierLeaves: freeze([predecessorUpdate, appended]),
    root: postRoot,
    metrics: freeze(metrics),
    witness: freeze({
      depth: kernel.depth,
      key: kernel.algebra.witnessHex(
        key,
        "persistent witness insertion key",
      ),
      preRoot: kernel.algebra.witnessField(
        expectedPreRoot,
        "persistent pre-root",
      ),
      intermediateRoot: kernel.algebra.witnessField(
        intermediateRoot,
        "persistent intermediate",
      ),
      postRoot: kernel.algebra.witnessField(
        postRoot,
        "persistent post-root",
      ),
      predecessor: witnessLeaf(kernel, predecessor),
      updatedPredecessor: witnessLeaf(kernel, predecessorUpdate),
      predecessorPath: prePath.siblings,
      append: freeze({
        index: appendIndex,
        emptyLeaf: freeze({
          type: "empty",
          index: appendIndex,
          key: "0".repeat(64),
          successorIndex: 0,
          successorKey: "0".repeat(64),
        }),
        newLeaf: witnessLeaf(kernel, appended),
        path: appendEmptyPath.siblings,
      }),
    }),
  };
  if (qualificationTrace !== null) {
    mutationValue.qualificationTrace = qualificationTrace;
  }
  const mutation = freeze(mutationValue);
  kernel.validMutations.add(mutation);
  return mutation;
}

function derivePersistentIndexedNullifierInsertionWithKernel(kernel, value) {
  const trace = kernel.qualificationTrace
    ? createQualificationTraceRecorder()
    : null;
  try {
    return runPersistentIndexedNullifierSemanticKernel(kernel, value, trace);
  } catch (cause) {
    const error = cause instanceof PersistentIndexedNullifierError
      ? cause
      : new PersistentIndexedNullifierError(
        "persistent indexed-nullifier semantic kernel failed unexpectedly",
        {
          cause,
          code: "PERSISTENT_UNEXPECTED_EXCEPTION",
        },
      );
    if (trace !== null) {
      const code = inferredFailureCode(error);
      if (error.code === "PERSISTENT_NULLIFIER_INVALID") error.code = code;
      const qualificationTrace = trace.finish(
        { treeDepth: kernel.depth },
        {
          outcome: "reject",
          rejection: {
            code,
            message: error.message,
          },
        },
      );
      Object.defineProperty(error, "qualificationTrace", {
        configurable: false,
        enumerable: true,
        value: qualificationTrace,
        writable: false,
      });
    }
    throw error;
  }
}

function applyPersistentIndexedNullifierMutationWithKernel(kernel, value) {
  const input = exactKeys(value, [
    "mutation",
    "writeLeaf",
    "writeNode",
  ], "persistent indexed-nullifier mutation apply");
  if (!kernel.validMutations.has(input.mutation)) {
    fail("persistent indexed-nullifier mutation was not derived by this module");
  }
  if (
    typeof input.writeLeaf !== "function" ||
    typeof input.writeNode !== "function"
  ) fail("persistent indexed-nullifier mutation writers must be functions");
  for (const node of input.mutation.nullifierNodes) {
    input.writeNode(node);
  }
  for (const leaf of input.mutation.nullifierLeaves) {
    input.writeLeaf(leaf);
  }
  return freeze({
    nodeWrites: input.mutation.nullifierNodes.length,
    leafWrites: input.mutation.nullifierLeaves.length,
    root: kernel.algebra.copy(
      input.mutation.root,
      "applied persistent nullifier root",
    ),
  });
}

export function derivePersistentIndexedNullifierInsertion(value) {
  return derivePersistentIndexedNullifierInsertionWithKernel(
    PRODUCTION_KERNEL,
    value,
  );
}

export function applyPersistentIndexedNullifierMutation(value) {
  return applyPersistentIndexedNullifierMutationWithKernel(
    PRODUCTION_KERNEL,
    value,
  );
}

function qualificationKernelView(kernel) {
  return freeze({
    semanticAlgebraName: kernel.algebra.name,
    depth: kernel.depth,
    capacity: kernel.capacity,
    maximumNormalCount: kernel.maximumNormalCount,
    defaults: () =>
      freeze(kernel.defaults.map((value, index) =>
        kernel.algebra.copy(
          value,
          `depth-4 qualification default ${index}`,
        )
      )),
    leafHash(value) {
      const input = exactKeys(value, [
        "physicalIndex",
        "leafType",
        "key",
        "successorIndex",
        "successorKey",
      ], "depth-4 qualification leaf hash");
      integer(
        input.physicalIndex,
        0,
        kernel.maximumPhysicalIndex,
        "depth-4 qualification leaf physicalIndex",
      );
      integer(
        input.successorIndex,
        0,
        kernel.maximumPhysicalIndex,
        "depth-4 qualification leaf successorIndex",
      );
      return kernel.algebra.hashLeaf({
        physicalIndex: input.physicalIndex,
        leafType: integer(
          input.leafType,
          1,
          3,
          "depth-4 qualification leaf type",
        ),
        key: kernel.algebra.field(
          input.key,
          "depth-4 qualification leaf key",
        ),
        successorIndex: input.successorIndex,
        successorKey: kernel.algebra.field(
          input.successorKey,
          "depth-4 qualification leaf successor key",
        ),
      });
    },
    derive(value) {
      return derivePersistentIndexedNullifierInsertionWithKernel(
        kernel,
        value,
      );
    },
    apply(value) {
      return applyPersistentIndexedNullifierMutationWithKernel(
        kernel,
        value,
      );
    },
  });
}

/**
 * Qualification-only view of the exact production insertion kernel at depth
 * four. Ordinary production callers cannot select a depth: the public
 * derive/apply functions above remain permanently pinned to depth 32.
 */
export function createDepth4PersistentIndexedNullifierQualificationKernel() {
  return qualificationKernelView(
    createKernel(4, { qualificationTrace: true }),
  );
}

/**
 * Universal-certificate entrypoint. This executes the same semantic kernel as
 * production with an opaque field/hash algebra. It is intentionally pinned to
 * depth four and is not a production tree constructor.
 */
export function createDepth4PersistentIndexedNullifierSymbolicKernel({
  algebra,
} = {}) {
  return qualificationKernelView(createKernel(4, {
    algebra,
    qualificationTrace: true,
  }));
}
