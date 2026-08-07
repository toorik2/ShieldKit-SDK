import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  createDepth4PersistentIndexedNullifierSymbolicKernel,
  PERSISTENT_NULLIFIER_LEAF_TYPES,
} from "../persistent-indexed-nullifier.mjs";

export const Q04_DEPTH4_SYMBOLIC_CERTIFICATE_SCHEMA =
  "shieldkit-v2-direct/q04-depth4-symbolic-certificate/v2";

const TREE_DEPTH = 4;
const CAPACITY = 1 << TREE_DEPTH;
const MAX_PREINSERT_NORMAL_COUNT = CAPACITY - 3;
const CORE_SOURCE_URL = new URL("../persistent-indexed-nullifier.mjs",
  import.meta.url);
const REQUIRED_CORE_FUNCTIONS = Object.freeze([
  "validateLeaf",
  "readStoredNode",
  "pathFromStore",
  "pathFromSiblings",
  "witnessLeaf",
  "runPersistentIndexedNullifierSemanticKernel",
]);
const FORBIDDEN_SEMANTIC_CORE_TOKENS =
  /\b(?:Buffer|BigInt)\b|frBytes|frBigInt|hashIndexedNullifier|persistentNullifierLeafHash|\bsame\s*\(/u;

export class Depth4SymbolicCertificateError extends Error {
  constructor(message) {
    super(message);
    this.name = "Depth4SymbolicCertificateError";
  }
}

const fail = (message) => {
  throw new Depth4SymbolicCertificateError(message);
};
const freeze = (value) => Object.freeze(value);
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
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
};
const canonicalJson = (value) => JSON.stringify(canonical(value));
const digest = (domain, value) =>
  createHash("sha256")
    .update(domain, "ascii")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
const fileSha256 = (url) =>
  createHash("sha256").update(readFileSync(url)).digest("hex");
const term = (kind, value) => freeze({ kind, ...value });
const variable = (name) => term("variable", { name });
const freeHash = (name) => term("free-hash", { name });
const scalar = (value) => term("scalar", { value });
const termEqual = (left, right) =>
  canonicalJson(left) === canonicalJson(right);

function extractFunction(source, name) {
  const marker = `function ${name}`;
  const start = source.indexOf(marker);
  if (start === -1) fail(`production source is missing ${name}`);
  const open = source.indexOf("{", start + marker.length);
  if (open === -1) fail(`production function ${name} has no body`);
  let depth = 0;
  let stringQuote = null;
  let escaped = false;
  for (let index = open; index < source.length; index += 1) {
    const character = source[index];
    if (stringQuote !== null) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === stringQuote) stringQuote = null;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      stringQuote = character;
      continue;
    }
    if (character === "{") depth += 1;
    if (character === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  fail(`production function ${name} is unterminated`);
}

export function inspectDepth4SemanticCorePolicy() {
  const source = readFileSync(CORE_SOURCE_URL, "utf8");
  const functions = REQUIRED_CORE_FUNCTIONS.map((name) => {
    const body = extractFunction(source, name);
    if (FORBIDDEN_SEMANTIC_CORE_TOKENS.test(body)) {
      fail(
        `shared semantic core function ${name} directly inspects a ` +
          "concrete field/hash representation",
      );
    }
    return freeze({
      name,
      sha256: digest("ShieldKit/Q04/semantic-function/v1\0", body),
    });
  });
  return freeze({
    policy:
      "opaque-field-and-hash-values-may-only-cross-the-semantic-algebra-v1",
    productionSourceSha256: fileSha256(CORE_SOURCE_URL),
    functions: freeze(functions),
    manifestSha256: digest(
      "ShieldKit/Q04/semantic-core-manifest/v1\0",
      functions,
    ),
  });
}

function createSymbolicAlgebra() {
  const zero = variable("ZERO");
  const ranks = new Map([
    ["K_PREDECESSOR", 0],
    ["X", 1],
    ["K_SUCCESSOR", 2],
  ]);
  const requireTerm = (value, label) => {
    if (
      value === null ||
      Array.isArray(value) ||
      typeof value !== "object" ||
      typeof value.kind !== "string"
    ) fail(`${label} must be an opaque symbolic field/hash term`);
    return value;
  };
  const compare = (left, right, leftLabel, rightLabel) => {
    requireTerm(left, leftLabel);
    requireTerm(right, rightLabel);
    if (termEqual(left, right)) return 0;
    const leftRank = left.kind === "variable" ? ranks.get(left.name) : null;
    const rightRank = right.kind === "variable" ? ranks.get(right.name) : null;
    if (leftRank === undefined || leftRank === null ||
        rightRank === undefined || rightRank === null) {
      fail(
        `symbolic order has no asserted relation for ${canonicalJson(left)} ` +
          `and ${canonicalJson(right)}`,
      );
    }
    return leftRank < rightRank ? -1 : 1;
  };
  const hashLeaf = ({
    physicalIndex,
    leafType,
    key,
    successorIndex,
    successorKey,
  }) => term("leaf-hash", {
    physicalIndex,
    leafType,
    key: requireTerm(key, "symbolic leaf key"),
    successorIndex,
    successorKey: requireTerm(
      successorKey,
      "symbolic leaf successor key",
    ),
  });
  const hashNode = (left, right) => term("node-hash", {
    left: requireTerm(left, "symbolic left node"),
    right: requireTerm(right, "symbolic right node"),
  });
  return freeze({
    name: "q04-free-hash-term-algebra-v1",
    zero,
    field: requireTerm,
    fromWitnessField: requireTerm,
    witnessField: requireTerm,
    witnessHex(value, label) {
      return digest(
        "ShieldKit/Q04/symbolic-witness-field/v1\0",
        requireTerm(value, label),
      );
    },
    equal(left, right) {
      return termEqual(left, right);
    },
    compare,
    hashLeaf,
    hashEmptyLeaf() {
      return term("empty-leaf-hash", {});
    },
    hashNode,
    isFrMinusOne() {
      return false;
    },
    copy: requireTerm,
  });
}

function buildLayers(leaves, algebra) {
  const layers = [freeze([...leaves])];
  for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
    const previous = layers[depth];
    const next = [];
    for (let index = 0; index < previous.length; index += 2) {
      next.push(algebra.hashNode(previous[index], previous[index + 1]));
    }
    layers.push(freeze(next));
  }
  return freeze(layers);
}

function pathFor(layers, index) {
  const siblings = [];
  let cursor = index;
  for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
    siblings.push(layers[depth][cursor ^ 1]);
    cursor = Math.floor(cursor / 2);
  }
  return freeze(siblings);
}

function skeletons() {
  const output = [];
  for (
    let normalCount = 0;
    normalCount <= MAX_PREINSERT_NORMAL_COUNT;
    normalCount += 1
  ) {
    if (normalCount === 0) {
      output.push(freeze({
        normalCount,
        predecessorIndex: 0,
        successorIndex: 1,
      }));
      continue;
    }
    const normals = Array.from(
      { length: normalCount },
      (_, index) => index + 2,
    );
    for (const predecessorIndex of [0, ...normals]) {
      for (const successorIndex of [1, ...normals]) {
        if (
          predecessorIndex === successorIndex ||
          (predecessorIndex === 0 && successorIndex === 1)
        ) continue;
        output.push(freeze({
          normalCount,
          predecessorIndex,
          successorIndex,
        }));
      }
    }
  }
  if (output.length !== 911) fail("depth-4 control skeleton count differs");
  return freeze(output);
}

function expectedLeafWitness(kernel, leaf) {
  const type = leaf.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.minimum
    ? "min"
    : leaf.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.normal
    ? "normal"
    : fail("symbolic predecessor leaf has an invalid type");
  return freeze({
    type,
    index: leaf.physicalIndex,
    key: kernel.semanticAlgebraName === "q04-free-hash-term-algebra-v1"
      ? digest("ShieldKit/Q04/symbolic-witness-field/v1\0", leaf.key)
      : fail("symbolic kernel algebra differs"),
    successorIndex: leaf.successorIndex,
    successorKey: digest(
      "ShieldKit/Q04/symbolic-witness-field/v1\0",
      leaf.successorKey,
    ),
  });
}

function executeSkeleton(skeleton) {
  const algebra = createSymbolicAlgebra();
  const kernel =
    createDepth4PersistentIndexedNullifierSymbolicKernel({ algebra });
  const defaults = kernel.defaults();
  const appendIndex = skeleton.normalCount + 2;
  const target = variable("X");
  const predecessorKey = skeleton.predecessorIndex === 0
    ? algebra.zero
    : variable("K_PREDECESSOR");
  const successorKey = skeleton.successorIndex === 1
    ? algebra.zero
    : variable("K_SUCCESSOR");
  const predecessor = freeze({
    physicalIndex: skeleton.predecessorIndex,
    leafType: skeleton.predecessorIndex === 0
      ? PERSISTENT_NULLIFIER_LEAF_TYPES.minimum
      : PERSISTENT_NULLIFIER_LEAF_TYPES.normal,
    key: predecessorKey,
    successorIndex: skeleton.successorIndex,
    successorKey,
  });
  const predecessorWithHash = freeze({
    ...predecessor,
    leafHash: algebra.hashLeaf(predecessor),
  });
  const leaves = Array.from(
    { length: CAPACITY },
    (_, index) => index <= skeleton.normalCount + 1
      ? freeHash(`ALLOCATED_LEAF_${index}`)
      : defaults[0],
  );
  leaves[skeleton.predecessorIndex] = predecessorWithHash.leafHash;
  const preLayers = buildLayers(leaves, algebra);
  const adapterCalls = [];
  const adapter = freeze({
    hasNormalKey(key) {
      adapterCalls.push(freeze({ method: "hasNormalKey", key }));
      return false;
    },
    predecessorIndex(key) {
      adapterCalls.push(freeze({ method: "predecessorIndex", key }));
      return skeleton.predecessorIndex;
    },
    readLeaf(physicalIndex) {
      adapterCalls.push(freeze({ method: "readLeaf", physicalIndex }));
      if (physicalIndex === skeleton.predecessorIndex) {
        return predecessorWithHash;
      }
      if (physicalIndex === appendIndex) return null;
      fail("symbolic kernel read an unmodelled leaf");
    },
    readNode(depth, nodeIndex) {
      adapterCalls.push(freeze({ method: "readNode", depth, nodeIndex }));
      const observed = preLayers[depth][nodeIndex];
      return termEqual(observed, defaults[depth]) ? null : observed;
    },
  });
  const mutation = kernel.derive({
    adapter,
    expectedPreRoot: preLayers[TREE_DEPTH][0],
    key: target,
    normalCount: skeleton.normalCount,
  });

  const updatedPredecessor = freeze({
    ...predecessor,
    successorIndex: appendIndex,
    successorKey: target,
  });
  const appended = freeze({
    physicalIndex: appendIndex,
    leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.normal,
    key: target,
    successorIndex: predecessor.successorIndex,
    successorKey: predecessor.successorKey,
  });
  const intermediateLeaves = [...leaves];
  intermediateLeaves[skeleton.predecessorIndex] =
    algebra.hashLeaf(updatedPredecessor);
  const intermediateLayers = buildLayers(intermediateLeaves, algebra);
  const postLeaves = [...intermediateLeaves];
  postLeaves[appendIndex] = algebra.hashLeaf(appended);
  const postLayers = buildLayers(postLeaves, algebra);

  if (!termEqual(mutation.root, postLayers[TREE_DEPTH][0])) {
    fail("symbolic production post-root differs from canonical replacement");
  }
  if (!termEqual(
    mutation.witness.preRoot,
    preLayers[TREE_DEPTH][0],
  )) fail("symbolic production pre-root witness differs");
  if (!termEqual(
    mutation.witness.intermediateRoot,
    intermediateLayers[TREE_DEPTH][0],
  )) fail("symbolic production intermediate-root witness differs");
  if (!termEqual(
    mutation.witness.postRoot,
    postLayers[TREE_DEPTH][0],
  )) fail("symbolic production post-root witness differs");
  if (!termEqual(
    mutation.witness.predecessorPath,
    pathFor(preLayers, skeleton.predecessorIndex),
  )) fail("symbolic predecessor path differs from the canonical tree");
  if (!termEqual(
    mutation.witness.append.path,
    pathFor(intermediateLayers, appendIndex),
  )) fail("symbolic append path differs from the canonical tree");
  if (!termEqual(
    mutation.witness.predecessor,
    expectedLeafWitness(kernel, predecessor),
  )) fail("symbolic predecessor witness differs");
  if (!termEqual(
    mutation.witness.updatedPredecessor,
    expectedLeafWitness(kernel, updatedPredecessor),
  )) fail("symbolic predecessor-update witness differs");
  if (!termEqual(
    mutation.witness.append.newLeaf,
    expectedLeafWitness(kernel, appended),
  )) fail("symbolic append witness differs");

  for (const node of mutation.nullifierNodes) {
    if (!termEqual(node.nodeHash, postLayers[node.depth][node.nodeIndex])) {
      fail(
        `symbolic write ${node.depth}:${node.nodeIndex} differs from ` +
          "the canonical post-tree",
      );
    }
  }
  const expectedNodeAddresses = new Set();
  for (const leafIndex of [skeleton.predecessorIndex, appendIndex]) {
    let cursor = leafIndex;
    expectedNodeAddresses.add(`0:${cursor}`);
    for (let depth = 0; depth < TREE_DEPTH; depth += 1) {
      cursor = Math.floor(cursor / 2);
      expectedNodeAddresses.add(`${depth + 1}:${cursor}`);
    }
  }
  if (
    mutation.nullifierNodes.length !== expectedNodeAddresses.size ||
    mutation.nullifierNodes.some(
      ({ depth, nodeIndex }) =>
        !expectedNodeAddresses.has(`${depth}:${nodeIndex}`),
    )
  ) fail("symbolic mutation writes do not cover exactly both update paths");

  const appliedNodes = [];
  const appliedLeaves = [];
  const applied = kernel.apply({
    mutation,
    writeNode(node) {
      appliedNodes.push(node);
    },
    writeLeaf(leaf) {
      appliedLeaves.push(leaf);
    },
  });
  if (
    applied.nodeWrites !== mutation.nullifierNodes.length ||
    applied.leafWrites !== 2 ||
    !termEqual(applied.root, mutation.root) ||
    !termEqual(appliedNodes, mutation.nullifierNodes) ||
    !termEqual(appliedLeaves, mutation.nullifierLeaves)
  ) fail("symbolic mutation application differs from the derived mutation");

  const productionProof = freeze({
    root: mutation.root,
    witness: mutation.witness,
    nullifierNodes: mutation.nullifierNodes,
    nullifierLeaves: mutation.nullifierLeaves,
    metrics: mutation.metrics,
  });
  const statement = freeze({
    ...skeleton,
    appendIndex,
    universallyQuantified: freeze({
      target: "X",
      predecessorKey:
        skeleton.predecessorIndex === 0 ? "minimum-sentinel" : "K_PREDECESSOR",
      successorKey:
        skeleton.successorIndex === 1 ? "maximum-sentinel" : "K_SUCCESSOR",
      untouchedAllocatedLeafHashes:
        skeleton.normalCount + 1,
      orderConstraints: freeze([
        ...(skeleton.predecessorIndex === 0
          ? []
          : ["K_PREDECESSOR < X"]),
        ...(skeleton.successorIndex === 1
          ? []
          : ["X < K_SUCCESSOR"]),
      ]),
    }),
    adapterCallCount: adapterCalls.length,
    adapterCallsSha256: digest(
      "ShieldKit/Q04/symbolic-adapter-calls/v1\0",
      adapterCalls,
    ),
    canonicalPostRootSha256: digest(
      "ShieldKit/Q04/symbolic-post-root/v1\0",
      postLayers[TREE_DEPTH][0],
    ),
    productionProofSha256: digest(
      "ShieldKit/Q04/symbolic-production-proof/v1\0",
      productionProof,
    ),
    proof: freeze({
      symbolicAlgebra: algebra.name,
      production: productionProof,
      adapterCalls: freeze(adapterCalls),
    }),
  });
  return freeze({
    ...statement,
    statementSha256: digest(
      "ShieldKit/Q04/symbolic-statement/v2\0",
      statement,
    ),
  });
}

function expectedCertificate() {
  const semanticCore = inspectDepth4SemanticCorePolicy();
  const cases = skeletons().map(executeSkeleton);
  const casesSha256 = digest(
    "ShieldKit/Q04/depth4-symbolic-cases/v2\0",
    cases,
  );
  const certificateWithoutDigest = freeze({
    schema: Q04_DEPTH4_SYMBOLIC_CERTIFICATE_SCHEMA,
    status: "machine-checked-symbolic-template-evidence",
    definition: freeze({
      depth: TREE_DEPTH,
      capacity: CAPACITY,
      preInsertionNormalCounts: MAX_PREINSERT_NORMAL_COUNT + 1,
      controlSkeletons: 911,
      representedConcreteRankStateGapTransitions: "93928268313",
      quotientClaim: false,
      universalTemplateClaim: true,
    }),
    semanticCore,
    cases: freeze(cases),
    casesSha256,
  });
  return freeze({
    ...certificateWithoutDigest,
    certificateSha256: digest(
      "ShieldKit/Q04/depth4-symbolic-certificate/v2\0",
      certificateWithoutDigest,
    ),
  });
}

export function buildDepth4SymbolicCertificate() {
  return expectedCertificate();
}

export function verifyDepth4SymbolicCertificate(value) {
  exactKeys(value, [
    "schema",
    "status",
    "definition",
    "semanticCore",
    "cases",
    "casesSha256",
    "certificateSha256",
  ], "depth-4 symbolic certificate");
  const expected = expectedCertificate();
  if (!termEqual(value, expected)) {
    fail(
      "depth-4 symbolic certificate differs from fresh exact-kernel " +
        "re-execution",
    );
  }
  return freeze({
    schema: value.schema,
    status: "verified-symbolic-template-evidence",
    controlSkeletons: value.cases.length,
    representedConcreteRankStateGapTransitions:
      value.definition.representedConcreteRankStateGapTransitions,
    formalTheoremClaim: false,
    certificateSha256: value.certificateSha256,
  });
}
