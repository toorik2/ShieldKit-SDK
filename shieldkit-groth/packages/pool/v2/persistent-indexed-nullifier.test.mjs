import assert from "node:assert/strict";
import test from "node:test";

import {
  create as createReference,
  insert as insertReference,
} from "../../action/v2/indexed-nullifier-tree.mjs";
import {
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
} from "../../action/v2/poseidon.mjs";
import {
  applyPersistentIndexedNullifierMutation,
  createDepth4PersistentIndexedNullifierQualificationKernel,
  derivePersistentIndexedNullifierInsertion,
  PERSISTENT_NULLIFIER_FR_MODULUS,
  PERSISTENT_NULLIFIER_LEAF_TYPES,
  persistentNullifierDefaults,
  persistentNullifierLeafHash,
} from "./persistent-indexed-nullifier.mjs";

const encode = (value) =>
  Buffer.from(value.toString(16).padStart(64, "0"), "hex");
const decode = (value) => BigInt(`0x${Buffer.from(value).toString("hex")}`);
const key = (depth, index) => `${depth}:${index}`;
const caught = (operation) => {
  let observed;
  try {
    operation();
  } catch (error) {
    observed = error;
  }
  assert.ok(observed instanceof Error, "operation must throw");
  return observed;
};

function createAdapterState({
  depth = 32,
  defaults = persistentNullifierDefaults(),
  leafHash = persistentNullifierLeafHash,
  applyMutation = applyPersistentIndexedNullifierMutation,
} = {}) {
  const nodes = new Map();
  const leaves = new Map();
  const order = new Map();
  const putNode = ({ depth, nodeIndex, nodeHash }) => {
    const id = key(depth, nodeIndex);
    if (Buffer.from(nodeHash).equals(defaults[depth])) nodes.delete(id);
    else nodes.set(id, Buffer.from(nodeHash));
  };
  const putLeaf = (leaf) => {
    leaves.set(leaf.physicalIndex, {
      ...leaf,
      leafHash: Buffer.from(leaf.leafHash),
      key: Buffer.from(leaf.key),
      successorKey: Buffer.from(leaf.successorKey),
    });
    if (leaf.leafType === PERSISTENT_NULLIFIER_LEAF_TYPES.normal) {
      order.set(leaf.key.toString("hex"), leaf.physicalIndex);
    }
  };
  const replaceLeaf = (leaf) => {
    putLeaf(leaf);
    let cursor = leaf.physicalIndex;
    let node = Buffer.from(leaf.leafHash);
    putNode({ depth: 0, nodeIndex: cursor, nodeHash: node });
    for (let level = 0; level < depth; level += 1) {
      const sibling = nodes.get(key(level, cursor ^ 1)) ?? defaults[level];
      node = encode(
        (cursor & 1) === 0
          ? hashIndexedNullifierNode(decode(node), decode(sibling))
          : hashIndexedNullifierNode(decode(sibling), decode(node)),
      );
      cursor = Math.floor(cursor / 2);
      putNode({ depth: level + 1, nodeIndex: cursor, nodeHash: node });
    }
  };
  const zero = Buffer.alloc(32);
  for (const base of [
    {
      physicalIndex: 0,
      leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.minimum,
      key: zero,
      successorIndex: 1,
      successorKey: zero,
    },
    {
      physicalIndex: 1,
      leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.maximum,
      key: zero,
      successorIndex: 1,
      successorKey: zero,
    },
  ]) {
    replaceLeaf({ ...base, leafHash: leafHash(base) });
  }
  let count = 0;
  const adapter = Object.freeze({
    hasNormalKey(candidate) {
      return order.has(Buffer.from(candidate).toString("hex"));
    },
    predecessorIndex(candidate) {
      const value = decode(candidate);
      let result = 0;
      for (const [hex, index] of order) {
        const observed = BigInt(`0x${hex}`);
        if (observed < value && (result === 0 ||
          decode(leaves.get(result).key) < observed)) result = index;
      }
      return result;
    },
    readLeaf(index) {
      const leaf = leaves.get(index);
      return leaf === undefined
        ? null
        : {
          ...leaf,
          leafHash: Buffer.from(leaf.leafHash),
          key: Buffer.from(leaf.key),
          successorKey: Buffer.from(leaf.successorKey),
        };
    },
    readNode(depth, nodeIndex) {
      const observed = nodes.get(key(depth, nodeIndex));
      return observed === undefined ? null : Buffer.from(observed);
    },
  });
  return {
    adapter,
    apply(mutation) {
      applyMutation({
        mutation,
        writeNode: putNode,
        writeLeaf: putLeaf,
      });
      count += 1;
    },
    count: () => count,
    root: () => Buffer.from(nodes.get(`${depth}:0`)),
    leaf: (index) => adapter.readLeaf(index),
  };
}

test("persistent insertion core matches the frozen production-Poseidon reference", () => {
  const state = createAdapterState();
  let reference = createReference({
    depth: 32,
    hashLeaf: hashIndexedNullifierLeaf,
    hashNode: hashIndexedNullifierNode,
  });
  for (const value of [
    0n,
    PERSISTENT_NULLIFIER_FR_MODULUS - 1n,
    7n,
    3n,
    99n,
  ]) {
    const input = encode(value);
    const mutation = derivePersistentIndexedNullifierInsertion({
      adapter: state.adapter,
      expectedPreRoot: state.root(),
      key: input,
      normalCount: state.count(),
    });
    const expected = insertReference(reference, input);
    assert.equal(mutation.root.toString("hex"), expected.tree.root.toString(16)
      .padStart(64, "0"));
    assert.deepEqual(mutation.witness, expected.witness);
    assert.equal("qualificationTrace" in mutation, false);
    assert.equal(mutation.metrics.leafHashCalls, 3);
    assert.equal(
      mutation.metrics.predecessorValidationLeafHashCalls,
      1,
    );
    assert.equal(mutation.metrics.mutationLeafHashCalls, 2);
    assert.equal(mutation.metrics.nodeHashCalls, 128);
    assert.equal(mutation.metrics.leafReads, 2);
    assert.equal(mutation.metrics.orderLookups, 2);
    assert.ok(
      mutation.metrics.nodeReads >= 32 && mutation.metrics.nodeReads <= 64,
    );
    state.apply(mutation);
    input.fill(0xff);
    assert.equal(state.leaf(state.count() + 1).key.toString("hex"),
      value.toString(16).padStart(64, "0"));
    reference = expected.tree;
  }
});

test("persistent insertion core rejects duplicates, noncanonical fields, and stale roots", () => {
  const state = createAdapterState();
  const first = derivePersistentIndexedNullifierInsertion({
    adapter: state.adapter,
    expectedPreRoot: state.root(),
    key: encode(1n),
    normalCount: 0,
  });
  state.apply(first);
  assert.throws(() => derivePersistentIndexedNullifierInsertion({
    adapter: state.adapter,
    expectedPreRoot: state.root(),
    key: encode(1n),
    normalCount: 1,
  }), /already exists/);
  assert.throws(() => derivePersistentIndexedNullifierInsertion({
    adapter: state.adapter,
    expectedPreRoot: state.root(),
    key: encode(PERSISTENT_NULLIFIER_FR_MODULUS),
    normalCount: 1,
  }), /canonical BN254 Fr/);
  assert.throws(() => derivePersistentIndexedNullifierInsertion({
    adapter: state.adapter,
    expectedPreRoot: Buffer.alloc(32),
    key: encode(2n),
    normalCount: 1,
  }), /root differs/);
});

test("fixed depth-4 qualification wrapper exercises the production kernel through capacity", () => {
  const qualification =
    createDepth4PersistentIndexedNullifierQualificationKernel();
  assert.equal(qualification.depth, 4);
  assert.equal(qualification.capacity, 16);
  assert.equal(qualification.maximumNormalCount, 14);
  const state = createAdapterState({
    depth: qualification.depth,
    defaults: qualification.defaults(),
    leafHash: qualification.leafHash,
    applyMutation: qualification.apply,
  });
  let reference = createReference({
    depth: 4,
    hashLeaf: hashIndexedNullifierLeaf,
    hashNode: hashIndexedNullifierNode,
  });
  const values = [
    0n,
    PERSISTENT_NULLIFIER_FR_MODULUS - 1n,
    ...Array.from({ length: 12 }, (_, index) => BigInt(index + 1)),
  ];
  for (const value of values) {
    const input = encode(value);
    const mutation = qualification.derive({
      adapter: state.adapter,
      expectedPreRoot: state.root(),
      key: input,
      normalCount: state.count(),
    });
    const expected = insertReference(reference, input);
    assert.equal(mutation.witness.depth, 4);
    assert.deepEqual(mutation.witness, expected.witness);
    assert.deepEqual(mutation.root, encode(expected.tree.root));
    assert.equal(mutation.metrics.treeDepth, 4);
    assert.equal(mutation.metrics.leafHashCalls, 3);
    assert.equal(mutation.metrics.nodeHashCalls, 16);
    assert.equal(mutation.metrics.logicalPathSiblingLookups, 8);
    assert.equal(mutation.metrics.pathOverrideHits, 1);
    assert.equal(mutation.metrics.pathAdapterNodeReads, 7);
    assert.equal(mutation.metrics.rootAdapterNodeReads, 1);
    assert.equal(mutation.metrics.nodeReads, 8);
    const trace = mutation.qualificationTrace;
    assert.equal(
      trace.schema,
      "shieldkit-v2-direct/persistent-nullifier-kernel-trace/v2",
    );
    assert.equal(trace.outcome, "accept");
    assert.equal(trace.rejection, null);
    assert.equal(trace.guards.every(({ passed }) => passed), true);
    assert.equal(trace.symbolicHashes.length, 19);
    assert.deepEqual(
      Object.fromEntries(
        [
          "predecessor-validation",
          "predecessor-membership",
          "predecessor-update",
          "predecessor-update-path",
          "append",
          "append-empty-membership",
          "append-update-path",
        ].map((phase) => [
          phase,
          trace.symbolicHashes.filter((entry) => entry.phase === phase).length,
        ]),
      ),
      {
        "predecessor-validation": 1,
        "predecessor-membership": 4,
        "predecessor-update": 1,
        "predecessor-update-path": 4,
        append: 1,
        "append-empty-membership": 4,
        "append-update-path": 4,
      },
    );
    assert.deepEqual(
      trace.symbolicHashes.map((entry) => entry.outputSymbol),
      Array.from({ length: 19 }, (_, index) => `h${index}`),
    );
    assert.equal(
      trace.adapterCalls.filter((entry) => entry.method === "readNode").length,
      8,
    );
    assert.equal(
      trace.adapterCalls.filter((entry) => entry.method === "readLeaf").length,
      2,
    );
    assert.equal(
      trace.adapterCalls.filter(
        (entry) => entry.method === "hasNormalKey",
      ).length,
      1,
    );
    assert.equal(
      trace.adapterCalls.filter(
        (entry) => entry.method === "predecessorIndex",
      ).length,
      1,
    );
    assert.equal(trace.branchFacts.normalCount, state.count());
    assert.equal(trace.branchFacts.appendIndex, state.count() + 2);
    for (const digest of [
      trace.adapterCallsSha256,
      trace.guardsSha256,
      trace.nodeAddressesSha256,
      trace.symbolicHashesSha256,
      trace.transcriptSha256,
    ]) {
      assert.match(digest, /^[0-9a-f]{64}$/u);
    }
    if (state.count() === 0) {
      assert.throws(
        () => applyPersistentIndexedNullifierMutation({
          mutation,
          writeLeaf() {},
          writeNode() {},
        }),
        /was not derived by this module/u,
      );
    }
    state.apply(mutation);
    reference = expected.tree;
  }
  assert.equal(state.count(), 14);
  const capacity = caught(() => qualification.derive({
      adapter: state.adapter,
      expectedPreRoot: state.root(),
      key: encode(0n),
      normalCount: state.count(),
    }));
  assert.match(
    capacity.message,
    /normalCount must be an integer from 0 through 13/u,
  );
  assert.equal(capacity.code, "PERSISTENT_COUNT_OR_CAPACITY");
  assert.equal(capacity.qualificationTrace.outcome, "reject");
  assert.equal(capacity.qualificationTrace.adapterCalls.length, 0);
  assert.equal(capacity.qualificationTrace.guards.length, 0);
});

test("production and depth-4 mutation capabilities are not interchangeable", () => {
  const productionState = createAdapterState();
  const productionMutation = derivePersistentIndexedNullifierInsertion({
    adapter: productionState.adapter,
    expectedPreRoot: productionState.root(),
    key: encode(17n),
    normalCount: 0,
  });
  const qualification =
    createDepth4PersistentIndexedNullifierQualificationKernel();
  assert.throws(
    () => qualification.apply({
      mutation: productionMutation,
      writeLeaf() {},
      writeNode() {},
    }),
    /was not derived by this module/u,
  );
});

test("qualification rejection traces preserve guard precedence and adapter prefix",
  () => {
    const qualification =
      createDepth4PersistentIndexedNullifierQualificationKernel();
    const state = createAdapterState({
      depth: qualification.depth,
      defaults: qualification.defaults(),
      leafHash: qualification.leafHash,
      applyMutation: qualification.apply,
    });
    const first = qualification.derive({
      adapter: state.adapter,
      expectedPreRoot: state.root(),
      key: encode(7n),
      normalCount: 0,
    });
    state.apply(first);

    const duplicate = caught(() => qualification.derive({
        adapter: state.adapter,
        expectedPreRoot: state.root(),
        key: encode(7n),
        normalCount: 1,
      }));
    assert.match(duplicate.message, /already exists/u);
    assert.equal(duplicate.code, "PERSISTENT_DUPLICATE");
    assert.equal(duplicate.qualificationTrace.outcome, "reject");
    assert.deepEqual(
      duplicate.qualificationTrace.adapterCalls.map(({ method }) => method),
      ["readNode", "hasNormalKey"],
    );
    assert.deepEqual(
      duplicate.qualificationTrace.guards.map(({ code, passed }) => ({
        code,
        passed,
      })),
      [
        { code: "PERSISTENT_ROOT_MISMATCH", passed: true },
        { code: "PERSISTENT_DUPLICATE_RESULT_TYPE", passed: true },
        { code: "PERSISTENT_DUPLICATE", passed: false },
      ],
    );
    assert.equal(
      duplicate.qualificationTrace.rejection.code,
      "PERSISTENT_DUPLICATE",
    );

    const malformed = caught(() => qualification.derive({
        adapter: state.adapter,
        expectedPreRoot: state.root(),
        key: Buffer.alloc(31),
        normalCount: 1,
      }));
    assert.match(malformed.message, /exactly 32 bytes/u);
    assert.equal(malformed.code, "PERSISTENT_KEY_LENGTH");
    assert.equal(malformed.qualificationTrace.outcome, "reject");
    assert.equal(malformed.qualificationTrace.adapterCalls.length, 0);
    assert.equal(malformed.qualificationTrace.guards.length, 0);

    const throwingAdapter = {
      ...state.adapter,
      readNode() {
        throw new Error("injected read fault");
      },
    };
    const adapterFailure = caught(() => qualification.derive({
        adapter: throwingAdapter,
        expectedPreRoot: state.root(),
        key: encode(8n),
        normalCount: 1,
      }));
    assert.match(adapterFailure.message, /adapter\.readNode threw/u);
    assert.equal(
      adapterFailure.code,
      "PERSISTENT_ADAPTER_READ_NODE_THREW",
    );
    assert.equal(adapterFailure.cause.message, "injected read fault");
    assert.equal(
      adapterFailure.qualificationTrace.adapterCalls[0].result.threw,
      true,
    );
  });

test("qualification rejection paths stop before later reads and never mutate adapter state",
  () => {
    const qualification =
      createDepth4PersistentIndexedNullifierQualificationKernel();
    const state = createAdapterState({
      depth: qualification.depth,
      defaults: qualification.defaults(),
      leafHash: qualification.leafHash,
      applyMutation: qualification.apply,
    });
    const snapshot = () => ({
      count: state.count(),
      root: state.root().toString("hex"),
      leaves: Array.from({ length: qualification.capacity }, (_, index) => {
        const value = state.leaf(index);
        return value === null
          ? null
          : {
            ...value,
            leafHash: value.leafHash.toString("hex"),
            key: value.key.toString("hex"),
            successorKey: value.successorKey.toString("hex"),
          };
      }),
    });
    const expectUnchangedReject = (operation) => {
      const before = snapshot();
      const error = caught(operation);
      assert.deepEqual(snapshot(), before);
      return error;
    };

    const staleRoot = expectUnchangedReject(() => qualification.derive({
      adapter: state.adapter,
      expectedPreRoot: Buffer.alloc(32),
      key: encode(9n),
      normalCount: 0,
    }));
    assert.equal(staleRoot.code, "PERSISTENT_ROOT_MISMATCH");
    assert.deepEqual(
      staleRoot.qualificationTrace.adapterCalls.map(({ method }) => method),
      ["readNode"],
    );
    assert.deepEqual(
      staleRoot.qualificationTrace.guards.map(({ code, passed }) => ({
        code,
        passed,
      })),
      [{ code: "PERSISTENT_ROOT_MISMATCH", passed: false }],
    );

    const nonBooleanDuplicate = expectUnchangedReject(() => qualification.derive({
      adapter: {
        ...state.adapter,
        hasNormalKey() {
          return 1;
        },
      },
      expectedPreRoot: state.root(),
      key: encode(9n),
      normalCount: 0,
    }));
    assert.equal(
      nonBooleanDuplicate.code,
      "PERSISTENT_DUPLICATE_RESULT_TYPE",
    );
    assert.deepEqual(
      nonBooleanDuplicate.qualificationTrace.adapterCalls.map(({ method }) =>
        method
      ),
      ["readNode", "hasNormalKey"],
    );
    assert.equal(
      nonBooleanDuplicate.qualificationTrace.guards.at(-1).code,
      "PERSISTENT_DUPLICATE_RESULT_TYPE",
    );
    assert.equal(
      nonBooleanDuplicate.qualificationTrace.guards.at(-1).passed,
      false,
    );

    const invalidPredecessor = expectUnchangedReject(() => qualification.derive({
      adapter: {
        ...state.adapter,
        predecessorIndex() {
          return "0";
        },
      },
      expectedPreRoot: state.root(),
      key: encode(9n),
      normalCount: 0,
    }));
    assert.equal(
      invalidPredecessor.code,
      "PERSISTENT_PREDECESSOR_INDEX",
    );
    assert.deepEqual(
      invalidPredecessor.qualificationTrace.adapterCalls.map(({ method }) =>
        method
      ),
      ["readNode", "hasNormalKey", "predecessorIndex"],
    );
    assert.equal(invalidPredecessor.qualificationTrace.guards.length, 3);

    const occupiedAppend = expectUnchangedReject(() => qualification.derive({
      adapter: {
        ...state.adapter,
        readLeaf(index) {
          return index === 2 ? state.leaf(0) : state.adapter.readLeaf(index);
        },
      },
      expectedPreRoot: state.root(),
      key: encode(9n),
      normalCount: 0,
    }));
    assert.equal(occupiedAppend.code, "PERSISTENT_APPEND_OCCUPIED");
    assert.deepEqual(
      occupiedAppend.qualificationTrace.adapterCalls.map(({ method }) => method),
      ["readNode", "hasNormalKey", "predecessorIndex", "readLeaf", "readLeaf"],
    );
    assert.equal(
      occupiedAppend.qualificationTrace.adapterCalls.filter(({ phase }) =>
        phase === "predecessor-membership"
      ).length,
      0,
    );
  });

test("qualification adapter exceptions retain exact read prefix and rejected apply invokes no writer",
  () => {
    const qualification =
      createDepth4PersistentIndexedNullifierQualificationKernel();
    const state = createAdapterState({
      depth: qualification.depth,
      defaults: qualification.defaults(),
      leafHash: qualification.leafHash,
      applyMutation: qualification.apply,
    });
    const deriveWith = (adapter) => caught(() => qualification.derive({
      adapter,
      expectedPreRoot: state.root(),
      key: encode(11n),
      normalCount: 0,
    }));
    const cases = [
      {
        name: "duplicate lookup",
        method: "hasNormalKey",
        expectedCode: "PERSISTENT_ADAPTER_HAS_NORMAL_KEY_THREW",
        expectedCalls: ["readNode", "hasNormalKey"],
        adapter: {
          ...state.adapter,
          hasNormalKey() {
            throw new Error("injected duplicate lookup fault");
          },
        },
      },
      {
        name: "predecessor lookup",
        method: "predecessorIndex",
        expectedCode: "PERSISTENT_ADAPTER_PREDECESSOR_INDEX_THREW",
        expectedCalls: ["readNode", "hasNormalKey", "predecessorIndex"],
        adapter: {
          ...state.adapter,
          predecessorIndex() {
            throw new Error("injected predecessor lookup fault");
          },
        },
      },
      {
        name: "predecessor leaf read",
        method: "readLeaf",
        expectedCode: "PERSISTENT_ADAPTER_READ_LEAF_THREW",
        expectedCalls: ["readNode", "hasNormalKey", "predecessorIndex", "readLeaf"],
        adapter: {
          ...state.adapter,
          readLeaf() {
            throw new Error("injected predecessor leaf fault");
          },
        },
      },
      {
        name: "path node read",
        method: "readNode",
        expectedCode: "PERSISTENT_ADAPTER_READ_NODE_THREW",
        expectedCalls: [
          "readNode",
          "hasNormalKey",
          "predecessorIndex",
          "readLeaf",
          "readLeaf",
          "readNode",
        ],
        adapter: {
          ...state.adapter,
          readNode(...args) {
            if (args[0] === qualification.depth) {
              return state.adapter.readNode(...args);
            }
            throw new Error("injected path node fault");
          },
        },
      },
    ];
    for (const entry of cases) {
      const error = deriveWith(entry.adapter);
      assert.equal(error.code, entry.expectedCode, entry.name);
      assert.match(error.message, new RegExp(`adapter\\.${entry.method} threw`, "u"));
      assert.deepEqual(
        error.qualificationTrace.adapterCalls.map(({ method }) => method),
        entry.expectedCalls,
        entry.name,
      );
      assert.equal(
        error.qualificationTrace.adapterCalls.at(-1).result.threw,
        true,
        entry.name,
      );
    }

    const mutation = qualification.derive({
      adapter: state.adapter,
      expectedPreRoot: state.root(),
      key: encode(11n),
      normalCount: 0,
    });
    let writerCalls = 0;
    assert.throws(
      () => qualification.apply({
        mutation,
        writeLeaf: null,
        writeNode() {
          writerCalls += 1;
        },
      }),
      /writers must be functions/u,
    );
    assert.equal(writerCalls, 0);
    assert.throws(
      () => qualification.apply({
        mutation: {},
        writeLeaf() {
          writerCalls += 1;
        },
        writeNode() {
          writerCalls += 1;
        },
      }),
      /was not derived by this module/u,
    );
    assert.equal(writerCalls, 0);
  });

test("qualification kernel rejects malformed caller and adapter surfaces before any adapter read",
  () => {
    const qualification =
      createDepth4PersistentIndexedNullifierQualificationKernel();
    const state = createAdapterState({
      depth: qualification.depth,
      defaults: qualification.defaults(),
      leafHash: qualification.leafHash,
      applyMutation: qualification.apply,
    });
    const valid = () => ({
      adapter: state.adapter,
      expectedPreRoot: state.root(),
      key: encode(12n),
      normalCount: 0,
    });
    const cases = [
      {
        name: "unknown insertion property",
        value: { ...valid(), unexpected: true },
        message: /insertion has missing or unknown properties/u,
      },
      {
        name: "missing adapter method",
        value: {
          ...valid(),
          adapter: { ...state.adapter, extra() {} },
        },
        message: /adapter has missing or unknown properties/u,
      },
      {
        name: "nonfunction adapter read",
        value: {
          ...valid(),
          adapter: { ...state.adapter, readNode: null },
        },
        message: /adapter\.readNode must be a function/u,
      },
      {
        name: "nonfunction adapter duplicate lookup",
        value: {
          ...valid(),
          adapter: { ...state.adapter, hasNormalKey: 1 },
        },
        message: /adapter\.hasNormalKey must be a function/u,
      },
      {
        name: "nonfunction adapter predecessor lookup",
        value: {
          ...valid(),
          adapter: { ...state.adapter, predecessorIndex: false },
        },
        message: /adapter\.predecessorIndex must be a function/u,
      },
      {
        name: "nonfunction adapter leaf read",
        value: {
          ...valid(),
          adapter: { ...state.adapter, readLeaf: {} },
        },
        message: /adapter\.readLeaf must be a function/u,
      },
      {
        name: "negative count",
        value: { ...valid(), normalCount: -1 },
        message: /normalCount must be an integer/u,
      },
      {
        name: "short key",
        value: { ...valid(), key: Buffer.alloc(31) },
        message: /key must contain exactly 32 bytes/u,
      },
      {
        name: "noncanonical key",
        value: { ...valid(), key: encode(PERSISTENT_NULLIFIER_FR_MODULUS) },
        message: /key must be a canonical BN254 Fr/u,
      },
      {
        name: "short expected root",
        value: { ...valid(), expectedPreRoot: Buffer.alloc(31) },
        message: /expectedPreRoot must contain exactly 32 bytes/u,
      },
      {
        name: "noncanonical expected root",
        value: {
          ...valid(),
          expectedPreRoot: encode(PERSISTENT_NULLIFIER_FR_MODULUS),
        },
        message: /expectedPreRoot must be a canonical BN254 Fr/u,
      },
    ];
    for (const entry of cases) {
      const error = caught(() => qualification.derive(entry.value));
      assert.match(error.message, entry.message, entry.name);
      assert.equal(error.qualificationTrace.outcome, "reject", entry.name);
      assert.equal(
        error.qualificationTrace.adapterCalls.length,
        0,
        entry.name,
      );
    }
  });

test("qualification kernel rejects malformed predecessor encodings, hashes, brackets, and membership",
  () => {
    const qualification =
      createDepth4PersistentIndexedNullifierQualificationKernel();
    const fresh = () => createAdapterState({
      depth: qualification.depth,
      defaults: qualification.defaults(),
      leafHash: qualification.leafHash,
      applyMutation: qualification.apply,
    });
    const derive = (state, adapter, value) => caught(() => qualification.derive({
      adapter,
      expectedPreRoot: state.root(),
      key: encode(value),
      normalCount: state.count(),
    }));

    {
      const state = fresh();
      const error = derive(state, {
        ...state.adapter,
        readLeaf(index) {
          return index === 0 ? null : state.adapter.readLeaf(index);
        },
      }, 4n);
      assert.match(error.message, /predecessor must be an object/u);
    }

    {
      const state = fresh();
      const error = derive(state, {
        ...state.adapter,
        readLeaf(index) {
          return index === 0 ? { ...state.leaf(0), leafType: 0 } :
            state.adapter.readLeaf(index);
        },
      }, 4n);
      assert.match(error.message, /predecessor\.leafType must be an integer/u);
      assert.equal(error.qualificationTrace.adapterCalls.at(-1).phase,
        "predecessor-leaf-read");
    }

    {
      const state = fresh();
      const error = derive(state, {
        ...state.adapter,
        readLeaf(index) {
          return index === 0
            ? { ...state.leaf(0), leafHash: Buffer.alloc(32) }
            : state.adapter.readLeaf(index);
        },
      }, 4n);
      assert.match(error.message, /leafHash differs from profile-pinned Poseidon/u);
    }

    {
      const state = fresh();
      const error = derive(state, {
        ...state.adapter,
        readLeaf(index) {
          return index === 0
            ? { ...state.leaf(0), successorIndex: 0 }
            : state.adapter.readLeaf(index);
        },
      }, 4n);
      assert.match(error.message, /violates indexed-nullifier sentinel encoding/u);
    }

    {
      const state = fresh();
      const malformed = {
        physicalIndex: 0,
        leafType: PERSISTENT_NULLIFIER_LEAF_TYPES.minimum,
        key: Buffer.alloc(32),
        successorIndex: 2,
        successorKey: encode(5n),
      };
      const error = derive(state, {
        ...state.adapter,
        readLeaf(index) {
          return index === 0
            ? { ...malformed, leafHash: qualification.leafHash(malformed) }
            : state.adapter.readLeaf(index);
        },
      }, 3n);
      assert.equal(error.code, "PERSISTENT_PREDECESSOR_MEMBERSHIP_ROOT");
      assert.equal(error.qualificationTrace.guards.at(-1).code,
        "PERSISTENT_PREDECESSOR_MEMBERSHIP_ROOT");
      assert.equal(error.qualificationTrace.guards.at(-1).passed, false);
    }

    {
      const state = fresh();
      for (const value of [7n, 20n]) {
        const mutation = qualification.derive({
          adapter: state.adapter,
          expectedPreRoot: state.root(),
          key: encode(value),
          normalCount: state.count(),
        });
        state.apply(mutation);
      }
      const honest = state.leaf(2);
      const malformed = {
        physicalIndex: honest.physicalIndex,
        leafType: honest.leafType,
        key: honest.key,
        successorIndex: honest.successorIndex,
        successorKey: encode(10n),
      };
      const error = derive(state, {
        ...state.adapter,
        readLeaf(index) {
          return index === 2
            ? { ...malformed, leafHash: qualification.leafHash(malformed) }
            : state.adapter.readLeaf(index);
        },
      }, 15n);
      assert.equal(error.code, "PERSISTENT_PREDECESSOR_NOT_BRACKETING");
      assert.equal(error.qualificationTrace.guards.at(-1).code,
        "PERSISTENT_PREDECESSOR_NOT_BRACKETING");
      assert.equal(error.qualificationTrace.guards.at(-1).passed, false);
    }

    {
      const state = fresh();
      for (const value of [7n, 20n]) {
        const mutation = qualification.derive({
          adapter: state.adapter,
          expectedPreRoot: state.root(),
          key: encode(value),
          normalCount: state.count(),
        });
        state.apply(mutation);
      }
      const honest = state.leaf(2);
      const malformed = {
        physicalIndex: honest.physicalIndex,
        leafType: honest.leafType,
        key: honest.key,
        successorIndex: honest.successorIndex,
        successorKey: encode(6n),
      };
      const error = derive(state, {
        ...state.adapter,
        readLeaf(index) {
          return index === 2
            ? { ...malformed, leafHash: qualification.leafHash(malformed) }
            : state.adapter.readLeaf(index);
        },
      }, 15n);
      assert.match(error.message, /normal successor must have a strictly greater key/u);
    }
  });

test("qualification kernel rejects malformed node reads in root, predecessor, and append phases",
  () => {
    const qualification =
      createDepth4PersistentIndexedNullifierQualificationKernel();
    const fresh = () => createAdapterState({
      depth: qualification.depth,
      defaults: qualification.defaults(),
      leafHash: qualification.leafHash,
      applyMutation: qualification.apply,
    });
    const derive = (state, adapter) => caught(() => qualification.derive({
      adapter,
      expectedPreRoot: state.root(),
      key: encode(6n),
      normalCount: 0,
    }));
    const cases = [
      {
        name: "root",
        adapter(state) {
          return {
            ...state.adapter,
            readNode(depth, nodeIndex) {
              return depth === qualification.depth && nodeIndex === 0
                ? Buffer.alloc(31)
                : state.adapter.readNode(depth, nodeIndex);
            },
          };
        },
        phase: "root-read",
        code: "PERSISTENT_NODE_INVALID",
      },
      {
        name: "predecessor membership",
        adapter(state) {
          return {
            ...state.adapter,
            readNode(depth, nodeIndex) {
              return depth === 0 && nodeIndex === 1
                ? Buffer.alloc(31)
                : state.adapter.readNode(depth, nodeIndex);
            },
          };
        },
        phase: "predecessor-membership",
        code: "PERSISTENT_NODE_INVALID",
      },
      {
        name: "append nonmembership",
        adapter(state) {
          return {
            ...state.adapter,
            readNode(depth, nodeIndex) {
              return depth === 0 && nodeIndex === 3
                ? Buffer.alloc(31)
                : state.adapter.readNode(depth, nodeIndex);
            },
          };
        },
        phase: "append-empty-membership",
        code: "PERSISTENT_NODE_INVALID",
      },
    ];
    for (const entry of cases) {
      const state = fresh();
      const error = derive(state, entry.adapter(state));
      assert.equal(error.code, entry.code, entry.name);
      assert.match(error.message, /must contain exactly 32 bytes/u, entry.name);
      assert.equal(
        error.qualificationTrace.adapterCalls.at(-1).phase,
        entry.phase,
        entry.name,
      );
    }
  });

test("qualification records adapter faults at append reads and propagates writer faults in order",
  () => {
    const qualification =
      createDepth4PersistentIndexedNullifierQualificationKernel();
    const state = createAdapterState({
      depth: qualification.depth,
      defaults: qualification.defaults(),
      leafHash: qualification.leafHash,
      applyMutation: qualification.apply,
    });
    const derive = (adapter) => caught(() => qualification.derive({
      adapter,
      expectedPreRoot: state.root(),
      key: encode(13n),
      normalCount: 0,
    }));

    let leafReads = 0;
    const appendLeafFault = derive({
      ...state.adapter,
      readLeaf(index) {
        leafReads += 1;
        if (leafReads === 2) throw new Error("injected append leaf fault");
        return state.adapter.readLeaf(index);
      },
    });
    assert.equal(appendLeafFault.code, "PERSISTENT_ADAPTER_READ_LEAF_THREW");
    assert.equal(appendLeafFault.qualificationTrace.adapterCalls.at(-1).phase,
      "append-leaf-read");

    let nodeReads = 0;
    const appendNodeFault = derive({
      ...state.adapter,
      readNode(...args) {
        nodeReads += 1;
        if (nodeReads === 6) throw new Error("injected append node fault");
        return state.adapter.readNode(...args);
      },
    });
    assert.equal(appendNodeFault.code, "PERSISTENT_ADAPTER_READ_NODE_THREW");
    assert.equal(appendNodeFault.qualificationTrace.adapterCalls.at(-1).phase,
      "append-empty-membership");

    const mutation = qualification.derive({
      adapter: state.adapter,
      expectedPreRoot: state.root(),
      key: encode(13n),
      normalCount: 0,
    });
    let nodeWrites = 0;
    let leafWrites = 0;
    assert.throws(
      () => qualification.apply({
        mutation,
        writeNode() {
          nodeWrites += 1;
          throw new Error("injected node writer fault");
        },
        writeLeaf() { leafWrites += 1; },
      }),
      /injected node writer fault/u,
    );
    assert.equal(nodeWrites, 1);
    assert.equal(leafWrites, 0);

    nodeWrites = 0;
    leafWrites = 0;
    assert.throws(
      () => qualification.apply({
        mutation,
        writeNode() { nodeWrites += 1; },
        writeLeaf() {
          leafWrites += 1;
          throw new Error("injected leaf writer fault");
        },
      }),
      /injected leaf writer fault/u,
    );
    assert.equal(nodeWrites, mutation.nullifierNodes.length);
    assert.equal(leafWrites, 1);
  });
