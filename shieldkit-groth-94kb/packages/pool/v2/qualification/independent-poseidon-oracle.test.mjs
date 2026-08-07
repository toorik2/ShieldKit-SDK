import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  hashEmptyNoteLeaf,
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
  hashNoteTreeNode,
  hashOutputNoteLeaf,
  poseidonHash,
} from "../../../action/v2/poseidon.mjs";
import {
  CIRCOMLIB_POSEIDON_CONSTANTS_SHA256,
  createIndependentPoseidonOracle,
  ORACLE_BN254_FR_MODULUS,
} from "./independent-poseidon-oracle.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../../../..");
const parameterSourcePath = resolve(
  root,
  "node_modules/circomlib/circuits/poseidon_constants.circom",
);
const oracle = createIndependentPoseidonOracle({ parameterSourcePath });
const hex = (value) => value.toString(16).padStart(64, "0");

test("independent oracle pins its Circom parameter source and derives domains", () => {
  assert.equal(
    oracle.metadata.parameterSourceSha256,
    CIRCOMLIB_POSEIDON_CONSTANTS_SHA256,
  );
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(oracle.domains).map(([label, value]) => [
        label,
        [value.counter, value.hex],
      ]),
    ),
    {
      NOTE_LEAF: [
        1,
        "0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a",
      ],
      NOTE_TREE_EMPTY: [
        9,
        "28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad",
      ],
      NOTE_TREE_NODE: [
        9,
        "06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153",
      ],
      NULLIFIER_TREE_LEAF: [
        5,
        "21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2",
      ],
      NULLIFIER_TREE_EMPTY: [
        3,
        "2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb",
      ],
      NULLIFIER_TREE_NODE: [
        0,
        "241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4",
      ],
    },
  );
});

test("independent oracle reproduces the frozen tree known-answer vectors", () => {
  const emptyNote = oracle.hashEmptyNoteLeaf();
  const emptyNullifier = oracle.hashIndexedNullifierLeaf([
    0n,
    0n,
    0n,
    0n,
    0n,
  ]);
  const minimum = oracle.hashIndexedNullifierLeaf([1n, 0n, 0n, 1n, 0n]);
  assert.deepEqual(
    {
      emptyNote: hex(emptyNote),
      noteParent: hex(oracle.hashNoteTreeNode(emptyNote, emptyNote)),
      emptyNullifier: hex(emptyNullifier),
      minimum: hex(minimum),
      nullifierParent: hex(
        oracle.hashIndexedNullifierNode(minimum, emptyNullifier),
      ),
      outputNoteLeaf: hex(oracle.hashOutputNoteLeaf(7n, 11n)),
    },
    {
      emptyNote:
        "24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081",
      noteParent:
        "265399a22fcc1a8f382ddeec66cc3b4fee4e52a4352d5209fcad526fd21e769c",
      emptyNullifier:
        "18df533689e5101f3e88e6e91339f278f68a84c86f22997b1bb28be7dec598a6",
      minimum:
        "04b96bcec386361928f02ccd62ed02446db3d900d3ce3083f6dbd5007b8d20e5",
      nullifierParent:
        "1fd573ef8ff8f6825abec3fe3b725941e4035344df59e31ee23a9766de8a9221",
      outputNoteLeaf:
        "0cda43a183b48956f4e64cb87efdcd9a716e8ad1354640895240cc3f2ffb6f09",
    },
  );
});

test("independent P2/P3/P6 permutation agrees at Fr boundaries and mixed inputs", () => {
  const last = ORACLE_BN254_FR_MODULUS - 1n;
  const vectors = [
    [0n, last],
    [last, 0n, 7n],
    [1n, 2n, 3n, 4n, 5n, 6n],
    [last, last, last, last, last, last],
  ];
  for (const vector of vectors) {
    assert.equal(oracle.poseidon(...vector), poseidonHash(...vector));
  }
  assert.equal(oracle.hashEmptyNoteLeaf(), hashEmptyNoteLeaf());
  assert.equal(
    oracle.hashNoteTreeNode(1n, last),
    hashNoteTreeNode(1n, last),
  );
  assert.equal(
    oracle.hashIndexedNullifierLeaf([2n, 7n, last, 1n, 0n]),
    hashIndexedNullifierLeaf([2n, 7n, last, 1n, 0n]),
  );
  assert.equal(
    oracle.hashIndexedNullifierNode(last, 1n),
    hashIndexedNullifierNode(last, 1n),
  );
  assert.equal(
    oracle.hashOutputNoteLeaf(last, 0n),
    hashOutputNoteLeaf(last, 0n),
  );
});

test("oracle implementation imports neither production Poseidon nor poseidon-lite", () => {
  const source = readFileSync(
    resolve(here, "independent-poseidon-oracle.mjs"),
    "utf8",
  );
  assert.doesNotMatch(source, /poseidon-lite/);
  assert.doesNotMatch(source, /action\/v2\/(?:poseidon|domains)/);
});
