import assert from "node:assert/strict";
import test from "node:test";

import { createDirectV2PoolModel } from "../../action/v2/transition.mjs";
import {
  PERSISTENT_NOTE_DEFAULTS,
  PERSISTENT_TREE_DEPTH,
  persistentTreeDefaults,
} from "./persistent-tree-engine.mjs";

test("persistent note defaults are depth-32 direct-V2 genesis semantics", () => {
  const model = createDirectV2PoolModel({
    profileId: "11".repeat(32),
    maximumLiveNotes: "210000000",
    denominationSats: "10000000",
  });
  const defaults = persistentTreeDefaults();
  assert.equal(defaults.length, PERSISTENT_TREE_DEPTH + 1);
  assert.equal(defaults[PERSISTENT_TREE_DEPTH].toString("hex"), model.state.noteRoot);
  assert.equal(PERSISTENT_NOTE_DEFAULTS[PERSISTENT_TREE_DEPTH].toString("hex"), model.state.noteRoot);
  assert.throws(() => defaults.push(Buffer.alloc(32)), TypeError);
});
