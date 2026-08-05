import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, resolve } from "node:path";

export const ORACLE_BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const CIRCOMLIB_POSEIDON_CONSTANTS_SHA256 =
  "94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee";
export const ORACLE_DOMAIN_PREFIX =
  "ShieldKit/PoolActionV2Direct/domain/v1/";

const ROUND_PARTIAL = Object.freeze({
  3: 57,
  4: 56,
  7: 63,
});
const SUPPORTED_ARITIES = Object.freeze(new Set([2, 3, 6]));
const TREE_DOMAIN_LABELS = Object.freeze([
  "NOTE_LEAF",
  "NOTE_TREE_EMPTY",
  "NOTE_TREE_NODE",
  "NULLIFIER_TREE_LEAF",
  "NULLIFIER_TREE_EMPTY",
  "NULLIFIER_TREE_NODE",
]);

export class IndependentPoseidonOracleError extends Error {
  constructor(message) {
    super(message);
    this.name = "IndependentPoseidonOracleError";
  }
}

const fail = (message) => {
  throw new IndependentPoseidonOracleError(message);
};
const freeze = (value) => Object.freeze(value);
const mod = (value) => {
  const reduced = value % ORACLE_BN254_FR_MODULUS;
  return reduced < 0n ? reduced + ORACLE_BN254_FR_MODULUS : reduced;
};
const pow5 = (value) => {
  const square = mod(value * value);
  return mod(square * square * value);
};
const canonicalFr = (value, label) => {
  if (
    typeof value !== "bigint" ||
    value < 0n ||
    value >= ORACLE_BN254_FR_MODULUS
  ) fail(`${label} must be a canonical BN254 Fr bigint`);
  return value;
};

function checkedParameterSource(path) {
  if (typeof path !== "string" || !isAbsolute(path)) {
    fail("Poseidon parameter source must be an absolute path");
  }
  const requested = resolve(path);
  const observed = lstatSync(requested);
  if (!observed.isFile() || observed.isSymbolicLink()) {
    fail("Poseidon parameter source must be a direct regular file");
  }
  if (realpathSync(requested) !== requested) {
    fail("Poseidon parameter source must not traverse a symbolic link");
  }
  const bytes = readFileSync(requested);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (sha256 !== CIRCOMLIB_POSEIDON_CONSTANTS_SHA256) {
    fail(
      `Poseidon parameter source hash ${sha256} differs from the frozen circomlib source`,
    );
  }
  return freeze({
    bytes,
    path: requested,
    sha256,
  });
}

function functionBody(source, name) {
  const marker = `function ${name}(t)`;
  const start = source.indexOf(marker);
  if (start === -1) fail(`Poseidon parameter source is missing ${name}`);
  const next = source.indexOf("\nfunction ", start + marker.length);
  return source.slice(start, next === -1 ? source.length : next);
}

function branchArray(functionSource, width, label) {
  const branch = new RegExp(`(?:if|else if) \\(t==${width}\\) \\{`).exec(
    functionSource,
  );
  if (!branch) fail(`${label} is missing state width ${width}`);
  const returnAt = functionSource.indexOf("return", branch.index);
  const openAt = functionSource.indexOf("[", returnAt);
  if (returnAt === -1 || openAt === -1) {
    fail(`${label} width ${width} has no returned array`);
  }
  let depth = 0;
  let closeAt = -1;
  for (let index = openAt; index < functionSource.length; index += 1) {
    if (functionSource[index] === "[") depth += 1;
    if (functionSource[index] === "]") {
      depth -= 1;
      if (depth === 0) {
        closeAt = index;
        break;
      }
    }
  }
  if (closeAt === -1) fail(`${label} width ${width} array is unterminated`);
  const values = [
    ...functionSource.slice(openAt, closeAt + 1).matchAll(/0x[0-9a-f]+/g),
  ].map((match) => BigInt(match[0]));
  if (values.length === 0) fail(`${label} width ${width} array is empty`);
  return freeze(values);
}

function parseParameters(bytes) {
  const source = bytes.toString("ascii");
  const bodies = Object.fromEntries(
    ["POSEIDON_C", "POSEIDON_M", "POSEIDON_P", "POSEIDON_S"].map((name) => [
      name,
      functionBody(source, name),
    ]),
  );
  const byWidth = {};
  for (const width of Object.keys(ROUND_PARTIAL).map(Number)) {
    const partialRounds = ROUND_PARTIAL[width];
    const C = branchArray(bodies.POSEIDON_C, width, "POSEIDON_C");
    const M = branchArray(bodies.POSEIDON_M, width, "POSEIDON_M");
    const P = branchArray(bodies.POSEIDON_P, width, "POSEIDON_P");
    const S = branchArray(bodies.POSEIDON_S, width, "POSEIDON_S");
    const expectedC = (width * 8) + partialRounds;
    const expectedMatrix = width * width;
    const expectedS = partialRounds * ((width * 2) - 1);
    if (
      C.length !== expectedC ||
      M.length !== expectedMatrix ||
      P.length !== expectedMatrix ||
      S.length !== expectedS
    ) {
      fail(
        `Poseidon width ${width} parameter dimensions differ: ` +
          `C=${C.length}/${expectedC}, M=${M.length}/${expectedMatrix}, ` +
          `P=${P.length}/${expectedMatrix}, S=${S.length}/${expectedS}`,
      );
    }
    for (const [name, values] of Object.entries({ C, M, P, S })) {
      values.forEach((value, index) =>
        canonicalFr(value, `${name}[${index}]`)
      );
    }
    byWidth[width] = freeze({ C, M, P, S, partialRounds, width });
  }
  return freeze(byWidth);
}

function fullMix(state, matrix, width) {
  const output = [];
  for (let column = 0; column < width; column += 1) {
    let value = 0n;
    for (let row = 0; row < width; row += 1) {
      value += state[row] * matrix[(row * width) + column];
    }
    output.push(mod(value));
  }
  return output;
}

function sparseMix(state, sparse, round, width) {
  const offset = round * ((width * 2) - 1);
  let first = 0n;
  for (let index = 0; index < width; index += 1) {
    first += sparse[offset + index] * state[index];
  }
  const output = [mod(first)];
  for (let index = 1; index < width; index += 1) {
    output.push(
      mod(
        state[index] +
          (state[0] * sparse[offset + width + index - 1]),
      ),
    );
  }
  return output;
}

function optimizedPoseidon(inputs, parameters) {
  const { C, M, P, S, partialRounds, width } = parameters;
  let state = [0n, ...inputs];
  for (let index = 0; index < width; index += 1) {
    state[index] = mod(state[index] + C[index]);
  }

  for (let round = 0; round < 3; round += 1) {
    state = state.map(pow5);
    const constantOffset = (round + 1) * width;
    state = state.map((value, index) =>
      mod(value + C[constantOffset + index])
    );
    state = fullMix(state, M, width);
  }

  state = state.map(pow5);
  state = state.map((value, index) => mod(value + C[(4 * width) + index]));
  state = fullMix(state, P, width);

  for (let round = 0; round < partialRounds; round += 1) {
    state[0] = mod(
      pow5(state[0]) + C[(5 * width) + round],
    );
    state = sparseMix(state, S, round, width);
  }

  for (let round = 0; round < 3; round += 1) {
    state = state.map(pow5);
    const constantOffset = (5 * width) + partialRounds + (round * width);
    state = state.map((value, index) =>
      mod(value + C[constantOffset + index])
    );
    state = fullMix(state, M, width);
  }

  state = state.map(pow5);
  return fullMix(state, M, width)[0];
}

function deriveDomain(label) {
  if (typeof label !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(label)) {
    fail("oracle domain label must be canonical uppercase ASCII");
  }
  for (let counter = 0; counter <= 0xffff_ffff; counter += 1) {
    const encodedCounter = Buffer.alloc(4);
    encodedCounter.writeUInt32BE(counter);
    const digest = createHash("sha256")
      .update(ORACLE_DOMAIN_PREFIX, "ascii")
      .update(label, "ascii")
      .update(encodedCounter)
      .digest();
    const value = BigInt(`0x${digest.toString("hex")}`);
    if (value > 0n && value < ORACLE_BN254_FR_MODULUS) {
      return freeze({
        counter,
        hex: digest.toString("hex"),
        value,
      });
    }
  }
  fail(`oracle domain derivation exhausted for ${label}`);
}

export function createIndependentPoseidonOracle({
  parameterSourcePath,
} = {}) {
  const source = checkedParameterSource(parameterSourcePath);
  const parameters = parseParameters(source.bytes);
  const domains = freeze(Object.fromEntries(
    TREE_DOMAIN_LABELS.map((label) => [label, deriveDomain(label)]),
  ));
  const poseidon = (...inputs) => {
    if (!SUPPORTED_ARITIES.has(inputs.length)) {
      fail("oracle exposes only the tree-required Poseidon arities 2, 3, and 6");
    }
    inputs.forEach((value, index) =>
      canonicalFr(value, `oracle Poseidon input ${index}`)
    );
    return canonicalFr(
      optimizedPoseidon(inputs, parameters[inputs.length + 1]),
      "oracle Poseidon output",
    );
  };
  const hashIndexedNullifierLeaf = (inputs) => {
    if (!Array.isArray(inputs) || inputs.length !== 5) {
      fail("oracle indexed-nullifier leaf requires five fields");
    }
    inputs.forEach((value, index) =>
      canonicalFr(value, `oracle indexed-nullifier leaf field ${index}`)
    );
    if (inputs[0] === 0n) {
      if (inputs.some((value) => value !== 0n)) {
        fail("oracle empty indexed-nullifier leaf fields must all be zero");
      }
      return poseidon(domains.NULLIFIER_TREE_EMPTY.value, 0n);
    }
    return poseidon(domains.NULLIFIER_TREE_LEAF.value, ...inputs);
  };
  return freeze({
    metadata: freeze({
      implementation:
        "independent-bigint-optimized-circomlib-poseidon-oracle-v1",
      parameterSourcePath: source.path,
      parameterSourceSha256: source.sha256,
      supportedArities: freeze([2, 3, 6]),
    }),
    domains,
    poseidon,
    hashEmptyNoteLeaf: () =>
      poseidon(domains.NOTE_TREE_EMPTY.value, 0n),
    hashNoteTreeNode: (left, right) =>
      poseidon(
        domains.NOTE_TREE_NODE.value,
        canonicalFr(left, "oracle left note node"),
        canonicalFr(right, "oracle right note node"),
      ),
    hashOutputNoteLeaf: (noteCommitment, recordTag) =>
      poseidon(
        domains.NOTE_LEAF.value,
        canonicalFr(noteCommitment, "oracle note commitment"),
        canonicalFr(recordTag, "oracle record tag"),
      ),
    hashIndexedNullifierLeaf,
    hashIndexedNullifierNode: (left, right) =>
      poseidon(
        domains.NULLIFIER_TREE_NODE.value,
        canonicalFr(left, "oracle left nullifier node"),
        canonicalFr(right, "oracle right nullifier node"),
      ),
  });
}
