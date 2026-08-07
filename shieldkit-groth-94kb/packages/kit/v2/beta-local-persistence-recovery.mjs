/**
 * Beta-only local persistence/recovery evidence.
 *
 * This is deliberately outside the normal action lifecycle and has no network,
 * descriptor, broadcaster, or final-runtime dependency. Its narrow claim is
 * stronger than the old in-memory demonstration: three exact Libauth-bound
 * packets, proof bindings, and locally signed transaction IDs are bound into
 * V2DirectStore canonical checkpoints. Every checkpoint is closed and
 * cold-reopened before the next transition is accepted.
 */
import { createHash } from 'node:crypto';

import {
  applyDirectV2Transition,
  createDirectV2PoolModel,
} from '../../action/v2/transition.mjs';
import {
  actionPacketPublicLimbs,
  decodeActionPacket,
  digestActionPacket,
} from '../../action/v2/packet.mjs';
import {
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  hashIndexedNullifierLeaf,
  hashIndexedNullifierNode,
} from '../../action/v2/poseidon.mjs';
import {
  canonicalizeJcs,
} from '../../profile/v2/profile-core.mjs';
import {
  validateV2BetaLocalProfilePackage,
  V2_BETA_LOCAL_ELIGIBILITY,
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../../profile/v2/beta-local-profile.mjs';
import {
  openExistingV2DirectStore,
  openV2DirectStore,
} from '../../pool/v2/store.mjs';
import {
  createV2PrivateActionStore,
} from './private-action-store.mjs';

export const V2_BETA_LOCAL_PERSISTENCE_RECOVERY_SCHEMA =
  'shieldkit-v2-direct-beta-single-contributor-persistence-recovery-v2';
export const V2_BETA_LOCAL_PERSISTENCE_RECOVERY_STATUS =
  'beta-single-contributor-evidence-bound-cold-reopen-verified-unqualified';

const HASH = /^[0-9a-f]{64}$/u;
const OPERATION_ID = /^v2op:[0-9a-f]{64}$/u;
const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);

export class V2BetaLocalPersistenceRecoveryError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'V2BetaLocalPersistenceRecoveryError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaLocalPersistenceRecoveryError(code, message, options);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalSha256 = (value) => sha256(Buffer.from(canonicalizeJcs(value), 'utf8'));
const frBytes = (value) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex');

function plain(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BETA_PERSISTENCE_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    fail('BETA_PERSISTENCE_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('BETA_PERSISTENCE_INVALID', `${label} must be lowercase 32-byte hexadecimal`);
  }
  return value;
}

function integer(value, label, low = 0, high = 0xffff_ffff) {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail('BETA_PERSISTENCE_INVALID', `${label} is outside its supported integer range`);
  }
  return value;
}

function decimal(value, label, { nonzero = false } = {}) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(value)
    || (nonzero && BigInt(value) === 0n) || BigInt(value) > 0xffff_ffffn) {
    fail('BETA_PERSISTENCE_INVALID', `${label} must be a canonical supported decimal`);
  }
  return value;
}

function capacity(value, label = 'maximumLiveNotes') {
  const normalized = decimal(value, label, { nonzero: true });
  if (BigInt(normalized) > 210_000_000n) {
    fail(
      'BETA_PERSISTENCE_INVALID',
      `${label} must not exceed 210000000`,
    );
  }
  return normalized;
}

function falseClaims(value, label) {
  exact(value, Object.keys(V2_BETA_LOCAL_FALSE_CLAIMS), label);
  if (canonicalizeJcs(value) !== canonicalizeJcs(V2_BETA_LOCAL_FALSE_CLAIMS)) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', `${label} left the beta-only claim boundary`);
  }
  return V2_BETA_LOCAL_FALSE_CLAIMS;
}

function profileBinding(value) {
  exact(value, ['betaProfilePackage', 'instanceId', 'profileCore'], 'beta persistence profile binding');
  let betaProfilePackage;
  try {
    betaProfilePackage = validateV2BetaLocalProfilePackage(value.betaProfilePackage, value.profileCore);
  } catch (error) {
    fail('BETA_PERSISTENCE_PROFILE_REJECTED', error instanceof Error ? error.message : 'invalid beta profile package', { cause: error });
  }
  const instanceId = hash(value.instanceId, 'instanceId');
  if (value.profileCore?.network?.id !== 2 || value.profileCore?.denominationSats !== '10000000') {
    fail('BETA_PERSISTENCE_PROFILE_REJECTED', 'beta persistence is restricted to the exact Chipnet beta profile');
  }
  return Object.freeze({
    betaProfilePackage,
    instanceId,
    profileCore: value.profileCore,
    profileId: betaProfilePackage.profileId,
  });
}

function verification(value, expected, label) {
  exact(value, Object.keys(expected), label);
  for (const [key, expectedValue] of Object.entries(expected)) {
    if ((expectedValue !== null && typeof expectedValue === 'object')
      ? canonicalizeJcs(value[key]) !== canonicalizeJcs(expectedValue)
      : value[key] !== expectedValue) {
      fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', `${label}.${key} is not the independently verified beta result`);
    }
  }
  return value;
}

function betaLibauthClaims(value) {
  // `bchVm` is the broad top-level qualification claim and remains false for
  // this beta bundle. The nested Libauth evidence uses the narrower,
  // independently checked `libauthBch2026` claim instead, so its exact schema
  // intentionally omits `bchVm` (matching validatePf10BetaLibauthEvidence).
  const betaBoundaryClaims = Object.fromEntries(
    Object.entries(V2_BETA_LOCAL_FALSE_CLAIMS)
      .filter(([name]) => name !== 'bchVm'),
  );
  const expected = {
    ...betaBoundaryClaims,
    authenticatedSerializedParentOutputs: true,
    bchnMempool: false,
    bchnMined: false,
    leanBch: false,
    libauthBch2026: true,
    liveChainParentProvenance: false,
    productionSettlementBuilderPath: true,
    unmodifiedMaintainerBenchmark: false,
  };
  exact(value, Object.keys(expected), 'beta Libauth evidence claims');
  if (canonicalizeJcs(value) !== canonicalizeJcs(expected)) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta Libauth claims are outside the local unqualified boundary');
  }
  return Object.freeze(expected);
}

function runtimeBinding(value, binding) {
  exact(value, ['manifest', 'manifestSha256', 'verification'], 'beta runtime binding');
  const manifest = exact(value.manifest, [
    'artifacts', 'assuranceClass', 'claims', 'eligibility', 'identity', 'profile',
    'proofArtifacts', 'proofQualification', 'runtime', 'schema', 'status',
  ], 'beta runtime manifest');
  if (canonicalSha256(manifest) !== hash(value.manifestSha256, 'runtime manifestSha256')
    || manifest.schema !== 'shieldkit-v2-direct-pf10-beta-local-runtime-bundle-v2'
    || manifest.status !== 'beta-local-runtime-built-unqualified'
    || manifest.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || manifest.assuranceClass !== 'beta-single-contributor') {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta runtime manifest is not canonical beta runtime evidence');
  }
  falseClaims(manifest.claims, 'beta runtime manifest claims');
  if (manifest.profile?.profileId !== binding.profileId
    || manifest.identity?.instanceId !== binding.instanceId
    || manifest.identity?.maximumLiveNotes !== binding.maximumLiveNotes
    || manifest.identity?.denominationSats !== binding.profileCore.denominationSats
    || !HASH.test(manifest.runtime?.materialSha256)) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta runtime manifest does not bind the exact profile, instance, or material');
  }
  verification(value.verification, {
    schema: 'shieldkit-v2-direct-pf10-beta-local-runtime-verification-v1',
    status: 'beta-runtime-reverified-unqualified',
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
    manifestSha256: value.manifestSha256,
    runtimeMaterialSha256: manifest.runtime.materialSha256,
  }, 'beta runtime verification');
  return Object.freeze({ manifest, manifestSha256: value.manifestSha256, runtimeMaterialSha256: manifest.runtime.materialSha256 });
}

function proofBinding(value, binding) {
  exact(value, ['evidence', 'evidenceSha256', 'verification'], 'beta proof qualification binding');
  const evidence = exact(value.evidence, [
    'actions', 'betaProvenance', 'claims', 'evidenceClass', 'eligibility',
    'fixture', 'identity', 'measurements', 'prover', 'schema', 'sourceArtifacts', 'versions',
  ], 'beta proof qualification evidence');
  if (canonicalSha256(evidence) !== hash(value.evidenceSha256, 'proof evidenceSha256')
    || evidence.schema !== 'shieldkit-v2-direct-beta-groth16-qualification-v1'
    || evidence.evidenceClass !== 'deterministic-beta-single-contributor-groth16-integration-evidence'
    || evidence.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || evidence.identity?.profileId !== binding.profileId
    || evidence.identity?.instanceId !== binding.instanceId
    || evidence.identity?.maximumLiveNotes !== binding.maximumLiveNotes
    || evidence.identity?.denominationSats !== binding.profileCore.denominationSats) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta proof evidence does not bind the exact beta identity');
  }
  falseClaims(evidence.claims, 'beta proof evidence claims');
  if (evidence.sourceArtifacts?.profileCore?.sha256 !== binding.betaProfilePackage.profileCoreSha256
    || evidence.sourceArtifacts?.r1cs?.sha256 !== binding.betaProfilePackage.artifacts.r1cs.sha256
    || evidence.sourceArtifacts?.wasm?.sha256 !== binding.betaProfilePackage.artifacts.witnessWasm.sha256
    || evidence.sourceArtifacts?.betaProvingKey?.sha256 !== binding.betaProfilePackage.artifacts.betaProvingKey.sha256
    || evidence.sourceArtifacts?.verificationKey?.sha256 !== binding.betaProfilePackage.artifacts.verificationKey.sha256) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta proof evidence artifact pins differ from beta profile/runtime material');
  }
  // Qualification is intentionally independent of the transaction-context
  // packets. It establishes ceremony/profile/relation evidence only; the
  // exact packets replayed below come solely from the Libauth qualification.
  verification(value.verification, {
    schema: 'shieldkit-v2-direct-beta-groth16-qualification-verification-v1',
    evidenceSha256: value.evidenceSha256,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    profileId: binding.profileId,
    instanceId: binding.instanceId,
    maximumLiveNotes: binding.maximumLiveNotes,
    status: 'beta-proof-qualification-reverified-unqualified',
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
  }, 'beta proof verification');
  return Object.freeze({ evidence, evidenceSha256: value.evidenceSha256 });
}

function libauthBinding(value, binding, runtime, proof) {
  exact(value, ['evidence', 'evidenceSha256', 'verification'], 'beta Libauth qualification binding');
  const evidence = value.evidence;
  if (canonicalSha256(evidence) !== hash(value.evidenceSha256, 'Libauth evidenceSha256')
    || evidence?.schema !== 'shieldkit-v2-direct-pf10-beta-local-libauth-evidence-v1'
    || evidence?.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || evidence.identity?.profileId !== binding.profileId
    || evidence.identity?.instanceId !== binding.instanceId
    || evidence.identity?.runtimeMaterialSha256 !== runtime.runtimeMaterialSha256
    || evidence.betaProofQualification?.sha256 !== proof.evidenceSha256
    || evidence.betaProofQualification?.profileId !== binding.profileId
    || evidence.betaProofQualification?.instanceId !== binding.instanceId) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta Libauth evidence does not bind the verified proof/runtime/profile identity');
  }
  betaLibauthClaims(evidence.claims);
  const actions = evidence.pf10FusedQGenesisActions?.actions;
  if (!Array.isArray(actions) || actions.length !== ACTIONS.length) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta Libauth evidence must contain exactly three signed actions');
  }
  const boundActions = actions.map((action, index) => {
    if (action?.kind !== ACTIONS[index] || !HASH.test(action.transactionId)
      || !HASH.test(action.packetSha256) || !HASH.test(action.proofBindingSha256)
      || !HASH.test(action.contextHash) || action.proofVerified !== true
      || action.inputCount !== 13 || typeof action.packetHex !== 'string'
      || !/^[0-9a-f]{1104}$/u.test(action.packetHex)
      || !Array.isArray(action.publicInputs) || action.publicInputs.length !== 2
      || action.publicInputs.some((entry) => typeof entry !== 'string'
        || !/^(0|[1-9][0-9]*)$/u.test(entry) || BigInt(entry) > ((1n << 128n) - 1n))
      || action.proof === null || Array.isArray(action.proof)
      || typeof action.proof !== 'object'
      || Object.getPrototypeOf(action.proof) !== Object.prototype) {
      fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', `beta Libauth ${ACTIONS[index]} action lacks an exact packet/proof transaction binding`);
    }
    const packet = Buffer.from(action.packetHex, 'hex');
    if (sha256(packet) !== action.packetSha256
      || canonicalSha256({ packetSha256: action.packetSha256, proof: action.proof, publicInputs: action.publicInputs }) !== action.proofBindingSha256) {
      fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', `beta Libauth ${ACTIONS[index]} packet or proof binding is noncanonical`);
    }
    return Object.freeze({
      kind: action.kind,
      packet,
      packetSha256: action.packetSha256,
      proofBindingSha256: action.proofBindingSha256,
      transactionId: action.transactionId,
      publicInputs: Object.freeze([...action.publicInputs]),
    });
  });
  verification(value.verification, {
    schema: 'shieldkit-v2-direct-pf10-beta-local-libauth-verification-v1',
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    evidenceSha256: value.evidenceSha256,
    proofEvidenceReverified: true,
    status: 'beta-local-libauth-reverified-unqualified',
    transactionSpecificProofs: value.verification.transactionSpecificProofs,
    transactions: value.verification.transactions,
  }, 'beta Libauth verification');
  if (!Array.isArray(value.verification.transactionSpecificProofs)
    || value.verification.transactionSpecificProofs.length !== ACTIONS.length
    || value.verification.transactionSpecificProofs.some((entry, index) =>
      entry?.kind !== ACTIONS[index]
      || entry.packetSha256 !== boundActions[index].packetSha256
      || entry.proofBindingSha256 !== boundActions[index].proofBindingSha256
      || entry.proofVerified !== true
      || entry.transactionId !== boundActions[index].transactionId)
    || !Array.isArray(value.verification.transactions) || value.verification.transactions.length !== ACTIONS.length
    || value.verification.transactions.some((entry, index) => entry?.kind !== ACTIONS[index]
      || entry.transactionId !== boundActions[index].transactionId || entry.inputs !== 13)) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta Libauth verification does not enumerate the exact three packet/proof/transaction bindings');
  }
  return Object.freeze({ evidence, evidenceSha256: value.evidenceSha256, actions: boundActions });
}

function preparedAction(value, index, packet) {
  exact(value, ['expectedActionSequence', 'kind', 'operationId', 'output', 'publicNullifier'], `preparedActions[${index}]`);
  if (value.kind !== ACTIONS[index] || value.expectedActionSequence !== index
    || typeof value.operationId !== 'string' || !OPERATION_ID.test(value.operationId)) {
    fail('BETA_PERSISTENCE_INVALID', 'prepared beta actions must be ordered deposit, transfer, withdrawal with canonical IDs');
  }
  if (index < 2) {
    if (value.output?.public?.outputNoteLeaf !== packet.outputNoteLeaf
      || !(value.output.public.encryptedRecord instanceof Uint8Array)
      || !Buffer.from(value.output.public.encryptedRecord).equals(packet.encryptedRecord)) {
      fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', `${packet.kind} private record does not match its proof packet public output`);
    }
  } else if (value.output !== null) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'withdrawal private record must have no output');
  }
  if ((index === 0 && value.publicNullifier !== null)
    || (index > 0 && value.publicNullifier !== packet.publicNullifier)) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', `${packet.kind} private record does not match its proof packet nullifier`);
  }
  return value;
}

function input(value) {
  exact(value, [
    'betaLibauthQualification', 'betaProfilePackage', 'betaProofQualification',
    'betaRuntime', 'carrierCount', 'genesis', 'instanceId', 'maximumLiveNotes',
    'preparedActions', 'privateActionDirectory', 'profileCore', 'stateStorePath',
  ], 'beta persistence recovery input');
  const selectedCapacity = capacity(value.maximumLiveNotes);
  const binding = Object.freeze({
    ...profileBinding({
      betaProfilePackage: value.betaProfilePackage,
      instanceId: value.instanceId,
      profileCore: value.profileCore,
    }),
    maximumLiveNotes: selectedCapacity,
  });
  if (!Array.isArray(value.preparedActions) || value.preparedActions.length !== ACTIONS.length
    || new Set(value.preparedActions.map((action) => action?.operationId)).size !== ACTIONS.length) {
    fail('BETA_PERSISTENCE_INVALID', 'preparedActions must contain three distinct beta actions');
  }
  exact(value.genesis, ['blockHash', 'height', 'outpoint'], 'beta persistence genesis');
  exact(value.genesis.outpoint, ['txid', 'vout'], 'beta persistence genesis outpoint');
  if (typeof value.privateActionDirectory !== 'string' || value.privateActionDirectory.length === 0
    || typeof value.stateStorePath !== 'string' || value.stateStorePath.length === 0) {
    fail('BETA_PERSISTENCE_INVALID', 'private state and action-store paths are required');
  }
  const runtime = runtimeBinding(value.betaRuntime, binding);
  const proof = proofBinding(value.betaProofQualification, binding);
  const libauth = libauthBinding(value.betaLibauthQualification, binding, runtime, proof);
  const decoded = libauth.actions.map((action) => {
    try { return decodeActionPacket(action.packet, { denominationSats: binding.profileCore.denominationSats }); }
    catch (error) { fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', error instanceof Error ? error.message : 'Libauth packet decoding failed', { cause: error }); }
  });
  for (const [index, packet] of decoded.entries()) {
    if (packet.kind !== ACTIONS[index] || packet.networkId !== binding.profileCore.network.id
      || packet.instanceId !== binding.instanceId || packet.preState.profileId !== binding.profileId
      || packet.postState.profileId !== binding.profileId
      || packet.preState.maximumLiveNotes !== selectedCapacity
      || packet.postState.maximumLiveNotes !== selectedCapacity) {
      fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'proof packet differs from beta profile/instance/capacity binding');
    }
    const expectedPublicInputs = actionPacketPublicLimbs(libauth.actions[index].packet, { denominationSats: binding.profileCore.denominationSats });
    if (canonicalizeJcs(libauth.actions[index].publicInputs) !== canonicalizeJcs(expectedPublicInputs)) {
      fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta Libauth public inputs do not equal the exact decoded packet');
    }
  }
  const preparedActions = Object.freeze(value.preparedActions.map((entry, index) => preparedAction(entry, index, decoded[index])));
  return Object.freeze({
    ...binding,
    carrierCount: integer(value.carrierCount, 'carrierCount', 1, 0xff),
    genesis: Object.freeze({ blockHash: hash(value.genesis.blockHash, 'genesis.blockHash'), height: integer(value.genesis.height, 'genesis.height'), outpoint: Object.freeze({ txid: hash(value.genesis.outpoint.txid, 'genesis.outpoint.txid'), vout: integer(value.genesis.outpoint.vout, 'genesis.outpoint.vout') }) }),
    maximumLiveNotes: selectedCapacity,
    preparedActions,
    privateActionDirectory: value.privateActionDirectory,
    stateStorePath: value.stateStorePath,
    runtime,
    proof,
    libauth,
    decoded,
  });
}

function applyPackets(input) {
  let current = createDirectV2PoolModel({ profileId: input.profileId, maximumLiveNotes: input.maximumLiveNotes, denominationSats: input.profileCore.denominationSats });
  const transitions = [];
  for (const [index, packet] of input.decoded.entries()) {
    const common = { kind: packet.kind, networkId: packet.networkId, profileId: input.profileId, instanceId: input.instanceId, denominationSats: input.profileCore.denominationSats, preState: current.state, noteTree: current.noteTree, nullifierTree: current.nullifierTree, transactionContextHash: packet.transactionContextHash, expectedPostState: packet.postState };
    let transition;
    if (packet.kind === 'deposit') transition = applyDirectV2Transition({ ...common, output: { outputNoteLeaf: packet.outputNoteLeaf, encryptedRecord: packet.encryptedRecord } });
    else if (packet.kind === 'transfer') transition = applyDirectV2Transition({ ...common, output: { outputNoteLeaf: packet.outputNoteLeaf, encryptedRecord: packet.encryptedRecord }, spend: { inputNoteLeaf: current.noteTree.leaves[0].toString(16).padStart(64, '0'), noteIndex: '0', publicNullifier: packet.publicNullifier } });
    else transition = applyDirectV2Transition({ ...common, spend: { inputNoteLeaf: current.noteTree.leaves[1].toString(16).padStart(64, '0'), noteIndex: '1', publicNullifier: packet.publicNullifier }, withdrawalLockingBytecodeHash: packet.withdrawalLockingBytecodeHash });
    const exactDigest = digestActionPacket(input.libauth.actions[index].packet, { denominationSats: input.profileCore.denominationSats }).toString('hex');
    if (transition.packetDigest !== exactDigest) fail('BETA_PERSISTENCE_REPLAY_REJECTED', 'deterministic transition did not recreate the exact Libauth packet');
    transitions.push(transition); current = transition;
  }
  return Object.freeze({ initial: createDirectV2PoolModel({ profileId: input.profileId, maximumLiveNotes: input.maximumLiveNotes, denominationSats: input.profileCore.denominationSats }), transitions: Object.freeze(transitions), terminal: current });
}

function noteSnapshot(tree, transactionIds) {
  const nodes = tree.nodes.map((node) => Object.freeze({ depth: node.level, nodeIndex: node.index, nodeHash: frBytes(node.value) }));
  const nodeByCoordinate = new Map(nodes.map((node) => [`${node.depth}:${node.nodeIndex}`, node]));
  const frontier = [];
  for (let depth = 0; depth < tree.depth; depth += 1) {
    if (((BigInt(tree.nextIndex) >> BigInt(depth)) & 1n) === 0n) continue;
    const node = nodeByCoordinate.get(`${depth}:${Math.floor(tree.nextIndex / (2 ** depth)) - 1}`);
    if (node === undefined) fail('BETA_PERSISTENCE_REPLAY_REJECTED', 'derived note frontier is absent from the deterministic tree');
    frontier.push(Object.freeze({ depth, nodeHash: node.nodeHash }));
  }
  return Object.freeze({
    nodes,
    frontier: Object.freeze(frontier),
    leaves: tree.leaves.map((leaf, noteIndex) => Object.freeze({ noteIndex, leafHash: frBytes(leaf), encryptedRecord: Buffer.from(transactionIds.outputs[noteIndex].encryptedRecord), actionSequence: noteIndex + 1, transactionId: Buffer.from(transactionIds.ids[noteIndex], 'hex') })),
  });
}

function nullifierSnapshot(tree) {
  const leafType = Object.freeze({ min: 1, normal: 2, max: 3 });
  const defaults = [hashIndexedNullifierLeaf([0n, 0n, 0n, 0n, 0n])];
  for (let depth = 0; depth < tree.depth; depth += 1) defaults.push(hashIndexedNullifierNode(defaults[depth], defaults[depth]));
  const leafHash = (leaf) => hashIndexedNullifierLeaf(leaf.type === 'min'
    ? [1n, BigInt(leaf.index), 0n, BigInt(leaf.successorIndex), BigInt(`0x${leaf.successorKey}`)]
    : leaf.type === 'max' ? [3n, BigInt(leaf.index), 0n, BigInt(leaf.successorIndex), 0n]
      : [2n, BigInt(leaf.index), BigInt(`0x${leaf.key}`), BigInt(leaf.successorIndex), BigInt(`0x${leaf.successorKey}`)]);
  let level = new Map(tree.leaves.map((leaf) => [leaf.index, leafHash(leaf)]));
  const nodes = [...level.entries()].map(([nodeIndex, nodeHash]) => ({ depth: 0, nodeIndex, nodeHash: frBytes(nodeHash) }));
  for (let depth = 0; depth < tree.depth; depth += 1) {
    const parents = new Set([...level.keys()].map((index) => Math.floor(index / 2)));
    const next = new Map();
    for (const parent of parents) {
      const nodeHash = hashIndexedNullifierNode(level.get(parent * 2) ?? defaults[depth], level.get((parent * 2) + 1) ?? defaults[depth]);
      if (nodeHash !== defaults[depth + 1]) next.set(parent, nodeHash);
    }
    level = next;
    nodes.push(...[...level.entries()].map(([nodeIndex, nodeHash]) => ({ depth: depth + 1, nodeIndex, nodeHash: frBytes(nodeHash) })));
  }
  return Object.freeze({
    nodes: Object.freeze(nodes.map((entry) => Object.freeze(entry)).sort((a, b) => a.depth - b.depth || a.nodeIndex - b.nodeIndex)),
    leaves: Object.freeze(tree.leaves.map((leaf) => Object.freeze({ physicalIndex: leaf.index, leafType: leafType[leaf.type], leafHash: frBytes(leafHash(leaf)), key: Buffer.from(leaf.key, 'hex'), successorIndex: leaf.successorIndex, successorKey: Buffer.from(leaf.successorKey, 'hex') }))),
  });
}

function checkpoint(input, transition, index) {
  const outputs = [input.decoded[0], input.decoded[1]];
  const notes = noteSnapshot(transition.noteTree, { ids: input.libauth.actions.map((action) => action.transactionId), outputs });
  const nullifiers = nullifierSnapshot(transition.nullifierTree);
  return Object.freeze({
    binding: { profileId: Buffer.from(input.profileId, 'hex'), instanceId: Buffer.from(input.instanceId, 'hex'), networkId: input.profileCore.network.id, denominationSats: input.profileCore.denominationSats, carrierCount: input.carrierCount, runtimeMaterialsSha256: Buffer.from(input.runtime.runtimeMaterialSha256, 'hex') },
    canonical: { state: encodeStateNftCommitment(transition.state, { denominationSats: input.profileCore.denominationSats }), outpoint: { txid: Buffer.from(input.libauth.actions[index].transactionId, 'hex'), vout: 0 }, actionSequence: index + 1, height: input.genesis.height, blockHash: Buffer.from(input.genesis.blockHash, 'hex') },
    noteNodes: notes.nodes, noteFrontier: notes.frontier, noteLeaves: notes.leaves.filter((leaf) => leaf.noteIndex <= (transition.state.noteCount === '1' ? 0 : 1)),
    nullifierNodes: nullifiers.nodes, nullifierLeaves: nullifiers.leaves,
    crashAt: null,
  });
}

function storeOpenArguments(input, state) {
  return { path: input.stateStorePath, profileId: Buffer.from(input.profileId, 'hex'), instanceId: Buffer.from(input.instanceId, 'hex'), networkId: input.profileCore.network.id, denominationSats: input.profileCore.denominationSats, carrierCount: input.carrierCount, runtimeMaterialsSha256: Buffer.from(input.runtime.runtimeMaterialSha256, 'hex'), state, outpoint: { txid: Buffer.from(input.genesis.outpoint.txid, 'hex'), vout: input.genesis.outpoint.vout }, actionSequence: 0 };
}

function operationBinding(record) {
  return Object.freeze({ actionMaterialSha256: record.actionMaterialSha256.toString('hex'), expectedActionSequence: record.expectedActionSequence, kind: record.kind, operationId: record.operationId, privateActionRecordSha256: record.privateActionRecordSha256.toString('hex') });
}

function evidenceCore(input, records, chain, checkpoints) {
  return Object.freeze({
    schema: V2_BETA_LOCAL_PERSISTENCE_RECOVERY_SCHEMA,
    status: V2_BETA_LOCAL_PERSISTENCE_RECOVERY_STATUS,
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    claims: V2_BETA_LOCAL_FALSE_CLAIMS,
    evidenceClass: 'beta-proof-qualification-and-libauth-packet-bound-public-checkpoints-with-cold-reopen',
    betaProfile: { profileId: input.profileId, profileCoreSha256: input.betaProfilePackage.profileCoreSha256, ceremonyResultSha256: input.betaProfilePackage.ceremony.resultSha256 },
    binding: { instanceId: input.instanceId, networkId: input.profileCore.network.id, denominationSats: input.profileCore.denominationSats, carrierCount: input.carrierCount, runtimeManifestSha256: input.runtime.manifestSha256, runtimeMaterialSha256: input.runtime.runtimeMaterialSha256, proofEvidenceSha256: input.proof.evidenceSha256, libauthEvidenceSha256: input.libauth.evidenceSha256 },
    genesis: { blockHash: input.genesis.blockHash, height: input.genesis.height, outpoint: input.genesis.outpoint, initialStateSha256: sha256(encodeStateNftCommitment(chain.initial.state, { denominationSats: input.profileCore.denominationSats })) },
    maximumLiveNotes: input.maximumLiveNotes,
    actions: Object.freeze(records.map((record, index) => Object.freeze({ ...operationBinding(record), packetSha256: input.libauth.actions[index].packetSha256, proofBindingSha256: input.libauth.actions[index].proofBindingSha256, transactionId: input.libauth.actions[index].transactionId, canonicalStateSha256: sha256(checkpoints[index].canonical.state) }))),
    replay: { actionCount: ACTIONS.length, terminalStateSha256: sha256(encodeStateNftCommitment(chain.terminal.state, { denominationSats: input.profileCore.denominationSats })), coldReopenCount: ACTIONS.length },
  });
}

function finalize(core) { return Object.freeze({ ...core, evidenceSha256: canonicalSha256(core) }); }

function evidence(value) {
  exact(value, ['actions', 'betaProfile', 'binding', 'claims', 'evidenceClass', 'evidenceSha256', 'eligibility', 'genesis', 'maximumLiveNotes', 'replay', 'schema', 'status'], 'beta persistence evidence');
  const { evidenceSha256, ...core } = value;
  if (value.schema !== V2_BETA_LOCAL_PERSISTENCE_RECOVERY_SCHEMA || value.status !== V2_BETA_LOCAL_PERSISTENCE_RECOVERY_STATUS || value.eligibility !== V2_BETA_LOCAL_ELIGIBILITY || value.evidenceClass !== 'beta-proof-qualification-and-libauth-packet-bound-public-checkpoints-with-cold-reopen' || canonicalSha256(core) !== hash(evidenceSha256, 'evidenceSha256')) {
    fail('BETA_PERSISTENCE_EVIDENCE_REJECTED', 'beta persistence evidence is noncanonical or outside its exact beta boundary');
  }
  falseClaims(value.claims, 'beta persistence evidence claims');
  return value;
}

/** Persist each evidence-bound public checkpoint, cold-reopening after each. */
export async function runV2BetaLocalPersistenceRecovery(value) {
  const inputValue = input(value);
  const chain = applyPackets(inputValue);
  const initialState = encodeStateNftCommitment(chain.initial.state, { denominationSats: inputValue.profileCore.denominationSats });
  let store;
  try { store = openV2DirectStore({ ...storeOpenArguments(inputValue, initialState), height: inputValue.genesis.height, blockHash: Buffer.from(inputValue.genesis.blockHash, 'hex') }); }
  catch (error) { fail('BETA_PERSISTENCE_STORE_REJECTED', error instanceof Error ? error.message : 'could not initialize beta store', { cause: error }); }
  finally { store?.close(); }
  let records;
  try {
    const privateStore = await createV2PrivateActionStore({ directory: inputValue.privateActionDirectory });
    records = await Promise.all(inputValue.preparedActions.map((action) => privateStore.create(action)));
  } catch (error) { fail('BETA_PERSISTENCE_STORE_REJECTED', error instanceof Error ? error.message : 'could not persist beta private records', { cause: error }); }
  const checkpoints = [];
  for (const [index, transition] of chain.transitions.entries()) {
    const snapshot = checkpoint(inputValue, transition, index);
    let opened;
    try {
      opened = openExistingV2DirectStore(storeOpenArguments(inputValue, initialState));
      opened.installAuthenticatedSnapshot(snapshot);
    } catch (error) { fail('BETA_PERSISTENCE_STORE_REJECTED', error instanceof Error ? error.message : 'could not install evidence-bound beta checkpoint', { cause: error }); }
    finally { opened?.close(); }
    try {
      opened = openExistingV2DirectStore(storeOpenArguments(inputValue, initialState));
      const canonical = opened.canonicalState();
      if (!Buffer.from(canonical.state).equals(snapshot.canonical.state) || !Buffer.from(canonical.outpoint.txid).equals(snapshot.canonical.outpoint.txid) || canonical.actionSequence !== index + 1) fail('BETA_PERSISTENCE_COLD_REOPEN_REJECTED', 'cold reopen did not retain the exact beta public checkpoint');
    } catch (error) { if (error instanceof V2BetaLocalPersistenceRecoveryError) throw error; fail('BETA_PERSISTENCE_COLD_REOPEN_REJECTED', error instanceof Error ? error.message : 'beta checkpoint cold reopen failed', { cause: error }); }
    finally { opened?.close(); }
    checkpoints.push(snapshot);
  }
  return finalize(evidenceCore(inputValue, records, chain, checkpoints));
}

/** Independently replay exact Libauth packets and compare them to the cold-reopened terminal store. */
export async function verifyV2BetaLocalPersistenceRecovery(value) {
  exact(value, ['betaLibauthQualification', 'betaProfilePackage', 'betaProofQualification', 'betaRuntime', 'evidence', 'preparedActions', 'privateActionDirectory', 'profileCore', 'stateStorePath'], 'beta persistence verification input');
  const checkedEvidence = evidence(value.evidence);
  const inputValue = input({
    betaLibauthQualification: value.betaLibauthQualification, betaProfilePackage: value.betaProfilePackage,
    betaProofQualification: value.betaProofQualification, betaRuntime: value.betaRuntime,
    carrierCount: checkedEvidence.binding.carrierCount, genesis: {
      blockHash: checkedEvidence.genesis.blockHash,
      height: checkedEvidence.genesis.height,
      outpoint: checkedEvidence.genesis.outpoint,
    },
    instanceId: checkedEvidence.binding.instanceId, maximumLiveNotes: checkedEvidence.maximumLiveNotes,
    preparedActions: checkedEvidence.actions.map((action) => ({ expectedActionSequence: action.expectedActionSequence, kind: action.kind, operationId: action.operationId, output: action.kind === 'withdrawal' ? null : value.preparedActions?.[action.expectedActionSequence]?.output, publicNullifier: action.kind === 'deposit' ? null : value.preparedActions?.[action.expectedActionSequence]?.publicNullifier })),
    privateActionDirectory: value.privateActionDirectory, profileCore: value.profileCore, stateStorePath: value.stateStorePath,
  });
  for (const [index, action] of checkedEvidence.actions.entries()) {
    exact(action, ['actionMaterialSha256', 'canonicalStateSha256', 'expectedActionSequence', 'kind', 'operationId', 'packetSha256', 'privateActionRecordSha256', 'proofBindingSha256', 'transactionId'], `beta persistence evidence actions[${index}]`);
    if (action.kind !== ACTIONS[index] || action.expectedActionSequence !== index
      || !HASH.test(action.packetSha256) || !HASH.test(action.proofBindingSha256)
      || !HASH.test(action.transactionId) || !HASH.test(action.canonicalStateSha256)
      || action.packetSha256 !== inputValue.libauth.actions[index].packetSha256
      || action.proofBindingSha256 !== inputValue.libauth.actions[index].proofBindingSha256
      || action.transactionId !== inputValue.libauth.actions[index].transactionId) {
      fail('BETA_PERSISTENCE_VERIFICATION_REJECTED', 'persistence action evidence does not bind the exact Libauth packet/proof/transaction');
    }
  }
  // Verification reads the durable private records rather than trusting caller
  // copies. The supplied actions are used only to preserve private witness
  // shape during strict input construction and are never used for replay.
  let records; let opened;
  try {
    const privateStore = await createV2PrivateActionStore({ directory: value.privateActionDirectory });
    records = await Promise.all(checkedEvidence.actions.map((action) => privateStore.load({ actionMaterialSha256: action.actionMaterialSha256, expectedActionSequence: action.expectedActionSequence, kind: action.kind, operationId: action.operationId, privateActionRecordSha256: action.privateActionRecordSha256 })));
    for (const [index, record] of records.entries()) {
      if (record.actionMaterialSha256.toString('hex') !== checkedEvidence.actions[index].actionMaterialSha256) fail('BETA_PERSISTENCE_VERIFICATION_REJECTED', 'cold-reopened private record material differs from evidence');
    }
    const chain = applyPackets(inputValue);
    const initialState = encodeStateNftCommitment(chain.initial.state, { denominationSats: inputValue.profileCore.denominationSats });
    opened = openExistingV2DirectStore(storeOpenArguments(inputValue, initialState));
    const canonical = opened.canonicalState();
    const terminal = encodeStateNftCommitment(chain.terminal.state, { denominationSats: inputValue.profileCore.denominationSats });
    if (!Buffer.from(canonical.state).equals(terminal) || canonical.actionSequence !== ACTIONS.length || canonical.outpoint.txid.toString('hex') !== checkedEvidence.actions[2].transactionId || sha256(terminal) !== checkedEvidence.replay.terminalStateSha256) fail('BETA_PERSISTENCE_VERIFICATION_REJECTED', 'cold-reopened terminal store does not equal independently replayed beta Libauth packets');
    return Object.freeze({ evidenceSha256: checkedEvidence.evidenceSha256, status: V2_BETA_LOCAL_PERSISTENCE_RECOVERY_STATUS, eligibility: V2_BETA_LOCAL_ELIGIBILITY });
  } catch (error) { if (error instanceof V2BetaLocalPersistenceRecoveryError) throw error; fail('BETA_PERSISTENCE_VERIFICATION_REJECTED', error instanceof Error ? error.message : 'beta persistence verification failed', { cause: error }); }
  finally { opened?.close(); }
}
