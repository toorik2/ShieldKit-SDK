#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { hashCanonical, hashFile, readJson, schemas, sha256, assertValid } from '../../contracts/src/index.mjs';
import { benchmark } from '../../../harness/src/harness/benchmark.ts';
import type { Implementation, Scenario, Step } from '../../../harness/src/harness/types.ts';

interface RawStep {
  label?: string;
  name?: string;
  locking?: string;
  lock?: string;
  unlocking?: string;
  unlock?: string;
  unlockingHex?: string;
  lockingHex?: string;
  checkpoint?: string;
  inCommit?: string;
  outCommit?: string | null;
}

interface RawToken {
  capability: 'none' | 'mutable' | 'minting';
  commitment: string;
}

interface RawGroup {
  lo: number;
  hi: number;
  inToken: RawToken | null;
  outToken: RawToken | null;
  outLocking: string | null;
}

interface Check {
  id: string;
  ok: boolean;
  detail: unknown;
}

const args = process.argv.slice(2);
const bundleArg = args[0];
const value = (name: string) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
if (!bundleArg) throw new Error('usage: judge-bundle.ts BUNDLE [--tier fast|qualification|promotion] [--out FILE]');
const tier = value('--tier') ?? 'fast';
if (!['fast', 'qualification', 'promotion'].includes(tier)) throw new Error(`unsupported tier: ${tier}`);

const defaultRepoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const repoRoot = resolve(process.env.VC_REPO_ROOT ?? defaultRepoRoot);
const bundlePath = resolve(bundleArg);
const outPath = resolve(value('--out') ?? resolve(dirname(bundlePath), `evidence-${tier}.json`));
const bundle = assertValid('bundle', readJson(bundlePath));

const resolveRepoRef = (path: string) => {
  const absolute = resolve(repoRoot, path);
  const rel = relative(repoRoot, absolute);
  if (rel === '..' || rel.startsWith(`..${sep}`) || rel.startsWith(sep)) throw new Error(`bundle reference escapes repository: ${path}`);
  return absolute;
};

const checks: Check[] = [];
const check = (id: string, ok: boolean, detail: unknown) => {
  checks.push({ id, ok, detail });
  return ok;
};

for (const [role, ref] of Object.entries(bundle.files as Record<string, { path: string; sha256: string; bytes: number }>)) {
  const path = resolveRepoRef(ref.path);
  const actual = hashFile(path);
  check(`hash:${role}`, actual === ref.sha256, { expected: ref.sha256, actual, path: ref.path });
}

for (const [role, expected] of Object.entries(bundle.judge.expected.artifactHashes ?? {}) as Array<[string, string]>) {
  const actual = bundle.files[role]?.sha256;
  check(`expected-hash:${role}`, actual === expected, { expected, actual: actual ?? null });
}

const readRole = (role: string) => {
  const ref = bundle.files[role];
  if (!ref) throw new Error(`bundle is missing required file role: ${role}`);
  return readJson(resolveRepoRef(ref.path));
};

const context = {
  valueSatoshis: BigInt(bundle.judge.sourceValueSatoshis),
  sequenceNumber: bundle.judge.sequenceNumber,
};

const normalizeRawStep = (raw: RawStep, index: number) => {
  const locking = raw.locking ?? raw.lock ?? raw.lockingHex;
  const unlocking = raw.unlocking ?? raw.unlock ?? raw.unlockingHex;
  if (typeof locking !== 'string' || typeof unlocking !== 'string') throw new Error(`step ${index} is missing locking/unlocking hex`);
  return {
    label: raw.label ?? raw.name ?? `input-${index}`,
    locking,
    unlocking,
    checkpoint: raw.checkpoint,
  };
};

const hexBytes = (hex: string, path: string) => {
  if (!/^(?:[a-fA-F0-9]{2})*$/.test(hex)) throw new Error(`${path} must be even-length hex`);
  return Uint8Array.from(Buffer.from(hex, 'hex'));
};

const toRun = (
  rows: RawStep[],
  options: { groups?: RawGroup[]; category?: string; execution?: { kind?: string; category?: string } } = {},
): Step[] => {
  const normalized = rows.map(normalizeRawStep);
  const base = normalized.map((step) => ({
    label: step.label,
    lockingBytecode: hexBytes(step.locking, 'locking bytecode'),
    unlockingBytecode: hexBytes(step.unlocking, 'unlocking bytecode'),
    ...(step.checkpoint ? { checkpoint: step.checkpoint } : {}),
  }));

  if (options.groups !== undefined) {
    if (typeof options.category !== 'string') throw new Error('grouped vectors require a token category');
    const category = hexBytes(options.category, 'group category');
    const result: Step[] = [...base];
    for (const [groupIndex, group] of options.groups.entries()) {
      if (!Number.isInteger(group.lo) || !Number.isInteger(group.hi) || group.lo < 0 || group.hi < group.lo || group.hi >= base.length) {
        throw new Error(`invalid group bounds at index ${groupIndex}`);
      }
      const groupSteps = base.slice(group.lo, group.hi + 1);
      const inputs = groupSteps.map((step, localIndex) => ({
        lockingBytecode: step.lockingBytecode,
        unlockingBytecode: step.unlockingBytecode,
        valueSatoshis: context.valueSatoshis,
        sequenceNumber: context.sequenceNumber,
        ...(localIndex === 0 && group.inToken !== null
          ? { token: { category, capability: group.inToken.capability, commitment: hexBytes(group.inToken.commitment, `group ${groupIndex} input commitment`) } }
          : {}),
      }));
      const outputs = group.outToken === null
        ? [{
            lockingBytecode: Uint8Array.from([0x6a]),
            valueSatoshis: context.valueSatoshis,
            countLockingBytesInOverhead: true,
          }]
        : [{
            lockingBytecode: hexBytes(group.outLocking ?? '', `group ${groupIndex} output locking`),
            valueSatoshis: context.valueSatoshis,
            token: { category, capability: group.outToken.capability, commitment: hexBytes(group.outToken.commitment, `group ${groupIndex} output commitment`) },
            countLockingBytesInOverhead: false,
          }];
      for (let localIndex = 0; localIndex < groupSteps.length; localIndex++) {
        result[group.lo + localIndex] = {
          ...groupSteps[localIndex]!,
          intraTx: { index: localIndex, inputs, outputs },
        };
      }
    }
    return result;
  }

  if (options.execution?.kind === 'covenant-chain') {
    if (typeof options.execution.category !== 'string') throw new Error('covenant-chain execution requires a token category');
    const category = hexBytes(options.execution.category, 'covenant category');
    return base.map((step, index) => {
      const raw = rows[index]!;
      if (typeof raw.inCommit !== 'string') throw new Error(`covenant step ${index} is missing inCommit`);
      const terminal = raw.outCommit === null;
      if (!terminal && typeof raw.outCommit !== 'string') throw new Error(`covenant step ${index} is missing outCommit`);
      return {
        ...step,
        covenant: {
          category,
          capability: 'mutable',
          inCommitment: hexBytes(raw.inCommit, `covenant step ${index} input commitment`),
          ...(terminal ? {} : { outCommitment: hexBytes(raw.outCommit!, `covenant step ${index} output commitment`) }),
          outLockingBytecode: terminal ? step.lockingBytecode : base[index + 1]!.lockingBytecode,
        },
      };
    });
  }

  const inputs = base.map((step) => ({
    lockingBytecode: step.lockingBytecode,
    unlockingBytecode: step.unlockingBytecode,
    valueSatoshis: context.valueSatoshis,
    sequenceNumber: context.sequenceNumber,
  }));
  return base.map((step, index) => ({ ...step, intraTx: { index, inputs } }));
};

let metrics: Record<string, unknown>;
if (bundle.judge.execution?.kind === 'singleton-size') {
  const vectors = readRole('vectors');
  const multiproof = readRole('multiproof-vectors');
  const locking = hexBytes(vectors.lockingOK, 'singleton locking bytecode');
  const unlocking = hexBytes(vectors.unlocking, 'singleton unlocking bytecode');
  const invalidUnlocking = hexBytes(vectors.invalidUnlocking, 'singleton invalid unlocking bytecode');
  const lockingSha256 = sha256(locking);
  const proofs = Array.isArray(multiproof.proofs) ? multiproof.proofs : [];
  const proofUnlockings = proofs.map((proof: any, index: number) =>
    hexBytes(proof.unlocking, `multiproof proof ${index} unlocking bytecode`));
  const uniqueUnlockings = new Set(proofUnlockings.map((bytes: Uint8Array) => Buffer.from(bytes).toString('hex')));
  const uniquePublicInputs = new Set(proofs.map((proof: any) => JSON.stringify(proof.publicInputs)));
  const allInvalidWitnessesDiffer = proofs.every((proof: any) =>
    typeof proof.invalidUnlocking === 'string' && proof.invalidUnlocking !== proof.unlocking);
  const committed = proofs.filter((proof: any) => proof.committed === true);
  const lockingInvariant = multiproof.lockingOK === vectors.lockingOK;
  const committedMatches = committed.length === 1 && committed[0].unlocking === vectors.unlocking;
  const txOverheadBytes = 8 + 1 + 1 + 36 + 4 + (unlocking.length < 0xfd ? 1 : unlocking.length <= 0xffff ? 3 : 5) + 8 + 1 + 25;
  const scriptBytes = locking.length + unlocking.length;
  const score = scriptBytes + txOverheadBytes;
  metrics = {
    lockingBytes: locking.length,
    unlockingBytes: unlocking.length,
    scriptBytes,
    txOverheadBytes,
    score,
    inputCount: 1,
    transactionCount: 1,
    proofsInRecoveredCorpus: proofs.length,
    publishedOperationCost: bundle.judge.expected.operationCost,
    publishedInputsForHeaviestStep: bundle.judge.expected.inputsForHeaviestStep,
    localVmReplay: false,
    bchCompatible: false,
    fitsStandardBudget: false,
  };
  check('size-track:locking-hash', lockingSha256 === bundle.judge.expected.lockingSha256, {
    expected: bundle.judge.expected.lockingSha256,
    actual: lockingSha256,
  });
  check('size-track:locking-bytes', locking.length === bundle.judge.expected.lockingBytes, {
    expected: bundle.judge.expected.lockingBytes,
    actual: locking.length,
  });
  check('size-track:script-bytes', scriptBytes === bundle.judge.expected.scriptBytes, {
    expected: bundle.judge.expected.scriptBytes,
    actual: scriptBytes,
  });
  check('size-track:tx-overhead', txOverheadBytes === bundle.judge.expected.txOverheadBytes, {
    expected: bundle.judge.expected.txOverheadBytes,
    actual: txOverheadBytes,
  });
  check('size-track:score', score === bundle.judge.expected.score, {
    expected: bundle.judge.expected.score,
    actual: score,
  });
  check('size-track:locking-invariance', lockingInvariant, { multiproofLockingMatches: lockingInvariant });
  check('size-track:distinct-witness-corpus',
    multiproof.numProofs === proofs.length &&
    proofs.length === bundle.judge.expected.proofsTested &&
    uniqueUnlockings.size === proofs.length &&
    uniquePublicInputs.size === proofs.length &&
    allInvalidWitnessesDiffer &&
    committedMatches, {
    expected: bundle.judge.expected.proofsTested,
    declared: multiproof.numProofs,
    proofs: proofs.length,
    uniqueUnlockings: uniqueUnlockings.size,
    uniquePublicInputs: uniquePublicInputs.size,
    allInvalidWitnessesDiffer,
    committedMatches,
  });
  check('size-track:invalid-witness-distinct', Buffer.compare(unlocking, invalidUnlocking) !== 0, 'primary invalid witness differs from valid witness');
  check('size-track:non-deployable-classification', bundle.capability.deploymentBinding === 'non-deployable-size-only', {
    deploymentBinding: bundle.capability.deploymentBinding,
    publishedOperationCost: bundle.judge.expected.operationCost,
    publishedInputsForHeaviestStep: bundle.judge.expected.inputsForHeaviestStep,
  });
  if (tier !== 'fast') {
    check('qualification:local-vm-replay', false, 'Recovered fast evidence is hash/score/corpus evidence only; the multi-billion-op loosened-VM replay and deterministic source rebuild are separate qualification gates.');
  }
} else if (bundle.files.vectors) {
  const vectors = readRole('vectors');
  const asRun = (run: any) => Array.isArray(run) ? { steps: run } : run;
  const validRun = vectors.valid?.steps ? vectors.valid : { steps: vectors.steps };
  const convertRun = (runInput: any) => {
    const run = asRun(runInput);
    return toRun(run.steps, run.groups
      ? { groups: run.groups, category: vectors.category }
      : { execution: bundle.judge.execution });
  };
  const scenario: Scenario = {
    valid: convertRun(validRun),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(convertRun),
    worstCaseProof: vectors.worstCaseProof ? convertRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(convertRun),
    invalidInputs: (vectors.invalidInputs ?? []).map(convertRun),
  };
  const impl: Implementation = {
    id: bundle.candidateId,
    name: bundle.candidateId,
    proofSystem: bundle.capability.proofSystem,
    field: bundle.capability.field,
    structure: bundle.capability.structure,
    proofBinding: bundle.capability.proofBinding,
    source: `CandidateBundle ${bundle.runId}`,
    load: async () => scenario,
  };
  const result = benchmark(impl, scenario);
  const score = result.totalBytes + result.totalTxOverheadBytes;
  metrics = {
    scriptBytes: result.totalBytes,
    txOverheadBytes: result.totalTxOverheadBytes,
    score,
    inputCount: result.stepCount,
    transactionCount: result.txCount,
    totalOperationCost: result.totalOperationCost,
    maxInputOperationCost: result.maxStepOperationCost,
    validPassed: result.validPassed,
    invalidRejected: result.invalidRejected,
    invalidTotal: result.invalidTotal,
    proofsPassed: result.proofsPassed,
    proofsTested: result.proofsTested,
    runtimeGeneral: result.runtimeGeneral,
    worstCaseAccepted: result.worstCase !== undefined,
    bchCompatible: result.bchCompatible,
    fitsStandardBudget: result.fitsStandardBudget,
  };
  check('benchmark:pass', result.pass, { validPassed: result.validPassed, invalid: [result.invalidRejected, result.invalidTotal] });
  check('benchmark:bch-compatible', result.bchCompatible, result.bchIncompatibleReason ?? 'all inputs accepted');
  check('benchmark:budget', result.fitsStandardBudget, { maxInputOperationCost: result.maxStepOperationCost });
  check('benchmark:score', score === bundle.judge.expected.score, { expected: bundle.judge.expected.score, actual: score });
  check('benchmark:script-bytes', result.totalBytes === bundle.judge.expected.scriptBytes, { expected: bundle.judge.expected.scriptBytes, actual: result.totalBytes });
  check('benchmark:tx-overhead', result.totalTxOverheadBytes === bundle.judge.expected.txOverheadBytes, { expected: bundle.judge.expected.txOverheadBytes, actual: result.totalTxOverheadBytes });
  check('benchmark:input-count', result.stepCount === bundle.judge.expected.inputCount, { expected: bundle.judge.expected.inputCount, actual: result.stepCount });
  if (tier !== 'fast') {
    check('qualification:invalid-rejection', result.invalidTotal >= result.stepCount && result.invalidRejected === result.invalidTotal, { rejected: result.invalidRejected, total: result.invalidTotal });
    check('qualification:distinct-proofs', result.proofsTested >= 4 && result.proofsPassed === result.proofsTested && result.runtimeGeneral, { passed: result.proofsPassed, tested: result.proofsTested });
    check('qualification:worst-case', result.worstCase !== undefined, result.worstCase ?? null);
  }
} else {
  const inputs = readRole('inputs') as RawStep[];
  const run = toRun(inputs, { execution: bundle.judge.execution });
  const scenario: Scenario = { valid: run };
  const impl: Implementation = {
    id: bundle.candidateId,
    name: bundle.candidateId,
    proofSystem: bundle.capability.proofSystem,
    field: bundle.capability.field,
    structure: bundle.capability.structure,
    proofBinding: bundle.capability.proofBinding,
    source: `CandidateBundle ${bundle.runId}`,
    load: async () => scenario,
  };
  const result = benchmark(impl, scenario);
  const score = result.totalBytes + result.totalTxOverheadBytes;
  metrics = {
    scriptBytes: result.totalBytes,
    txOverheadBytes: result.totalTxOverheadBytes,
    score,
    inputCount: result.stepCount,
    transactionCount: result.txCount,
    validPassed: result.validPassed,
    bchCompatible: result.bchCompatible,
    fitsStandardBudget: result.fitsStandardBudget,
  };
  check('fast:valid', result.validPassed, result.error ?? 'all inputs accepted');
  check('fast:bch-compatible', result.bchCompatible, result.bchIncompatibleReason ?? 'all inputs accepted');
  check('fast:budget', result.fitsStandardBudget, { maxInputOperationCost: result.maxStepOperationCost });
  check('fast:score', score === bundle.judge.expected.score, { expected: bundle.judge.expected.score, actual: score });
  check('fast:input-count', result.stepCount === bundle.judge.expected.inputCount, { expected: bundle.judge.expected.inputCount, actual: result.stepCount });
  if (tier !== 'fast') check('qualification:promotion-vectors', false, 'source-only bundle has no independent invalid, extra-valid, or worst-case vectors');
}

if (bundle.judge.expected.transactionCount !== undefined) {
  check('benchmark:transaction-count', metrics.transactionCount === bundle.judge.expected.transactionCount, {
    expected: bundle.judge.expected.transactionCount,
    actual: metrics.transactionCount,
  });
}

if (bundle.buildResult) {
  check('build:real-gate', bundle.buildResult.built === true && bundle.buildResult.gateOk === true, {
    built: bundle.buildResult.built,
    gateOk: bundle.buildResult.gateOk,
    gateThrow: bundle.buildResult.gateThrow,
  });
}

if (tier === 'promotion') {
  const envelope = readRole('envelope');
  check('promotion:utxo-envelope', Object.values(envelope.gates ?? {}).length > 0 && Object.values(envelope.gates).every(Boolean), envelope.gates ?? null);
  check('promotion:standardness', envelope.parent?.standardWholeTx?.accept === true && envelope.spend?.standardAll === true && envelope.spend?.standardWholeTx?.accept === true && envelope.vmbconf?.standardFalse === 0, {
    parent: envelope.parent?.standardWholeTx,
    spendAll: envelope.spend?.standardAll,
    spendWhole: envelope.spend?.standardWholeTx,
    vmbconf: envelope.vmbconf,
  });
  const envelopeLean = [envelope.parent?.lean, ...(envelope.spend?.lean ?? [])].filter(Boolean);
  check('promotion:leanbch-envelope', envelopeLean.length === bundle.judge.expected.inputCount + 1 && envelopeLean.every((row: any) => row.accept === true && row.txValid === true && row.tokenValid === true), { rows: envelopeLean.length });

  const a1 = readRole('a1-summary');
  const countRows = Object.values(a1.counts ?? {}) as any[];
  const a1Total = countRows.reduce((sum, row) => sum + row.total, 0);
  check('promotion:a1', a1Total >= 89 && countRows.every((row) => row.executed === row.total && row.skipped === 0 && row.noOp === 0 && row.globalFalseAccepts === 0) && a1.falseAccepts.length === 0 && a1.standardFalseAccepts.length === 0 && a1.noOps.length === 0, { total: a1Total, counts: a1.counts, falseAccepts: a1.falseAccepts, noOps: a1.noOps });
  const dualAgreement = (a1.dual ?? []).every((row: any) => ['accept', 'txValid', 'tokenValid'].every((field) => row.lean?.[field] === row.libauth?.[field]));
  check('promotion:leanbch-a1', (a1.dual ?? []).length > 0 && dualAgreement, { rows: (a1.dual ?? []).length });

  const role = readRole('role-battery');
  check('promotion:role-battery', role.total >= 52 && role.globalAccepts.length === 0, { total: role.total, globalAccepts: role.globalAccepts });
  const deployment = readRole('deployment-battery');
  check('promotion:deployment-battery', deployment.total >= 12 && deployment.globalAccepts.length === 0 && deployment.standardGlobalAccepts.length === 0 && deployment.noOps.length === 0, { total: deployment.total, globalAccepts: deployment.globalAccepts, standardGlobalAccepts: deployment.standardGlobalAccepts, noOps: deployment.noOps });

  const corpus = readRole('full-corpus');
  check('promotion:full-corpus', corpus.rows >= 256 && corpus.built === corpus.rows && corpus.gateOk === corpus.rows && corpus.manualAllAccept === corpus.rows && corpus.perInputAllAccept === corpus.rows && corpus.capOverflows === 0 && corpus.gateThrows === 0 && corpus.lockInvariant === true, corpus);
  const invariance = readRole('lock-invariance');
  check('promotion:lock-invariance', invariance.rows >= 256 && invariance.allLockingsInvariant === true && invariance.allUnlockingsDistinct === true, { rows: invariance.rows, allLockingsInvariant: invariance.allLockingsInvariant, allUnlockingsDistinct: invariance.allUnlockingsDistinct });
  check('promotion:public-bench-transcript', bundle.files['bench-output'] !== undefined, bundle.files['bench-output'] ?? null);
}

const evidence = {
  schema: schemas.evidence,
  runId: bundle.runId,
  candidateId: bundle.candidateId,
  lane: bundle.lane,
  tier,
  verdict: checks.every((row) => row.ok) ? 'green' : 'red',
  generatedAt: new Date().toISOString(),
  bundle: relative(repoRoot, bundlePath).split(sep).join('/'),
  bundleSha256: hashCanonical(bundle),
  metrics,
  capability: bundle.capability,
  toolchain: bundle.toolchain,
  provenance: bundle.provenance,
  checks,
};
assertValid('evidence', evidence);
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(evidence, null, 2)}\n`);
console.log(JSON.stringify({ verdict: evidence.verdict, tier, candidate: bundle.candidateId, metrics, evidence: outPath }, null, 2));
if (evidence.verdict !== 'green') process.exitCode = 1;
