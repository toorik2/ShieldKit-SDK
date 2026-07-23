import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export function analyzeBaseline(verifierRecord, bchRecord, g0Lock) {
  const baseline = verifierRecord.measurements;
  const limits = bchRecord.measurements.sourceRecordedLimits;
  const selected = g0Lock.selectedVerifier;
  const unlockingViolations = baseline.perInputUnlockingBytes
    .map((bytes, inputIndex) => ({
      inputIndex,
      bytes,
      overUnlockingLimitBytes: bytes - selected.perInputUnlockingLimitBytes,
    }))
    .filter((entry) => entry.overUnlockingLimitBytes > 0);
  const minimumRelayFeeSatoshis = Math.ceil(
    baseline.wireBytes * (limits.defaultMinRelaySatPerKb / 1000),
  );
  const qualificationReasons = [
    `candidate mismatch: fee reference ${verifierRecord.candidate}, selected ${selected.candidate}`,
    `input-count mismatch: fee reference ${baseline.sourceOutputs}, selected ${selected.inputs}`,
    'verifier-only fixture omits the binding/state/transparent-fee settlement roles and canonical change output',
    `encoded fixture fee shortfall: ${minimumRelayFeeSatoshis - baseline.feeSatoshis} satoshis at the recorded relay floor`,
  ];
  return {
    feeReference: {
      candidate: verifierRecord.candidate,
      wireBytes: baseline.wireBytes,
      allBytesScore: baseline.allBytesScore,
      qualification: 'fee reference only; never the selected verifier or a G2 settlement candidate',
    },
    sourceLimits: {
      standardTransactionBytes: limits.maxStandardTransactionBytes,
      standardUnlockingBytes: limits.maxStandardUnlockingBytecodeBytesAfterUpgrade12,
      defaultMinRelaySatPerKb: limits.defaultMinRelaySatPerKb,
    },
    selectedPolicy: {
      candidate: selected.candidate,
      inputCount: selected.inputs,
      completeTransactionWireLimitBytes: selected.completeTransactionWireLimitBytes,
      perInputUnlockingLimitBytes: selected.perInputUnlockingLimitBytes,
      percentageHeadroomRequired: selected.percentageHeadroomRequired,
      allBytesCap: null,
      allBytesRequirement: 'report complete all-bytes score; no project-local all-bytes cap is defined',
    },
    baseline: {
      allBytes: baseline.allBytesScore,
      wireBytes: baseline.wireBytes,
      perInputUnlockingBytes: baseline.perInputUnlockingBytes,
      encodedFeeSatoshis: baseline.feeSatoshis,
    },
    wireReferenceDeltaToSelectedCap: selected.completeTransactionWireLimitBytes - baseline.wireBytes,
    maximumUnlockingBytes: Math.max(...baseline.perInputUnlockingBytes),
    unlockingViolations,
    minimumRelayFeeSatoshis,
    fixtureFeeShortfallSatoshis: minimumRelayFeeSatoshis - baseline.feeSatoshis,
    feeAsPercentOfOneNote: (minimumRelayFeeSatoshis / 10_000_000) * 100,
    baselineQualifiesForG2: false,
    baselineDisqualificationReasons: qualificationReasons,
  };
}

export async function analyzeRepositoryBaseline() {
  const verifier = JSON.parse(await readFile(
    path.join(repositoryRoot, 'evidence/G1/verifier-baseline/observation.json'),
    'utf8',
  ));
  const bch = JSON.parse(await readFile(
    path.join(repositoryRoot, 'evidence/G1/bch-surface/observation.json'),
    'utf8',
  ));
  const g0Lock = JSON.parse(await readFile(
    path.join(repositoryRoot, 'policy/g0-lock.json'),
    'utf8',
  ));
  return analyzeBaseline(verifier, bch, g0Lock);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(`${JSON.stringify(await analyzeRepositoryBaseline(), null, 2)}\n`);
}
