import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export function analyzeBaseline(verifierRecord, bchRecord) {
  const baseline = verifierRecord.measurements;
  const limits = bchRecord.measurements.sourceRecordedLimits;
  const g2 = {
    allBytes: 95_000,
    wireBytes: 95_000,
    unlockingBytes: 9_500,
  };
  const unlockingViolations = baseline.perInputUnlockingBytes
    .map((bytes, inputIndex) => ({
      inputIndex,
      bytes,
      overG2CeilingBytes: bytes - g2.unlockingBytes,
    }))
    .filter((entry) => entry.overG2CeilingBytes > 0);
  const minimumRelayFeeSatoshis = Math.ceil(
    baseline.wireBytes * (limits.defaultMinRelaySatPerKb / 1000),
  );
  return {
    candidate: verifierRecord.candidate,
    sourceLimits: {
      standardTransactionBytes: limits.maxStandardTransactionBytes,
      standardUnlockingBytes: limits.maxStandardUnlockingBytecodeBytesAfterUpgrade12,
      defaultMinRelaySatPerKb: limits.defaultMinRelaySatPerKb,
    },
    g2Ceilings: g2,
    baseline: {
      allBytes: baseline.allBytesScore,
      wireBytes: baseline.wireBytes,
      perInputUnlockingBytes: baseline.perInputUnlockingBytes,
      encodedFeeSatoshis: baseline.feeSatoshis,
    },
    allBytesBudgetRemaining: g2.allBytes - baseline.allBytesScore,
    wireBudgetRemaining: g2.wireBytes - baseline.wireBytes,
    maximumUnlockingBytes: Math.max(...baseline.perInputUnlockingBytes),
    unlockingViolations,
    minimumRelayFeeSatoshis,
    fixtureFeeShortfallSatoshis: minimumRelayFeeSatoshis - baseline.feeSatoshis,
    feeAsPercentOfOneNote: (minimumRelayFeeSatoshis / 10_000_000) * 100,
    baselineQualifiesForG2: unlockingViolations.length === 0
      && baseline.allBytesScore <= g2.allBytes
      && baseline.wireBytes <= g2.wireBytes,
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
  return analyzeBaseline(verifier, bch);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(`${JSON.stringify(await analyzeRepositoryBaseline(), null, 2)}\n`);
}

