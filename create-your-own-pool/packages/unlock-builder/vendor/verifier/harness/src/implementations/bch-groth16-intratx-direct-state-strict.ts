// BCH-native BN254 Groth16 verifier - hardened direct-state strict fixed deployment.
// Unlike the portable sibling, this entry supplies the 10,000-satoshi source values
// required by the strict root deployment guard, so the 83,344 B artifact is benchmarked
// as-is rather than silently downgraded to the 83,086 B portable profile.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
  checkpoint?: string;
}

interface Vectors {
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  worstCaseProof?: RawStep[];
  invalid?: RawStep[][];
}

const vectors = JSON.parse(readFileSync('src/bch/groth16-intratx-direct-state-strict-vectors.json', 'utf8')) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((step) => ({
    lockingBytecode: hexToBin(step.locking),
    unlockingBytecode: hexToBin(step.unlocking),
    valueSatoshis: 10000n,
    sequenceNumber: 0xffffffff,
  }));
  return raw.map((step, index) => ({
    label: step.label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: step.checkpoint,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16IntratxDirectStateStrict: Implementation = {
  id: 'bch-groth16-intratx-direct-state-strict',
  name: 'BCH Groth16 intra-tx direct-state boundary (strict 83,344 B fixed deployment)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: ten P2SH32 inputs in one intra-transaction-linked BN254 verifier. ' +
    'This strict fixed-deployment profile binds the complete source-role topology, carrier lengths, ' +
    'transaction envelope, 10,000-satoshi source values, and canonical input coordinates. It is ' +
    'benchmarked with its exact deployment context; the portable sibling omits deployment-only value pins.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
