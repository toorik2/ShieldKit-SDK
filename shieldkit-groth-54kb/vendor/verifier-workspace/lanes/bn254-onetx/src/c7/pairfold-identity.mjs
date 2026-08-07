// Canonical construction identities. Lifecycle and benchmark state deliberately
// live in manifests and evidence, never in these names.
export const PAIRFOLD_7_IDENTITY = Object.freeze({
  humanName: 'BN254 PairFold-7',
  descriptor: 'Authenticated P2SH Chain',
  displayName: 'BN254 PairFold-7 — Authenticated P2SH Chain',
  slug: 'bn254-pairfold-7-p2shchain-pf1',
  curve: 'bn254',
  construction: 'pairfold',
  topology: 7,
  stateModel: 'p2shchain',
  revision: 'pf1',
});

// Four shared P2SH executors + genesis + terminal = six inputs.
export const PAIRFOLD_6_IDENTITY = Object.freeze({
  humanName: 'BN254 PairFold-6',
  descriptor: 'Authenticated P2SH Chain',
  displayName: 'BN254 PairFold-6 — Authenticated P2SH Chain',
  slug: 'bn254-pairfold-6-p2shchain-pf1',
  curve: 'bn254',
  construction: 'pairfold',
  topology: 6,
  stateModel: 'p2shchain',
  revision: 'pf1',
});

// Six shared P2SH executors + genesis + terminal = eight inputs.
// Spike identity — not green until density/table/body path is completed.
export const PAIRFOLD_8_IDENTITY = Object.freeze({
  humanName: 'BN254 PairFold-8',
  descriptor: 'Authenticated P2SH Chain',
  displayName: 'BN254 PairFold-8 — Authenticated P2SH Chain (spike)',
  slug: 'bn254-pairfold-8-p2shchain-spike1',
  curve: 'bn254',
  construction: 'pairfold',
  topology: 8,
  stateModel: 'p2shchain',
  revision: 'spike1',
});
