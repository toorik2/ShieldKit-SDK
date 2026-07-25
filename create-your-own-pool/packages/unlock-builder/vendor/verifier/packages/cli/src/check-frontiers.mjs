#!/usr/bin/env node
import { buildCandidateBundle } from './bundle.mjs';
import { judgeBundle } from './judge.mjs';
import { makeRunId } from './repo.mjs';

const frontiers = [
  {
    candidate: 'lanes/bn254-onetx/candidates/bn254-onetx-directstate-10-public-ds1.json',
    tier: 'promotion',
    id: 'bn254-onetx',
  },
  {
    candidate: 'lanes/bn254-native/candidates/bn254-native-covenant-mtx-frozen-pa1.json',
    tier: 'fast',
    id: 'bn254-native',
  },
  {
    candidate: 'lanes/bls12-381-native/candidates/bls12-381-native-covenant-mtx-frozen-lc1.json',
    tier: 'fast',
    id: 'bls12-381-native',
  },
  {
    candidate: 'lanes/bn254-singleton/candidates/bn254-singleton-genpow-1-public-gp1.json',
    tier: 'fast',
    id: 'bn254-singleton',
  },
  {
    candidate: 'lanes/bls12-381-singleton/candidates/bls12-381-singleton-genpow-1-public-gp1.json',
    tier: 'fast',
    id: 'bls12-381-singleton',
  },
];

const batchId = makeRunId('frontiers', 'all-frontiers');
for (const frontier of frontiers) {
  const runId = `${batchId}-${frontier.id}`;
  const built = await buildCandidateBundle(frontier.candidate, {
    runId,
    out: `.vc/checks/frontiers/${batchId}/${frontier.id}`,
  });
  judgeBundle(built.bundlePath, { tier: frontier.tier });
}

console.log(`frontier evidence: ${frontiers.length}/${frontiers.length} green`);
