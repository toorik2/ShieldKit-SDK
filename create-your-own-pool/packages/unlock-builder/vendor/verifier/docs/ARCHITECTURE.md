# Lane-oriented verifier architecture

## Status

The repository is migrating by compatibility wrapper, not mass rewrite. Existing verifier source, harness behavior, artifacts, catalogue history, and reproduce commands remain authoritative until an independently judged replacement reaches parity.

The first migrated lane is `lanes/bn254-onetx`. Its frontier manifest wraps the real checked-in 83,294-byte public-context evidence bundle; its source manifest builds the lane-owned `src/c7/build.ts` orchestration behind an isolated output contract. Lane source builders are loaded from lane-owned modules, so adding a lane does not add special cases to the shared CLI. The historical `build/chunked/pairing/c7_merge.ts` path is a compatibility shim.

The frozen BN254 native and BLS12-381 native crowns are also represented as measured lanes. Their historical script-byte headlines remain provenance facts, while the new judge recomputes transaction overhead from terminal-covenant and grouped-token contexts. Neither is marked promoted by the new control plane until fresh attack, standardness, LeanBCH, and provenance gates are emitted.

The held public singleton size crowns are recovered as `bn254-singleton` and `bls12-381-singleton`. Their decoded locking bytecode and witnesses are pinned byte-exact from the merged maintainer benchmark; the JSON corpora preserve the same content with repository-standard terminal newlines, and the public harness adapters are copied byte-exact. These lanes are deliberately classified `non-deployable-size-only`: fast evidence recomputes locking, unlocking, envelope, and score bytes without spending billions of loosened-VM operations. Local VM replay and deterministic source rebuild remain explicit qualification gates, not implied by artifact recovery.

The source compatibility candidate also pins the hashes of its result, inputs, closed transaction, source outputs, boundary parts, and operation-margin record. Refactors must preserve those products exactly or explicitly create a new candidate identity and evidence line.

Its manifest uses a complete typed build profile rather than an arbitrary environment map. The lane adapter clears legacy C7 and generator switches from the ambient process before translating the profile, containing environment compatibility to one migration boundary.

## Units

- **Lane**: path-owned verifier family with one capability/scoring contract.
- **CandidateManifest**: validated, hashable configuration and toolchain identity.
- **CandidateBundle**: immutable references to concrete transaction, scripts, vectors, and build output.
- **EvidenceRecord**: judge-produced metrics and gate results. Candidate-reported metrics are non-authoritative.
- **Arena**: scoped worktrees and retained branches rooted under `.vc/`; divergent commits receive an incremental recovery bundle before worktree removal.

## Trust boundary

```text
lane source + candidate manifest
            |
            v
      candidate builder  ---->  CandidateBundle
                                      |
                                      v
                       independent judge + BCH VM + LeanBCH
                                      |
                                      v
                              EvidenceRecord
                                      |
                              promotion only
                                      v
                        catalogue/artifact views
```

Lane workers do not edit the judge or shared evidence views. Promotion judges do not edit candidate source. Experiments write only to `.vc/` and never update frontier headlines directly.

## Control-plane commands

```bash
npm run vc -- validate lanes/bn254-onetx/candidates/bn254-onetx-directstate-10-public-ds1.json
npm run vc -- build lanes/bn254-onetx/candidates/bn254-onetx-directstate-10-source-r25.json
npm run vc -- verify lanes/bn254-onetx/candidates/bn254-onetx-directstate-10-public-ds1.json --tier promotion

npm run vc -- arena create sub75-r1 --workers close,topology,packing,bytecode --target-lane bn254-onetx --dry-run
npm run vc -- arena status sub75-r1
npm run vc -- arena check sub75-r1
npm run vc -- arena close sub75-r1 --yes
npm run vc -- arena finalize sub75-r1 --integrated-into master --yes
npm run vc -- gc
npm run check:frontiers
```

`arena close` refuses dirty, unbootstrapped, or out-of-scope worktrees; creates and verifies an incremental bundle when branches diverge from the base; removes the worktrees; and retains every branch. `arena finalize` deletes those branches only after Git proves every worker tip is reachable from the declared integration ref and that commit is present in a remote-tracking ref. Finalized arenas alone become GC-eligible.

`check:frontiers` independently checks all five current lane frontiers: promotion evidence for the one-transaction lane, fresh honest/hash/score evidence for both measured native crowns, and byte-exact public score/corpus evidence for both non-deployable singleton size crowns.

## Migration order

1. Agent governance, contracts, isolated outputs, BN254 one-tx compatibility adapter.
2. Candidate-path judge loading and machine evidence.
3. Extract the BN254 C7 configuration, planning, emission, assembly, and evidence responsibilities behind byte-identical tests.
4. Migrate native BN254, BLS12-381, and singleton lanes. FRI/Circle-STARK remains pending a concrete promotable candidate.
5. Generate catalogue apex and leaderboard views from immutable evidence records.
6. Materialize large fixture files from a unique content-addressed object store.
7. Retire legacy registries, environment wrappers, copied vectors, and obsolete tools only after parity.

## Non-negotiable promotion gates

- all locking, unlocking, and transaction-overhead bytes scored;
- real BCH-2026 transaction execution and standardness;
- adversarial rejection with no skipped or no-op mutations;
- capability and locking invariance across the declared corpus;
- deterministic source, fixture, toolchain, and artifact hashes;
- independent LeanBCH acceptance/validity agreement;
- unmodified public maintainer scorer for submission claims.
