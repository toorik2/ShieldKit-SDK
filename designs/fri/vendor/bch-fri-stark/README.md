# BCH DEEP-ALI FRI-STARK Verifier

A hash based FRI-STARK verifier that runs on the unmodified Bitcoin Cash 2026 script VM. The whole proof is checked inside a single standard transaction. There is no rollup, no bridge, and no trusted verifier contract. The transaction spends a set of covenants, and the spend itself is the verification: every covenant script executes on chain, and if any check fails the network rejects the transaction.

## What this is

The proof system is a DEEP-ALI FRI-STARK over the Goldilocks field, with a quadratic extension GF(p^2) for the challenges. The statement is a Poseidon2 hash chain expressed as an AIR (algebraic intermediate representation). The prover runs off chain. The verifier is a multi input P2SH32 transaction: input 0 carries the Fiat-Shamir committed data, and the other inputs each run one piece of the verification (the trace and composition openings, the DEEP quotient, the composition polynomial, and the FRI low degree test). The inputs cross read each other on chain, so the pieces are tied into one coherent check.

## Current state

The soundness wiring is complete. Every value a cheating prover could otherwise pick freely is either recomputed on chain or single sourced from the one committed blob and cross bound: the out of domain openings, the batching and DEEP alphas, the FRI fold challenges and commitment roots, the query positions, the carry chain between split parts, and the field inverse hints. On top of that, every covenant is pinned to its committed P2SH32 locking, so no input can be dropped or swapped for a cheap filler that returns true without doing the work.

Two independent adversarial audits were run against this wiring, and each one found and fixed a real forged accept in the covenant binding layer. The first showed that hashing an input's unlocking bytes authenticates the bytes, not the code that runs, so the binding was moved to the spent output's locking, which consensus ties to the executed redeem. The second showed that binding only the terminal inputs was not enough, because the inputs that other inputs read are read by their bytes and not by their execution, so the binding now covers every input, anchored on the one committed blob.

Tests run on real libauth (the reference BCH VM), with no mocks:

- The full sound transaction accepts all 22 of its inputs and rejects 10 distinct forged covenant attacks (omitting a terminal, substituting a wrong covenant, and bare filler swaps at every producer role).
- The demo builder accepts 27 of 27 inputs and is byte identical across runs.
- The reference prover and verifier agree, and the deploy check passes with zero failures.

What is not done yet: the sound configuration is over the 100 KB standard transaction limit, so byte reduction is in progress (see below), and the sound wired transaction has not been re-deployed on chain (the demo was). The final on chain sizes are settled by an offline proving run at the real security parameters.

## Size, and why soundness costs bytes

- Demo verifier, the version that ran on chipnet: 28 inputs, 92,191 bytes on chain.
- Same demo builder in the measurement harness: 92,167 bytes.
- Fully soundness wired verifier, same demo sized proving config, in the harness: 120,537 bytes.

The roughly 28 KB gap is the price of soundness, and it is expected. A demo whose components accept on their own checks almost nothing, so it stays small. Making it sound means replacing every free witness with a value that is forced, either recomputed or read and compared against the committed blob, and pinning every covenant so none can be faked. Each of those checks is real script that executes on chain, so each one costs bytes. The byte reduction levers are all soundness neutral by construction (they change how a value is computed, not what is checked), and they exist to bring the sound build back under the standard transaction limit. One of them, a deferred reduction MAC for the composition, is already landed and validated; the rest are scheduled together with the offline proving run.

## On chain (BCH chipnet)

The demo verifier was funded and spent on chipnet, and both transactions are in the chain.

- Fund transaction: `b8952034f1123691149a2beb5320aeaf9da2a94d4f71225ff6a3dfa6db4ea341` (28 P2SH32 covenant outputs, block height 314509)
- Spend transaction: `1f56490fb495e48a889f8327a006f9377478d9108b9bdad5c28724904c7e74b0` (28 covenant inputs, 92,191 bytes, block height 314510)

The spend is the proof: all 28 covenant scripts executed and were accepted inside a chipnet block. The sound wired re-deploy is pending the offline proving run.

## Layout

- `apps/native_ct_air_stark.py`, `native_ct_air_prover.py`, `native_ct_air_config.py`: the STARK prover and the reference verifier, plus the security parameters. This is the source of truth that the on chain checks reproduce.
- `apps/native_ct_shard.py`: the on chain verifier itself, written as covenant programs in a small token IR.
- `apps/native_ct_verifier_tx.py`: the transaction builder that wires the covenants into the multi input P2SH32 layout, in both the demo and the sound mode.
- `apps/native_gf_p2.py`, `native_ntt.py`, `native_poseidon2.py`, `native_poseidon2_constants.py`: the field, NTT, and Poseidon2 primitives.
- `cashvm.py`, `structures_*.py`, `stark.py`: the token VM model, the FRI structures, and the reference Merkle tree.
- `cashscript/native_shard/`: the real libauth harness. `p2sh_multi_input.mjs` runs an N input P2SH32 transaction on the BCH-2026 VM and reports the per input accept result plus the exact serialized size.

## Running the tests

The Python side needs no dependencies. From `apps/`:

```
python -c "import native_ct_air_stark as STK, native_ct_air_prover as CT; pf = STK.prove(CT._demo_witness(depth=2), blowup=8, grind_b=2, n_queries=6, fold_step=3, deep=True); print(STK.verify(pf))"
```

The transaction level tests execute the covenants on the real BCH VM, so they need libauth. Once, from `cashscript/`:

```
npm install
```

Then from `apps/`:

```
python -c "import native_ct_shard as S; S.self_test()"
python -c "import native_ct_verifier_tx as V; V.self_test()"            # demo, 27/27 accept
python -c "import native_ct_verifier_tx as V; V.sound_full_selftest()"  # sound, 22/22 accept plus forged rejects
python -c "import native_shard_deploy_check as D; D.run()"
```

## Status

This is research code. It shows that a hash based STARK can be verified on unmodified Bitcoin Cash in one standard transaction, and it carries a soundness wiring that has survived two adversarial audits. It is not production hardened and has not had an external security review. Use it at your own risk.
