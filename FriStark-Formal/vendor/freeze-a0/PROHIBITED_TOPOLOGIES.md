# V2 STARK — Prohibited topologies

Fail closed. Any implementation path that introduces a banned topology is a product defect.

## Product flow (only permitted)

```text
sync public pool history
→ construct one private witness locally
→ generate one STARK proof locally under production FRI params
→ sign one wallet-owned transparent funding input
→ broadcast one BCH settlement transaction
```

## Hard bans (same spirit as V2 Direct)

1. Batching multiple user actions into one proof or one settlement.
2. Batcher, coordinator, or sequencer roles with special keys.
3. Sponsor, faucet, or fee-ticket funding of user actions.
4. Remote prover as a required product path.
5. Preparation transaction before settlement.
6. Recursive proofs or proof aggregation across actions.
7. Root-history accumulators that replace full history recovery.
8. Cross-profile or cross-version migration from Groth16 V2 Direct or V1.

## STARK-specific bans

1. **In-repo qualification suite** — do not build Q/B campaigns, evidence verifiers, clean-host/soak runners, or a parallel assurance package in ShieldKit-SDK. That work belongs in [ShieldKit-Assurance](https://github.com/toorik2/ShieldKit-Assurance).
2. **Low-bit research tips as product** — golf configs (`nq=1`, small blowup, M31 lanes) must not appear in release runtime material or Chipnet evidence.
3. **Demo / unwired packer as product** — soundness-unwired multi-input layouts are development-only.
4. **Bare redeem packaging** — locking bytecode must be real P2SH32 (`OP_HASH256 <hash> OP_EQUAL`); unlock = witness ‖ push(redeem).
5. **Mock proofs / mock VM** in any artifact labeled qualification or final.
6. **Trusted setup** — no ceremony, no zkey, no toxic waste story for this profile.
7. **Mainnet by default** — network gate refuses mainnet until a separate reviewed decision; Chipnet-only for this programme’s production readiness.
8. **Dual optional public ABIs** — exactly one PUBLIC_STATEMENT binding path; no “Poseidon or SHA-256 depending on flag.”
9. **Depth reduction escape** — product profile trees are depth 32; shipping depth &lt; 32 under the same `relationId` is forbidden.

## Allowed development-only exceptions

Labeled `eligibility: development-only` only:

- Smaller FRI params for packer unit tests.
- Offline AIR unit tests without full settlement.
- Single-host local journals without chain.

Development exceptions never promote to `final` without regenerating under production params and re-running gates.
