# HARNESS — verifier.cash measure loop  (AI-only, dense)
goal: beat BN254 BCH-native 738,099B/63tx. score=on-chain bytes. gate=accept valid/reject tampered. wall/input: ulen≤10,000B, opcost≤(41+len)·800=8,032,800.

## layout
verifier.cash/
 groth16_cashscript/  upstream mr-zwets/groth16_cashscript (sources+graders)
 cashscript/          mr-zwets/cashscript@feat/reusable-functions (OP_DEFINE/OP_INVOKE fork). CLI=packages/cashc/dist/cashc-cli.js
 node_modules/        @bitauth/libauth 3.1.0-next.8 (BCH2026 VM; metrics.operationCost), @noble/curves 1.9.7 (use esm/)
 out/{bch,checkpoints}  generated vectors
 tools/               fix-chunk-internal.mjs · gen-proof-vectors.mjs

## build (1×)
cd cashscript && npm i --ignore-scripts --no-audit --no-fund
(cd packages/utils && npx tsc -p tsconfig.build.json)
(cd packages/cashc && npx tsc -p tsconfig.build.json)
cd .. && npm i --no-audit --no-fund
# yarn broken on box (mise shim, no ver) ⇒ npm workspaces + manual tsc. node26 OK.

## patches (clone only, fork untouched)
fix-chunk-internal.mjs: chunked/**/chunkNN.cash stale plain `function` → `internal function` (reusable→OP_DEFINE/OP_INVOKE); `spend`=entry stays plain. gen_chunks.py ALSO stale (emits plain `function`; +needs `pip install py_ecc` + path port to regen).
gen-proof-vectors.mjs : synth self-consistent BN254 instance from noble — own VK ⇒ c=(a·b−αβ−Xγ)·δ⁻¹ mod r (NO proving key) → out/checkpoints/pairing-vectors.json {vk{alpha,beta,gamma,delta,ic},proof{a,b,c},publicInputs,invalid.publicInputs,golden{millerHex(12×32B BE),verified,invalidVerified}}.

## compiler gotcha
`internal function`=reusable(OP_DEFINE/OP_INVOKE), callable. plain `function`=entry(spend), NOT callable ⇒ "Undefined reference to symbol X". singleton .cash migrated; chunked+generator were not.

## measure
cashc <f> -h→hex · -s bytes · -c opcount. eval libauth BCH2026 VM ⇒ opcost=state.metrics.operationCost. graders grade vs noble (+py_ecc).
node groth16_cashscript/singleton/bn254/fp2.mjs           # leaf vs noble
node groth16_cashscript/chunked/shamir/build_vectors.mjs  # 3-ch vkx: bytes+opcost+fit
node tools/gen-proof-vectors.mjs                          # (re)gen fixture
node groth16_cashscript/singleton/bn254/{miller4,finalexp,verify}.mjs  # pairing pipeline

## baselines (2026-06-22, pinned VM)
fp2: 526B · 8/8+tamper-rej · 2,548,182
vkx shamir 3ch: lock 1456/1454/1565B · opcost 6.92M/5.86M/0.40M · all fit 8.03M · ≈21,033B/13.2M (< doc'd ~23KB/14.3M; tighter compiler)
singleton groth16.cash: 19,814B/787ops (floor)
miller4: 10,303B · PASS · 709,563,868
finalexp: 6,469B · PASS(3/3+rej) · 141,107,998
verify.cash(runtime VK): 15,721B · valid ACCEPT 892,701,751 / invalid REJECT

## proof vectors = NOT a blocker
public repo never writes pairing-vectors.json but fully synthesizable (gen-proof-vectors.mjs); full pairing pipeline verified locally, no external data/proving-key. caveat: groth16.cash BAKES VK ⇒ re-bake (byte-neutral) to use that variant; verify.cash runtime-VK works as-is. official fixed VK only for real leaderboard submission.

## grounding
PRINCIPLES.md = cost model + floor/gap + triage. thesis: B≈O_total/800+chunk-overhead ⇒ byte-min≈op-cost-min.

## FRI-STARK production bench

The FRI-STARK candidate has a separate fail-closed bench because a local VM
acceptance result is not sufficient evidence for a real-money verifier:

```bash
node fri_stark55/verifier-bench.mjs
# or, from harness/: pnpm benchmark:fri-stark55
```

It runs the token-aware stateless BCH transaction verifier plus standard and
strict BCH-2026 VM checks, the JS/reference differential, false-statement and
FRI/DEEP/Fiat-Shamir/Merkle mutation cases, split-input and P2SH binding cases,
token/category/capability substitutions, transaction serialization/provenance
checks, reproducibility, and resource ceilings. A production adapter must
declare `kind: "production-adapter"`, `deploymentStatus: "production"`, the
exact manifest statement ID/description/spec digest, and matching query/security/binding
parameters, supply the real application relation, and is
exercised with both its soundness and mutation bundles under consensus and
standard rules; its manifest must also
name a separate executable reference module that does not import the adapter,
which the bench invokes directly
for every differential case, pin every reachable verifier source file by
SHA-256, and hash-pin the dependency/toolchain lockfile. The adapter is loaded
twice and its runtime outpoints, values, locking hashes, token categories, and
NFT commitments are bound to the manifest's funded records; extra valid proofs
must pass both VM modes. Proof-family invalid cases
must reach the verifier under consensus-valid transaction semantics, so a
malformed transaction cannot masquerade as a soundness result. The release verdict
additionally requires a non-fixture application statement, provable >=128-bit
evidence, real mainnet UTXOs/category, distinct runtime proofs, reproducible
hashes, and independently hashed verifier/full-node/audit evidence. The
checked-in Fibonacci artifact is intentionally expected to fail.
The bench also includes a consensus regression for canonical single-opcode
pushes (`OP_0`, `OP_1NEGATE`, `OP_1..OP_16`) so a raw witness/library loader
cannot reinterpret an opcode byte as the next witness value.
