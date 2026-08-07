# Design 02 REVISION v2 — VK decision corrected to the CURRENT product VK (2026-08-06)

Supersedes v1's "product VK = e52d09c3" for the PRODUCT build. The REFERENCE
build conclusion (reference VK != product VK, rebake required, no ceremony)
is unchanged. Only the identity of the product VK is corrected.

## New evidence (evidence/03-implementation/product-build-r1.json)

1. The installed **current** v2-beta-product runtime
   (`~/.local/share/shieldkit-*/v2-beta-product-artifacts/runtime/`) pins:
   - verification_key.json sha256 **d38f3cfc0c77711d...** (2,765 B)
   - beta.zkey sha256 **61683ef2...** (226,816,412 B)
   - main-chipnet.r1cs sha256 **077f58f5...** (90,298,572 B) + wasm 87f5878e...
   - runtime manifest beta-runtime-manifest.json with per-file sha256.
2. The runtime ships the deposit qualification set: **packet.bin (552 B SDA2)**,
   proof.json, public.json, and **v2-direct-groth16-adapter.json** (schema
   `shieldkit-v2-direct-groth16-adapter-v1`) — the current product's V2-Direct
   adapter with a valid proof for VK d38f3cfc.
3. The current product code (`packages/action/v2/packet.mjs`) is SDA2 552 B.

## Why the change

- The goal text pinned verification_key.json `e52d09c3` from the older
  `shieldkit-pin-artifacts-v1` release manifest (final.zkey 254a7bb2,
  g1_relation.r1cs 6a797e69, public-input-abi = SCAR 752-byte digest).
- The CURRENT product (v2-beta-product offline r3, the PF10 design being
  swapped) proves with d38f3cfc / beta.zkey 61683ef2 / main-chipnet / SDA2 552.
- "Current version design with only the verifier swapped" => the pf6 product
  build must accept proofs from the CURRENT circuit/key set (d38f3cfc).
- Ceremony posture unchanged: current material is also single-contributor
  (`ceremonyQualified=false`); NO new ceremony; reuse + documented.

## Decision (v2)

- **Product build VK = d38f3cfc** (current runtime), packet ABI = sda2-v2-direct
  (552 B), circuit = main-chipnet (current).
- e52d09c3/SCAR-752/g1_relation remains the older pinned generation — retained
  as reference material; NOT the swap target.
- User override: if the pinned e52d09c3 set is required instead, the identical
  rebake machinery applies (adapter + packet + proof for that VK), with
  re-measurement.

## Product build measurement (evidence/03-implementation/product-build-r1.json)

- 9 inputs / 1 tx; all 6 verifier roles real-VM accept in the complete
  9-input context (gateOk=true).
- wire 56,379 / score 56,664 / sigmaUnlock 55,976 (vs PF10 90,977 — 38.5%
  smaller); max verifier op cost 7,045,619 (terminal).
- Per-role (stabilized): exec0-3 9,853/9,848/9,877/8,893; genesis 7,600;
  terminal 9,350.
- Digest binding exactly as frozen: packet@6 (552 B, sha256 882edc10),
  digest@genesis offset 451.
