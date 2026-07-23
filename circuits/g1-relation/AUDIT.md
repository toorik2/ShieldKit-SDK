# G1 relation pre-setup constraint audit

This local audit reviews the compiled 752-byte relation before any trusted
setup. It generated no ptau, zkey, proof, verifier, transaction, network
request, or deployment artifact.

## Reproduction

```bash
npm ci --prefix circuits/g1-relation --no-audit --no-fund
npm ci --prefix packages/core --no-audit --no-fund
circuits/g1-relation/node_modules/.bin/circom2 \
  circuits/g1-relation/src/g1_relation.circom --r1cs --wasm --sym --inspect -o BUILD
npm --prefix circuits/g1-relation run generate:core-vectors -- VECTORS
npm --prefix circuits/g1-relation run audit:constraints -- BUILD VECTORS RESULT.json
```

The audit reconstructs the packet from typed circuit inputs, checks the two
public SHA-256 limbs for deposit/transfer/withdrawal, verifies the R1CS/SYM
public order, checks direct constraint incidence for all named input leaves,
and executes the mutation matrix recorded in the evidence directory.

## Result and interpretation

The recorded compile has 608,499 R1CS constraints, two public inputs, and
1,768 private inputs. All 1,770 direct input leaves (including the two public
limbs) resolve in the SYM map. Every private leaf has R1CS incidence except
`postMaximumReserve`, which Circom aliases away after enforcing equality with
`preMaximumReserve`; it is independently serialized into the SHA packet and a
fixed-public-limb mutation rejects.

`--inspect` emitted 2 `CA01` and 149 `CA02` warnings. The G1-local warnings
are unused *outputs* of `Num2Bits` range components; their inputs remain
constrained by decomposition. The rest originate in pinned circomlib SHA-256
internals. This audit does not treat the warnings as a proof of absence of all
cryptographic implementation defects.

Three re-bound mutations accept by design: an active encrypted record byte,
the transaction-context digest, and the withdrawal script hash. Each becomes a
different SHA-bound action when its public digest is recomputed. The relation
does not validate record encryption or reconstruct/bind the BCH context and
script preimages; those remain explicit G1/G2 limitations, not unexpected
private-input freedom.

This is a pre-setup audit result only. It does not change G1 from OPEN and does
not establish setup, proving, verification, BCH VM, or deployment readiness.
