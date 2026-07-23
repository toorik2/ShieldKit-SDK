# G1 BCH transaction-topology candidate

Status: G1 feasibility candidate; not a profile or broadcast template

Version: 0.1.0

## 1. Objective

This candidate couples the two-public-input Groth16 verifier family to one
state-reserve covenant, one action-packet carrier, and the frozen transparent
fee model. It is the topology G1 must compile and measure. G2 may freeze it only
after complete standard transactions execute with real proofs and required
headroom.

No script in this document is an `OP_TRUE`, synthetic acceptance path, or
substitute for proof verification.

## 2. Settlement inputs

The candidate settlement transaction has exactly nine inputs in this order:

| Index | Role | Required source output |
| ---: | --- | --- |
| 0–5 | distributed Groth16 verifier | six profile-bound P2S verifier carriers |
| 6 | binding/action carrier | profile-bound P2S binding covenant carrying the canonical action packet |
| 7 | state and BCH reserve | instance-bound P2S state covenant holding the unique mutable state NFT |
| 8 | transparent fee funding | one ordinary user- or sponsor-controlled BCH UTXO |

All inputs use sequence `0`; transaction version is `2`; locktime is `0`.

The verifier topology is not assumed to remain valid when the input count grows
from its six-input sizing fixture to nine. Every verifier role must be generated
for and execute against the exact nine-input topology.

## 3. Dependency construction without circular script hashes

Scripts are instantiated in this directed order:

```
profile artifacts and verifier locks
    -> profileId
    -> genesis inputs and instanceId
    -> binding lock
    -> state lock
    -> genesis transaction
```

1. Verifier locks are generated for roles 0–5 and the nine-input envelope.
   Their exact bytes are included in the profile-hashed `bch-verifier-set`, so
   they cannot embed the resulting `profileId` or any later `instanceId`
   without an impossible hash fixed point. They bind the verification key and
   topology and derive the public limbs from the input-6 packet, but do not
   treat its identity fields as expected constants.
2. The verifier bundle is finalized and derives `profileId`; the fresh category
   input and reserve cap then derive `instanceId`.
3. The binding covenant is instantiated with the exact six verifier locking
   bytecodes and the derived profile/instance constants. It rejects a packet
   whose identity fields differ.
4. The state covenant is instantiated with the exact binding locking bytecode,
   profile, instance, state NFT category, denomination, and maximum reserve.
5. Genesis creates the unique mutable state NFT under the exact state lock.

The binding covenant does not embed the state lock. It authenticates input 7 by
the unique instance NFT and requires output 0 to preserve that NFT and input
7's exact locking bytecode. The state covenant self-pins input 7/output 0 and
pins input 6's exact binding lock. This closes the dependency without a
state/binding hash cycle.

Replacing any accepting verifier or binding script with a distinct accepting
P2S script must fail whole-transaction validation.

## 4. Settlement outputs

Outputs are canonical:

### Deposit and transfer

| Index | Role |
| ---: | --- |
| 0 | successor state NFT and reserve under the unchanged state lock |
| 1 | transparent fee-input change under the packet-bound change lock |

### Withdrawal

| Index | Role |
| ---: | --- |
| 0 | successor state NFT and reserve under the unchanged state lock |
| 1 | exactly 10,000,000 satoshis under the packet-bound recipient lock |
| 2 | transparent fee-input change under the packet-bound change lock |

Every action has exactly one change output. The planner must select a fee input
that leaves a standard, positive change output after paying the fee. Burning a
dust remainder or silently omitting change is not canonical.

No settlement output is an `OP_RETURN`, protocol-fee, maintainer-fee, relayer,
admin, pause, rescue, or upgrade output. No unconstrained output is permitted.

## 5. Carrier preparation

Verifier and binding source outputs are prepared permissionlessly from
authenticated profile data. The preparation package:

- creates the six exact verifier locks and one exact binding lock;
- records every source outpoint, value, token prefix, and locking bytecode;
- carries no shielded spending secret;
- grants no exclusive right to settle;
- permits no substituted script or value;
- has an explicit theft, race, and reorg model; and
- uses ordinary user-controlled funding and change.

For deposit, binding input 6 contributes exactly the 10,000,000-satoshi reserve
increase in addition to its profile-fixed carrier value. Transfer and
withdrawal binding inputs contain only the carrier value.

Preparation fees are separate from the settlement fee and must be included in
wallet cost and privacy reporting.

## 6. Fee and BCH conservation

Let:

- `V[i]` be verifier-carrier values for inputs 0–5;
- `B` be the profile-fixed binding-carrier value;
- `F` be input 8's transparent value;
- `C` be the canonical change value;
- `Rpre` and `Rpost` be state input/output values;
- `W` be the withdrawal value or zero; and
- `K = sum(V[i]) + B`.

The action equations are:

```
deposit:    input6 = B + D, Rpost = Rpre + D, W = 0
transfer:   input6 = B,     Rpost = Rpre,     W = 0
withdrawal: input6 = B,     Rpost = Rpre - D, W = D
```

The miner fee is:

```
fee = K + F - C
```

after the action-specific `D` terms cancel. Therefore the reserve never pays a
miner fee. Carrier values may contribute, input 8 pays the remainder, and the
fee is positive and at least the active peer floor for the exact serialized
transaction.

The proof constrains the reserve transition. The covenants constrain actual
source values, output values, action kind, contribution, withdrawal, change,
and full transaction conservation.

## 7. Transaction-context commitment

The action packet contains a 32-byte `transactionContextDigest`. Its canonical
preimage excludes all unlocking bytecodes, signatures, and the proof to avoid a
circular transaction ID, but includes:

- version and locktime;
- ordered input count and output count;
- for every input: role, outpoint, sequence, source value, SHA-256 of exact
  source locking bytecode, and SHA-256 of canonical token data;
- for every output: role, value, SHA-256 of exact locking bytecode, and SHA-256
  of canonical token data; and
- network, profile, instance, and action kind.

Each covenant validates the portion accessible to its role, and the binding
covenant validates the complete preimage against actual introspection. The
Groth16 relation binds the digest through the action packet.

G1 must prove that current BCH introspection and VM budgets can validate this
preimage. If direct recomputation is too expensive or unavailable, the
replacement topology must preserve transitive authentication of every field;
an unchecked caller-supplied digest is a kill condition.

## 8. State covenant

Input 7 accepts only when:

- the source NFT category equals the instance's derived state category;
- capability is mutable, fungible amount is zero, and commitment is canonical;
- the source value equals packet `pre.reserveSats`;
- the source commitment equals the packet pre-state commitment;
- input 6 uses the exact profile binding lock;
- output 0 preserves the category, mutable capability, zero fungible amount,
  and input 7's exact locking bytecode;
- output 0 value and commitment equal the proven post-state;
- the packet maximum reserve equals the immutable constructor value;
- the action kind selects the exact output layout; and
- there is no additional state-category token input or output.

No runtime key or signature can override these conditions.

## 9. Binding covenant

Input 6:

- parses exactly one canonical action packet at a fixed unlocking position;
- recomputes its SHA-256 digest and two public field limbs;
- authenticates the six exact verifier source locks and roles;
- authenticates input 7's state NFT category and packet pre-state;
- requires output 0 to preserve input 7's NFT and exact state locking bytecode;
- validates the complete transaction-context preimage;
- validates deposit contribution, withdrawal output, fee input, change output,
  carrier values, and output counts; and
- self-pins its active bytecode and rejects trailing/unparsed packet data.

The six verifier roles must derive their public inputs from the same input-6
packet bytes rather than accepting witness-provided scalar values.

## 10. Fee input

Input 8 is outside the anonymity claim and may be P2PKH, P2PK, or another
profile-allowed ordinary spend type. Its outpoint, source value, source lock
hash, sequence, and change destination are packet-bound. The wallet signs only
after displaying the complete unsigned transaction and confirming:

- the state contribution or withdrawal;
- exact fee and feerate;
- every carrier value;
- recipient output, if any;
- change value and script; and
- the transparent linkage warning.

The shielded spending key never authorizes input 8 and is not exposed to the
integrating application.

## 11. Required G1/G2 falsifiers

The candidate is rejected if:

- the six-input verifier cannot be regenerated for nine exact roles;
- any verifier input exceeds 9,500 unlocking bytes;
- binding or state locks exceed 190 P2S bytes;
- total all-bytes or serialized size exceeds 95,000 bytes;
- any role accepts a substituted locking bytecode, value, token, index,
  outpoint, sequence, output, packet, proof element, or digest limb;
- fee input or change can be omitted, duplicated, or detached;
- deposit or withdrawal can alter the reserve by a value other than `D`;
- the state NFT can be duplicated, replaced, burned into an accepted
  successor, or moved under another lock;
- any prepared carrier requires a privileged supplier; or
- any complete action is non-standard on an unmodified current Chipnet peer.
