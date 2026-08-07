# ShieldKit-Groth-54KB — Design 05: Deposit Pipeline Port Spec (v1)

Status: spec for the WP-3 kit-integration remainder. All signatures extracted
from the product source (read-only); the read-only import path is VERIFIED
(transition/circuit-witness/packet load from the product tree).

## 1. The linear flow (no fixed-point iteration needed)

The transactionContextHash covers ONLY the tx skeleton (model.context:
outpoints, outputs, values, version/locktime) — NOT the unlocking bytecodes
(settlement.mjs:1209 `hashDirectV2TransactionContext(model.context, {carrierCount})`;
asserted vs the packet at :1422). So:

1. Tx skeleton: 9 inputs (outpoints = pool covenant UTXOs + fee UTXO) + outputs
   (state covenant @0 with SKS2 NFT, verifier locks @1-6, OP_1 carrier @7,
   change @8) with fixed values.
2. contextHash = hashDirectV2TransactionContext(skeleton.context, {carrierCount: 6}).
3. Packet: encodeActionPacket({instanceId, state, note, transactionContextHash: contextHash, ...}).
4. Circuit input: applyDirectV2Transition({kind:'deposit', networkId, profileId,
   instanceId, denominationSats, preState, noteTree, nullifierTree,
   transactionContextHash, output}) -> buildDirectV2CircuitInput({transition, denominationSats}).
5. Prove (rapidsnark, ~2 s) -> adapter -> pf6 lane build (~50 s, real-gate green).
6. Assemble 9-input tx (pf6 unlocks + packet + state + fee sig) -> testmempoolaccept -> broadcast.

## 2. Module imports (read-only, verified working)

- transition.mjs: applyDirectV2Transition({kind, networkId, profileId, instanceId,
  denominationSats, preState, noteTree, nullifierTree, transactionContextHash,
  output?, spend?, withdrawalLockingBytecodeHash?})
- circuit-witness.mjs: buildDirectV2CircuitInput({transition, spend, output, denominationSats})
- packet.mjs: encodeActionPacket / decodeActionPacket / digestActionPacket /
  actionPacketPublicLimbs / validateActionPacket
- state.mjs: encodeStateNftCommitment / decodeStateNftCommitment (SKS2 128 B)
- notes.mjs: validateDirectV2OutputConstruction (output note keys: esk, rho, r, q...)
- settlement.mjs: prepareV2DirectSettlement / hashDirectV2TransactionContext /
  transactionFromModel (the model/context construction is the port's core)
- pool store: note-tree.mjs / indexed-nullifier-tree.mjs (fresh pool = empty trees)

## 3. Fresh-pool simplifications (first deposit)

- noteTree/nullifierTree = empty trees (deterministic zero paths).
- preState = initial SKS2 (profileId, empty roots, counts 0, reserve = rolling
  base 2,500, sequence 0).
- spend = undefined (deposit); output = fresh note keys (generate once,
  record in the pool custody file — NEVER in evidence).
- profileId = SHA256('SKP2' || RFC8785(pf6 profileCore)) — profileCore carries
  the pf6 topology + material hashes (profile-core.mjs, read-only).

## 4. Deployment sequence (chipnet, zero-conf)

1. source tx (funding, hot wallet) -> txid -> instanceId (reversed).
2. genesis (pool-create): state covenant (88 B) + 6 verifier locks + OP_1 + change.
3. deposit (9-in), then transfer, then withdrawal (recovered-note spend),
   then recover flows per Q-08 scope.
4. Every tx: testmempoolaccept -> broadcast -> mempool visibility; 1 sat/B + 1.

## 5. Verification gates (no shortcuts)

- Full-context real-VM replay of every assembled tx (harness evaluatePair).
- BCHN testmempoolaccept acceptance (WP-4 B-02 core).
- Tamper classes on the deployed tx (WP-4 corpus).
- LeanBCH full-redeem on identical bytes (WP-4/WP-6).


## v2 (2026-08-06): fresh-pool constants VALIDATED

- pf6 profileId `0342b922...` (src/pf6-profile-core.json; product deriveProfileId).
- Initial SKS2: 128 B, magic SKS2, reserve 0, empty roots, seq 0 (encodeStateNftCommitment round-trip verified).
- Empty note/nullifier tree roots + the 32-sibling empty append path
  (src/fresh-pool-constants.json) — **matches the product's own qualification
  deposit siblings 32/32** (that deposit was the first on a fresh pool).
- Reserve invariant: reserveSats == liveNoteCount x denomination (0 at genesis);
  the state OUTPUT value = stateBase (2,500) + reserve (the covenant floor).
- Next: address/key generation -> packet -> transition -> circuit input -> prove
  -> pf6 build -> assemble -> deploy (zero-conf chain).
