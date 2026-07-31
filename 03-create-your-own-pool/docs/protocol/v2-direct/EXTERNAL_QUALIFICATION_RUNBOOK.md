# V2 Direct external qualification runbook

This is the fail-closed handoff for the external gates. It is not a release
procedure and does not make a development artifact qualified. Every JSON
artifact below is exact RFC8785/JCS bytes and must be retained with its raw
inputs and command transcripts. Final-profile inputs are SHA-256 pinned by the
signed final manifest; post-final external evidence and derived results are
instead hash-chained and bound to those pinned inputs.
`npm test`, local-verifier lanes, test seams, fixtures, local ceremony
simulation, and `external-release-gate.mjs` output are not gate evidence.

Run all commands from the outer checkout root (the directory containing
`package.json` and `03-create-your-own-pool/`) with Node >=22.5.0, a clean
source tree, and the final compiled release root. Use the gate-specific
immutable install command: Q-08 requires `npm ci --ignore-scripts --no-audit
--no-fund`; do not imply that a bare root `npm ci` is script-free. Use only a
final runtime with `finalKey:true`, `developmentKey:false`,
`ceremonyQualified:true`, `production:false`, and `releaseQualified:false`.
The only hard BCH policy ceilings are:

```text
serialized transaction <= 100000 bytes
every input unlocking bytecode <= 10000 bytes
every standard VM resource <= 100%
```

90,000/9,500 or other margins are telemetry only. Never substitute a
preparation transaction, a weakened binding, an aggregate/synthetic record, or
an unavailable VM for a failed candidate.

## Order and custody

```text
B-01-pre + Q-01-pre freeze, including the selected high-capacity descriptor
  -> D-01 ceremony (5 contributors, beacon, 2 transcript verifiers, 2 repro hosts)
    -> Q-01 final-artifact replay (same source, relation, profile, and D-01 root)
      -> B-02-final, Q-02, Q-03, Q-07 (same final root and raw transactions)
        -> D-02 four independent audit closures
          -> Q-08 two independent clean hosts with independently funded journeys
            -> Q-09 30-day >=1000-settlement Chipnet soak plus separate 32-note playground
```

The ceremony coordinator, each contributor, each transcript verifier, each
reproduction host, the four VM-lane authorities, auditors, and Q-08 host
authorities must use different signer IDs, Ed25519 keys, organizations, and
independence domains where the final evidence policy requires it. A contributor
receipt proves hash-chain integrity, not machine independence, entropy
destruction, or governance; keep separate, out-of-band identity/operations
evidence. Participants never send entropy to the coordinator. Signing keys,
wallet seeds, and host private keys stay local; host signing keys are direct,
non-symlink, mode-0600 PKCS#8 files. Do not place secrets in the manifest,
corpus, command transcript, or source tree.

Use a fresh private output directory for every writer. Inputs and retained
bundles are direct, user-owned, mode-0600 files under direct mode-0700
directories unless a gate states a narrower contract. Paths are absolute and
normalized; symlinks and hard-linked files are forbidden. Q-02 corpus
references are the documented safe relative-path exception under its corpus
directory. A failure must preserve a `failure.json` where the runner supports
it; never overwrite, retry in place, or relabel a failed run as a fresh run.

## B-01-pre and Q-01-pre: candidate freeze

First create Q-01-pre at the exact clean commit/tree selected for review. The
argument is an existing direct mode-0700 directory outside the checkout; the
command creates one timestamped exact four-file bundle beneath it and prints
the resulting absolute `bundlePath`:

```text
node 03-create-your-own-pool/scripts/v2-q01-commit-bound-evidence.mjs \
  --output-directory <absolute-existing-mode-0700-directory>
```

Then seal that Q-01-pre bundle together with the development-key PF10 runtime:

```text
node 03-create-your-own-pool/scripts/v2-b01-pre-freeze.mjs \
  --runtime-bundle <absolute-.codex-build/v2-pf10-development-runtime> \
  --q01-pre-bundle <absolute-q01-bundlePath> \
  --expected-commit <sha1> --expected-tree <sha1> \
  --output-dir <absolute-new-directory-outside-the-checkout>

node 03-create-your-own-pool/scripts/v2-b01-pre-freeze.mjs \
  --verify <absolute-b01-pre-bundle>
```

The PF10 runtime directory must share its parent with the direct mode-0700
`v2-pf10-libauth-qualification` and `v2-development-profile` bundles. B-01
invokes the authoritative runtime-coherence verifier: exact 57-artifact
inventory; development profile and relation source; build/setup
attestations; R1CS, WASM, development zkey and VK; canonical and raw proof
qualification; Libauth transactions; structural locks; runtime-material
commitment; and independent Powers-of-Tau/zkey reproduction checks. It hashes
the runtime before and after the four-lane Q-01 replay and rechecks the clean
source commit/tree.

Success is deliberately named
`b01-pre-freeze-candidate-awaiting-independent-review`. It sets
`reviewed:false`, `ceremonyAuthorized:false`, `finalKey:false`,
`production:false`, and `releaseQualified:false`. It retains absolute custody
paths and hashes rather than copying the large runtime. Independent reviewers
must receive every referenced directory, rerun `--verify`, review the frozen
relation/packet/public-input ABI/topology, and separately authorize the
immutable commit/tag before D-01. The generated record is not that review or
authorization.

## D-01: final ceremony and reproduction

Prerequisites are the immutable B-01-pre relation/packet/public-input ABI and
selected topology, plus committed four-implementation Q-01-pre conformance.
The final release policy is Chipnet-only and must authorize one coordinator,
at least five sequence-sorted `ceremony-contributor` authorities, exact roles
`transcript-verifier-a`/`transcript-verifier-b`, and exact roles
`reproduction-host-a`/`reproduction-host-b`. All signer IDs, public keys,
organizations, and independence domains are globally distinct.

For each contribution, the coordinator creates a request using the existing
API in `packages/profile/setup/external-contribution.mjs`:

```text
shieldkit/external-contribution-request/v1
{ ceremonyId, sequence:"1"..., r1csSha256:"sha256:<64hex>",
  ptauSha256:"sha256:<64hex>", previousZkeySha256:"sha256:<64hex>" }
```

The independent participant runs `snarkjs zkey contribute` over the exact
previous zkey, creates an Ed25519 receipt over its canonical domain-separated
body, and returns only the resulting zkey and receipt:

```text
shieldkit/external-contribution-receipt/v1
{ request, contributedZkeySha256:"sha256:<64hex>",
  entropyCommitment:"sha256:<64hex>",
  participant:{id,publicKeySpkiBase64}, signature }
```

The coordinator verifies five or more contiguous receipts with unique IDs and
keys, exact R1CS/ptau/previous-zkey links, then records the resulting
`shieldkit/external-contribution-transcript/v1` and its `transcriptSha256`.
Apply a publicly specified beacon after the last contribution; retain the
beacon value, iteration count, input/output zkey hashes, toolchain hash, and
raw command transcript. Two clean transcript verifiers independently check the
whole contribution chain and beacon. Two separate clean reproduction hosts
rebuild every final artifact from the same source/lockfile and report identical
R1CS, final zkey, verification key, runtime material, lock, and manifest
hashes. The existing final-evidence validator additionally requires canonical
signed envelopes and the schemas:

```text
shieldkit-v2-direct-final-contributor-registry-v1
shieldkit-v2-direct-final-ceremony-transcript-v2
shieldkit-v2-direct-final-ceremony-beacon-v1
shieldkit-v2-direct-final-transcript-verification-v2
shieldkit-v2-direct-final-reproduction-v2
```

Stage the signed-manifest artifacts at:

```text
artifacts/v2-direct/<profileId>/ceremony/contributors.json
artifacts/v2-direct/<profileId>/ceremony/transcript.json
artifacts/v2-direct/<profileId>/ceremony/beacon.json
artifacts/v2-direct/<profileId>/ceremony/verify-host-a.json
artifacts/v2-direct/<profileId>/ceremony/verify-host-b.json
artifacts/v2-direct/<profileId>/ceremony/repro-host-a.json
artifacts/v2-direct/<profileId>/ceremony/repro-host-b.json
```

Accept D-01 only if all signatures, policy authorizations, artifact hashes,
five distinct contribution identities, beacon linkage, two verifier roles, and
two reproduction roles validate and both reproductions match exactly. Reject
any reused authority/domain/key, changed semantic freeze, missing raw command
record, noncanonical JSON, mismatched zkey, or local-simulation claim.

**Implemented fail-closed verifier.** `external-contribution.mjs` and
`final-runtime-evidence.mjs` remain APIs, and `ceremony.mjs` remains explicitly
local/development. The final evidence verifier is:

```text
node 03-create-your-own-pool/scripts/v2-final-ceremony-qualification.mjs \
  --profile-core <absolute> --descriptor <absolute> --final-manifest <absolute> \
  --release-root <compiled-root-id> --ceremony-dir <absolute> \
  --expected-commit <sha1> --expected-tree <sha1> \
  --output-dir <absolute-new-dir>
```

It must reject a dirty tree, unpinned files, unsupported schemas, less than
five contributors, and non-distinct authorities; re-read all signed evidence
and final artifacts; and write only
`<output-dir>/d01-final-ceremony-qualification.json` (canonical JCS, 0600)
with schema `shieldkit-v2-direct-d01-final-ceremony-qualification-v1`, status
`d01-qualified-final-key-not-production-or-release`, `d01Qualified:true`,
`production:false`, `releaseQualified:false`, profile/instance/descriptor/
manifest/runtime/final-zkey hashes, policy/transcript/beacon/contributor/
verifier/repro artifact SHA-256s, contributor count, source commit/tree, and
release-root binding. The ceremony directory is a direct, no-symlink,
inventory-exhaustive binding bundle: all JSON is JCS and it contains the
canonical `post-ceremony-binding.json`, schema
`shieldkit-v2-direct-d01-post-ceremony-binding-v1`, not a misleading
“pre-ceremony freeze” record. It binds the already-completed, signed final
runtime evidence to the exact descriptor/manifest/release root/source commit
and tree, R1CS/PTAU/final-zkey/VK/toolchain hashes, transcript/beacon,
five-contributor threshold, and the two verifier plus two reproduction
envelopes. The inventory must retain the seven canonical filenames above
with hashes exactly equal to the independently verified final-runtime
contributor registry, transcript, beacon, verifier pair, and reproduction
pair; a copied `post-ceremony-binding.json` cannot stand in for them. The
primary evidence remains the signed-manifest final-runtime
artifacts and is revalidated by `final-runtime-evidence.mjs`; this wrapper
adds no alternate ceremony signature format. The public verifier has no test
seam and writes no success artifact on failure; where it can safely create the
new requested output directory it writes one direct 0600 `failure.json`.

## Q-01: post-D-01 final-artifact replay

Run this immediately after D-01 and before any final-key VM gate. The
Q-01-pre bundle must be the immutable mode-0700, exact four-file bundle
created at the same clean source commit/tree used by D-01. Its four direct
mode-0600 files are `manifest.json`, `source-set.json`,
`qualification.json`, and `execution.json`; no additional file, symlink,
hard link, noncanonical JSON, or changed mode is accepted.

```text
node 03-create-your-own-pool/scripts/v2-q01-final-artifact-replay.mjs \
  --profile-core <absolute-mode-0600-file> \
  --descriptor <absolute-mode-0600-file> \
  --final-manifest <absolute-mode-0600-file> \
  --release-root <compiled-root-id> \
  --d01-result <absolute-mode-0600-file> \
  --ceremony-dir <absolute-direct-ceremony-directory> \
  --q01-pre-bundle <absolute-mode-0700-directory> \
  --expected-commit <sha1> --expected-tree <sha1> \
  --output-dir <absolute-new-directory-outside-the-checkout>
```

The verifier resolves the compiled release root before opening
caller-selected evidence. It then re-runs the read-only D-01 verifier over
the direct ceremony directory and requires its resulting canonical D-01
record to exactly equal `--d01-result`; a well-shaped caller-supplied D-01
summary is never sufficient. It revalidates the canonical profile core,
signed descriptor and final manifest through the existing final-runtime
validators; requires `finalKey:true`, `developmentKey:false`,
`ceremonyQualified:true`, `production:false`, and
`releaseQualified:false`; and binds the exact D-01 result, release bootstrap,
profile/instance/topology, descriptor/manifest, source commit/tree, R1CS,
witness WASM, final zkey, VK, runtime material, SnarkJS toolchain, transcript,
beacon, contributor threshold, transcript-verifier pair, and reproduction
pair.

The final relation-source-manifest artifact is resolved by its exact
signed-runtime artifact ID and hash from the validated descriptor. The existing relation
manifest parser checks its schema and complete include graph, then the
existing source verifier independently compares every relation source with
the live checkout. Finally, the authoritative Q-01-pre verifier reruns the
TypeScript, Rust, compiled-Circom, and BCH-covenant lanes and requires their
canonical semantic outputs to be byte-identical to the sealed freeze. The
bundle is hashed before and after the replay and must remain unchanged.

Success creates exactly one canonical mode-0600 file in the newly created
mode-0700 output directory:

```text
q01-final-artifact-replay.json
schema: shieldkit-v2-direct-q01-final-artifact-replay-v1
status: q01-final-artifact-replay-qualified-not-production-or-release
q01FinalReplayQualified: true
production: false
releaseQualified: false
```

Failure never leaves that success artifact and may leave only a bounded
mode-0600 `failure.json`. Unknown CLI fields, a dirty or different source,
test-only Q-01-pre evidence, development/pre-final runtime material,
self-resealed semantic/vector/relation drift, a wrong release root or D-01
identity, noncanonical input, unsafe path/mode, or injected public verifier
seam is fatal. The exported TEST-ONLY dependency seam writes a distinct
`shieldkit-v2-direct-q01-final-artifact-replay-test-only-v1` artifact with
`q01FinalReplayQualified:false`; it validates test fixtures only and is never
qualification evidence.

The verifier is implemented, but no compiled final release root, authentic
D-01 result, signed final descriptor/manifest, or post-D-01 Q-01 result exists
yet. Do not promote its local test fixture.

## B-02-final and Q-02/Q-03/Q-07: one immutable transaction set

Use the D-01 final descriptor and generate the exact selected-topology raw
deposit, transfer, and withdrawal transactions once. Every lane consumes the
same raw bytes, txid, source-output bytes, profile/instance/descriptor/final
locks/runtime/manifest root, tool version and command transcript. Each action
is independently executed by: latest **unmodified** maintainer verifier
benchmark, Libauth, BCHN `testmempoolaccept`, mined BCHN, and LeanBCH.
Base-case acceptance is replayed in all five lanes. Current Q-02
rejection mutations are replayed in Libauth, maintainer, BCHN-mempool, and
LeanBCH. BCHN-mined is intentionally acceptance-only: it proves canonical
inclusion of a valid transaction and cannot prove rejection. An invalid-case
mined-inclusion envelope is rejected rather than treated as negative
evidence. Q-02's external authority roles are exactly `maintainer`,
`bchn-mempool`, `bchn-mined`, and `leanbch`; their IDs and Ed25519 keys must be
unique and come from signed artifact `q02-lane-authorities` with schema
`shieldkit-v2-direct-q02-lane-authorities-v2`. Lane envelopes use
`shieldkit-v2-direct-q02-lane-envelope-v2`, canonical signed attestation
domain `shieldkit-v2-direct-q02-lane-attestation`, version 2, and bind the
expected case subject, raw tx SHA-256/txid and accept/reject expectation.

Existing Q-02 verification is executable (once Node and the final compiled
release root exist):

```bash
node 03-create-your-own-pool/scripts/v2-q02-final-key-corpus.mjs \
  --corpus /absolute/q02/corpus.json --descriptor /absolute/descriptor.json \
  --profile-core /absolute/profile-core.json --release-root <compiled-root-id>
```

It writes no artifact: it reads a canonical
`shieldkit-v2-direct-q02-final-key-corpus-v1` corpus and succeeds only for 768
base cases (256 each deposit/transfer/withdrawal), 9,984 typed mutation cases,
unique proof/packet/transaction identities, final Groth16 verification, exact
topology/input-output layout, source-input authentication, and replayed lane
envelopes. Save its stdout, command, environment, and corpus SHA-256 as a
signed manifest artifact. The corpus and all referenced proof, packet, raw tx,
source-output, local VM, metadata, and external-lane envelope files are the
handoff, not a boolean summary.

Publish B-02 files at:

```text
artifacts/v2-direct/<profileId>/verification/{maintainer,libauth,
  bchn-mempool,bchn-mined,leanbch,measurements}.json
```

`measurements.json` must enumerate every source/output/lock/unlock/serialized
transaction byte count, every VM resource percentage, and every hash
iteration, keyed to raw tx SHA-256 and txid. Reject a missing lane, any lane
accepting a required-invalid case, any lane rejecting a required-valid case,
or a lane that is not in the exact case-specific set. Accepted base cases
require maintainer, BCHN-mempool, BCHN-mined, and LeanBCH external envelopes;
rejected mutations require maintainer, BCHN-mempool, and LeanBCH and forbid a
BCHN-mined reference. Also reject different raw transactions/root, or any
100000/10000/100% violation.

Q-03 must execute burn, partial bundle, mixed parent, fake category, duplicate
NFT, minting authority, omitted successor, altered role counts, and every
MSM/Miller/terminal role swap (including affine and identity branches) against
the selected final locks. Fresh local Libauth plus signed maintainer,
BCHN-mempool, and LeanBCH accept/reject pairs must all agree. All attacks must
reject.

Q-07 needs a signed published-machine manifest and authoritative replay of the
final corpus: p95 prove <=60s, peak RSS <=4GiB, apply <=250ms, full prescribed
100000-action recovery <=15m/RSS <=2GiB/store <=2.5GiB, warm tree work at 100k
within 10% of 1k, fixed-depth operation counts, and separately measured true
cold I/O. The frozen history is one deposit, 99,998 transfers replacing the
one live note, then one withdrawal (99,999 note leaves/nullifiers, zero live
notes/reserve). The small-fixture `v2-q07-performance-harness.mjs` remains
nonqualifying. `v2-q07-final-performance.mjs` is now a fail-closed final
evidence verifier, but no final-profile corpus, published-machine evidence, or
qualifying result exists.

**Implemented fail-closed interfaces.** Run them only from the exact clean
compiled release checkout and only with the final artifacts they require:

```text
node 03-create-your-own-pool/scripts/v2-b02-final-vm.mjs --profile-core <absolute> --descriptor <absolute>
  --final-manifest <absolute> --release-root <compiled-root-id>
  --transactions <absolute> --lane-evidence-dir <absolute> \
  --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-dir>

node 03-create-your-own-pool/scripts/v2-q03-final-lock-attacks.mjs --profile-core <absolute> --descriptor <absolute>
  --final-manifest <absolute> --release-root <compiled-root-id> \
  --b02-result <absolute> --attack-corpus <absolute> --lane-evidence-dir <absolute> \
  --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-dir>

node 03-create-your-own-pool/scripts/v2-q07-final-performance.mjs --profile-core <absolute> --descriptor <absolute>
  --final-manifest <absolute> --release-root <compiled-root-id> \
  --q02-corpus <absolute> --b02-result <absolute> --evidence-dir <absolute> \
  --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-dir>
```

Their sole success artifacts must be canonical JCS, mode 0600:
`b02-final-vm.json` (`shieldkit-v2-direct-b02-final-vm-v1`),
`q03-final-lock-attacks.json` (`shieldkit-v2-direct-q03-final-lock-attacks-v4`), and
`q07-final-performance.json` (`shieldkit-v2-direct-q07-final-performance-v2`). Each must
include `status`, its `q..Qualified`/`b02Qualified:true`, exact final identity
hashes and source pins, input artifact SHA-256s, raw txids/SHA-256s, tool and
machine manifests, per-input results, and complete measurements; Q-03 also
includes each attack/lane rejection, Q-07 each raw timed sample plus claimed
metric. A failed invocation writes its fail-closed `failure.json` schema when
the requested output directory can be created safely. Failure records are
diagnostics, never qualification evidence. No aggregate pass fields can
replace replayable per-case evidence.

## D-02: four audits and closure

After final Q-01 replay, B-02, Q-02, Q-03, Q-07, and applicable pre-audit
Q-05/Q-06 evidence are frozen, obtain independent signed reports
in `audits/v2-direct/{protocol,circuit,covenants,wallet}/` covering respectively
protocol/privacy; circuit/note encryption/ceremony; verifier carriers/binding/
state/topology; and wallet/persistence/recovery/network gate. Each report must
pin the source tree, final root, reviewed artifact hashes, scope, method,
findings, severity/applicability, remediations, and auditor identity/signature.
The closure ledger must reference every report and finding. Reject unresolved
critical/high, applicable medium, skipped mandatory test, synthetic proof,
unavailable VM, non-reproducible artifact, unsigned report, or scope gap.

**Implemented fail-closed verifier.** Run:

```text
node 03-create-your-own-pool/scripts/v2-d02-audit-closure.mjs --profile-core <absolute> --descriptor <absolute>
  --final-manifest <absolute> --release-root <compiled-root-id> \
  --audit-dir <absolute> --evidence-root <absolute> \
  --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-dir>
```

It rehashes/reverifies four independently signed reports and every linked
final artifact, rejects the blockers above, and writes only
`audit-closure.json` with schema `shieldkit-v2-direct-d02-audit-closure-v2`,
`status:"d02-qualified-audit-closure-not-production-or-release"`, `d02Qualified:true`, final identity/source pins,
auditor key fingerprints, report SHA-256s, finding/closure ledger hashes, and
an explicit zero-open-blocker result; otherwise write bound `failure.json`.

## Q-08: two real clean hosts

Only after D-02 as an external policy dependency, provision clean host A and B from the approved compiled
release root. Each host independently verifies signed/pinned final artifacts,
runs exactly `npm ci --ignore-scripts --no-audit --no-fund`, creates/imports a
wallet, displays its funding address, receives a distinct out-of-band raw
funding transaction, syncs from genesis, confirms one deposit, transfer and
withdrawal, deletes local state, recovers from chain history, and confirms a
withdrawal of the recovered note. Funding checkpoints use the v2 schema. The
parser independently checks CashAddress-to-locking-bytecode, the raw
transaction/output index/value, and a six-confirmation raw-header/Merkle proof.
The non-faucet/non-sponsor field is a signer/observer provenance declaration,
not a fact established from transaction bytes:

```text
shieldkit-v2-direct-q08-out-of-band-funding-v2
{fundedAt,fundingAddress,fundingTransactionHex,fundingOutputIndex,
 fundingValueSatoshis,fundingLockingBytecodeHex,chainEvidence,
 provenanceDeclaration:{classification:"declared-non-faucet-non-sponsor",
 scope:"signer-assertion-not-independently-verified"},schema,
 status:"funded-out-of-band"}
```

The signed command plan is `shieldkit-v2-direct-q08-command-plan-v1` with the
exact ten ordered steps `npmCi,wallet,fundingAddress,sync,deposit,transfer,
withdraw,deleteLocalState,recover,recoveredSpend`; test/fixture/mock commands
are refused. Both Q-08 host execution and pair qualification require and
revalidate the D-02 closure; a missing or invalid closure blocks them before a
qualifying host or pair result can be written.
Every action output uses
`shieldkit-v2-direct-q08-step-result-v1`, includes exact raw tx hex/txid and
the local Libauth all-input artifact plus signed maintainer/BCHN-mempool/
BCHN-mined/LeanBCH lane evidence. The host envelope and statement bind the
profile, instance, descriptor, manifest, runtime, release root/bootstrap,
source commit/tree, command/funding/source-pin hashes and hash-chained command
stdout/stderr. Host identity, signer, organization, independence domain,
funding checkpoint/address, and all action txids must differ across A/B.

Each host runs the existing one-shot writer. Production command contracts must
also emit canonical host-state evidence for wallet creation, genesis sync,
local-state deletion, and recovery; absent evidence fails closed. These records
bind exact command stdout/stderr hashes and public state facts, but are signed
host evidence rather than independent proof of wallet internals.

```bash
node 03-create-your-own-pool/scripts/v2-clean-machine-qualification.mjs \
  --output-dir /absolute/new-host-run --descriptor /absolute/descriptor.json \
  --final-manifest /absolute/manifest.json --profile-core /absolute/profile-core.json \
  --release-root <compiled-root-id> --command-plan /absolute/command-plan.json \
  --d02-closure /absolute/audit-closure.json \
  --funding-checkpoint /absolute/funding.json --host-identity /absolute/identity.json \
  --host-role clean-host-a --host-signing-key /absolute/key.pk8 \
  --expected-commit <sha1> --expected-tree <sha1>
```

Repeat with `clean-host-b`, its own inputs and a new directory. Then, from a
clean verifier checkout, run:

```bash
node 03-create-your-own-pool/scripts/v2-q08-pair-qualification.mjs \
  --profile-core /absolute/profile-core.json --descriptor /absolute/descriptor.json \
  --d02-closure /absolute/audit-closure.json \
  --host-a-envelope /absolute/host-a/q08-clean-host-a-signed-host-transcript.json \
  --host-b-envelope /absolute/host-b/q08-clean-host-b-signed-host-transcript.json \
  --output-dir /absolute/new-pair --expected-commit <sha1> \
  --expected-tree <sha1> --release-root <compiled-root-id>
```

It replays both complete signed journeys and writes
`q08-pair-qualification.json` (schema
`shieldkit-v2-direct-q08-pair-qualification-v2`, status `q08-pair-qualified`,
`q08Qualified:true`) only on exact agreement; tests/test-only mode cannot
write qualifying output. Save the two envelopes and pair artifact under
`artifacts/v2-direct/<profileId>/qualification/`. Any reused authority,
funding, txid, source pin, local VM mismatch, missing external envelope, or
noncanonical/symlinked input rejects the pair.

## Q-09: actual Chipnet rollout evidence

Start only after replaying Q-02 and Q-08. The selected final descriptor used
by B-02, Q-02, and Q-08 must already be the final-qualified high-capacity
instance (`maximumLiveNotes >= 210000000`): Q-09 replays those artifacts against
that exact instance. Create only the separate final-qualified playground
descriptor with exactly 32 live notes at this stage; it shares the final
profile/root but not instance ID. Keep at least two distinct trusted Ed25519
chain observers. Collect raw canonical Chipnet headers, >=6-confirmed Merkle
inclusions, observer signatures, and a hash-chained settlement journal of
>=1000 direct deposits/transfers (no `withdraw` or `withdrawal` entries), with
elapsed chain time >=30*24*60*60 seconds. The journal must include the exact
deposit transaction IDs and a two-observer-attested declaration that funding is
non-faucet/non-sponsor. That declaration is provenance testimony, not an
independent cryptographic proof of source-of-funds; do not replace it with a
forbidden-word scan. Reject mainnet, opaque txids, unconfirmed records, and
gaps/duplicates.

The playground evidence must show exactly 32 raw one-note fills, deposit 33
rejected before proof invocation, withdrawals and refills restoring capacity,
erase/recover/recovered-note spend, and >=2 competing prepared candidates with
one confirmed winner and non-broadcast/reproof losers. Candidates must share
the exact carrier/binding/state prevouts; only funding may differ; each has
fresh all-input Libauth evidence. Do not publish the playground before Q-02
and Q-08 pass, and do not use a sponsor or faucet.

Run the existing final validator from an exact clean checkout:

```bash
node 03-create-your-own-pool/scripts/v2-chipnet-soak.mjs \
  --output-dir /absolute/new-q09 --descriptor /absolute/high-capacity.json \
  --playground-descriptor /absolute/playground-32.json \
  --profile-core /absolute/profile-core.json --release-root <compiled-root-id> \
  --source-pin /absolute/q09-source-pin.json --chain-observers /absolute/observers.json \
  --q02-corpus /absolute/q02/corpus.json --q08-host-a /absolute/host-a/envelope.json \
  --q08-host-b /absolute/host-b/envelope.json --q08-pair /absolute/q08-pair-qualification.json \
  --chain-evidence /absolute/chipnet-chain.json --settlements /absolute/settlements.json \
  --playground /absolute/playground.json --expected-commit <sha1> --expected-tree <sha1>
```

Its sole qualifying output is mode-0600
`q09-chipnet-rollout-validation.json`, schema
`shieldkit-v2-direct-q09-chipnet-rollout-validation/v1`, status
`chipnet-rollout-qualified`, `q09Qualified:true`, and hashes for final identity,
source pin, Q-02 corpus, Q-08 pair/envelopes, observer/chain/settlement/
playground evidence, exact settlement count/action counts, first/last block
times, >=30-day elapsed time, confirmations, terminal state/outpoint, and raw
settlement txids. Otherwise it writes `failure.json`; its inaccessible test
seam can write only `test-only-nonqualifying`.

## Boundary probes and handoff

The three current boundary commands intentionally exit nonzero and merely list
missing external evidence; they must never be attached as a pass:

```bash
npm run qualification:external:final-ceremony-and-audits
npm run qualification:external:bchn
npm run qualification:external:chipnet
```

Before handing to the next gate, provide the final signed manifest and profile
core; compiled release-root ID; clean commit/tree; all command transcripts and
tool/machine manifests; raw artifacts plus SHA-256 inventory; signed authority
policy and public keys; D-01/B-02/Q-02/Q-03/Q-07/D-02/Q-08/Q-09 result or
failure artifacts; and an explicit gate status. A missing artifact, missing
executable, unverified signature, wrong path mode, or false qualification flag
means **blocked**, never partial pass.
