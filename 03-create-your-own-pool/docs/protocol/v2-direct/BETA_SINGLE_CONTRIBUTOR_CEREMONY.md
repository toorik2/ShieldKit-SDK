# Single-contributor beta setup

This is an operator procedure for a deliberately non-qualifying beta proving
key. It is not D-01, an alternative D-01 procedure, a release procedure, or
evidence for public deployment. The production D-01 requirements remain: at
least five independent phase-2 contributors, a public beacon, two transcript
verifiers, and two independent reproduction hosts.

## Exact trust statement

A single contributor can establish a reproducible, cryptographically checked
beta setup transcript and a proving key that is useful for private local
integration work. It cannot establish that toxic waste is unknown to every
party. The contributor may retain the phase-2 secret, and a receipt or claimed
destruction does not change that fact.

The following claims are false for the setup and for every artifact derived
from it:

```text
ceremonyQualified=false       d01Qualified=false
finalKey=false                q01FinalReplayQualified=false
b02Qualified=false            q02Qualified=false
q03Qualified=false            q07Qualified=false
d02Qualified=false            q08Qualified=false
q09Qualified=false            production=false
releaseQualified=false
participantIndependenceEstablished=false
```

Call the resulting material a **beta proving key** and a
**single-contributor beta setup**, never a final key or final ceremony. A
successful cryptographic zkey verification establishes only that the key is
well-formed for its pinned R1CS/PTau inputs; it is not a ceremony-independence
or release claim.

## Scope and custody boundary

Use beta material only in an explicit beta/local integration environment. Do
not put it in a final descriptor, signed final manifest, compiled release
root, normal wallet/runtime path, clean-host procedure, or broadcast/soak
workflow. Do not label beta evidence B-02, Q-02, Q-03, Q-07, D-02, Q-08, or
Q-09; those names are reserved for the final-rooted qualification gates.

The beta custody directory is private: direct, user-owned, mode 0700, with
direct mode-0600 files. Do not use symlinks or hard links. Retain the pinned
R1CS, PTau, input and output zkey hashes, toolchain identity, receipt,
transcript, and cryptographic verification result. These records demonstrate
provenance and reproducibility, not independence or destruction.

## Entropy handling

Entropy is never pasted into chat, supplied in command-line arguments, placed
in environment variables, written to an input file, or printed to terminal
logs. Do not record raw dice values, a seed, passphrase, random bytes, shell
history, or process arguments. The retained receipt/transcript contains only
public identities, command/toolchain metadata, and commitments/hashes needed
for custody verification.

The contribution process combines two independent inputs:

1. Roll a fair six-sided die at least 100 times. Enter between 100 and 128
   outcomes as digits from `1` through `6`, with no spaces or separators,
   only through the contribution process's controlling TTY; do not save it,
   copy it through a clipboard manager, or redirect it.
2. It adds a 64-byte operating-system randomness hedge generated inside that same
   process. It must not be passed into the process through argv, environment,
   a file, a pipe, chat, or a log.

The 100-or-more d6 rolls are operator entropy; the 64-byte OS value is a hedge,
not a substitute for the rolls. TTY-only input reduces accidental persistence
but does not prove entropy quality or secret destruction.

## Lifecycle

1. Freeze and record the exact R1CS, PTau, input zkey, source commit/tree, and
   toolchain hashes before contributing. Confirm the beta custody directory is
   private and newly created.
2. Use the domain-separated beta contribution lifecycle represented by
   `packages/profile/setup/external-contribution.mjs`: bind the expected
   previous-zkey/R1CS/PTau hashes in the beta-only request schema, perform one
   phase-2 contribution, and retain the beta-only signed receipt/transcript.
   These schemas and the signing domain cannot be replayed as generic or final
   contribution evidence. The underlying cryptographic operation is `snarkjs
   zkey contribute` over those exact inputs.

   ```text
   shieldkit/v2-beta-single-contributor-contribution-request/v2
   shieldkit/v2-beta-single-contributor-contribution-receipt/v2
   shieldkit/v2-beta-single-contributor-ceremony-transcript/v2
   ```
3. Collect at least 100 d6 rolls only through the controlling TTY, and obtain
   the independent 64-byte OS hedge directly from the in-process CSPRNG. Keep
   all raw entropy out of persistent channels.
4. Record the output zkey hash and receipt/transcript. Run cryptographic zkey
   verification against the pinned R1CS and PTau, then export and hash the
   verification key. Preserve both success and failure records; a failure is
   not retryable in place.
5. Treat the beta proving key as potentially known to its contributor. If the
   local policy requests destruction, the operator may destroy transient
   material after verification, but must state only that destruction was
   requested/performed locally. It is not independently verifiable and does
   not upgrade any claim.

### Operator command

Run this lane only with Node >=22.5.0 from an exact clean source checkout. The
input B-01-pre bundle must verify against that exact checkout. Create an empty,
direct, user-owned mode-0700 parent outside the source checkout; `prepare`
creates the named child atomically and refuses an existing target:

```text
npm run ceremony:v2:beta-single -- prepare \
  --b01-bundle <absolute-mode-0700-b01-pre-bundle> \
  --ceremony-id <lowercase-stable-id> \
  --participant-id <lowercase-public-id> \
  --output-dir <absolute-new-beta-custody-directory>
```

Preparation independently revalidates B-01-pre, makes private copies of the
pinned R1CS, PTau, and initial zkey, fully verifies the Powers of Tau and input
zkey with the pinned Node/snarkjs dependency closure, and creates a local
mode-0600 Ed25519 receipt key. It publishes no contribution or qualification.
After a successful signed receipt and atomic result publication, the runner
removes that local private receipt key; public verification needs only the
prepared public key and signed receipt.

When at least 100 physical die outcomes are ready, run the contribution
directly in an interactive terminal. Do not paste the rolls here or into any
other chat, file, shell argument, environment variable, or pipe:

```text
npm run ceremony:v2:beta-single -- contribute \
  --ceremony-dir <absolute-beta-custody-directory>
```

The process disables TTY echo, accepts 100 through 128 characters from `1`
through `6` with no spaces or separators, length-prefixes the complete sequence,
adds 64 bytes from the operating-system CSPRNG, derives a request-bound
secret, and sends it to the pinned snarkjs child only after the exact entropy
prompt appears. It does not offer an entropy CLI option. The result directory
is published atomically only after `zkey verify`, canonical verification-key
export, toolchain remeasurement, signed receipt creation, and exact
one-contributor beta-transcript validation all succeed.

Rerun the public verification path after contribution:

```text
npm run ceremony:v2:beta-single -- verify \
  --ceremony-dir <absolute-beta-custody-directory>
```

This re-reads every pin and signed record, reruns zkey verification, derives
the verification key again, and still returns only
`beta-single-contributor-reverified-unqualified` with every qualification,
production, and release claim false. Unknown or duplicate arguments fail
closed. The signed v2 request binds the exact entropy-policy hash and the
preparation pins and remeasures the security-critical implementation files
before and after contribution. The CLI completes all non-secret preparation,
artifact, toolchain, implementation, and signing-key checks before asking for
dice. A v1 preparation is deliberately incompatible and cannot be reused.
There is deliberately no `--beta` flag on D-01 and no broadcast flag.
Preparation, contribution, and verification require a clean Git index and
worktree: staged changes, unstaged changes, and non-ignored untracked paths all
fail closed. The implementation manifest hashes every tracked file and requires
the same Git commit and tree before and after that measurement, so it detects
source drift after preparation without falsely labeling dirty bytes as a clean
commit. It is not an external trust anchor and cannot defeat a host or same-user
attacker who controlled the runner before preparation.
If the process is interrupted after a private stage is created, the runner
refuses in-place retry: preserve diagnostics, discard that ceremony attempt,
and prepare a fresh ceremony ID with fresh dice. If terminal state appears
damaged after an uncatchable `SIGKILL`, power loss, or host failure, run
`stty sane` from a trusted local terminal before continuing; such failures
cannot provide a secret-erasure guarantee.

## Optional beta-local integration handoff

After a successful ceremony re-verification, the result may be consumed only
by the separate private beta-local integration runner. That runner requires the
ceremony-bound exact B-01-pre manifest and runtime, a clean checkout for its
build-time commit/tree binding, and a new private output below `.codex-build/`.
It copies and re-inventories its custody inputs, then produces and re-verifies
only an unqualified local evidence root. It has no network or broadcast
interface. Follow [BETA_LOCAL_INTEGRATION.md](BETA_LOCAL_INTEGRATION.md) for
the exact build and re-verification commands.

This handoff does not change the ceremony's trust statement. In particular, it
does not demonstrate unknown toxic waste, add a participant, create a final
key, establish a D-01 lineage, or permit production/release/qualification
claims. The generated completion and inventory records, rather than this
document, contain any actual run-specific hashes and verifier results.

## Later finalization is separate

A public beacon is a later, separate step in a real final D-01 ceremony after
the required independent contributors. It does not convert this beta setup
into D-01, and it must not be represented as a beta "finalization" step.

Final D-01 must start a fresh final key lineage: a beta proving-key hash must
not be reused as a D-01 final proving key, and beta receipt/transcript/output
artifacts must not be copied into final ceremony inventory or runtime evidence.
The only route to `d01Qualified:true` is the unmodified five-party D-01 flow
in the external qualification runbook, followed by its independent replay and
later gates.
