# @shield.cash/setup-profile-bridge

Offline, development-only adapter between a completed local Groth16 setup and
the manifest-v1 profile builder. It accepts a regular, non-symlink
`setup-metadata.json` plus its caller-provided SHA-256, validates the metadata
and its actual `final.zkey` and `verification_key.json`, and injects those two
files into the current profile-builder artifact list. The caller supplies only
descriptors (`id`, `kind`, `path`) for those key artifacts; any caller source
or hash is rejected.

The bridge accepts only the local schema and permanent `development-only` /
`local-initialization` mode. It rejects production relabeling, ceremony
records, metadata/output/hash drift, wrong current ABI (exactly two public
inputs and zero outputs), an R1CS artifact not matching the setup metadata,
and a generator identity/hash not matching the setup run. Existing profile
destinations remain fail-closed through the profile builder.

`node cli.mjs --input bridge-input.json` resolves paths relative to its input
file and emits only the development bundle path and derived identifiers. The
returned `profileId` and `instanceId` are derived from profile material and the
caller-supplied pre-genesis identity inputs; they do not construct, broadcast,
or otherwise establish a BCH genesis or instance. The bridge does not perform
setup, create a proof, broadcast, deploy, fund a wallet, or construct an
instance. Using new setup material changes the profile ID and requires a
separate, later explicit genesis and instance workflow.
