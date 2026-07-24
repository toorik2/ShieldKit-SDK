# Profile-replacement drill

`runProfileReplacementDrill` is an offline check for the future ceremony/MPC
replacement boundary. It accepts exactly two existing, caller-pinned profile
bundles; it does not select a profile, mutate a bundle, initialize setup,
handle private keys, or broadcast.

Run a real-bundle drill with a JSON file containing `left` and `right` objects,
each with `bundleDirectory` and the complete `expectedProfile` triple
(`network`, `profileId`, `instanceId`):

```sh
node packages/profile-replacement-drill/cli.mjs --input replacement-drill.json
```

Bundle paths in that input are resolved relative to the input file. The output
is canonical JSON containing only public identifiers and derived authority
hashes.

To atomically publish the canonical result as immutable evidence, add an
explicit output path:

```sh
node packages/profile-replacement-drill/cli.mjs \
  --input replacement-drill.json \
  --output replacement-drill-result.json
```

Publication fails if the output already exists.

For each bundle it verifies the manifest hash boundary and pinned
profile/instance coordinates, rederives the category from its fresh category
input, parses the authenticated PF7 verifier-set, and independently derives
the PF7 settlement helper. It requires both the PF7 source set and helper to
change, then opens both bundles through the unchanged desktop SDK interface.
It also proves that the left bundle rejects the right bundle's three-part
profile binding.

The drill supports either two `development-only` bundles or two future
`ceremony-production` bundles. `ceremony-production` means that the normal
bundle loader checked the typed transcript/contribution fields and artifact
integrity; it does not verify ceremony cryptography or establish that the
participants destroyed toxic waste.

The test builds two distinct, hash-authenticated local bundles with structural
P2SH32 PF7 carrier authority and runs the drill. Those carrier scripts do not
verify a proof, so the test makes no PF7 VM, proof, standardness, Chipnet,
ceremony, deployment, or release claim. A real-MPC run must supply two actual
ceremony bundles and separately execute all artifact-dependent G1+ gates.
