# Forge ontology (Wave F — real reject predicates)

Each class is a **shipped Bool predicate** that fails if the reject path breaks.
No `def forge_X := true` constants.

| ID | Reject path (code) | DiffWarrant check |
|----|--------------------|-------------------|
| F-ST | `!(verifyProductAir mutWrongKind/…)` ProductV1 mutations | `forge_F-ST`, `st_mut_*` |
| F-BIND | `Binding.Forges.allForgesRejected` + `forgeRejected omit_*` + unlocking breaks wf | `forge_F-BIND`, `binding_*` |
| F-FRI | `!(runStep friFold zero…one)` | `forge_F-FRI` |
| F-DEEP | `!(runStep deepQAt badDeepInp)` + `!matchesExpect` (x=z inv fail) | `forge_F-DEEP` |
| F-FS | `!(runStep fsAbsorb bad post)` | `forge_F-FS` |
| F-MERK | `!(runStep merkleDigest bad)` | `forge_F-MERK` |
| F-PACK | `unpack badOrderBlob = none` | `forge_F-PACK` |
| F-PARAM | product eligibility blowup=1 → `paramsFail` / verify err | `forge_F-PARAM` |
| F-GRIND | `!grindOk [] [] 64` + runStep grindCheck | `forge_F-GRIND` |
| F-PROD | `mutationsAllRejected` | `forge_F-PROD` |

Module: `FriStark/Soundness/ForgeCoverage.lean`  
Harness: `diff_warrant` → `WARRANT_FORGE_COVERAGE_OK`  
Lean theorems: `forge_ST_ok` … `all_forges_covered_ok` via `native_decide` on **those predicates**.
