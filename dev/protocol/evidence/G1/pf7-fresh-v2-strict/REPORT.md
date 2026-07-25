# ShieldKit-SDK PF7 fresh development corpus (V2 strict-Fr)

Observed: 2026-07-24T03:57:44Z

- Product: ShieldKit-SDK
- Candidate: `bn254-onetx-pf7-sub62-r1` (7 PF7 inputs)
- Corpus SHA-256: `6b0d9d8d481553b8c32a7c82c9846a88ff8d1efd13b73b2d38d9447307f80179`
- verifierSet SHA-256: `0cef373e6add67a72645b33dcc0bb5ea91d4d1c520a8c2eea4a339f1f741ccd6`
- deposit raw attacks: 18/18 reject, falseAccepts=0
- seam redteam: deposit/transfer/withdrawal verdicts = {'deposit': 'pass', 'transfer': 'pass', 'withdrawal': 'pass'}
- Profile (with this verifier set): `sha256:34d907599331997dfc67083742f0fcbb37b971687b1ae420658a172de2119c49`
- Instance: `sha256:1cce04acbd7b6b9fd9f40aac36edaf18024e7e77bbd23d044d9785692850cb3b`
- Not complete ten-input settlement closure; binding/state/fee roles unevaluated in this corpus.
