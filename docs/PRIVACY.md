# V1 privacy claim and leakage matrix

Document version: 0.1

Status: product privacy model (ShieldKit V1)

## 1. Claim

For a conforming 0.1 BCH action, the protocol aims to make it computationally
infeasible for a passive observer using only BCH consensus-visible data to
determine which qualifying earlier deposit or note funded a qualifying private
transfer or withdrawal, except for information implied by the public boundary,
the set of compatible candidate notes, and the observer's prior knowledge.

This is a blockchain unlinkability claim. It is not a claim of network
anonymity, traffic-analysis resistance, provider-query privacy, or protection
from deductions that follow from a uniquely identifying candidate set or user
behavior.

The claim applies only when:

- all actions use the ratified profile, instance, denomination, and canonical
  transaction shapes;
- the relevant cryptographic assumptions hold;
- wallet secrets and note plaintexts are not disclosed;
- the implementation does not add identifying metadata; and
- the observer cannot reduce the candidate set to one using information outside
  BCH consensus-visible data.

## 2. Leakage matrix

| Information | BCH observer learns it? | V1 treatment |
| --- | --- | --- |
| Profile and pool instance | Yes | Public and domain-bound |
| Transaction ID, block position, confirmation time, and transaction graph | Yes | Unhidden |
| Deposit and withdrawal boundary scripts and values | Yes | Public boundary |
| Note denomination | Yes | Fixed at 0.1 BCH |
| Action type, if transaction shapes differ | Possibly | Must be measured and documented |
| Complete transaction shape, input/output count, scripts, tokens, and byte lengths | Yes | Public; canonicalization should reduce fingerprinting |
| State roots, nullifiers, counters, and successor state | Yes | Public commitments and spent-note markers |
| Encrypted note-record location and length | Yes | Public; plaintext and recipient should remain hidden under the encryption assumptions |
| Which candidate note is consumed | No, by the cryptographic claim | The core blockchain unlinkability target |
| Link from a qualifying deposit to a later qualifying withdrawal | No, by the cryptographic claim | The core blockchain unlinkability target |
| Internal sender, recipient, and transferred ownership | No, by the cryptographic claim | Hidden unless revealed by boundary behavior or external data |
| Miner fee, transparent fee inputs, reimbursement outputs, and change | Yes, if present | Exact leakage depends on the fee mechanism selected at G6 |
| Deposit/withdrawal timing and candidate-set size | Yes | Explicit inference surface; no timing-anonymity promise |
| Wallet, SDK, or application fingerprint | Possibly | Must be measured; not hidden if it changes observable bytes or behavior |
| IP address, peer topology, broadcast origin, and traffic timing | Outside claim | No V1 network-anonymity promise |
| Indexer, RPC, artifact-host, or coordinator queries | Outside claim | Providers are optional and untrusted; query privacy is not promised |
| Compromised device, seed, viewing data, note plaintext, or application telemetry | Outside claim | Endpoint security and disclosure are separate threats |

## 3. Prohibited shorthand

Documentation and APIs must not reduce this claim to “anonymous,” “untraceable,”
or “private transaction.” User-facing language must say what is hidden, from
whom, and which public or external signals can still reveal a link.

## 4. Evidence required later

G7 must test this claim against exact transactions and population assumptions,
including timing, transaction-shape, fee-source, provider-query, and
application-fingerprint correlation. A cryptographically valid construction
does not pass G7 if the released transaction behavior makes the claimed link
deterministic.
