# G1 frozen verifier-envelope arithmetic

Observed inputs: the committed verifier-baseline and BCHN v29 source records.

Verdict for the narrow arithmetic claim: **PASS**.

The 54,949 all-bytes baseline leaves 40,051 bytes under the G2 all-bytes
ceiling. Its 54,739-byte transaction leaves 40,261 serialized bytes under the
G2 transaction ceiling. Those figures are only gross space: the candidate
still omits the real shield.cash relation and public-input variation, state and
binding covenants, fee input, change output, encrypted recovery record, and
preparation transactions.

The baseline itself cannot be promoted to G2. Its first three unlocking
bytecodes are 9,853, 9,848, and 9,877 bytes, exceeding the frozen 9,500-byte G2
ceiling by 353, 348, and 377 bytes. A verifier candidate must repartition or
reduce those inputs while retaining real proof execution.

At the source-recorded default floor of 1 satoshi per serialized byte, the
baseline transaction requires 54,739 satoshis. Its fixture encodes only 5,000
satoshis, a 49,739-satoshi shortfall. The minimum estimate is 0.54739 percent
of a 0.1 BCH note.

This is deterministic arithmetic over recorded observations. It is not peer
relay, full-envelope, fee-market, or proof-system qualification evidence.

