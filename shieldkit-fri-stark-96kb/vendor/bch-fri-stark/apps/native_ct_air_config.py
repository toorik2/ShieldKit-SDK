"""
native_ct_air_config.py -- HP1.2 of PATHC_STANDARD_SHARD_MEASURE_BUILD.

The ONE canonical pinned configuration for the native CT-AIR proof + verifier
shard (Data/Logic separation, RULES.md Prinzip 6). The Python prover (HP1.x)
reads these values; the on-chain shard's hardcoded soundness params (HP3.8) MUST
be checked against these by the harness (HP4) -> single source, drift-protected
(R2-L3 field/param consistency).

Values migrated HP1.0d + rebalanced HP1.6 (2026-07-04) to BLOWUP=2048, QUERIES=8,
GRIND_BITS=24 = 104-bit under the CORRECTED conjectural formula q*(log2(BLOWUP)-1)+grind
(HP1.0a: the CT-AIR comp has symbolic degree ~2T and is FRI'd directly, so the tested rate is
2/BLOWUP, not 1/BLOWUP -- the old q*log2(BLOWUP)+grind over-counted 1 bit/query). HP1.6: grind
is the EXPONENTIAL prover PoW (2^grind); the earlier grind=40 (bl512) was ~5.5 days of single-
thread SHA256 -- infeasible for a client-side per-transaction prover -- so blowup was raised to
2048 (higher per-query = fewer grind bits: 2^24 PoW ~7s python / instant optimized) at the same
q=8 and >=100-bit total (security = query+grind is split-invariant). q=8 keeps the topology-split
power-of-2 slot partition; both soundness terms >=100-bit (query 104 conjectural; commit
GF(p^2) field-cap ~127 non-binding). Byte + commit + ZK-mask derivation and primary sources
(BCIKS/ethSTARK/Aurora/Habock): the FRI soundness and ZK masking research literature.
Each value traces to primary sources plus the real byte model, none of it invented.

Field split (HP6.1): S-box / MDS / SHA256-Merkle stay BASE Goldilocks (8 byte);
the Fiat-Shamir / FRI-fold challenge (beta) and the DEEP/ALI combination (alpha)
use the quadratic EXTENSION GF(p^2) so the 64-bit base field does not cap
challenge soundness. Prover and shard MUST agree on this split.
"""
import math

# Goldilocks base field
P = (1 << 64) - (1 << 32) + 1

# FRI / soundness params (HP1.0d migration: bl512/q8/grind40 = 104-bit corrected-conjectural).
# QUERY-term uses the CORRECTED per-query rate log2(BLOWUP)-1 (HP1.0a, see SECURITY_BITS below).
# q=8 is a power of 2 -> keeps the topology-split slot partition (N_open/N_comp | QUERIES).
BLOWUP = 2048
QUERIES = 8
GRIND_BITS = 24
FOLD = 8

# Merkle node width in BYTES (byte reduction lever N3). The FRI/opener trees
# hash with SHA256 and may TRUNCATE each node to this width. Collision-resistance of an n-byte node = n*4 bit (birthday
# 2^(n*8/2)); STARK soundness needs it >= the soundness target -> guarded below. 32 = full SHA256 (128-bit CR, current).
# The N3 lever lowers it to 2*lambda/8 (26B = 104-bit CR, matching the SECURITY_BITS query term) scoped to the CT-AIR
# verifier trees, activated at HP11 whole-tx productionization. A value < 32 is a genuine byte saving (sib 33B -> n+1 B).
MERKLE_HASH_BYTES = 25  # N3: 100-bit CR (= SECURITY_TARGET); -7B per sibling/root vs full SHA256

# ZK witness-hiding mask degree (HP1.2/1.3): random coefficients per trace column, added as
# R(x)*Z_H(x) by native_ntt.lde_coset (vanishes on the trace domain H). Floor = 4*QUERIES,
# asserted below. HP1.4 OPEN: the trace randomizer alone does NOT provably close the deep
# FRI-fold channel -- provable perfect-ZK additionally needs a separate FRI mask polynomial.
MASK_DEG = 64

# native trace size driver: membership-tree depth D -> trace 2^m (cost_report_native.trace_rows)
# Membership depth: T saturates at 2^10 for D>=4 with this AIR; D=4 is the minimum that keeps
# FRI domain N=T*BLOWUP=2^21=8^7 (all s=3 fold-8, no tail). Larger D only lengthens membership
# Merkle paths (deepquery unlock) without adding FRI soundness — keep the minimum for ship size.
TRACE_D = 4

# field split (HP6.1): which parts run in the quadratic extension GF(p^2)
EXT_DEGREE = 2
# Quadratic-extension non-residue: GF(p^2) = F_p[u]/(u^2 - EXT_NONRES). Goldilocks
# uses u^2 - 7 (Plonky2/Plonky3 binomial extension; cost_report_native_ext.py:63).
# u^2 - 7 is a field iff 7 is a quadratic NON-residue mod p -> guarded below.
EXT_NONRES = 7
BASE_FIELD_OPS = ("sbox", "mds", "sha256_merkle")            # base Goldilocks (8 byte)
EXT_FIELD_OPS = ("fs_challenge", "fri_fold_beta", "deep_alpha")  # GF(p^2)

SECURITY_TARGET_BITS = 100

# self-validating guard (sharp-edges pit-of-success): a config that does not reach
# the >=100-bit target must fail LOUDLY at import, not silently weaken soundness.
# CORRECTED formula (HP1.0a): the CT-AIR composition has symbolic degree ~2T and is FRI'd
# DIRECTLY (no ethSTARK degree-split to <N/BLOWUP; native_ct_air_stark.py:45-47,159-171), so
# the tested Reed-Solomon rate is rho = 2/BLOWUP and per-query soundness = log2(1/rho) =
# log2(BLOWUP)-1 -- NOT log2(BLOWUP). (ethSTARK v1.2 Conjecture 7.3, spec line 555.) The old
# q*log2(BLOWUP)+grind over-counted 1 bit/query. Conjectural capacity regime (industry standard);
# the commit-term (BCIKS Thm 8.3 / ethSTARK Eq 10 = (m+1/2)^7*N^2/(2^1.5*|K|)) uses the FRI-fold
# challenge field |K| = GF(p^2) = 2^128 (fri_fold_beta) -> field cap ~127, conjecturally non-binding.
# 2nd-order (documented, not gated): the ZK mask lifts deg(comp) from ~2T to ~2(T+MASK_DEG), so the
# TRUE conjectural per-query is log2(BLOWUP)-1 - log2(1+MASK_DEG/T); at deploy (T=2^10, MASK_DEG=64)
# that is ~9.91 not 10.0 -> true ~103.3 bit. The headline below uses the un-masked rate 2/BLOWUP
# (standard STARK practice; MASK_DEG<<T makes the effect ~0.7 bit) and the >=100 target keeps >3-bit margin.
SECURITY_BITS = QUERIES * (math.log2(BLOWUP) - 1) + GRIND_BITS
assert SECURITY_BITS >= SECURITY_TARGET_BITS, (
    "pinned config below %d-bit: q=%d blowup=%d grind=%d -> %.1f bit"
    % (SECURITY_TARGET_BITS, QUERIES, BLOWUP, GRIND_BITS, SECURITY_BITS))
# ZK witness-hiding floor (HP1.2/1.3): the verifier learns each trace column at 2 rows per query
# (row k and row kn=k+shift) AND the composition FRI-opened at the antipode per query (2 more
# trace points), with NO separate FRI mask. Bounded independence (Aurora ePrint 2018/828
# Def 4.4 / S7.1; Habock-Al Kindi ePrint 2024/1037 Lemma 1 / Eq 3 with nF=0) needs >= (evaluations
# revealed outside H) random coeffs/column: 2*QUERIES is the necessary red line (direct trace
# openings alone leak below it), 4*QUERIES the sufficient floor (incl. composition antipodes).
assert MASK_DEG >= 4 * QUERIES, (
    "ZK mask too small: mask_deg=%d < 4*queries=%d -> trace/composition openings leak the witness"
    % (MASK_DEG, 4 * QUERIES))
assert EXT_DEGREE == 2, "extension field must be quadratic GF(p^2) for >=100-bit challenges"
# fail-closed (byte-lever N3, sharp-edges pit-of-success): the Merkle node width must keep collision-resistance
# (n*4 bit) at or above the soundness target, else a truncated tree is the weakest link -> forgeable openings.
# 25B=100-bit (exact), 26B=104-bit (matches the query term). Reject any width that drops below target or exceeds SHA256.
assert 4 * MERKLE_HASH_BYTES >= SECURITY_TARGET_BITS, (
    "MERKLE_HASH_BYTES=%d -> %d-bit collision-resistance < %d-bit target: truncated Merkle would be forgeable"
    % (MERKLE_HASH_BYTES, 4 * MERKLE_HASH_BYTES, SECURITY_TARGET_BITS))
assert MERKLE_HASH_BYTES <= 32, "MERKLE_HASH_BYTES=%d exceeds SHA256 output (32B)" % MERKLE_HASH_BYTES
# fail-closed: EXT_NONRES MUST be a quadratic non-residue or GF(p^2) is not a field
# (u^2-EXT_NONRES reducible -> zero divisors -> unsound challenges). Euler's criterion.
assert pow(EXT_NONRES, (P - 1) // 2, P) == P - 1, (
    "EXT_NONRES=%d is a quadratic residue mod p -> u^2-%d reducible, GF(p^2) invalid"
    % (EXT_NONRES, EXT_NONRES))


if __name__ == "__main__":
    print("HP1 native CT-AIR config (pinned, >=100-bit corrected-conjectural):")
    print("  BLOWUP=%d QUERIES=%d GRIND_BITS=%d FOLD=%d TRACE_D=%d MASK_DEG=%d"
          % (BLOWUP, QUERIES, GRIND_BITS, FOLD, TRACE_D, MASK_DEG))
    print("  security = %d*(log2(%d)-1)+%d = %.1f bit (target >=%d) OK"
          % (QUERIES, BLOWUP, GRIND_BITS, SECURITY_BITS, SECURITY_TARGET_BITS))
    print("  ZK mask_deg=%d >= 4*queries=%d OK" % (MASK_DEG, 4 * QUERIES))
    print("  field split: base=%s  ext(GF(p^%d), u^2=%d)=%s"
          % (BASE_FIELD_OPS, EXT_DEGREE, EXT_NONRES, EXT_FIELD_OPS))
