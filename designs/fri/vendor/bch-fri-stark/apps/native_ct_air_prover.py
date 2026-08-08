"""
native_ct_air_prover.py -- HP1.3-1.6 of PATHC_STANDARD_SHARD_MEASURE_BUILD.

Native CT-AIR prover for a confidential transfer, over Goldilocks, EC-free, using
the KAT-verified Poseidon2 (native_poseidon2.py). Built incrementally; each AIR
constraint block has a satisfied-on-valid / fails-on-tamper gate (TEST_RULES: real
witness, no mocks). Reuses the stark.py engine (prove/verify) like membership_stark.py.

THIS FILE (current stage): the Poseidon2 round-transition AIR gate -- the core and
hardest constraint. air_check_perm verifies, row-to-row, that the recorded trace is
a valid Poseidon2 permutation:
  * S-box (x^7) via aux: x2=x^2, x4=x2^2, x6=x4*x2, y=x6*x, x=cur[i]+rc[r][i]
    (full round: all 12 lanes; partial round: lane 0 only, lanes>=1 pass through),
  * linear layer: next_state == matmul_external(y) (full) / matmul_internal(y) (partial).
Later stages add: sponge input/output boundary, owner/nf/cm hashes, Poseidon2-Merkle
membership, range (Num2Bits 64), conservation, then stark.py prove/verify + export.
"""
import os
import sys

_APPS = os.path.dirname(os.path.abspath(__file__))
if _APPS not in sys.path:
    sys.path.insert(0, _APPS)

import native_poseidon2 as P2
import native_gf_p2 as _F2                # HP4: GF(p^2) arithmetic for the DEEP AIR-eval-once at z
from native_poseidon2 import P, WIDTH, RC, _matmul_external, _matmul_internal

ROUNDS = P2._ROUNDS            # 30
RF_HALF = P2._RF_HALF          # 4
ROUNDS_P = P2.ROUNDS_P         # 22


def _sbox_aux_ok(x, a, b, c, y):
    """x^7 low-degree decomposition check: a=x^2, b=a^2, c=b*a, y=c*x."""
    return (a == (x * x) % P and b == (a * a) % P
            and c == (b * a) % P and y == (c * x) % P)


def air_check_perm(states, aux):
    """True iff (states, aux) is a valid Poseidon2 round-per-row trace.
    This is the verifier-side transition relation, recomputed independently of
    permutation_trace (S-box via aux + linear layer recomputation)."""
    if len(states) != ROUNDS + 1 or len(aux) != ROUNDS:
        return False
    p_end = RF_HALF + ROUNDS_P
    for r in range(ROUNDS):
        cur, nxt, a = states[r], states[r + 1], aux[r]
        full = (r < RF_HALF) or (r >= p_end)
        if a["full"] != full:
            return False
        y = a["y"]
        if full:
            for i in range(WIDTH):
                x = (cur[i] + RC[r][i]) % P
                if not _sbox_aux_ok(x, a["x2"][i], a["x4"][i], a["x6"][i], y[i]):
                    return False
            chk = y[:]
            _matmul_external(chk)
        else:
            x = (cur[0] + RC[r][0]) % P
            if not _sbox_aux_ok(x, a["x2"][0], a["x4"][0], a["x6"][0], y[0]):
                return False
            for i in range(1, WIDTH):
                if y[i] != cur[i]:      # partial round: non-active lanes pass through
                    return False
            chk = y[:]
            _matmul_internal(chk)
        if chk != nxt:
            return False
    return True


# ---- range + conservation (HP1.4 / HP1.5), wrap-safe over Goldilocks ----------
# Ausfuehrungs-Luecke A1 (planen.md): Num2Bits(64) over Goldilocks is VACUOUS
# (every field element < p < 2^64) and would leave conservation field-wrap
# attackable. Sound bound: (N_OUT+1)*2^B < p. For 1-in/2-out (out0+out1+fee=3
# terms) B=62 is the maximal wrap-safe width (3*2^62 < p < 3*2^63).
N_IN = 1
N_OUT = 2
_TERMS = N_OUT + 1  # out0 + out1 + fee (the larger side of the balance)


def _max_wrap_safe_bits():
    b = 0
    while _TERMS * (1 << (b + 1)) < P:
        b += 1
    return b


RANGE_BITS = _max_wrap_safe_bits()  # 62 for 1-in/2-out
assert _TERMS * (1 << RANGE_BITS) < P, "range bound not wrap-safe"
assert _TERMS * (1 << (RANGE_BITS + 1)) >= P, "range bound not maximal"


def range_bits(v):
    """LSB-first bit decomposition of v in RANGE_BITS bits. Raises if v >= 2^B
    (an out-of-range / wrap-attempt value cannot be represented -> caught)."""
    if not (0 <= v < (1 << RANGE_BITS)):
        raise ValueError("value %d not in [0, 2^%d)" % (v, RANGE_BITS))
    return [(v >> i) & 1 for i in range(RANGE_BITS)]


def air_check_range(v, bits):
    """True iff bits are boolean AND recompose to v in RANGE_BITS bits."""
    if len(bits) != RANGE_BITS:
        return False
    acc = 0
    for i, b in enumerate(bits):
        if b not in (0, 1):                 # booleanity: b*(b-1)==0
            return False
        acc = (acc + (b << i))
    return acc == v % P and v < (1 << RANGE_BITS)


def air_check_conservation(v_in, v_outs, fee):
    """True iff v_in == sum(v_outs)+fee. Sound (exact, no wrap) ONLY when every
    value is range-checked to < 2^RANGE_BITS (caller MUST pair this with
    air_check_range); then both sides are < p so the field identity is integer."""
    return v_in % P == (sum(v_outs) + fee) % P


# ---- transfer computation (HP1.3 value level): witness -> public statement -----
# 1-in / 2-out confidential transfer over the EC-free hash-note model (HP2-ERGEBNIS):
#   owner_pk = Poseidon2(sk)                         (ownership)
#   nf       = Poseidon2(sk, rho_in, DOM_NF)         (nullifier, domain-separated)
#   cm_in    = Poseidon2(value_in, owner_pk, rho_in, blind_in)
#   root     = Poseidon2-Merkle path of cm_in over siblings   (membership)
#   cm_out_i = Poseidon2(value_out_i, owner_out_i, rho_out_i, blind_out_i)
#   conservation: value_in == value_out_0 + value_out_1 + fee  (all range-checked, A1)
# Public statement (verifier inputs): root, nf, cm_out_0, cm_out_1. Values stay hidden.
DOM_NF = 0x636173685f6e66  # "cash_nf" domain tag for nullifier (fixed separator)


def compute_transfer(w):
    """Compute the public statement from a witness dict. Returns (statement, derived).
    Enforces range (all values < 2^RANGE_BITS) + conservation (A1 wrap-safe)."""
    sk = w["sk"] % P
    value_in = w["value_in"]; fee = w["fee"]
    value_outs = list(w["value_outs"]); owners_out = list(w["owners_out"])
    rhos_out = list(w["rhos_out"]); blinds_out = list(w["blinds_out"])
    # range-check ALL values (FP-agent A1 addendum): in, outs, fee
    for v in [value_in, fee] + value_outs:
        if not air_check_range(v, range_bits(v)):
            raise ValueError("value out of wrap-safe range [0,2^%d): %d" % (RANGE_BITS, v))
    if not air_check_conservation(value_in, value_outs, fee):
        raise ValueError("conservation violated: %d != sum(%s)+%d" % (value_in, value_outs, fee))
    owner_pk = P2.hash_to_1([sk])
    nf = P2.hash_to_1([sk, w["rho_in"], DOM_NF])
    cm_in = P2.hash_to_1([value_in, owner_pk, w["rho_in"], w["blind_in"]])
    digest = cm_in
    for sib in w["siblings"]:
        digest = P2.merkle_compress(digest, sib % P)
    root = digest
    cm_out = [P2.hash_to_1([value_outs[i], owners_out[i], rhos_out[i], blinds_out[i]])
              for i in range(N_OUT)]
    statement = {"root": root, "nf": nf, "cm_out": cm_out, "depth": len(w["siblings"])}
    derived = {"owner_pk": owner_pk, "cm_in": cm_in}
    return statement, derived


def _derive_ext_matrix():
    """Explicit 12x12 external linear layer M_EXT, derived from the VERIFIED
    matmul_external by applying it to the unit vectors (no hand-transcription).
    The round-AIR's full-round state-update constraint is next[j] = (M_EXT . y)[j]."""
    M = [[0] * WIDTH for _ in range(WIDTH)]
    for k in range(WIDTH):
        e = [0] * WIDTH
        e[k] = 1
        _matmul_external(e)
        for j in range(WIDTH):
            M[j][k] = e[j]
    return M


M_EXT = _derive_ext_matrix()


def _ext_apply(y):
    return [sum(M_EXT[j][k] * y[k] for k in range(WIDTH)) % P for j in range(WIDTH)]


def _invert_matrix(M):
    """Inverse of a WIDTH x WIDTH matrix over GF(P) via Gauss-Jordan. Raises if
    singular (M_EXT is MDS -> invertible)."""
    n = WIDTH
    a = [[M[i][j] % P for j in range(n)] + [1 if j == i else 0 for j in range(n)]
         for i in range(n)]
    for col in range(n):
        piv = next((r for r in range(col, n) if a[r][col] % P != 0), None)
        if piv is None:
            raise ValueError("matrix singular at col %d" % col)
        a[col], a[piv] = a[piv], a[col]
        invp = pow(a[col][col], P - 2, P)
        a[col] = [(v * invp) % P for v in a[col]]
        for r in range(n):
            if r != col and a[r][col] % P != 0:
                f = a[r][col]
                a[r] = [(a[r][k] - f * a[col][k]) % P for k in range(2 * n)]
    return [row[n:] for row in a]


M_EXT_INV = _invert_matrix(M_EXT)


def _ext_inv_apply(v):
    """M_EXT^{-1} . v -- recovers a block's sponge-absorbed input from its committed
    first row (states[0] = M_EXT . absorbed). The verifier binds chaining + the
    zero-capacity sponge structure through this public linear map."""
    return [sum(M_EXT_INV[j][k] * v[k] for k in range(WIDTH)) % P for j in range(WIDTH)]


def _int_apply(y):
    """Internal linear layer: result[i] = y[i]*diag[i] + sum(y)  (verified formula)."""
    s = sum(y) % P
    return [((y[i] * P2.MAT_DIAG12[i]) % P + s) % P for i in range(WIDTH)]


def _absorb(inputs):
    """Sponge-absorbed t=12 state for <=RATE inputs: [inputs || 0-pad(rate) || 0-cap].
    permutation_trace(_absorb(xs))[states][_ROUNDS][0] == hash_to_1(xs)."""
    assert len(inputs) <= P2.RATE, "single-perm sponge holds <=%d inputs" % P2.RATE
    st = [0] * WIDTH
    for i, v in enumerate(inputs):
        st[i] = v % P
    return st


def _block(inputs):
    """One Poseidon2-permutation block for a hash of `inputs`. Returns
    {input, states, aux, out} where out == hash_to_1(inputs)."""
    st = _absorb(inputs)
    states, aux = P2.permutation_trace(st)
    return {"input": st, "states": states, "aux": aux, "out": states[-1][0]}


def build_ct_trace(w):
    """Structured round-per-row CT-AIR trace of the transfer (HP1.6 step 1).
    Blocks (each one Poseidon2 permutation): owner, nf, cm_in, D x membership
    compress, 2 x cm_out. Plus range bits (all values) + conservation tuple.
    Returns (trace, statement); air_check_full verifies the whole thing."""
    stmt, der = compute_transfer(w)             # value-level (range+conservation enforced)
    sk = w["sk"] % P
    blocks = {}
    blocks["owner"] = _block([sk])
    owner_pk = blocks["owner"]["out"]
    blocks["nf"] = _block([sk, w["rho_in"], DOM_NF])
    blocks["cm_in"] = _block([w["value_in"], owner_pk, w["rho_in"], w["blind_in"]])
    # membership: chain compress(digest, sibling) from cm_in up to root
    digest = blocks["cm_in"]["out"]
    blocks["memb"] = []
    for sib in w["siblings"]:
        b = _block([digest, sib % P])
        blocks["memb"].append({"block": b, "sibling": sib % P, "in_digest": digest})
        digest = b["out"]
    blocks["cm_out"] = [
        _block([w["value_outs"][i], w["owners_out"][i], w["rhos_out"][i], w["blinds_out"][i]])
        for i in range(N_OUT)]
    # range bits for ALL values (A1) ; conservation tuple
    rng = {
        "value_in": range_bits(w["value_in"]),
        "fee": range_bits(w["fee"]),
        "value_outs": [range_bits(v) for v in w["value_outs"]],
    }
    cons = {"value_in": w["value_in"], "value_outs": list(w["value_outs"]), "fee": w["fee"]}
    trace = {"blocks": blocks, "owner_pk": owner_pk, "rng": rng, "cons": cons, "siblings": w["siblings"]}
    return trace, stmt


def air_check_full(trace, stmt):
    """Verify EVERY CT-AIR relation on the structured trace: per-block Poseidon2
    round transitions, sponge input/output bindings, cross-block chaining,
    range, conservation, and the public-statement boundary. True iff all hold."""
    bl = trace["blocks"]

    def block_ok(b, expect_input):
        if b["input"] != _absorb(expect_input):
            return False                                  # sponge input boundary
        if not air_check_perm(b["states"], b["aux"]):
            return False                                  # Poseidon2 round transitions
        if b["out"] != b["states"][-1][0]:
            return False                                  # output binding
        return True

    sk_in = bl["owner"]["input"][0]                       # sk recovered from owner block
    if not block_ok(bl["owner"], [sk_in]):
        return False
    owner_pk = bl["owner"]["out"]
    if owner_pk != trace["owner_pk"]:
        return False
    # nf block: inputs [sk, rho_in, DOM_NF]; sk must match owner's sk; DOM pinned
    nf_in = bl["nf"]["input"]
    if nf_in[0] != sk_in or nf_in[2] != DOM_NF:
        return False
    if not block_ok(bl["nf"], [nf_in[0], nf_in[1], nf_in[2]]):
        return False
    # cm_in: inputs [value_in, owner_pk, rho_in, blind_in]; owner_pk must chain
    cm = bl["cm_in"]["input"]
    if cm[1] != owner_pk:
        return False
    if not block_ok(bl["cm_in"], [cm[0], cm[1], cm[2], cm[3]]):
        return False
    # membership chain: in_digest[0]=cm_in.out, each level chains, final == root
    digest = bl["cm_in"]["out"]
    for lvl in bl["memb"]:
        if lvl["in_digest"] != digest:
            return False
        if not block_ok(lvl["block"], [digest, lvl["sibling"]]):
            return False
        digest = lvl["block"]["out"]
    if digest != stmt["root"]:
        return False                                      # statement: membership root
    if bl["nf"]["out"] != stmt["nf"]:
        return False                                      # statement: nullifier
    for i in range(N_OUT):
        if bl["cm_out"][i]["out"] != stmt["cm_out"][i]:
            return False                                  # statement: output commitments
    # range (A1): all values; conservation
    c = trace["cons"]
    if not air_check_range(c["value_in"], trace["rng"]["value_in"]):
        return False
    if not air_check_range(c["fee"], trace["rng"]["fee"]):
        return False
    for i in range(N_OUT):
        if not air_check_range(c["value_outs"][i], trace["rng"]["value_outs"][i]):
            return False
    if not air_check_conservation(c["value_in"], c["value_outs"], c["fee"]):
        return False
    return True


# ---- flat-column round layout (HP1.6 step2: what FRI commits / the shard reads) -
# Committed columns per row: 12 state lanes s0..s11 + S-box aux u2,u4,u6 per lane
# (deg<=2 decomposition, plan HP2.1 / cost_report_native) = 48, plus 4 A3 held-value
# columns = 52 columns total.
LANES = list(range(WIDTH))
# A3 held-value columns: one per range-checked value, held constant across the trace
# (membership_stark `nu` pattern) -> the value<->commitment link + conservation become
# FRI-expressible (single-row boundary / hold transition) instead of cross-row reads.
HELD_VALUES = ["value_in", "value_out0", "value_out1", "fee"]
HELD_COLS = ["vh_%s" % v for v in HELD_VALUES]
FLAT_COLS = (["s%d" % i for i in LANES]
             + ["u2_%d" % i for i in LANES]
             + ["u4_%d" % i for i in LANES]
             + ["u6_%d" % i for i in LANES]
             + HELD_COLS)


def block_flat_columns(block):
    """Flatten one Poseidon2 perm-block (states[0..30], aux[0..29]) into the flat
    committed columns over its 31 rows. Row 30 (output) has zero aux; the A3 held-value
    columns are 0 here (build_full_flat_trace fills them constant across the trace)."""
    states, aux = block["states"], block["aux"]
    n = len(states)                       # 31
    cols = {c: [0] * n for c in FLAT_COLS}
    for r in range(n):
        for i in LANES:
            cols["s%d" % i][r] = states[r][i]
        if r < len(aux):
            for i in LANES:
                cols["u2_%d" % i][r] = aux[r]["x2"][i]
                cols["u4_%d" % i][r] = aux[r]["x4"][i]
                cols["u6_%d" % i][r] = aux[r]["x6"][i]
    return cols, n


def air_check_flat_rounds(cols, n, rc_rows, full_rows):
    """Verify the Poseidon2 round transition reading ONLY from the flat columns
    (the verifier's view). For each round-row r: S-box aux (x2=x^2,x4=x2^2,x6=x4*x2)
    and state update next = M_EXT.y (full) / internal(y) (partial), y=x6*(s+rc)."""
    for r in range(n - 1):
        s = [cols["s%d" % i][r] for i in LANES]
        snext = [cols["s%d" % i][r + 1] for i in LANES]
        rc = rc_rows[r]
        full = full_rows[r]
        active = LANES if full else [0]
        y = s[:]                                      # partial: inactive lanes pass through
        for i in active:
            x = (s[i] + rc[i]) % P
            u2 = cols["u2_%d" % i][r]; u4 = cols["u4_%d" % i][r]; u6 = cols["u6_%d" % i][r]
            if not _sbox_aux_ok(x, u2, u4, u6, (u6 * x) % P):
                return False
            y[i] = (u6 * x) % P
        upd = _ext_apply(y) if full else _int_apply(y)
        if upd != snext:
            return False
    return True


def _block_rc_full(n_rows):
    """Per-row rc vectors + full-flags for a perm block (public layout)."""
    p_end = RF_HALF + ROUNDS_P
    rc_rows = []
    full_rows = []
    for r in range(n_rows - 1):            # transitions 0..29
        rc_rows.append(RC[r] if r < ROUNDS else [0] * WIDTH)
        full_rows.append((r < RF_HALF) or (r >= p_end))
    return rc_rows, full_rows


def range_rows(value):
    """Flat range-AIR rows for one value: per bit r, (bit, acc) where acc is the
    running recomposition sum_{j<=r} bit_j * 2^j. Last acc == value (< 2^RANGE_BITS)."""
    bits = range_bits(value)              # raises if value >= 2^RANGE_BITS (A1-safe)
    rows = []
    acc = 0
    for r in range(RANGE_BITS):
        acc = (acc + (bits[r] << r))
        rows.append((bits[r], acc))
    return rows


def air_check_range_rows(rows, value):
    """Verify flat range rows: each bit boolean, acc recomposes step-by-step, and
    the final acc equals value (so value < 2^RANGE_BITS, wrap-safe per A1)."""
    if len(rows) != RANGE_BITS:
        return False
    acc = 0
    for r, (bit, a) in enumerate(rows):
        if bit not in (0, 1):                          # booleanity b*(b-1)==0
            return False
        acc = acc + (bit << r)
        if a != acc:                                   # step-wise recomposition
            return False
    return rows[-1][1] == value % P and value < (1 << RANGE_BITS)


def _ordered_blocks(trace):
    """Block evaluation order with chaining metadata. Each entry:
    (name, block, absorbed_inputs, chain) where chain maps an absorbed-input
    index to the source (block-name) whose output feeds it (or None = witness)."""
    bl = trace["blocks"]
    # A2: order blocks so every chaining dependency is the IMMEDIATELY-PRECEDING
    # block (adjacent rows) -> chaining = adjacent re-absorb transition (FRI-expressible,
    # no copy argument). owner -> cm_in -> memb0 -> ... ; nf + cm_out are independent.
    seq = []
    seq.append(("owner", bl["owner"], bl["owner"]["input"], {}))
    seq.append(("cm_in", bl["cm_in"], bl["cm_in"]["input"], {1: "owner"}))  # input[1]=owner_pk
    prev = "cm_in"
    for j, lvl in enumerate(bl["memb"]):
        name = "memb%d" % j
        seq.append((name, lvl["block"], lvl["block"]["input"], {0: prev}))  # input[0]=prev digest
        prev = name
    final_memb = prev
    seq.append(("nf", bl["nf"], bl["nf"]["input"], {}))                     # independent (sk witness)
    for i in range(N_OUT):
        seq.append(("cm_out%d" % i, bl["cm_out"][i], bl["cm_out"][i]["input"], {}))
    return seq, final_memb  # final_memb output == root


def build_full_flat_trace(trace):
    """Concatenate every perm-block's flat round columns into ONE flat trace
    (single committed column set over all rows). Returns (cols, T, layout).
    layout[r] = {block, type in {round_full,round_partial,boundary,pad}, rc[12]}.
    (HP1.6: range/conservation flat rows are added in the next increment; this
    builds + binds the hash/membership/ownership AIR, WIP-marked.)"""
    seq, _ = _ordered_blocks(trace)
    cols = {c: [] for c in FLAT_COLS}
    layout = []
    blocks_meta = []
    for name, block, absorbed, chain in seq:
        bc, n = block_flat_columns(block)
        offset = len(layout)
        rc_rows, full_rows = _block_rc_full(n)
        for c in FLAT_COLS:
            cols[c].extend(bc[c])
        for r in range(n):
            if r == n - 1:
                typ = "boundary"; rc = [0] * WIDTH                 # output row (no transition)
            else:
                typ = "round_full" if full_rows[r] else "round_partial"; rc = rc_rows[r]
            layout.append({"block": name, "type": typ, "rc": rc})
        blocks_meta.append({"name": name, "offset": offset, "n": n,
                            "absorbed": absorbed, "chain": chain})
    # range rows (HP1.4 in-circuit, A1-safe) + conservation row (HP1.5)
    cons = trace["cons"]
    val_specs = [("value_in", cons["value_in"], "cm_in"),
                 ("value_out0", cons["value_outs"][0], "cm_out0"),
                 ("value_out1", cons["value_outs"][1], "cm_out1"),
                 ("fee", cons["fee"], None)]
    range_meta = []
    for vname, value, src in val_specs:
        roff = len(layout)
        for r, (bit, acc) in enumerate(range_rows(value)):
            rowv = {c: 0 for c in FLAT_COLS}
            rowv["s0"] = bit; rowv["s1"] = acc; rowv["s2"] = value % P
            for c in FLAT_COLS:
                cols[c].append(rowv[c])
            layout.append({"block": "range:" + vname, "type": "range", "rc": [0] * WIDTH})
        range_meta.append({"vname": vname, "offset": roff, "n": RANGE_BITS,
                           "value": value % P, "src": src})
    cons_row = len(layout)
    crow = {c: 0 for c in FLAT_COLS}
    crow["s0"] = cons["value_in"] % P; crow["s1"] = cons["value_outs"][0] % P
    crow["s2"] = cons["value_outs"][1] % P; crow["s3"] = cons["fee"] % P
    for c in FLAT_COLS:
        cols[c].append(crow[c])
    layout.append({"block": "cons", "type": "cons", "rc": [0] * WIDTH})
    raw = len(layout)
    T = 1
    while T < raw:
        T <<= 1
    for c in FLAT_COLS:                                            # pad with copy rows
        last = cols[c][-1] if cols[c] else 0
        cols[c].extend([last] * (T - raw))
    for _ in range(T - raw):
        layout.append({"block": "_pad", "type": "pad", "rc": [0] * WIDTH})
    # A3: populate the held-value columns -- constant = the range-checked value across
    # ALL rows (the prover commits them held). ct_check_held binds each to its
    # commitment block (absorbed[0]) + range block (s2) + conservation, FRI-expressibly.
    for rmv in range_meta:
        cols["vh_" + rmv["vname"]] = [rmv["value"]] * T
    return cols, T, {"rows": layout, "blocks": blocks_meta, "range": range_meta,
                     "cons_row": cons_row, "raw": raw}


def air_check_flat_full(cols, T, meta, stmt):
    """Verify, reading ONLY from the flat columns: per-block Poseidon2 round AIR,
    cross-block chaining (absorbed input == matmul_external preimage via M_EXT),
    and the public-statement boundary (membership root, nf, cm_out)."""
    rows = meta["rows"]
    bm = meta["blocks"]
    by_name = {b["name"]: b for b in bm}

    def out_of(name):                                    # block output = last row, lane 0
        b = by_name[name]; return cols["s0"][b["offset"] + b["n"] - 1]

    # per-block round transitions
    for b in bm:
        off, n = b["offset"], b["n"]
        sub = {c: cols[c][off:off + n] for c in FLAT_COLS}
        rc_rows, full_rows = _block_rc_full(n)
        if not air_check_flat_rounds(sub, n, rc_rows, full_rows):
            return False
        # chaining/input boundary: first flat row == matmul_external(absorbed),
        # and chained absorbed entries equal the source block outputs.
        absorbed = list(b["absorbed"])
        for idx, src in b["chain"].items():
            if absorbed[idx] != out_of(src):
                return False
        if [cols["s%d" % i][off] for i in LANES] != _ext_apply(absorbed):
            return False
    # statement boundary
    _, final_memb = _ordered_blocks_from_meta(meta)
    if out_of(final_memb) != stmt["root"]:
        return False
    if out_of("nf") != stmt["nf"]:
        return False
    for i in range(N_OUT):
        if out_of("cm_out%d" % i) != stmt["cm_out"][i]:
            return False
    # range rows (HP1.4): bits boolean + acc recompose; value constant + linked to cm
    for rmv in meta["range"]:
        off, n = rmv["offset"], rmv["n"]
        rows = [(cols["s0"][off + i], cols["s1"][off + i]) for i in range(n)]
        if not air_check_range_rows(rows, cols["s2"][off]):
            return False
        if any(cols["s2"][off + i] != rmv["value"] for i in range(n)):
            return False
        if rmv["src"] is not None and rmv["value"] != by_name[rmv["src"]]["absorbed"][0]:
            return False
    # conservation row (HP1.5, A1-safe): value_in == out0+out1+fee, each == its range value
    co = meta["cons_row"]
    vin, o0, o1, fee = (cols["s0"][co], cols["s1"][co], cols["s2"][co], cols["s3"][co])
    if (o0 + o1 + fee) % P != vin % P:
        return False
    rmap = {x["vname"]: x["value"] for x in meta["range"]}
    if (vin != rmap["value_in"] or o0 != rmap["value_out0"]
            or o1 != rmap["value_out1"] or fee != rmap["fee"]):
        return False
    return True


def _ordered_blocks_from_meta(meta):
    names = [b["name"] for b in meta["blocks"]]
    memb = [n for n in names if n.startswith("memb")]
    final_memb = memb[-1] if memb else "cm_in"
    return names, final_memb


# ---- poly-form AIR public layout + round constraints (HP1.6 FRI bridge) --------
# Selectors + round-constant value-lists over the T trace rows. In prove these are
# interpolated over H and evaluated at the query x; here we validate the constraint
# FORMULATION by checking residuals vanish on H (the trace domain).
def ct_public_layout(meta, T):
    rows = meta["rows"]
    is_full = [0] * T
    is_partial = [0] * T
    rc = [[0] * T for _ in range(WIDTH)]
    for r, row in enumerate(rows):
        if row["type"] == "round_full":
            is_full[r] = 1
        elif row["type"] == "round_partial":
            is_partial[r] = 1
        if row["type"] in ("round_full", "round_partial"):
            for k in range(WIDTH):
                rc[k][r] = row["rc"][k] % P
    # A2 sponge-structure selectors: is_block_start (each perm block's row0 -> the
    # absorbed input must have zero capacity) + is_reabsorb (a block's output row that
    # feeds the NEXT block's chained input). chain_minv[r] = the M_EXT^{-1} row of the
    # chained absorb-lane -> capacity + chaining become adjacent-row transition
    # constraints (FRI-expressible; the A2 cross-row-copy problem dissolves).
    is_block_start = [0] * T
    is_reabsorb = [0] * T
    chain_minv = [[0] * WIDTH for _ in range(T)]
    by_name = {b["name"]: b for b in meta["blocks"]}
    for b in meta["blocks"]:
        is_block_start[b["offset"]] = 1
        for idx, src in b["chain"].items():
            s = by_name[src]
            ra = b["offset"] - 1                       # src output row (adjacent, A2-step1)
            assert s["offset"] + s["n"] == b["offset"], "chain src not adjacent (A2-step1)"
            assert 0 <= ra < T - 1, "reabsorb row out of transition range"
            is_reabsorb[ra] = 1
            chain_minv[ra] = [M_EXT_INV[idx][j] for j in range(WIDTH)]
    # range selectors + bit weight (poly-form Num2Bits, A1-safe): per range block of
    # RANGE_BITS rows, is_range (booleanity everywhere), is_range_first (acc==bit0),
    # is_range_step (within-block acc recomposition + value-const), is_range_last
    # (acc==value). range_weight[r] = 2^(local bit index) -> acc[L]=sum bit_j*2^j.
    is_range = [0] * T
    is_range_first = [0] * T
    is_range_step = [0] * T
    is_range_last = [0] * T
    range_weight = [0] * T
    for rmv in meta["range"]:
        off, n = rmv["offset"], rmv["n"]
        for local in range(n):
            r = off + local
            is_range[r] = 1
            range_weight[r] = (1 << local) % P
            if local == 0:
                is_range_first[r] = 1
            if local == n - 1:
                is_range_last[r] = 1
            else:
                is_range_step[r] = 1               # step r -> r+1 stays inside the block
    return {"is_full": is_full, "is_partial": is_partial, "rc": rc,
            "is_block_start": is_block_start, "is_reabsorb": is_reabsorb,
            "chain_minv": chain_minv, "is_range": is_range,
            "is_range_first": is_range_first, "is_range_step": is_range_step,
            "is_range_last": is_range_last, "range_weight": range_weight}


def _round_residuals(cur, nxt, isf, isp, rc_at):
    """Round-transition residuals (must all be 0 on a valid round row).
    isf/isp = full/partial selector at the row; rc_at = [rc_k] at the row.
    Gating: sbox-aux lane k active when full (all k) or partial (k==0)."""
    res = []
    isr = (isf + isp) % P
    y_full = [0] * WIDTH
    y_part = [0] * WIDTH
    for k in range(WIDTH):
        x = (cur["s%d" % k] + rc_at[k]) % P
        u2 = cur["u2_%d" % k]; u4 = cur["u4_%d" % k]; u6 = cur["u6_%d" % k]
        gate = isr if k == 0 else isf                          # partial: only lane 0
        res.append((gate * ((u2 - (x * x)) % P)) % P)
        res.append((gate * ((u4 - (u2 * u2)) % P)) % P)
        res.append((gate * ((u6 - (u4 * u2)) % P)) % P)
        y_full[k] = (u6 * x) % P
        y_part[k] = (u6 * x) % P if k == 0 else cur["s%d" % k]
    ef = _ext_apply(y_full)
    ip = _int_apply(y_part)
    for j in range(WIDTH):
        sj = nxt["s%d" % j]
        res.append((isf * ((sj - ef[j]) % P) + isp * ((sj - ip[j]) % P)) % P)
    return res


def ct_check_rounds_on_H(cols, T, meta):
    """Validate the poly-form round constraints on H: for every round row, all
    round residuals are 0; on non-round rows the gate makes them 0 too."""
    pub = ct_public_layout(meta, T)
    for r in range(T - 1):
        cur = {c: cols[c][r] for c in FLAT_COLS}
        nxt = {c: cols[c][r + 1] for c in FLAT_COLS}
        rc_at = [pub["rc"][k][r] for k in range(WIDTH)]
        for v in _round_residuals(cur, nxt, pub["is_full"][r], pub["is_partial"][r], rc_at):
            if v % P != 0:
                return False
    return True


def _chain_residuals(cur, nxt, isbs, isra, minv_chain_row):
    """A2 sponge-structure residuals (all 0 on a valid trace):
      capacity:  is_block_start * (M_EXT^{-1} . cur_state)[k] for capacity lanes k
                 -> the absorbed sponge input has zero capacity (init), forcing an
                 8-lane rate (not a free 12-lane state) -> domain-separation sound.
      chaining:  is_reabsorb * ((M_EXT^{-1} . nxt_state)[chain_idx] - cur_state0)
                 -> the next block's chained absorb-lane equals THIS block's output
                 (lane 0). Adjacent rows (A2-step1) -> a low-degree transition."""
    res = []
    for k in range(P2.RATE, WIDTH):
        cap = sum(M_EXT_INV[k][j] * cur["s%d" % j] for j in range(WIDTH)) % P
        res.append((isbs * cap) % P)
    chained = sum(minv_chain_row[j] * nxt["s%d" % j] for j in range(WIDTH)) % P
    res.append((isra * ((chained - cur["s0"]) % P)) % P)
    return res


def ct_check_chain_on_H(cols, T, meta):
    """Validate the A2 capacity + re-absorb chaining constraints on H: at every block
    start the absorbed capacity vanishes, and at every re-absorb (block boundary) the
    next block's chained input equals this block's output. Selector-gated -> identically
    0 on all other rows (no over-constraining)."""
    pub = ct_public_layout(meta, T)
    for r in range(T - 1):
        cur = {c: cols[c][r] for c in FLAT_COLS}
        nxt = {c: cols[c][r + 1] for c in FLAT_COLS}
        for v in _chain_residuals(cur, nxt, pub["is_block_start"][r],
                                  pub["is_reabsorb"][r], pub["chain_minv"][r]):
            if v % P != 0:
                return False
    return True


def _range_residuals(cur, nxt, isr, isf, ist, isl, w_next):
    """Poly-form Num2Bits range residuals (all 0 on a valid trace), A1-safe (B=62).
    s0=bit, s1=acc, s2=value. isr=is_range, isf=is_range_first, ist=is_range_step,
    isl=is_range_last, w_next=2^(local index of the NEXT row)."""
    b = cur["s0"]
    res = []
    res.append((isr * ((b * (b - 1)) % P)) % P)                              # booleanity b*(b-1)
    res.append((isf * ((cur["s1"] - b) % P)) % P)                            # acc[0] == bit0
    res.append((ist * ((nxt["s1"] - cur["s1"] - (nxt["s0"] * w_next)) % P)) % P)  # acc step
    res.append((ist * ((nxt["s2"] - cur["s2"]) % P)) % P)                    # value constant
    res.append((isl * ((cur["s1"] - cur["s2"]) % P)) % P)                    # acc[last] == value
    return res


def ct_check_range_on_H(cols, T, meta):
    """Validate the poly-form range (Num2Bits) constraints on H: booleanity at every
    range row, step-wise acc recomposition + value-const within a block, acc==value at
    the block end. Selector-gated -> identically 0 elsewhere. Replaces the row-form
    air_check_range_rows in the FRI-expressible constraint set (A1 wrap-safe, B=62)."""
    pub = ct_public_layout(meta, T)
    for r in range(T - 1):
        cur = {c: cols[c][r] for c in FLAT_COLS}
        nxt = {c: cols[c][r + 1] for c in FLAT_COLS}
        for v in _range_residuals(cur, nxt, pub["is_range"][r], pub["is_range_first"][r],
                                  pub["is_range_step"][r], pub["is_range_last"][r],
                                  pub["range_weight"][r + 1]):
            if v % P != 0:
                return False
    return True


def ct_check_boundary(cols, meta, stmt):
    """Verifier-side public-statement boundary from committed columns ONLY: the
    membership root, the nullifier and the output commitments equal the public statement
    (each at its block's output row, lane 0). Range is ct_check_range_on_H; the
    value<->commitment link + conservation are ct_check_held; sponge capacity + chaining
    are ct_check_chain_on_H. Every binding is FRI-expressible."""
    bm = meta["blocks"]
    by_name = {b["name"]: b for b in bm}

    def out_of(name):
        b = by_name[name]; return cols["s0"][b["offset"] + b["n"] - 1]

    _, final_memb = _ordered_blocks_from_meta(meta)
    if out_of(final_memb) != stmt["root"]:
        return False
    if out_of("nf") != stmt["nf"]:
        return False
    for i in range(N_OUT):
        if out_of("cm_out%d" % i) != stmt["cm_out"][i]:
            return False
    return True


def ct_check_held(cols, meta):
    """A3 held-value columns -> FRI-expressible value bindings (membership_stark `nu`
    pattern). For each range-checked value: the held column is CONSTANT (hold transition
    nxt==cur), equals the range block's committed value (link to s2) and -- for the
    committed values -- the absorbed[0] of its commitment block (M_EXT^{-1} load,
    same-block boundary). Conservation reads the four held columns at ONE row. This
    replaces the cross-row direct reads, which a succinct FRI verifier cannot perform."""
    by_name = {b["name"]: b for b in meta["blocks"]}
    T = len(cols["s0"])
    for rmv in meta["range"]:
        col = cols["vh_" + rmv["vname"]]
        v = col[0]
        for r in range(T - 1):                              # hold: constant across rows
            if col[r + 1] != col[r]:
                return False
        if v != cols["s2"][rmv["offset"]]:                  # link: held == range value
            return False
        if rmv["src"] is not None:                          # cm-bind: held == absorbed[0]
            b = by_name[rmv["src"]]
            row0 = [cols["s%d" % i][b["offset"]] for i in LANES]
            if v != _ext_inv_apply(row0)[0]:
                return False
    co = meta["cons_row"]                                   # conservation at one row (A1-safe)
    vin = cols["vh_value_in"][co]; o0 = cols["vh_value_out0"][co]
    o1 = cols["vh_value_out1"][co]; fee = cols["vh_fee"][co]
    if (o0 + o1 + fee) % P != vin % P:
        return False
    return True


def ct_air_algebraic_check(cols, T, meta, stmt):
    """Complete algebraic CT-AIR check (verifier-side, committed columns only): round
    transitions + A2 capacity/chaining + A3 held-value bindings + range + statement."""
    return (ct_check_rounds_on_H(cols, T, meta)
            and ct_check_chain_on_H(cols, T, meta)
            and ct_check_held(cols, meta)
            and ct_check_range_on_H(cols, T, meta)
            and ct_check_boundary(cols, meta, stmt))


# ---- unified constraint interface for the STARK prove/verify (HP1.6) -----------
# prove (composition over the FRI domain) and verify (recompute at a query point) MUST
# evaluate the SAME constraints in the SAME order. These aggregate the verified
# per-class residual helpers into one fixed-order TRANSITION list + one BOUNDARY list,
# evaluable at any field point (selectors pre-evaluated in pub_x) -- not only on H.
def _hold_residuals(cur, nxt):
    """A3 held-value hold transition: every held column is constant (nxt == cur)."""
    return [(nxt[c] - cur[c]) % P for c in HELD_COLS]


def ct_num_transition_residuals():
    """Fixed count of transition residuals (prove/verify draw one alpha each, in order):
    round 4*WIDTH + chain (WIDTH-RATE)+1 + hold len(HELD_COLS) + range 5."""
    return 4 * WIDTH + (WIDTH - P2.RATE + 1) + len(HELD_COLS) + 5


def ct_transition_residuals(cur, nxt, pub_x, w_next):
    """All CT-AIR TRANSITION residuals at one domain point (selectors pre-evaluated in
    pub_x: is_full/is_partial/rc[WIDTH]/is_block_start/is_reabsorb/chain_minv[WIDTH]/
    is_range/is_range_first/is_range_step/is_range_last; w_next = range weight at the
    NEXT row). Fixed order: round (48) + chain (5) + hold (4) + range (5)."""
    res = _round_residuals(cur, nxt, pub_x["is_full"], pub_x["is_partial"], pub_x["rc"])
    res += _chain_residuals(cur, nxt, pub_x["is_block_start"], pub_x["is_reabsorb"],
                            pub_x["chain_minv"])
    res += _hold_residuals(cur, nxt)
    res += _range_residuals(cur, nxt, pub_x["is_range"], pub_x["is_range_first"],
                            pub_x["is_range_step"], pub_x["is_range_last"], w_next)
    return res


def ct_boundary_constraints(meta, stmt):
    """All CT-AIR BOUNDARY constraints as (row, fn) with fn(cur) -> base residual,
    enforced in the composition via the quotient 1/(x - H[row]). Public statement
    (root/nf/cm_out) + A3 held link + held cm-bind + conservation. Closures bind their
    loop variables via default args (no late-binding)."""
    bm = {b["name"]: b for b in meta["blocks"]}
    _, final_memb = _ordered_blocks_from_meta(meta)

    def out_row(name):
        b = bm[name]; return b["offset"] + b["n"] - 1

    cons = []
    cons.append((out_row(final_memb), lambda cur, rv=stmt["root"]: (cur["s0"] - rv) % P))
    cons.append((out_row("nf"), lambda cur, rv=stmt["nf"]: (cur["s0"] - rv) % P))
    for i in range(N_OUT):
        cons.append((out_row("cm_out%d" % i),
                     lambda cur, rv=stmt["cm_out"][i]: (cur["s0"] - rv) % P))
    for rmv in meta["range"]:
        hc = "vh_" + rmv["vname"]
        cons.append((rmv["offset"], lambda cur, hc=hc: (cur[hc] - cur["s2"]) % P))   # link
        if rmv["src"] is not None:                                                   # cm-bind
            off = bm[rmv["src"]]["offset"]
            cons.append((off, lambda cur, hc=hc: (cur[hc]
                         - sum(M_EXT_INV[0][j] * cur["s%d" % j] for j in range(WIDTH))) % P))
    cons.append((meta["cons_row"], lambda cur: (cur["vh_value_in"]
                 - (cur["vh_value_out0"] + cur["vh_value_out1"] + cur["vh_fee"])) % P))
    return cons


# ---- HP4: GF(p^2) generalisation of the CT-AIR composition eval ------------------------------------
# DEEP evaluates the AIR ONCE at an out-of-domain point z in GF(p^2) (DEEP_ALI_resolution.md sec 5-7); the
# residual functions above are base-field-only (%P), invalid on GF(p^2) cur/nxt. These MIRROR them faithfully
# with native_gf_p2 (_F2) arithmetic -- SAME fixed order, SAME structure. The base functions are UNTOUCHED
# (deep=False path unchanged). Cross-checked in native_ct_air_stark: on base-embedded domain points the
# GF(p^2) eval EQUALS the base eval (real check, no mock). Base matrix/RC constants scale the GF(p^2) vector
# via _F2.scalar (base*ext); public statement constants embed via _F2.from_base.
def _gf2_matvec(row, y):
    """dense row . GF(p^2)-vector: sum_k base_row[k] * y_ext[k] (via _F2.scalar)."""
    acc = _F2.ZERO
    for k in range(WIDTH):
        acc = _F2.add(acc, _F2.scalar(row[k], y[k]))
    return acc


def _gf2_matvec_state(row, cur):
    """dense row . GF(p^2) state read from cur['s0..s{WIDTH-1}']."""
    acc = _F2.ZERO
    for j in range(WIDTH):
        acc = _F2.add(acc, _F2.scalar(row[j], cur["s%d" % j]))
    return acc


def _ext_apply_ext(y):
    return [_gf2_matvec(M_EXT[j], y) for j in range(WIDTH)]


def _int_apply_ext(y):
    s = _F2.ZERO
    for e in y:
        s = _F2.add(s, e)
    return [_F2.add(_F2.scalar(P2.MAT_DIAG12[i], y[i]), s) for i in range(WIDTH)]


def _round_residuals_ext(cur, nxt, isf, isp, rc_at):
    """GF(p^2) mirror of _round_residuals (:643-665)."""
    res = []
    isr = _F2.add(isf, isp)
    y_full = [_F2.ZERO] * WIDTH
    y_part = [_F2.ZERO] * WIDTH
    for k in range(WIDTH):
        x = _F2.add(cur["s%d" % k], rc_at[k])
        u2 = cur["u2_%d" % k]; u4 = cur["u4_%d" % k]; u6 = cur["u6_%d" % k]
        gate = isr if k == 0 else isf
        res.append(_F2.mul(gate, _F2.sub(u2, _F2.mul(x, x))))
        res.append(_F2.mul(gate, _F2.sub(u4, _F2.mul(u2, u2))))
        res.append(_F2.mul(gate, _F2.sub(u6, _F2.mul(u4, u2))))
        y_full[k] = _F2.mul(u6, x)
        y_part[k] = _F2.mul(u6, x) if k == 0 else cur["s%d" % k]
    ef = _ext_apply_ext(y_full)
    ip = _int_apply_ext(y_part)
    for j in range(WIDTH):
        sj = nxt["s%d" % j]
        res.append(_F2.add(_F2.mul(isf, _F2.sub(sj, ef[j])), _F2.mul(isp, _F2.sub(sj, ip[j]))))
    return res


def _chain_residuals_ext(cur, nxt, isbs, isra, minv_chain_row):
    """GF(p^2) mirror of _chain_residuals (:682-696). minv_chain_row entries are GF(p^2) (chain_minv at z)."""
    res = []
    for k in range(P2.RATE, WIDTH):
        cap = _gf2_matvec_state(M_EXT_INV[k], cur)
        res.append(_F2.mul(isbs, cap))
    chained = _F2.ZERO
    for j in range(WIDTH):
        chained = _F2.add(chained, _F2.mul(minv_chain_row[j], nxt["s%d" % j]))
    res.append(_F2.mul(isra, _F2.sub(chained, cur["s0"])))
    return res


def _range_residuals_ext(cur, nxt, isr, isf, ist, isl, w_next):
    """GF(p^2) mirror of _range_residuals (:715-726)."""
    b = cur["s0"]
    res = []
    res.append(_F2.mul(isr, _F2.mul(b, _F2.sub(b, _F2.ONE))))
    res.append(_F2.mul(isf, _F2.sub(cur["s1"], b)))
    res.append(_F2.mul(ist, _F2.sub(_F2.sub(nxt["s1"], cur["s1"]), _F2.mul(nxt["s0"], w_next))))
    res.append(_F2.mul(ist, _F2.sub(nxt["s2"], cur["s2"])))
    res.append(_F2.mul(isl, _F2.sub(cur["s1"], cur["s2"])))
    return res


def _hold_residuals_ext(cur, nxt):
    """GF(p^2) mirror of _hold_residuals (:814-816)."""
    return [_F2.sub(nxt[c], cur[c]) for c in HELD_COLS]


def ct_transition_residuals_ext(cur, nxt, pub_x, w_next):
    """HP4.1: all CT-AIR TRANSITION residuals at the OOD point z over GF(p^2). SAME fixed order as the base
    ct_transition_residuals (round 4*WIDTH + chain (WIDTH-RATE+1) + hold len(HELD_COLS) + range 5)."""
    res = _round_residuals_ext(cur, nxt, pub_x["is_full"], pub_x["is_partial"], pub_x["rc"])
    res += _chain_residuals_ext(cur, nxt, pub_x["is_block_start"], pub_x["is_reabsorb"], pub_x["chain_minv"])
    res += _hold_residuals_ext(cur, nxt)
    res += _range_residuals_ext(cur, nxt, pub_x["is_range"], pub_x["is_range_first"],
                                pub_x["is_range_step"], pub_x["is_range_last"], w_next)
    return res


def ct_boundary_constraints_ext(meta, stmt):
    """HP4.2: the CT-AIR BOUNDARY closures over GF(p^2). fn(cur_ext) -> GF(p^2) residual. SAME (row, fn)
    structure/order as base ct_boundary_constraints (:839-865); public stmt constants embed via _F2.from_base."""
    bm = {b["name"]: b for b in meta["blocks"]}
    _, final_memb = _ordered_blocks_from_meta(meta)

    def out_row(name):
        b = bm[name]; return b["offset"] + b["n"] - 1

    cons = []
    cons.append((out_row(final_memb), lambda cur, rv=stmt["root"]: _F2.sub(cur["s0"], _F2.from_base(rv))))
    cons.append((out_row("nf"), lambda cur, rv=stmt["nf"]: _F2.sub(cur["s0"], _F2.from_base(rv))))
    for i in range(N_OUT):
        cons.append((out_row("cm_out%d" % i),
                     lambda cur, rv=stmt["cm_out"][i]: _F2.sub(cur["s0"], _F2.from_base(rv))))
    for rmv in meta["range"]:
        hc = "vh_" + rmv["vname"]
        cons.append((rmv["offset"], lambda cur, hc=hc: _F2.sub(cur[hc], cur["s2"])))            # link
        if rmv["src"] is not None:                                                              # cm-bind
            off = bm[rmv["src"]]["offset"]
            cons.append((off, lambda cur, hc=hc: _F2.sub(cur[hc], _gf2_matvec_state(M_EXT_INV[0], cur))))
    cons.append((meta["cons_row"], lambda cur: _F2.sub(cur["vh_value_in"],
                 _F2.add(_F2.add(cur["vh_value_out0"], cur["vh_value_out1"]), cur["vh_fee"]))))
    return cons


def ct_build_layout(D):
    """Structural-only flat layout (block offsets/types/chains, range blocks, cons row,
    padded T) derivable from the PUBLIC membership depth D alone -- NO witness values.
    The verifier rebuilds the constraint structure with this (mirrors build_layout in
    membership_stark). Cross-checked against build_full_flat_trace's meta in _self_test."""
    n_blk = ROUNDS + 1
    seq = ["owner", "cm_in"] + ["memb%d" % j for j in range(D)] + ["nf", "cm_out0", "cm_out1"]
    chains = {"cm_in": {1: "owner"}}
    prev = "cm_in"
    for j in range(D):
        chains["memb%d" % j] = {0: prev}; prev = "memb%d" % j
    blocks = []
    layout = []
    off = 0
    for name in seq:
        rc_rows, full_rows = _block_rc_full(n_blk)
        blocks.append({"name": name, "offset": off, "n": n_blk, "chain": chains.get(name, {})})
        for r in range(n_blk):
            if r == n_blk - 1:
                layout.append({"block": name, "type": "boundary", "rc": [0] * WIDTH})
            else:
                typ = "round_full" if full_rows[r] else "round_partial"
                layout.append({"block": name, "type": typ, "rc": rc_rows[r]})
        off += n_blk
    range_meta = []
    for vname, src in [("value_in", "cm_in"), ("value_out0", "cm_out0"),
                       ("value_out1", "cm_out1"), ("fee", None)]:
        roff = off
        for _ in range(RANGE_BITS):
            layout.append({"block": "range:" + vname, "type": "range", "rc": [0] * WIDTH})
        range_meta.append({"vname": vname, "offset": roff, "n": RANGE_BITS, "src": src})
        off += RANGE_BITS
    cons_row = off
    layout.append({"block": "cons", "type": "cons", "rc": [0] * WIDTH})
    off += 1
    raw = off
    T = 1
    while T < raw:
        T <<= 1
    for _ in range(T - raw):
        layout.append({"block": "_pad", "type": "pad", "rc": [0] * WIDTH})
    meta = {"rows": layout, "blocks": blocks, "range": range_meta,
            "cons_row": cons_row, "raw": raw}
    return meta, T


def ct_air_constraint_check(cols, T, meta, stmt):
    """Reproduce ct_air_algebraic_check via the UNIFIED prove/verify constraint interface
    (ct_transition_residuals + ct_boundary_constraints) evaluated on H. Confirms the two
    formulations agree -> the interface prove/verify will use is correct."""
    lay = ct_public_layout(meta, T)
    for r in range(T - 1):
        cur = {c: cols[c][r] for c in FLAT_COLS}
        nxt = {c: cols[c][r + 1] for c in FLAT_COLS}
        pub_x = {"is_full": lay["is_full"][r], "is_partial": lay["is_partial"][r],
                 "rc": [lay["rc"][k][r] for k in range(WIDTH)],
                 "is_block_start": lay["is_block_start"][r], "is_reabsorb": lay["is_reabsorb"][r],
                 "chain_minv": lay["chain_minv"][r],
                 "is_range": lay["is_range"][r], "is_range_first": lay["is_range_first"][r],
                 "is_range_step": lay["is_range_step"][r], "is_range_last": lay["is_range_last"][r]}
        for v in ct_transition_residuals(cur, nxt, pub_x, lay["range_weight"][r + 1]):
            if v % P != 0:
                return False
    for row, fn in ct_boundary_constraints(meta, stmt):
        cur = {c: cols[c][row] for c in FLAT_COLS}
        if fn(cur) % P != 0:
            return False
    return True


def _demo_witness(depth=2, seed=12345):
    """Deterministic test witness (seeded -> reproducible, HP1.9). NOT a mock: real
    field values driving the real verified hashes; values are wrap-safe (< 2^62)."""
    import random
    rng = random.Random(seed)
    fld = lambda: rng.randrange(1, P)
    value_in = 1_000_000
    v0 = 600_000; v1 = 399_000; fee = 1_000           # sum == value_in
    return {
        "sk": fld(), "rho_in": fld(), "blind_in": fld(),
        "value_in": value_in, "fee": fee,
        "value_outs": [v0, v1],
        "owners_out": [fld(), fld()], "rhos_out": [fld(), fld()], "blinds_out": [fld(), fld()],
        "siblings": [fld() for _ in range(depth)],
    }


def _self_test():
    # derived linear-layer matrices must reproduce the verified Poseidon2 matmuls
    import copy
    for trial in range(5):
        v = [(i * 13 + trial * 7 + 1) % P for i in range(WIDTH)]
        ext = v[:]; _matmul_external(ext)
        assert _ext_apply(v) == ext, "M_EXT does not reproduce matmul_external"
        intn = v[:]; _matmul_internal(intn)
        assert _int_apply(v) == intn, "_int_apply does not reproduce matmul_internal"
        assert _ext_inv_apply(_ext_apply(v)) == [x % P for x in v], "M_EXT_INV is not the inverse"
    # M_EXT . M_EXT_INV == I (identity over GF(P))
    for i in range(WIDTH):
        for j in range(WIDTH):
            dot = sum(M_EXT[i][k] * M_EXT_INV[k][j] for k in range(WIDTH)) % P
            assert dot == (1 if i == j else 0), "M_EXT*M_EXT_INV != I at (%d,%d)" % (i, j)
    # _ext_inv_apply recovers a block's sponge-absorbed input (capacity lanes == 0)
    _b = _block([7, 8, 9])
    _rec = _ext_inv_apply(_b["states"][0])
    assert _rec == _b["input"], "ext_inv does not recover absorbed input"
    assert all(_rec[i] == 0 for i in range(P2.RATE, WIDTH)), "recovered capacity not zero"
    # valid trace accepts
    inp = [(i * 11 + 5) % P for i in range(WIDTH)]
    states, aux = P2.permutation_trace(inp)
    assert air_check_perm(states, aux) is True, "valid perm trace rejected"
    # KAT input too
    s2, a2 = P2.permutation_trace(list(range(WIDTH)))
    assert air_check_perm(s2, a2) is True, "KAT perm trace rejected"

    # tamper gates (each MUST be rejected) -- real fuzz, no mock
    # (1) flip a next-state lane
    t = copy.deepcopy(states); t[5][3] = (t[5][3] + 1) % P
    assert air_check_perm(t, aux) is False, "tamper next-state not rejected"
    # (2) flip an S-box aux (x4) on a full round
    t = copy.deepcopy(aux); t[0]["x4"][2] = (t[0]["x4"][2] + 1) % P
    assert air_check_perm(states, t) is False, "tamper sbox-aux not rejected"
    # (3) flip a post-sbox y on a partial round (lane 0)
    t = copy.deepcopy(aux); t[10]["y"][0] = (t[10]["y"][0] + 1) % P
    assert air_check_perm(states, t) is False, "tamper partial y not rejected"
    # (4) flip a pass-through lane on a partial round
    t = copy.deepcopy(aux); t[10]["y"][5] = (t[10]["y"][5] + 1) % P
    assert air_check_perm(states, t) is False, "tamper partial passthrough not rejected"

    # ---- range (HP1.4) + conservation (HP1.5) gates, incl. field-wrap attack ----
    assert RANGE_BITS == 62, "expected wrap-safe RANGE_BITS=62 for 1-in/2-out, got %d" % RANGE_BITS
    v_in, outs, fee = 1000, [600, 300], 100
    # valid: every value range-ok AND conservation holds
    assert air_check_range(v_in, range_bits(v_in))
    assert all(air_check_range(v, range_bits(v)) for v in outs)
    assert air_check_range(fee, range_bits(fee))
    assert air_check_conservation(v_in, outs, fee) is True, "valid conservation rejected"
    # booleanity tamper: a bit = 2 -> rejected
    bb = range_bits(600); bb[3] = 2
    assert air_check_range(600, bb) is False, "non-boolean bit not rejected"
    # recomposition tamper: bits do not sum to v -> rejected
    bb = range_bits(600); bb[0] ^= 1
    assert air_check_range(600, bb) is False, "wrong recomposition not rejected"
    # FIELD-WRAP ATTACK (A1): outputs (p-1, v_in+1, fee=0) satisfy conservation mod p
    # (mint ~p coins) BUT p-1 does not fit in 62 bits -> range proof impossible -> caught.
    atk_outs, atk_fee = [P - 1, v_in + 1], 0
    assert air_check_conservation(v_in, atk_outs, atk_fee) is True, \
        "wrap sum should satisfy raw conservation (that's the attack)"
    try:
        range_bits(P - 1)
        wrap_in_range = True
    except ValueError:
        wrap_in_range = False
    assert wrap_in_range is False, "p-1 must NOT fit in 62 bits"
    assert air_check_range(P - 1, [(P - 1 >> i) & 1 for i in range(RANGE_BITS)]) is False, \
        "wrap value passed range -> A1 fix broken"

    # ---- transfer computation (HP1.3 value level) ----
    w = _demo_witness(depth=2)
    stmt, der = compute_transfer(w)
    # statement is well-formed
    assert all(0 <= stmt[k] < P for k in ("root", "nf"))
    assert len(stmt["cm_out"]) == N_OUT and all(0 <= c < P for c in stmt["cm_out"])
    # deterministic: recompute -> identical statement (HP1.9 determinism precondition)
    stmt2, _ = compute_transfer(_demo_witness(depth=2))
    assert stmt == stmt2, "compute_transfer not deterministic"
    # statement actually binds the witness: changing sk changes nf+root
    w2 = _demo_witness(depth=2); w2["sk"] = (w2["sk"] + 1) % P
    s2, _ = compute_transfer(w2)
    assert s2["nf"] != stmt["nf"] and s2["root"] != stmt["root"], "statement not bound to sk"
    # conservation enforced: a non-balancing witness is rejected
    wbad = _demo_witness(depth=2); wbad["value_outs"][0] += 1   # sum now != value_in
    try:
        compute_transfer(wbad); cons_ok = False
    except ValueError:
        cons_ok = True
    assert cons_ok, "non-balancing transfer not rejected"
    # range enforced: an out-of-range value is rejected
    wrange = _demo_witness(depth=2); wrange["value_in"] = 1 << RANGE_BITS
    try:
        compute_transfer(wrange); rng_ok = False
    except ValueError:
        rng_ok = True
    assert rng_ok, "out-of-range value not rejected"

    # ---- full round-per-row CT-AIR trace gate (HP1.6 step 1) ----
    trace, st = build_ct_trace(_demo_witness(depth=3))
    assert air_check_full(trace, st) is True, "valid CT-AIR trace rejected"
    # tamper gates (each MUST be rejected) -- real fuzz over every constraint class
    # (1) Poseidon2 round inside the cm_in block
    t = copy.deepcopy(trace); t["blocks"]["cm_in"]["states"][7][2] = (t["blocks"]["cm_in"]["states"][7][2] + 1) % P
    assert air_check_full(t, st) is False, "block round tamper not rejected"
    # (2) broken cross-block chaining: owner_pk not fed into cm_in
    t = copy.deepcopy(trace); t["blocks"]["cm_in"]["input"][1] = (t["blocks"]["cm_in"]["input"][1] + 1) % P
    assert air_check_full(t, st) is False, "chaining tamper not rejected"
    # (3) statement tamper: wrong public root
    t = copy.deepcopy(st); t["root"] = (t["root"] + 1) % P
    assert air_check_full(trace, t) is False, "wrong root not rejected"
    # (4) statement tamper: wrong nullifier
    t = copy.deepcopy(st); t["nf"] = (t["nf"] + 1) % P
    assert air_check_full(trace, t) is False, "wrong nf not rejected"
    # (5) range bit tamper
    t = copy.deepcopy(trace); t["rng"]["value_outs"][0][4] = 2
    assert air_check_full(t, st) is False, "range tamper not rejected"
    # (6) conservation tamper
    t = copy.deepcopy(trace); t["cons"]["value_outs"][0] += 1
    assert air_check_full(t, st) is False, "conservation tamper not rejected"
    # (7) nullifier domain tag tamper
    t = copy.deepcopy(trace); t["blocks"]["nf"]["input"][2] = (DOM_NF + 1) % P
    assert air_check_full(t, st) is False, "DOM_NF tamper not rejected"

    # ---- flat-column round layout (HP1.6 step2): verifier-view round AIR ----
    blk = trace["blocks"]["cm_in"]
    fcols, fn_rows = block_flat_columns(blk)
    rc_rows, full_rows = _block_rc_full(fn_rows)
    assert air_check_flat_rounds(fcols, fn_rows, rc_rows, full_rows) is True, \
        "valid flat round trace rejected"
    # flat columns reproduce the block output (last row, lane 0)
    assert fcols["s0"][fn_rows - 1] == blk["out"], "flat output != block out"
    # tamper a flat state column -> rejected
    ft = copy.deepcopy(fcols); ft["s4"][6] = (ft["s4"][6] + 1) % P
    assert air_check_flat_rounds(ft, fn_rows, rc_rows, full_rows) is False, \
        "flat state tamper not rejected"
    # tamper a flat aux column -> rejected
    ft = copy.deepcopy(fcols); ft["u4_0"][9] = (ft["u4_0"][9] + 1) % P
    assert air_check_flat_rounds(ft, fn_rows, rc_rows, full_rows) is False, \
        "flat aux tamper not rejected"

    # ---- full flat trace: chained blocks + statement (HP1.6 step2) ----
    trace3, st3 = build_ct_trace(_demo_witness(depth=3))
    fc2, T2, meta2 = build_full_flat_trace(trace3)
    assert air_check_flat_full(fc2, T2, meta2, st3) is True, "valid full flat trace rejected"
    assert (T2 & (T2 - 1)) == 0 and T2 >= meta2["raw"], "flat T not power-of-two >= raw"
    assert len(fc2["s0"]) == T2, "column length != T"
    # tamper a round-row flat state in the nf block -> rejected (round AIR)
    ft2 = copy.deepcopy(fc2); ft2["s2"][40] = (ft2["s2"][40] + 1) % P
    assert air_check_flat_full(ft2, T2, meta2, st3) is False, "flat round tamper not rejected"
    # tamper the public statement root -> rejected (statement boundary)
    st3b = dict(st3); st3b["root"] = (st3b["root"] + 1) % P
    assert air_check_flat_full(fc2, T2, meta2, st3b) is False, "flat root tamper not rejected"
    # break chaining: corrupt cm_in's absorbed owner_pk slot -> rejected
    m2 = copy.deepcopy(meta2)
    for b in m2["blocks"]:
        if b["name"] == "cm_in":
            b["absorbed"][1] = (b["absorbed"][1] + 1) % P
    assert air_check_flat_full(fc2, T2, m2, st3) is False, "chaining tamper not rejected"
    # flat range-bit tamper -> rejected
    ft3 = copy.deepcopy(fc2); roff = meta2["range"][0]["offset"]; ft3["s0"][roff + 3] = 2
    assert air_check_flat_full(ft3, T2, meta2, st3) is False, "flat range-bit tamper not rejected"
    # flat conservation tamper -> rejected
    ft3 = copy.deepcopy(fc2); ft3["s1"][meta2["cons_row"]] = (ft3["s1"][meta2["cons_row"]] + 1) % P
    assert air_check_flat_full(ft3, T2, meta2, st3) is False, "flat conservation tamper not rejected"
    # poly-form round constraints vanish on H (FRI bridge); tamper -> nonzero
    assert ct_check_rounds_on_H(fc2, T2, meta2) is True, "poly round constraints not vanishing on H"
    ftp = copy.deepcopy(fc2); ftp["s3"][20] = (ftp["s3"][20] + 1) % P
    assert ct_check_rounds_on_H(ftp, T2, meta2) is False, "poly round tamper not caught"
    # row 2 = owner-block round 2 = FULL round -> lane 5 active -> its aux IS constrained
    ftp = copy.deepcopy(fc2); ftp["u6_5"][2] = (ftp["u6_5"][2] + 1) % P
    assert ct_check_rounds_on_H(ftp, T2, meta2) is False, "poly aux tamper (full round) not caught"
    # row 12 = partial round -> lanes>0 inactive, their aux is gated off (unused, no
    # soundness impact: partial state-update uses s_k, not aux_k) -> NOT constrained
    ftp = copy.deepcopy(fc2); ftp["u6_5"][12] = (ftp["u6_5"][12] + 1) % P
    assert ct_check_rounds_on_H(ftp, T2, meta2) is True, "inactive partial-round aux wrongly constrained"
    # complete verifier-side algebraic AIR (rounds + boundary via committed cols + M_EXT_INV)
    assert ct_air_algebraic_check(fc2, T2, meta2, st3) is True, "valid algebraic AIR rejected"
    fr = copy.deepcopy(fc2); fr["s3"][20] = (fr["s3"][20] + 1) % P            # round
    assert ct_air_algebraic_check(fr, T2, meta2, st3) is False, "alg round tamper not caught"
    sb = dict(st3); sb["nf"] = (sb["nf"] + 1) % P                              # statement
    assert ct_air_algebraic_check(fc2, T2, meta2, sb) is False, "alg statement tamper not caught"
    fr = copy.deepcopy(fc2); fr["s0"][meta2["range"][1]["offset"] + 2] = 2     # range bit
    assert ct_air_algebraic_check(fr, T2, meta2, st3) is False, "alg range tamper not caught"
    fr = copy.deepcopy(fc2); fr["vh_value_out0"] = [(x + 1) % P for x in fr["vh_value_out0"]]
    assert ct_air_algebraic_check(fr, T2, meta2, st3) is False, "alg held/conservation tamper not caught"

    # ---- A2: capacity + re-absorb chaining as poly-form transition constraints ----
    assert ct_check_chain_on_H(fc2, T2, meta2) is True, "valid chain/capacity rejected on H"
    pubA = ct_public_layout(meta2, T2)
    ra_rows = [r for r in range(T2) if pubA["is_reabsorb"][r]]
    bs_rows = [r for r in range(T2) if pubA["is_block_start"][r]]
    assert ra_rows and bs_rows, "expected re-absorb + block-start rows"
    # capacity tamper: perturb a block-start row0 -> M_EXT^-1 yields nonzero capacity
    fcap = copy.deepcopy(fc2); fcap["s9"][bs_rows[0]] = (fcap["s9"][bs_rows[0]] + 1) % P
    assert ct_check_chain_on_H(fcap, T2, meta2) is False, "capacity tamper not caught"
    # chaining tamper: change a block's output (lane 0 at its re-absorb row) so the
    # next block's chained absorb-lane no longer matches -> caught
    fch = copy.deepcopy(fc2); fch["s0"][ra_rows[0]] = (fch["s0"][ra_rows[0]] + 1) % P
    assert ct_check_chain_on_H(fch, T2, meta2) is False, "chaining tamper not caught"
    # gating: a capacity-lane perturbation on a non-block-start/non-reabsorb row does
    # NOT trip chain residuals (the round AIR catches it elsewhere) -> no over-constraint
    mid = next(r for r in range(T2 - 1) if not pubA["is_block_start"][r]
               and not pubA["is_reabsorb"][r])
    fgate = copy.deepcopy(fc2); fgate["s9"][mid] = (fgate["s9"][mid] + 1) % P
    assert ct_check_chain_on_H(fgate, T2, meta2) is True, "chain selector wrongly gated on"
    # integrated: the complete algebraic check rejects each chain tamper
    assert ct_air_algebraic_check(fcap, T2, meta2, st3) is False, "alg capacity tamper not caught"
    assert ct_air_algebraic_check(fch, T2, meta2, st3) is False, "alg chaining tamper not caught"

    # ---- A3: held-value columns -> FRI-expressible value<->cm link + conservation ----
    assert ct_check_held(fc2, meta2) is True, "valid held-value bindings rejected"
    # hold tamper: a held column not constant across rows -> caught
    fh = copy.deepcopy(fc2); fh["vh_value_in"][7] = (fh["vh_value_in"][7] + 1) % P
    assert ct_check_held(fh, meta2) is False, "held non-constant not caught"
    # link tamper: held value != its range block's committed value (fee has no cm, so
    # ONLY the range link can catch it) -> caught
    fh = copy.deepcopy(fc2); fh["vh_fee"] = [(x + 1) % P for x in fh["vh_fee"]]
    assert ct_check_held(fh, meta2) is False, "held<->range link tamper not caught"
    # cm-bind tamper: perturb a commitment block's row0 so absorbed[0] != held -> caught
    fh = copy.deepcopy(fc2)
    cmoff = next(b["offset"] for b in meta2["blocks"] if b["name"] == "cm_in")
    fh["s3"][cmoff] = (fh["s3"][cmoff] + 1) % P
    assert ct_check_held(fh, meta2) is False, "held<->commitment bind tamper not caught"

    # ---- range as poly-form selector constraints (ct_check_range_on_H, A1-safe) ----
    assert ct_check_range_on_H(fc2, T2, meta2) is True, "valid poly-form range rejected"
    roff = meta2["range"][1]["offset"]                       # value_out0 range block
    frb = copy.deepcopy(fc2); frb["s0"][roff + 4] = 2        # non-boolean bit
    assert ct_check_range_on_H(frb, T2, meta2) is False, "range booleanity tamper not caught"
    frb = copy.deepcopy(fc2); frb["s1"][roff + 5] = (frb["s1"][roff + 5] + 1) % P  # acc
    assert ct_check_range_on_H(frb, T2, meta2) is False, "range acc-recomposition tamper not caught"
    frb = copy.deepcopy(fc2); frb["s2"][roff + 6] = (frb["s2"][roff + 6] + 1) % P  # value drift
    assert ct_check_range_on_H(frb, T2, meta2) is False, "range value-const tamper not caught"

    # ---- unified prove/verify constraint interface (ct_transition / ct_boundary) ----
    # aggregated interface reproduces the complete algebraic check on H
    assert ct_air_constraint_check(fc2, T2, meta2, st3) is True, "unified interface rejects valid trace"
    # transition-residual count is exactly as declared (prove/verify draw one alpha each)
    _puc = {"is_full": 0, "is_partial": 0, "rc": [0] * WIDTH, "is_block_start": 0,
            "is_reabsorb": 0, "chain_minv": [0] * WIDTH, "is_range": 0, "is_range_first": 0,
            "is_range_step": 0, "is_range_last": 0}
    _dummy = {c: 0 for c in FLAT_COLS}
    assert len(ct_transition_residuals(_dummy, _dummy, _puc, 0)) == ct_num_transition_residuals(), \
        "transition residual count != ct_num_transition_residuals()"
    # tampers caught identically to ct_air_algebraic_check (round / statement / held)
    fu = copy.deepcopy(fc2); fu["s3"][20] = (fu["s3"][20] + 1) % P
    assert ct_air_constraint_check(fu, T2, meta2, st3) is False, "unified misses round tamper"
    su = dict(st3); su["nf"] = (su["nf"] + 1) % P
    assert ct_air_constraint_check(fc2, T2, meta2, su) is False, "unified misses statement tamper"
    fu = copy.deepcopy(fc2); fu["vh_value_out0"] = [(x + 1) % P for x in fu["vh_value_out0"]]
    assert ct_air_constraint_check(fu, T2, meta2, st3) is False, "unified misses held tamper"
    # verifier-side structural layout (depth only, NO witness) matches the prover's meta
    lmeta, lT = ct_build_layout(3)
    assert lT == T2, "ct_build_layout T mismatch"
    assert [(b["name"], b["offset"], b["n"], b["chain"]) for b in lmeta["blocks"]] == \
           [(b["name"], b["offset"], b["n"], b["chain"]) for b in meta2["blocks"]], "block structure mismatch"
    assert [(r["vname"], r["offset"], r["n"], r["src"]) for r in lmeta["range"]] == \
           [(r["vname"], r["offset"], r["n"], r["src"]) for r in meta2["range"]], "range layout mismatch"
    assert lmeta["cons_row"] == meta2["cons_row"], "cons_row mismatch"
    assert [(row["type"], row["rc"]) for row in lmeta["rows"]] == \
           [(row["type"], row["rc"]) for row in meta2["rows"]], "row types/rc mismatch"

    # ---- flat range rows (HP1.4 in-circuit, A1-safe) ----
    val = 0x3fffffffabcdef & ((1 << RANGE_BITS) - 1)
    rr = range_rows(val)
    assert len(rr) == RANGE_BITS
    assert air_check_range_rows(rr, val) is True, "valid range rows rejected"
    # bit tamper (non-boolean) -> rejected
    rt = [list(x) for x in rr]; rt[5][0] = 2
    assert air_check_range_rows([tuple(x) for x in rt], val) is False, "non-boolean bit not rejected"
    # acc recompose tamper -> rejected
    rt = [list(x) for x in rr]; rt[7][1] = (rt[7][1] + 1)
    assert air_check_range_rows([tuple(x) for x in rt], val) is False, "acc tamper not rejected"
    # wrong claimed value (acc != value) -> rejected
    assert air_check_range_rows(rr, (val + 1)) is False, "wrong value not rejected"
    # out-of-range value cannot even build rows (A1)
    try:
        range_rows(1 << RANGE_BITS); oor = False
    except ValueError:
        oor = True
    assert oor, "out-of-range value built range rows"
    return True


if __name__ == "__main__":
    ok = _self_test()
    print("HP1.3 Poseidon2 round-transition AIR gate:", "OK" if ok else "FAIL")
    print("  valid traces accepted (random + KAT); 4/4 tamper classes rejected")
    print("HP1.4 range (Num2Bits, wrap-safe B=%d) + HP1.5 conservation: OK" % RANGE_BITS)
    print("  A1 field-wrap attack (v_out=p-1) blocked: passes raw conservation, FAILS range")
    print("HP1.3 transfer computation (owner/nf/cm/membership/conservation): OK")
    print("  deterministic, statement bound to witness, conservation+range enforced")
    print("HP1.6 step1 full round-per-row CT-AIR trace (air_check_full): OK")
    print("  valid trace accepted; 7/7 tamper classes rejected (round/chain/root/nf/range/cons/DOM)")
    print("HP1.6 step2 A2 capacity + re-absorb chaining (poly-form transitions): OK")
    print("  chaining is now an adjacent-row constraint (FRI-expressible); capacity+chain tamper rejected")
    print("HP1.6 A3 held-value columns (value<->cm link + conservation, FRI-expressible): OK")
    print("  hold/link/commitment-bind tamper rejected; replaces non-succinct cross-row reads")
    print("HP1.6 range as poly-form selector constraints (Num2Bits, A1-safe B=%d): OK" % RANGE_BITS)
    print("  booleanity + acc-recomposition + value-const + acc==value; tamper rejected")
    print("HP1.6 unified prove/verify constraint interface (%d transition + boundary): OK"
          % ct_num_transition_residuals())
    print("  reproduces algebraic check on H; ct_build_layout(D) matches prover meta (witness-free)")
