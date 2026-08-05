/-
  LeanBCH.Number — the VM-number encoding + the byte-width lattice.

  TWO HALVES.

  Half A (transcribed VERBATIM from `stackcert/Stackcert/Cost/Width.lean`, namespace
  `Stackcert.Cost` → `LeanBCH`, dropping the vestigial `import Stackcert.Cost.Metrics`):
  the `intByteLen` width lattice — libauth `bigIntToVmNumber` WIDTH, and the full band
  `intByteLen z ≤ L ↔ |z| < 2^(8L-1)` with the five value-dependent arithmetic-cost
  transfer bounds (mul ≤ La+Lb; add/sub ≤ max+1; tdiv ≤ La; tmod ≤ Lb).

  Half B (NEW — the concrete VM-number spec over `Bytes := List UInt8`): the actual
  `bigIntToVmNumber` / `vmNumberToBigInt` from libauth
  `vm/instruction-sets/common/instruction-sets-utils.js` (pin 3.1.0-next.8), the
  correctness `vmNumber_roundTrip`, the bridge `intByteLen_eq_encodedLength` connecting
  Half A's width to the real encoder, and BCH minimal-encoding (`isMinimallyEncoded`,
  `bigIntToVmNumber_minimal`), plus the libauth boundary witnesses.

  `magBytes` uses a fuel parameter (structural recursion) so it REDUCES — the edge-case
  witnesses close by `decide`, keeping the axiom footprint clean (no `native_decide`).
-/
import LeanBCH.Core

set_option maxRecDepth 2048

namespace LeanBCH

/-! ## Half A — the `intByteLen` width lattice (transcribed, PROVEN) -/

/-- Little-endian base-256 magnitude digits, with fuel to force structural
    reduction. `magBytes` supplies fuel `n+1`, always ≥ the digit count. -/
def magBytesFuel : Nat → Nat → List Nat
  | 0,     _   => []
  | _+1,   0   => []
  | f+1,   n+1 => ((n+1) % 256) :: magBytesFuel f ((n+1) / 256)

/-! ### The O(n·log n) runtime encoder (`@[implemented_by]`), proved equal to the fuel model.

    `magBytesFuel` above is the LOGICAL model — it reduces (so `decide` KATs stay `native_decide`-free)
    but it is O(n²): each `n / 256` on a `k`-byte bignum is O(k), summed over the `k` bytes.
    Materializing a 10000-byte VM number that way takes seconds and hangs the compiled conformance
    runner. So `magBytes` keeps the fuel body as its logical meaning (every downstream proof and KAT
    is untouched) but is `@[implemented_by]` the divide-and-conquer `magBytesImpl` below, proved
    BYTE-FOR-BYTE equal in `magBytesImpl_eq`. Only the speed changes, never the bytes. -/

/-- Little-endian base-256 digits of `v` in EXACTLY `w` positions (`leDigits v 0 = []`,
    `leDigits v (w+1) = v%256 :: leDigits (v/256) w`). The fixed-width spec the fast encoder targets;
    `magBytes n = leDigits n (nbytes n)` (`magBytes_eq_leDigits`), minimal because the top digit ≠ 0. -/
def leDigits : Nat → Nat → List Nat
  | _, 0     => []
  | v, w+1   => (v % 256) :: leDigits (v / 256) w

/-- Exact base-256 digit count of a nonzero `n` (`0` for `n = 0`): the unique `k` with
    `256^(k-1) ≤ n < 256^k`, i.e. `⌊log₂ n / 8⌋ + 1`. `Nat.log2` is `@[extern "lean_nat_log2"]`
    (GMP bit-length), so this is O(1)-ish at runtime — the width seed for `encFixedF`. -/
def nbytes (n : Nat) : Nat := if n = 0 then 0 else n.log2 / 8 + 1

/-- Divide-and-conquer fixed-width little-endian encoder: `encFixedF f w v = leDigits v w` whenever
    `w ≤ f` (`encFixedF_eq`). It halves the width at `B = 256^(w/2) = 1 <<< (8·(w/2))` — one
    GMP-backed shift plus a single div/mod (each O(size)) — then recurses on each half:
    `T(k) = 2·T(k/2) + O(k) = O(k·log k)`, versus the byte-at-a-time O(k²) of `magBytesFuel`.
    Structural recursion on the fuel `f` (TOTAL, no `partial`/`termination_by`, and it REDUCES);
    seeding `f := w` at the top always dominates the log-depth, so the fuel never runs out early. -/
def encFixedF : Nat → Nat → Nat → List Nat
  | 0,     _,     _ => []
  | _+1,   0,     _ => []
  | _+1,   1,     v => [v % 256]
  | f+1,   w+2,   v =>
      let h := (w + 2) / 2
      let B := 1 <<< (8 * h)
      encFixedF f h (v % B) ++ encFixedF f (w + 2 - h) (v / B)

/-- The fast runtime magnitude encoder — the `@[implemented_by]` target for `magBytes`. Seeding the
    fuel and width with `nbytes n` (its own exact byte count) makes `w ≤ f` hold trivially, so
    `magBytesImpl n = leDigits n (nbytes n) = magBytes n` (`magBytesImpl_eq`). `n = 0` falls through
    `encFixedF 0 0 0 = []`. O(n·log n). -/
def magBytesImpl (n : Nat) : List Nat := encFixedF (nbytes n) (nbytes n) n

/-- Little-endian minimal magnitude bytes of `n` (`[]` for 0). The logical model is the fuel-based
    `magBytesFuel` (it reduces, so KATs close by `decide`); the RUNTIME is served by the provably
    equal O(n·log n) `magBytesImpl` (`magBytesImpl_eq`). -/
@[implemented_by magBytesImpl]
def magBytes (n : Nat) : List Nat := magBytesFuel (n + 1) n

/-- libauth VM-number width: minimal signed-magnitude + a 0x80 sign-pad byte when the
    top magnitude byte has its high bit set. Length is sign-symmetric via `Int.natAbs`. -/
def intByteLen (z : Int) : Nat :=
  match magBytes z.natAbs with
  | []     => 0
  | b      => if b.getLast! ≥ 128 then b.length + 1 else b.length

theorem intByteLen_zero : intByteLen 0 = 0 := rfl

/-- Sign-symmetry: the encoding width ignores sign (it's a magnitude + sign byte). -/
theorem intByteLen_neg (z : Int) : intByteLen (-z) = intByteLen z := by
  unfold intByteLen; rw [Int.natAbs_neg]

-- Edge-case witnesses PINNING the libauth boundaries (the spec surface). `decide`
-- reduces the fuel-based `magBytes`, so no `native_decide` — axiom footprint stays clean.
example : intByteLen 0     = 0 := by decide
example : intByteLen 1     = 1 := by decide
example : intByteLen 127   = 1 := by decide   -- MSB < 0x80 → no pad
example : intByteLen 128   = 2 := by decide   -- MSB = 0x80 → +1 sign byte
example : intByteLen 255   = 2 := by decide
example : intByteLen 256   = 2 := by decide   -- rolls to a second byte, MSB=1 < 0x80
example : intByteLen 32767 = 2 := by decide
example : intByteLen 32768 = 3 := by decide   -- 0x8000 → high bit set → +1
example : intByteLen (-1)   = 1 := by decide
example : intByteLen (-127) = 1 := by decide
example : intByteLen (-128) = 2 := by decide

/-! ### The `intByteLen` width lattice — value-dependent arithmetic-cost transfer bounds

    The math crux of M0.5 item 2: to price the arithmeticCost tier (`Cost.Arith`, the
    `|a|·|b|` operand pre-charge + result double-bill) in terms of OPERAND widths, the cost
    engine needs to bound `intByteLen` of an arithmetic RESULT by the `intByteLen`s of its
    inputs. All five transfer bounds reduce to ONE structural fact — the BAND
    `intByteLen z ≤ L ↔ |z| < 2^(8L-1)` (`intByteLen_band`) — plus `intByteLen z = 0 ↔ z = 0`.

    The band is proved bottom-up over the fuel-based `magBytes`: `magBytesFuel_stable` (fuel
    is irrelevant past the digit count) unlocks the value-level recursion `magBytes_succ`,
    which gives the clean digit recursion `wid_hi : wid m = wid (m/256) + 1` (m ≥ 256) —
    the top magnitude byte, hence the 0x80 sign-pad, is shared across the ÷256 step, so each
    low digit adds exactly one byte. Strong induction on that recursion yields the band.
    Then the five transfers are elementary `Nat` pow arithmetic. Pure Lean 4 core, NO mathlib
    (`8*L-1` guarded via `L ≥ 1`; the L=0/z=0 corner handled separately).

    ★ STATUS: REFERENCE LEMMAS — NOT LOAD-BEARING. The five width-transfer bounds
    (`intByteLen_mul/add/sub/tdiv/tmod`, below) and `intByteLen_neg` currently have NO call sites —
    `Cost.Arith` prices the arithmeticCost tier from `intByteLen` of the actual operands directly,
    not via these result-width bounds. They are kept as a proven, exact width lattice for reference
    (and for a future cost proof that reasons about result widths), not as a live cost bound. -/

theorem magBytesFuel_stable : ∀ n f g, n < f → n < g → magBytesFuel f n = magBytesFuel g n := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro f g hf hg
    match n, f, g, hf, hg with
    | 0, f, g, _, _ => cases f <;> cases g <;> rfl
    | n+1, f+1, g+1, hf, hg =>
      simp only [magBytesFuel]
      have hlt : (n+1)/256 < n+1 := Nat.div_lt_self (Nat.succ_pos n) (by omega)
      congr 1
      exact ih ((n+1)/256) hlt f g (by omega) (by omega)

theorem magBytes_succ (m : Nat) (hm : 1 ≤ m) :
    magBytes m = (m % 256) :: magBytes (m/256) := by
  obtain ⟨n, rfl⟩ : ∃ n, m = n + 1 := ⟨m-1, by omega⟩
  unfold magBytes
  simp only [magBytesFuel]
  congr 1
  exact magBytesFuel_stable ((n+1)/256) (n+1) ((n+1)/256+1)
    (Nat.div_lt_self (Nat.succ_pos n) (by omega)) (by omega)

theorem magBytes_ne_nil (m : Nat) (hm : 1 ≤ m) : magBytes m ≠ [] := by
  rw [magBytes_succ m hm]; exact List.cons_ne_nil _ _

/-! ### `magBytesImpl` is byte-for-byte `magBytes` — the divide-and-conquer speedup is sound.

    Chain: `encFixedF f w v = leDigits v w` (`encFixedF_eq`, when `w ≤ f`) and
    `magBytes n = leDigits n (nbytes n)` (`magBytes_eq_leDigits`), seeded at `f = w = nbytes n`. -/

/-- Splitting a fixed-width encoding at position `a`: the low `a` digits, then the rest of `v/256^a`. -/
theorem leDigits_add (a : Nat) : ∀ v b,
    leDigits v (a + b) = leDigits v a ++ leDigits (v / 256 ^ a) b := by
  induction a with
  | zero => intro v b; simp [leDigits]
  | succ a ih =>
    intro v b
    have e1 : a + 1 + b = (a + b) + 1 := by omega
    rw [e1]
    show (v % 256) :: leDigits (v / 256) (a + b)
       = ((v % 256) :: leDigits (v / 256) a) ++ leDigits (v / 256 ^ (a + 1)) b
    rw [ih (v / 256) b, List.cons_append]
    have hdd : v / 256 / 256 ^ a = v / 256 ^ (a + 1) := by
      rw [Nat.div_div_eq_div_mul, ← Nat.pow_succ']
    rw [hdd]

/-- The low `w` digits depend only on `v mod 256^w`. -/
theorem leDigits_mod_pow (w : Nat) : ∀ v,
    leDigits (v % 256 ^ w) w = leDigits v w := by
  induction w with
  | zero => intro v; simp [leDigits]
  | succ w ih =>
    intro v
    show (v % 256 ^ (w + 1) % 256) :: leDigits (v % 256 ^ (w + 1) / 256) w
       = (v % 256) :: leDigits (v / 256) w
    have hdvd : (256 : Nat) ∣ 256 ^ (w + 1) := ⟨256 ^ w, Nat.pow_succ'⟩
    have hhead : v % 256 ^ (w + 1) % 256 = v % 256 := Nat.mod_mod_of_dvd v hdvd
    have htail : v % 256 ^ (w + 1) / 256 = v / 256 % 256 ^ w := by
      rw [Nat.pow_succ']; exact Nat.mod_mul_right_div_self v 256 (256 ^ w)
    rw [hhead, htail, ih (v / 256)]

/-- `1 <<< (8·h) = 256^h` (the shift is the GMP-backed split point). -/
theorem shift_eq_pow256 (h : Nat) : (1 <<< (8 * h)) = 256 ^ h := by
  rw [Nat.shiftLeft_eq, Nat.one_mul, Nat.pow_mul]

/-- The fuelled divide-and-conquer encoder computes exactly the fixed-width digits. -/
theorem encFixedF_eq : ∀ f w v, w ≤ f → encFixedF f w v = leDigits v w := by
  intro f
  induction f with
  | zero =>
    intro w v hw
    have hw0 : w = 0 := Nat.le_zero.mp hw
    subst hw0; rfl
  | succ f ih =>
    intro w v hw
    match w with
    | 0 => rfl
    | 1 => rfl
    | (w + 2) =>
      have hh_le : (w + 2) / 2 ≤ f := by omega
      have hr_le : (w + 2) - (w + 2) / 2 ≤ f := by omega
      have hsum : (w + 2) / 2 + ((w + 2) - (w + 2) / 2) = w + 2 := by omega
      show encFixedF f ((w + 2) / 2) (v % (1 <<< (8 * ((w + 2) / 2))))
            ++ encFixedF f ((w + 2) - (w + 2) / 2) (v / (1 <<< (8 * ((w + 2) / 2))))
         = leDigits v (w + 2)
      rw [ih _ _ hh_le, ih _ _ hr_le, shift_eq_pow256, leDigits_mod_pow,
          ← leDigits_add, hsum]

/-- The exact byte count of `n/256` is one byte less than that of `n` — the digit recursion. -/
theorem nbytes_div256 (n : Nat) (hn : n ≠ 0) : nbytes (n / 256) = n.log2 / 8 := by
  rcases Nat.lt_or_ge n 256 with hlt | hge
  · have hd : n / 256 = 0 := Nat.div_eq_of_lt hlt
    have hlog : n.log2 < 8 := (Nat.log2_lt hn).mpr (by
      have : (2 : Nat) ^ 8 = 256 := by decide
      omega)
    rw [hd, Nat.div_eq_of_lt hlog]; rfl
  · have hd0 : n / 256 ≠ 0 := by
      have : 1 ≤ n / 256 := (Nat.le_div_iff_mul_le (by decide : 0 < 256)).mpr (by omega)
      omega
    have hb8 : 8 ≤ n.log2 := (Nat.le_log2 hn).mpr (by
      have : (2 : Nat) ^ 8 = 256 := by decide
      omega)
    have hlog_div : (n / 256).log2 = n.log2 - 8 := by
      rw [Nat.log2_eq_iff hd0]
      refine ⟨?_, ?_⟩
      · rw [Nat.le_div_iff_mul_le (by decide : 0 < 256)]
        calc 2 ^ (n.log2 - 8) * 256
            = 2 ^ (n.log2 - 8) * 2 ^ 8 := by rw [show (256 : Nat) = 2 ^ 8 from by decide]
          _ = 2 ^ ((n.log2 - 8) + 8) := (Nat.pow_add 2 _ _).symm
          _ = 2 ^ n.log2 := by rw [Nat.sub_add_cancel hb8]
          _ ≤ n := Nat.log2_self_le hn
      · rw [Nat.div_lt_iff_lt_mul (by decide : 0 < 256)]
        calc n < 2 ^ (n.log2 + 1) := Nat.lt_log2_self
          _ = 2 ^ ((n.log2 - 8 + 1) + 8) := by rw [show n.log2 - 8 + 1 + 8 = n.log2 + 1 from by omega]
          _ = 2 ^ (n.log2 - 8 + 1) * 2 ^ 8 := Nat.pow_add 2 _ _
          _ = 2 ^ (n.log2 - 8 + 1) * 256 := by rw [show (2 : Nat) ^ 8 = 256 from by decide]
    rw [nbytes, if_neg hd0, hlog_div]
    have hsc : n.log2 - 8 + 8 = n.log2 := Nat.sub_add_cancel hb8
    rw [← Nat.add_div_right (n.log2 - 8) (by decide : 0 < 8), hsc]

/-- The fuel model is the fixed-width digits at the exact byte count `nbytes n`. -/
theorem magBytes_eq_leDigits (n : Nat) : magBytes n = leDigits n (nbytes n) := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    rcases Nat.eq_zero_or_pos n with rfl | hpos
    · rfl
    · have hn0 : n ≠ 0 := by omega
      rw [magBytes_succ n hpos, nbytes, if_neg hn0]
      show (n % 256) :: magBytes (n / 256) = (n % 256) :: leDigits (n / 256) (n.log2 / 8)
      rw [ih (n / 256) (Nat.div_lt_self hpos (by decide)), nbytes_div256 n hn0]

/-- The `@[implemented_by]` runtime encoder is byte-for-byte the consensus `magBytes`. -/
theorem magBytesImpl_eq (n : Nat) : magBytesImpl n = magBytes n :=
  (encFixedF_eq _ _ _ (Nat.le_refl _)).trans (magBytes_eq_leDigits n).symm

def wid (m : Nat) : Nat :=
  match magBytes m with
  | []     => 0
  | b      => if b.getLast! ≥ 128 then b.length + 1 else b.length

theorem intByteLen_eq_wid (z : Int) : intByteLen z = wid z.natAbs := rfl
theorem wid_zero : wid 0 = 0 := rfl

theorem wid_lo (m : Nat) (h1 : 1 ≤ m) (h2 : m < 256) :
    wid m = if 128 ≤ m then 2 else 1 := by
  have hmod : m % 256 = m := Nat.mod_eq_of_lt h2
  have hdiv : m / 256 = 0 := Nat.div_eq_of_lt h2
  unfold wid
  rw [magBytes_succ m h1, hmod, hdiv]
  show (if (m :: magBytes 0).getLast! ≥ 128 then _ else _) = _
  have h0 : magBytes 0 = ([] : List Nat) := rfl
  rw [h0]
  simp only [List.getLast!, List.length]
  by_cases hc : 128 ≤ m <;> simp [hc]

theorem wid_hi (m : Nat) (h : 256 ≤ m) : wid m = wid (m/256) + 1 := by
  have hm1 : 1 ≤ m := by omega
  have hm' : 1 ≤ m/256 := by
    have := Nat.div_le_div_right (c := 256) h; simpa using this
  have hne : magBytes (m/256) ≠ [] := magBytes_ne_nil _ hm'
  unfold wid
  rw [magBytes_succ m hm1]
  cases hb : magBytes (m/256) with
  | nil => exact absurd hb hne
  | cons b l =>
    show (if ((m % 256) :: b :: l).getLast! ≥ 128 then ((m % 256) :: b :: l).length + 1
            else ((m % 256) :: b :: l).length)
       = (if (b :: l).getLast! ≥ 128 then (b :: l).length + 1 else (b :: l).length) + 1
    have hg : ((m % 256) :: b :: l).getLast! = (b :: l).getLast! := rfl
    rw [hg]
    simp only [List.length_cons]
    by_cases hc : (b :: l).getLast! ≥ 128
    · rw [if_pos hc, if_pos hc]
    · rw [if_neg hc, if_neg hc]


theorem wid_pos (m : Nat) (hm : 1 ≤ m) : 1 ≤ wid m := by
  rcases Nat.lt_or_ge m 256 with hlt | hge
  · rw [wid_lo m hm hlt]; by_cases hc : 128 ≤ m <;> simp [hc]
  · rw [wid_hi m hge]; omega

theorem pow256 (L : Nat) (hL : 2 ≤ L) : 256 * 2^(8*(L-1)-1) = 2^(8*L-1) := by
  have h : (256 : Nat) = 2^8 := by decide
  rw [h, ← Nat.pow_add]; congr 1; omega

theorem wid_band : ∀ m L, 1 ≤ L → (wid m ≤ L ↔ m < 2^(8*L-1)) := by
  intro m
  induction m using Nat.strongRecOn with
  | _ m ih =>
    intro L hL
    have hpow128 : (128 : Nat) ≤ 2^(8*L-1) := by
      calc (128:Nat) = 2^7 := by decide
        _ ≤ 2^(8*L-1) := Nat.pow_le_pow_right (by decide) (by omega)
    rcases Nat.lt_or_ge m 256 with hlt | hge
    · rcases Nat.eq_zero_or_pos m with rfl | hpos
      · rw [wid_zero]
        exact ⟨fun _ => by omega, fun _ => Nat.zero_le L⟩
      · rw [wid_lo m hpos hlt]
        by_cases hc : 128 ≤ m
        · rw [if_pos hc]
          constructor
          · intro hL2
            have h256 : (256:Nat) ≤ 2^(8*L-1) := by
              calc (256:Nat) = 2^8 := by decide
                _ ≤ 2^(8*L-1) := Nat.pow_le_pow_right (by decide) (by omega)
            exact Nat.lt_of_lt_of_le hlt h256
          · intro hm
            rcases Nat.lt_or_ge L 2 with hLlt | hLge
            · have hL1 : L = 1 := by omega
              subst hL1
              have h128 : (2:Nat)^(8*1-1) = 128 := by decide
              rw [h128] at hm; omega
            · exact hLge
        · rw [if_neg hc]
          exact ⟨fun _ => by omega, fun _ => hL⟩
    · rw [wid_hi m hge]
      have hm' : 1 ≤ m/256 := by
        have := Nat.div_le_div_right (c := 256) hge; simpa using this
      have hmlt : m/256 < m := Nat.div_lt_self (by omega) (by omega)
      rcases Nat.lt_or_ge L 2 with hL1 | hL2
      · have hLe : L = 1 := by omega
        subst hLe
        have hwp := wid_pos (m/256) hm'
        have h128 : (2:Nat)^(8*1-1) = 128 := by decide
        constructor
        · intro h; omega
        · intro h; rw [h128] at h; omega
      · have hkey : m/256 < 2^(8*(L-1)-1) ↔ m < 2^(8*L-1) := by
          rw [Nat.div_lt_iff_lt_mul (by decide : (0:Nat) < 256), Nat.mul_comm, pow256 L hL2]
        rw [← hkey, ← ih (m/256) hmlt (L-1) (by omega)]
        omega

theorem intByteLen_band (z : Int) (L : Nat) (hL : 1 ≤ L) :
    intByteLen z ≤ L ↔ z.natAbs < 2^(8*L-1) := by
  rw [intByteLen_eq_wid]; exact wid_band z.natAbs L hL

theorem intByteLen_eq_zero (z : Int) : intByteLen z = 0 ↔ z = 0 := by
  rw [intByteLen_eq_wid]
  constructor
  · intro h
    rcases Nat.eq_zero_or_pos z.natAbs with hz | hz
    · exact Int.natAbs_eq_zero.mp hz
    · have := wid_pos z.natAbs hz; omega
  · intro h; subst h; rfl


theorem intByteLen_pos_of_ne (z : Int) (h : z ≠ 0) : 1 ≤ intByteLen z := by
  rcases Nat.eq_zero_or_pos (intByteLen z) with hz | hz
  · exact absurd ((intByteLen_eq_zero z).mp hz) h
  · exact hz

theorem pow_double_le (M : Nat) (hM : 1 ≤ M) :
    2^(8*M-1) + 2^(8*M-1) ≤ 2^(8*(M+1)-1) := by
  have hdbl : 2^(8*M-1) + 2^(8*M-1) = 2^(8*M) := by
    have h2 : 2^(8*M-1) + 2^(8*M-1) = 2^(8*M-1) * 2 := by omega
    rw [h2, ← Nat.pow_succ]; congr 1; omega
  rw [hdbl]; exact Nat.pow_le_pow_right (by decide) (by omega)

theorem intByteLen_mul (a b : Int) :
    intByteLen (a * b) ≤ intByteLen a + intByteLen b := by
  by_cases ha : a = 0
  · subst ha; simp [intByteLen_zero]
  by_cases hb : b = 0
  · subst hb; simp [intByteLen_zero]
  have ha1 := intByteLen_pos_of_ne a ha
  have hb1 := intByteLen_pos_of_ne b hb
  rw [intByteLen_band (a*b) (intByteLen a + intByteLen b) (by omega)]
  have ha' : a.natAbs < 2^(8*(intByteLen a)-1) := (intByteLen_band a _ ha1).mp (Nat.le_refl _)
  have hb' : b.natAbs < 2^(8*(intByteLen b)-1) := (intByteLen_band b _ hb1).mp (Nat.le_refl _)
  calc (a*b).natAbs = a.natAbs * b.natAbs := Int.natAbs_mul a b
    _ < 2^(8*(intByteLen a)-1) * 2^(8*(intByteLen b)-1) := Nat.mul_lt_mul'' ha' hb'
    _ = 2^((8*(intByteLen a)-1)+(8*(intByteLen b)-1)) := (Nat.pow_add 2 _ _).symm
    _ ≤ 2^(8*(intByteLen a + intByteLen b)-1) := Nat.pow_le_pow_right (by decide) (by omega)

theorem intByteLen_add (a b : Int) :
    intByteLen (a + b) ≤ max (intByteLen a) (intByteLen b) + 1 := by
  rcases Nat.eq_zero_or_pos (max (intByteLen a) (intByteLen b)) with hM0 | hMpos
  · have ha0 : intByteLen a = 0 := by omega
    have hb0 : intByteLen b = 0 := by omega
    have hz1 : a = 0 := (intByteLen_eq_zero a).mp ha0
    have hz2 : b = 0 := (intByteLen_eq_zero b).mp hb0
    subst hz1; subst hz2; simp [intByteLen_zero]
  · rw [intByteLen_band (a+b) (max (intByteLen a) (intByteLen b) + 1) (by omega)]
    have ha' := (intByteLen_band a _ hMpos).mp (Nat.le_max_left (intByteLen a) (intByteLen b))
    have hb' := (intByteLen_band b _ hMpos).mp (Nat.le_max_right (intByteLen a) (intByteLen b))
    have htri : (a+b).natAbs ≤ a.natAbs + b.natAbs := Int.natAbs_add_le a b
    have hpow := pow_double_le (max (intByteLen a) (intByteLen b)) hMpos
    omega

theorem intByteLen_sub (a b : Int) :
    intByteLen (a - b) ≤ max (intByteLen a) (intByteLen b) + 1 := by
  rcases Nat.eq_zero_or_pos (max (intByteLen a) (intByteLen b)) with hM0 | hMpos
  · have ha0 : intByteLen a = 0 := by omega
    have hb0 : intByteLen b = 0 := by omega
    have hz1 : a = 0 := (intByteLen_eq_zero a).mp ha0
    have hz2 : b = 0 := (intByteLen_eq_zero b).mp hb0
    subst hz1; subst hz2; simp [intByteLen_zero]
  · rw [intByteLen_band (a-b) (max (intByteLen a) (intByteLen b) + 1) (by omega)]
    have ha' := (intByteLen_band a _ hMpos).mp (Nat.le_max_left (intByteLen a) (intByteLen b))
    have hb' := (intByteLen_band b _ hMpos).mp (Nat.le_max_right (intByteLen a) (intByteLen b))
    have htri : (a-b).natAbs ≤ a.natAbs + b.natAbs := Int.natAbs_sub_le a b
    have hpow := pow_double_le (max (intByteLen a) (intByteLen b)) hMpos
    omega

theorem intByteLen_tdiv (a b : Int) :
    intByteLen (Int.tdiv a b) ≤ intByteLen a := by
  by_cases ha : a = 0
  · subst ha; simp [Int.zero_tdiv, intByteLen_zero]
  have ha1 := intByteLen_pos_of_ne a ha
  rw [intByteLen_band (Int.tdiv a b) (intByteLen a) ha1]
  have ha' : a.natAbs < 2^(8*(intByteLen a)-1) := (intByteLen_band a _ ha1).mp (Nat.le_refl _)
  have hle : (Int.tdiv a b).natAbs ≤ a.natAbs := Int.natAbs_tdiv_le_natAbs a b
  omega

theorem intByteLen_tmod (a b : Int) (hb : b ≠ 0) :
    intByteLen (Int.tmod a b) ≤ intByteLen b := by
  have hb1 := intByteLen_pos_of_ne b hb
  rw [intByteLen_band (Int.tmod a b) (intByteLen b) hb1]
  have hb' : b.natAbs < 2^(8*(intByteLen b)-1) := (intByteLen_band b _ hb1).mp (Nat.le_refl _)
  have hbpos : 0 < b.natAbs := Int.natAbs_pos.mpr hb
  have hmod : (Int.tmod a b).natAbs < b.natAbs := by
    rw [Int.natAbs_tmod]; exact Nat.mod_lt _ hbpos
  omega

/-! ## Half B — the concrete byte encoder / decoder (the actual VM-number spec)

    libauth `vm/instruction-sets/common/instruction-sets-utils.js` (pin 3.1.0-next.8):

    `bigIntToVmNumber(integer)`  (line 402): `0n → []`; else push little-endian magnitude
    bytes; then if the top magnitude byte has bit 0x80 set, push a sign byte (`0x80` if
    negative else `0x00`); ELSE if negative, OR the top byte with `0x80`.

    `vmNumberToBigInt(bytes)` (line 342): `[] → 0`; else little-endian decode, the last
    byte's 0x80 bit is the sign, cleared from the magnitude, then negate if set.

    We keep the pipeline at the Nat-digit level (`encodeDigits`/`decodeDigits`) and map to
    `Bytes := List UInt8` only at the boundary — every produced digit is `< 256`, so the
    `UInt8.ofNat`/`toNat` round-trip is the identity and the correctness proof stays pure
    `Nat`. `x ||| 0x80` for `x < 128` is `x + 128` byte-for-byte; we use the arithmetic form. -/

/-- Little-endian base-256 value of a Nat-digit list (`decode` of the plain magnitude). -/
def natOfDigits : List Nat → Nat
  | []      => 0
  | x :: xs => x + 256 * natOfDigits xs

/-- Sign-apply on the little-endian magnitude digits (libauth `bigIntToVmNumber` tail).
    Recurses to the LAST digit (the most-significant byte). -/
def encodeDigits (neg : Bool) : List Nat → List Nat
  | []      => []
  | x :: rest =>
    match rest with
    | []     =>
        if 128 ≤ x then [x, if neg then 128 else 0]   -- top bit set → +1 sign byte
        else if neg then [x + 128] else [x]           -- else set 0x80 on the top byte
    | _ :: _ => x :: encodeDigits neg rest

/-- Decode signed VM-number digits back to `(magnitude, negative)` (libauth
    `vmNumberToBigInt` tail): the last byte's 0x80 bit is the sign, cleared from magnitude. -/
def decodeDigits : List Nat → (Nat × Bool)
  | []      => (0, false)
  | x :: rest =>
    match rest with
    | []     => if 128 ≤ x then (x - 128, true) else (x, false)
    | _ :: _ => let p := decodeDigits rest; (x + 256 * p.1, p.2)

/-- The libauth `bigIntToVmNumber` over `Bytes`. -/
def bigIntToVmNumber (z : Int) : Bytes :=
  (encodeDigits (decide (z < 0)) (magBytes z.natAbs)).map (fun d => (UInt8.ofNat d))

/-- The libauth `vmNumberToBigInt` over `Bytes` (minimal-encoding accepted). -/
def vmNumberToBigInt (b : Bytes) : Int :=
  let p := decodeDigits (b.map (fun w => w.toNat))
  if p.2 then -(Int.ofNat p.1) else Int.ofNat p.1

/-! ### Digit-level facts feeding the round-trip. -/

/-- Every magnitude digit is a genuine byte (`< 256`). -/
theorem magBytes_lt_256 : ∀ n, ∀ d ∈ magBytes n, d < 256 := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    rcases Nat.eq_zero_or_pos n with rfl | hpos
    · intro d hd; simp [magBytes, magBytesFuel] at hd
    · rw [magBytes_succ n hpos]
      intro d hd
      rcases List.mem_cons.mp hd with h | h
      · subst h; exact Nat.mod_lt _ (by decide)
      · exact ih (n/256) (Nat.div_lt_self hpos (by decide)) d h

/-- `encodeDigits` keeps every digit a genuine byte (`< 256`). -/
theorem encodeDigits_lt_256 (neg : Bool) :
    ∀ L, (∀ d ∈ L, d < 256) → ∀ d ∈ encodeDigits neg L, d < 256 := by
  intro L
  induction L with
  | nil => intro _ d hd; simp [encodeDigits] at hd
  | cons x rest ih =>
    intro hL d hd
    have hx : x < 256 := hL x (by simp)
    cases rest with
    | nil =>
      simp only [encodeDigits] at hd
      by_cases hc : 128 ≤ x
      · rw [if_pos hc] at hd
        rcases List.mem_cons.mp hd with h | h
        · subst h; exact hx
        · rcases List.mem_cons.mp h with h2 | h2
          · subst h2; by_cases hn : neg <;> simp [hn]
          · simp at h2
      · rw [if_neg hc] at hd
        by_cases hn : neg
        · simp only [hn, if_true] at hd
          rcases List.mem_cons.mp hd with h | h
          · subst h; omega
          · simp at h
        · simp only [hn, Bool.false_eq_true, if_false] at hd
          rcases List.mem_cons.mp hd with h | h
          · subst h; exact hx
          · simp at h
    | cons y rest' =>
      have hrec : encodeDigits neg (x :: y :: rest') = x :: encodeDigits neg (y :: rest') := rfl
      rw [hrec] at hd
      rcases List.mem_cons.mp hd with h | h
      · subst h; exact hx
      · exact ih (fun d' hd' => hL d' (List.mem_cons_of_mem _ hd')) d h

/-- The map/unmap boundary is the identity on digit lists whose entries are genuine bytes. -/
theorem map_toNat_ofNat (L : List Nat) (hL : ∀ d ∈ L, d < 256) :
    (L.map (fun d => (UInt8.ofNat d))).map (fun w => w.toNat) = L := by
  induction L with
  | nil => rfl
  | cons x xs ih =>
    have hx : x < 256 := hL x (by simp)
    simp only [List.map_cons]
    have hxx : (UInt8.ofNat x).toNat = x := by
      have : (UInt8.ofNat x).toNat = x % 256 := rfl
      rw [this]; exact Nat.mod_eq_of_lt hx
    rw [hxx, ih (fun d hd => hL d (List.mem_cons_of_mem _ hd))]

/-- `encodeDigits` never empties a nonempty magnitude list. -/
theorem encodeDigits_ne_nil (neg : Bool) (x : Nat) : ∀ rest, encodeDigits neg (x :: rest) ≠ [] := by
  intro rest
  cases rest with
  | nil =>
    by_cases hc : 128 ≤ x
    · simp only [encodeDigits, if_pos hc]; exact List.cons_ne_nil _ _
    · simp only [encodeDigits, if_neg hc]
      by_cases hn : neg <;> simp [hn]
  | cons y r =>
    show x :: encodeDigits neg (y :: r) ≠ []
    exact List.cons_ne_nil _ _

/-- `encodeDigits` of a NONEMPTY magnitude list is decoded back to `(value, sign)`.
    Pure structural induction — no powers of 256. -/
theorem decode_encode (neg : Bool) :
    ∀ L, L ≠ [] → decodeDigits (encodeDigits neg L) = (natOfDigits L, neg) := by
  intro L
  induction L with
  | nil => intro h; exact absurd rfl h
  | cons x rest ih =>
    intro _
    cases rest with
    | nil =>
      have hval : natOfDigits [x] = x := rfl
      rw [hval]
      by_cases hc : 128 ≤ x
      · -- top bit set: append sign byte, decode two-byte tail
        simp only [encodeDigits, if_pos hc]
        by_cases hn : neg
        · simp only [hn, if_true]
          have h1 : decodeDigits [128] = (0, true) := rfl
          show (x + 256 * (decodeDigits [128]).1, (decodeDigits [128]).2) = (x, true)
          rw [h1]; simp
        · simp only [hn, Bool.false_eq_true, if_false]
          have h1 : decodeDigits [0] = (0, false) := rfl
          show (x + 256 * (decodeDigits [0]).1, (decodeDigits [0]).2) = (x, false)
          rw [h1]; simp
      · simp only [encodeDigits, if_neg hc]
        by_cases hn : neg
        · -- negative, set top bit: [x+128], single byte ≥ 128
          simp only [hn, if_true]
          have hge : 128 ≤ x + 128 := by omega
          show (if 128 ≤ x + 128 then (x + 128 - 128, true) else (x + 128, false)) = (x, true)
          rw [if_pos hge, Nat.add_sub_cancel]
        · simp only [hn, Bool.false_eq_true, if_false]
          show (if 128 ≤ x then (x - 128, true) else (x, false)) = (x, false)
          rw [if_neg hc]
    | cons y rest' =>
      have hrec : encodeDigits neg (x :: y :: rest')
                = x :: encodeDigits neg (y :: rest') := rfl
      rw [hrec]
      have hne : encodeDigits neg (y :: rest') ≠ [] := encodeDigits_ne_nil neg y rest'
      cases hcz : encodeDigits neg (y :: rest') with
      | nil => exact absurd hcz hne
      | cons a l =>
        show decodeDigits (x :: a :: l) = (natOfDigits (x :: y :: rest'), neg)
        have : decodeDigits (x :: a :: l)
             = (x + 256 * (decodeDigits (a :: l)).1, (decodeDigits (a :: l)).2) := rfl
        rw [this, ← hcz, ih (by simp)]
        simp [natOfDigits]

/-- Little-endian decode of the plain magnitude digits recovers the magnitude. -/
theorem natOfDigits_magBytes : ∀ n, natOfDigits (magBytes n) = n := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    rcases Nat.eq_zero_or_pos n with rfl | hpos
    · rfl
    · rw [magBytes_succ n hpos]
      show (n % 256) + 256 * natOfDigits (magBytes (n/256)) = n
      rw [ih (n/256) (Nat.div_lt_self hpos (by decide))]
      omega

/-! ### The key correctness theorem. -/

/-- `vmNumberToBigInt (bigIntToVmNumber z) = z` — the encoder is a section of the decoder. -/
theorem vmNumber_roundTrip (z : Int) : vmNumberToBigInt (bigIntToVmNumber z) = z := by
  by_cases hz : z = 0
  · subst hz; rfl
  -- magnitude is nonzero, so the digit list is nonempty
  have hnat : z.natAbs ≠ 0 := fun h => hz (Int.natAbs_eq_zero.mp h)
  have hpos : 1 ≤ z.natAbs := Nat.one_le_iff_ne_zero.mpr hnat
  have hLne : magBytes z.natAbs ≠ [] := magBytes_ne_nil _ hpos
  unfold vmNumberToBigInt bigIntToVmNumber
  -- strip the UInt8 boundary
  rw [map_toNat_ofNat _ (encodeDigits_lt_256 _ _ (magBytes_lt_256 _))]
  -- decode ∘ encode = (value, sign)
  rw [decode_encode _ _ hLne, natOfDigits_magBytes]
  dsimp only
  -- reassemble the Int from (magnitude, sign)
  by_cases hneg : z < 0
  · rw [if_pos (decide_eq_true_eq.mpr hneg)]
    have key : Int.ofNat z.natAbs = -z := by
      have h2 : ((-z).natAbs : Int) = -z := Int.natAbs_of_nonneg (by omega)
      rwa [Int.natAbs_neg] at h2
    rw [key]; omega
  · rw [if_neg (by rw [decide_eq_true_eq]; exact hneg)]
    exact Int.natAbs_of_nonneg (by omega)

/-! ### The bridge to Half A: the width lattice is a fact about the ACTUAL bytes. -/

/-- `encodeDigits` length: appends exactly one byte iff the top magnitude digit ≥ 128. -/
theorem encodeDigits_length (neg : Bool) :
    ∀ L, L ≠ [] →
      (encodeDigits neg L).length = if L.getLast! ≥ 128 then L.length + 1 else L.length := by
  intro L
  induction L with
  | nil => intro h; exact absurd rfl h
  | cons x rest ih =>
    intro _
    cases rest with
    | nil =>
      have hgl : ([x] : List Nat).getLast! = x := rfl
      rw [hgl]
      by_cases hc : 128 ≤ x
      · show (encodeDigits neg [x]).length = _
        simp only [encodeDigits, if_pos hc]; rfl
      · show (encodeDigits neg [x]).length = _
        simp only [encodeDigits, if_neg hc]
        by_cases hn : neg <;> simp [hn]
    | cons y rest' =>
      have hrec : encodeDigits neg (x :: y :: rest')
                = x :: encodeDigits neg (y :: rest') := rfl
      have hgl : (x :: y :: rest').getLast! = (y :: rest').getLast! := rfl
      rw [hrec, hgl, List.length_cons, ih (by simp)]
      by_cases hc : (y :: rest').getLast! ≥ 128
      · rw [if_pos hc, if_pos hc]; simp [List.length_cons]
      · rw [if_neg hc, if_neg hc]; simp [List.length_cons]

/-- The Half-A width equals the length of the ACTUAL libauth-encoded bytes. -/
theorem intByteLen_eq_encodedLength (z : Int) :
    intByteLen z = (bigIntToVmNumber z).length := by
  unfold bigIntToVmNumber
  rw [List.length_map]
  rw [intByteLen_eq_wid]
  by_cases hz : z.natAbs = 0
  · rw [hz]
    have : magBytes 0 = ([] : List Nat) := rfl
    simp [wid, encodeDigits, this]
  · have hpos : 1 ≤ z.natAbs := Nat.one_le_iff_ne_zero.mpr hz
    have hLne : magBytes z.natAbs ≠ [] := magBytes_ne_nil _ hpos
    rw [encodeDigits_length _ _ hLne]
    show wid z.natAbs = _
    unfold wid
    cases hb : magBytes z.natAbs with
    | nil => exact absurd hb hLne
    | cons a l => rfl

/-! ### BCH minimal-encoding (consumed by the VM push path). -/

/-- BCH rejects non-minimal number pushes. libauth `vmNumberToBigInt` `requiresMinimal`
    (line 358): non-minimal iff `(msb & 0x7f)==0 ∧ (len≤1 ∨ (2nd-msb & 0x80)==0)`.
    `(b & 0x7f) = b % 128` and `(b & 0x80)≠0 ↔ b ≥ 128` (byte-wise), used arithmetically. -/
def isMinimallyEncoded (b : Bytes) : Bool :=
  match b.reverse with
  | []          => true
  | msb :: rest =>
      if msb.toNat % 128 ≠ 0 then true
      else match rest with
        | []            => false
        | second :: _   => second.toNat ≥ 128

/-- The MSB magnitude digit of a nonzero value is ≥ 1 (no leading zero byte). -/
theorem magBytes_getLast_pos : ∀ n, 1 ≤ n → 1 ≤ (magBytes n).getLast! := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro hpos
    rcases Nat.lt_or_ge n 256 with hlt | hge
    · have h1 : 1 ≤ n := hpos
      rw [magBytes_succ n h1, Nat.mod_eq_of_lt hlt, Nat.div_eq_of_lt hlt]
      have : magBytes 0 = ([] : List Nat) := rfl
      rw [this]
      show 1 ≤ ([n] : List Nat).getLast!
      simpa using h1
    · have h1 : 1 ≤ n := by omega
      have hd : 1 ≤ n / 256 := by
        have := Nat.div_le_div_right (c := 256) hge; simpa using this
      have hdlt : n / 256 < n := Nat.div_lt_self (by omega) (by decide)
      have hne : magBytes (n/256) ≠ [] := magBytes_ne_nil _ hd
      rw [magBytes_succ n h1]
      cases hb : magBytes (n/256) with
      | nil => exact absurd hb hne
      | cons c l =>
        have hgl : ((n % 256) :: c :: l).getLast! = (c :: l).getLast! := rfl
        rw [hgl, ← hb]
        exact ih (n/256) hdlt hd

/-- Explicit reverse of an encoded number: the most-significant region is either a sign
    pad over the top digit (`≥ 128` case) or the sign-flipped top digit itself. -/
theorem encodeDigits_reverse (neg : Bool) : ∀ L, L ≠ [] →
    (encodeDigits neg L).reverse =
      (if 128 ≤ L.getLast! then
          (if neg then 128 else 0) :: L.getLast! :: L.dropLast.reverse
       else
          (if neg then L.getLast! + 128 else L.getLast!) :: L.dropLast.reverse) := by
  intro L
  induction L with
  | nil => intro h; exact absurd rfl h
  | cons x rest ih =>
    intro _
    cases rest with
    | nil =>
      have hgl : ([x] : List Nat).getLast! = x := rfl
      have hdl : ([x] : List Nat).dropLast = [] := rfl
      rw [hgl, hdl]
      by_cases hc : 128 ≤ x
      · show (encodeDigits neg [x]).reverse = _
        simp only [encodeDigits, if_pos hc]; simp
      · show (encodeDigits neg [x]).reverse = _
        simp only [encodeDigits, if_neg hc]
        by_cases hn : neg <;> simp [hn]
    | cons y rest' =>
      have hrec : encodeDigits neg (x :: y :: rest')
                = x :: encodeDigits neg (y :: rest') := rfl
      have hgl : (x :: y :: rest').getLast! = (y :: rest').getLast! := rfl
      have hdl : (x :: y :: rest').dropLast = x :: (y :: rest').dropLast := rfl
      rw [hrec, List.reverse_cons, ih (by simp), hgl, hdl, List.reverse_cons]
      by_cases hc : 128 ≤ (y :: rest').getLast!
      · rw [if_pos hc, if_pos hc]; rfl
      · rw [if_neg hc, if_neg hc]; rfl

/-- The `getLast!` of a nonempty list is a member of it. -/
theorem getLast!_mem : ∀ (l : List Nat), l ≠ [] → l.getLast! ∈ l
  | [], h => absurd rfl h
  | [x], _ => by simp
  | a :: b :: t, _ => by
      have h : (a :: b :: t).getLast! = (b :: t).getLast! := rfl
      rw [h]
      exact List.mem_cons_of_mem a (getLast!_mem (b :: t) (by simp))

/-- Sign-flipping the top byte of a `< 128` magnitude digit leaves the low 7 bits intact. -/
theorem topByte_mod (d : Nat) (h : d < 128) (b : Bool) :
    (UInt8.ofNat (if b then d + 128 else d)).toNat % 128 = d := by
  cases b with
  | false =>
    show (d % 256) % 128 = d
    rw [Nat.mod_eq_of_lt (show d < 256 by omega)]
    exact Nat.mod_eq_of_lt h
  | true =>
    show ((d + 128) % 256) % 128 = d
    rw [Nat.mod_eq_of_lt (show d + 128 < 256 by omega), Nat.add_mod_right, Nat.mod_eq_of_lt h]

/-- Every `bigIntToVmNumber` output is minimally encoded — the VM push predicate accepts it. -/
theorem bigIntToVmNumber_minimal (z : Int) :
    isMinimallyEncoded (bigIntToVmNumber z) = true := by
  by_cases hz : z.natAbs = 0
  · have : z = 0 := Int.natAbs_eq_zero.mp hz
    subst this; rfl
  have hpos : 1 ≤ z.natAbs := Nat.one_le_iff_ne_zero.mpr hz
  have hLne : magBytes z.natAbs ≠ [] := magBytes_ne_nil _ hpos
  have hldpos : 1 ≤ (magBytes z.natAbs).getLast! := magBytes_getLast_pos _ hpos
  have hldlt : (magBytes z.natAbs).getLast! < 256 :=
    magBytes_lt_256 z.natAbs _ (getLast!_mem _ hLne)
  have hsnd : (UInt8.ofNat (magBytes z.natAbs).getLast!).toNat = (magBytes z.natAbs).getLast! :=
    Nat.mod_eq_of_lt hldlt
  unfold bigIntToVmNumber isMinimallyEncoded
  rw [← List.map_reverse, encodeDigits_reverse (decide (z < 0)) _ hLne]
  -- abstract the sign Bool (no mathlib `set`; plain `generalize`)
  generalize hnb : decide (z < 0) = nb
  by_cases hc : 128 ≤ (magBytes z.natAbs).getLast!
  · -- top bit set: msb = sign pad (0 or 128), second-msb = ld ≥ 128
    rw [if_pos hc]
    have hmsb : (UInt8.ofNat (if nb then 128 else 0)).toNat % 128 = 0 := by
      cases nb <;> decide
    simp only [List.map_cons, hmsb, hsnd, ne_eq, not_true_eq_false, if_false,
               decide_eq_true_eq]
    exact hc
  · -- top bit clear: msb = ld (unchanged) or ld+128 (negative); low 7 bits = ld ≥ 1
    rw [if_neg hc]
    have hlt : (magBytes z.natAbs).getLast! < 128 := by omega
    have hne0 : (magBytes z.natAbs).getLast! ≠ 0 := by omega
    have hmsb := topByte_mod (magBytes z.natAbs).getLast! hlt nb
    simp only [List.map_cons, hmsb, ne_eq, hne0, not_false_eq_true, if_true]

/-! ### libauth `bigIntToVmNumber` boundary witnesses (cross-checked against pin 3.1.0-next.8).

    The fuel-based `magBytes` reduces, so these close by `decide` — no `native_decide`. -/

example : bigIntToVmNumber 0    = ([] : Bytes)                := by decide
example : bigIntToVmNumber 1    = ([0x01] : Bytes)            := by decide
example : bigIntToVmNumber 128  = ([0x80, 0x00] : Bytes)      := by decide
example : bigIntToVmNumber (-1) = ([0x81] : Bytes)            := by decide
example : bigIntToVmNumber 255  = ([0xff, 0x00] : Bytes)      := by decide
example : bigIntToVmNumber (-128) = ([0x80, 0x80] : Bytes)    := by decide
-- extra cross-checks against libauth: 2-byte no-pad, negative top-bit-flip, 3-byte pad
example : bigIntToVmNumber 256   = ([0x00, 0x01] : Bytes)       := by decide
example : bigIntToVmNumber (-127) = ([0xff] : Bytes)            := by decide
example : bigIntToVmNumber 32768 = ([0x00, 0x80, 0x00] : Bytes) := by decide

-- round-trip sanity on the same boundary witnesses (decode ∘ encode = id)
example : vmNumberToBigInt (bigIntToVmNumber 128)    = 128    := by decide
example : vmNumberToBigInt (bigIntToVmNumber (-128)) = -128   := by decide

-- minimal-encoding accepts every witness; and pins the NON-minimal rejects
example : isMinimallyEncoded ([0x80, 0x00] : Bytes) = true    := by decide  -- 128
example : isMinimallyEncoded ([0x00] : Bytes)       = false   := by decide  -- non-minimal 0
example : isMinimallyEncoded ([0x00, 0x00] : Bytes) = false   := by decide  -- non-minimal
example : isMinimallyEncoded ([0x01, 0x00] : Bytes) = false   := by decide  -- non-minimal 1

/-! ### `magBytesImpl` (the O(n·log n) runtime encoder) agrees with the fuel model.

    The universal proof is `magBytesImpl_eq`; these are executable cross-checks. The `decide`
    witnesses reduce BOTH algorithms in the kernel (the D&C `magBytesImpl` vs the byte-at-a-time
    `magBytesFuel`), so they add nothing but `[propext, Quot.sound]`. The `#eval`s run the compiled
    encoders against the raw fuel reference `magBytesFuel (v+1) v`, including a 10000-byte value. -/

-- Kernel cross-checks: divide-and-conquer = fuel model, on hand-picked boundary values.
example : magBytesImpl 0        = magBytes 0        := by decide
example : magBytesImpl 1        = magBytes 1        := by decide
example : magBytesImpl 127      = magBytes 127      := by decide
example : magBytesImpl 128      = magBytes 128      := by decide
example : magBytesImpl 255      = magBytes 255      := by decide
example : magBytesImpl 256      = magBytes 256      := by decide
example : magBytesImpl 32768    = magBytes 32768    := by decide
example : magBytesImpl 65535    = magBytes 65535    := by decide
example : magBytesImpl 65536    = magBytes 65536    := by decide
example : magBytesImpl 16777216 = magBytes 16777216 := by decide  -- 2^24, a 4-byte value

-- Executable cross-checks against the raw fuel reference (compiled path).
#eval (List.range 512).all (fun v => magBytesImpl v == magBytesFuel (v + 1) v)      -- true
#eval [255, 256, 32768, 65535, 65536, 16777215, 16777216, 2^64, 2^100, 2^1000].all
        (fun v => magBytesImpl v == magBytesFuel (v + 1) v)                          -- true

-- The large value: 2^79998 = 64·256^9999 (79998 = 8·9999 + 6), so exactly 10000 magnitude bytes
-- ([0]×9999 ++ [64]); top byte 64 < 128 ⇒ no sign pad ⇒ intByteLen = 10000.
#eval (magBytesImpl (2 ^ 79998)).length                                             -- 10000
#eval magBytesImpl (2 ^ 79998) == (List.replicate 9999 0 ++ [64])                   -- true
#eval intByteLen (2 ^ 79998)                                                        -- 10000

end LeanBCH
