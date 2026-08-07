//! CT-AIR: layout, witness, trace build, transition/boundary residuals (base + GF(p^2)).
//! Faithful port of vendor native_ct_air_prover.py for the transfer relation.
use serde::{Deserialize, Serialize};
use crate::air_matrices::{M_EXT, M_EXT_INV};
use crate::field::{self, P};
use crate::flat_cols::{FLAT_COLS, N_FLAT};
use crate::gf2::{self, Ext};
use crate::poseidon2::{self, hash_to_1, merkle_compress, permutation_trace, RATE, WIDTH};
use crate::poseidon2_constants::{MAT_DIAG12, RC, ROUNDS_F, ROUNDS_P};

pub const ROUNDS: usize = ROUNDS_F + ROUNDS_P; // 30
pub const N_OUT: usize = 2;
pub const RANGE_BITS: usize = 62;
pub const DOM_NF: u64 = 0x636173685f6e66; // "cash_nf"
pub const HELD_COLS: [&str; 4] = ["vh_value_in", "vh_value_out0", "vh_value_out1", "vh_fee"];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    pub sk: u64,
    pub rho_in: u64,
    pub blind_in: u64,
    pub value_in: u64,
    pub fee: u64,
    pub value_outs: [u64; 2],
    pub owners_out: [u64; 2],
    pub rhos_out: [u64; 2],
    pub blinds_out: [u64; 2],
    pub siblings: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct Statement {
    pub root: u64,
    pub nf: u64,
    pub cm_out: [u64; 2],
    pub depth: usize,
}

/// Domain tag used by pool_prove.build_witness for kind-binding into the membership path.
pub const DOM_POOL: u64 = 0x534B4631; // "SKF1"
const POOL_VALUE_D: u64 = 10_000_000;

/// Development demo witness (not oracle-aligned). Prefer [`pool_witness`] for product/diff.
pub fn demo_witness(depth: usize, seed: u64) -> Witness {
    let mut rng = crate::py_random::PyRandom::new(seed);
    let sk = rng.randrange_1_p(P);
    let rho_in = rng.randrange_1_p(P);
    let blind_in = rng.randrange_1_p(P);
    let owners_out = [rng.randrange_1_p(P), rng.randrange_1_p(P)];
    let rhos_out = [rng.randrange_1_p(P), rng.randrange_1_p(P)];
    let blinds_out = [rng.randrange_1_p(P), rng.randrange_1_p(P)];
    let siblings = (0..depth).map(|_| rng.randrange_1_p(P)).collect();
    Witness {
        sk,
        rho_in,
        blind_in,
        value_in: POOL_VALUE_D,
        fee: 0,
        value_outs: [POOL_VALUE_D, 0],
        owners_out,
        rhos_out,
        blinds_out,
        siblings,
    }
}

/// Kind-distinct witness matching `packages/prove/python/pool_prove.build_witness`
/// (CPython `random.Random`, value schedule, DOM_POOL sibling tag).
pub fn pool_witness(kind: &str, depth: usize, seed: u64) -> Witness {
    let kind_id: u64 = match kind {
        "deposit" => 1,
        "transfer" => 2,
        "withdrawal" => 3,
        _ => 0,
    };
    let mut rng = crate::py_random::PyRandom::new(seed ^ kind_id);
    let sk = rng.randrange_1_p(P);
    let rho_in = rng.randrange_1_p(P);
    let blind_in = rng.randrange_1_p(P);
    let mut siblings: Vec<u64> = (0..depth).map(|_| rng.randrange_1_p(P)).collect();
    let (value_in, fee, value_outs) = match kind {
        "deposit" => (POOL_VALUE_D, 0, [POOL_VALUE_D, 0]),
        "transfer" => (POOL_VALUE_D, 0, [POOL_VALUE_D, 0]),
        "withdrawal" => (POOL_VALUE_D, POOL_VALUE_D, [0, 0]),
        _ => (POOL_VALUE_D, 0, [POOL_VALUE_D, 0]),
    };
    let owners_out = [rng.randrange_1_p(P), rng.randrange_1_p(P)];
    let rhos_out = [rng.randrange_1_p(P), rng.randrange_1_p(P)];
    let blinds_out = [rng.randrange_1_p(P), rng.randrange_1_p(P)];
    // pool_prove: siblings[0] = hash_to_1([DOM_POOL, kind_id, siblings[0]])
    if !siblings.is_empty() {
        siblings[0] = hash_to_1(&[DOM_POOL, kind_id, siblings[0]]);
    }
    Witness {
        sk,
        rho_in,
        blind_in,
        value_in,
        fee,
        value_outs,
        owners_out,
        rhos_out,
        blinds_out,
        siblings,
    }
}

fn absorb(inputs: &[u64]) -> [u64; WIDTH] {
    let mut st = [0u64; WIDTH];
    assert!(inputs.len() <= RATE);
    for (i, v) in inputs.iter().enumerate() {
        st[i] = *v % P;
    }
    st
}

struct Block {
    input: [u64; WIDTH],
    states: Vec<[u64; WIDTH]>,
    aux: Vec<poseidon2::RoundAux>,
    out: u64,
}

fn block(inputs: &[u64]) -> Block {
    let st = absorb(inputs);
    let (states, aux) = permutation_trace(&st);
    let out = states[states.len() - 1][0];
    Block {
        input: st,
        states,
        aux,
        out,
    }
}

pub fn compute_transfer(w: &Witness) -> (Statement, u64, u64) {
    let sk = w.sk % P;
    let owner_pk = hash_to_1(&[sk]);
    let nf = hash_to_1(&[sk, w.rho_in, DOM_NF]);
    let cm_in = hash_to_1(&[w.value_in, owner_pk, w.rho_in, w.blind_in]);
    let mut digest = cm_in;
    for sib in &w.siblings {
        digest = merkle_compress(digest, *sib % P);
    }
    let cm_out = [
        hash_to_1(&[w.value_outs[0], w.owners_out[0], w.rhos_out[0], w.blinds_out[0]]),
        hash_to_1(&[w.value_outs[1], w.owners_out[1], w.rhos_out[1], w.blinds_out[1]]),
    ];
    (
        Statement {
            root: digest,
            nf,
            cm_out,
            depth: w.siblings.len(),
        },
        owner_pk,
        cm_in,
    )
}

#[derive(Clone)]
pub struct Meta {
    pub rows: Vec<RowMeta>,
    pub blocks: Vec<BlockMeta>,
    pub range: Vec<RangeMeta>,
    pub cons_row: usize,
    pub raw: usize,
}

#[derive(Clone)]
pub struct RowMeta {
    pub block: String,
    pub typ: String, // round_full | round_partial | boundary | range | cons | pad
    pub rc: [u64; WIDTH],
}

#[derive(Clone)]
pub struct BlockMeta {
    pub name: String,
    pub offset: usize,
    pub n: usize,
    pub chain: Vec<(usize, String)>, // lane -> prev block name
}

#[derive(Clone)]
pub struct RangeMeta {
    pub vname: String,
    pub offset: usize,
    pub n: usize,
    pub src: Option<String>,
}

fn block_rc_full(n_rows: usize) -> (Vec<[u64; WIDTH]>, Vec<bool>) {
    // Mirrors _block_rc_full: rounds 0..29 with full/partial pattern from Poseidon2
    let rf_half = ROUNDS_F / 2;
    let p_end = rf_half + ROUNDS_P;
    let mut rc_rows = Vec::new();
    let mut full_rows = Vec::new();
    // n_rows = ROUNDS+1 = 31; rows 0..29 are rounds, row 30 boundary
    for r in 0..ROUNDS {
        let full = r < rf_half || r >= p_end;
        full_rows.push(full);
        rc_rows.push(RC[r]);
    }
    // padding if needed
    while rc_rows.len() < n_rows - 1 {
        rc_rows.push([0u64; WIDTH]);
        full_rows.push(false);
    }
    (rc_rows, full_rows)
}

pub fn ct_build_layout(d: usize) -> (Meta, usize) {
    let n_blk = ROUNDS + 1;
    let mut seq = vec!["owner".to_string(), "cm_in".to_string()];
    for j in 0..d {
        seq.push(format!("memb{j}"));
    }
    seq.push("nf".to_string());
    seq.push("cm_out0".to_string());
    seq.push("cm_out1".to_string());

    let mut chains: std::collections::HashMap<String, Vec<(usize, String)>> =
        std::collections::HashMap::new();
    chains.insert("cm_in".into(), vec![(1, "owner".into())]);
    let mut prev = "cm_in".to_string();
    for j in 0..d {
        let name = format!("memb{j}");
        chains.insert(name.clone(), vec![(0, prev.clone())]);
        prev = name;
    }

    let mut blocks = Vec::new();
    let mut layout = Vec::new();
    let mut off = 0usize;
    for name in &seq {
        let (rc_rows, full_rows) = block_rc_full(n_blk);
        blocks.push(BlockMeta {
            name: name.clone(),
            offset: off,
            n: n_blk,
            chain: chains.get(name).cloned().unwrap_or_default(),
        });
        for r in 0..n_blk {
            if r == n_blk - 1 {
                layout.push(RowMeta {
                    block: name.clone(),
                    typ: "boundary".into(),
                    rc: [0u64; WIDTH],
                });
            } else {
                let typ = if full_rows[r] {
                    "round_full"
                } else {
                    "round_partial"
                };
                layout.push(RowMeta {
                    block: name.clone(),
                    typ: typ.into(),
                    rc: rc_rows[r],
                });
            }
        }
        off += n_blk;
    }
    let mut range_meta = Vec::new();
    for (vname, src) in [
        ("value_in", Some("cm_in")),
        ("value_out0", Some("cm_out0")),
        ("value_out1", Some("cm_out1")),
        ("fee", None),
    ] {
        let roff = off;
        for _ in 0..RANGE_BITS {
            layout.push(RowMeta {
                block: format!("range:{vname}"),
                typ: "range".into(),
                rc: [0u64; WIDTH],
            });
        }
        range_meta.push(RangeMeta {
            vname: vname.into(),
            offset: roff,
            n: RANGE_BITS,
            src: src.map(|s| s.into()),
        });
        off += RANGE_BITS;
    }
    let cons_row = off;
    layout.push(RowMeta {
        block: "cons".into(),
        typ: "cons".into(),
        rc: [0u64; WIDTH],
    });
    off += 1;
    let raw = off;
    let mut t = 1usize;
    while t < raw {
        t <<= 1;
    }
    for _ in 0..(t - raw) {
        layout.push(RowMeta {
            block: "_pad".into(),
            typ: "pad".into(),
            rc: [0u64; WIDTH],
        });
    }
    (
        Meta {
            rows: layout,
            blocks,
            range: range_meta,
            cons_row,
            raw,
        },
        t,
    )
}

pub type Cols = std::collections::HashMap<String, Vec<u64>>;

pub fn build_full_flat_trace(w: &Witness) -> (Cols, usize, Meta, Statement) {
    let (stmt, owner_pk, _cm_in) = compute_transfer(w);
    let d = w.siblings.len();
    let (meta, t) = ct_build_layout(d);

    // Build structured blocks
    let sk = w.sk % P;
    let owner = block(&[sk]);
    let nf = block(&[sk, w.rho_in, DOM_NF]);
    let cm_in_b = block(&[w.value_in, owner_pk, w.rho_in, w.blind_in]);
    let mut digest = cm_in_b.out;
    let mut memb = Vec::new();
    for sib in &w.siblings {
        let b = block(&[digest, *sib % P]);
        digest = b.out;
        memb.push(b);
    }
    let cm_out_b = [
        block(&[w.value_outs[0], w.owners_out[0], w.rhos_out[0], w.blinds_out[0]]),
        block(&[w.value_outs[1], w.owners_out[1], w.rhos_out[1], w.blinds_out[1]]),
    ];

    let mut cols: Cols = FLAT_COLS
        .iter()
        .map(|c| ((*c).to_string(), vec![0u64; t]))
        .collect();

    // Fill hash blocks from meta.blocks order
    let mut block_map: std::collections::HashMap<String, &Block> = std::collections::HashMap::new();
    block_map.insert("owner".into(), &owner);
    block_map.insert("cm_in".into(), &cm_in_b);
    block_map.insert("nf".into(), &nf);
    for (j, b) in memb.iter().enumerate() {
        block_map.insert(format!("memb{j}"), b);
    }
    block_map.insert("cm_out0".into(), &cm_out_b[0]);
    block_map.insert("cm_out1".into(), &cm_out_b[1]);

    for bm in &meta.blocks {
        let b = block_map[&bm.name];
        for r in 0..bm.n {
            let row = bm.offset + r;
            let st = b.states[r];
            for i in 0..WIDTH {
                cols.get_mut(&format!("s{i}")).unwrap()[row] = st[i];
            }
            if r < b.aux.len() {
                let ax = &b.aux[r];
                for i in 0..WIDTH {
                    cols.get_mut(&format!("u2_{i}")).unwrap()[row] = ax.x2[i];
                    cols.get_mut(&format!("u4_{i}")).unwrap()[row] = ax.x4[i];
                    cols.get_mut(&format!("u6_{i}")).unwrap()[row] = ax.x6[i];
                }
            }
        }
    }

    // Held values constant
    let held_vals = [
        ("vh_value_in", w.value_in),
        ("vh_value_out0", w.value_outs[0]),
        ("vh_value_out1", w.value_outs[1]),
        ("vh_fee", w.fee),
    ];
    for (c, v) in held_vals {
        for x in cols.get_mut(c).unwrap().iter_mut() {
            *x = v;
        }
    }

    // Range rows: bit decomposition into s0, accumulator s1, held link s2
    for rmv in &meta.range {
        let v = match rmv.vname.as_str() {
            "value_in" => w.value_in,
            "value_out0" => w.value_outs[0],
            "value_out1" => w.value_outs[1],
            "fee" => w.fee,
            _ => 0,
        };
        let mut acc = 0u64;
        for i in 0..RANGE_BITS {
            let bit = (v >> i) & 1;
            let row = rmv.offset + i;
            cols.get_mut("s0").unwrap()[row] = bit;
            acc = field::add(acc, field::mul(bit, 1u64 << i));
            cols.get_mut("s1").unwrap()[row] = acc;
            cols.get_mut("s2").unwrap()[row] = v;
        }
    }

    // conservation row: put held values already set
    (cols, t, meta, stmt)
}

#[cfg(test)]
mod pool_witness_tests {
    use super::*;

    /// Oracle statements from pool_prove.build_witness + compute_transfer (seed=1, depth=4).
    #[test]
    fn statement_matches_python_oracle_depth4() {
        // deposit
        let d = pool_witness("deposit", 4, 1);
        let (sd, _, _) = compute_transfer(&d);
        assert_eq!(sd.root, 881379245664449661);
        assert_eq!(sd.nf, 11154009705651292287);
        assert_eq!(sd.cm_out, [11477707993666098620, 7265027288646044627]);
        assert_eq!(sd.depth, 4);
        // transfer
        let t = pool_witness("transfer", 4, 1);
        let (st, _, _) = compute_transfer(&t);
        assert_eq!(st.root, 7532836036820049908);
        assert_eq!(st.nf, 13099292797636154673);
        assert_eq!(st.cm_out, [3284114210922206751, 12168423928671344501]);
        // withdrawal
        let w = pool_witness("withdrawal", 4, 1);
        let (sw, _, _) = compute_transfer(&w);
        assert_eq!(sw.root, 16237354410293146115);
        assert_eq!(sw.nf, 18086283948120588837);
        assert_eq!(sw.cm_out, [13118357680757942657, 15444401959088528816]);
    }
}

// ---- public layout selectors ----
pub struct PubLayout {
    pub is_full: Vec<u64>,
    pub is_partial: Vec<u64>,
    pub is_block_start: Vec<u64>,
    pub is_reabsorb: Vec<u64>,
    pub is_range: Vec<u64>,
    pub is_range_first: Vec<u64>,
    pub is_range_step: Vec<u64>,
    pub is_range_last: Vec<u64>,
    pub range_weight: Vec<u64>,
    pub rc: Vec<Vec<u64>>, // WIDTH x T
    pub chain_minv: Vec<Vec<u64>>, // WIDTH x T (stored as T rows of WIDTH)
}

pub fn ct_public_layout(meta: &Meta, t: usize) -> PubLayout {
    let mut lay = PubLayout {
        is_full: vec![0; t],
        is_partial: vec![0; t],
        is_block_start: vec![0; t],
        is_reabsorb: vec![0; t],
        is_range: vec![0; t],
        is_range_first: vec![0; t],
        is_range_step: vec![0; t],
        is_range_last: vec![0; t],
        range_weight: vec![0; t],
        rc: vec![vec![0; t]; WIDTH],
        chain_minv: vec![vec![0u64; WIDTH]; t],
    };
    for (r, row) in meta.rows.iter().enumerate() {
        match row.typ.as_str() {
            "round_full" => {
                lay.is_full[r] = 1;
                for k in 0..WIDTH {
                    lay.rc[k][r] = row.rc[k];
                }
            }
            "round_partial" => {
                lay.is_partial[r] = 1;
                for k in 0..WIDTH {
                    lay.rc[k][r] = row.rc[k];
                }
            }
            "range" => {
                lay.is_range[r] = 1;
            }
            _ => {}
        }
    }
    // block starts / reabsorb / chain_minv (Python ct_public_layout)
    let by_name: std::collections::HashMap<_, _> =
        meta.blocks.iter().map(|b| (b.name.clone(), b)).collect();
    for b in &meta.blocks {
        lay.is_block_start[b.offset] = 1;
        for (idx, src) in &b.chain {
            let s = by_name.get(src).expect("chain src");
            assert_eq!(s.offset + s.n, b.offset, "chain src not adjacent");
            let ra = b.offset - 1;
            lay.is_reabsorb[ra] = 1;
            // full M_EXT_INV row for absorb-lane idx
            for j in 0..WIDTH {
                lay.chain_minv[ra][j] = M_EXT_INV[*idx][j];
            }
            let _ = idx;
        }
    }
    for rmv in &meta.range {
        let off = rmv.offset;
        let n = rmv.n;
        for local in 0..n {
            let r = off + local;
            lay.is_range[r] = 1;
            lay.range_weight[r] = (1u64 << local) % P;
            if local == 0 {
                lay.is_range_first[r] = 1;
            }
            if local == n - 1 {
                lay.is_range_last[r] = 1;
            } else {
                lay.is_range_step[r] = 1;
            }
        }
    }
    lay
}

pub fn ct_num_transition_residuals() -> usize {
    4 * WIDTH + (WIDTH - RATE + 1) + HELD_COLS.len() + 5
}

fn col(cur: &std::collections::HashMap<String, u64>, name: &str) -> u64 {
    *cur.get(name).unwrap_or(&0)
}

/// Flat-column indices matching `FLAT_COLS` layout (s | u2 | u4 | u6 | held).
#[inline]
pub fn flat_s(k: usize) -> usize {
    k
}
#[inline]
pub fn flat_u2(k: usize) -> usize {
    WIDTH + k
}
#[inline]
pub fn flat_u4(k: usize) -> usize {
    2 * WIDTH + k
}
#[inline]
pub fn flat_u6(k: usize) -> usize {
    3 * WIDTH + k
}
pub const FLAT_VH_IN: usize = 4 * WIDTH;
pub const FLAT_VH_OUT0: usize = 4 * WIDTH + 1;
pub const FLAT_VH_OUT1: usize = 4 * WIDTH + 2;
pub const FLAT_VH_FEE: usize = 4 * WIDTH + 3;

/// Transition residuals over a stack row `[u64; N_FLAT]` (no HashMap allocs).
pub fn ct_transition_residuals_flat(
    cur: &[u64],
    nxt: &[u64],
    is_full: u64,
    is_partial: u64,
    rc: &[u64],
    is_block_start: u64,
    is_reabsorb: u64,
    chain_minv: &[u64],
    is_range: u64,
    is_range_first: u64,
    is_range_step: u64,
    is_range_last: u64,
    w_next: u64,
) -> Vec<u64> {
    debug_assert!(cur.len() >= N_FLAT && nxt.len() >= N_FLAT);
    let mut res = Vec::with_capacity(ct_num_transition_residuals());
    let isr = field::add(is_full, is_partial);
    let mut y_full = [0u64; WIDTH];
    let mut y_part = [0u64; WIDTH];
    for k in 0..WIDTH {
        let x = field::add(cur[flat_s(k)], rc[k]);
        let u2 = cur[flat_u2(k)];
        let u4 = cur[flat_u4(k)];
        let u6 = cur[flat_u6(k)];
        let gate = if k == 0 { isr } else { is_full };
        res.push(field::mul(gate, field::sub(u2, field::mul(x, x))));
        res.push(field::mul(gate, field::sub(u4, field::mul(u2, u2))));
        res.push(field::mul(gate, field::sub(u6, field::mul(u4, u2))));
        y_full[k] = field::mul(u6, x);
        y_part[k] = if k == 0 {
            field::mul(u6, x)
        } else {
            cur[flat_s(k)]
        };
    }
    let ef = matvec_mext(&y_full);
    let ip = {
        let s: u64 = y_part.iter().fold(0, |a, b| field::add(a, *b));
        let mut out = [0u64; WIDTH];
        for i in 0..WIDTH {
            out[i] = field::add(field::mul(y_part[i], MAT_DIAG12[i]), s);
        }
        out
    };
    for j in 0..WIDTH {
        let sj = nxt[flat_s(j)];
        res.push(field::add(
            field::mul(is_full, field::sub(sj, ef[j])),
            field::mul(is_partial, field::sub(sj, ip[j])),
        ));
    }
    for k in RATE..WIDTH {
        let mut cap = 0u64;
        for j in 0..WIDTH {
            cap = field::add(cap, field::mul(M_EXT_INV[k][j], cur[flat_s(j)]));
        }
        res.push(field::mul(is_block_start, cap));
    }
    let mut chained = 0u64;
    for j in 0..WIDTH {
        chained = field::add(chained, field::mul(chain_minv[j], nxt[flat_s(j)]));
    }
    res.push(field::mul(is_reabsorb, field::sub(chained, cur[flat_s(0)])));
    // held: indices 48..51
    for idx in FLAT_VH_IN..=FLAT_VH_FEE {
        res.push(field::sub(nxt[idx], cur[idx]));
    }
    let b = cur[flat_s(0)];
    res.push(field::mul(is_range, field::mul(b, field::sub(b, 1))));
    res.push(field::mul(is_range_first, field::sub(cur[flat_s(1)], b)));
    res.push(field::mul(
        is_range_step,
        field::sub(
            field::sub(nxt[flat_s(1)], cur[flat_s(1)]),
            field::mul(nxt[flat_s(0)], w_next),
        ),
    ));
    res.push(field::mul(
        is_range_step,
        field::sub(nxt[flat_s(2)], cur[flat_s(2)]),
    ));
    res.push(field::mul(
        is_range_last,
        field::sub(cur[flat_s(1)], cur[flat_s(2)]),
    ));
    res
}

pub fn ct_transition_residuals(
    cur: &std::collections::HashMap<String, u64>,
    nxt: &std::collections::HashMap<String, u64>,
    is_full: u64,
    is_partial: u64,
    rc: &[u64],
    is_block_start: u64,
    is_reabsorb: u64,
    chain_minv: &[u64],
    is_range: u64,
    is_range_first: u64,
    is_range_step: u64,
    is_range_last: u64,
    w_next: u64,
) -> Vec<u64> {
    let mut cf = [0u64; N_FLAT];
    let mut nf = [0u64; N_FLAT];
    for (i, name) in FLAT_COLS.iter().enumerate() {
        cf[i] = col(cur, name);
        nf[i] = col(nxt, name);
    }
    ct_transition_residuals_flat(
        &cf,
        &nf,
        is_full,
        is_partial,
        rc,
        is_block_start,
        is_reabsorb,
        chain_minv,
        is_range,
        is_range_first,
        is_range_step,
        is_range_last,
        w_next,
    )
}

fn matvec_mext(y: &[u64; WIDTH]) -> [u64; WIDTH] {
    let mut out = [0u64; WIDTH];
    for j in 0..WIDTH {
        let mut acc = 0u64;
        for k in 0..WIDTH {
            acc = field::add(acc, field::mul(M_EXT[j][k], y[k]));
        }
        out[j] = acc;
    }
    out
}

// GF(p^2) residual helpers (mirrors _*_ext)
fn e_col(cur: &std::collections::HashMap<String, Ext>, name: &str) -> Ext {
    *cur.get(name).unwrap_or(&gf2::ZERO)
}

pub fn ct_transition_residuals_ext(
    cur: &std::collections::HashMap<String, Ext>,
    nxt: &std::collections::HashMap<String, Ext>,
    is_full: Ext,
    is_partial: Ext,
    rc: &[Ext],
    is_block_start: Ext,
    is_reabsorb: Ext,
    chain_minv: &[Ext],
    is_range: Ext,
    is_range_first: Ext,
    is_range_step: Ext,
    is_range_last: Ext,
    w_next: Ext,
) -> Vec<Ext> {
    let mut res = Vec::with_capacity(ct_num_transition_residuals());
    let isr = gf2::add(is_full, is_partial);
    let mut y_full = [gf2::ZERO; WIDTH];
    let mut y_part = [gf2::ZERO; WIDTH];
    for k in 0..WIDTH {
        let x = gf2::add(e_col(cur, &format!("s{k}")), rc[k]);
        let u2 = e_col(cur, &format!("u2_{k}"));
        let u4 = e_col(cur, &format!("u4_{k}"));
        let u6 = e_col(cur, &format!("u6_{k}"));
        let gate = if k == 0 { isr } else { is_full };
        res.push(gf2::mul(gate, gf2::sub(u2, gf2::mul(x, x))));
        res.push(gf2::mul(gate, gf2::sub(u4, gf2::mul(u2, u2))));
        res.push(gf2::mul(gate, gf2::sub(u6, gf2::mul(u4, u2))));
        y_full[k] = gf2::mul(u6, x);
        y_part[k] = if k == 0 {
            gf2::mul(u6, x)
        } else {
            e_col(cur, &format!("s{k}"))
        };
    }
    let ef: Vec<Ext> = (0..WIDTH)
        .map(|j| {
            let mut acc = gf2::ZERO;
            for k in 0..WIDTH {
                acc = gf2::add(acc, gf2::scalar(M_EXT[j][k], y_full[k]));
            }
            acc
        })
        .collect();
    let mut ssum = gf2::ZERO;
    for e in &y_part {
        ssum = gf2::add(ssum, *e);
    }
    let ip: Vec<Ext> = (0..WIDTH)
        .map(|i| gf2::add(gf2::scalar(MAT_DIAG12[i], y_part[i]), ssum))
        .collect();
    for j in 0..WIDTH {
        let sj = e_col(nxt, &format!("s{j}"));
        res.push(gf2::add(
            gf2::mul(is_full, gf2::sub(sj, ef[j])),
            gf2::mul(is_partial, gf2::sub(sj, ip[j])),
        ));
    }
    for k in RATE..WIDTH {
        let mut cap = gf2::ZERO;
        for j in 0..WIDTH {
            cap = gf2::add(cap, gf2::scalar(M_EXT_INV[k][j], e_col(cur, &format!("s{j}"))));
        }
        res.push(gf2::mul(is_block_start, cap));
    }
    let mut chained = gf2::ZERO;
    for j in 0..WIDTH {
        chained = gf2::add(chained, gf2::mul(chain_minv[j], e_col(nxt, &format!("s{j}"))));
    }
    res.push(gf2::mul(is_reabsorb, gf2::sub(chained, e_col(cur, "s0"))));
    for c in &HELD_COLS {
        res.push(gf2::sub(e_col(nxt, c), e_col(cur, c)));
    }
    let b = e_col(cur, "s0");
    res.push(gf2::mul(is_range, gf2::mul(b, gf2::sub(b, gf2::ONE))));
    res.push(gf2::mul(is_range_first, gf2::sub(e_col(cur, "s1"), b)));
    res.push(gf2::mul(
        is_range_step,
        gf2::sub(
            gf2::sub(e_col(nxt, "s1"), e_col(cur, "s1")),
            gf2::mul(e_col(nxt, "s0"), w_next),
        ),
    ));
    res.push(gf2::mul(is_range_step, gf2::sub(e_col(nxt, "s2"), e_col(cur, "s2"))));
    res.push(gf2::mul(is_range_last, gf2::sub(e_col(cur, "s1"), e_col(cur, "s2"))));
    res
}

pub fn boundary_rows_and_values(meta: &Meta, stmt: &Statement) -> Vec<(usize, u64, String)> {
    // Returns (row, expected_value_or_tag, kind) simplified for base compose:
    // We evaluate residual via closures differently in prove.
    let mut out = Vec::new();
    let bm: std::collections::HashMap<_, _> =
        meta.blocks.iter().map(|b| (b.name.clone(), b)).collect();
    let final_memb = meta
        .blocks
        .iter()
        .rev()
        .find(|b| b.name.starts_with("memb"))
        .map(|b| b.name.clone())
        .unwrap_or_else(|| "cm_in".into());
    let out_row = |name: &str| {
        let b = bm.get(name).unwrap();
        b.offset + b.n - 1
    };
    out.push((out_row(&final_memb), stmt.root, "root".into()));
    out.push((out_row("nf"), stmt.nf, "nf".into()));
    out.push((out_row("cm_out0"), stmt.cm_out[0], "cm0".into()));
    out.push((out_row("cm_out1"), stmt.cm_out[1], "cm1".into()));
    for rmv in &meta.range {
        // link residual at range offset: vh - s2
        out.push((rmv.offset, 0, format!("link:{}", rmv.vname)));
        if rmv.src.is_some() {
            let off = bm[rmv.src.as_ref().unwrap()].offset;
            out.push((off, 0, format!("cmbind:{}", rmv.vname)));
        }
    }
    out.push((meta.cons_row, 0, "cons".into()));
    out
}

/// HP4.2: boundary residuals over GF(p^2) at OOD cur (same order as base `make_bcons` / pool_prove).
pub fn ct_boundary_residuals_ext(
    meta: &Meta,
    stmt: &Statement,
    cur: &std::collections::HashMap<String, Ext>,
) -> Vec<(usize, Ext)> {
    let bm: std::collections::HashMap<_, _> =
        meta.blocks.iter().map(|b| (b.name.clone(), b.clone())).collect();
    let final_memb = meta
        .blocks
        .iter()
        .rev()
        .find(|b| b.name.starts_with("memb"))
        .map(|b| b.name.clone())
        .unwrap_or_else(|| "cm_in".into());
    let out_row = |name: &str| {
        let b = &bm[name];
        b.offset + b.n - 1
    };
    let mut cons = Vec::new();
    cons.push((
        out_row(&final_memb),
        gf2::sub(e_col(cur, "s0"), gf2::from_base(stmt.root)),
    ));
    cons.push((
        out_row("nf"),
        gf2::sub(e_col(cur, "s0"), gf2::from_base(stmt.nf)),
    ));
    cons.push((
        out_row("cm_out0"),
        gf2::sub(e_col(cur, "s0"), gf2::from_base(stmt.cm_out[0])),
    ));
    cons.push((
        out_row("cm_out1"),
        gf2::sub(e_col(cur, "s0"), gf2::from_base(stmt.cm_out[1])),
    ));
    for rmv in &meta.range {
        let hc = format!("vh_{}", rmv.vname);
        cons.push((
            rmv.offset,
            gf2::sub(e_col(cur, &hc), e_col(cur, "s2")),
        ));
        if let Some(src) = &rmv.src {
            let off = bm[src].offset;
            let mut s = gf2::ZERO;
            for j in 0..WIDTH {
                s = gf2::add(s, gf2::scalar(M_EXT_INV[0][j], e_col(cur, &format!("s{j}"))));
            }
            cons.push((off, gf2::sub(e_col(cur, &hc), s)));
        }
    }
    cons.push((
        meta.cons_row,
        gf2::sub(
            e_col(cur, "vh_value_in"),
            gf2::add(
                gf2::add(e_col(cur, "vh_value_out0"), e_col(cur, "vh_value_out1")),
                e_col(cur, "vh_fee"),
            ),
        ),
    ));
    cons
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout_depth4() {
        let (_, t) = ct_build_layout(4);
        assert_eq!(t, 1024);
    }
    #[test]
    fn kat_hash_chain() {
        let w = demo_witness(2, 12345);
        let (stmt, _, _) = compute_transfer(&w);
        assert!(stmt.root != 0);
    }
}
