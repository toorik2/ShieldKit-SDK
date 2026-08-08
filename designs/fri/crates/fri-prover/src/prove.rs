//! DEEP-ALI FRI-STARK prove/verify for CT-AIR (port of native_ct_air_stark).
use crate::air::{
    self, ct_num_transition_residuals, ct_public_layout, ct_transition_residuals_flat,
    ct_transition_residuals_ext, ct_boundary_residuals_ext, build_full_flat_trace, Witness,
    Statement, Meta, PubLayout, HELD_COLS, FLAT_VH_IN, FLAT_VH_OUT0, FLAT_VH_OUT1, FLAT_VH_FEE,
};
use crate::poseidon2::{WIDTH, RATE};
use crate::flat_cols::{FLAT_COLS, N_FLAT};
use crate::field::{self, P, find_gen, root, enc};
use crate::fs::{grind_seq,self, Fs, grind, ext_challenge};
use crate::gf2::{self, Ext};
use crate::merkle::{
    self, Tree, leaf_base, leaf_ext, leaf_ext_coset, merkle, m_root, m_path, m_verify,
};
use crate::ntt::{intt, lde_coset, lde_coset_batch};
use crate::air_matrices::M_EXT_INV;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

pub const CFG_BLOWUP: u64 = 2048;
pub const CFG_QUERIES: usize = 8;
pub const CFG_GRIND: u32 = 24;
pub const CFG_FOLD: usize = 8; // fold arity; pool_prove uses fold_step=3 (2^3)
pub const MASK_DEG: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriParams {
    pub blowup: u64,
    pub queries: usize,
    pub grind_bits: u32,
    pub fold_step: usize,
    pub mask_deg: usize,
    pub deep: bool,
}

impl Default for FriParams {
    fn default() -> Self {
        Self {
            blowup: CFG_BLOWUP,
            queries: CFG_QUERIES,
            grind_bits: CFG_GRIND,
            fold_step: 3,
            mask_deg: MASK_DEG,
            deep: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProveResult {
    pub statement: StatementDto,
    pub prove_seconds: f64,
    pub peak_rss_bytes: u64,
    pub verify_ok: bool,
    pub proof_blob_sha256: String,
    pub proof: serde_json::Value,
    pub engine: String,
    pub mask_seed: Option<u64>,
    pub witness_seed: u64,
    pub mask_source: Option<String>,
    pub depth: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatementDto {
    pub root: u64,
    pub nf: u64,
    pub cm_out: [u64; 2],
    pub depth: usize,
    pub kind: String,
}

fn peak_rss() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:") {
                    let kb: u64 = rest.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
                    return kb * 1024;
                }
            }
        }
    }
    0
}

fn setup(t: usize, blowup: u64) -> (usize, u64, u64, u64, Vec<u64>, Vec<u64>, u64) {
    let n = (blowup as usize) * t;
    let ot = root(t as u64);
    let on = root(n as u64);
    let off = find_gen();
    let hd: Vec<u64> = (0..t as u64).map(|i| field::mod_pow(ot, i)).collect();
    let dd: Vec<u64> = (0..n as u64)
        .map(|i| field::mul(off, field::mod_pow(on, i)))
        .collect();
    let last = hd[t - 1];
    (n, ot, on, off, hd, dd, last)
}

fn ood_horner(coeffs: &[u64], z: Ext) -> Ext {
    let mut acc = gf2::ZERO;
    for &c in coeffs.iter().rev() {
        acc = gf2::add(gf2::mul(z, acc), gf2::from_base(c));
    }
    acc
}

fn ood_public_at(h_vals: &[u64], t: usize, ot: u64, z: Ext) -> Ext {
    let coeffs = intt(h_vals, ot);
    ood_horner(&coeffs, z)
}

fn ood_trace_at(h_vals: &[u64], mask_r: &[u64], t: usize, ot: u64, z: Ext) -> Ext {
    let mut coeffs = intt(h_vals, ot);
    coeffs.resize(t + mask_r.len(), 0);
    for k in 0..mask_r.len() {
        coeffs[k] = field::sub(coeffs[k], mask_r[k]);
        coeffs[t + k] = field::add(coeffs[t + k], mask_r[k]);
    }
    ood_horner(&coeffs, z)
}

fn row_flat(col_slices: &[&[u64]], i: usize) -> [u64; N_FLAT] {
    let mut r = [0u64; N_FLAT];
    for j in 0..N_FLAT {
        r[j] = col_slices[j][i];
    }
    r
}

fn compose_at_flat(
    cur: &[u64; N_FLAT],
    nxt: &[u64; N_FLAT],
    x: u64,
    w_next: u64,
    last: u64,
    zhx_inv: u64,
    hd: &[u64],
    pub_x: &PubAt,
    alphas_t: &[Ext],
    bcons: &[(usize, Box<dyn Fn(&[u64; N_FLAT]) -> u64 + Send + Sync>)],
    alphas_b: &[Ext],
) -> Ext {
    let xl = field::sub(x, last);
    let mut acc = gf2::ZERO;
    let tres = ct_transition_residuals_flat(
        cur,
        nxt,
        pub_x.is_full,
        pub_x.is_partial,
        &pub_x.rc,
        pub_x.is_block_start,
        pub_x.is_reabsorb,
        &pub_x.chain_minv,
        pub_x.is_range,
        pub_x.is_range_first,
        pub_x.is_range_step,
        pub_x.is_range_last,
        w_next,
    );
    for (a, v) in alphas_t.iter().zip(tres.iter()) {
        let q = field::mul(field::mul(*v, xl), zhx_inv);
        acc = gf2::add(acc, gf2::scalar(q, *a));
    }
    for ((row, fnc), a) in bcons.iter().zip(alphas_b.iter()) {
        let v = fnc(cur);
        let den = field::inv(field::sub(x, hd[*row]));
        acc = gf2::add(acc, gf2::scalar(field::mul(v, den), *a));
    }
    acc
}

struct PubAt {
    is_full: u64,
    is_partial: u64,
    rc: [u64; WIDTH],
    is_block_start: u64,
    is_reabsorb: u64,
    chain_minv: [u64; WIDTH],
    is_range: u64,
    is_range_first: u64,
    is_range_step: u64,
    is_range_last: u64,
}

struct SelLde {
    is_full: Vec<u64>,
    is_partial: Vec<u64>,
    is_block_start: Vec<u64>,
    is_reabsorb: Vec<u64>,
    is_range: Vec<u64>,
    is_range_first: Vec<u64>,
    is_range_step: Vec<u64>,
    is_range_last: Vec<u64>,
    range_weight: Vec<u64>,
    rc: Vec<Vec<u64>>,
    chain_minv: Vec<Vec<u64>>, // WIDTH x N
}

fn selector_lde(lay: &PubLayout, t: usize, n: usize, ot: u64, on: u64, off: u64) -> SelLde {
    let lde = |v: &[u64]| lde_coset(v, t, n, ot, on, off, None);
    let mut rc = Vec::new();
    for k in 0..WIDTH {
        rc.push(lde(&lay.rc[k]));
    }
    let mut chain_minv = Vec::new();
    for j in 0..WIDTH {
        let colj: Vec<u64> = (0..t).map(|r| lay.chain_minv[r][j]).collect();
        chain_minv.push(lde(&colj));
    }
    SelLde {
        is_full: lde(&lay.is_full),
        is_partial: lde(&lay.is_partial),
        is_block_start: lde(&lay.is_block_start),
        is_reabsorb: lde(&lay.is_reabsorb),
        is_range: lde(&lay.is_range),
        is_range_first: lde(&lay.is_range_first),
        is_range_step: lde(&lay.is_range_step),
        is_range_last: lde(&lay.is_range_last),
        range_weight: lde(&lay.range_weight),
        rc,
        chain_minv,
    }
}

fn pub_at_sv(sv: &SelLde, i: usize) -> PubAt {
    let mut rc = [0u64; WIDTH];
    for k in 0..WIDTH {
        rc[k] = sv.rc[k][i];
    }
    let mut chain_minv = [0u64; WIDTH];
    for k in 0..WIDTH {
        chain_minv[k] = sv.chain_minv[k][i];
    }
    PubAt {
        is_full: sv.is_full[i],
        is_partial: sv.is_partial[i],
        rc,
        is_block_start: sv.is_block_start[i],
        is_reabsorb: sv.is_reabsorb[i],
        chain_minv,
        is_range: sv.is_range[i],
        is_range_first: sv.is_range_first[i],
        is_range_step: sv.is_range_step[i],
        is_range_last: sv.is_range_last[i],
    }
}

fn vh_flat_idx(vname: &str) -> usize {
    match vname {
        "value_in" => FLAT_VH_IN,
        "value_out0" => FLAT_VH_OUT0,
        "value_out1" => FLAT_VH_OUT1,
        "fee" => FLAT_VH_FEE,
        _ => FLAT_VH_IN,
    }
}

fn make_bcons(
    meta: &Meta,
    stmt: &Statement,
) -> Vec<(usize, Box<dyn Fn(&[u64; N_FLAT]) -> u64 + Send + Sync>)> {
    let bm: HashMap<_, _> = meta.blocks.iter().map(|b| (b.name.clone(), b.clone())).collect();
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
    let mut cons: Vec<(usize, Box<dyn Fn(&[u64; N_FLAT]) -> u64 + Send + Sync>)> = Vec::new();
    let root = stmt.root;
    let nf = stmt.nf;
    let cm0 = stmt.cm_out[0];
    let cm1 = stmt.cm_out[1];
    cons.push((
        out_row(&final_memb),
        Box::new(move |cur| field::sub(cur[0], root)),
    ));
    cons.push((out_row("nf"), Box::new(move |cur| field::sub(cur[0], nf))));
    cons.push((
        out_row("cm_out0"),
        Box::new(move |cur| field::sub(cur[0], cm0)),
    ));
    cons.push((
        out_row("cm_out1"),
        Box::new(move |cur| field::sub(cur[0], cm1)),
    ));
    for rmv in &meta.range {
        let hi = vh_flat_idx(&rmv.vname);
        cons.push((
            rmv.offset,
            Box::new(move |cur| field::sub(cur[hi], cur[2])),
        ));
        if let Some(src) = &rmv.src {
            let off = bm[src].offset;
            cons.push((
                off,
                Box::new(move |cur| {
                    let mut s = 0u64;
                    for j in 0..WIDTH {
                        s = field::add(s, field::mul(M_EXT_INV[0][j], cur[j]));
                    }
                    field::sub(cur[hi], s)
                }),
            ));
        }
    }
    cons.push((
        meta.cons_row,
        Box::new(move |cur| {
            field::sub(
                cur[FLAT_VH_IN],
                field::add(
                    field::add(cur[FLAT_VH_OUT0], cur[FLAT_VH_OUT1]),
                    cur[FLAT_VH_FEE],
                ),
            )
        }),
    ));
    cons
}

/// Prove CT-AIR witness. `seed` makes deterministic ZK masks (test/oracle).
/// `mask_seed`: `Some(seed)` -> deterministic ZK masks (test/oracle, byte-reproducible);
/// `None` -> ZK mask + Merkle salts drawn from a CSPRNG (rand::thread_rng, OS-seeded;
/// 128-bit effective entropy via two interleaved SplitMix64 streams) — the PRODUCTION path.
pub fn prove(w: &Witness, params: &FriParams, mask_seed: Option<u64>, kind: &str) -> ProveResult {
    let t0 = Instant::now();
    let rss0 = peak_rss();
    let (cols, t, meta, stmt) = build_full_flat_trace(w);
    let (n, ot, on, off, hd, dd, last) = setup(t, params.blowup);
    let lay = ct_public_layout(&meta, t);
    let mut rng = RngSource::new(mask_seed);

    // LDE + masks
    let col_names: Vec<String> = FLAT_COLS.iter().map(|s| (*s).to_string()).collect();
    let h_cols: Vec<Vec<u64>> = col_names.iter().map(|c| cols[c].clone()).collect();
    let mut masks: Vec<Vec<u64>> = (0..col_names.len())
        .map(|_| (0..params.mask_deg).map(|_| rng.next_u64() % P).collect())
        .collect();
    let mut colvals_vec = lde_coset_batch(&h_cols, t, n, ot, on, off, &masks);
    // Drop pre-LDE column clones promptly (peak RSS path).
    drop(h_cols);
    let mut colvals: HashMap<String, Vec<u64>> = HashMap::with_capacity(col_names.len());
    let mut mask_rs: HashMap<String, Vec<u64>> = HashMap::with_capacity(col_names.len());
    for (i, c) in col_names.iter().enumerate() {
        colvals.insert(c.clone(), std::mem::take(&mut colvals_vec[i]));
        mask_rs.insert(c.clone(), std::mem::take(&mut masks[i]));
    }
    drop(colvals_vec);
    drop(masks);
    // Flat salt buffer (n×16): avoids 4.2M Vec headers (~100–150 MiB).
    let mut salts = vec![0u8; n * 16];
    for i in 0..n {
        for b in 0..16 {
            salts[i * 16 + b] = (rng.next_u64() & 0xff) as u8;
        }
    }
    let leaves: Vec<merkle::Hash> = (0..n)
        .map(|i| {
            let vals: Vec<u64> = col_names.iter().map(|c| colvals[c][i]).collect();
            leaf_base(&vals, &salts[i * 16..i * 16 + 16])
        })
        .collect();
    let tree = merkle(leaves);

    let mut fs = Fs::new();
    fs.absorb(m_root(&tree));
    fs.absorb_int(stmt.root);
    fs.absorb_int(stmt.nf);
    fs.absorb_int(stmt.cm_out[0]);
    fs.absorb_int(stmt.cm_out[1]);
    let n_t = ct_num_transition_residuals();
    let bcons = make_bcons(&meta, &stmt);
    let alphas_t: Vec<Ext> = (0..n_t).map(|_| ext_challenge(&mut fs)).collect();
    let alphas_b: Vec<Ext> = (0..bcons.len()).map(|_| ext_challenge(&mut fs)).collect();

    let shift = n / t;
    let sv = selector_lde(&lay, t, n, ot, on, off);
    // Flat column slices for stack-row composition (no per-row HashMap allocs).
    let col_slices: Vec<&[u64]> = FLAT_COLS
        .iter()
        .map(|c| colvals[*c].as_slice())
        .collect();
    let comp: Vec<Ext> = (0..n)
        .into_par_iter()
        .map(|i| {
            let x = dd[i];
            let inx = (i + shift) % n;
            let cur = row_flat(&col_slices, i);
            let nxt = row_flat(&col_slices, inx);
            let pub_x = pub_at_sv(&sv, i);
            let w_next = sv.range_weight[inx];
            let zhx_inv = field::inv(field::sub(field::mod_pow(x, t as u64), 1));
            compose_at_flat(
                &cur, &nxt, x, w_next, last, zhx_inv, &hd, &pub_x, &alphas_t, &bcons, &alphas_b,
            )
        })
        .collect();

    // DEEP path (required for production). Reuse selector LDEs in `sv` — do not re-LDE.
    let mut q: Vec<Ext> = if params.deep {
        vec![gf2::ZERO; n]
    } else {
        comp.clone()
    };
    let mut deep_json = serde_json::Map::new();
    // Keep composition Merkle tree through query emission (cp paths required by DEEP verify).
    let mut comp_tree_opt: Option<Tree> = None;
    if params.deep {
        let comp_leaves: Vec<merkle::Hash> = (0..n)
            .map(|i| leaf_ext(comp[i], &[0u8; 16]))
            .collect();
        let comp_tree = merkle(comp_leaves);
        fs.absorb(m_root(&comp_tree));
        comp_tree_opt = Some(comp_tree);
        let mut z = ext_challenge(&mut fs);
        if z.1 % P == 0 {
            z = (z.0, 1);
        }
        let zg = gf2::scalar(ot, z);
        let pcz: HashMap<String, Ext> = col_names
            .iter()
            .map(|c| {
                (
                    c.clone(),
                    ood_trace_at(&cols[c], &mask_rs[c], t, ot, z),
                )
            })
            .collect();
        let pczg: HashMap<String, Ext> = col_names
            .iter()
            .map(|c| {
                (
                    c.clone(),
                    ood_trace_at(&cols[c], &mask_rs[c], t, ot, zg),
                )
            })
            .collect();
        // Trace H-domain columns no longer needed after OOD opens.
        drop(mask_rs);
        drop(cols);
        let rw_zg = ood_public_at(&lay.range_weight, t, ot, zg);
        // Public selectors at z (verifier recomputes these; absorb before deep_alphas).
        let isf = ood_public_at(&lay.is_full, t, ot, z);
        let isp = ood_public_at(&lay.is_partial, t, ot, z);
        let isbs = ood_public_at(&lay.is_block_start, t, ot, z);
        let isra = ood_public_at(&lay.is_reabsorb, t, ot, z);
        let isr = ood_public_at(&lay.is_range, t, ot, z);
        let isrf = ood_public_at(&lay.is_range_first, t, ot, z);
        let isrs = ood_public_at(&lay.is_range_step, t, ot, z);
        let isrl = ood_public_at(&lay.is_range_last, t, ot, z);
        let mut rc_e = [gf2::ZERO; WIDTH];
        for k in 0..WIDTH {
            rc_e[k] = ood_public_at(&lay.rc[k], t, ot, z);
        }
        let mut chain_e = [gf2::ZERO; WIDTH];
        for j in 0..WIDTH {
            let colj: Vec<u64> = (0..t).map(|r| lay.chain_minv[r][j]).collect();
            chain_e[j] = ood_public_at(&colj, t, ot, z);
        }
        // Full DEEP AIR-eval-once at z: transitions + boundary OOD residuals.
        let zhz_inv = gf2::inv(gf2::sub(gf2::power(z, t as u64), gf2::ONE));
        let tres = ct_transition_residuals_ext(
            &pcz, &pczg, isf, isp, &rc_e, isbs, isra, &chain_e, isr, isrf, isrs, isrl, rw_zg,
        );
        let zl = gf2::sub(z, gf2::from_base(last));
        let mut comp_z = gf2::ZERO;
        for (a, v) in alphas_t.iter().zip(tres.iter()) {
            comp_z = gf2::add(comp_z, gf2::mul(gf2::mul(gf2::mul(*v, zl), zhz_inv), *a));
        }
        let bcons_ext = ct_boundary_residuals_ext(&meta, &stmt, &pcz);
        for ((row, residual), a) in bcons_ext.iter().zip(alphas_b.iter()) {
            let den = gf2::inv(gf2::sub(z, gf2::from_base(hd[*row])));
            comp_z = gf2::add(comp_z, gf2::mul(gf2::mul(*residual, den), *a));
        }
        let _ = &bcons;
        // HP5.3 absorb order matches pool_prove / native_ct_air_stark.
        for c in &col_names {
            fs.absorb_int(pcz[c].0);
            fs.absorb_int(pcz[c].1);
            fs.absorb_int(pczg[c].0);
            fs.absorb_int(pczg[c].1);
        }
        let sel_masks: Vec<Ext> = {
            let mut v = vec![isf, isp, isbs, isra, isr, isrf, isrs, isrl];
            v.extend_from_slice(&rc_e);
            v.extend_from_slice(&chain_e);
            v
        };
        for m in &sel_masks {
            fs.absorb_int(m.0);
            fs.absorb_int(m.1);
        }
        fs.absorb_int(rw_zg.0);
        fs.absorb_int(rw_zg.1);
        fs.absorb_int(comp_z.0);
        fs.absorb_int(comp_z.1);
        let n_terms = 2 * col_names.len() + sel_masks.len() + 2;
        let deep_alphas: Vec<Ext> = (0..n_terms).map(|_| ext_challenge(&mut fs)).collect();
        // Build q: (col_z, col_zg)*ncols then selector@z, range_weight@zg, comp@z.
        // Apply z-side then zg-side so only one inv[] lives at a time.
        let mut ai = 0usize;
        let mut add_term = |q: &mut [Ext],
                            dvals: &[u64],
                            mask: Ext,
                            inv_arr: &[Ext],
                            a: Ext,
                            is_ext: bool,
                            ext_vals: Option<&[Ext]>| {
            for j in 0..n {
                let dv = if is_ext {
                    ext_vals.unwrap()[j]
                } else {
                    gf2::from_base(dvals[j])
                };
                q[j] = gf2::add(q[j], gf2::mul(a, gf2::mul(gf2::sub(dv, mask), inv_arr[j])));
            }
        };
        let inv_z: Vec<Ext> = (0..n)
            .into_par_iter()
            .map(|j| gf2::inv(gf2::sub(gf2::from_base(dd[j]), z)))
            .collect();
        let mut pending_zg: Vec<(&str, Ext, Ext)> = Vec::with_capacity(col_names.len());
        for c in &col_names {
            let a_z = deep_alphas[ai];
            ai += 1;
            add_term(&mut q, &colvals[c], pcz[c], &inv_z, a_z, false, None);
            let a_zg = deep_alphas[ai];
            ai += 1;
            pending_zg.push((c.as_str(), pczg[c], a_zg));
        }
        let sel_lde_pairs: Vec<(&[u64], Ext)> = {
            let mut v: Vec<(&[u64], Ext)> = vec![
                (&sv.is_full, isf),
                (&sv.is_partial, isp),
                (&sv.is_block_start, isbs),
                (&sv.is_reabsorb, isra),
                (&sv.is_range, isr),
                (&sv.is_range_first, isrf),
                (&sv.is_range_step, isrs),
                (&sv.is_range_last, isrl),
            ];
            for k in 0..WIDTH {
                v.push((&sv.rc[k], rc_e[k]));
            }
            for j in 0..WIDTH {
                v.push((&sv.chain_minv[j], chain_e[j]));
            }
            v
        };
        for (dvals, m) in &sel_lde_pairs {
            let a = deep_alphas[ai];
            ai += 1;
            add_term(&mut q, dvals, *m, &inv_z, a, false, None);
        }
        let a_rw = deep_alphas[ai];
        ai += 1;
        let a_comp = deep_alphas[ai];
        ai += 1;
        add_term(&mut q, &[], comp_z, &inv_z, a_comp, true, Some(&comp));
        drop(inv_z);

        let inv_zg: Vec<Ext> = (0..n)
            .into_par_iter()
            .map(|j| gf2::inv(gf2::sub(gf2::from_base(dd[j]), zg)))
            .collect();
        for (c, mask, a) in pending_zg {
            add_term(&mut q, &colvals[c], mask, &inv_zg, a, false, None);
        }
        add_term(&mut q, &sv.range_weight, rw_zg, &inv_zg, a_rw, false, None);
        drop(inv_zg);
        let _ = ai;

        deep_json.insert(
            "comp_root".into(),
            serde_json::json!(hex::encode(m_root(comp_tree_opt.as_ref().unwrap()))),
        );
        deep_json.insert("z".into(), serde_json::json!([z.0, z.1]));
        deep_json.insert("zg".into(), serde_json::json!([zg.0, zg.1]));
        deep_json.insert("comp_z".into(), serde_json::json!([comp_z.0, comp_z.1]));
        deep_json.insert("rw_zg".into(), serde_json::json!([rw_zg.0, rw_zg.1]));
        deep_json.insert(
            "deep_alphas".into(),
            serde_json::json!(deep_alphas.iter().map(|a| [a.0, a.1]).collect::<Vec<_>>()),
        );
        deep_json.insert(
            "sel_z".into(),
            serde_json::json!(sel_masks.iter().map(|m| [m.0, m.1]).collect::<Vec<_>>()),
        );
        let mut pcz_json = serde_json::Map::new();
        let mut pczg_json = serde_json::Map::new();
        for c in &col_names {
            pcz_json.insert(c.clone(), serde_json::json!([pcz[c].0, pcz[c].1]));
            pczg_json.insert(c.clone(), serde_json::json!([pczg[c].0, pczg[c].1]));
        }
        deep_json.insert("Pcz".into(), serde_json::Value::Object(pcz_json));
        deep_json.insert("Pczg".into(), serde_json::Value::Object(pczg_json));
    }
    // Selectors only needed through DEEP quotient construction.
    drop(sv);

    // FRI: fold_step=1 classic; fold_step>=2 ethSTARK layer-skip (production fold_step=3).
    let fold_step = if params.fold_step == 0 { 1 } else { params.fold_step };
    let mut fri_layers: Vec<Vec<Ext>> = Vec::new(); // fold-2 path layers
    let mut fri_trees: Vec<Tree> = Vec::new();
    let mut fri_rounds: Vec<(usize, usize, Vec<Ext>)> = Vec::new(); // (li0, s, layer) fold-8
    let mut vals = q;
    let mut dom = dd;
    let mut betas: Vec<Ext> = Vec::new();
    fs.absorb(b"fri");
    let inv2 = field::inv(2);
    let final_layer: Vec<Ext>;
    if fold_step == 1 {
        loop {
            let leaves: Vec<merkle::Hash> = vals.iter().map(|v| leaf_ext(*v, &[0u8; 16])).collect();
            let tr = merkle(leaves);
            fri_trees.push(tr);
            fs.absorb(m_root(fri_trees.last().unwrap()));
            if vals.len() <= 8 {
                fri_layers.push(vals);
                break;
            }
            let beta = ext_challenge(&mut fs);
            betas.push(beta);
            let half = vals.len() / 2;
            let mut nv = vec![gf2::ZERO; half];
            for j in 0..half {
                let x = dom[j];
                let fp = vals[j];
                let fm = vals[j + half];
                let i2x = field::inv(field::mul(2, x));
                nv[j] = gf2::add(
                    gf2::scalar(inv2, gf2::add(fp, fm)),
                    gf2::mul(beta, gf2::scalar(i2x, gf2::sub(fp, fm))),
                );
            }
            fri_layers.push(vals);
            vals = nv;
            for j in 0..half {
                dom[j] = field::mul(dom[j], dom[j]);
            }
            dom.truncate(half);
        }
        final_layer = fri_layers.last().unwrap().clone();
    } else {
        // fold-by-2^s layer-skipping (ethSTARK 3.11.1)
        let mut li0 = 0usize;
        loop {
            let s = fri_folds_to_final(vals.len()).min(fold_step);
            if s == 0 {
                let leaves: Vec<merkle::Hash> =
                    vals.iter().map(|v| leaf_ext(*v, &[0u8; 16])).collect();
                let tr = merkle(leaves);
                fri_trees.push(tr);
                fs.absorb(m_root(fri_trees.last().unwrap()));
                fri_rounds.push((li0, 0, vals.clone()));
                final_layer = vals;
                break;
            }
            let stride = vals.len() >> s;
            let leaves: Vec<merkle::Hash> = (0..stride)
                .map(|base| {
                    let coset: Vec<Ext> = (0..(1usize << s))
                        .map(|m| vals[base + m * stride])
                        .collect();
                    leaf_ext_coset(&coset, &[0u8; 16])
                })
                .collect();
            let tr = merkle(leaves);
            fri_trees.push(tr);
            fs.absorb(m_root(fri_trees.last().unwrap()));
            fri_rounds.push((li0, s, vals.clone()));
            for _ in 0..s {
                let beta = ext_challenge(&mut fs);
                betas.push(beta);
                let half = vals.len() / 2;
                let mut nv = vec![gf2::ZERO; half];
                for j in 0..half {
                    let x = dom[j];
                    let fp = vals[j];
                    let fm = vals[j + half];
                    let i2x = field::inv(field::mul(2, x));
                    nv[j] = gf2::add(
                        gf2::scalar(inv2, gf2::add(fp, fm)),
                        gf2::mul(beta, gf2::scalar(i2x, gf2::sub(fp, fm))),
                    );
                }
                vals = nv;
                for j in 0..half {
                    dom[j] = field::mul(dom[j], dom[j]);
                }
                dom.truncate(half);
            }
            li0 += s;
        }
    }
    let nonce = if mask_seed.is_some() {
            // Deterministic (test/oracle) mode: canonical smallest nonce -> byte-reproducible.
            grind_seq(&fs.s, params.grind_bits)
        } else {
            // Production (random-mask) mode: parallel PoW grind (SLA path); the winning
            // nonce is a valid PoW solution (v < 2^(64-bits)) — nondeterministic is fine.
            grind(&fs.s, params.grind_bits)
        };
    fs.absorb(&nonce);
    let idxs: Vec<usize> = (0..params.queries).map(|_| fs.challenge_idx(n)).collect();
    let mut queries = Vec::new();
    for &k in &idxs {
        let mut op = serde_json::json!({
            "k": k,
            "ck": col_names.iter().map(|c| (c.clone(), colvals[c][k])).collect::<HashMap<_,_>>(),
            "sk": hex::encode(&salts[k * 16..k * 16 + 16]),
            "pk": m_path(&tree, k).iter().map(|(s,b)| (hex::encode(s), b)).collect::<Vec<_>>(),
            "fri": []
        });
        if params.deep {
            op["cc"] = serde_json::json!([comp[k].0, comp[k].1]);
            let ct = comp_tree_opt
                .as_ref()
                .expect("comp_tree required for DEEP query openings");
            op["cp"] = serde_json::json!(
                m_path(ct, k)
                    .iter()
                    .map(|(s, b)| (hex::encode(s), b))
                    .collect::<Vec<_>>()
            );
        }
        let mut fri_ops = Vec::new();
        let mut ci = k;
        if fold_step == 1 {
            for li in 0..fri_layers.len().saturating_sub(1) {
                let half = fri_layers[li].len() / 2;
                let ii = ci % half;
                fri_ops.push(serde_json::json!({
                    "v": [fri_layers[li][ii].0, fri_layers[li][ii].1],
                    "vp": m_path(&fri_trees[li], ii).iter().map(|(s,b)| (hex::encode(s), b)).collect::<Vec<_>>(),
                    "w": [fri_layers[li][ii+half].0, fri_layers[li][ii+half].1],
                    "wp": m_path(&fri_trees[li], ii+half).iter().map(|(s,b)| (hex::encode(s), b)).collect::<Vec<_>>(),
                }));
                ci = ii;
            }
        } else {
            for (ridx, &(_li0, s, ref layer)) in fri_rounds.iter().enumerate() {
                if s == 0 {
                    break;
                }
                let stride = layer.len() >> s;
                let base = ci % stride;
                let coset: Vec<[u64; 2]> = (0..(1usize << s))
                    .map(|m| {
                        let v = layer[base + m * stride];
                        [v.0, v.1]
                    })
                    .collect();
                fri_ops.push(serde_json::json!({
                    "base": base,
                    "coset": coset,
                    "p": m_path(&fri_trees[ridx], base).iter().map(|(s,b)| (hex::encode(s), b)).collect::<Vec<_>>(),
                }));
                ci = base;
            }
        }
        op["fri"] = serde_json::json!(fri_ops);
        queries.push(op);
    }
    let mut proof = serde_json::json!({
        "stmt": {
            "root": stmt.root,
            "nf": stmt.nf,
            "cm_out": stmt.cm_out,
            "depth": stmt.depth,
        },
        "tp_root": hex::encode(m_root(&tree)),
        "fri_roots": fri_trees.iter().map(|t| hex::encode(m_root(t))).collect::<Vec<_>>(),
        "final": final_layer.iter().map(|v| [v.0, v.1]).collect::<Vec<_>>(),
        "betas": betas.iter().map(|b| [b.0, b.1]).collect::<Vec<_>>(),
        "nonce": hex::encode(nonce),
        "queries": queries,
        "grind_b": params.grind_bits,
        "blowup": params.blowup,
        "nq": params.queries,
        "mask_deg": params.mask_deg,
        "pairleaf": false,
        "fold_step": fold_step,
        "deep": params.deep,
        "engine": "shieldkit-fri-prover-rust",
    });
    if params.deep {
        for (k, v) in deep_json {
            proof[k] = v;
        }
    }
    let blob = serde_json::to_vec(&proof).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&blob);
    let proof_blob_sha256 = hex::encode(hasher.finalize());
    let verify_ok = verify_proof(&proof);
    let dt = t0.elapsed().as_secs_f64();
    let rss1 = peak_rss();
    ProveResult {
        statement: StatementDto {
            root: stmt.root,
            nf: stmt.nf,
            cm_out: stmt.cm_out,
            depth: stmt.depth,
            kind: kind.into(),
        },
        prove_seconds: dt,
        peak_rss_bytes: rss1.max(rss0),
        verify_ok,
        proof_blob_sha256,
        proof,
        engine: "shieldkit-fri-prover-rust".into(),
        mask_seed: None,
        witness_seed: 0,
        mask_source: None,
        depth: 0,
    }
}

fn fri_folds_to_final(n: usize) -> usize {
    let mut f = 0usize;
    while (n >> f) > 8 {
        f += 1;
    }
    f
}

fn parse_path(v: &serde_json::Value) -> Vec<(Vec<u8>, u8)> {
    v.as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|p| {
            let arr = p.as_array()?;
            let s = hex::decode(arr.get(0)?.as_str()?).ok()?;
            let b = arr.get(1)?.as_u64()? as u8;
            Some((s, b))
        })
        .collect()
}

fn parse_ext(v: &serde_json::Value) -> Option<Ext> {
    let a = v.as_array()?;
    Some((a.get(0)?.as_u64()?, a.get(1)?.as_u64()?))
}

/// Full DEEP-ALI FRI verify: FS replay, DEEP AIR binding, grind, query Merkle + FRI openings.
pub fn verify_proof(proof: &serde_json::Value) -> bool {
    verify_proof_why(proof).0
}

/// ethSTARK coset fold: fold a 2^s-coset of committed layer `li0` down to one value.
fn coset_fold(
    coset: &[Ext],
    base: usize,
    li0: usize,
    s: usize,
    betas_round: &[Ext],
    off: u64,
    on: u64,
    n: usize,
    inv2: u64,
) -> Ext {
    let layer_n = n >> li0;
    let stride = layer_n >> s;
    let mut cur = coset.to_vec();
    for f in 0..s {
        let h = cur.len() / 2;
        let beta = betas_round[f];
        let mut nxt = vec![gf2::ZERO; h];
        for m in 0..h {
            let gidx = (base + m * stride) as u64;
            let x = field::mod_pow(field::mul(off, field::mod_pow(on, gidx)), 1u64 << (li0 + f));
            let i2x = field::inv(field::mul(2, x));
            let fp = cur[m];
            let fm = cur[m + h];
            nxt[m] = gf2::add(
                gf2::scalar(inv2, gf2::add(fp, fm)),
                gf2::mul(beta, gf2::scalar(i2x, gf2::sub(fp, fm))),
            );
        }
        cur = nxt;
    }
    cur[0]
}

/// DEEP-quotient q(x_k) — same term order as prove HP5.5 / vendor _deep_replay.q_at.
fn deep_q_at(
    x: u64,
    k: usize,
    ck: &HashMap<String, u64>,
    cc: Ext,
    z: Ext,
    zg: Ext,
    pcz: &HashMap<String, Ext>,
    pczg: &HashMap<String, Ext>,
    sel_terms: &[(&[u64], Ext)],
    range_weight_k: u64,
    rw_zg: Ext,
    comp_z: Ext,
    deep_alphas: &[Ext],
) -> Ext {
    let invz = gf2::inv(gf2::sub(gf2::from_base(x), z));
    let invzg = gf2::inv(gf2::sub(gf2::from_base(x), zg));
    let mut acc = gf2::ZERO;
    let mut ai = 0usize;
    for c in FLAT_COLS {
        let cke = gf2::from_base(*ck.get(*c).unwrap_or(&0));
        acc = gf2::add(
            acc,
            gf2::mul(deep_alphas[ai], gf2::mul(gf2::sub(cke, pcz[*c]), invz)),
        );
        ai += 1;
        acc = gf2::add(
            acc,
            gf2::mul(deep_alphas[ai], gf2::mul(gf2::sub(cke, pczg[*c]), invzg)),
        );
        ai += 1;
    }
    for (dvals, m) in sel_terms {
        let dv = gf2::from_base(dvals[k]);
        acc = gf2::add(
            acc,
            gf2::mul(deep_alphas[ai], gf2::mul(gf2::sub(dv, *m), invz)),
        );
        ai += 1;
    }
    acc = gf2::add(
        acc,
        gf2::mul(
            deep_alphas[ai],
            gf2::mul(gf2::sub(gf2::from_base(range_weight_k), rw_zg), invzg),
        ),
    );
    ai += 1;
    acc = gf2::add(
        acc,
        gf2::mul(deep_alphas[ai], gf2::mul(gf2::sub(cc, comp_z), invz)),
    );
    acc
}

pub fn verify_proof_why(proof: &serde_json::Value) -> (bool, String) {
    let stmt = &proof["stmt"];
    let depth = stmt["depth"].as_u64().unwrap_or(0) as usize;
    let blowup = proof["blowup"].as_u64().unwrap_or(0);
    if depth == 0 || blowup == 0 {
        return (false, "bad params".into());
    }
    let (meta, t) = air::ct_build_layout(depth);
    let (n, ot, on, off, hd, dd, last) = setup(t, blowup);
    let lay = ct_public_layout(&meta, t);
    // Selector LDE needed for DEEP q(x_k) and non-deep AIR (vendor _selector_vectors).
    let sv = selector_lde(&lay, t, n, ot, on, off);
    let tp_root = hex::decode(proof["tp_root"].as_str().unwrap_or("")).unwrap_or_default();
    if tp_root.is_empty() {
        return (false, "tp_root".into());
    }
    let fri_roots: Vec<Vec<u8>> = proof["fri_roots"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|r| hex::decode(r.as_str()?).ok())
        .collect();
    let fold_step = proof["fold_step"].as_u64().unwrap_or(1) as usize;
    let deep = proof["deep"].as_bool().unwrap_or(false);
    let pairleaf = proof["pairleaf"].as_bool().unwrap_or(false);

    let mut fs = Fs::new();
    fs.absorb(&tp_root);
    fs.absorb_int(stmt["root"].as_u64().unwrap_or(0));
    fs.absorb_int(stmt["nf"].as_u64().unwrap_or(0));
    if let Some(cm) = stmt["cm_out"].as_array() {
        for c in cm {
            fs.absorb_int(c.as_u64().unwrap_or(0));
        }
    }
    let n_t = ct_num_transition_residuals();
    let statement = Statement {
        root: stmt["root"].as_u64().unwrap_or(0),
        nf: stmt["nf"].as_u64().unwrap_or(0),
        cm_out: [
            stmt["cm_out"]
                .as_array()
                .and_then(|a| a.get(0))
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
            stmt["cm_out"]
                .as_array()
                .and_then(|a| a.get(1))
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
        ],
        depth,
    };
    let bcons = make_bcons(&meta, &statement);
    let alphas_t: Vec<Ext> = (0..n_t).map(|_| ext_challenge(&mut fs)).collect();
    let alphas_b: Vec<Ext> = (0..bcons.len()).map(|_| ext_challenge(&mut fs)).collect();

    // DEEP state for q_at at queries
    let mut deep_z = gf2::ZERO;
    let mut deep_zg = gf2::ZERO;
    let mut deep_pcz: HashMap<String, Ext> = HashMap::new();
    let mut deep_pczg: HashMap<String, Ext> = HashMap::new();
    let mut deep_alphas: Vec<Ext> = Vec::new();
    let mut deep_comp_z = gf2::ZERO;
    let mut deep_rw_zg = gf2::ZERO;
    let mut deep_sel_masks: Vec<Ext> = Vec::new();
    let mut deep_comp_root: Vec<u8> = Vec::new();

    if deep {
        deep_comp_root = hex::decode(proof["comp_root"].as_str().unwrap_or("")).unwrap_or_default();
        if deep_comp_root.is_empty() {
            return (false, "comp_root".into());
        }
        fs.absorb(&deep_comp_root);
        let mut z = ext_challenge(&mut fs);
        if z.1 % P == 0 {
            z = (z.0, 1);
        }
        let zg = gf2::scalar(ot, z);
        let pz = parse_ext(&proof["z"]).unwrap_or((0, 0));
        let pzg = parse_ext(&proof["zg"]).unwrap_or((0, 0));
        if z != pz || zg != pzg {
            return (false, "deep z mismatch".into());
        }
        for c in FLAT_COLS {
            let a = parse_ext(&proof["Pcz"][*c]).unwrap_or((0, 0));
            let b = parse_ext(&proof["Pczg"][*c]).unwrap_or((0, 0));
            deep_pcz.insert((*c).into(), a);
            deep_pczg.insert((*c).into(), b);
        }
        let comp_z_pf = parse_ext(&proof["comp_z"]).unwrap_or((0, 0));
        let rw_zg = parse_ext(&proof["rw_zg"]).unwrap_or((0, 0));
        let isf = ood_public_at(&lay.is_full, t, ot, z);
        let isp = ood_public_at(&lay.is_partial, t, ot, z);
        let isbs = ood_public_at(&lay.is_block_start, t, ot, z);
        let isra = ood_public_at(&lay.is_reabsorb, t, ot, z);
        let isr = ood_public_at(&lay.is_range, t, ot, z);
        let isrf = ood_public_at(&lay.is_range_first, t, ot, z);
        let isrs = ood_public_at(&lay.is_range_step, t, ot, z);
        let isrl = ood_public_at(&lay.is_range_last, t, ot, z);
        let mut rc_e = [gf2::ZERO; WIDTH];
        for k in 0..WIDTH {
            rc_e[k] = ood_public_at(&lay.rc[k], t, ot, z);
        }
        let mut chain_e = [gf2::ZERO; WIDTH];
        for j in 0..WIDTH {
            let colj: Vec<u64> = (0..t).map(|r| lay.chain_minv[r][j]).collect();
            chain_e[j] = ood_public_at(&colj, t, ot, z);
        }
        let rw_check = ood_public_at(&lay.range_weight, t, ot, zg);
        if rw_check != rw_zg {
            return (false, "deep range_weight(z*g) mismatch".into());
        }
        let zhz_inv = gf2::inv(gf2::sub(gf2::power(z, t as u64), gf2::ONE));
        let tres = ct_transition_residuals_ext(
            &deep_pcz, &deep_pczg, isf, isp, &rc_e, isbs, isra, &chain_e, isr, isrf, isrs, isrl,
            rw_zg,
        );
        let zl = gf2::sub(z, gf2::from_base(last));
        let mut comp_z = gf2::ZERO;
        for (a, v) in alphas_t.iter().zip(tres.iter()) {
            comp_z = gf2::add(comp_z, gf2::mul(gf2::mul(gf2::mul(*v, zl), zhz_inv), *a));
        }
        let bcons_ext = ct_boundary_residuals_ext(&meta, &statement, &deep_pcz);
        for ((row, residual), a) in bcons_ext.iter().zip(alphas_b.iter()) {
            let den = gf2::inv(gf2::sub(z, gf2::from_base(hd[*row])));
            comp_z = gf2::add(comp_z, gf2::mul(gf2::mul(*residual, den), *a));
        }
        if comp_z != comp_z_pf {
            return (false, "comp(z) != AIR(z)".into());
        }
        for c in FLAT_COLS {
            let a = deep_pcz[*c];
            let b = deep_pczg[*c];
            fs.absorb_int(a.0);
            fs.absorb_int(a.1);
            fs.absorb_int(b.0);
            fs.absorb_int(b.1);
        }
        deep_sel_masks = vec![isf, isp, isbs, isra, isr, isrf, isrs, isrl];
        deep_sel_masks.extend_from_slice(&rc_e);
        deep_sel_masks.extend_from_slice(&chain_e);
        for m in &deep_sel_masks {
            fs.absorb_int(m.0);
            fs.absorb_int(m.1);
        }
        fs.absorb_int(rw_zg.0);
        fs.absorb_int(rw_zg.1);
        fs.absorb_int(comp_z_pf.0);
        fs.absorb_int(comp_z_pf.1);
        let n_terms = 2 * FLAT_COLS.len() + deep_sel_masks.len() + 2;
        deep_alphas = (0..n_terms).map(|_| ext_challenge(&mut fs)).collect();
        if let Some(pf_da) = proof["deep_alphas"].as_array() {
            if pf_da.len() != deep_alphas.len() {
                return (false, "deep_alphas length".into());
            }
            for (i, a) in deep_alphas.iter().enumerate() {
                if parse_ext(&pf_da[i]) != Some(*a) {
                    return (false, "deep_alphas mismatch".into());
                }
            }
        }
        deep_z = z;
        deep_zg = zg;
        deep_comp_z = comp_z_pf;
        deep_rw_zg = rw_zg;
    }

    fs.absorb(b"fri");
    let mut betas_v: Vec<Ext> = Vec::new();
    let mut sizes: Vec<usize> = Vec::new();
    let mut rmeta: Vec<(usize, usize, usize)> = Vec::new(); // (s, size, li0)
    let mut size = n;
    let mut ri = 0usize;
    if fold_step == 1 {
        loop {
            if ri >= fri_roots.len() {
                return (false, "fri_roots short".into());
            }
            fs.absorb(&fri_roots[ri]);
            sizes.push(size);
            ri += 1;
            if size <= 8 {
                break;
            }
            betas_v.push(ext_challenge(&mut fs));
            size /= 2;
        }
    } else {
        let mut g = 0usize;
        loop {
            if ri >= fri_roots.len() {
                return (false, "fri_roots short".into());
            }
            fs.absorb(&fri_roots[ri]);
            let s = fri_folds_to_final(size).min(fold_step);
            rmeta.push((s, size, g));
            ri += 1;
            if s == 0 {
                break;
            }
            for _ in 0..s {
                betas_v.push(ext_challenge(&mut fs));
                size >>= 1;
            }
            g += s;
        }
    }
    if fri_roots.len() != ri {
        return (false, "fri_roots length".into());
    }
    let pf_betas = proof["betas"].as_array().cloned().unwrap_or_default();
    if pf_betas.len() != betas_v.len() {
        return (false, "beta count".into());
    }
    for (i, b) in betas_v.iter().enumerate() {
        if parse_ext(&pf_betas[i]) != Some(*b) {
            return (false, "beta mismatch".into());
        }
    }
    let grind_b = proof["grind_b"].as_u64().unwrap_or(0) as u32;
    let nonce = hex::decode(proof["nonce"].as_str().unwrap_or("")).unwrap_or_default();
    if nonce.len() != 8 {
        return (false, "nonce".into());
    }
    {
        let mut cat = fs.s.clone();
        cat.extend_from_slice(&nonce);
        let h = merkle::sha256f(&cat);
        let v = u64::from_le_bytes(h[..8].try_into().unwrap());
        if v >= (1u64 << (64 - grind_b)) {
            return (false, "grind".into());
        }
    }
    fs.absorb(&nonce);
    let nq = proof["nq"].as_u64().unwrap_or(0) as usize;
    let idxs: Vec<usize> = (0..nq).map(|_| fs.challenge_idx(n)).collect();
    let queries = proof["queries"].as_array().cloned().unwrap_or_default();
    if queries.len() != idxs.len() {
        return (false, "query count".into());
    }

    // Final layer root bind (vendor HP7.4c)
    let final_arr = proof["final"].as_array().cloned().unwrap_or_default();
    let final_vals: Vec<Ext> = final_arr.iter().filter_map(parse_ext).collect();
    if final_vals.is_empty() {
        return (false, "final empty".into());
    }
    let final_leaves: Vec<merkle::Hash> = if fold_step == 1 && pairleaf {
        let hf = final_vals.len() / 2;
        (0..hf)
            .map(|i| {
                // pair leaf not used in production path (pairleaf=false)
                leaf_ext(final_vals[i], &[0u8; 16])
            })
            .collect()
    } else {
        final_vals
            .iter()
            .map(|v| leaf_ext(*v, &[0u8; 16]))
            .collect()
    };
    let final_tree = merkle(final_leaves);
    if m_root(&final_tree) != fri_roots.last().map(|r| r.as_slice()).unwrap_or(&[]) {
        return (false, "final root".into());
    }

    // sel_terms for q_at: LDE vectors + masks at z
    let sel_terms: Vec<(&[u64], Ext)> = if deep {
        let mut v: Vec<(&[u64], Ext)> = vec![
            (&sv.is_full, deep_sel_masks[0]),
            (&sv.is_partial, deep_sel_masks[1]),
            (&sv.is_block_start, deep_sel_masks[2]),
            (&sv.is_reabsorb, deep_sel_masks[3]),
            (&sv.is_range, deep_sel_masks[4]),
            (&sv.is_range_first, deep_sel_masks[5]),
            (&sv.is_range_step, deep_sel_masks[6]),
            (&sv.is_range_last, deep_sel_masks[7]),
        ];
        for k in 0..WIDTH {
            v.push((&sv.rc[k], deep_sel_masks[8 + k]));
        }
        for j in 0..WIDTH {
            v.push((&sv.chain_minv[j], deep_sel_masks[8 + WIDTH + j]));
        }
        v
    } else {
        Vec::new()
    };

    let inv2 = field::inv(2);
    for (qi, q) in queries.iter().enumerate() {
        let k = q["k"].as_u64().unwrap_or(0) as usize;
        if k != idxs[qi] {
            return (false, "idx mismatch".into());
        }
        let x = dd[k];
        let sk = hex::decode(q["sk"].as_str().unwrap_or("")).unwrap_or_default();
        let ck_obj = match q["ck"].as_object() {
            Some(o) => o,
            None => return (false, "ck".into()),
        };
        let mut ck_map: HashMap<String, u64> = HashMap::new();
        let mut vals = Vec::with_capacity(N_FLAT);
        for c in FLAT_COLS {
            let v = ck_obj.get(*c).and_then(|x| x.as_u64()).unwrap_or(0);
            vals.push(v);
            ck_map.insert((*c).into(), v);
        }
        let leaf = leaf_base(&vals, &sk);
        let path = parse_path(&q["pk"]);
        if !m_verify(&tp_root, leaf.as_slice(), k, &path) {
            return (false, "col path k".into());
        }

        // DEEP: open comp(x_k) and recompute q(x_k)
        let comp_x = if deep {
            let cc = parse_ext(&q["cc"]).unwrap_or((0, 0));
            let cp = parse_path(&q["cp"]);
            let cleaf = leaf_ext(cc, &[0u8; 16]);
            if !m_verify(&deep_comp_root, cleaf.as_slice(), k, &cp) {
                return (false, "comp path k".into());
            }
            deep_q_at(
                x,
                k,
                &ck_map,
                cc,
                deep_z,
                deep_zg,
                &deep_pcz,
                &deep_pczg,
                &sel_terms,
                sv.range_weight[k],
                deep_rw_zg,
                deep_comp_z,
                &deep_alphas,
            )
        } else {
            // non-deep path not used in product; keep fail-closed
            return (false, "non-deep verify not implemented".into());
        };

        let fri = q["fri"].as_array().cloned().unwrap_or_default();
        if fold_step == 1 {
            let mut ci = k;
            for (li, fo) in fri.iter().enumerate() {
                let half = sizes[li] / 2;
                let ii = ci % half;
                let fv = parse_ext(&fo["v"]).unwrap_or((0, 0));
                let fw = parse_ext(&fo["w"]).unwrap_or((0, 0));
                let vp = parse_path(&fo["vp"]);
                let wp = parse_path(&fo["wp"]);
                let leaf_v = leaf_ext(fv, &[0u8; 16]);
                let leaf_w = leaf_ext(fw, &[0u8; 16]);
                if !m_verify(&fri_roots[li], leaf_v.as_slice(), ii, &vp) {
                    return (false, format!("fri{li} v"));
                }
                if !m_verify(&fri_roots[li], leaf_w.as_slice(), ii + half, &wp) {
                    return (false, format!("fri{li} w"));
                }
                if li == 0 {
                    let tgt = if k >= half { fw } else { fv };
                    if tgt != comp_x {
                        return (false, "comp != fri0".into());
                    }
                }
                // Algebraic fold: xpos = (off * oN^ii)^(2^li)
                let xpos = field::mod_pow(
                    field::mul(off, field::mod_pow(on, ii as u64)),
                    1u64 << li,
                );
                let beta = betas_v[li];
                let i2x = field::inv(field::mul(2, xpos));
                let folded = gf2::add(
                    gf2::scalar(inv2, gf2::add(fv, fw)),
                    gf2::mul(beta, gf2::scalar(i2x, gf2::sub(fv, fw))),
                );
                if li + 1 < fri.len() {
                    let nh = sizes[li + 1] / 2;
                    let nxt = if ii >= nh {
                        parse_ext(&fri[li + 1]["w"]).unwrap_or((0, 0))
                    } else {
                        parse_ext(&fri[li + 1]["v"]).unwrap_or((0, 0))
                    };
                    if folded != nxt {
                        return (false, format!("fold L{li}"));
                    }
                } else if folded != final_vals[ii % final_vals.len()] {
                    return (false, "fri final".into());
                }
                ci = ii;
            }
        } else {
            let mut ci = k;
            for (ridx, fo) in fri.iter().enumerate() {
                let (s, sz, li0) = rmeta[ridx];
                let stride = sz >> s;
                let base = fo["base"].as_u64().unwrap_or(0) as usize;
                if base != ci % stride {
                    return (false, format!("fri{ridx} base"));
                }
                let coset_j = fo["coset"].as_array().cloned().unwrap_or_default();
                let coset: Vec<Ext> = coset_j.iter().filter_map(parse_ext).collect();
                if coset.len() != (1usize << s) {
                    return (false, format!("fri{ridx} coset size"));
                }
                let leaf = leaf_ext_coset(&coset, &[0u8; 16]);
                let path = parse_path(&fo["p"]);
                if !m_verify(&fri_roots[ridx], leaf.as_slice(), base, &path) {
                    return (false, format!("fri{ridx} coset"));
                }
                if ridx == 0 {
                    let elem = coset[ci / stride];
                    if elem != comp_x {
                        return (false, "comp != fri0".into());
                    }
                }
                let betas_round = &betas_v[li0..li0 + s];
                let folded = coset_fold(&coset, base, li0, s, betas_round, off, on, n, inv2);
                ci = base;
                if ridx + 1 < fri.len() {
                    let (ns, nsz, _nli0) = rmeta[ridx + 1];
                    let nstride = nsz >> ns;
                    let ncoset_j = fri[ridx + 1]["coset"].as_array().cloned().unwrap_or_default();
                    let ncoset: Vec<Ext> = ncoset_j.iter().filter_map(parse_ext).collect();
                    if folded != ncoset[ci / nstride] {
                        return (false, format!("fold round {ridx}"));
                    }
                } else if folded != final_vals[ci % final_vals.len()] {
                    return (false, "fri final".into());
                }
            }
        }
    }
    let _ = last; // used in non-deep path
    (true, "ok".into())
}

/// ZK mask/salt randomness source.
///
/// Deterministic mode: one SplitMix64 stream seeded with the caller's u64.
/// Random (production) mode: two SplitMix64 streams seeded from `rand::thread_rng()`
/// (ChaCha12 CSPRNG, OS entropy); draws alternate between the streams so the joint
/// seed entropy is 128 bits (>= the 100-bit security bar).
struct RngSource {
    a: SplitMix64,
    b: SplitMix64,
    toggle: bool,
    mode: &'static str,
}
impl RngSource {
    fn new(seed: Option<u64>) -> Self {
        match seed {
            Some(s) => Self {
                a: SplitMix64::new(s),
                b: SplitMix64::new(s.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1)),
                toggle: false,
                mode: "splitmix64(seed)",
            },
            None => {
                use rand::Rng;
                let mut os = rand::thread_rng();
                Self {
                    a: SplitMix64::new(os.gen::<u64>()),
                    b: SplitMix64::new(os.gen::<u64>()),
                    toggle: false,
                    mode: "csprng(thread_rng, 128-bit)",
                }
            }
        }
    }
    fn next_u64(&mut self) -> u64 {
        self.toggle = !self.toggle;
        if self.toggle {
            self.a.next_u64()
        } else {
            self.b.next_u64()
        }
    }
}

struct SplitMix64 {
    state: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

/// `seed`: `Some(n)` -> deterministic witness + deterministic ZK masks (test/oracle).
/// `None` -> deterministic witness (witness seed 0 for the current test-witness path;
/// production witness comes from the caller — see item 2) + CSPRNG ZK masks.
pub fn prove_kind(
    kind: &str,
    depth: usize,
    params: &FriParams,
    seed: Option<u64>,
) -> ProveResult {
    let ws = seed.unwrap_or(0);
    let w = air::pool_witness(kind, depth, ws);
    let mut r = prove(&w, params, seed, kind);
    r.mask_seed = seed;
    r.witness_seed = ws;
    r.mask_source = Some(match seed {
        Some(_) => "splitmix64(seed)".to_string(),
        None => "csprng(thread_rng, 128-bit)".to_string(),
    });
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selftest_small() {
        let params = FriParams {
            blowup: 4,
            queries: 2,
            grind_bits: 2,
            fold_step: 1,
            mask_deg: 8,
            deep: true,
        };
        let r = prove_kind("transfer", 4, &params, Some(7));
        assert!(r.verify_ok, "deep verify failed: {:?}", verify_proof_why(&r.proof));
        assert!(r.prove_seconds < 120.0);
    }

    #[test]
    fn selftest_fold_step3() {
        let params = FriParams {
            blowup: 8,
            queries: 2,
            grind_bits: 2,
            fold_step: 3,
            mask_deg: 8,
            deep: true,
        };
        let r = prove_kind("transfer", 4, &params, Some(1));
        assert!(
            r.verify_ok,
            "fold3 deep verify failed: {:?}",
            verify_proof_why(&r.proof)
        );
        assert_eq!(r.proof["fold_step"].as_u64(), Some(3));
        // composition paths must be non-empty at queries
        let q0 = &r.proof["queries"][0];
        assert!(
            q0["cp"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
            "cp path must be non-empty for DEEP verify"
        );
        assert!(q0.get("cc").is_some(), "cc required");
    }

    #[test]
    fn adversarial_tamper_rejects() {
        let params = FriParams {
            blowup: 4,
            queries: 2,
            grind_bits: 2,
            fold_step: 1,
            mask_deg: 8,
            deep: true,
        };
        let r = prove_kind("transfer", 4, &params, Some(3));
        assert!(r.verify_ok);

        // Tamper composition root
        let mut p = r.proof.clone();
        p["comp_root"] = serde_json::json!("00".repeat(25));
        let (ok, why) = verify_proof_why(&p);
        assert!(!ok, "tampered comp_root must fail, got ok why={why}");

        // Tamper first query composition opening
        let mut p = r.proof.clone();
        if let Some(cc) = p["queries"][0]["cc"].as_array_mut() {
            if let Some(v) = cc.get_mut(0) {
                *v = serde_json::json!(v.as_u64().unwrap_or(0).wrapping_add(1));
            }
        }
        let (ok, why) = verify_proof_why(&p);
        assert!(!ok, "tampered cc must fail, got ok why={why}");

        // Empty composition path must fail
        let mut p = r.proof.clone();
        p["queries"][0]["cp"] = serde_json::json!([]);
        let (ok, why) = verify_proof_why(&p);
        assert!(!ok, "empty cp must fail, got ok why={why}");

        // Tamper FRI layer-0 opening (breaks fri0==q or merkle)
        let mut p = r.proof.clone();
        if let Some(fri) = p["queries"][0]["fri"].as_array_mut() {
            if let Some(fl0) = fri.get_mut(0) {
                if let Some(v) = fl0.get_mut("v").and_then(|x| x.as_array_mut()) {
                    if let Some(limb) = v.get_mut(0) {
                        *limb = serde_json::json!(limb.as_u64().unwrap_or(0).wrapping_add(7));
                    }
                }
                if let Some(c) = fl0.get_mut("coset").and_then(|x| x.as_array_mut()) {
                    if let Some(e0) = c.get_mut(0).and_then(|x| x.as_array_mut()) {
                        if let Some(limb) = e0.get_mut(0) {
                            *limb = serde_json::json!(limb.as_u64().unwrap_or(0).wrapping_add(7));
                        }
                    }
                }
            }
        }
        let (ok, why) = verify_proof_why(&p);
        assert!(!ok, "tampered fri0 must fail, got ok why={why}");

        // Tamper final layer (final root bind)
        let mut p = r.proof.clone();
        if let Some(f) = p["final"].as_array_mut() {
            if let Some(e0) = f.get_mut(0).and_then(|x| x.as_array_mut()) {
                if let Some(limb) = e0.get_mut(0) {
                    *limb = serde_json::json!(limb.as_u64().unwrap_or(0).wrapping_add(1));
                }
            }
        }
        let (ok, why) = verify_proof_why(&p);
        assert!(!ok, "tampered final must fail, got ok why={why}");
    }

    #[test]
    fn adversarial_tamper_fold3() {
        let params = FriParams {
            blowup: 8,
            queries: 2,
            grind_bits: 2,
            fold_step: 3,
            mask_deg: 8,
            deep: true,
        };
        let r = prove_kind("deposit", 4, &params, Some(5));
        assert!(r.verify_ok, "{:?}", verify_proof_why(&r.proof));
        let mut p = r.proof.clone();
        // corrupt deep_alphas
        if let Some(da) = p["deep_alphas"].as_array_mut() {
            if let Some(a0) = da.get_mut(0).and_then(|x| x.as_array_mut()) {
                if let Some(limb) = a0.get_mut(0) {
                    *limb = serde_json::json!(limb.as_u64().unwrap_or(0).wrapping_add(1));
                }
            }
        }
        let (ok, why) = verify_proof_why(&p);
        assert!(!ok, "tampered deep_alphas must fail, got ok why={why}");
    }
}
