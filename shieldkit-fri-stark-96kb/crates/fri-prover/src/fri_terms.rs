//! Fast fold-8 FRI query terms from a Rust proof JSON dump.
//! Replaces pure-Python `query_fri_terms_fold8` which re-derives heavy structures
//! and hangs at production-floor domain sizes (N=2^24).
use crate::field::{self, P};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriRoundTerm {
    pub base: u64,
    pub coset: Vec<[u64; 2]>,
    pub path: Vec<(String, u8)>,
    pub root: String,
    pub s: usize,
    pub li0: usize,
    pub stride: u64,
    pub betas: Vec<[u64; 2]>,
    pub i2x: Vec<u64>,
    pub ci: u64,
    pub comp_pos: u64,
    pub fold_tgt: [u64; 2],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryFriTerms {
    pub k: u64,
    pub rounds: Vec<FriRoundTerm>,
}

fn fri_folds_to_final(n: usize) -> usize {
    // Number of fold-by-2 steps that bring size n down to <= 8 (vendor/stark + prove.rs).
    let mut f = 0usize;
    while (n >> f) > 8 {
        f += 1;
    }
    f
}

fn as_u64(v: &Value) -> u64 {
    match v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_i64().map(|i| i as u64))
            .unwrap_or(0),
        Value::String(s) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn as_ext(v: &Value) -> [u64; 2] {
    match v {
        Value::Array(a) if a.len() >= 2 => [as_u64(&a[0]), as_u64(&a[1])],
        _ => [0, 0],
    }
}

fn parse_path(v: &Value) -> Vec<(String, u8)> {
    let mut out = Vec::new();
    let Some(arr) = v.as_array() else {
        return out;
    };
    for item in arr {
        if let Value::Array(pair) = item {
            if pair.len() >= 2 {
                let h = pair[0].as_str().unwrap_or("").to_string();
                let b = as_u64(&pair[1]) as u8;
                out.push((h, b));
            }
        }
    }
    out
}

/// Build fold-8 per-query round terms (witness-side) from proof dump.
pub fn query_fri_terms_fold8(proof: &Value) -> Result<Vec<QueryFriTerms>, String> {
    let fold_step = proof
        .get("fold_step")
        .map(as_u64)
        .unwrap_or(1) as usize;
    if fold_step == 1 {
        return Err("query_fri_terms_fold8 requires fold_step>=2".into());
    }
    let stmt = proof
        .get("stmt")
        .ok_or("proof missing stmt")?;
    let depth = as_u64(stmt.get("depth").unwrap_or(&Value::from(4))) as usize;
    let blowup = as_u64(proof.get("blowup").unwrap_or(&Value::from(32))) as usize;
    let (_meta, t) = crate::air::ct_build_layout(depth);
    let n = blowup * t;
    let o_n = field::root(n as u64);
    let off = field::find_gen();

    let betas_all: Vec<[u64; 2]> = proof
        .get("betas")
        .and_then(|b| b.as_array())
        .map(|a| a.iter().map(as_ext).collect())
        .unwrap_or_default();
    let fri_roots: Vec<String> = proof
        .get("fri_roots")
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    let final_layer: Vec<[u64; 2]> = proof
        .get("final")
        .and_then(|f| f.as_array())
        .map(|a| a.iter().map(as_ext).collect())
        .unwrap_or_default();

    // round meta: (li0, s, size)
    let mut rounds_meta: Vec<(usize, usize, usize)> = Vec::new();
    let mut size = n;
    let mut g = 0usize;
    loop {
        let s = fri_folds_to_final(size).min(fold_step);
        rounds_meta.push((g, s, size));
        if s == 0 {
            break;
        }
        g += s;
        size >>= s;
    }

    let queries = proof
        .get("queries")
        .and_then(|q| q.as_array())
        .ok_or("proof missing queries")?;

    let mut out = Vec::with_capacity(queries.len());
    for q in queries {
        let k = as_u64(q.get("k").unwrap_or(&Value::from(0)));
        let fri = q
            .get("fri")
            .and_then(|f| f.as_array())
            .cloned()
            .unwrap_or_default();
        let mut ci = k;
        let mut rnds = Vec::new();
        for (ridx, fl) in fri.iter().enumerate() {
            if ridx >= rounds_meta.len() {
                break;
            }
            let (li0, s, _sz) = rounds_meta[ridx];
            let base = as_u64(fl.get("base").unwrap_or(&Value::from(0)));
            let coset: Vec<[u64; 2]> = fl
                .get("coset")
                .and_then(|c| c.as_array())
                .map(|a| a.iter().map(as_ext).collect())
                .unwrap_or_default();
            let path = parse_path(fl.get("p").unwrap_or(&Value::Null));
            let stride = ((n as u64) >> li0) >> s as u64;
            // per-butterfly inverse hints i2x = inv(2 * x_pos)
            let mut i2x = Vec::new();
            let mut cnt = 1usize << s;
            for f in 0..s {
                let h = cnt / 2;
                for m in 0..h {
                    let exp = (li0 + f) as u32;
                    let xpos = field::mod_pow(
                        field::mul(off, field::mod_pow(o_n, base + (m as u64) * stride)),
                        1u64 << exp,
                    );
                    let twox = field::mul(2, xpos);
                    i2x.push(field::inv(twox));
                }
                cnt = h;
            }
            let ci_next = base;
            let fold_tgt = if ridx + 1 < fri.len() {
                let (nli0, ns, _) = rounds_meta[ridx + 1];
                let nstride = ((n as u64) >> nli0) >> ns as u64;
                let ncoset: Vec<[u64; 2]> = fri[ridx + 1]
                    .get("coset")
                    .and_then(|c| c.as_array())
                    .map(|a| a.iter().map(as_ext).collect())
                    .unwrap_or_default();
                let idx = (ci_next / nstride) as usize;
                if idx < ncoset.len() {
                    ncoset[idx]
                } else {
                    [0, 0]
                }
            } else {
                let idx = (ci_next as usize) % final_layer.len().max(1);
                final_layer.get(idx).copied().unwrap_or([0, 0])
            };
            let root = fri_roots.get(ridx).cloned().unwrap_or_default();
            let betas = betas_all
                .get(li0..li0 + s)
                .map(|s| s.to_vec())
                .unwrap_or_default();
            rnds.push(FriRoundTerm {
                base,
                coset,
                path,
                root,
                s,
                li0,
                stride,
                betas,
                i2x,
                ci,
                comp_pos: if stride > 0 { ci / stride } else { 0 },
                fold_tgt,
            });
            ci = ci_next;
        }
        out.push(QueryFriTerms { k, rounds: rnds });
    }
    let _ = P; // keep import used for docs
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fri_folds_basic() {
        assert_eq!(fri_folds_to_final(8), 0);
        assert!(fri_folds_to_final(16) >= 1);
        let (_, t4) = crate::air::ct_build_layout(4);
        assert_eq!(t4, 1024);
    }
}
