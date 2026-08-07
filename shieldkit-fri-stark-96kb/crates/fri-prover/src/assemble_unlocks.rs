//! Materialize FRI-related unlock witnesses from a proof dump.
//! Redeems are supplied externally (profile-fixed); this only packs unlock bytes.
use crate::field;
use crate::fri_terms::{query_fri_terms_fold8, FriRoundTerm, QueryFriTerms};
use crate::script_enc::{concat, enc8, push_bytes, push_num};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleUnlock {
    pub role: String,
    pub index: usize,
    pub unlock_bytecode_hex: String,
    pub unlock_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssembleUnlocksResult {
    pub ok: bool,
    pub engine: String,
    pub n_queries: usize,
    pub fri_terms: Vec<QueryFriTerms>,
    /// Per-query aggregated-FRI unlock bytecode (one unlock per gq-group when gq=1 → nq unlocks).
    pub aggfri_unlocks: Vec<RoleUnlock>,
    pub wall_seconds: f64,
    pub note: String,
}

fn fri_loop_round_witness(r: &FriRoundTerm) -> Vec<u8> {
    // [stride, pe, betas(2*s), i2x(2^s-1), base, root, sibs reversed, preimage, k=base, d]
    let pe = 1u64 << r.li0;
    let mut parts: Vec<Vec<u8>> = Vec::new();
    parts.push(push_num(r.stride));
    parts.push(push_num(pe));
    for bt in &r.betas {
        parts.push(push_num(bt[0]));
        parts.push(push_num(bt[1]));
    }
    for x in &r.i2x {
        parts.push(push_num(*x));
    }
    parts.push(push_num(r.base));
    let root = hex::decode(&r.root).unwrap_or_default();
    parts.push(push_bytes(&root));
    // siblings deepest-first = reversed path order for stack bottom→top
    for (sib_hex, _) in r.path.iter().rev() {
        let sib = hex::decode(sib_hex).unwrap_or_default();
        parts.push(push_bytes(&sib));
    }
    // preimage = salt16 || coset cells
    let mut preimage = vec![0u8; 16];
    for v in &r.coset {
        preimage.extend_from_slice(&enc8(v[0] % field::P));
        preimage.extend_from_slice(&enc8(v[1] % field::P));
    }
    parts.push(push_bytes(&preimage));
    parts.push(push_num(r.base));
    parts.push(push_num(r.path.len() as u64));
    concat(&parts)
}

/// Unlock for one agg-FRI query group (gq=1): frl at bottom, s=3 round witnesses, then comp limbs.
/// Matches vendor `_fri_loop_chain_unlock` (without product final_pre).
pub fn pack_aggfri_unlock_one(
    terms: &QueryFriTerms,
    fri_root_last_hex: &str,
    pad: usize,
) -> Vec<u8> {
    let frl = hex::decode(fri_root_last_hex).unwrap_or_default();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    // frl at bottom of unlock stack region
    parts.push(push_bytes(&frl));
    // s=3 rounds only, last-round deepest first (reversed)
    let s3: Vec<&FriRoundTerm> = terms.rounds.iter().filter(|r| r.s == 3).collect();
    for r in s3.iter().rev() {
        parts.push(fri_loop_round_witness(r));
    }
    // layer-0 composition from first coset element of round0 at comp_pos — caller should
    // pass correct limbs; we place 0,0 placeholder if missing and note in docs.
    // Vendor places NUM(comp0), NUM(comp1) at top of chain unlock before pad.
    // For product fixed locks, comp comes from deepquery cross-input; unlock still needs
    // initial carried value. Use fold of first coset slot as stand-in only when empty.
    let (c0, c1) = if let Some(r0) = terms.rounds.first() {
        let idx = r0.comp_pos as usize;
        if idx < r0.coset.len() {
            (r0.coset[idx][0], r0.coset[idx][1])
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };
    parts.push(push_num(c0));
    parts.push(push_num(c1));
    if pad > 0 {
        parts.push(push_bytes(&vec![0u8; pad]));
    }
    concat(&parts)
}

/// Materialize FRI unlocks from a proof dump (JSON Value).
pub fn assemble_unlocks_from_proof(proof: &Value, aggfri_pad: usize) -> Result<AssembleUnlocksResult, String> {
    let t0 = std::time::Instant::now();
    let fri_terms = query_fri_terms_fold8(proof)?;
    let fri_roots = proof
        .get("fri_roots")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let frl = fri_roots
        .last()
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();

    let mut aggfri_unlocks = Vec::new();
    for (i, terms) in fri_terms.iter().enumerate() {
        let unlock = pack_aggfri_unlock_one(terms, &frl, aggfri_pad);
        aggfri_unlocks.push(RoleUnlock {
            role: "aggFRI".into(),
            index: i,
            unlock_bytes: unlock.len(),
            unlock_bytecode_hex: hex::encode(unlock),
        });
    }

    Ok(AssembleUnlocksResult {
        ok: true,
        engine: "shieldkit-fri-assemble-unlocks-rust".into(),
        n_queries: fri_terms.len(),
        fri_terms,
        aggfri_unlocks,
        wall_seconds: t0.elapsed().as_secs_f64(),
        note: "FRI terms + aggFRI unlock packs from proof dump; deepquery/blob/comp redeems+unlocks still stitched by product path. Use fri_terms to skip Python query_fri_terms_fold8.".into(),
    })
}

/// Stitch fixed redeems with optional unlock overrides → roleHex-like rows.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemIn {
    pub role: String,
    pub index: usize,
    pub redeem_bytecode_hex: String,
    #[serde(default)]
    pub unlock_bytecode_hex: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StitchedRole {
    pub role: String,
    pub index: usize,
    pub redeem_bytecode_hex: String,
    pub unlock_bytecode_hex: String,
    pub redeem_bytes: usize,
    pub unlock_bytes: usize,
    pub script_sig_hex: String,
    pub script_sig_bytes: usize,
}

pub fn stitch_redeems_unlocks(
    redeems: &[RedeemIn],
    unlock_overrides: &[(usize, String)],
) -> Vec<StitchedRole> {
    let map: std::collections::HashMap<usize, String> =
        unlock_overrides.iter().cloned().collect();
    redeems
        .iter()
        .map(|r| {
            let unlock_hex = map
                .get(&r.index)
                .cloned()
                .or_else(|| r.unlock_bytecode_hex.clone())
                .unwrap_or_default();
            let redeem = hex::decode(&r.redeem_bytecode_hex).unwrap_or_default();
            let unlock = hex::decode(&unlock_hex).unwrap_or_default();
            // scriptSig = unlock || PUSH(redeem)
            let mut ss = unlock.clone();
            ss.extend_from_slice(&crate::script_enc::encode_data_push(&redeem));
            StitchedRole {
                role: r.role.clone(),
                index: r.index,
                redeem_bytecode_hex: r.redeem_bytecode_hex.clone(),
                unlock_bytecode_hex: unlock_hex,
                redeem_bytes: redeem.len(),
                unlock_bytes: unlock.len(),
                script_sig_hex: hex::encode(&ss),
                script_sig_bytes: ss.len(),
            }
        })
        .collect()
}
