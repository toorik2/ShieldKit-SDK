//! Native Goldilocks DEEP-ALI FRI-STARK prover (same AIR lineage as vendor bch-fri-stark).
pub mod air;
pub mod air_matrices;
pub mod assemble_unlocks;
pub mod field;
pub mod flat_cols;
pub mod fri_terms;
pub mod fs;
pub mod gf2;
pub mod merkle;
pub mod ntt;
pub mod poseidon2;
pub mod poseidon2_constants;
pub mod prove;
pub mod py_random;
pub mod script_enc;

pub use air::{demo_witness, pool_witness, Statement, Witness};
pub use assemble_unlocks::{
    assemble_unlocks_from_proof, stitch_redeems_unlocks, AssembleUnlocksResult, RedeemIn,
    StitchedRole,
};
pub use fri_terms::{query_fri_terms_fold8, QueryFriTerms};
pub use prove::{prove, prove_kind, verify_proof, verify_proof_why, FriParams, ProveResult};
