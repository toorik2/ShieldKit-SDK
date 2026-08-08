use crate::field::enc;
use sha2::{Digest, Sha256};

pub const MERKLE_HASH_BYTES: usize = 25;
pub type Hash = [u8; MERKLE_HASH_BYTES];

pub fn sha256f(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

pub fn hf(b: &[u8]) -> Hash {
    let full = sha256f(b);
    let mut out = [0u8; MERKLE_HASH_BYTES];
    out.copy_from_slice(&full[..MERKLE_HASH_BYTES]);
    out
}

pub fn leaf_base(vals: &[u64], salt: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(salt.len() + vals.len() * 8);
    buf.extend_from_slice(salt);
    for v in vals {
        buf.extend_from_slice(&enc(*v));
    }
    hf(&buf)
}

pub fn leaf_ext(v: (u64, u64), salt: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(salt.len() + 16);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(&enc(v.0));
    buf.extend_from_slice(&enc(v.1));
    hf(&buf)
}

/// ethSTARK layer-skip leaf: pack a 2^s-coset of GF(p^2) values into one Merkle leaf.
pub fn leaf_ext_coset(coset: &[(u64, u64)], salt: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(salt.len() + coset.len() * 16);
    buf.extend_from_slice(salt);
    for v in coset {
        buf.extend_from_slice(&enc(v.0));
        buf.extend_from_slice(&enc(v.1));
    }
    hf(&buf)
}

/// Compact Merkle tree: fixed-size hashes (no per-node Vec header).
pub type Tree = Vec<Vec<Hash>>;

pub fn merkle(leaves: Vec<Hash>) -> Tree {
    let mut tree = vec![leaves];
    while tree.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let layer = tree.last().unwrap();
        let n = layer.len();
        let mut next = Vec::with_capacity((n + 1) / 2);
        let mut i = 0;
        while i < n {
            let left = &layer[i];
            let right = if i + 1 < n { &layer[i + 1] } else { left };
            let mut cat = [0u8; MERKLE_HASH_BYTES * 2];
            cat[..MERKLE_HASH_BYTES].copy_from_slice(left);
            cat[MERKLE_HASH_BYTES..].copy_from_slice(right);
            next.push(hf(&cat));
            i += 2;
        }
        tree.push(next);
    }
    tree
}

pub fn m_root(tree: &Tree) -> &[u8] {
    &tree[tree.len() - 1][0]
}

pub fn m_path(tree: &Tree, mut idx: usize) -> Vec<(Hash, u8)> {
    let mut path = Vec::new();
    for d in 0..tree.len() - 1 {
        let layer = &tree[d];
        let j = idx ^ 1;
        let j = if j >= layer.len() { idx } else { j };
        path.push((layer[j], (idx & 1) as u8));
        idx /= 2;
    }
    path
}

pub fn m_verify(root: &[u8], leaf: &[u8], mut idx: usize, path: &[(Vec<u8>, u8)]) -> bool {
    let mut h = [0u8; MERKLE_HASH_BYTES];
    if leaf.len() < MERKLE_HASH_BYTES {
        return false;
    }
    h.copy_from_slice(&leaf[..MERKLE_HASH_BYTES]);
    for (sib, bit) in path {
        let mut cat = [0u8; MERKLE_HASH_BYTES * 2];
        if *bit == 1 {
            cat[..MERKLE_HASH_BYTES].copy_from_slice(&sib[..MERKLE_HASH_BYTES.min(sib.len())]);
            cat[MERKLE_HASH_BYTES..].copy_from_slice(&h);
        } else {
            cat[..MERKLE_HASH_BYTES].copy_from_slice(&h);
            cat[MERKLE_HASH_BYTES..].copy_from_slice(&sib[..MERKLE_HASH_BYTES.min(sib.len())]);
        }
        h = hf(&cat);
        let _ = idx;
    }
    h.as_slice() == root
}
