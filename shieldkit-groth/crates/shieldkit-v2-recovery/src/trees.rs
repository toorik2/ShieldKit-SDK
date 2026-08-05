use crate::{RecoveryError, Result, array32, canonical_fr_bytes};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, hash_map::Entry};

pub const TREE_DEPTH: usize = 32;
const TREE_CAPACITY: u64 = 1_u64 << TREE_DEPTH;

const NOTE_TREE_EMPTY: &str = "28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad";
const NOTE_TREE_NODE: &str = "06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153";
const NULLIFIER_TREE_LEAF: &str =
    "21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2";
const NULLIFIER_TREE_EMPTY: &str =
    "2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb";
const NULLIFIER_TREE_NODE: &str =
    "241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkTreeRoot {
    pub root: [u8; 32],
    pub allocated_leaves: usize,
    pub leaf_hash_calls: u64,
    pub node_hash_calls: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedTreeNode {
    pub depth: u8,
    pub node_index: u64,
    pub node_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedNoteTree {
    pub summary: BulkTreeRoot,
    pub nodes: Vec<MaterializedTreeNode>,
    pub frontier: Vec<MaterializedTreeNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedNullifierLeaf {
    pub physical_index: u64,
    pub leaf_type: u8,
    pub leaf_hash: [u8; 32],
    pub key: [u8; 32],
    pub successor_index: u64,
    pub successor_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedIndexedNullifierTree {
    pub summary: BulkTreeRoot,
    pub nodes: Vec<MaterializedTreeNode>,
    pub leaves: Vec<MaterializedNullifierLeaf>,
}

#[derive(Clone, Debug)]
pub struct NoteTree {
    defaults: Vec<Fr>,
    frontier: Vec<Option<Fr>>,
    nodes: HashMap<(usize, u64), Fr>,
    leaves: Vec<[u8; 32]>,
    root: Fr,
}

impl NoteTree {
    pub fn empty() -> Result<Self> {
        let empty_leaf = poseidon(&[domain(NOTE_TREE_EMPTY)?, Fr::from(0_u8)])?;
        let node_domain = domain(NOTE_TREE_NODE)?;
        let mut defaults = vec![empty_leaf];
        for level in 0..TREE_DEPTH {
            defaults.push(poseidon(&[node_domain, defaults[level], defaults[level]])?);
        }
        let root = defaults[TREE_DEPTH];
        Ok(Self {
            root,
            defaults,
            frontier: vec![None; TREE_DEPTH],
            nodes: HashMap::from([((TREE_DEPTH, 0), root)]),
            leaves: Vec::new(),
        })
    }

    pub fn append(&mut self, value: [u8; 32]) -> Result<()> {
        let mut node = canonical_fr_bytes(&value, "output note leaf")?;
        let index = u64::try_from(self.leaves.len())
            .map_err(|_| RecoveryError::new("note-tree index exceeds u64"))?;
        if index >= (1_u64 << TREE_DEPTH) {
            return Err(RecoveryError::new("note tree is full"));
        }
        self.nodes.insert((0, index), node);
        let node_domain = domain(NOTE_TREE_NODE)?;
        let mut cursor = index;
        for level in 0..TREE_DEPTH {
            let is_right = ((index >> level) & 1) == 1;
            let sibling = if is_right {
                self.frontier[level].ok_or_else(|| {
                    RecoveryError::new(format!("note-tree frontier is missing level {level}"))
                })?
            } else {
                self.defaults[level]
            };
            if !is_right {
                self.frontier[level] = Some(node);
            }
            node = if is_right {
                poseidon(&[node_domain, sibling, node])?
            } else {
                poseidon(&[node_domain, node, sibling])?
            };
            cursor >>= 1;
            self.nodes.insert((level + 1, cursor), node);
        }
        self.leaves.push(value);
        self.root = node;
        Ok(())
    }

    pub fn root_bytes(&self) -> Result<[u8; 32]> {
        fr_bytes(&self.root)
    }

    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    pub fn frontier_entry_count(&self) -> usize {
        self.frontier.iter().filter(|entry| entry.is_some()).count()
    }

    /// Export the exact authenticated prefix accumulated during raw replay.
    /// This performs no Poseidon hashing and does not replay any append path.
    pub fn materialized(&self) -> Result<MaterializedNoteTree> {
        let allocated = u64::try_from(self.leaves.len())
            .map_err(|_| RecoveryError::new("note leaf count exceeds u64"))?;
        let mut nodes = Vec::new();
        for depth in 0..=TREE_DEPTH {
            let width = allocated_width(allocated, depth)?;
            for node_index in 0..width {
                let node = self.nodes.get(&(depth, node_index)).ok_or_else(|| {
                    RecoveryError::new(format!(
                        "incremental note tree is missing allocated node {depth}:{node_index}"
                    ))
                })?;
                nodes.push(MaterializedTreeNode {
                    depth: depth as u8,
                    node_index,
                    node_hash: fr_bytes(node)?,
                });
            }
        }
        let mut frontier = Vec::with_capacity(allocated.count_ones() as usize);
        for (depth, entry) in self.frontier.iter().enumerate() {
            if ((allocated >> depth) & 1) == 1 {
                let node = entry.as_ref().ok_or_else(|| {
                    RecoveryError::new(format!(
                        "incremental note tree is missing active frontier depth {depth}"
                    ))
                })?;
                let node_index = (allocated >> depth)
                    .checked_sub(1)
                    .ok_or_else(|| RecoveryError::new("note frontier index underflowed"))?;
                frontier.push(MaterializedTreeNode {
                    depth: depth as u8,
                    node_index,
                    node_hash: fr_bytes(node)?,
                });
            }
        }
        Ok(MaterializedNoteTree {
            summary: BulkTreeRoot {
                root: fr_bytes(&self.root)?,
                allocated_leaves: self.leaves.len(),
                leaf_hash_calls: 0,
                node_hash_calls: 0,
            },
            nodes,
            frontier,
        })
    }
}

#[derive(Clone, Debug)]
pub struct IndexedNullifierTree {
    defaults: Vec<Fr>,
    nodes: HashMap<(usize, u64), Fr>,
    leaves: Vec<Leaf>,
    ordered: BTreeMap<[u8; 32], u64>,
    keys: Vec<[u8; 32]>,
    root: Fr,
}

#[derive(Clone, Debug)]
struct Leaf {
    kind: u8,
    index: u64,
    key: [u8; 32],
    successor_index: u64,
    successor_key: [u8; 32],
}

impl Leaf {
    fn empty() -> Self {
        Self {
            kind: 0,
            index: 0,
            key: [0; 32],
            successor_index: 0,
            successor_key: [0; 32],
        }
    }

    fn minimum() -> Self {
        Self {
            kind: 1,
            index: 0,
            key: [0; 32],
            successor_index: 1,
            successor_key: [0; 32],
        }
    }

    fn maximum() -> Self {
        Self {
            kind: 3,
            index: 1,
            key: [0; 32],
            successor_index: 1,
            successor_key: [0; 32],
        }
    }
}

impl IndexedNullifierTree {
    pub fn empty() -> Result<Self> {
        let empty_hash = hash_nullifier_leaf(&Leaf::empty())?;
        let node_domain = domain(NULLIFIER_TREE_NODE)?;
        let mut defaults = vec![empty_hash];
        for level in 0..TREE_DEPTH {
            defaults.push(poseidon(&[node_domain, defaults[level], defaults[level]])?);
        }
        let mut tree = Self {
            root: defaults[TREE_DEPTH],
            defaults,
            nodes: HashMap::new(),
            leaves: vec![Leaf::minimum(), Leaf::maximum()],
            ordered: BTreeMap::new(),
            keys: Vec::new(),
        };
        tree.replace_leaf(0)?;
        tree.replace_leaf(1)?;
        Ok(tree)
    }

    pub fn insert(&mut self, key: [u8; 32]) -> Result<()> {
        canonical_fr_bytes(&key, "public nullifier")?;
        if self.ordered.contains_key(&key) {
            return Err(RecoveryError::new("public nullifier is already present"));
        }
        let append_index = u64::try_from(self.leaves.len())
            .map_err(|_| RecoveryError::new("nullifier-tree index exceeds u64"))?;
        if append_index >= (1_u64 << TREE_DEPTH) {
            return Err(RecoveryError::new("indexed nullifier tree is full"));
        }
        let predecessor_index = self
            .ordered
            .range(..key)
            .next_back()
            .map_or(0, |(_, index)| *index);
        let predecessor_position = usize::try_from(predecessor_index)
            .map_err(|_| RecoveryError::new("predecessor index exceeds this platform"))?;
        let predecessor = self.leaves[predecessor_position].clone();
        let new_leaf = Leaf {
            kind: 2,
            index: append_index,
            key,
            successor_index: predecessor.successor_index,
            successor_key: predecessor.successor_key,
        };
        self.leaves[predecessor_position].successor_index = append_index;
        self.leaves[predecessor_position].successor_key = key;
        self.replace_leaf(predecessor_index)?;
        self.leaves.push(new_leaf);
        self.replace_leaf(append_index)?;
        self.ordered.insert(key, append_index);
        self.keys.push(key);
        Ok(())
    }

    fn replace_leaf(&mut self, index: u64) -> Result<()> {
        let position = usize::try_from(index)
            .map_err(|_| RecoveryError::new("leaf index exceeds this platform"))?;
        let mut node = hash_nullifier_leaf(
            self.leaves
                .get(position)
                .ok_or_else(|| RecoveryError::new("leaf index is not allocated"))?,
        )?;
        if node == self.defaults[0] {
            self.nodes.remove(&(0, index));
        } else {
            self.nodes.insert((0, index), node);
        }
        let node_domain = domain(NULLIFIER_TREE_NODE)?;
        let mut cursor = index;
        for level in 0..TREE_DEPTH {
            let sibling_index = cursor ^ 1;
            let sibling = self
                .nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or(self.defaults[level]);
            node = if cursor & 1 == 0 {
                poseidon(&[node_domain, node, sibling])?
            } else {
                poseidon(&[node_domain, sibling, node])?
            };
            cursor >>= 1;
            if node == self.defaults[level + 1] {
                self.nodes.remove(&(level + 1, cursor));
            } else {
                self.nodes.insert((level + 1, cursor), node);
            }
        }
        self.root = node;
        Ok(())
    }

    pub fn root_bytes(&self) -> Result<[u8; 32]> {
        fr_bytes(&self.root)
    }

    pub fn keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    pub fn authenticated_node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Export all allocated authenticated nodes and successor leaves retained
    /// during raw replay without computing another Poseidon hash.
    pub fn materialized(&self) -> Result<MaterializedIndexedNullifierTree> {
        let allocated = u64::try_from(self.leaves.len())
            .map_err(|_| RecoveryError::new("nullifier leaf count exceeds u64"))?;
        let mut nodes = Vec::new();
        for depth in 0..=TREE_DEPTH {
            let width = allocated_width(allocated, depth)?;
            for node_index in 0..width {
                let node = self
                    .nodes
                    .get(&(depth, node_index))
                    .unwrap_or(&self.defaults[depth]);
                nodes.push(MaterializedTreeNode {
                    depth: depth as u8,
                    node_index,
                    node_hash: fr_bytes(node)?,
                });
            }
        }
        let leaves = self
            .leaves
            .iter()
            .map(|leaf| {
                let leaf_hash = self
                    .nodes
                    .get(&(0, leaf.index))
                    .unwrap_or(&self.defaults[0]);
                Ok(MaterializedNullifierLeaf {
                    physical_index: leaf.index,
                    leaf_type: leaf.kind,
                    leaf_hash: fr_bytes(leaf_hash)?,
                    key: leaf.key,
                    successor_index: leaf.successor_index,
                    successor_key: leaf.successor_key,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(MaterializedIndexedNullifierTree {
            summary: BulkTreeRoot {
                root: fr_bytes(&self.root)?,
                allocated_leaves: self.leaves.len(),
                leaf_hash_calls: 0,
                node_hash_calls: 0,
            },
            nodes,
            leaves,
        })
    }
}

fn allocated_width(allocated_leaves: u64, depth: usize) -> Result<u64> {
    if depth > TREE_DEPTH {
        return Err(RecoveryError::new("tree depth exceeds the pinned depth"));
    }
    if depth == TREE_DEPTH {
        return Ok(1);
    }
    let divisor = 1_u64 << depth;
    Ok(allocated_leaves.div_ceil(divisor))
}

fn fold_allocated_prefix(
    mut layer: Vec<Fr>,
    defaults: &[Fr],
    node_domain: Fr,
) -> Result<(Fr, u64)> {
    if layer.is_empty() {
        return Ok((defaults[TREE_DEPTH], 0));
    }
    let mut node_hash_calls = 0_u64;
    for default in defaults.iter().take(TREE_DEPTH) {
        let mut parents = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(*default);
            parents.push(poseidon(&[node_domain, left, right])?);
            node_hash_calls = node_hash_calls
                .checked_add(1)
                .ok_or_else(|| RecoveryError::new("bulk tree hash count overflowed"))?;
        }
        layer = parents;
    }
    if layer.len() != 1 {
        return Err(RecoveryError::new(
            "bulk tree reconstruction did not converge to one root",
        ));
    }
    Ok((layer[0], node_hash_calls))
}

fn materialize_allocated_prefix(
    mut layer: Vec<Fr>,
    allocated_leaves: u64,
    defaults: &[Fr],
    node_domain: Fr,
) -> Result<(
    Fr,
    u64,
    Vec<MaterializedTreeNode>,
    Vec<MaterializedTreeNode>,
)> {
    if layer.is_empty() {
        return Ok((
            defaults[TREE_DEPTH],
            0,
            vec![MaterializedTreeNode {
                depth: TREE_DEPTH as u8,
                node_index: 0,
                node_hash: fr_bytes(&defaults[TREE_DEPTH])?,
            }],
            Vec::new(),
        ));
    }
    let estimated_nodes = layer
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(TREE_DEPTH))
        .ok_or_else(|| RecoveryError::new("materialized tree node capacity overflowed"))?;
    let mut nodes = Vec::with_capacity(estimated_nodes);
    let mut frontier = Vec::with_capacity(TREE_DEPTH);
    let mut node_hash_calls = 0_u64;
    for (level, default) in defaults.iter().enumerate().take(TREE_DEPTH) {
        for (node_index, node) in layer.iter().enumerate() {
            nodes.push(MaterializedTreeNode {
                depth: level as u8,
                node_index: u64::try_from(node_index)
                    .map_err(|_| RecoveryError::new("tree node index exceeds u64"))?,
                node_hash: fr_bytes(node)?,
            });
        }
        if ((allocated_leaves >> level) & 1) == 1 {
            let frontier_index = (allocated_leaves >> level)
                .checked_sub(1)
                .ok_or_else(|| RecoveryError::new("note frontier index underflowed"))?;
            let position = usize::try_from(frontier_index)
                .map_err(|_| RecoveryError::new("note frontier index exceeds this platform"))?;
            let node = layer.get(position).ok_or_else(|| {
                RecoveryError::new(format!(
                    "materialized note frontier is missing level {level}"
                ))
            })?;
            frontier.push(MaterializedTreeNode {
                depth: level as u8,
                node_index: frontier_index,
                node_hash: fr_bytes(node)?,
            });
        }
        let mut parents = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(*default);
            parents.push(poseidon(&[node_domain, left, right])?);
            node_hash_calls = node_hash_calls
                .checked_add(1)
                .ok_or_else(|| RecoveryError::new("materialized tree hash count overflowed"))?;
        }
        layer = parents;
    }
    if layer.len() != 1 {
        return Err(RecoveryError::new(
            "materialized tree reconstruction did not converge to one root",
        ));
    }
    nodes.push(MaterializedTreeNode {
        depth: TREE_DEPTH as u8,
        node_index: 0,
        node_hash: fr_bytes(&layer[0])?,
    });
    Ok((layer[0], node_hash_calls, nodes, frontier))
}

fn bulk_defaults(empty_leaf: Fr, node_domain: Fr) -> Result<(Vec<Fr>, u64)> {
    let mut defaults = vec![empty_leaf];
    let mut node_hash_calls = 0_u64;
    for level in 0..TREE_DEPTH {
        defaults.push(poseidon(&[node_domain, defaults[level], defaults[level]])?);
        node_hash_calls += 1;
    }
    Ok((defaults, node_hash_calls))
}

/// Reconstruct the terminal note root directly from the allocated append
/// prefix. Each final tree node is hashed once; historical append paths are not
/// replayed.
pub fn bulk_note_root(leaves: &[[u8; 32]]) -> Result<BulkTreeRoot> {
    let count = u64::try_from(leaves.len())
        .map_err(|_| RecoveryError::new("note leaf count exceeds u64"))?;
    if count > TREE_CAPACITY {
        return Err(RecoveryError::new("note tree is full"));
    }
    let empty_leaf = poseidon(&[domain(NOTE_TREE_EMPTY)?, Fr::from(0_u8)])?;
    let node_domain = domain(NOTE_TREE_NODE)?;
    let (defaults, default_hash_calls) = bulk_defaults(empty_leaf, node_domain)?;
    let layer = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| canonical_fr_bytes(leaf, &format!("note leaf {index}")))
        .collect::<Result<Vec<_>>>()?;
    let (root, tree_hash_calls) = fold_allocated_prefix(layer, &defaults, node_domain)?;
    Ok(BulkTreeRoot {
        root: fr_bytes(&root)?,
        allocated_leaves: leaves.len(),
        leaf_hash_calls: 1,
        node_hash_calls: default_hash_calls
            .checked_add(tree_hash_calls)
            .ok_or_else(|| RecoveryError::new("bulk note hash count overflowed"))?,
    })
}

/// Reconstruct the terminal note tree once and retain every allocated node plus
/// the minimal frontier needed by the next append. No historical append path is
/// replayed.
pub fn materialize_note_tree(leaves: &[[u8; 32]]) -> Result<MaterializedNoteTree> {
    let count = u64::try_from(leaves.len())
        .map_err(|_| RecoveryError::new("note leaf count exceeds u64"))?;
    if count > TREE_CAPACITY {
        return Err(RecoveryError::new("note tree is full"));
    }
    let empty_leaf = poseidon(&[domain(NOTE_TREE_EMPTY)?, Fr::from(0_u8)])?;
    let node_domain = domain(NOTE_TREE_NODE)?;
    let (defaults, default_hash_calls) = bulk_defaults(empty_leaf, node_domain)?;
    let layer = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| canonical_fr_bytes(leaf, &format!("note leaf {index}")))
        .collect::<Result<Vec<_>>>()?;
    let (root, tree_hash_calls, nodes, frontier) =
        materialize_allocated_prefix(layer, count, &defaults, node_domain)?;
    Ok(MaterializedNoteTree {
        summary: BulkTreeRoot {
            root: fr_bytes(&root)?,
            allocated_leaves: leaves.len(),
            leaf_hash_calls: 1,
            node_hash_calls: default_hash_calls
                .checked_add(tree_hash_calls)
                .ok_or_else(|| RecoveryError::new("materialized note hash count overflowed"))?,
        },
        nodes,
        frontier,
    })
}

fn indexed_nullifier_leaves(keys: &[[u8; 32]]) -> Result<Vec<Leaf>> {
    let count = u64::try_from(keys.len())
        .map_err(|_| RecoveryError::new("nullifier key count exceeds u64"))?;
    if count > TREE_CAPACITY - 2 {
        return Err(RecoveryError::new("indexed nullifier tree is full"));
    }
    let mut ordered = BTreeMap::<[u8; 32], u64>::new();
    for (offset, key) in keys.iter().enumerate() {
        canonical_fr_bytes(key, &format!("nullifier key {offset}"))?;
        let physical_index = u64::try_from(offset)
            .ok()
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| RecoveryError::new("nullifier physical index overflowed"))?;
        if ordered.insert(*key, physical_index).is_some() {
            return Err(RecoveryError::new("public nullifier is already present"));
        }
    }

    let allocated = keys
        .len()
        .checked_add(2)
        .ok_or_else(|| RecoveryError::new("nullifier allocated leaf count overflowed"))?;
    let mut successors = vec![1_u64; allocated];
    let mut successor_keys = vec![[0_u8; 32]; allocated];
    let mut predecessor = 0_u64;
    for (key, physical_index) in &ordered {
        let predecessor_index = usize::try_from(predecessor)
            .map_err(|_| RecoveryError::new("predecessor index exceeds this platform"))?;
        successors[predecessor_index] = *physical_index;
        successor_keys[predecessor_index] = *key;
        predecessor = *physical_index;
    }

    let mut leaves = Vec::with_capacity(allocated);
    for physical_index in 0..allocated {
        let leaf = match physical_index {
            0 => Leaf {
                successor_index: successors[0],
                successor_key: successor_keys[0],
                ..Leaf::minimum()
            },
            1 => Leaf::maximum(),
            _ => Leaf {
                kind: 2,
                index: u64::try_from(physical_index)
                    .map_err(|_| RecoveryError::new("leaf index exceeds u64"))?,
                key: keys[physical_index - 2],
                successor_index: successors[physical_index],
                successor_key: successor_keys[physical_index],
            },
        };
        leaves.push(leaf);
    }
    Ok(leaves)
}

/// Reconstruct the terminal indexed-nullifier root from keys in physical
/// insertion order. Successor links are derived independently by canonical key
/// order, then each allocated leaf and final sparse-tree node is hashed once.
pub fn bulk_indexed_nullifier_root(keys: &[[u8; 32]]) -> Result<BulkTreeRoot> {
    let leaves = indexed_nullifier_leaves(keys)?;
    let allocated = leaves.len();
    let empty_hash = hash_nullifier_leaf(&Leaf::empty())?;
    let node_domain = domain(NULLIFIER_TREE_NODE)?;
    let (defaults, default_hash_calls) = bulk_defaults(empty_hash, node_domain)?;
    let leaf_hashes = leaves
        .iter()
        .map(hash_nullifier_leaf)
        .collect::<Result<Vec<_>>>()?;
    let (root, tree_hash_calls) = fold_allocated_prefix(leaf_hashes, &defaults, node_domain)?;
    Ok(BulkTreeRoot {
        root: fr_bytes(&root)?,
        allocated_leaves: allocated,
        leaf_hash_calls: u64::try_from(allocated)
            .map_err(|_| RecoveryError::new("nullifier leaf hash count exceeds u64"))?
            .checked_add(1)
            .ok_or_else(|| RecoveryError::new("nullifier leaf hash count overflowed"))?,
        node_hash_calls: default_hash_calls
            .checked_add(tree_hash_calls)
            .ok_or_else(|| RecoveryError::new("bulk nullifier hash count overflowed"))?,
    })
}

/// Reconstruct the terminal indexed-nullifier tree once and retain its
/// authenticated nodes plus the exact sentinel/normal successor leaves. The
/// ordered predecessor index can be populated directly from these leaves.
pub fn materialize_indexed_nullifier_tree(
    keys: &[[u8; 32]],
) -> Result<MaterializedIndexedNullifierTree> {
    let leaves = indexed_nullifier_leaves(keys)?;
    let allocated = leaves.len();
    let empty_hash = hash_nullifier_leaf(&Leaf::empty())?;
    let node_domain = domain(NULLIFIER_TREE_NODE)?;
    let (defaults, default_hash_calls) = bulk_defaults(empty_hash, node_domain)?;
    let leaf_hashes = leaves
        .iter()
        .map(hash_nullifier_leaf)
        .collect::<Result<Vec<_>>>()?;
    let allocated_u64 = u64::try_from(allocated)
        .map_err(|_| RecoveryError::new("nullifier allocated leaf count exceeds u64"))?;
    let (root, tree_hash_calls, nodes, _) =
        materialize_allocated_prefix(leaf_hashes.clone(), allocated_u64, &defaults, node_domain)?;
    let materialized_leaves = leaves
        .iter()
        .zip(leaf_hashes.iter())
        .map(|(leaf, leaf_hash)| {
            Ok(MaterializedNullifierLeaf {
                physical_index: leaf.index,
                leaf_type: leaf.kind,
                leaf_hash: fr_bytes(leaf_hash)?,
                key: leaf.key,
                successor_index: leaf.successor_index,
                successor_key: leaf.successor_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(MaterializedIndexedNullifierTree {
        summary: BulkTreeRoot {
            root: fr_bytes(&root)?,
            allocated_leaves: allocated,
            leaf_hash_calls: allocated_u64
                .checked_add(1)
                .ok_or_else(|| RecoveryError::new("nullifier leaf hash count overflowed"))?,
            node_hash_calls: default_hash_calls
                .checked_add(tree_hash_calls)
                .ok_or_else(|| {
                    RecoveryError::new("materialized nullifier hash count overflowed")
                })?,
        },
        nodes,
        leaves: materialized_leaves,
    })
}

fn hash_nullifier_leaf(leaf: &Leaf) -> Result<Fr> {
    if leaf.kind == 0 {
        return poseidon(&[domain(NULLIFIER_TREE_EMPTY)?, Fr::from(0_u8)]);
    }
    poseidon(&[
        domain(NULLIFIER_TREE_LEAF)?,
        Fr::from(leaf.kind),
        Fr::from(leaf.index),
        canonical_fr_bytes(&leaf.key, "indexed nullifier key")?,
        Fr::from(leaf.successor_index),
        canonical_fr_bytes(&leaf.successor_key, "indexed nullifier successor key")?,
    ])
}

thread_local! {
    // `Poseidon::new_circom` materializes the complete round-constant and MDS
    // parameter set. Rebuilding it for every tree node dominates replay time.
    // The hasher clears its state after each `hash` call, so one instance per
    // arity and thread is deterministic and safe to reuse.
    static POSEIDON_HASHERS: RefCell<HashMap<usize, Poseidon<Fr>>> =
        RefCell::new(HashMap::new());
}

fn poseidon(inputs: &[Fr]) -> Result<Fr> {
    POSEIDON_HASHERS.with(|hashers| {
        let mut hashers = hashers.borrow_mut();
        if let Entry::Vacant(entry) = hashers.entry(inputs.len()) {
            let hasher = Poseidon::<Fr>::new_circom(inputs.len()).map_err(|_| {
                RecoveryError::new("profile-pinned Poseidon parameters are unavailable")
            })?;
            entry.insert(hasher);
        }
        hashers
            .get_mut(&inputs.len())
            .ok_or_else(|| RecoveryError::new("profile-pinned Poseidon hasher is unavailable"))?
            .hash(inputs)
            .map_err(|_| RecoveryError::new("profile-pinned Poseidon hashing failed"))
    })
}

fn domain(value: &str) -> Result<Fr> {
    let bytes = hex::decode(value)
        .map_err(|_| RecoveryError::new("internal Poseidon domain is not hexadecimal"))?;
    canonical_fr_bytes(&array32(&bytes, "Poseidon domain")?, "Poseidon domain")
}

fn fr_bytes(value: &Fr) -> Result<[u8; 32]> {
    let encoded = value.into_bigint().to_bytes_be();
    if encoded.len() > 32 {
        return Err(RecoveryError::new(
            "Poseidon result exceeds the canonical field width",
        ));
    }
    let mut bytes = [0_u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roots_match_the_frozen_javascript_reference() {
        assert_eq!(
            hex::encode(
                NoteTree::empty()
                    .expect("note tree")
                    .root_bytes()
                    .expect("root")
            ),
            "1b5e3c7f6833e4d1b8f321410d27dcbe695474e9a98c25f8976af85378a32c98"
        );
        assert_eq!(
            hex::encode(
                IndexedNullifierTree::empty()
                    .expect("nullifier tree")
                    .root_bytes()
                    .expect("root")
            ),
            "1bffbaa6bb28b38e9d7fe374d9b7ba4df4bb661c8b16aecb4ffe68a22301e6ec"
        );
    }

    #[test]
    fn duplicate_nullifier_is_rejected() {
        let mut tree = IndexedNullifierTree::empty().expect("tree");
        let key = array32(
            &hex::decode("0000000000000000000000000000000000000000000000000000000000000007")
                .expect("hex"),
            "key",
        )
        .expect("array");
        tree.insert(key).expect("first");
        assert!(
            tree.insert(key)
                .expect_err("duplicate")
                .to_string()
                .contains("already")
        );
    }

    #[test]
    fn nonempty_roots_match_the_frozen_javascript_reference() {
        let mut notes = NoteTree::empty().expect("note tree");
        let mut note_leaves = Vec::new();
        for (leaf, expected) in [
            (
                5_u8,
                "2fdd802a2dbaedbaa588e5e9158f9de9f8971561cf3007d74e3e5f1a812d27ad",
            ),
            (
                6_u8,
                "23e6c04a8c300a03d2b239b5678476b1c0cb4d698bc5e775287b1668d9fb9e1b",
            ),
        ] {
            let mut encoded = [0_u8; 32];
            encoded[31] = leaf;
            notes.append(encoded).expect("append");
            note_leaves.push(encoded);
            assert_eq!(
                hex::encode(notes.root_bytes().expect("note root")),
                expected
            );
            assert_eq!(
                bulk_note_root(&note_leaves).expect("bulk note root").root,
                notes.root_bytes().expect("incremental note root")
            );
        }

        let mut nullifiers = IndexedNullifierTree::empty().expect("nullifier tree");
        let mut nullifier_keys = Vec::new();
        for (key, expected) in [
            (
                8_u8,
                "2f91dee4ccd5fd4b4c5374126b3e4eb1151417d84ac5be667f6f5178dd8d50d3",
            ),
            (
                9_u8,
                "13b7222d10f4508443ac35390bb1a5b72ba5a9f3cbad27ecb200af2e71d179fc",
            ),
        ] {
            let mut encoded = [0_u8; 32];
            encoded[31] = key;
            nullifiers.insert(encoded).expect("insert");
            nullifier_keys.push(encoded);
            assert_eq!(
                hex::encode(nullifiers.root_bytes().expect("nullifier root")),
                expected
            );
            assert_eq!(
                bulk_indexed_nullifier_root(&nullifier_keys)
                    .expect("bulk nullifier root")
                    .root,
                nullifiers.root_bytes().expect("incremental nullifier root")
            );
        }
    }

    #[test]
    fn bulk_reconstruction_matches_incremental_edges_and_insertion_orders() {
        let mut note_tree = NoteTree::empty().expect("note tree");
        let mut nullifier_tree = IndexedNullifierTree::empty().expect("nullifier tree");
        let mut note_leaves = Vec::new();
        let mut nullifier_keys = Vec::new();
        let mut fr_minus_one = shieldkit_v2_codec::BN254_FR_MODULUS;
        fr_minus_one[31] -= 1;
        for (index, key) in [
            [0_u8; 32],
            fr_minus_one,
            {
                let mut value = [0_u8; 32];
                value[31] = 7;
                value
            },
            {
                let mut value = [0_u8; 32];
                value[31] = 2;
                value
            },
            {
                let mut value = [0_u8; 32];
                value[31] = 201;
                value
            },
        ]
        .into_iter()
        .enumerate()
        {
            let mut note = [0_u8; 32];
            note[30..]
                .copy_from_slice(&u16::try_from(index + 1).expect("small index").to_be_bytes());
            note_tree.append(note).expect("note append");
            nullifier_tree.insert(key).expect("nullifier insert");
            note_leaves.push(note);
            nullifier_keys.push(key);
            assert_eq!(
                bulk_note_root(&note_leaves).expect("bulk note root").root,
                note_tree.root_bytes().expect("note root")
            );
            assert_eq!(
                bulk_indexed_nullifier_root(&nullifier_keys)
                    .expect("bulk nullifier root")
                    .root,
                nullifier_tree.root_bytes().expect("nullifier root")
            );
            let incremental_notes = note_tree.materialized().expect("incremental note material");
            let bottom_up_notes =
                materialize_note_tree(&note_leaves).expect("bottom-up note material");
            assert_eq!(incremental_notes.nodes, bottom_up_notes.nodes);
            assert_eq!(incremental_notes.frontier, bottom_up_notes.frontier);
            let incremental_nullifiers = nullifier_tree
                .materialized()
                .expect("incremental nullifier material");
            let bottom_up_nullifiers = materialize_indexed_nullifier_tree(&nullifier_keys)
                .expect("bottom-up nullifier material");
            assert_eq!(incremental_nullifiers.nodes, bottom_up_nullifiers.nodes);
            assert_eq!(incremental_nullifiers.leaves, bottom_up_nullifiers.leaves);
        }
        assert!(
            bulk_indexed_nullifier_root(&[nullifier_keys[0], nullifier_keys[0]])
                .expect_err("duplicate")
                .to_string()
                .contains("already")
        );
        let mut noncanonical = shieldkit_v2_codec::BN254_FR_MODULUS;
        assert!(bulk_note_root(&[noncanonical]).is_err());
        assert!(bulk_indexed_nullifier_root(&[noncanonical]).is_err());
        noncanonical.fill(0xff);
        assert!(bulk_note_root(&[noncanonical]).is_err());
    }

    #[test]
    fn bottom_up_materialization_retains_nodes_frontier_and_successor_order() {
        let note_leaves = (1_u8..=5)
            .map(|value| {
                let mut leaf = [0_u8; 32];
                leaf[31] = value;
                leaf
            })
            .collect::<Vec<_>>();
        let notes = materialize_note_tree(&note_leaves).expect("materialized note tree");
        assert_eq!(
            notes.summary,
            bulk_note_root(&note_leaves).expect("bulk note tree")
        );
        assert_eq!(
            notes.nodes.last().expect("note root node"),
            &MaterializedTreeNode {
                depth: TREE_DEPTH as u8,
                node_index: 0,
                node_hash: notes.summary.root,
            }
        );
        assert_eq!(
            notes
                .frontier
                .iter()
                .map(|entry| entry.depth)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );

        let nullifier_keys = [9_u8, 2, 7, 0, 5]
            .map(|value| {
                let mut key = [0_u8; 32];
                key[31] = value;
                key
            })
            .to_vec();
        let nullifiers = materialize_indexed_nullifier_tree(&nullifier_keys)
            .expect("materialized nullifier tree");
        assert_eq!(
            nullifiers.summary,
            bulk_indexed_nullifier_root(&nullifier_keys).expect("bulk nullifier tree")
        );
        assert_eq!(nullifiers.leaves.len(), nullifier_keys.len() + 2);
        assert_eq!(
            nullifiers.nodes.last().expect("nullifier root node"),
            &MaterializedTreeNode {
                depth: TREE_DEPTH as u8,
                node_index: 0,
                node_hash: nullifiers.summary.root,
            }
        );
        for (offset, key) in nullifier_keys.iter().enumerate() {
            let leaf = &nullifiers.leaves[offset + 2];
            assert_eq!(leaf.physical_index, (offset + 2) as u64);
            assert_eq!(leaf.leaf_type, 2);
            assert_eq!(&leaf.key, key);
        }
        let mut ordered = Vec::new();
        let mut cursor = nullifiers.leaves[0].successor_index;
        while cursor != 1 {
            let leaf = &nullifiers.leaves[cursor as usize];
            ordered.push(leaf.key);
            cursor = leaf.successor_index;
        }
        let mut expected = nullifier_keys.clone();
        expected.sort();
        assert_eq!(ordered, expected);
    }
}
