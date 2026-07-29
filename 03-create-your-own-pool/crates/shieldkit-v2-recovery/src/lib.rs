#![forbid(unsafe_code)]

pub mod bch;
pub mod stream;
pub mod trees;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use bch::{
    MAX_STANDARD_TRANSACTION_BYTES, MAX_STANDARD_UNLOCK_BYTES, Output, Transaction, hash256,
    parse_transaction_hex,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shieldkit_v2_codec::{
    ActionKindV2, BN254_FR_MODULUS, DirectActionPacketV2, DirectV2ContextInput,
    DirectV2ContextOutput, DirectV2Role, DirectV2RoleKind, DirectV2TransactionContext, PoolStateV2,
};
use std::collections::{HashMap, HashSet};
use std::fmt;
use trees::{
    IndexedNullifierTree, MaterializedIndexedNullifierTree, MaterializedNoteTree, NoteTree,
    TREE_DEPTH, materialize_indexed_nullifier_tree, materialize_note_tree,
};

pub const SCAN_SCHEMA: &str = "shieldkit-v2-recovery-scan-v2";
pub const SCAN_RESULT_SCHEMA: &str = "shieldkit-v2-recovery-scan-result-v2";
pub const VERIFY_SCHEMA: &str = "shieldkit-v2-recovery-verify-v2";
pub const AUTHENTICATE_SNAPSHOT_SCHEMA: &str = "shieldkit-v2-recovery-authenticate-snapshot-v2";
pub const AUTHENTICATED_MATERIAL_SCHEMA: &str = "shieldkit-v2-recovery-authenticated-material-v2";
pub const SNAPSHOT_SCHEMA: &str = "shieldkit-v2-recovery-snapshot-v2";
pub const POSEIDON_PROFILE: &str = "shieldkit-pool-action-v2-direct-poseidon-v1";
pub const EXTERNAL_AUTHENTICATION_BOUNDARY: &str = "Caller must authenticate profile artifacts, active-best-chain block inclusion, confirmations, and reorg status; snapshot hashes or signatures are provenance only, never consensus.";

pub type Result<T> = std::result::Result<T, RecoveryError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryError {
    message: String,
}

impl RecoveryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RecoveryError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanRequest {
    pub schema: String,
    pub network_id: u8,
    pub profile_id: String,
    pub instance_id: String,
    pub denomination_sats: String,
    pub carrier_count: u8,
    pub runtime_materials_sha256: String,
    pub genesis: AnchoredRawTransaction,
    pub genesis_outpoint: DisplayOutpoint,
    pub initial_state_hex: String,
    pub actions: Vec<AnchoredRawTransaction>,
    pub funding_prevouts: Vec<AuthenticatedSourceTransaction>,
    pub expected_tip: ExpectedTip,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamingScanRequestHeader {
    pub network_id: u8,
    pub profile_id: String,
    pub instance_id: String,
    pub denomination_sats: String,
    pub carrier_count: u8,
    pub runtime_materials_sha256: String,
    pub genesis: AnchoredRawTransaction,
    pub genesis_outpoint: DisplayOutpoint,
    pub initial_state_hex: String,
    pub expected_tip: ExpectedTip,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnchoredRawTransaction {
    pub transaction_id: String,
    pub raw_transaction: String,
    pub height: u32,
    pub block_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedSourceTransaction {
    pub transaction_id: String,
    pub raw_transaction: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisplayOutpoint {
    pub transaction_id: String,
    pub output_index: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedTip {
    pub transaction_id: String,
    pub output_index: u32,
    pub height: u32,
    pub block_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifySnapshotRequest {
    pub schema: String,
    pub scan: ScanRequest,
    pub snapshot: RecoverySnapshot,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticateSnapshotRequest {
    pub schema: String,
    pub network_id: u8,
    pub profile_id: String,
    pub instance_id: String,
    pub denomination_sats: String,
    pub carrier_count: u8,
    pub runtime_materials_sha256: String,
    pub genesis: SnapshotPoint,
    pub tip: SnapshotPoint,
    pub snapshot: RecoverySnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoverySnapshot {
    pub schema: String,
    pub version: u8,
    pub network_id: u8,
    pub profile_id: String,
    pub instance_id: String,
    pub denomination_sats: String,
    pub carrier_count: u8,
    pub runtime_materials_sha256: String,
    pub poseidon_profile: String,
    pub genesis: SnapshotPoint,
    pub tip: SnapshotPoint,
    pub action_count: String,
    pub history_sha256: String,
    pub state_hex: String,
    pub note_tree: NoteTreeSnapshot,
    pub nullifier_tree: NullifierTreeSnapshot,
    pub actions: Vec<ActionSnapshot>,
    pub external_authentication_boundary: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotPoint {
    pub transaction_id: String,
    pub output_index: u32,
    pub height: u32,
    pub block_hash: String,
    pub state_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoteTreeSnapshot {
    pub depth: u8,
    pub count: String,
    pub root: String,
    pub leaves: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NullifierTreeSnapshot {
    pub depth: u8,
    pub count: String,
    pub root: String,
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionSnapshot {
    pub transaction_id: String,
    pub height: u32,
    pub block_hash: String,
    pub kind: String,
    pub packet_hex: String,
    pub transaction_context_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedSnapshotResult {
    pub schema: String,
    pub content_sha256: String,
    pub binding: AuthenticatedSnapshotBinding,
    pub canonical: AuthenticatedCanonicalState,
    pub note_nodes: Vec<AuthenticatedTreeNode>,
    pub note_frontier: Vec<AuthenticatedTreeFrontier>,
    pub note_leaves: Vec<AuthenticatedNoteLeaf>,
    pub nullifier_nodes: Vec<AuthenticatedTreeNode>,
    pub nullifier_leaves: Vec<AuthenticatedNullifierLeaf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedSnapshotBinding {
    pub profile_id: String,
    pub instance_id: String,
    pub network_id: u8,
    pub denomination_sats: String,
    pub carrier_count: u8,
    pub runtime_materials_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedCanonicalState {
    pub state: String,
    pub outpoint: AuthenticatedOutpoint,
    pub action_sequence: u64,
    pub height: u32,
    pub block_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedOutpoint {
    pub txid: String,
    pub vout: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedTreeNode {
    pub depth: u8,
    pub node_index: u64,
    pub node_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedTreeFrontier {
    pub depth: u8,
    pub node_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedNoteLeaf {
    pub note_index: u32,
    pub leaf_hash: String,
    pub encrypted_record: String,
    pub action_sequence: u64,
    pub transaction_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedNullifierLeaf {
    pub physical_index: u64,
    pub leaf_type: u8,
    pub leaf_hash: String,
    pub key: String,
    pub successor_index: u64,
    pub successor_key: String,
}

struct AuthenticatedTreeMaterial {
    note_tree: MaterializedNoteTree,
    nullifier_tree: MaterializedIndexedNullifierTree,
    note_leaves: Vec<AuthenticatedNoteLeaf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryScanResult {
    pub schema: String,
    pub snapshot: RecoverySnapshot,
    pub material: AuthenticatedSnapshotResult,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotUnsigned<'a> {
    schema: &'a str,
    version: u8,
    network_id: u8,
    profile_id: &'a str,
    instance_id: &'a str,
    denomination_sats: &'a str,
    carrier_count: u8,
    runtime_materials_sha256: &'a str,
    poseidon_profile: &'a str,
    genesis: &'a SnapshotPoint,
    tip: &'a SnapshotPoint,
    action_count: &'a str,
    history_sha256: &'a str,
    state_hex: &'a str,
    note_tree: &'a NoteTreeSnapshot,
    nullifier_tree: &'a NullifierTreeSnapshot,
    actions: &'a [ActionSnapshot],
    external_authentication_boundary: &'a str,
}

impl RecoverySnapshot {
    fn unsigned(&self) -> SnapshotUnsigned<'_> {
        SnapshotUnsigned {
            schema: &self.schema,
            version: self.version,
            network_id: self.network_id,
            profile_id: &self.profile_id,
            instance_id: &self.instance_id,
            denomination_sats: &self.denomination_sats,
            carrier_count: self.carrier_count,
            runtime_materials_sha256: &self.runtime_materials_sha256,
            poseidon_profile: &self.poseidon_profile,
            genesis: &self.genesis,
            tip: &self.tip,
            action_count: &self.action_count,
            history_sha256: &self.history_sha256,
            state_hex: &self.state_hex,
            note_tree: &self.note_tree,
            nullifier_tree: &self.nullifier_tree,
            actions: &self.actions,
            external_authentication_boundary: &self.external_authentication_boundary,
        }
    }

    pub fn recompute_content_sha256(&self) -> Result<String> {
        sha256_json(&self.unsigned())
    }

    fn refresh_hash(&mut self) -> Result<()> {
        self.content_sha256 = self.recompute_content_sha256()?;
        Ok(())
    }

    pub fn authenticate_structure(&self) -> Result<()> {
        self.authenticate_and_materialize().map(|_| ())
    }

    fn authenticate_and_materialize(&self) -> Result<AuthenticatedTreeMaterial> {
        if self.schema != SNAPSHOT_SCHEMA
            || self.version != 2
            || self.poseidon_profile != POSEIDON_PROFILE
            || self.external_authentication_boundary != EXTERNAL_AUTHENTICATION_BOUNDARY
        {
            return Err(RecoveryError::new(
                "snapshot schema, version, Poseidon profile, or authentication boundary differs",
            ));
        }
        let expected_hash = sha256_json(&self.unsigned())?;
        if self.content_sha256 != expected_hash {
            return Err(RecoveryError::new(
                "snapshot contentSha256 authentication failed",
            ));
        }
        validate_network(self.network_id)?;
        identifier(&self.profile_id, "snapshot profileId")?;
        identifier(&self.instance_id, "snapshot instanceId")?;
        identifier(
            &self.runtime_materials_sha256,
            "snapshot runtimeMaterialsSha256",
        )?;
        canonical_decimal(&self.denomination_sats, "snapshot denominationSats")?;
        if self.carrier_count == 0 {
            return Err(RecoveryError::new(
                "snapshot carrierCount must be from 1 to 255",
            ));
        }
        validate_snapshot_point(&self.genesis, "snapshot genesis")?;
        validate_snapshot_point(&self.tip, "snapshot tip")?;
        if self.genesis.output_index != 0 || self.tip.output_index != 0 {
            return Err(RecoveryError::new(
                "snapshot genesis and tip must bind output 0",
            ));
        }
        if self.note_tree.depth != TREE_DEPTH as u8 || self.nullifier_tree.depth != TREE_DEPTH as u8
        {
            return Err(RecoveryError::new(
                "snapshot tree depth differs from the profile-pinned depth 32",
            ));
        }
        let action_count = canonical_decimal(&self.action_count, "snapshot actionCount")?;
        if action_count
            != u64::try_from(self.actions.len())
                .map_err(|_| RecoveryError::new("snapshot action count exceeds u64"))?
        {
            return Err(RecoveryError::new(
                "snapshot actionCount differs from the action records",
            ));
        }
        let denomination = canonical_decimal(&self.denomination_sats, "snapshot denominationSats")?;
        if denomination == 0 {
            return Err(RecoveryError::new(
                "snapshot denominationSats must be nonzero",
            ));
        }
        let state_bytes = fixed_bytes::<128>(&self.state_hex, "snapshot stateHex")?;
        let state = PoolStateV2::decode(&state_bytes, denomination)
            .map_err(|error| RecoveryError::new(format!("snapshot state is invalid: {error}")))?;
        if hex::encode(state.profile_id) != self.profile_id {
            return Err(RecoveryError::new(
                "snapshot state profileId differs from snapshot profileId",
            ));
        }
        if self.tip.state_hex != self.state_hex {
            return Err(RecoveryError::new(
                "snapshot tip state differs from stateHex",
            ));
        }
        let genesis_state_bytes =
            fixed_bytes::<128>(&self.genesis.state_hex, "snapshot genesis stateHex")?;
        let genesis_state =
            PoolStateV2::decode(&genesis_state_bytes, denomination).map_err(|error| {
                RecoveryError::new(format!("snapshot genesis state is invalid: {error}"))
            })?;
        if hex::encode(genesis_state.profile_id) != self.profile_id {
            return Err(RecoveryError::new(
                "snapshot genesis state profileId differs from snapshot profileId",
            ));
        }

        let note_leaves = self
            .note_tree
            .leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| fixed_bytes::<32>(leaf, &format!("snapshot note leaf {index}")))
            .collect::<Result<Vec<_>>>()?;
        let notes = materialize_note_tree(&note_leaves)?;
        let note_count = canonical_decimal(&self.note_tree.count, "snapshot note count")?;
        if note_count
            != u64::try_from(note_leaves.len())
                .map_err(|_| RecoveryError::new("snapshot note count exceeds u64"))?
            || state.note_count
                != u32::try_from(note_count).map_err(|_| {
                    RecoveryError::new("snapshot note count exceeds the state counter")
                })?
            || hex::encode(notes.summary.root) != self.note_tree.root
            || state.note_root != notes.summary.root
        {
            return Err(RecoveryError::new(
                "snapshot note tree does not reconstruct the committed state root/count",
            ));
        }

        let nullifier_keys = self
            .nullifier_tree
            .keys
            .iter()
            .enumerate()
            .map(|(index, key)| fixed_bytes::<32>(key, &format!("snapshot nullifier key {index}")))
            .collect::<Result<Vec<_>>>()?;
        let nullifiers = materialize_indexed_nullifier_tree(&nullifier_keys)?;
        let nullifier_count =
            canonical_decimal(&self.nullifier_tree.count, "snapshot nullifier count")?;
        if nullifier_count
            != u64::try_from(nullifier_keys.len())
                .map_err(|_| RecoveryError::new("snapshot nullifier count exceeds u64"))?
            || state.nullifier_count
                != u32::try_from(nullifier_count).map_err(|_| {
                    RecoveryError::new("snapshot nullifier count exceeds the state counter")
                })?
            || hex::encode(nullifiers.summary.root) != self.nullifier_tree.root
            || state.nullifier_root != nullifiers.summary.root
        {
            return Err(RecoveryError::new(
                "snapshot indexed-nullifier tree does not reconstruct the committed state root/count",
            ));
        }
        if self.history_sha256 != snapshot_history_hash(&self.genesis, &self.actions)? {
            return Err(RecoveryError::new(
                "snapshot historySha256 does not match its anchored action records",
            ));
        }
        if self.actions.is_empty() {
            if point_identity(&self.tip) != point_identity(&self.genesis) {
                return Err(RecoveryError::new(
                    "snapshot with no actions has a tip different from genesis",
                ));
            }
        } else {
            let last = self
                .actions
                .last()
                .ok_or_else(|| RecoveryError::new("snapshot action list changed unexpectedly"))?;
            if last.transaction_id != self.tip.transaction_id
                || last.height != self.tip.height
                || last.block_hash != self.tip.block_hash
            {
                return Err(RecoveryError::new(
                    "snapshot tip differs from the last action anchor",
                ));
            }
        }
        let empty_note_root = NoteTree::empty()?.root_bytes()?;
        let empty_nullifier_root = IndexedNullifierTree::empty()?.root_bytes()?;
        if genesis_state.note_count != 0
            || genesis_state.nullifier_count != 0
            || genesis_state.reserve_sats != 0
            || genesis_state.action_sequence != 0
            || genesis_state.note_root != empty_note_root
            || genesis_state.nullifier_root != empty_nullifier_root
        {
            return Err(RecoveryError::new(
                "snapshot genesis state is not the profile-pinned empty raw-genesis state",
            ));
        }
        let mut packet_state = genesis_state;
        let mut packet_state_bytes = genesis_state_bytes;
        let mut packet_height = self.genesis.height;
        let mut packet_block_hash = self.genesis.block_hash.clone();
        let mut note_cursor = 0_usize;
        let mut nullifier_cursor = 0_usize;
        let mut materialized_note_leaves = Vec::with_capacity(note_leaves.len());
        let mut transaction_ids = HashSet::with_capacity(self.actions.len());
        for (index, action) in self.actions.iter().enumerate() {
            identifier(
                &action.transaction_id,
                &format!("snapshot action {index} transactionId"),
            )?;
            identifier(
                &action.block_hash,
                &format!("snapshot action {index} blockHash"),
            )?;
            identifier(
                &action.transaction_context_hash,
                &format!("snapshot action {index} transactionContextHash"),
            )?;
            if !transaction_ids.insert(&action.transaction_id) {
                return Err(RecoveryError::new(format!(
                    "snapshot action {index} repeats an earlier transactionId"
                )));
            }
            validate_chain_position(
                packet_height,
                &packet_block_hash,
                action.height,
                &action.block_hash,
                &format!("snapshot action {index}"),
            )?;
            let packet_bytes = fixed_bytes::<552>(
                &action.packet_hex,
                &format!("snapshot action {index} packetHex"),
            )?;
            let packet =
                DirectActionPacketV2::decode(&packet_bytes, denomination).map_err(|error| {
                    RecoveryError::new(format!(
                        "snapshot action {index} packet is invalid: {error}"
                    ))
                })?;
            if kind_name(packet.kind) != action.kind
                || hex::encode(packet.transaction_context_hash) != action.transaction_context_hash
                || packet.network_id != self.network_id
                || hex::encode(packet.instance_id) != self.instance_id
                || hex::encode(packet.pre_state.profile_id) != self.profile_id
                || hex::encode(packet.post_state.profile_id) != self.profile_id
                || packet.pre_state != packet_state
                || packet.pre_state.encode(denomination).map_err(codec_error)? != packet_state_bytes
            {
                return Err(RecoveryError::new(format!(
                    "snapshot action {index} packet bindings differ"
                )));
            }
            let (note_delta, nullifier_delta) =
                validate_state_delta(&packet, denomination, &format!("snapshot action {index}"))?;
            if note_delta == 1 {
                let expected = note_leaves.get(note_cursor).ok_or_else(|| {
                    RecoveryError::new(format!(
                        "snapshot action {index} has no corresponding ordered note leaf"
                    ))
                })?;
                if packet.output_note_leaf != *expected {
                    return Err(RecoveryError::new(format!(
                        "snapshot action {index} output note leaf differs from the ordered terminal tree"
                    )));
                }
                materialized_note_leaves.push(AuthenticatedNoteLeaf {
                    note_index: u32::try_from(note_cursor)
                        .map_err(|_| RecoveryError::new("snapshot note index exceeds u32"))?,
                    leaf_hash: hex::encode(packet.output_note_leaf),
                    encrypted_record: hex::encode(packet.encrypted_record),
                    action_sequence: packet.post_state.action_sequence,
                    transaction_id: action.transaction_id.clone(),
                });
                note_cursor = note_cursor
                    .checked_add(1)
                    .ok_or_else(|| RecoveryError::new("snapshot note cursor overflowed"))?;
            }
            if nullifier_delta == 1 {
                let expected = nullifier_keys.get(nullifier_cursor).ok_or_else(|| {
                    RecoveryError::new(format!(
                        "snapshot action {index} has no corresponding ordered nullifier key"
                    ))
                })?;
                if packet.public_nullifier != *expected {
                    return Err(RecoveryError::new(format!(
                        "snapshot action {index} public nullifier differs from the ordered terminal tree"
                    )));
                }
                nullifier_cursor = nullifier_cursor
                    .checked_add(1)
                    .ok_or_else(|| RecoveryError::new("snapshot nullifier cursor overflowed"))?;
            }
            packet_state_bytes = packet
                .post_state
                .encode(denomination)
                .map_err(codec_error)?;
            packet_state = packet.post_state;
            packet_height = action.height;
            packet_block_hash = action.block_hash.clone();
        }
        if packet_state_bytes != state_bytes
            || note_cursor != note_leaves.len()
            || nullifier_cursor != nullifier_keys.len()
        {
            return Err(RecoveryError::new(
                "snapshot packet chain differs from its terminal state or ordered tree leaves",
            ));
        }
        Ok(AuthenticatedTreeMaterial {
            note_tree: notes,
            nullifier_tree: nullifiers,
            note_leaves: materialized_note_leaves,
        })
    }
}

/// Incremental raw-genesis replay used by the framed transport. Only the
/// authenticated tree state, the previous chain transaction, and the records
/// required by the result are retained; raw action and funding transactions
/// are consumed one pair at a time.
pub(crate) struct StreamingRawReplay {
    network_id: u8,
    profile_id_text: String,
    instance_id_text: String,
    denomination_sats: String,
    carrier_count: u8,
    runtime_materials_sha256: String,
    denomination: u64,
    profile_id: [u8; 32],
    instance_id: [u8; 32],
    carriers: usize,
    expected_tip: ExpectedTip,
    genesis_point: SnapshotPoint,
    state_lock: Vec<u8>,
    state_base_sats: u64,
    note_tree: NoteTree,
    nullifier_tree: IndexedNullifierTree,
    chain_ids: HashSet<[u8; 32]>,
    previous: Transaction,
    previous_state: PoolStateV2,
    previous_state_bytes: [u8; 128],
    prior_height: u32,
    prior_block_hash: String,
    used_funding_outpoints: HashSet<([u8; 32], u32)>,
    action_snapshots: Vec<ActionSnapshot>,
    materialized_note_leaves: Vec<AuthenticatedNoteLeaf>,
}

impl StreamingRawReplay {
    pub(crate) fn new(header: StreamingScanRequestHeader) -> Result<Self> {
        validate_network(header.network_id)?;
        let profile_id = identifier(&header.profile_id, "profileId")?;
        let instance_id = identifier(&header.instance_id, "instanceId")?;
        identifier(
            &header.runtime_materials_sha256,
            "runtimeMaterialsSha256",
        )?;
        let denomination = canonical_decimal(&header.denomination_sats, "denominationSats")?;
        if denomination == 0 {
            return Err(RecoveryError::new("denominationSats must be nonzero"));
        }
        if header.carrier_count == 0 {
            return Err(RecoveryError::new("carrierCount must be from 1 to 255"));
        }
        let carriers = usize::from(header.carrier_count);
        let initial_state_bytes = fixed_bytes::<128>(&header.initial_state_hex, "initialStateHex")?;
        let initial_state = PoolStateV2::decode(&initial_state_bytes, denomination)
            .map_err(|error| RecoveryError::new(format!("initial state is invalid: {error}")))?;
        if initial_state.profile_id != profile_id {
            return Err(RecoveryError::new(
                "initial state profileId differs from profileId",
            ));
        }

        validate_anchor(&header.genesis, "genesis")?;
        validate_outpoint(&header.genesis_outpoint, "genesisOutpoint")?;
        if header.genesis_outpoint.output_index != 0
            || header.genesis_outpoint.transaction_id != header.genesis.transaction_id
        {
            return Err(RecoveryError::new(
                "genesisOutpoint must bind the supplied genesis transaction output 0",
            ));
        }
        validate_expected_tip(&header.expected_tip)?;

        let genesis = parse_anchored(&header.genesis, "genesis")?;
        if genesis.raw.len() > MAX_STANDARD_TRANSACTION_BYTES {
            return Err(RecoveryError::new(
                "genesis transaction exceeds the 100000-byte policy ceiling",
            ));
        }
        for (index, input) in genesis.inputs.iter().enumerate() {
            if input.unlocking_bytecode.len() > MAX_STANDARD_UNLOCK_BYTES {
                return Err(RecoveryError::new(format!(
                    "genesis input {index} exceeds the 10000-byte unlocking policy ceiling"
                )));
            }
        }
        if genesis.inputs[0].outpoint_transaction_hash != instance_id {
            return Err(RecoveryError::new(
                "genesis first input outpoint hash does not establish the instanceId CashToken category in token-prefix wire order",
            ));
        }
        let expected_genesis_outputs = carriers
            .checked_add(3)
            .ok_or_else(|| RecoveryError::new("genesis output count overflows"))?;
        if genesis.outputs.len() != expected_genesis_outputs {
            return Err(RecoveryError::new(format!(
                "genesis must contain exactly {expected_genesis_outputs} outputs"
            )));
        }
        validate_state_output(
            genesis
                .outputs
                .first()
                .ok_or_else(|| RecoveryError::new("genesis has no state output"))?,
            &instance_id,
            &initial_state_bytes,
            "genesis output 0",
        )?;
        for (index, output) in genesis.outputs.iter().enumerate().skip(1) {
            require_tokenless(output, &format!("genesis output {index}"))?;
            require_context_lock(output, &format!("genesis output {index}"))?;
            if index <= carriers + 1 && output.value_sats == 0 {
                return Err(RecoveryError::new(format!(
                    "genesis rolling output {index} must have a nonzero base value"
                )));
            }
        }
        require_p2pkh(
            &genesis.outputs[carriers + 2].locking_bytecode,
            "genesis wallet change output",
        )?;
        let state_lock = genesis.outputs[0].locking_bytecode.clone();
        require_context_lock(&genesis.outputs[0], "genesis state output")?;
        let state_base_sats = genesis.outputs[0]
            .value_sats
            .checked_sub(initial_state.reserve_sats)
            .ok_or_else(|| {
                RecoveryError::new("genesis state output is below the initial reserve")
            })?;
        if state_base_sats == 0 {
            return Err(RecoveryError::new(
                "genesis state output base value must be nonzero",
            ));
        }

        let note_tree = NoteTree::empty()?;
        let nullifier_tree = IndexedNullifierTree::empty()?;
        if initial_state.note_count != 0
            || initial_state.nullifier_count != 0
            || initial_state.reserve_sats != 0
            || initial_state.action_sequence != 0
            || initial_state.note_root != note_tree.root_bytes()?
            || initial_state.nullifier_root != nullifier_tree.root_bytes()?
        {
            return Err(RecoveryError::new(
                "raw-genesis replay requires zero counters/reserve/sequence and the profile-pinned empty tree roots",
            ));
        }

        let genesis_point = SnapshotPoint {
            transaction_id: header.genesis.transaction_id.clone(),
            output_index: 0,
            height: header.genesis.height,
            block_hash: header.genesis.block_hash.clone(),
            state_hex: header.initial_state_hex.clone(),
        };
        let prior_height = header.genesis.height;
        let prior_block_hash = header.genesis.block_hash.clone();
        Ok(Self {
            network_id: header.network_id,
            profile_id_text: header.profile_id,
            instance_id_text: header.instance_id,
            denomination_sats: header.denomination_sats,
            carrier_count: header.carrier_count,
            runtime_materials_sha256: header.runtime_materials_sha256,
            denomination,
            profile_id,
            instance_id,
            carriers,
            expected_tip: header.expected_tip,
            genesis_point,
            state_lock,
            state_base_sats,
            note_tree,
            nullifier_tree,
            chain_ids: HashSet::from([genesis.hash]),
            previous: genesis,
            previous_state: initial_state,
            previous_state_bytes: initial_state_bytes,
            prior_height,
            prior_block_hash,
            used_funding_outpoints: HashSet::new(),
            action_snapshots: Vec::new(),
            materialized_note_leaves: Vec::new(),
        })
    }

    pub(crate) fn apply(
        &mut self,
        anchored: AnchoredRawTransaction,
        source: AuthenticatedSourceTransaction,
    ) -> Result<()> {
        let position = self.action_snapshots.len();
        let label = format!("actions[{position}]");
        validate_anchor(&anchored, &label)?;
        validate_chain_position(
            self.prior_height,
            &self.prior_block_hash,
            anchored.height,
            &anchored.block_hash,
            &label,
        )?;
        let transaction = parse_anchored(&anchored, &label)?;
        if transaction.raw.len() > MAX_STANDARD_TRANSACTION_BYTES {
            return Err(RecoveryError::new(format!(
                "{label} exceeds the 100000-byte transaction policy ceiling"
            )));
        }
        if !self.chain_ids.insert(transaction.hash) {
            return Err(RecoveryError::new(format!(
                "{label} duplicates a chain transaction"
            )));
        }
        for (index, input) in transaction.inputs.iter().enumerate() {
            if input.unlocking_bytecode.len() > MAX_STANDARD_UNLOCK_BYTES {
                return Err(RecoveryError::new(format!(
                    "{label} input {index} exceeds the 10000-byte unlocking policy ceiling"
                )));
            }
        }
        let expected_inputs = self
            .carriers
            .checked_add(3)
            .ok_or_else(|| RecoveryError::new("action input count overflows"))?;
        if transaction.inputs.len() != expected_inputs {
            return Err(RecoveryError::new(format!(
                "{label} must contain exactly {expected_inputs} inputs"
            )));
        }
        for index in 0..self.carriers {
            require_parent_outpoint(
                &transaction.inputs[index],
                &self.previous,
                u32::try_from(index + 1)
                    .map_err(|_| RecoveryError::new("carrier output index exceeds u32"))?,
                &format!("{label} verifier input {index}"),
            )?;
        }
        require_parent_outpoint(
            &transaction.inputs[self.carriers],
            &self.previous,
            u32::try_from(self.carriers + 1)
                .map_err(|_| RecoveryError::new("binding output index exceeds u32"))?,
            &format!("{label} binding input"),
        )?;
        require_parent_outpoint(
            &transaction.inputs[self.carriers + 1],
            &self.previous,
            0,
            &format!("{label} state input"),
        )?;

        identifier(
            &source.transaction_id,
            &format!("{label}.fundingPrevout.transactionId"),
        )?;
        require_standard_raw_hex_length(
            &source.raw_transaction,
            &format!("{label}.fundingPrevout.rawTransaction"),
        )?;
        let funding_transaction = parse_transaction_hex(
            &source.raw_transaction,
            &format!("{label}.fundingPrevout.rawTransaction"),
        )?;
        if funding_transaction.transaction_id != source.transaction_id {
            return Err(RecoveryError::new(format!(
                "{label} funding prevout computed txid differs from transactionId"
            )));
        }
        if funding_transaction.raw.len() > MAX_STANDARD_TRANSACTION_BYTES {
            return Err(RecoveryError::new(format!(
                "{label} funding prevout exceeds the 100000-byte transaction policy ceiling"
            )));
        }
        for (input_index, input) in funding_transaction.inputs.iter().enumerate() {
            if input.unlocking_bytecode.len() > MAX_STANDARD_UNLOCK_BYTES {
                return Err(RecoveryError::new(format!(
                    "{label} funding prevout input {input_index} exceeds the 10000-byte unlocking policy ceiling"
                )));
            }
        }
        if self.chain_ids.contains(&funding_transaction.hash) {
            return Err(RecoveryError::new(format!(
                "{label} funding prevout is a chain transaction"
            )));
        }

        let funding_input = &transaction.inputs[self.carriers + 2];
        if funding_transaction.hash != funding_input.outpoint_transaction_hash {
            return Err(RecoveryError::new(format!(
                "{label} funding input differs from its paired txid-pinned raw prevout transaction"
            )));
        }
        let funding_output = funding_transaction
            .outputs
            .get(usize::try_from(funding_input.outpoint_index).map_err(|_| {
                RecoveryError::new(format!(
                    "{label} funding output index exceeds this platform"
                ))
            })?)
            .ok_or_else(|| {
                RecoveryError::new(format!("{label} funding outpoint does not exist"))
            })?;
        require_tokenless(funding_output, &format!("{label} funding prevout"))?;
        require_p2pkh(
            &funding_output.locking_bytecode,
            &format!("{label} funding prevout"),
        )?;
        if !self.used_funding_outpoints.insert((
            funding_input.outpoint_transaction_hash,
            funding_input.outpoint_index,
        )) {
            return Err(RecoveryError::new(format!(
                "{label} reuses an earlier funding outpoint"
            )));
        }

        let packet_bytes = extract_packet(
            &transaction.inputs[self.carriers].unlocking_bytecode,
            &self.previous.outputs[self.carriers + 1].locking_bytecode,
            &format!("{label} binding input"),
        )?;
        let packet = DirectActionPacketV2::decode(&packet_bytes, self.denomination)
            .map_err(|error| RecoveryError::new(format!("{label} packet is invalid: {error}")))?;
        if packet.network_id != self.network_id
            || packet.instance_id != self.instance_id
            || packet.pre_state.profile_id != self.profile_id
            || packet.post_state.profile_id != self.profile_id
            || packet.pre_state != self.previous_state
            || packet
                .pre_state
                .encode(self.denomination)
                .map_err(codec_error)?
                != self.previous_state_bytes
        {
            return Err(RecoveryError::new(format!(
                "{label} packet network/instance/profile/pre-state binding differs"
            )));
        }
        validate_state_output(
            &self.previous.outputs[0],
            &self.instance_id,
            &self.previous_state_bytes,
            &format!("{label} source state output"),
        )?;
        let post_state_bytes = packet
            .post_state
            .encode(self.denomination)
            .map_err(codec_error)?;
        let expected_outputs = self
            .carriers
            .checked_add(if packet.kind == ActionKindV2::Withdrawal {
                4
            } else {
                3
            })
            .ok_or_else(|| RecoveryError::new("action output count overflows"))?;
        if transaction.outputs.len() != expected_outputs {
            return Err(RecoveryError::new(format!(
                "{label} output count differs from its action kind"
            )));
        }
        validate_state_output(
            &transaction.outputs[0],
            &self.instance_id,
            &post_state_bytes,
            &format!("{label} successor state output"),
        )?;
        if transaction.outputs[0].locking_bytecode != self.state_lock
            || self.previous.outputs[0].locking_bytecode != self.state_lock
            || self.previous.outputs[0].value_sats
                != self
                    .state_base_sats
                    .checked_add(packet.pre_state.reserve_sats)
                    .ok_or_else(|| RecoveryError::new("source state value overflows"))?
            || transaction.outputs[0].value_sats
                != self
                    .state_base_sats
                    .checked_add(packet.post_state.reserve_sats)
                    .ok_or_else(|| RecoveryError::new("successor state value overflows"))?
        {
            return Err(RecoveryError::new(format!(
                "{label} state lock/base/reserve value differs"
            )));
        }

        for index in 0..self.carriers {
            require_tokenless(
                &self.previous.outputs[index + 1],
                &format!("{label} source verifier output {index}"),
            )?;
            require_tokenless(
                &transaction.outputs[index + 1],
                &format!("{label} successor verifier output {index}"),
            )?;
            if transaction.outputs[index + 1] != self.previous.outputs[index + 1] {
                return Err(RecoveryError::new(format!(
                    "{label} successor verifier output {index} differs from its exact source"
                )));
            }
        }
        require_tokenless(
            &self.previous.outputs[self.carriers + 1],
            &format!("{label} source binding output"),
        )?;
        require_tokenless(
            &transaction.outputs[self.carriers + 1],
            &format!("{label} successor binding output"),
        )?;
        if transaction.outputs[self.carriers + 1] != self.previous.outputs[self.carriers + 1] {
            return Err(RecoveryError::new(format!(
                "{label} successor binding output differs from its exact source"
            )));
        }
        for (index, output) in transaction.outputs.iter().enumerate().skip(1) {
            require_tokenless(output, &format!("{label} output {index}"))?;
            require_context_lock(output, &format!("{label} output {index}"))?;
        }

        validate_state_transition(
            &packet,
            &mut self.note_tree,
            &mut self.nullifier_tree,
            self.denomination,
            &label,
        )?;
        if packet.kind != ActionKindV2::Withdrawal {
            self.materialized_note_leaves.push(AuthenticatedNoteLeaf {
                note_index: packet
                    .post_state
                    .note_count
                    .checked_sub(1)
                    .ok_or_else(|| RecoveryError::new("post-state note index underflowed"))?,
                leaf_hash: hex::encode(packet.output_note_leaf),
                encrypted_record: hex::encode(packet.encrypted_record),
                action_sequence: packet.post_state.action_sequence,
                transaction_id: transaction.transaction_id.clone(),
            });
        }

        let sources = input_sources(
            &transaction,
            &self.previous,
            &funding_transaction,
            self.carriers,
            &label,
        )?;
        let context = transaction_context(
            &transaction,
            &sources,
            &packet,
            &self.profile_id,
            &self.instance_id,
            self.carriers,
        )?;
        let context_hash = context
            .sha256_with_carrier_count(self.carrier_count)
            .map_err(codec_error)?;
        if context_hash != packet.transaction_context_hash {
            return Err(RecoveryError::new(format!(
                "{label} transactionContextHash differs from the actual transaction and txid-verified source outputs"
            )));
        }

        validate_values_and_tail(
            &transaction,
            &sources,
            &packet,
            self.denomination,
            self.carriers,
            &label,
        )?;

        self.action_snapshots.push(ActionSnapshot {
            transaction_id: transaction.transaction_id.clone(),
            height: anchored.height,
            block_hash: anchored.block_hash.clone(),
            kind: kind_name(packet.kind).to_owned(),
            packet_hex: hex::encode(packet_bytes),
            transaction_context_hash: hex::encode(context_hash),
        });
        self.previous = transaction;
        self.previous_state = packet.post_state;
        self.previous_state_bytes = post_state_bytes;
        self.prior_height = anchored.height;
        self.prior_block_hash = anchored.block_hash;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<(RecoverySnapshot, AuthenticatedSnapshotResult)> {
        if self.expected_tip.output_index != 0
            || self.expected_tip.transaction_id != self.previous.transaction_id
            || self.expected_tip.height != self.prior_height
            || self.expected_tip.block_hash != self.prior_block_hash
        {
            return Err(RecoveryError::new(
                "replayed tip differs from expectedTip; history may be omitted, reordered, forked, or stale",
            ));
        }

        let tip_point = SnapshotPoint {
            transaction_id: self.previous.transaction_id,
            output_index: 0,
            height: self.prior_height,
            block_hash: self.prior_block_hash,
            state_hex: hex::encode(self.previous_state_bytes),
        };
        let note_snapshot = NoteTreeSnapshot {
            depth: TREE_DEPTH as u8,
            count: self.note_tree.leaves().len().to_string(),
            root: hex::encode(self.note_tree.root_bytes()?),
            leaves: self.note_tree.leaves().iter().map(hex::encode).collect(),
        };
        let nullifier_snapshot = NullifierTreeSnapshot {
            depth: TREE_DEPTH as u8,
            count: self.nullifier_tree.keys().len().to_string(),
            root: hex::encode(self.nullifier_tree.root_bytes()?),
            keys: self.nullifier_tree.keys().iter().map(hex::encode).collect(),
        };
        let history_sha256 = snapshot_history_hash(&self.genesis_point, &self.action_snapshots)?;
        let mut snapshot = RecoverySnapshot {
            schema: SNAPSHOT_SCHEMA.to_owned(),
            version: 2,
            network_id: self.network_id,
            profile_id: self.profile_id_text,
            instance_id: self.instance_id_text,
            denomination_sats: self.denomination_sats,
            carrier_count: self.carrier_count,
            runtime_materials_sha256: self.runtime_materials_sha256,
            poseidon_profile: POSEIDON_PROFILE.to_owned(),
            genesis: self.genesis_point,
            tip: tip_point.clone(),
            action_count: self.action_snapshots.len().to_string(),
            history_sha256,
            state_hex: tip_point.state_hex.clone(),
            note_tree: note_snapshot,
            nullifier_tree: nullifier_snapshot,
            actions: self.action_snapshots,
            external_authentication_boundary: EXTERNAL_AUTHENTICATION_BOUNDARY.to_owned(),
            content_sha256: String::new(),
        };
        snapshot.refresh_hash()?;
        let material = AuthenticatedTreeMaterial {
            note_tree: self.note_tree.materialized()?,
            nullifier_tree: self.nullifier_tree.materialized()?,
            note_leaves: self.materialized_note_leaves,
        };
        let authenticated = authenticated_material_result(&snapshot, material)?;
        Ok((snapshot, authenticated))
    }
}

fn scan_internal(request: &ScanRequest) -> Result<(RecoverySnapshot, AuthenticatedTreeMaterial)> {
    if request.schema != SCAN_SCHEMA {
        return Err(RecoveryError::new("scan request schema is unsupported"));
    }
    validate_network(request.network_id)?;
    let profile_id = identifier(&request.profile_id, "profileId")?;
    let instance_id = identifier(&request.instance_id, "instanceId")?;
    identifier(
        &request.runtime_materials_sha256,
        "runtimeMaterialsSha256",
    )?;
    let denomination = canonical_decimal(&request.denomination_sats, "denominationSats")?;
    if denomination == 0 {
        return Err(RecoveryError::new("denominationSats must be nonzero"));
    }
    if request.carrier_count == 0 {
        return Err(RecoveryError::new("carrierCount must be from 1 to 255"));
    }
    let carriers = usize::from(request.carrier_count);
    let initial_state_bytes = fixed_bytes::<128>(&request.initial_state_hex, "initialStateHex")?;
    let initial_state = PoolStateV2::decode(&initial_state_bytes, denomination)
        .map_err(|error| RecoveryError::new(format!("initial state is invalid: {error}")))?;
    if initial_state.profile_id != profile_id {
        return Err(RecoveryError::new(
            "initial state profileId differs from profileId",
        ));
    }

    validate_anchor(&request.genesis, "genesis")?;
    validate_outpoint(&request.genesis_outpoint, "genesisOutpoint")?;
    if request.genesis_outpoint.output_index != 0
        || request.genesis_outpoint.transaction_id != request.genesis.transaction_id
    {
        return Err(RecoveryError::new(
            "genesisOutpoint must bind the supplied genesis transaction output 0",
        ));
    }
    validate_expected_tip(&request.expected_tip)?;

    let genesis = parse_anchored(&request.genesis, "genesis")?;
    if genesis.raw.len() > MAX_STANDARD_TRANSACTION_BYTES {
        return Err(RecoveryError::new(
            "genesis transaction exceeds the 100000-byte policy ceiling",
        ));
    }
    for (index, input) in genesis.inputs.iter().enumerate() {
        if input.unlocking_bytecode.len() > MAX_STANDARD_UNLOCK_BYTES {
            return Err(RecoveryError::new(format!(
                "genesis input {index} exceeds the 10000-byte unlocking policy ceiling"
            )));
        }
    }
    if genesis.inputs[0].outpoint_transaction_hash != instance_id {
        return Err(RecoveryError::new(
            "genesis first input outpoint hash does not establish the instanceId CashToken category in token-prefix wire order",
        ));
    }
    let expected_genesis_outputs = carriers
        .checked_add(3)
        .ok_or_else(|| RecoveryError::new("genesis output count overflows"))?;
    if genesis.outputs.len() != expected_genesis_outputs {
        return Err(RecoveryError::new(format!(
            "genesis must contain exactly {expected_genesis_outputs} outputs"
        )));
    }
    validate_state_output(
        genesis
            .outputs
            .first()
            .ok_or_else(|| RecoveryError::new("genesis has no state output"))?,
        &instance_id,
        &initial_state_bytes,
        "genesis output 0",
    )?;
    for (index, output) in genesis.outputs.iter().enumerate().skip(1) {
        require_tokenless(output, &format!("genesis output {index}"))?;
        require_context_lock(output, &format!("genesis output {index}"))?;
        if index <= carriers + 1 && output.value_sats == 0 {
            return Err(RecoveryError::new(format!(
                "genesis rolling output {index} must have a nonzero base value"
            )));
        }
    }
    require_p2pkh(
        &genesis.outputs[carriers + 2].locking_bytecode,
        "genesis wallet change output",
    )?;
    let state_lock = genesis.outputs[0].locking_bytecode.clone();
    require_context_lock(&genesis.outputs[0], "genesis state output")?;
    let state_base_sats = genesis.outputs[0]
        .value_sats
        .checked_sub(initial_state.reserve_sats)
        .ok_or_else(|| RecoveryError::new("genesis state output is below the initial reserve"))?;
    if state_base_sats == 0 {
        return Err(RecoveryError::new(
            "genesis state output base value must be nonzero",
        ));
    }

    let mut note_tree = NoteTree::empty()?;
    let mut nullifier_tree = IndexedNullifierTree::empty()?;
    if initial_state.note_count != 0
        || initial_state.nullifier_count != 0
        || initial_state.reserve_sats != 0
        || initial_state.action_sequence != 0
        || initial_state.note_root != note_tree.root_bytes()?
        || initial_state.nullifier_root != nullifier_tree.root_bytes()?
    {
        return Err(RecoveryError::new(
            "raw-genesis replay requires zero counters/reserve/sequence and the profile-pinned empty tree roots",
        ));
    }

    let mut funding = HashMap::<[u8; 32], Transaction>::new();
    for (index, source) in request.funding_prevouts.iter().enumerate() {
        identifier(
            &source.transaction_id,
            &format!("fundingPrevouts[{index}].transactionId"),
        )?;
        require_standard_raw_hex_length(
            &source.raw_transaction,
            &format!("fundingPrevouts[{index}].rawTransaction"),
        )?;
        let transaction = parse_transaction_hex(
            &source.raw_transaction,
            &format!("fundingPrevouts[{index}].rawTransaction"),
        )?;
        if transaction.transaction_id != source.transaction_id {
            return Err(RecoveryError::new(format!(
                "fundingPrevouts[{index}] computed txid differs from transactionId"
            )));
        }
        if transaction.raw.len() > MAX_STANDARD_TRANSACTION_BYTES {
            return Err(RecoveryError::new(format!(
                "fundingPrevouts[{index}] exceeds the 100000-byte transaction policy ceiling"
            )));
        }
        for (input_index, input) in transaction.inputs.iter().enumerate() {
            if input.unlocking_bytecode.len() > MAX_STANDARD_UNLOCK_BYTES {
                return Err(RecoveryError::new(format!(
                    "fundingPrevouts[{index}] input {input_index} exceeds the 10000-byte unlocking policy ceiling"
                )));
            }
        }
        if transaction.hash == genesis.hash
            || funding.insert(transaction.hash, transaction).is_some()
        {
            return Err(RecoveryError::new(
                "funding prevout transactions contain a duplicate or chain transaction",
            ));
        }
    }

    let mut chain_ids = HashSet::from([genesis.hash]);
    let mut previous = genesis;
    let mut previous_state = initial_state.clone();
    let mut previous_state_bytes = initial_state_bytes;
    let mut prior_height = request.genesis.height;
    let mut prior_block_hash = request.genesis.block_hash.clone();
    let mut used_funding_outpoints = HashSet::new();
    let mut used_funding_transactions = HashSet::new();
    let mut action_snapshots = Vec::with_capacity(request.actions.len());
    let mut materialized_note_leaves = Vec::new();

    for (position, anchored) in request.actions.iter().enumerate() {
        let label = format!("actions[{position}]");
        validate_anchor(anchored, &label)?;
        validate_chain_position(
            prior_height,
            &prior_block_hash,
            anchored.height,
            &anchored.block_hash,
            &label,
        )?;
        let transaction = parse_anchored(anchored, &label)?;
        if transaction.raw.len() > MAX_STANDARD_TRANSACTION_BYTES {
            return Err(RecoveryError::new(format!(
                "{label} exceeds the 100000-byte transaction policy ceiling"
            )));
        }
        if !chain_ids.insert(transaction.hash) {
            return Err(RecoveryError::new(format!(
                "{label} duplicates a chain transaction"
            )));
        }
        if funding.contains_key(&transaction.hash) {
            return Err(RecoveryError::new(format!(
                "{label} is also supplied as a funding prevout transaction"
            )));
        }
        for (index, input) in transaction.inputs.iter().enumerate() {
            if input.unlocking_bytecode.len() > MAX_STANDARD_UNLOCK_BYTES {
                return Err(RecoveryError::new(format!(
                    "{label} input {index} exceeds the 10000-byte unlocking policy ceiling"
                )));
            }
        }
        let expected_inputs = carriers
            .checked_add(3)
            .ok_or_else(|| RecoveryError::new("action input count overflows"))?;
        if transaction.inputs.len() != expected_inputs {
            return Err(RecoveryError::new(format!(
                "{label} must contain exactly {expected_inputs} inputs"
            )));
        }
        for index in 0..carriers {
            require_parent_outpoint(
                &transaction.inputs[index],
                &previous,
                u32::try_from(index + 1)
                    .map_err(|_| RecoveryError::new("carrier output index exceeds u32"))?,
                &format!("{label} verifier input {index}"),
            )?;
        }
        require_parent_outpoint(
            &transaction.inputs[carriers],
            &previous,
            u32::try_from(carriers + 1)
                .map_err(|_| RecoveryError::new("binding output index exceeds u32"))?,
            &format!("{label} binding input"),
        )?;
        require_parent_outpoint(
            &transaction.inputs[carriers + 1],
            &previous,
            0,
            &format!("{label} state input"),
        )?;

        let funding_input = &transaction.inputs[carriers + 2];
        let funding_transaction = funding
            .get(&funding_input.outpoint_transaction_hash)
            .ok_or_else(|| {
                RecoveryError::new(format!(
                    "{label} funding input lacks an explicit txid-pinned raw prevout transaction"
                ))
            })?;
        let funding_output = funding_transaction
            .outputs
            .get(usize::try_from(funding_input.outpoint_index).map_err(|_| {
                RecoveryError::new(format!(
                    "{label} funding output index exceeds this platform"
                ))
            })?)
            .ok_or_else(|| {
                RecoveryError::new(format!("{label} funding outpoint does not exist"))
            })?;
        require_tokenless(funding_output, &format!("{label} funding prevout"))?;
        require_p2pkh(
            &funding_output.locking_bytecode,
            &format!("{label} funding prevout"),
        )?;
        if !used_funding_outpoints.insert((
            funding_input.outpoint_transaction_hash,
            funding_input.outpoint_index,
        )) {
            return Err(RecoveryError::new(format!(
                "{label} reuses an earlier funding outpoint"
            )));
        }
        used_funding_transactions.insert(funding_input.outpoint_transaction_hash);

        let packet_bytes = extract_packet(
            &transaction.inputs[carriers].unlocking_bytecode,
            &previous.outputs[carriers + 1].locking_bytecode,
            &format!("{label} binding input"),
        )?;
        let packet = DirectActionPacketV2::decode(&packet_bytes, denomination)
            .map_err(|error| RecoveryError::new(format!("{label} packet is invalid: {error}")))?;
        if packet.network_id != request.network_id
            || packet.instance_id != instance_id
            || packet.pre_state.profile_id != profile_id
            || packet.post_state.profile_id != profile_id
            || packet.pre_state != previous_state
            || packet.pre_state.encode(denomination).map_err(codec_error)? != previous_state_bytes
        {
            return Err(RecoveryError::new(format!(
                "{label} packet network/instance/profile/pre-state binding differs"
            )));
        }
        validate_state_output(
            &previous.outputs[0],
            &instance_id,
            &previous_state_bytes,
            &format!("{label} source state output"),
        )?;
        let post_state_bytes = packet
            .post_state
            .encode(denomination)
            .map_err(codec_error)?;
        let expected_outputs = carriers
            .checked_add(if packet.kind == ActionKindV2::Withdrawal {
                4
            } else {
                3
            })
            .ok_or_else(|| RecoveryError::new("action output count overflows"))?;
        if transaction.outputs.len() != expected_outputs {
            return Err(RecoveryError::new(format!(
                "{label} output count differs from its action kind"
            )));
        }
        validate_state_output(
            &transaction.outputs[0],
            &instance_id,
            &post_state_bytes,
            &format!("{label} successor state output"),
        )?;
        if transaction.outputs[0].locking_bytecode != state_lock
            || previous.outputs[0].locking_bytecode != state_lock
            || previous.outputs[0].value_sats
                != state_base_sats
                    .checked_add(packet.pre_state.reserve_sats)
                    .ok_or_else(|| RecoveryError::new("source state value overflows"))?
            || transaction.outputs[0].value_sats
                != state_base_sats
                    .checked_add(packet.post_state.reserve_sats)
                    .ok_or_else(|| RecoveryError::new("successor state value overflows"))?
        {
            return Err(RecoveryError::new(format!(
                "{label} state lock/base/reserve value differs"
            )));
        }

        for index in 0..carriers {
            require_tokenless(
                &previous.outputs[index + 1],
                &format!("{label} source verifier output {index}"),
            )?;
            require_tokenless(
                &transaction.outputs[index + 1],
                &format!("{label} successor verifier output {index}"),
            )?;
            if transaction.outputs[index + 1] != previous.outputs[index + 1] {
                return Err(RecoveryError::new(format!(
                    "{label} successor verifier output {index} differs from its exact source"
                )));
            }
        }
        require_tokenless(
            &previous.outputs[carriers + 1],
            &format!("{label} source binding output"),
        )?;
        require_tokenless(
            &transaction.outputs[carriers + 1],
            &format!("{label} successor binding output"),
        )?;
        if transaction.outputs[carriers + 1] != previous.outputs[carriers + 1] {
            return Err(RecoveryError::new(format!(
                "{label} successor binding output differs from its exact source"
            )));
        }
        for (index, output) in transaction.outputs.iter().enumerate().skip(1) {
            require_tokenless(output, &format!("{label} output {index}"))?;
            require_context_lock(output, &format!("{label} output {index}"))?;
        }

        validate_state_transition(
            &packet,
            &mut note_tree,
            &mut nullifier_tree,
            denomination,
            &label,
        )?;
        if packet.kind != ActionKindV2::Withdrawal {
            materialized_note_leaves.push(AuthenticatedNoteLeaf {
                note_index: packet
                    .post_state
                    .note_count
                    .checked_sub(1)
                    .ok_or_else(|| RecoveryError::new("post-state note index underflowed"))?,
                leaf_hash: hex::encode(packet.output_note_leaf),
                encrypted_record: hex::encode(packet.encrypted_record),
                action_sequence: packet.post_state.action_sequence,
                transaction_id: transaction.transaction_id.clone(),
            });
        }

        let sources = input_sources(
            &transaction,
            &previous,
            funding_transaction,
            carriers,
            &label,
        )?;
        let context = transaction_context(
            &transaction,
            &sources,
            &packet,
            &profile_id,
            &instance_id,
            carriers,
        )?;
        let context_hash = context
            .sha256_with_carrier_count(request.carrier_count)
            .map_err(codec_error)?;
        if context_hash != packet.transaction_context_hash {
            return Err(RecoveryError::new(format!(
                "{label} transactionContextHash differs from the actual transaction and txid-verified source outputs"
            )));
        }

        validate_values_and_tail(
            &transaction,
            &sources,
            &packet,
            denomination,
            carriers,
            &label,
        )?;

        action_snapshots.push(ActionSnapshot {
            transaction_id: transaction.transaction_id.clone(),
            height: anchored.height,
            block_hash: anchored.block_hash.clone(),
            kind: kind_name(packet.kind).to_owned(),
            packet_hex: hex::encode(packet_bytes),
            transaction_context_hash: hex::encode(context_hash),
        });
        previous = transaction;
        previous_state = packet.post_state;
        previous_state_bytes = post_state_bytes;
        prior_height = anchored.height;
        prior_block_hash = anchored.block_hash.clone();
    }

    if used_funding_transactions.len() != request.funding_prevouts.len() {
        return Err(RecoveryError::new(
            "fundingPrevouts contains an unreferenced raw source transaction",
        ));
    }
    if request.expected_tip.output_index != 0
        || request.expected_tip.transaction_id != previous.transaction_id
        || request.expected_tip.height != prior_height
        || request.expected_tip.block_hash != prior_block_hash
    {
        return Err(RecoveryError::new(
            "replayed tip differs from expectedTip; history may be omitted, reordered, forked, or stale",
        ));
    }

    let genesis_point = SnapshotPoint {
        transaction_id: request.genesis.transaction_id.clone(),
        output_index: 0,
        height: request.genesis.height,
        block_hash: request.genesis.block_hash.clone(),
        state_hex: request.initial_state_hex.clone(),
    };
    let tip_point = SnapshotPoint {
        transaction_id: previous.transaction_id,
        output_index: 0,
        height: prior_height,
        block_hash: prior_block_hash,
        state_hex: hex::encode(previous_state_bytes),
    };
    let note_snapshot = NoteTreeSnapshot {
        depth: TREE_DEPTH as u8,
        count: note_tree.leaves().len().to_string(),
        root: hex::encode(note_tree.root_bytes()?),
        leaves: note_tree.leaves().iter().map(hex::encode).collect(),
    };
    let nullifier_snapshot = NullifierTreeSnapshot {
        depth: TREE_DEPTH as u8,
        count: nullifier_tree.keys().len().to_string(),
        root: hex::encode(nullifier_tree.root_bytes()?),
        keys: nullifier_tree.keys().iter().map(hex::encode).collect(),
    };
    let history_sha256 = snapshot_history_hash(&genesis_point, &action_snapshots)?;
    let mut snapshot = RecoverySnapshot {
        schema: SNAPSHOT_SCHEMA.to_owned(),
        version: 2,
        network_id: request.network_id,
        profile_id: request.profile_id.clone(),
        instance_id: request.instance_id.clone(),
        denomination_sats: request.denomination_sats.clone(),
        carrier_count: request.carrier_count,
        runtime_materials_sha256: request.runtime_materials_sha256.clone(),
        poseidon_profile: POSEIDON_PROFILE.to_owned(),
        genesis: genesis_point,
        tip: tip_point.clone(),
        action_count: action_snapshots.len().to_string(),
        history_sha256,
        state_hex: tip_point.state_hex.clone(),
        note_tree: note_snapshot,
        nullifier_tree: nullifier_snapshot,
        actions: action_snapshots,
        external_authentication_boundary: EXTERNAL_AUTHENTICATION_BOUNDARY.to_owned(),
        content_sha256: String::new(),
    };
    snapshot.refresh_hash()?;
    let material = AuthenticatedTreeMaterial {
        note_tree: note_tree.materialized()?,
        nullifier_tree: nullifier_tree.materialized()?,
        note_leaves: materialized_note_leaves,
    };
    Ok((snapshot, material))
}

pub fn scan(request: &ScanRequest) -> Result<RecoverySnapshot> {
    scan_internal(request).map(|(snapshot, _)| snapshot)
}

pub fn scan_with_material(request: &ScanRequest) -> Result<RecoveryScanResult> {
    let (snapshot, material) = scan_internal(request)?;
    let authenticated = authenticated_material_result(&snapshot, material)?;
    Ok(RecoveryScanResult {
        schema: SCAN_RESULT_SCHEMA.to_owned(),
        snapshot,
        material: authenticated,
    })
}

pub fn authenticate_snapshot(
    request: &AuthenticateSnapshotRequest,
) -> Result<AuthenticatedSnapshotResult> {
    if request.schema != AUTHENTICATE_SNAPSHOT_SCHEMA {
        return Err(RecoveryError::new(
            "authenticate-snapshot request schema is unsupported",
        ));
    }
    validate_network(request.network_id)?;
    identifier(&request.profile_id, "expected profileId")?;
    identifier(&request.instance_id, "expected instanceId")?;
    identifier(
        &request.runtime_materials_sha256,
        "expected runtimeMaterialsSha256",
    )?;
    let denomination = canonical_decimal(&request.denomination_sats, "expected denominationSats")?;
    if denomination == 0 {
        return Err(RecoveryError::new(
            "expected denominationSats must be nonzero",
        ));
    }
    if request.carrier_count == 0 {
        return Err(RecoveryError::new(
            "expected carrierCount must be from 1 to 255",
        ));
    }
    validate_snapshot_point(&request.genesis, "expected genesis")?;
    validate_snapshot_point(&request.tip, "expected tip")?;
    if request.genesis.output_index != 0 || request.tip.output_index != 0 {
        return Err(RecoveryError::new(
            "expected genesis and tip must bind exact state output 0",
        ));
    }

    let material = request.snapshot.authenticate_and_materialize()?;
    if request.snapshot.network_id != request.network_id
        || request.snapshot.profile_id != request.profile_id
        || request.snapshot.instance_id != request.instance_id
        || request.snapshot.denomination_sats != request.denomination_sats
        || request.snapshot.carrier_count != request.carrier_count
        || request.snapshot.runtime_materials_sha256 != request.runtime_materials_sha256
        || request.snapshot.genesis != request.genesis
        || request.snapshot.tip != request.tip
        || request.snapshot.state_hex != request.tip.state_hex
    {
        return Err(RecoveryError::new(
            "snapshot differs from the independently authenticated profile, genesis, or canonical tip",
        ));
    }
    authenticated_material_result(&request.snapshot, material)
}

fn authenticated_material_result(
    snapshot: &RecoverySnapshot,
    material: AuthenticatedTreeMaterial,
) -> Result<AuthenticatedSnapshotResult> {
    let denomination = canonical_decimal(
        &snapshot.denomination_sats,
        "authenticated denominationSats",
    )?;
    let state_bytes = fixed_bytes::<128>(&snapshot.state_hex, "authenticated snapshot stateHex")?;
    let state = PoolStateV2::decode(&state_bytes, denomination).map_err(|error| {
        RecoveryError::new(format!("authenticated snapshot state is invalid: {error}"))
    })?;
    let note_nodes = material
        .note_tree
        .nodes
        .into_iter()
        .map(|node| AuthenticatedTreeNode {
            depth: node.depth,
            node_index: node.node_index,
            node_hash: hex::encode(node.node_hash),
        })
        .collect();
    let note_frontier = material
        .note_tree
        .frontier
        .into_iter()
        .map(|node| AuthenticatedTreeFrontier {
            depth: node.depth,
            node_hash: hex::encode(node.node_hash),
        })
        .collect();
    let nullifier_nodes = material
        .nullifier_tree
        .nodes
        .into_iter()
        .map(|node| AuthenticatedTreeNode {
            depth: node.depth,
            node_index: node.node_index,
            node_hash: hex::encode(node.node_hash),
        })
        .collect();
    let nullifier_leaves = material
        .nullifier_tree
        .leaves
        .into_iter()
        .map(|leaf| AuthenticatedNullifierLeaf {
            physical_index: leaf.physical_index,
            leaf_type: leaf.leaf_type,
            leaf_hash: hex::encode(leaf.leaf_hash),
            key: hex::encode(leaf.key),
            successor_index: leaf.successor_index,
            successor_key: hex::encode(leaf.successor_key),
        })
        .collect();
    Ok(AuthenticatedSnapshotResult {
        schema: AUTHENTICATED_MATERIAL_SCHEMA.to_owned(),
        content_sha256: snapshot.content_sha256.clone(),
        binding: AuthenticatedSnapshotBinding {
            profile_id: snapshot.profile_id.clone(),
            instance_id: snapshot.instance_id.clone(),
            network_id: snapshot.network_id,
            denomination_sats: snapshot.denomination_sats.clone(),
            carrier_count: snapshot.carrier_count,
            runtime_materials_sha256: snapshot.runtime_materials_sha256.clone(),
        },
        canonical: AuthenticatedCanonicalState {
            state: snapshot.state_hex.clone(),
            outpoint: AuthenticatedOutpoint {
                txid: snapshot.tip.transaction_id.clone(),
                vout: snapshot.tip.output_index,
            },
            action_sequence: state.action_sequence,
            height: snapshot.tip.height,
            block_hash: snapshot.tip.block_hash.clone(),
        },
        note_nodes,
        note_frontier,
        note_leaves: material.note_leaves,
        nullifier_nodes,
        nullifier_leaves,
    })
}

pub fn verify_snapshot(request: &VerifySnapshotRequest) -> Result<RecoverySnapshot> {
    if request.schema != VERIFY_SCHEMA {
        return Err(RecoveryError::new(
            "verify-snapshot request schema is unsupported",
        ));
    }
    request.snapshot.authenticate_structure()?;
    let reconstructed = scan(&request.scan)?;
    if reconstructed != request.snapshot {
        return Err(RecoveryError::new(
            "snapshot differs from independent raw-genesis replay",
        ));
    }
    Ok(reconstructed)
}

fn parse_anchored(value: &AnchoredRawTransaction, label: &str) -> Result<Transaction> {
    require_standard_raw_hex_length(&value.raw_transaction, &format!("{label}.rawTransaction"))?;
    let transaction =
        parse_transaction_hex(&value.raw_transaction, &format!("{label}.rawTransaction"))?;
    if transaction.transaction_id != value.transaction_id {
        return Err(RecoveryError::new(format!(
            "{label} computed txid differs from transactionId"
        )));
    }
    Ok(transaction)
}

fn require_standard_raw_hex_length(value: &str, label: &str) -> Result<()> {
    if value.len() > MAX_STANDARD_TRANSACTION_BYTES * 2 {
        return Err(RecoveryError::new(format!(
            "{label} exceeds the 100000-byte transaction policy ceiling"
        )));
    }
    Ok(())
}

fn validate_anchor(value: &AnchoredRawTransaction, label: &str) -> Result<()> {
    identifier(&value.transaction_id, &format!("{label}.transactionId"))?;
    identifier(&value.block_hash, &format!("{label}.blockHash"))?;
    Ok(())
}

fn validate_outpoint(value: &DisplayOutpoint, label: &str) -> Result<()> {
    identifier(&value.transaction_id, &format!("{label}.transactionId"))?;
    Ok(())
}

fn validate_expected_tip(value: &ExpectedTip) -> Result<()> {
    identifier(&value.transaction_id, "expectedTip.transactionId")?;
    identifier(&value.block_hash, "expectedTip.blockHash")?;
    if value.output_index != 0 {
        return Err(RecoveryError::new(
            "expectedTip.outputIndex must be exact state output 0",
        ));
    }
    Ok(())
}

fn validate_snapshot_point(value: &SnapshotPoint, label: &str) -> Result<()> {
    identifier(&value.transaction_id, &format!("{label}.transactionId"))?;
    identifier(&value.block_hash, &format!("{label}.blockHash"))?;
    fixed_bytes::<128>(&value.state_hex, &format!("{label}.stateHex"))?;
    Ok(())
}

fn point_identity(value: &SnapshotPoint) -> (&str, u32, u32, &str) {
    (
        &value.transaction_id,
        value.output_index,
        value.height,
        &value.block_hash,
    )
}

fn validate_chain_position(
    prior_height: u32,
    prior_block_hash: &str,
    height: u32,
    block_hash: &str,
    label: &str,
) -> Result<()> {
    if height < prior_height {
        return Err(RecoveryError::new(format!(
            "{label} block height precedes its state parent"
        )));
    }
    if height == prior_height && block_hash != prior_block_hash {
        return Err(RecoveryError::new(format!(
            "{label} shares a height with its state parent but has a different block hash"
        )));
    }
    Ok(())
}

fn validate_state_output(
    output: &Output,
    instance_id: &[u8; 32],
    state: &[u8; 128],
    label: &str,
) -> Result<()> {
    let token = output
        .token
        .as_ref()
        .ok_or_else(|| RecoveryError::new(format!("{label} lacks the state NFT")))?;
    let nft = token
        .nft
        .as_ref()
        .ok_or_else(|| RecoveryError::new(format!("{label} state token lacks an NFT")))?;
    if token.category_wire != *instance_id
        || token.amount != 0
        || nft.capability != 1
        || nft.commitment.as_slice() != state
        || output.token_prefix.len() != 163
        || output.token_prefix[0] != 0xef
        || output.token_prefix[1..33] != instance_id[..]
        || output.token_prefix[33] != 0x61
        || output.token_prefix[34] != 0x80
    {
        return Err(RecoveryError::new(format!(
            "{label} must contain the exact zero-amount mutable category-bound 128-byte state NFT"
        )));
    }
    Ok(())
}

fn require_tokenless(output: &Output, label: &str) -> Result<()> {
    if output.token.is_some() || !output.token_prefix.is_empty() {
        return Err(RecoveryError::new(format!("{label} must be tokenless")));
    }
    Ok(())
}

fn require_context_lock(output: &Output, label: &str) -> Result<()> {
    if output.locking_bytecode.is_empty() || output.locking_bytecode.len() > 10_000 {
        return Err(RecoveryError::new(format!(
            "{label} locking bytecode must contain 1 to 10000 bytes"
        )));
    }
    if output.token_prefix.len() > 10_000 {
        return Err(RecoveryError::new(format!(
            "{label} token prefix exceeds 10000 bytes"
        )));
    }
    Ok(())
}

fn require_p2pkh(lock: &[u8], label: &str) -> Result<()> {
    if lock.len() != 25
        || lock[0] != 0x76
        || lock[1] != 0xa9
        || lock[2] != 0x14
        || lock[23] != 0x88
        || lock[24] != 0xac
    {
        return Err(RecoveryError::new(format!(
            "{label} must use canonical P2PKH locking bytecode"
        )));
    }
    Ok(())
}

fn require_parent_outpoint(
    input: &bch::Input,
    previous: &Transaction,
    expected_index: u32,
    label: &str,
) -> Result<()> {
    if input.outpoint_transaction_hash != previous.hash || input.outpoint_index != expected_index {
        return Err(RecoveryError::new(format!(
            "{label} does not spend the exact preceding bundle transaction output {expected_index}"
        )));
    }
    Ok(())
}

fn minimal_push(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0];
    }
    if data.len() == 1 && (1..=16).contains(&data[0]) {
        return vec![0x50 + data[0]];
    }
    if data == [0x81] {
        return vec![0x4f];
    }
    let mut encoded = match data.len() {
        1..=75 => vec![data.len() as u8],
        76..=255 => vec![0x4c, data.len() as u8],
        256..=65_535 => {
            let mut header = vec![0x4d];
            header.extend_from_slice(&(data.len() as u16).to_le_bytes());
            header
        }
        _ => {
            let mut header = vec![0x4e];
            header.extend_from_slice(&(data.len() as u32).to_le_bytes());
            header
        }
    };
    encoded.extend_from_slice(data);
    encoded
}

fn extract_single_minimal_push(bytes: &[u8], label: &str) -> Result<Vec<u8>> {
    let opcode = *bytes
        .first()
        .ok_or_else(|| RecoveryError::new(format!("{label} redeem push is missing")))?;
    let (header_len, data_len, numeric_data): (usize, usize, Option<Vec<u8>>) = match opcode {
        0 => (1, 0, Some(Vec::new())),
        0x4f => (1, 0, Some(vec![0x81])),
        0x51..=0x60 => (1, 0, Some(vec![opcode - 0x50])),
        1..=75 => (1, usize::from(opcode), None),
        0x4c => {
            let length = *bytes.get(1).ok_or_else(|| {
                RecoveryError::new(format!("{label} PUSHDATA1 length is truncated"))
            })?;
            (2, usize::from(length), None)
        }
        0x4d => {
            let length = bytes.get(1..3).ok_or_else(|| {
                RecoveryError::new(format!("{label} PUSHDATA2 length is truncated"))
            })?;
            (
                3,
                usize::from(u16::from_le_bytes([length[0], length[1]])),
                None,
            )
        }
        0x4e => {
            let length = bytes.get(1..5).ok_or_else(|| {
                RecoveryError::new(format!("{label} PUSHDATA4 length is truncated"))
            })?;
            let decoded = u32::from_le_bytes([length[0], length[1], length[2], length[3]]);
            (
                5,
                usize::try_from(decoded).map_err(|_| {
                    RecoveryError::new(format!("{label} PUSHDATA4 length exceeds this platform"))
                })?,
                None,
            )
        }
        _ => {
            return Err(RecoveryError::new(format!(
                "{label} suffix is not one data-push instruction"
            )));
        }
    };
    let redeem = if let Some(data) = numeric_data {
        if bytes.len() != 1 {
            return Err(RecoveryError::new(format!(
                "{label} contains bytes after its redeem push"
            )));
        }
        data
    } else {
        let end = header_len
            .checked_add(data_len)
            .ok_or_else(|| RecoveryError::new(format!("{label} redeem push length overflows")))?;
        let data = bytes
            .get(header_len..end)
            .ok_or_else(|| RecoveryError::new(format!("{label} redeem push is truncated")))?;
        if end != bytes.len() {
            return Err(RecoveryError::new(format!(
                "{label} contains bytes after its redeem push"
            )));
        }
        data.to_vec()
    };
    if redeem.is_empty() || minimal_push(&redeem) != bytes {
        return Err(RecoveryError::new(format!(
            "{label} redeem script must use exactly one minimal nonempty push"
        )));
    }
    Ok(redeem)
}

fn extract_packet(unlocking: &[u8], source_binding_lock: &[u8], label: &str) -> Result<[u8; 552]> {
    if unlocking.len() <= 555
        || unlocking[0] != 0x4d
        || unlocking[1] != 0x28
        || unlocking[2] != 0x02
    {
        return Err(RecoveryError::new(format!(
            "{label} must begin with exact minimal PUSHDATA2(552)"
        )));
    }
    let mut packet = [0_u8; 552];
    packet.copy_from_slice(&unlocking[3..555]);
    let redeem = extract_single_minimal_push(&unlocking[555..], label)?;
    if source_binding_lock.len() != 35
        || source_binding_lock[0] != 0xaa
        || source_binding_lock[1] != 0x20
        || source_binding_lock[34] != 0x87
        || source_binding_lock[2..34] != hash256(&redeem)
    {
        return Err(RecoveryError::new(format!(
            "{label} redeem hash256 does not match its exact source P2SH32 locking bytecode"
        )));
    }
    Ok(packet)
}

fn validate_state_transition(
    packet: &DirectActionPacketV2,
    notes: &mut NoteTree,
    nullifiers: &mut IndexedNullifierTree,
    denomination: u64,
    label: &str,
) -> Result<()> {
    let pre = &packet.pre_state;
    let post = &packet.post_state;
    if pre.note_root != notes.root_bytes()?
        || pre.nullifier_root != nullifiers.root_bytes()?
        || usize::try_from(pre.note_count).ok() != Some(notes.leaves().len())
        || usize::try_from(pre.nullifier_count).ok() != Some(nullifiers.keys().len())
    {
        return Err(RecoveryError::new(format!(
            "{label} pre-state roots/counters differ from incrementally reconstructed history"
        )));
    }
    let (note_delta, nullifier_delta) = validate_state_delta(packet, denomination, label)?;
    if note_delta == 1 {
        notes.append(packet.output_note_leaf)?;
    }
    if nullifier_delta == 1 {
        nullifiers.insert(packet.public_nullifier)?;
    }
    if post.note_root != notes.root_bytes()?
        || post.nullifier_root != nullifiers.root_bytes()?
        || usize::try_from(post.note_count).ok() != Some(notes.leaves().len())
        || usize::try_from(post.nullifier_count).ok() != Some(nullifiers.keys().len())
    {
        return Err(RecoveryError::new(format!(
            "{label} post-state roots/counters differ from profile-pinned Poseidon reconstruction"
        )));
    }
    Ok(())
}

fn validate_state_delta(
    packet: &DirectActionPacketV2,
    denomination: u64,
    label: &str,
) -> Result<(u32, u32)> {
    let pre = &packet.pre_state;
    let post = &packet.post_state;
    let (note_delta, nullifier_delta) = match packet.kind {
        ActionKindV2::Deposit => (1, 0),
        ActionKindV2::Transfer => (1, 1),
        ActionKindV2::Withdrawal => (0, 1),
    };
    if post.note_count
        != pre
            .note_count
            .checked_add(note_delta)
            .ok_or_else(|| RecoveryError::new(format!("{label} note counter overflows")))?
        || post.nullifier_count
            != pre
                .nullifier_count
                .checked_add(nullifier_delta)
                .ok_or_else(|| RecoveryError::new(format!("{label} nullifier counter overflows")))?
        || post.action_sequence
            != pre
                .action_sequence
                .checked_add(1)
                .ok_or_else(|| RecoveryError::new(format!("{label} action sequence overflows")))?
    {
        return Err(RecoveryError::new(format!(
            "{label} exact state counter/sequence delta is invalid"
        )));
    }
    let expected_reserve = match packet.kind {
        ActionKindV2::Deposit => pre.reserve_sats.checked_add(denomination),
        ActionKindV2::Transfer => Some(pre.reserve_sats),
        ActionKindV2::Withdrawal => pre.reserve_sats.checked_sub(denomination),
    };
    if expected_reserve != Some(post.reserve_sats) {
        return Err(RecoveryError::new(format!(
            "{label} exact denomination reserve delta is invalid"
        )));
    }
    Ok((note_delta, nullifier_delta))
}

fn input_sources<'a>(
    transaction: &Transaction,
    previous: &'a Transaction,
    funding: &'a Transaction,
    carriers: usize,
    label: &str,
) -> Result<Vec<&'a Output>> {
    let mut sources = Vec::with_capacity(transaction.inputs.len());
    for index in 0..carriers {
        sources.push(previous.outputs.get(index + 1).ok_or_else(|| {
            RecoveryError::new(format!("{label} source verifier output is missing"))
        })?);
    }
    sources.push(
        previous.outputs.get(carriers + 1).ok_or_else(|| {
            RecoveryError::new(format!("{label} source binding output is missing"))
        })?,
    );
    sources.push(
        previous
            .outputs
            .first()
            .ok_or_else(|| RecoveryError::new(format!("{label} source state output is missing")))?,
    );
    let funding_index = usize::try_from(transaction.inputs[carriers + 2].outpoint_index)
        .map_err(|_| RecoveryError::new(format!("{label} funding index exceeds this platform")))?;
    sources.push(
        funding
            .outputs
            .get(funding_index)
            .ok_or_else(|| RecoveryError::new(format!("{label} funding output is missing")))?,
    );
    Ok(sources)
}

fn transaction_context(
    transaction: &Transaction,
    sources: &[&Output],
    packet: &DirectActionPacketV2,
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    carriers: usize,
) -> Result<DirectV2TransactionContext> {
    if transaction.inputs.len() != sources.len() {
        return Err(RecoveryError::new("internal source/input count mismatch"));
    }
    let inputs = transaction
        .inputs
        .iter()
        .zip(sources)
        .enumerate()
        .map(|(index, (input, source))| {
            require_context_lock(source, &format!("context source input {index}"))?;
            Ok(DirectV2ContextInput {
                role: input_role(index, carriers),
                outpoint_transaction_hash: input.outpoint_transaction_hash,
                outpoint_index: input.outpoint_index,
                sequence: input.sequence,
                value_sats: source.value_sats,
                locking_bytecode: source.locking_bytecode.clone(),
                token_prefix: source.token_prefix.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let outputs = transaction
        .outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            require_context_lock(output, &format!("context output {index}"))?;
            Ok(DirectV2ContextOutput {
                role: output_role(index, carriers, packet.kind),
                value_sats: output.value_sats,
                locking_bytecode: output.locking_bytecode.clone(),
                token_prefix: output.token_prefix.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DirectV2TransactionContext {
        network_id: packet.network_id,
        kind: packet.kind,
        profile_id: *profile_id,
        instance_id: *instance_id,
        transaction_version: transaction.version,
        locktime: transaction.locktime,
        pre_action_sequence: packet.pre_state.action_sequence,
        post_action_sequence: packet.post_state.action_sequence,
        inputs,
        outputs,
    })
}

fn input_role(index: usize, carriers: usize) -> DirectV2Role {
    if index < carriers {
        DirectV2Role {
            kind: DirectV2RoleKind::Verifier,
            ordinal: index as u8,
        }
    } else {
        DirectV2Role {
            kind: match index - carriers {
                0 => DirectV2RoleKind::Binding,
                1 => DirectV2RoleKind::State,
                _ => DirectV2RoleKind::Funding,
            },
            ordinal: 0,
        }
    }
}

fn output_role(index: usize, carriers: usize, kind: ActionKindV2) -> DirectV2Role {
    let role_kind = if index == 0 {
        DirectV2RoleKind::State
    } else if index <= carriers {
        DirectV2RoleKind::Verifier
    } else if index == carriers + 1 {
        DirectV2RoleKind::Binding
    } else if kind == ActionKindV2::Withdrawal && index == carriers + 2 {
        DirectV2RoleKind::Withdrawal
    } else {
        DirectV2RoleKind::Change
    };
    DirectV2Role {
        kind: role_kind,
        ordinal: if role_kind == DirectV2RoleKind::Verifier {
            (index - 1) as u8
        } else {
            0
        },
    }
}

fn validate_values_and_tail(
    transaction: &Transaction,
    sources: &[&Output],
    packet: &DirectActionPacketV2,
    denomination: u64,
    carriers: usize,
    label: &str,
) -> Result<()> {
    let input_total = sources.iter().try_fold(0_u64, |total, output| {
        total
            .checked_add(output.value_sats)
            .ok_or_else(|| RecoveryError::new(format!("{label} input value total overflows")))
    })?;
    let output_total = transaction
        .outputs
        .iter()
        .try_fold(0_u64, |total, output| {
            total
                .checked_add(output.value_sats)
                .ok_or_else(|| RecoveryError::new(format!("{label} output value total overflows")))
        })?;
    let fee = input_total
        .checked_sub(output_total)
        .ok_or_else(|| RecoveryError::new(format!("{label} output value exceeds input value")))?;
    let funding = sources[carriers + 2];
    let (change_index, payout_index) = if packet.kind == ActionKindV2::Withdrawal {
        (carriers + 3, Some(carriers + 2))
    } else {
        (carriers + 2, None)
    };
    let change = transaction
        .outputs
        .get(change_index)
        .ok_or_else(|| RecoveryError::new(format!("{label} change output is missing")))?;
    require_p2pkh(&change.locking_bytecode, &format!("{label} change output"))?;
    if change.value_sats == 0 || change.locking_bytecode == funding.locking_bytecode {
        return Err(RecoveryError::new(format!(
            "{label} change must be nonzero fresh P2PKH"
        )));
    }
    if let Some(index) = payout_index {
        let payout = &transaction.outputs[index];
        require_p2pkh(
            &payout.locking_bytecode,
            &format!("{label} withdrawal output"),
        )?;
        if payout.value_sats != denomination || payout.locking_bytecode == change.locking_bytecode {
            return Err(RecoveryError::new(format!(
                "{label} withdrawal payout must be exact denomination to a distinct P2PKH"
            )));
        }
        let payout_hash: [u8; 32] = Sha256::digest(&payout.locking_bytecode).into();
        if payout_hash != packet.withdrawal_locking_bytecode_hash {
            return Err(RecoveryError::new(format!(
                "{label} withdrawal locking-bytecode hash differs"
            )));
        }
    }
    let boundary = if packet.kind == ActionKindV2::Deposit {
        denomination
    } else {
        0
    };
    let expected_funding = change
        .value_sats
        .checked_add(fee)
        .and_then(|value| value.checked_add(boundary))
        .ok_or_else(|| RecoveryError::new(format!("{label} funding value overflows")))?;
    if funding.value_sats != expected_funding {
        return Err(RecoveryError::new(format!(
            "{label} funding prevout does not exactly fund change, fee, and deposit boundary"
        )));
    }
    Ok(())
}

fn snapshot_history_hash(genesis: &SnapshotPoint, actions: &[ActionSnapshot]) -> Result<String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct History<'a> {
        domain: &'static str,
        genesis: &'a SnapshotPoint,
        actions: &'a [ActionSnapshot],
    }
    sha256_json(&History {
        domain: "ShieldKit/V2Direct/recovery-history/v1",
        genesis,
        actions,
    })
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| RecoveryError::new(format!("canonical JSON encoding failed: {error}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn kind_name(kind: ActionKindV2) -> &'static str {
    match kind {
        ActionKindV2::Deposit => "deposit",
        ActionKindV2::Transfer => "transfer",
        ActionKindV2::Withdrawal => "withdrawal",
    }
}

fn validate_network(network: u8) -> Result<()> {
    if network != 1 && network != 2 {
        return Err(RecoveryError::new(
            "networkId must be mainnet 1 or chipnet 2",
        ));
    }
    Ok(())
}

fn identifier(value: &str, label: &str) -> Result<[u8; 32]> {
    fixed_bytes::<32>(value, label)
}

pub fn decode_lower_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(RecoveryError::new(format!(
            "{label} must be even-length lowercase hexadecimal"
        )));
    }
    hex::decode(value).map_err(|_| RecoveryError::new(format!("{label} is not valid hexadecimal")))
}

pub fn fixed_bytes<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = decode_lower_hex(value, label)?;
    if bytes.len() != N {
        return Err(RecoveryError::new(format!(
            "{label} must contain exactly {N} bytes"
        )));
    }
    let mut array = [0_u8; N];
    array.copy_from_slice(&bytes);
    Ok(array)
}

pub fn array32(value: &[u8], label: &str) -> Result<[u8; 32]> {
    if value.len() != 32 {
        return Err(RecoveryError::new(format!(
            "{label} must contain exactly 32 bytes"
        )));
    }
    let mut array = [0_u8; 32];
    array.copy_from_slice(value);
    Ok(array)
}

pub fn canonical_fr_bytes(value: &[u8; 32], label: &str) -> Result<Fr> {
    if value >= &BN254_FR_MODULUS {
        return Err(RecoveryError::new(format!(
            "{label} is not a canonical BN254 Fr encoding"
        )));
    }
    Ok(Fr::from_be_bytes_mod_order(value))
}

fn canonical_decimal(value: &str, label: &str) -> Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(RecoveryError::new(format!(
            "{label} must be a canonical unsigned decimal string"
        )));
    }
    value
        .parse::<u64>()
        .map_err(|_| RecoveryError::new(format!("{label} exceeds u64")))
}

fn codec_error(error: shieldkit_v2_codec::CodecError) -> RecoveryError {
    RecoveryError::new(format!("V2 codec rejected data: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_lower_hex_rejects_uppercase_and_odd_length() {
        assert!(decode_lower_hex("AA", "value").is_err());
        assert!(decode_lower_hex("a", "value").is_err());
        assert_eq!(decode_lower_hex("00ff", "value").expect("hex"), [0, 255]);
    }

    #[test]
    fn display_hash_import_is_used_consistently() {
        let display = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let wire = bch::parse_display_hash(display, "display").expect("hash");
        assert_eq!(bch::display_hash(&wire), display);
    }

    #[test]
    fn binding_unlock_requires_one_minimal_source_authenticated_p2sh32_redeem_push() {
        let mut packet = [0_u8; 552];
        packet[..4].copy_from_slice(b"SDA2");
        let redeem = [&[0x61; 256][..], &[0x75, 0x51][..]].concat();
        let mut source_lock = vec![0xaa, 0x20];
        source_lock.extend_from_slice(&bch::hash256(&redeem));
        source_lock.push(0x87);
        let mut prefix = vec![0x4d, 0x28, 0x02];
        prefix.extend_from_slice(&packet);
        let mut canonical = prefix.clone();
        canonical.extend(minimal_push(&redeem));
        assert_eq!(
            extract_packet(&canonical, &source_lock, "binding").expect("canonical"),
            packet
        );

        for malformed in [
            prefix.clone(),
            [canonical.as_slice(), &[0][..]].concat(),
            [
                prefix.as_slice(),
                &[0x4e, 0x02, 0x01, 0, 0][..],
                redeem.as_slice(),
            ]
            .concat(),
        ] {
            assert!(extract_packet(&malformed, &source_lock, "binding").is_err());
        }

        let mut wrong_redeem = redeem.clone();
        wrong_redeem[0] ^= 1;
        let wrong_unlock = [prefix.as_slice(), minimal_push(&wrong_redeem).as_slice()].concat();
        assert!(
            extract_packet(&wrong_unlock, &source_lock, "binding")
                .expect_err("wrong redeem")
                .to_string()
                .contains("hash256")
        );
        assert!(
            extract_packet(&canonical, &[0x75, 0x51], "binding")
                .expect_err("non-P2SH32 source")
                .to_string()
                .contains("P2SH32")
        );

        for numeric_redeem in [[0], [1], [16], [0x81]] {
            let mut numeric_lock = vec![0xaa, 0x20];
            numeric_lock.extend_from_slice(&bch::hash256(&numeric_redeem));
            numeric_lock.push(0x87);
            let numeric_unlock =
                [prefix.as_slice(), minimal_push(&numeric_redeem).as_slice()].concat();
            assert_eq!(
                extract_packet(&numeric_unlock, &numeric_lock, "binding")
                    .expect("minimal numeric redeem"),
                packet
            );
        }
    }
}
