use crate::{
    ActionSnapshot, AnchoredRawTransaction, AuthenticateSnapshotRequest,
    AuthenticatedCanonicalState, AuthenticatedNoteLeaf, AuthenticatedNullifierLeaf,
    AuthenticatedSnapshotBinding, AuthenticatedSnapshotResult, AuthenticatedSourceTransaction,
    AuthenticatedTreeFrontier, AuthenticatedTreeNode, RecoveryError, RecoverySnapshot, Result,
    SnapshotPoint, StreamingRawReplay, StreamingScanRequestHeader, authenticate_snapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use shieldkit_v2_codec::DirectActionPacketV2;
use std::io::{Read, Write};

pub const STREAM_MAGIC: &[u8; 8] = b"SKR2F001";
pub const STREAM_INPUT_SCHEMA: &str = "shieldkit-v2-recovery-stream-input-v2";
pub const AUTHENTICATE_STREAM_INPUT_SCHEMA: &str =
    "shieldkit-v2-recovery-authenticate-snapshot-stream-input-v2";
pub const STREAM_OUTPUT_SCHEMA: &str = "shieldkit-v2-recovery-stream-output-v2";
pub const MAX_FRAME_BYTES: usize = 512 * 1024;
pub const MAX_STREAM_ACTIONS: u64 = u32::MAX as u64 - 2;
const INPUT_TRANSCRIPT_DOMAIN: &[u8] = b"ShieldKit V2 recovery stream input v2\0";
const AUTHENTICATE_INPUT_TRANSCRIPT_DOMAIN: &[u8] =
    b"ShieldKit V2 recovery authenticate snapshot stream input v2\0";
const OUTPUT_TRANSCRIPT_DOMAIN: &[u8] = b"ShieldKit V2 recovery stream output v2\0";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputHeader {
    schema: String,
    #[serde(rename = "type")]
    frame_type: String,
    action_count: String,
    request: StreamingScanRequestHeader,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputAction {
    schema: String,
    #[serde(rename = "type")]
    frame_type: String,
    index: String,
    action: AnchoredRawTransaction,
    funding_prevout: AuthenticatedSourceTransaction,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputEnd {
    schema: String,
    #[serde(rename = "type")]
    frame_type: String,
    action_count: String,
    frame_count: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticateInputHeader {
    schema: String,
    #[serde(rename = "type")]
    frame_type: String,
    action_count: String,
    request: StreamingAuthenticateSnapshotRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StreamingAuthenticateSnapshotRequest {
    network_id: u8,
    profile_id: String,
    instance_id: String,
    denomination_sats: String,
    carrier_count: u8,
    runtime_materials_sha256: String,
    genesis: SnapshotPoint,
    tip: SnapshotPoint,
    snapshot: CompactRecoverySnapshot,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompactRecoverySnapshot {
    schema: String,
    version: u8,
    network_id: u8,
    profile_id: String,
    instance_id: String,
    denomination_sats: String,
    carrier_count: u8,
    runtime_materials_sha256: String,
    poseidon_profile: String,
    genesis: SnapshotPoint,
    tip: SnapshotPoint,
    action_count: String,
    history_sha256: String,
    state_hex: String,
    note_tree: CompactTreeSnapshot,
    nullifier_tree: CompactTreeSnapshot,
    external_authentication_boundary: String,
    content_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompactTreeSnapshot {
    depth: u8,
    count: String,
    root: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticateInputAction {
    schema: String,
    #[serde(rename = "type")]
    frame_type: String,
    index: String,
    action: ActionSnapshot,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputHeader<'a> {
    schema: &'a str,
    #[serde(rename = "type")]
    frame_type: &'a str,
    action_count: String,
    note_node_count: String,
    note_frontier_count: String,
    note_leaf_count: String,
    nullifier_node_count: String,
    nullifier_leaf_count: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputRecord<'a, T: Serialize> {
    schema: &'a str,
    #[serde(rename = "type")]
    frame_type: &'a str,
    index: String,
    value: T,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputEnd<'a> {
    schema: &'a str,
    #[serde(rename = "type")]
    frame_type: &'a str,
    action_count: String,
    note_node_count: String,
    note_frontier_count: String,
    note_leaf_count: String,
    nullifier_node_count: String,
    nullifier_leaf_count: String,
    frame_count: String,
    digest: String,
}

struct FramedReader<R> {
    inner: R,
}

impl<R: Read> FramedReader<R> {
    fn open(mut inner: R) -> Result<Self> {
        let mut magic = [0_u8; STREAM_MAGIC.len()];
        read_exact_labeled(&mut inner, &mut magic, "stream magic")?;
        if &magic != STREAM_MAGIC {
            return Err(RecoveryError::new(
                "recovery stream magic or framing version is unsupported",
            ));
        }
        Ok(Self { inner })
    }

    fn frame(&mut self, label: &str) -> Result<Vec<u8>> {
        let mut length_bytes = [0_u8; 4];
        read_exact_labeled(&mut self.inner, &mut length_bytes, label)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(RecoveryError::new(format!(
                "{label} length must be from 1 to {MAX_FRAME_BYTES} bytes"
            )));
        }
        let mut payload = vec![0_u8; length];
        read_exact_labeled(&mut self.inner, &mut payload, label)?;
        Ok(payload)
    }

    fn require_eof(&mut self) -> Result<()> {
        let mut trailing = [0_u8; 1];
        match self.inner.read(&mut trailing) {
            Ok(0) => Ok(()),
            Ok(_) => Err(RecoveryError::new(
                "recovery stream has trailing data after its end frame",
            )),
            Err(error) => Err(RecoveryError::new(format!(
                "cannot check recovery stream trailing data: {error}"
            ))),
        }
    }
}

struct FramedWriter<W> {
    inner: W,
    digest: Sha256,
    frame_count: u64,
}

impl<W: Write> FramedWriter<W> {
    fn open(mut inner: W) -> Result<Self> {
        inner
            .write_all(STREAM_MAGIC)
            .map_err(|error| RecoveryError::new(format!("cannot write stream magic: {error}")))?;
        let mut digest = Sha256::new();
        digest.update(OUTPUT_TRANSCRIPT_DOMAIN);
        Ok(Self {
            inner,
            digest,
            frame_count: 0,
        })
    }

    fn data<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let payload = serde_json::to_vec(value).map_err(|error| {
            RecoveryError::new(format!("cannot encode recovery output frame: {error}"))
        })?;
        let framed = checked_frame(&payload, "recovery output frame")?;
        self.digest.update(&framed);
        self.inner.write_all(&framed).map_err(|error| {
            RecoveryError::new(format!("cannot write recovery output frame: {error}"))
        })?;
        self.frame_count = self
            .frame_count
            .checked_add(1)
            .ok_or_else(|| RecoveryError::new("recovery output frame count overflowed"))?;
        Ok(())
    }

    fn end<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let payload = serde_json::to_vec(value).map_err(|error| {
            RecoveryError::new(format!("cannot encode recovery output end frame: {error}"))
        })?;
        let framed = checked_frame(&payload, "recovery output end frame")?;
        self.inner.write_all(&framed).map_err(|error| {
            RecoveryError::new(format!("cannot write recovery output end frame: {error}"))
        })?;
        self.inner
            .flush()
            .map_err(|error| RecoveryError::new(format!("cannot flush recovery output: {error}")))
    }

    fn digest_hex(&self) -> String {
        hex::encode(self.digest.clone().finalize())
    }
}

fn checked_frame(payload: &[u8], label: &str) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(RecoveryError::new(format!(
            "{label} length must be from 1 to {MAX_FRAME_BYTES} bytes"
        )));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| RecoveryError::new(format!("{label} length exceeds u32")))?;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

fn read_exact_labeled<R: Read>(reader: &mut R, bytes: &mut [u8], label: &str) -> Result<()> {
    reader
        .read_exact(bytes)
        .map_err(|error| RecoveryError::new(format!("{label} is truncated: {error}")))
}

fn canonical_count(value: &str, label: &str, maximum: u64) -> Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RecoveryError::new(format!(
            "{label} must be a canonical unsigned decimal integer"
        )));
    }
    let count = value
        .parse::<u64>()
        .map_err(|_| RecoveryError::new(format!("{label} exceeds u64")))?;
    if count > maximum {
        return Err(RecoveryError::new(format!(
            "{label} exceeds the protocol maximum {maximum}"
        )));
    }
    Ok(count)
}

fn frame_type(payload: &[u8], label: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|error| RecoveryError::new(format!("{label} is not strict JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| RecoveryError::new(format!("{label} must be a JSON object")))?;
    object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| RecoveryError::new(format!("{label}.type must be a string")))
}

fn require_input_identity(
    schema: &str,
    frame_type: &str,
    expected_schema: &str,
    expected_type: &str,
) -> Result<()> {
    if schema != expected_schema || frame_type != expected_type {
        return Err(RecoveryError::new(format!(
            "expected {expected_schema} {expected_type} frame"
        )));
    }
    Ok(())
}

fn update_input_digest(digest: &mut Sha256, payload: &[u8]) -> Result<()> {
    digest.update(checked_frame(payload, "recovery input frame")?);
    Ok(())
}

/// Consume a strict framed raw history without constructing a monolithic JSON
/// request and emit individually framed authenticated records. The caller must
/// stage all output and trust it only after validating the terminal frame.
pub fn scan_framed<R: Read, W: Write>(input: R, output: W) -> Result<()> {
    let mut reader = FramedReader::open(input)?;
    let mut input_digest = Sha256::new();
    input_digest.update(INPUT_TRANSCRIPT_DOMAIN);

    let header_payload = reader.frame("recovery stream header frame")?;
    if frame_type(&header_payload, "recovery stream header frame")? != "header" {
        return Err(RecoveryError::new(
            "recovery stream must begin with a header frame",
        ));
    }
    let header: InputHeader = serde_json::from_slice(&header_payload).map_err(|error| {
        RecoveryError::new(format!("recovery stream header is invalid: {error}"))
    })?;
    require_input_identity(
        &header.schema,
        &header.frame_type,
        STREAM_INPUT_SCHEMA,
        "header",
    )?;
    let action_count = canonical_count(
        &header.action_count,
        "recovery stream header actionCount",
        MAX_STREAM_ACTIONS,
    )?;
    update_input_digest(&mut input_digest, &header_payload)?;
    let mut replay = StreamingRawReplay::new(header.request)?;

    for index in 0..action_count {
        let payload = reader.frame(&format!("recovery stream action frame {index}"))?;
        if frame_type(&payload, &format!("recovery stream action frame {index}"))? != "action" {
            return Err(RecoveryError::new(format!(
                "recovery stream frame {} must be action {}",
                index + 1,
                index
            )));
        }
        let action: InputAction = serde_json::from_slice(&payload).map_err(|error| {
            RecoveryError::new(format!(
                "recovery stream action frame {index} is invalid: {error}"
            ))
        })?;
        require_input_identity(
            &action.schema,
            &action.frame_type,
            STREAM_INPUT_SCHEMA,
            "action",
        )?;
        let actual_index = canonical_count(
            &action.index,
            &format!("recovery stream action frame {index} index"),
            MAX_STREAM_ACTIONS,
        )?;
        if actual_index != index {
            return Err(RecoveryError::new(format!(
                "recovery stream action index {actual_index} is reordered or duplicated; expected {index}"
            )));
        }
        update_input_digest(&mut input_digest, &payload)?;
        replay.apply(action.action, action.funding_prevout)?;
    }

    let end_payload = reader.frame("recovery stream end frame")?;
    if frame_type(&end_payload, "recovery stream end frame")? != "end" {
        return Err(RecoveryError::new(
            "recovery stream lacks its exact end frame",
        ));
    }
    let end: InputEnd = serde_json::from_slice(&end_payload).map_err(|error| {
        RecoveryError::new(format!("recovery stream end frame is invalid: {error}"))
    })?;
    require_input_identity(&end.schema, &end.frame_type, STREAM_INPUT_SCHEMA, "end")?;
    let end_action_count = canonical_count(
        &end.action_count,
        "recovery stream end actionCount",
        MAX_STREAM_ACTIONS,
    )?;
    let end_frame_count = canonical_count(
        &end.frame_count,
        "recovery stream end frameCount",
        MAX_STREAM_ACTIONS + 1,
    )?;
    if end_action_count != action_count || end_frame_count != action_count + 1 {
        return Err(RecoveryError::new(
            "recovery stream end counts differ from the consumed frames",
        ));
    }
    if end.digest.len() != 64
        || !end
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RecoveryError::new(
            "recovery stream end digest must be 32 lowercase hexadecimal bytes",
        ));
    }
    let actual_input_digest = hex::encode(input_digest.finalize());
    if end.digest != actual_input_digest {
        return Err(RecoveryError::new(
            "recovery stream input transcript digest differs",
        ));
    }
    reader.require_eof()?;

    let (snapshot, material) = replay.finish()?;
    write_output(output, snapshot, material)
}

/// Consume a compact, independently anchored snapshot plus exactly ordered
/// action records. Ordered note leaves and nullifier keys are derived only from
/// decoded packets, then the existing authenticator materializes both terminal
/// trees bottom-up exactly once.
pub fn authenticate_snapshot_framed<R: Read, W: Write>(input: R, output: W) -> Result<()> {
    let mut reader = FramedReader::open(input)?;
    let mut input_digest = Sha256::new();
    input_digest.update(AUTHENTICATE_INPUT_TRANSCRIPT_DOMAIN);

    let header_payload = reader.frame("authenticate snapshot stream header frame")?;
    if frame_type(&header_payload, "authenticate snapshot stream header frame")? != "header" {
        return Err(RecoveryError::new(
            "authenticate snapshot stream must begin with a header frame",
        ));
    }
    let header: AuthenticateInputHeader =
        serde_json::from_slice(&header_payload).map_err(|error| {
            RecoveryError::new(format!(
                "authenticate snapshot stream header is invalid: {error}"
            ))
        })?;
    require_input_identity(
        &header.schema,
        &header.frame_type,
        AUTHENTICATE_STREAM_INPUT_SCHEMA,
        "header",
    )?;
    let action_count = canonical_count(
        &header.action_count,
        "authenticate snapshot stream header actionCount",
        MAX_STREAM_ACTIONS,
    )?;
    let snapshot_action_count = canonical_count(
        &header.request.snapshot.action_count,
        "authenticate snapshot stream compact snapshot actionCount",
        MAX_STREAM_ACTIONS,
    )?;
    if snapshot_action_count != action_count {
        return Err(RecoveryError::new(
            "authenticate snapshot stream header actionCount differs from its compact snapshot",
        ));
    }
    update_input_digest(&mut input_digest, &header_payload)?;

    let denomination = crate::canonical_decimal(
        &header.request.denomination_sats,
        "authenticate snapshot stream denominationSats",
    )?;
    if denomination == 0 {
        return Err(RecoveryError::new(
            "authenticate snapshot stream denominationSats must be nonzero",
        ));
    }
    let action_capacity = usize::try_from(action_count)
        .map_err(|_| RecoveryError::new("snapshot action count exceeds this platform"))?;
    let mut actions = Vec::with_capacity(action_capacity);
    let mut note_leaves = Vec::new();
    let mut nullifier_keys = Vec::new();
    for index in 0..action_count {
        let label = format!("authenticate snapshot stream action frame {index}");
        let payload = reader.frame(&label)?;
        if frame_type(&payload, &label)? != "action" {
            return Err(RecoveryError::new(format!(
                "authenticate snapshot stream frame {} must be action {}",
                index + 1,
                index
            )));
        }
        let action: AuthenticateInputAction = serde_json::from_slice(&payload)
            .map_err(|error| RecoveryError::new(format!("{label} is invalid: {error}")))?;
        require_input_identity(
            &action.schema,
            &action.frame_type,
            AUTHENTICATE_STREAM_INPUT_SCHEMA,
            "action",
        )?;
        let actual_index =
            canonical_count(&action.index, &format!("{label} index"), MAX_STREAM_ACTIONS)?;
        if actual_index != index {
            return Err(RecoveryError::new(format!(
                "authenticate snapshot stream action index {actual_index} is reordered or duplicated; expected {index}"
            )));
        }
        let packet_bytes =
            crate::fixed_bytes::<552>(&action.action.packet_hex, &format!("{label} packetHex"))?;
        let packet = DirectActionPacketV2::decode(&packet_bytes, denomination)
            .map_err(|error| RecoveryError::new(format!("{label} packet is invalid: {error}")))?;
        let (note_delta, nullifier_delta) =
            crate::validate_state_delta(&packet, denomination, &label)?;
        if note_delta == 1 {
            note_leaves.push(hex::encode(packet.output_note_leaf));
        }
        if nullifier_delta == 1 {
            nullifier_keys.push(hex::encode(packet.public_nullifier));
        }
        update_input_digest(&mut input_digest, &payload)?;
        actions.push(action.action);
    }

    let end_payload = reader.frame("authenticate snapshot stream end frame")?;
    if frame_type(&end_payload, "authenticate snapshot stream end frame")? != "end" {
        return Err(RecoveryError::new(
            "authenticate snapshot stream lacks its exact end frame",
        ));
    }
    let end: InputEnd = serde_json::from_slice(&end_payload).map_err(|error| {
        RecoveryError::new(format!(
            "authenticate snapshot stream end frame is invalid: {error}"
        ))
    })?;
    require_input_identity(
        &end.schema,
        &end.frame_type,
        AUTHENTICATE_STREAM_INPUT_SCHEMA,
        "end",
    )?;
    let end_action_count = canonical_count(
        &end.action_count,
        "authenticate snapshot stream end actionCount",
        MAX_STREAM_ACTIONS,
    )?;
    let end_frame_count = canonical_count(
        &end.frame_count,
        "authenticate snapshot stream end frameCount",
        MAX_STREAM_ACTIONS + 1,
    )?;
    if end_action_count != action_count || end_frame_count != action_count + 1 {
        return Err(RecoveryError::new(
            "authenticate snapshot stream end counts differ from the consumed frames",
        ));
    }
    if end.digest.len() != 64
        || !end
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RecoveryError::new(
            "authenticate snapshot stream end digest must be 32 lowercase hexadecimal bytes",
        ));
    }
    let actual_input_digest = hex::encode(input_digest.finalize());
    if end.digest != actual_input_digest {
        return Err(RecoveryError::new(
            "authenticate snapshot stream input transcript digest differs",
        ));
    }
    reader.require_eof()?;

    let StreamingAuthenticateSnapshotRequest {
        network_id,
        profile_id,
        instance_id,
        denomination_sats,
        carrier_count,
        runtime_materials_sha256,
        genesis,
        tip,
        snapshot,
    } = header.request;
    let compact = snapshot;
    let snapshot = RecoverySnapshot {
        schema: compact.schema,
        version: compact.version,
        network_id: compact.network_id,
        profile_id: compact.profile_id,
        instance_id: compact.instance_id,
        denomination_sats: compact.denomination_sats,
        carrier_count: compact.carrier_count,
        runtime_materials_sha256: compact.runtime_materials_sha256,
        poseidon_profile: compact.poseidon_profile,
        genesis: compact.genesis,
        tip: compact.tip,
        action_count: compact.action_count,
        history_sha256: compact.history_sha256,
        state_hex: compact.state_hex,
        note_tree: crate::NoteTreeSnapshot {
            depth: compact.note_tree.depth,
            count: compact.note_tree.count,
            root: compact.note_tree.root,
            leaves: note_leaves,
        },
        nullifier_tree: crate::NullifierTreeSnapshot {
            depth: compact.nullifier_tree.depth,
            count: compact.nullifier_tree.count,
            root: compact.nullifier_tree.root,
            keys: nullifier_keys,
        },
        actions,
        external_authentication_boundary: compact.external_authentication_boundary,
        content_sha256: compact.content_sha256,
    };
    let material = authenticate_snapshot(&AuthenticateSnapshotRequest {
        schema: crate::AUTHENTICATE_SNAPSHOT_SCHEMA.to_owned(),
        network_id,
        profile_id,
        instance_id,
        denomination_sats,
        carrier_count,
        runtime_materials_sha256,
        genesis,
        tip,
        snapshot: snapshot.clone(),
    })?;
    write_output(output, snapshot, material)
}

fn write_output<W: Write>(
    output: W,
    snapshot: RecoverySnapshot,
    material: AuthenticatedSnapshotResult,
) -> Result<()> {
    let RecoverySnapshot {
        schema: snapshot_schema,
        version,
        network_id,
        profile_id,
        instance_id,
        denomination_sats,
        carrier_count,
        runtime_materials_sha256,
        poseidon_profile,
        genesis,
        tip,
        action_count,
        history_sha256,
        state_hex,
        note_tree,
        nullifier_tree,
        actions,
        external_authentication_boundary,
        content_sha256,
    } = snapshot;
    let AuthenticatedSnapshotResult {
        schema: material_schema,
        content_sha256: material_content_sha256,
        binding,
        canonical,
        note_nodes,
        note_frontier,
        note_leaves,
        nullifier_nodes,
        nullifier_leaves,
    } = material;

    let counts = [
        u64::try_from(actions.len()).map_err(|_| RecoveryError::new("action count exceeds u64"))?,
        u64::try_from(note_nodes.len())
            .map_err(|_| RecoveryError::new("note node count exceeds u64"))?,
        u64::try_from(note_frontier.len())
            .map_err(|_| RecoveryError::new("note frontier count exceeds u64"))?,
        u64::try_from(note_leaves.len())
            .map_err(|_| RecoveryError::new("note leaf count exceeds u64"))?,
        u64::try_from(nullifier_nodes.len())
            .map_err(|_| RecoveryError::new("nullifier node count exceeds u64"))?,
        u64::try_from(nullifier_leaves.len())
            .map_err(|_| RecoveryError::new("nullifier leaf count exceeds u64"))?,
    ];
    let header = OutputHeader {
        schema: STREAM_OUTPUT_SCHEMA,
        frame_type: "header",
        action_count: counts[0].to_string(),
        note_node_count: counts[1].to_string(),
        note_frontier_count: counts[2].to_string(),
        note_leaf_count: counts[3].to_string(),
        nullifier_node_count: counts[4].to_string(),
        nullifier_leaf_count: counts[5].to_string(),
    };
    let mut writer = FramedWriter::open(output)?;
    writer.data(&header)?;

    let compact_snapshot = json!({
        "schema": snapshot_schema,
        "version": version,
        "networkId": network_id,
        "profileId": profile_id,
        "instanceId": instance_id,
        "denominationSats": denomination_sats,
        "carrierCount": carrier_count,
        "runtimeMaterialsSha256": runtime_materials_sha256,
        "poseidonProfile": poseidon_profile,
        "genesis": genesis,
        "tip": tip,
        "actionCount": action_count,
        "historySha256": history_sha256,
        "stateHex": state_hex,
        "noteTree": {
            "depth": note_tree.depth,
            "count": note_tree.count,
            "root": note_tree.root,
        },
        "nullifierTree": {
            "depth": nullifier_tree.depth,
            "count": nullifier_tree.count,
            "root": nullifier_tree.root,
        },
        "externalAuthenticationBoundary": external_authentication_boundary,
        "contentSha256": content_sha256,
    });
    let material_header = json!({
        "schema": material_schema,
        "contentSha256": material_content_sha256,
        "binding": binding,
        "canonical": canonical,
    });
    writer.data(&json!({
        "schema": STREAM_OUTPUT_SCHEMA,
        "type": "snapshot",
        "snapshot": compact_snapshot,
        "material": material_header,
    }))?;

    write_records(&mut writer, "action", actions)?;
    write_records(&mut writer, "note-node", note_nodes)?;
    write_records(&mut writer, "note-frontier", note_frontier)?;
    write_records(&mut writer, "note-leaf", note_leaves)?;
    write_records(&mut writer, "nullifier-node", nullifier_nodes)?;
    write_records(&mut writer, "nullifier-leaf", nullifier_leaves)?;

    let digest = writer.digest_hex();
    let end = OutputEnd {
        schema: STREAM_OUTPUT_SCHEMA,
        frame_type: "end",
        action_count: counts[0].to_string(),
        note_node_count: counts[1].to_string(),
        note_frontier_count: counts[2].to_string(),
        note_leaf_count: counts[3].to_string(),
        nullifier_node_count: counts[4].to_string(),
        nullifier_leaf_count: counts[5].to_string(),
        frame_count: writer.frame_count.to_string(),
        digest,
    };
    writer.end(&end)
}

fn write_records<W: Write, T: Serialize>(
    writer: &mut FramedWriter<W>,
    frame_type: &'static str,
    values: Vec<T>,
) -> Result<()> {
    for (index, value) in values.into_iter().enumerate() {
        writer.data(&OutputRecord {
            schema: STREAM_OUTPUT_SCHEMA,
            frame_type,
            index: index.to_string(),
            value,
        })?;
    }
    Ok(())
}

// Keep the concrete row types part of this module's compile-time wire audit.
const _: fn(
    ActionSnapshot,
    AuthenticatedSnapshotBinding,
    AuthenticatedCanonicalState,
    AuthenticatedTreeNode,
    AuthenticatedTreeFrontier,
    AuthenticatedNoteLeaf,
    AuthenticatedNullifierLeaf,
) = |_, _, _, _, _, _, _| {};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_length_is_hard_bounded() {
        assert!(checked_frame(&[], "empty").is_err());
        assert!(checked_frame(&vec![0_u8; MAX_FRAME_BYTES], "maximum").is_ok());
        assert!(checked_frame(&vec![0_u8; MAX_FRAME_BYTES + 1], "oversize").is_err());
    }

    #[test]
    fn framed_reader_rejects_truncation_and_trailing_data() {
        let mut truncated = STREAM_MAGIC.to_vec();
        truncated.extend_from_slice(&10_u32.to_be_bytes());
        truncated.extend_from_slice(b"short");
        let mut reader = FramedReader::open(Cursor::new(truncated)).expect("magic");
        assert!(
            reader
                .frame("test frame")
                .expect_err("truncation")
                .to_string()
                .contains("truncated")
        );

        let mut trailing = STREAM_MAGIC.to_vec();
        trailing.push(1);
        let mut reader = FramedReader::open(Cursor::new(trailing)).expect("magic");
        assert!(
            reader
                .require_eof()
                .expect_err("trailing")
                .to_string()
                .contains("trailing")
        );
    }

    #[test]
    fn canonical_counts_reject_aliases_and_protocol_overflow() {
        assert_eq!(canonical_count("0", "count", 10).expect("zero"), 0);
        assert_eq!(canonical_count("10", "count", 10).expect("ten"), 10);
        for invalid in ["", "00", "+1", "-1", " 1", "11"] {
            assert!(canonical_count(invalid, "count", 10).is_err(), "{invalid}");
        }
    }
}
