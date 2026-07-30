//! Independent verifier for the Q07 *non-chain* lifecycle corpus.
//!
//! This module intentionally does not accept a recovery snapshot, transaction
//! ID, block hash, height, path, or network input. Those are chain-recovery
//! concepts with a separate external-authentication boundary. A successful
//! result here proves only that the deterministic qualification corpus is
//! internally consistent with the frozen V2 codecs and trees.

use crate::trees::{
    IndexedNullifierTree, NoteTree, materialize_indexed_nullifier_tree, materialize_note_tree,
};
use crate::{RecoveryError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use shieldkit_v2_codec::{
    ACTION_PACKET_BYTES, ActionKindV2, CommittedDirectV2TransactionContext, DirectActionPacketV2,
    DirectV2Account, DirectV2Address, DirectV2RoleKind, PoolStateV2, derive_direct_v2_address,
    recover_direct_v2_output,
};
use std::io::BufRead;

pub const Q07_LIFECYCLE_SCHEMA: &str = "shieldkit-v2-direct/q07-non-chain-lifecycle-corpus/v1";
pub const Q07_LIFECYCLE_RESULT_SCHEMA: &str =
    "shieldkit-v2-direct/q07-non-chain-lifecycle-corpus-result/v1";
pub const Q07_LIFECYCLE_ACTION_TRANSCRIPT_DOMAIN: &[u8] =
    b"ShieldKit/V2/Q07/non-chain-lifecycle/action-transcript/v1\0";
pub const Q07_LIFECYCLE_FULL_ACTIONS: u64 = 100_000;
pub const Q07_LIFECYCLE_FULL_TRANSFERS: u64 = 99_998;
const MAX_LINE_BYTES: usize = 256 * 1024;
const Q07_NETWORK_ID: u8 = 2;
const Q07_CARRIER_COUNT: u8 = 10;
const Q07_DENOMINATION_SATS: u64 = 10_000_000;
const Q07_MAXIMUM_LIVE_NOTES: u32 = 32;
const Q07_CARRIER_VALUE_SATS: u64 = 1_000;
const Q07_BINDING_VALUE_SATS: u64 = 1_000;
const Q07_STATE_BASE_SATS: u64 = 1_000;
const Q07_CHANGE_SATS: u64 = 2_000;
const Q07_FEE_SATS: u64 = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Q07LifecycleResult {
    pub action_count: String,
    pub action_counts: Q07ActionCounts,
    pub action_transcript_sha256: String,
    pub authority: String,
    pub body_sha256: String,
    pub chain_authenticated: bool,
    pub instance_id: String,
    pub profile_id: String,
    pub q07_lifecycle_corpus_verified: bool,
    pub q07_qualified: bool,
    pub schema: String,
    pub status: String,
    pub terminal_note_root: String,
    pub terminal_nullifier_root: String,
    pub terminal_state_hex: String,
    pub terminal_state_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Q07ActionCounts {
    pub deposit: String,
    pub transfer: String,
    pub withdrawal: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Header {
    account: QualificationAccount,
    action_count: String,
    action_counts: Q07ActionCounts,
    carrier_count: String,
    context_class: String,
    denomination_sats: String,
    instance_id: String,
    maximum_live_notes: String,
    network_id: String,
    profile_id: String,
    schema: String,
    #[serde(rename = "type")]
    frame_type: String,
    version: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationAccount {
    address: QualificationAddress,
    credentials_classification: String,
    incoming_view_secret: String,
    spend_secret: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationAddress {
    authority: String,
    incoming_view_public_key: String,
    instance_id: String,
    network_id: u8,
    profile_id: String,
    schema: String,
    spend_public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Action {
    action_transcript_sha256: String,
    context_hex: String,
    context_sha256: String,
    kind: String,
    ordinal: String,
    packet_hex: String,
    packet_sha256: String,
    schema: String,
    #[serde(rename = "type")]
    frame_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct End {
    action_count: String,
    action_counts: Q07ActionCounts,
    action_transcript_sha256: String,
    body_sha256: String,
    record_count: String,
    schema: String,
    terminal_state_hex: String,
    terminal_state_sha256: String,
    #[serde(rename = "type")]
    frame_type: String,
    version: String,
}

fn qerr(message: impl Into<String>) -> RecoveryError {
    RecoveryError::new(format!("Q07 lifecycle corpus: {}", message.into()))
}

fn parse_decimal(value: &str, label: &str) -> Result<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.as_bytes()[0] == b'0')
    {
        return Err(qerr(format!(
            "{label} must be a canonical unsigned decimal string"
        )));
    }
    value
        .parse::<u64>()
        .map_err(|_| qerr(format!("{label} exceeds u64")))
}

fn parse_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(qerr(format!(
            "{label} must be exactly {N} lowercase hexadecimal bytes"
        )));
    }
    let decoded = hex::decode(value).map_err(|_| qerr(format!("{label} is not hexadecimal")))?;
    decoded
        .try_into()
        .map_err(|_| qerr(format!("{label} length changed while decoding")))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn fixture_digest(label: &str) -> [u8; 32] {
    sha256(format!("ShieldKit/V2/Q07/non-chain-lifecycle/{label}").as_bytes())
}

fn expected_profile_id() -> [u8; 32] {
    fixture_digest("profile-id")
}
fn expected_instance_id() -> [u8; 32] {
    fixture_digest("instance-id")
}
fn qualification_secret(value: u8) -> [u8; 32] {
    let mut result = [0_u8; 32];
    result[31] = value;
    result
}

fn canonical_line<T: serde::Serialize>(value: &T, source: &[u8], label: &str) -> Result<()> {
    let canonical = serde_json::to_vec(value)
        .map_err(|error| qerr(format!("cannot canonicalize {label}: {error}")))?;
    if canonical != source {
        return Err(qerr(format!("{label} is not canonical JSON")));
    }
    Ok(())
}

fn read_line<R: BufRead>(reader: &mut R, label: &str) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| qerr(format!("cannot read {label}: {error}")))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(qerr(format!("{label} is missing final LF")))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line
            .len()
            .checked_add(take)
            .is_none_or(|size| size > MAX_LINE_BYTES)
        {
            return Err(qerr(format!("{label} exceeds {MAX_LINE_BYTES} bytes")));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                return Err(qerr(format!("{label} must use LF, not CRLF")));
            }
            return Ok(Some(line));
        }
    }
}

fn decode_canonical<T: for<'a> Deserialize<'a> + serde::Serialize>(
    line: &[u8],
    label: &str,
) -> Result<T> {
    if line.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(qerr(format!("{label} contains a UTF-8 BOM")));
    }
    let parsed = serde_json::from_slice::<T>(line)
        .map_err(|error| qerr(format!("invalid {label}: {error}")))?;
    canonical_line(&parsed, line, label)?;
    Ok(parsed)
}

fn require_counts(counts: &Q07ActionCounts, transfers: u64) -> Result<()> {
    if parse_decimal(&counts.deposit, "actionCounts.deposit")? != 1
        || parse_decimal(&counts.transfer, "actionCounts.transfer")? != transfers
        || parse_decimal(&counts.withdrawal, "actionCounts.withdrawal")? != 1
    {
        return Err(qerr(
            "actionCounts does not match required lifecycle schedule",
        ));
    }
    Ok(())
}

fn account_from_header(header: &Header) -> Result<DirectV2Account> {
    let address = &header.account.address;
    if address.schema != "shieldkit-address-v2-direct" {
        return Err(qerr("qualification account address schema differs"));
    }
    let direct = DirectV2Address {
        network_id: address.network_id,
        profile_id: parse_hex(&address.profile_id, "account.address.profileId")?,
        instance_id: parse_hex(&address.instance_id, "account.address.instanceId")?,
        spend_public_key: parse_hex(&address.spend_public_key, "account.address.spendPublicKey")?,
        incoming_view_public_key: parse_hex(
            &address.incoming_view_public_key,
            "account.address.incomingViewPublicKey",
        )?,
        authority: parse_hex(&address.authority, "account.address.authority")?,
    };
    let account = DirectV2Account {
        address: direct,
        spend_secret: parse_hex(&header.account.spend_secret, "account.spendSecret")?,
        incoming_view_secret: parse_hex(
            &header.account.incoming_view_secret,
            "account.incomingViewSecret",
        )?,
    };
    account
        .validate()
        .map_err(|error| qerr(format!("qualification account is invalid: {error}")))?;
    let expected = DirectV2Account {
        address: derive_direct_v2_address(
            Q07_NETWORK_ID,
            expected_profile_id(),
            expected_instance_id(),
            &qualification_secret(7),
            &qualification_secret(8),
        )
        .map_err(|error| {
            qerr(format!(
                "cannot derive pinned qualification account: {error}"
            ))
        })?,
        spend_secret: qualification_secret(7),
        incoming_view_secret: qualification_secret(8),
    };
    if account != expected {
        return Err(qerr(
            "qualification account is not the exact public deterministic account",
        ));
    }
    Ok(account)
}

fn fixture_context_hash(label: &str, ordinal: u64, index: u64) -> [u8; 32] {
    fixture_digest(&format!("context/{label}/{ordinal}/{index}"))
}

fn state_token_prefix_hash(state: &PoolStateV2) -> Result<[u8; 32]> {
    let mut prefix = Vec::with_capacity(163);
    prefix.push(0xef);
    // The mutable state NFT category is the pool instance identifier. The
    // JavaScript fixture passes its display-order reverse to libauth, which
    // serializes this exact protocol/wire-order value.
    prefix.extend_from_slice(&expected_instance_id());
    prefix.extend_from_slice(&[0x61, 0x80]);
    prefix.extend_from_slice(
        &state
            .encode(Q07_DENOMINATION_SATS)
            .map_err(|error| qerr(error.to_string()))?,
    );
    if prefix.len() != 163 {
        return Err(qerr("fixture state token prefix length differs"));
    }
    Ok(sha256(&prefix))
}

#[allow(clippy::too_many_arguments)]
fn assert_fixture_input(
    context: &CommittedDirectV2TransactionContext,
    index: usize,
    kind: DirectV2RoleKind,
    ordinal: u8,
    outpoint_hash: [u8; 32],
    outpoint_index: u32,
    value_sats: u64,
    token_hash: [u8; 32],
    label: &str,
) -> Result<()> {
    let input = context
        .inputs
        .get(index)
        .ok_or_else(|| qerr(format!("fixture {label} input is missing")))?;
    if input.role.kind != kind
        || input.role.ordinal != ordinal
        || input.outpoint_transaction_hash != outpoint_hash
        || input.outpoint_index != outpoint_index
        || input.sequence != 0
        || input.value_sats != value_sats
        || input.locking_bytecode_hash != sha256(&[0x51])
        || input.token_prefix_hash != token_hash
    {
        return Err(qerr(format!("fixture {label} input differs")));
    }
    Ok(())
}

fn assert_fixture_output(
    context: &CommittedDirectV2TransactionContext,
    index: usize,
    kind: DirectV2RoleKind,
    ordinal: u8,
    value_sats: u64,
    token_hash: [u8; 32],
    label: &str,
) -> Result<()> {
    let output = context
        .outputs
        .get(index)
        .ok_or_else(|| qerr(format!("fixture {label} output is missing")))?;
    if output.role.kind != kind
        || output.role.ordinal != ordinal
        || output.value_sats != value_sats
        || output.locking_bytecode_hash != sha256(&[0x51])
        || output.token_prefix_hash != token_hash
    {
        return Err(qerr(format!("fixture {label} output differs")));
    }
    Ok(())
}

fn validate_exact_fixture_context(
    context: &CommittedDirectV2TransactionContext,
    packet: &DirectActionPacketV2,
    ordinal: u64,
) -> Result<()> {
    context
        .validate_role_topology(Q07_CARRIER_COUNT)
        .map_err(|error| qerr(format!("fixture context topology differs: {error}")))?;
    if context.network_id != Q07_NETWORK_ID
        || context.kind != packet.kind
        || context.profile_id != expected_profile_id()
        || context.instance_id != expected_instance_id()
        || context.transaction_version != 2
        || context.locktime != 0
        || context.pre_action_sequence != packet.pre_state.action_sequence
        || context.post_action_sequence != packet.post_state.action_sequence
    {
        return Err(qerr("fixture context header differs"));
    }
    let empty = sha256(&[]);
    let carriers = usize::from(Q07_CARRIER_COUNT);
    for carrier in 0..carriers {
        assert_fixture_input(
            context,
            carrier,
            DirectV2RoleKind::Verifier,
            carrier as u8,
            fixture_context_hash("carrier-input", ordinal, carrier as u64),
            carrier as u32,
            Q07_CARRIER_VALUE_SATS,
            empty,
            "carrier",
        )?;
        assert_fixture_output(
            context,
            carrier + 1,
            DirectV2RoleKind::Verifier,
            carrier as u8,
            Q07_CARRIER_VALUE_SATS,
            empty,
            "carrier",
        )?;
    }
    assert_fixture_input(
        context,
        carriers,
        DirectV2RoleKind::Binding,
        0,
        fixture_context_hash("binding-input", ordinal, 0),
        0,
        Q07_BINDING_VALUE_SATS,
        empty,
        "binding",
    )?;
    assert_fixture_input(
        context,
        carriers + 1,
        DirectV2RoleKind::State,
        0,
        fixture_context_hash("state-input", ordinal, 0),
        0,
        Q07_STATE_BASE_SATS + packet.pre_state.reserve_sats,
        state_token_prefix_hash(&packet.pre_state)?,
        "state",
    )?;
    let reserve_delta = packet
        .post_state
        .reserve_sats
        .saturating_sub(packet.pre_state.reserve_sats);
    assert_fixture_input(
        context,
        carriers + 2,
        DirectV2RoleKind::Funding,
        0,
        fixture_context_hash("funding-input", ordinal, 0),
        0,
        reserve_delta + Q07_CHANGE_SATS + Q07_FEE_SATS,
        empty,
        "funding",
    )?;
    assert_fixture_output(
        context,
        0,
        DirectV2RoleKind::State,
        0,
        Q07_STATE_BASE_SATS + packet.post_state.reserve_sats,
        state_token_prefix_hash(&packet.post_state)?,
        "state",
    )?;
    assert_fixture_output(
        context,
        carriers + 1,
        DirectV2RoleKind::Binding,
        0,
        Q07_BINDING_VALUE_SATS,
        empty,
        "binding",
    )?;
    if packet.kind == ActionKindV2::Withdrawal {
        assert_fixture_output(
            context,
            carriers + 2,
            DirectV2RoleKind::Withdrawal,
            0,
            Q07_DENOMINATION_SATS,
            empty,
            "withdrawal",
        )?;
        assert_fixture_output(
            context,
            carriers + 3,
            DirectV2RoleKind::Change,
            0,
            Q07_CHANGE_SATS,
            empty,
            "change",
        )?;
    } else {
        assert_fixture_output(
            context,
            carriers + 2,
            DirectV2RoleKind::Change,
            0,
            Q07_CHANGE_SATS,
            empty,
            "change",
        )?;
    }
    let input_total = context
        .inputs
        .iter()
        .try_fold(0_u64, |total, input| total.checked_add(input.value_sats))
        .ok_or_else(|| qerr("fixture input total overflows"))?;
    let output_total = context
        .outputs
        .iter()
        .try_fold(0_u64, |total, output| total.checked_add(output.value_sats))
        .ok_or_else(|| qerr("fixture output total overflows"))?;
    if input_total
        != output_total
            .checked_add(Q07_FEE_SATS)
            .ok_or_else(|| qerr("fixture output total overflows"))?
    {
        return Err(qerr("fixture value conservation differs"));
    }
    Ok(())
}

fn expected_kind(ordinal: u64, action_count: u64) -> &'static str {
    if ordinal == 1 {
        "deposit"
    } else if ordinal == action_count {
        "withdrawal"
    } else {
        "transfer"
    }
}

fn action_kind_name(kind: ActionKindV2) -> &'static str {
    match kind {
        ActionKindV2::Deposit => "deposit",
        ActionKindV2::Transfer => "transfer",
        ActionKindV2::Withdrawal => "withdrawal",
    }
}

fn action_projection(action: &Action) -> Value {
    serde_json::json!({
        "contextHex": action.context_hex,
        "contextSha256": action.context_sha256,
        "kind": action.kind,
        "ordinal": action.ordinal,
        "packetHex": action.packet_hex,
        "packetSha256": action.packet_sha256,
        "schema": action.schema,
        "type": action.frame_type,
    })
}

fn action_projection_bytes(action: &Action) -> Result<Vec<u8>> {
    serde_json::to_vec(&action_projection(action))
        .map_err(|error| qerr(format!("cannot canonicalize action projection: {error}")))
}

#[allow(clippy::too_many_arguments)]
fn validate_action(
    action: &Action,
    header: &Header,
    account: &DirectV2Account,
    ordinal: u64,
    action_count: u64,
    current_state: &PoolStateV2,
    live_note: &mut Option<shieldkit_v2_codec::RecoveredDirectV2Output>,
    notes: &mut NoteTree,
    nullifiers: &mut IndexedNullifierTree,
) -> Result<PoolStateV2> {
    if action.schema != Q07_LIFECYCLE_SCHEMA || action.frame_type != "action" {
        return Err(qerr(format!("action {ordinal} schema/type differs")));
    }
    if parse_decimal(&action.ordinal, "action.ordinal")? != ordinal {
        return Err(qerr(format!("action {ordinal} ordinal differs")));
    }
    if action.kind != expected_kind(ordinal, action_count) {
        return Err(qerr(format!("action {ordinal} kind violates schedule")));
    }
    let packet_bytes = hex::decode(&action.packet_hex)
        .map_err(|_| qerr(format!("action {ordinal} packetHex is invalid")))?;
    if packet_bytes.len() != ACTION_PACKET_BYTES || action.packet_hex != hex::encode(&packet_bytes)
    {
        return Err(qerr(format!(
            "action {ordinal} packetHex is noncanonical or wrong length"
        )));
    }
    if parse_hex::<32>(&action.packet_sha256, "action.packetSha256")? != sha256(&packet_bytes) {
        return Err(qerr(format!("action {ordinal} packet SHA-256 differs")));
    }
    let context_bytes = hex::decode(&action.context_hex)
        .map_err(|_| qerr(format!("action {ordinal} contextHex is invalid")))?;
    if action.context_hex != hex::encode(&context_bytes) {
        return Err(qerr(format!("action {ordinal} contextHex is noncanonical")));
    }
    if parse_hex::<32>(&action.context_sha256, "action.contextSha256")? != sha256(&context_bytes) {
        return Err(qerr(format!("action {ordinal} context SHA-256 differs")));
    }
    let context = shieldkit_v2_codec::CommittedDirectV2TransactionContext::decode(&context_bytes)
        .map_err(|error| qerr(format!("action {ordinal} context is invalid: {error}")))?;
    let packet = DirectActionPacketV2::decode(
        &packet_bytes,
        parse_decimal(&header.denomination_sats, "denominationSats")?,
    )
    .map_err(|error| qerr(format!("action {ordinal} packet is invalid: {error}")))?;
    if action.kind != action_kind_name(packet.kind) {
        return Err(qerr(format!("action {ordinal} text/packet kind differs")));
    }
    validate_exact_fixture_context(&context, &packet, ordinal)?;
    let zero32 = [0_u8; 32];
    if (packet.kind == ActionKindV2::Withdrawal
        && packet.withdrawal_locking_bytecode_hash != sha256(&[0x51]))
        || (packet.kind != ActionKindV2::Withdrawal
            && packet.withdrawal_locking_bytecode_hash != zero32)
    {
        return Err(qerr(format!(
            "action {ordinal} withdrawal payout binding differs"
        )));
    }
    if packet.transaction_context_hash != sha256(&context_bytes)
        || packet.network_id
            != u8::try_from(parse_decimal(&header.network_id, "networkId")?)
                .map_err(|_| qerr("networkId exceeds u8"))?
        || packet.instance_id != parse_hex(&header.instance_id, "instanceId")?
        || packet.pre_state.profile_id != parse_hex(&header.profile_id, "profileId")?
        || packet.post_state.profile_id != parse_hex(&header.profile_id, "profileId")?
        || packet.pre_state != *current_state
        || context.network_id != packet.network_id
        || context.kind != packet.kind
        || context.instance_id != packet.instance_id
        || context.pre_action_sequence != packet.pre_state.action_sequence
        || context.post_action_sequence != packet.post_state.action_sequence
    {
        return Err(qerr(format!(
            "action {ordinal} packet/context/state binding differs"
        )));
    }
    let denomination = parse_decimal(&header.denomination_sats, "denominationSats")?;
    if packet.post_state.action_sequence != packet.pre_state.action_sequence + 1
        || packet.post_state.maximum_live_notes != packet.pre_state.maximum_live_notes
    {
        return Err(qerr(format!(
            "action {ordinal} state transition sequence/capacity differs"
        )));
    }
    match packet.kind {
        ActionKindV2::Deposit => {
            if live_note.is_some()
                || packet.post_state.note_count != packet.pre_state.note_count + 1
                || packet.post_state.nullifier_count != packet.pre_state.nullifier_count
                || packet.post_state.reserve_sats != packet.pre_state.reserve_sats + denomination
            {
                return Err(qerr("deposit transition counters/reserve/live-note differ"));
            }
            let recovered = recover_direct_v2_output(
                account,
                &packet.output_note_leaf,
                &packet.encrypted_record,
            )
            .map_err(|error| qerr(format!("deposit output cannot be recovered: {error}")))?;
            notes
                .append(packet.output_note_leaf)
                .map_err(|error| qerr(error.to_string()))?;
            *live_note = Some(recovered);
        }
        ActionKindV2::Transfer => {
            let prior = live_note
                .take()
                .ok_or_else(|| qerr("transfer has no live qualification note"))?;
            if packet.public_nullifier != prior.nullifier
                || packet.post_state.note_count != packet.pre_state.note_count + 1
                || packet.post_state.nullifier_count != packet.pre_state.nullifier_count + 1
                || packet.post_state.reserve_sats != packet.pre_state.reserve_sats
            {
                return Err(qerr("transfer transition/nullifier counters differ"));
            }
            nullifiers
                .insert(packet.public_nullifier)
                .map_err(|error| qerr(error.to_string()))?;
            let recovered = recover_direct_v2_output(
                account,
                &packet.output_note_leaf,
                &packet.encrypted_record,
            )
            .map_err(|error| qerr(format!("transfer output cannot be recovered: {error}")))?;
            notes
                .append(packet.output_note_leaf)
                .map_err(|error| qerr(error.to_string()))?;
            *live_note = Some(recovered);
        }
        ActionKindV2::Withdrawal => {
            let prior = live_note
                .take()
                .ok_or_else(|| qerr("withdrawal has no live qualification note"))?;
            if packet.public_nullifier != prior.nullifier
                || packet.post_state.note_count != packet.pre_state.note_count
                || packet.post_state.nullifier_count != packet.pre_state.nullifier_count + 1
                || packet.pre_state.reserve_sats != denomination
                || packet.post_state.reserve_sats != 0
            {
                return Err(qerr("withdrawal transition/nullifier counters differ"));
            }
            nullifiers
                .insert(packet.public_nullifier)
                .map_err(|error| qerr(error.to_string()))?;
        }
    }
    if packet.post_state.note_root
        != notes
            .root_bytes()
            .map_err(|error| qerr(error.to_string()))?
        || packet.post_state.nullifier_root
            != nullifiers
                .root_bytes()
                .map_err(|error| qerr(error.to_string()))?
    {
        return Err(qerr(format!("action {ordinal} post-state roots differ")));
    }
    Ok(packet.post_state)
}

fn verify_with_transfer_count<R: BufRead>(
    mut reader: R,
    transfers: u64,
) -> Result<Q07LifecycleResult> {
    let header_line = read_line(&mut reader, "header")?.ok_or_else(|| qerr("missing header"))?;
    let header: Header = decode_canonical(&header_line, "header")?;
    let action_count = transfers
        .checked_add(2)
        .ok_or_else(|| qerr("action count overflow"))?;
    if header.schema != Q07_LIFECYCLE_SCHEMA
        || header.frame_type != "header"
        || header.version != "1"
        || header.context_class != "deterministic-non-chain-fixture-context-not-chain-authenticated"
        || header.account.credentials_classification
            != "explicit-public-deterministic-qualification-only-non-operational"
        || parse_decimal(&header.action_count, "actionCount")? != action_count
        || parse_decimal(&header.network_id, "networkId")? != u64::from(Q07_NETWORK_ID)
        || parse_decimal(&header.carrier_count, "carrierCount")? != u64::from(Q07_CARRIER_COUNT)
        || parse_decimal(&header.denomination_sats, "denominationSats")? != Q07_DENOMINATION_SATS
        || parse_decimal(&header.maximum_live_notes, "maximumLiveNotes")?
            != u64::from(Q07_MAXIMUM_LIVE_NOTES)
        || parse_hex::<32>(&header.profile_id, "profileId")? != expected_profile_id()
        || parse_hex::<32>(&header.instance_id, "instanceId")? != expected_instance_id()
    {
        return Err(qerr(
            "header differs from frozen non-chain lifecycle profile",
        ));
    }
    require_counts(&header.action_counts, transfers)?;
    let account = account_from_header(&header)?;
    if account.address.network_id != parse_decimal(&header.network_id, "networkId")? as u8
        || account.address.profile_id != parse_hex(&header.profile_id, "profileId")?
        || account.address.instance_id != parse_hex(&header.instance_id, "instanceId")?
    {
        return Err(qerr("qualification account does not bind header identity"));
    }
    let denomination = parse_decimal(&header.denomination_sats, "denominationSats")?;
    let maximum_live_notes = u32::try_from(parse_decimal(
        &header.maximum_live_notes,
        "maximumLiveNotes",
    )?)
    .map_err(|_| qerr("maximumLiveNotes exceeds u32"))?;
    let mut notes = NoteTree::empty().map_err(|error| qerr(error.to_string()))?;
    let mut nullifiers = IndexedNullifierTree::empty().map_err(|error| qerr(error.to_string()))?;
    let mut current_state = PoolStateV2 {
        profile_id: parse_hex(&header.profile_id, "profileId")?,
        note_root: notes
            .root_bytes()
            .map_err(|error| qerr(error.to_string()))?,
        nullifier_root: nullifiers
            .root_bytes()
            .map_err(|error| qerr(error.to_string()))?,
        note_count: 0,
        nullifier_count: 0,
        maximum_live_notes,
        reserve_sats: 0,
        action_sequence: 0,
    };
    current_state
        .validate(denomination)
        .map_err(|error| qerr(format!("initial state invalid: {error}")))?;
    let mut body = Sha256::new();
    body.update(&header_line);
    body.update(b"\n");
    let mut transcript = Sha256::new();
    transcript.update(Q07_LIFECYCLE_ACTION_TRANSCRIPT_DOMAIN);
    transcript.update(&header_line);
    let mut transcript: [u8; 32] = transcript.finalize().into();
    let mut live_note = None;
    for ordinal in 1..=action_count {
        let line = read_line(&mut reader, &format!("action {ordinal}"))?
            .ok_or_else(|| qerr(format!("action {ordinal} is missing")))?;
        let action: Action = decode_canonical(&line, &format!("action {ordinal}"))?;
        let mut hasher = Sha256::new();
        hasher.update(Q07_LIFECYCLE_ACTION_TRANSCRIPT_DOMAIN);
        hasher.update(transcript);
        hasher.update(action_projection_bytes(&action)?);
        let expected: [u8; 32] = hasher.finalize().into();
        if parse_hex::<32>(
            &action.action_transcript_sha256,
            "action.actionTranscriptSha256",
        )? != expected
        {
            return Err(qerr(format!("action {ordinal} transcript differs")));
        }
        current_state = validate_action(
            &action,
            &header,
            &account,
            ordinal,
            action_count,
            &current_state,
            &mut live_note,
            &mut notes,
            &mut nullifiers,
        )?;
        body.update(&line);
        body.update(b"\n");
        transcript = expected;
    }
    if live_note.is_some() {
        return Err(qerr("terminal lifecycle still has a live note"));
    }
    let end_line = read_line(&mut reader, "end")?.ok_or_else(|| qerr("missing end"))?;
    let end: End = decode_canonical(&end_line, "end")?;
    if read_line(&mut reader, "trailing record")?.is_some() {
        return Err(qerr("contains a trailing record"));
    }
    let body_sha256: [u8; 32] = body.finalize().into();
    if end.schema != Q07_LIFECYCLE_SCHEMA
        || end.frame_type != "end"
        || end.version != "1"
        || parse_decimal(&end.action_count, "end.actionCount")? != action_count
        || parse_decimal(&end.record_count, "end.recordCount")? != action_count + 2
        || parse_hex::<32>(&end.action_transcript_sha256, "end.actionTranscriptSha256")?
            != transcript
        || parse_hex::<32>(&end.body_sha256, "end.bodySha256")? != body_sha256
    {
        return Err(qerr("end counters or transcript/body hashes differ"));
    }
    require_counts(&end.action_counts, transfers)?;
    let terminal_bytes = current_state
        .encode(denomination)
        .map_err(|error| qerr(error.to_string()))?;
    if end.terminal_state_hex != hex::encode(terminal_bytes)
        || parse_hex::<32>(&end.terminal_state_sha256, "end.terminalStateSha256")?
            != sha256(&terminal_bytes)
    {
        return Err(qerr("terminal state differs"));
    }
    let expected_terminal_notes =
        u32::try_from(transfers + 1).map_err(|_| qerr("terminal note count exceeds u32"))?;
    let expected_terminal_sequence = transfers + 2;
    if current_state.note_count != expected_terminal_notes
        || current_state.nullifier_count != expected_terminal_notes
        || current_state.reserve_sats != 0
        || current_state.action_sequence != expected_terminal_sequence
    {
        return Err(qerr("terminal lifecycle counters/reserve/sequence differ"));
    }
    if transfers == Q07_LIFECYCLE_FULL_TRANSFERS
        && (current_state.note_count != 99_999
            || current_state.nullifier_count != 99_999
            || current_state.reserve_sats != 0
            || current_state.action_sequence != 100_000)
    {
        return Err(qerr("full Q07 terminal counters/reserve/sequence differ"));
    }
    let note_bottom_up =
        materialize_note_tree(notes.leaves()).map_err(|error| qerr(error.to_string()))?;
    let nullifier_bottom_up = materialize_indexed_nullifier_tree(nullifiers.keys())
        .map_err(|error| qerr(error.to_string()))?;
    if note_bottom_up.summary.root != current_state.note_root
        || nullifier_bottom_up.summary.root != current_state.nullifier_root
    {
        return Err(qerr(
            "independent bottom-up terminal tree materialization differs",
        ));
    }
    Ok(Q07LifecycleResult {
        schema: Q07_LIFECYCLE_RESULT_SCHEMA.into(),
        status: "verified".into(),
        q07_lifecycle_corpus_verified: true,
        chain_authenticated: false,
        q07_qualified: false,
        authority: "non-chain-lifecycle-corpus".into(),
        action_count: action_count.to_string(),
        action_counts: Q07ActionCounts {
            deposit: "1".into(),
            transfer: transfers.to_string(),
            withdrawal: "1".into(),
        },
        profile_id: header.profile_id,
        instance_id: header.instance_id,
        action_transcript_sha256: hex::encode(transcript),
        body_sha256: end.body_sha256,
        terminal_state_sha256: end.terminal_state_sha256,
        terminal_state_hex: end.terminal_state_hex,
        terminal_note_root: hex::encode(current_state.note_root),
        terminal_nullifier_root: hex::encode(current_state.nullifier_root),
    })
}

/// Verify only the frozen, exact 100,000-action Q07 lifecycle schedule.
pub fn verify_q07_lifecycle<R: BufRead>(reader: R) -> Result<Q07LifecycleResult> {
    verify_with_transfer_count(reader, Q07_LIFECYCLE_FULL_TRANSFERS)
}

/// Test-only reduced schedule hook. It is intentionally not wired to a CLI.
#[doc(hidden)]
pub fn verify_q07_lifecycle_reduced_for_test<R: BufRead>(
    reader: R,
    transfers: u64,
) -> Result<Q07LifecycleResult> {
    if !(1..=62).contains(&transfers) {
        return Err(qerr(
            "test-only reduced schedule must contain 3 through 64 total actions",
        ));
    }
    verify_with_transfer_count(reader, transfers)
}
