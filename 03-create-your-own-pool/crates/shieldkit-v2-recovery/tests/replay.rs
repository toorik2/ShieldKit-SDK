use sha2::{Digest, Sha256};
use shieldkit_v2_codec::{
    ActionKindV2, DirectActionPacketV2, DirectV2ContextInput, DirectV2ContextOutput, DirectV2Role,
    DirectV2RoleKind, DirectV2TransactionContext, PoolStateV2,
};
use shieldkit_v2_recovery::bch::{display_hash, hash256};
use shieldkit_v2_recovery::trees::{IndexedNullifierTree, NoteTree};
use shieldkit_v2_recovery::{
    AUTHENTICATE_SNAPSHOT_SCHEMA, AUTHENTICATED_MATERIAL_SCHEMA, AnchoredRawTransaction,
    AuthenticateSnapshotRequest, AuthenticatedSourceTransaction, DisplayOutpoint, ExpectedTip,
    SCAN_RESULT_SCHEMA, SCAN_SCHEMA, ScanRequest, VERIFY_SCHEMA, VerifySnapshotRequest,
    authenticate_snapshot, scan, scan_with_material,
    stream::{
        AUTHENTICATE_STREAM_INPUT_SCHEMA, STREAM_INPUT_SCHEMA, STREAM_MAGIC, STREAM_OUTPUT_SCHEMA,
        authenticate_snapshot_framed, scan_framed,
    },
    verify_snapshot,
};
use std::io::{Cursor, Read};

const DENOMINATION: u64 = 10_000_000;
const FEE: u64 = 500;
const CHANGE: u64 = 5_000;
const STATE_BASE: u64 = 2_000;
const BINDING_BASE: u64 = 1_500;

#[derive(Clone)]
struct ModelOutput {
    value: u64,
    token_prefix: Vec<u8>,
    lock: Vec<u8>,
}

impl ModelOutput {
    fn contents(&self) -> Vec<u8> {
        [&self.token_prefix[..], &self.lock[..]].concat()
    }
}

#[derive(Clone)]
struct ModelInput {
    hash: [u8; 32],
    index: u32,
    unlock: Vec<u8>,
    sequence: u32,
}

struct Fixture {
    request: ScanRequest,
}

fn role(kind: DirectV2RoleKind, ordinal: u8) -> DirectV2Role {
    DirectV2Role { kind, ordinal }
}

fn p2pkh(byte: u8) -> Vec<u8> {
    [&[0x76, 0xa9, 0x14][..], &[byte; 20], &[0x88, 0xac]].concat()
}

fn p2sh32(redeem: &[u8]) -> Vec<u8> {
    [&[0xaa, 0x20][..], &hash256(redeem), &[0x87]].concat()
}

fn data_push(data: &[u8]) -> Vec<u8> {
    let mut encoded = match data.len() {
        1..=75 => vec![data.len() as u8],
        76..=255 => vec![0x4c, data.len() as u8],
        256..=65_535 => {
            let mut header = vec![0x4d];
            header.extend_from_slice(&(data.len() as u16).to_le_bytes());
            header
        }
        _ => panic!("test redeem exceeds PUSHDATA2"),
    };
    encoded.extend_from_slice(data);
    encoded
}

fn compact(value: u64) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut result = vec![0xfd];
            result.extend_from_slice(&(value as u16).to_le_bytes());
            result
        }
        0x1_0000..=0xffff_ffff => {
            let mut result = vec![0xfe];
            result.extend_from_slice(&(value as u32).to_le_bytes());
            result
        }
        _ => {
            let mut result = vec![0xff];
            result.extend_from_slice(&value.to_le_bytes());
            result
        }
    }
}

fn transaction(inputs: &[ModelInput], outputs: &[ModelOutput]) -> Vec<u8> {
    let mut raw = 2_u32.to_le_bytes().to_vec();
    raw.extend(compact(inputs.len() as u64));
    for input in inputs {
        raw.extend_from_slice(&input.hash);
        raw.extend_from_slice(&input.index.to_le_bytes());
        raw.extend(compact(input.unlock.len() as u64));
        raw.extend_from_slice(&input.unlock);
        raw.extend_from_slice(&input.sequence.to_le_bytes());
    }
    raw.extend(compact(outputs.len() as u64));
    for output in outputs {
        raw.extend_from_slice(&output.value.to_le_bytes());
        let contents = output.contents();
        raw.extend(compact(contents.len() as u64));
        raw.extend(contents);
    }
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw
}

fn state_prefix(instance: &[u8; 32], state: &[u8; 128]) -> Vec<u8> {
    let mut prefix = vec![0xef];
    prefix.extend_from_slice(instance);
    prefix.push(0x61);
    prefix.push(0x80);
    prefix.extend_from_slice(state);
    assert_eq!(prefix.len(), 163);
    prefix
}

fn state_output(instance: &[u8; 32], state: &PoolStateV2, state_lock: &[u8]) -> ModelOutput {
    let encoded = state.encode(DENOMINATION).expect("state encoding");
    ModelOutput {
        value: STATE_BASE + state.reserve_sats,
        token_prefix: state_prefix(instance, &encoded),
        lock: state_lock.to_vec(),
    }
}

fn txid(raw: &[u8]) -> String {
    display_hash(&hash256(raw))
}

fn block_hash(height: u32) -> String {
    format!("{height:064x}")
}

fn anchored(raw: &[u8], height: u32) -> AnchoredRawTransaction {
    AnchoredRawTransaction {
        transaction_id: txid(raw),
        raw_transaction: hex::encode(raw),
        height,
        block_hash: block_hash(height),
    }
}

fn funding_source(value: u64, tag: u8) -> (Vec<u8>, ModelOutput) {
    let output = ModelOutput {
        value,
        token_prefix: Vec::new(),
        lock: p2pkh(tag),
    };
    let input = ModelInput {
        hash: [tag.wrapping_add(0x80); 32],
        index: u32::from(tag),
        unlock: vec![0x51],
        sequence: u32::MAX,
    };
    (transaction(&[input], std::slice::from_ref(&output)), output)
}

fn make_fixture(carrier_count: u8) -> Fixture {
    let profile = [0x11; 32];
    let mut instance = [0_u8; 32];
    for (index, byte) in instance.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let state_lock = vec![0x52, 0x21, 0x02];
    let binding_redeem = [&[0x61; 256][..], &[0x75, 0x51][..]].concat();
    let verifier_outputs = (0..carrier_count)
        .map(|index| ModelOutput {
            value: 1_000 + u64::from(index),
            token_prefix: Vec::new(),
            lock: vec![0x51, index],
        })
        .collect::<Vec<_>>();
    let binding_output = ModelOutput {
        value: BINDING_BASE,
        token_prefix: Vec::new(),
        lock: p2sh32(&binding_redeem),
    };
    let mut note_tree = NoteTree::empty().expect("note tree");
    let mut nullifier_tree = IndexedNullifierTree::empty().expect("nullifier tree");
    let initial_state = PoolStateV2 {
        profile_id: profile,
        note_root: note_tree.root_bytes().expect("root"),
        nullifier_root: nullifier_tree.root_bytes().expect("root"),
        note_count: 0,
        nullifier_count: 0,
        maximum_live_notes: 8,
        reserve_sats: 0,
        action_sequence: 0,
    };
    let mut genesis_outputs = vec![state_output(&instance, &initial_state, &state_lock)];
    genesis_outputs.extend(verifier_outputs.clone());
    genesis_outputs.push(binding_output.clone());
    genesis_outputs.push(ModelOutput {
        value: 7_000,
        token_prefix: Vec::new(),
        lock: p2pkh(0x20),
    });
    // The first input outpoint hash is the CashTokens category genesis anchor.
    let genesis_raw = transaction(
        &[ModelInput {
            hash: instance,
            index: 7,
            unlock: vec![0x51],
            sequence: u32::MAX,
        }],
        &genesis_outputs,
    );
    let genesis_hash = hash256(&genesis_raw);
    let genesis_anchor = anchored(&genesis_raw, 100);
    let mut previous_hash = genesis_hash;
    let mut previous_outputs = genesis_outputs;
    let mut pre_state = initial_state.clone();
    let mut actions = Vec::new();
    let mut funding_prevouts = Vec::new();

    for (action_index, kind) in [
        ActionKindV2::Deposit,
        ActionKindV2::Transfer,
        ActionKindV2::Withdrawal,
    ]
    .into_iter()
    .enumerate()
    {
        let tag = 0x31 + action_index as u8;
        let funding_value = CHANGE + FEE + u64::from(kind == ActionKindV2::Deposit) * DENOMINATION;
        let (funding_raw, funding_output) = funding_source(funding_value, tag);
        let funding_hash = hash256(&funding_raw);
        funding_prevouts.push(AuthenticatedSourceTransaction {
            transaction_id: txid(&funding_raw),
            raw_transaction: hex::encode(&funding_raw),
        });

        let output_leaf = if kind == ActionKindV2::Withdrawal {
            [0_u8; 32]
        } else {
            let mut value = [0_u8; 32];
            value[31] = 5 + action_index as u8;
            value
        };
        let public_nullifier = if kind == ActionKindV2::Deposit {
            [0_u8; 32]
        } else {
            let mut value = [0_u8; 32];
            value[31] = 7 + action_index as u8;
            value
        };
        if kind != ActionKindV2::Withdrawal {
            note_tree.append(output_leaf).expect("append");
        }
        if kind != ActionKindV2::Deposit {
            nullifier_tree.insert(public_nullifier).expect("insert");
        }
        let post_note_count = pre_state.note_count + u32::from(kind != ActionKindV2::Withdrawal);
        let post_nullifier_count =
            pre_state.nullifier_count + u32::from(kind != ActionKindV2::Deposit);
        let post_state = PoolStateV2 {
            profile_id: profile,
            note_root: note_tree.root_bytes().expect("root"),
            nullifier_root: nullifier_tree.root_bytes().expect("root"),
            note_count: post_note_count,
            nullifier_count: post_nullifier_count,
            maximum_live_notes: 8,
            reserve_sats: u64::from(post_note_count - post_nullifier_count) * DENOMINATION,
            action_sequence: pre_state.action_sequence + 1,
        };
        let mut outputs = vec![state_output(&instance, &post_state, &state_lock)];
        outputs.extend(verifier_outputs.clone());
        outputs.push(binding_output.clone());
        let payout_lock = p2pkh(0x60 + action_index as u8);
        if kind == ActionKindV2::Withdrawal {
            outputs.push(ModelOutput {
                value: DENOMINATION,
                token_prefix: Vec::new(),
                lock: payout_lock.clone(),
            });
        }
        outputs.push(ModelOutput {
            value: CHANGE,
            token_prefix: Vec::new(),
            lock: p2pkh(0x70 + action_index as u8),
        });

        let mut sources = Vec::new();
        sources.extend(
            previous_outputs[1..=usize::from(carrier_count)]
                .iter()
                .cloned(),
        );
        sources.push(previous_outputs[usize::from(carrier_count) + 1].clone());
        sources.push(previous_outputs[0].clone());
        sources.push(funding_output.clone());
        let mut context_inputs = Vec::new();
        for (index, source) in sources.iter().enumerate().take(usize::from(carrier_count)) {
            context_inputs.push(DirectV2ContextInput {
                role: role(DirectV2RoleKind::Verifier, index as u8),
                outpoint_transaction_hash: previous_hash,
                outpoint_index: (index + 1) as u32,
                sequence: u32::MAX,
                value_sats: source.value,
                locking_bytecode: source.lock.clone(),
                token_prefix: source.token_prefix.clone(),
            });
        }
        context_inputs.push(DirectV2ContextInput {
            role: role(DirectV2RoleKind::Binding, 0),
            outpoint_transaction_hash: previous_hash,
            outpoint_index: u32::from(carrier_count) + 1,
            sequence: u32::MAX,
            value_sats: sources[usize::from(carrier_count)].value,
            locking_bytecode: sources[usize::from(carrier_count)].lock.clone(),
            token_prefix: Vec::new(),
        });
        context_inputs.push(DirectV2ContextInput {
            role: role(DirectV2RoleKind::State, 0),
            outpoint_transaction_hash: previous_hash,
            outpoint_index: 0,
            sequence: u32::MAX,
            value_sats: sources[usize::from(carrier_count) + 1].value,
            locking_bytecode: sources[usize::from(carrier_count) + 1].lock.clone(),
            token_prefix: sources[usize::from(carrier_count) + 1].token_prefix.clone(),
        });
        context_inputs.push(DirectV2ContextInput {
            role: role(DirectV2RoleKind::Funding, 0),
            outpoint_transaction_hash: funding_hash,
            outpoint_index: 0,
            sequence: u32::MAX,
            value_sats: funding_output.value,
            locking_bytecode: funding_output.lock.clone(),
            token_prefix: Vec::new(),
        });
        let context_outputs = outputs
            .iter()
            .enumerate()
            .map(|(index, output)| DirectV2ContextOutput {
                role: if index == 0 {
                    role(DirectV2RoleKind::State, 0)
                } else if index <= usize::from(carrier_count) {
                    role(DirectV2RoleKind::Verifier, (index - 1) as u8)
                } else if index == usize::from(carrier_count) + 1 {
                    role(DirectV2RoleKind::Binding, 0)
                } else if kind == ActionKindV2::Withdrawal
                    && index == usize::from(carrier_count) + 2
                {
                    role(DirectV2RoleKind::Withdrawal, 0)
                } else {
                    role(DirectV2RoleKind::Change, 0)
                },
                value_sats: output.value,
                locking_bytecode: output.lock.clone(),
                token_prefix: output.token_prefix.clone(),
            })
            .collect::<Vec<_>>();
        let context = DirectV2TransactionContext {
            network_id: 2,
            kind,
            profile_id: profile,
            instance_id: instance,
            transaction_version: 2,
            locktime: 0,
            pre_action_sequence: pre_state.action_sequence,
            post_action_sequence: post_state.action_sequence,
            inputs: context_inputs,
            outputs: context_outputs,
        };
        let context_hash = context
            .sha256_with_carrier_count(carrier_count)
            .expect("context hash");
        let packet = DirectActionPacketV2 {
            network_id: 2,
            kind,
            instance_id: instance,
            pre_state: pre_state.clone(),
            post_state: post_state.clone(),
            public_nullifier,
            output_note_leaf: output_leaf,
            encrypted_record: [0_u8; 128],
            withdrawal_locking_bytecode_hash: if kind == ActionKindV2::Withdrawal {
                Sha256::digest(&payout_lock).into()
            } else {
                [0_u8; 32]
            },
            transaction_context_hash: context_hash,
        };
        let packet_bytes = packet.encode(DENOMINATION).expect("packet");
        let mut inputs = (0..carrier_count)
            .map(|index| ModelInput {
                hash: previous_hash,
                index: u32::from(index) + 1,
                unlock: vec![0x51],
                sequence: u32::MAX,
            })
            .collect::<Vec<_>>();
        let mut binding_unlock = vec![0x4d, 0x28, 0x02];
        binding_unlock.extend_from_slice(&packet_bytes);
        binding_unlock.extend(data_push(&binding_redeem));
        inputs.push(ModelInput {
            hash: previous_hash,
            index: u32::from(carrier_count) + 1,
            unlock: binding_unlock,
            sequence: u32::MAX,
        });
        inputs.push(ModelInput {
            hash: previous_hash,
            index: 0,
            unlock: vec![0x51],
            sequence: u32::MAX,
        });
        inputs.push(ModelInput {
            hash: funding_hash,
            index: 0,
            unlock: vec![0x51],
            sequence: u32::MAX,
        });
        let raw = transaction(&inputs, &outputs);
        actions.push(anchored(&raw, 101 + action_index as u32));
        previous_hash = hash256(&raw);
        previous_outputs = outputs;
        pre_state = post_state;
    }
    let expected_tip_anchor = actions.last().expect("actions").clone();
    Fixture {
        request: ScanRequest {
            schema: SCAN_SCHEMA.to_owned(),
            network_id: 2,
            profile_id: hex::encode(profile),
            instance_id: hex::encode(instance),
            denomination_sats: DENOMINATION.to_string(),
            carrier_count,
            runtime_materials_sha256: "a5".repeat(32),
            genesis: genesis_anchor.clone(),
            genesis_outpoint: DisplayOutpoint {
                transaction_id: genesis_anchor.transaction_id,
                output_index: 0,
            },
            initial_state_hex: hex::encode(
                initial_state.encode(DENOMINATION).expect("initial state"),
            ),
            actions,
            funding_prevouts,
            expected_tip: ExpectedTip {
                transaction_id: expected_tip_anchor.transaction_id,
                output_index: 0,
                height: expected_tip_anchor.height,
                block_hash: expected_tip_anchor.block_hash,
            },
        },
    }
}

fn update_action_identity(request: &mut ScanRequest, index: usize) {
    let raw = hex::decode(&request.actions[index].raw_transaction).expect("raw");
    request.actions[index].transaction_id = txid(&raw);
    if index + 1 == request.actions.len() {
        request.expected_tip.transaction_id = request.actions[index].transaction_id.clone();
    }
}

fn retain_first_action(request: &mut ScanRequest) {
    request.actions.truncate(1);
    request.funding_prevouts.truncate(1);
    request.expected_tip = ExpectedTip {
        transaction_id: request.actions[0].transaction_id.clone(),
        output_index: 0,
        height: request.actions[0].height,
        block_hash: request.actions[0].block_hash.clone(),
    };
}

fn replace_first_unlock(request: &mut ScanRequest, length: usize) {
    let mut raw = hex::decode(&request.actions[0].raw_transaction).expect("raw");
    // version[4] || input count[1] || outpoint hash[32] || outpoint index[4]
    let length_offset = 41;
    assert_eq!(&raw[length_offset..length_offset + 2], &[1, 0x51]);
    let mut replacement = compact(length as u64);
    replacement.extend(vec![0x51; length]);
    raw.splice(length_offset..length_offset + 2, replacement);
    request.actions[0].raw_transaction = hex::encode(raw);
    update_action_identity(request, 0);
}

fn find(raw: &[u8], needle: &[u8], occurrence: usize) -> usize {
    raw.windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .nth(occurrence)
        .map(|(index, _)| index)
        .expect("needle occurrence")
}

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

fn stream_input(request: &ScanRequest, action_indices: &[usize]) -> Vec<u8> {
    let wire_indices = (0..action_indices.len()).collect::<Vec<_>>();
    stream_input_with_wire_indices(request, action_indices, &wire_indices)
}

fn stream_input_with_wire_indices(
    request: &ScanRequest,
    action_indices: &[usize],
    wire_indices: &[usize],
) -> Vec<u8> {
    assert_eq!(action_indices.len(), wire_indices.len());
    let mut result = STREAM_MAGIC.to_vec();
    let header = serde_json::json!({
        "schema": STREAM_INPUT_SCHEMA,
        "type": "header",
        "actionCount": action_indices.len().to_string(),
        "request": {
            "networkId": request.network_id,
            "profileId": request.profile_id,
            "instanceId": request.instance_id,
            "denominationSats": request.denomination_sats,
            "carrierCount": request.carrier_count,
            "runtimeMaterialsSha256": request.runtime_materials_sha256,
            "genesis": request.genesis,
            "genesisOutpoint": request.genesis_outpoint,
            "initialStateHex": request.initial_state_hex,
            "expectedTip": request.expected_tip,
        },
    });
    let header = serde_json::to_vec(&header).expect("header JSON");
    let mut digest = Sha256::new();
    digest.update(b"ShieldKit V2 recovery stream input v2\0");
    let header_frame = framed(&header);
    digest.update(&header_frame);
    result.extend(header_frame);
    for (wire_index, request_index) in wire_indices.iter().zip(action_indices) {
        let action = serde_json::json!({
            "schema": STREAM_INPUT_SCHEMA,
            "type": "action",
            "index": wire_index.to_string(),
            "action": request.actions[*request_index],
            "fundingPrevout": request.funding_prevouts[*request_index],
        });
        let action = serde_json::to_vec(&action).expect("action JSON");
        let action_frame = framed(&action);
        digest.update(&action_frame);
        result.extend(action_frame);
    }
    let end = serde_json::json!({
        "schema": STREAM_INPUT_SCHEMA,
        "type": "end",
        "actionCount": action_indices.len().to_string(),
        "frameCount": (action_indices.len() + 1).to_string(),
        "digest": hex::encode(digest.finalize()),
    });
    result.extend(framed(&serde_json::to_vec(&end).expect("end JSON")));
    result
}

fn compact_snapshot(snapshot: &shieldkit_v2_recovery::RecoverySnapshot) -> serde_json::Value {
    serde_json::json!({
        "schema": snapshot.schema,
        "version": snapshot.version,
        "networkId": snapshot.network_id,
        "profileId": snapshot.profile_id,
        "instanceId": snapshot.instance_id,
        "denominationSats": snapshot.denomination_sats,
        "carrierCount": snapshot.carrier_count,
        "runtimeMaterialsSha256": snapshot.runtime_materials_sha256,
        "poseidonProfile": snapshot.poseidon_profile,
        "genesis": snapshot.genesis,
        "tip": snapshot.tip,
        "actionCount": snapshot.action_count,
        "historySha256": snapshot.history_sha256,
        "stateHex": snapshot.state_hex,
        "noteTree": {
            "depth": snapshot.note_tree.depth,
            "count": snapshot.note_tree.count,
            "root": snapshot.note_tree.root,
        },
        "nullifierTree": {
            "depth": snapshot.nullifier_tree.depth,
            "count": snapshot.nullifier_tree.count,
            "root": snapshot.nullifier_tree.root,
        },
        "externalAuthenticationBoundary": snapshot.external_authentication_boundary,
        "contentSha256": snapshot.content_sha256,
    })
}

fn authenticate_stream_input(
    request: &AuthenticateSnapshotRequest,
    action_indices: &[usize],
    wire_indices: &[usize],
) -> Vec<u8> {
    assert_eq!(action_indices.len(), wire_indices.len());
    let mut result = STREAM_MAGIC.to_vec();
    let header = serde_json::json!({
        "schema": AUTHENTICATE_STREAM_INPUT_SCHEMA,
        "type": "header",
        "actionCount": action_indices.len().to_string(),
        "request": {
            "networkId": request.network_id,
            "profileId": request.profile_id,
            "instanceId": request.instance_id,
            "denominationSats": request.denomination_sats,
            "carrierCount": request.carrier_count,
            "runtimeMaterialsSha256": request.runtime_materials_sha256,
            "genesis": request.genesis,
            "tip": request.tip,
            "snapshot": compact_snapshot(&request.snapshot),
        },
    });
    let header = serde_json::to_vec(&header).expect("authenticate header JSON");
    let mut digest = Sha256::new();
    digest.update(b"ShieldKit V2 recovery authenticate snapshot stream input v2\0");
    let header_frame = framed(&header);
    digest.update(&header_frame);
    result.extend(header_frame);
    for (wire_index, action_index) in wire_indices.iter().zip(action_indices) {
        let action = serde_json::json!({
            "schema": AUTHENTICATE_STREAM_INPUT_SCHEMA,
            "type": "action",
            "index": wire_index.to_string(),
            "action": request.snapshot.actions[*action_index],
        });
        let action = serde_json::to_vec(&action).expect("authenticate action JSON");
        let action_frame = framed(&action);
        digest.update(&action_frame);
        result.extend(action_frame);
    }
    let end = serde_json::json!({
        "schema": AUTHENTICATE_STREAM_INPUT_SCHEMA,
        "type": "end",
        "actionCount": action_indices.len().to_string(),
        "frameCount": (action_indices.len() + 1).to_string(),
        "digest": hex::encode(digest.finalize()),
    });
    result.extend(framed(
        &serde_json::to_vec(&end).expect("authenticate end JSON"),
    ));
    result
}

fn authentication_request(
    snapshot: shieldkit_v2_recovery::RecoverySnapshot,
) -> AuthenticateSnapshotRequest {
    AuthenticateSnapshotRequest {
        schema: AUTHENTICATE_SNAPSHOT_SCHEMA.to_owned(),
        network_id: snapshot.network_id,
        profile_id: snapshot.profile_id.clone(),
        instance_id: snapshot.instance_id.clone(),
        denomination_sats: snapshot.denomination_sats.clone(),
        carrier_count: snapshot.carrier_count,
        runtime_materials_sha256: snapshot.runtime_materials_sha256.clone(),
        genesis: snapshot.genesis.clone(),
        tip: snapshot.tip.clone(),
        snapshot,
    }
}

#[test]
fn runtime_materials_sha256_is_v2_signed_and_request_bound() {
    let fixture = make_fixture(1);
    let mut legacy_scan = fixture.request.clone();
    legacy_scan.schema = "shieldkit-v2-recovery-scan-v1".to_owned();
    assert!(scan(&legacy_scan)
        .expect_err("v1 scan schema must fail closed")
        .to_string()
        .contains("schema is unsupported"));
    let result = scan_with_material(&fixture.request).expect("v2 scan result");
    assert_eq!(
        result.snapshot.runtime_materials_sha256,
        fixture.request.runtime_materials_sha256
    );
    assert_eq!(
        result.material.binding.runtime_materials_sha256,
        result.snapshot.runtime_materials_sha256
    );

    let mut malformed = fixture.request.clone();
    malformed.runtime_materials_sha256 = "A5".repeat(32);
    assert!(scan(&malformed)
        .expect_err("uppercase runtime material digest must fail")
        .to_string()
        .contains("runtimeMaterialsSha256"));

    let mut authentication = authentication_request(result.snapshot);
    let mut legacy_authentication = authentication.clone();
    legacy_authentication.schema = "shieldkit-v2-recovery-authenticate-snapshot-v1".to_owned();
    assert!(authenticate_snapshot(&legacy_authentication)
        .expect_err("v1 authenticate schema must fail closed")
        .to_string()
        .contains("schema is unsupported"));
    authentication.runtime_materials_sha256 = "5a".repeat(32);
    assert!(authenticate_snapshot(&authentication)
        .expect_err("runtime material request/snapshot mismatch must fail")
        .to_string()
        .contains("independently authenticated"));
}

fn retain_genesis_only(request: &mut ScanRequest) {
    request.actions.clear();
    request.funding_prevouts.clear();
    request.expected_tip = ExpectedTip {
        transaction_id: request.genesis.transaction_id.clone(),
        output_index: 0,
        height: request.genesis.height,
        block_hash: request.genesis.block_hash.clone(),
    };
}

fn parse_stream_output(bytes: &[u8]) -> Vec<serde_json::Value> {
    assert_eq!(&bytes[..STREAM_MAGIC.len()], STREAM_MAGIC);
    let mut cursor = STREAM_MAGIC.len();
    let mut frames = Vec::new();
    while cursor < bytes.len() {
        let length =
            u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().expect("length")) as usize;
        cursor += 4;
        frames.push(
            serde_json::from_slice(&bytes[cursor..cursor + length]).expect("output frame JSON"),
        );
        cursor += length;
    }
    assert_eq!(cursor, bytes.len());
    frames
}

struct ChunkedReader {
    inner: Cursor<Vec<u8>>,
    chunk: usize,
}

impl Read for ChunkedReader {
    fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
        let limit = target.len().min(self.chunk);
        self.inner.read(&mut target[..limit])
    }
}

#[test]
fn uses_the_full_transaction_and_unlock_policy_ceilings() {
    let fixture = make_fixture(1);
    let mut exact_unlock = fixture.request.clone();
    retain_first_action(&mut exact_unlock);
    replace_first_unlock(&mut exact_unlock, 10_000);
    scan(&exact_unlock).expect("an exact 10000-byte unlock is within the full ceiling");

    let mut excessive_unlock = fixture.request.clone();
    retain_first_action(&mut excessive_unlock);
    replace_first_unlock(&mut excessive_unlock, 10_001);
    assert!(
        scan(&excessive_unlock)
            .expect_err("unlock above full ceiling")
            .to_string()
            .contains("10000-byte unlocking policy ceiling")
    );

    let mut excessive_transaction = fixture.request;
    retain_first_action(&mut excessive_transaction);
    replace_first_unlock(&mut excessive_transaction, 100_000);
    assert!(
        scan(&excessive_transaction)
            .expect_err("transaction above full ceiling")
            .to_string()
            .contains("100000-byte transaction policy ceiling")
    );
}

#[test]
fn framed_scan_is_chunk_bounded_and_material_equivalent() {
    let fixture = make_fixture(3);
    let expected = scan_with_material(&fixture.request).expect("monolithic reference");
    let input = stream_input(&fixture.request, &[0, 1, 2]);
    let mut output = Vec::new();
    scan_framed(
        ChunkedReader {
            inner: Cursor::new(input),
            chunk: 3,
        },
        &mut output,
    )
    .expect("framed scan");
    let frames = parse_stream_output(&output);
    assert_eq!(frames[0]["schema"], STREAM_OUTPUT_SCHEMA);
    assert_eq!(frames[0]["type"], "header");
    assert_eq!(frames[0]["actionCount"], "3");
    assert_eq!(frames[1]["type"], "snapshot");
    assert_eq!(
        frames[1]["snapshot"]["contentSha256"],
        expected.snapshot.content_sha256
    );
    assert_eq!(
        frames[1]["material"]["contentSha256"],
        expected.material.content_sha256
    );

    let mut actions = Vec::new();
    let mut note_nodes = Vec::new();
    let mut note_frontier = Vec::new();
    let mut note_leaves = Vec::new();
    let mut nullifier_nodes = Vec::new();
    let mut nullifier_leaves = Vec::new();
    for frame in &frames[2..frames.len() - 1] {
        match frame["type"].as_str().expect("frame type") {
            "action" => actions.push(frame["value"].clone()),
            "note-node" => note_nodes.push(frame["value"].clone()),
            "note-frontier" => note_frontier.push(frame["value"].clone()),
            "note-leaf" => note_leaves.push(frame["value"].clone()),
            "nullifier-node" => nullifier_nodes.push(frame["value"].clone()),
            "nullifier-leaf" => nullifier_leaves.push(frame["value"].clone()),
            other => panic!("unexpected record {other}"),
        }
    }
    assert_eq!(
        serde_json::Value::Array(actions),
        serde_json::to_value(&expected.snapshot.actions).expect("actions")
    );
    assert_eq!(
        serde_json::Value::Array(note_nodes),
        serde_json::to_value(&expected.material.note_nodes).expect("note nodes")
    );
    assert_eq!(
        serde_json::Value::Array(note_frontier),
        serde_json::to_value(&expected.material.note_frontier).expect("frontier")
    );
    assert_eq!(
        serde_json::Value::Array(note_leaves),
        serde_json::to_value(&expected.material.note_leaves).expect("note leaves")
    );
    assert_eq!(
        serde_json::Value::Array(nullifier_nodes),
        serde_json::to_value(&expected.material.nullifier_nodes).expect("nullifier nodes")
    );
    assert_eq!(
        serde_json::Value::Array(nullifier_leaves),
        serde_json::to_value(&expected.material.nullifier_leaves).expect("nullifier leaves")
    );

    let end = frames.last().expect("end");
    assert_eq!(end["type"], "end");
    assert_eq!(end["frameCount"], (frames.len() - 1).to_string());
    let mut digest = Sha256::new();
    digest.update(b"ShieldKit V2 recovery stream output v2\0");
    let mut cursor = STREAM_MAGIC.len();
    for _ in 0..frames.len() - 1 {
        let length =
            u32::from_be_bytes(output[cursor..cursor + 4].try_into().expect("length")) as usize;
        digest.update(&output[cursor..cursor + 4 + length]);
        cursor += 4 + length;
    }
    assert_eq!(end["digest"], hex::encode(digest.finalize()));
}

#[test]
fn framed_scan_rejects_truncation_reorder_duplication_digest_and_trailing_data() {
    let fixture = make_fixture(1);
    let valid = stream_input(&fixture.request, &[0, 1, 2]);

    let mut truncated = valid.clone();
    truncated.pop();
    assert!(
        scan_framed(Cursor::new(truncated), Vec::new())
            .expect_err("truncated")
            .to_string()
            .contains("truncated")
    );

    let reordered = stream_input(&fixture.request, &[1, 0, 2]);
    assert!(
        scan_framed(Cursor::new(reordered), Vec::new())
            .expect_err("reordered")
            .to_string()
            .contains("exact preceding")
    );

    let duplicated = stream_input(&fixture.request, &[0, 0, 2]);
    assert!(
        scan_framed(Cursor::new(duplicated), Vec::new())
            .expect_err("duplicated")
            .to_string()
            .contains("duplicates a chain transaction")
    );

    let duplicated_index = stream_input_with_wire_indices(&fixture.request, &[0, 1, 2], &[0, 0, 2]);
    assert!(
        scan_framed(Cursor::new(duplicated_index), Vec::new())
            .expect_err("duplicated index")
            .to_string()
            .contains("reordered or duplicated")
    );

    let reordered_index = stream_input_with_wire_indices(&fixture.request, &[0, 1, 2], &[1, 0, 2]);
    assert!(
        scan_framed(Cursor::new(reordered_index), Vec::new())
            .expect_err("reordered index")
            .to_string()
            .contains("reordered or duplicated")
    );

    let mut bad_digest = valid.clone();
    let digest_offset = bad_digest
        .windows(b"\"digest\":\"".len())
        .rposition(|window| window == b"\"digest\":\"")
        .expect("digest")
        + b"\"digest\":\"".len();
    bad_digest[digest_offset] = if bad_digest[digest_offset] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert!(
        scan_framed(Cursor::new(bad_digest), Vec::new())
            .expect_err("digest")
            .to_string()
            .contains("transcript digest")
    );

    let mut trailing = valid;
    trailing.push(0);
    assert!(
        scan_framed(Cursor::new(trailing), Vec::new())
            .expect_err("trailing")
            .to_string()
            .contains("trailing data")
    );
}

#[test]
fn framed_snapshot_authentication_matches_monolithic_at_zero_and_nonzero_actions() {
    for action_count in [0_usize, 3] {
        let mut scan_request = make_fixture(3).request;
        if action_count == 0 {
            retain_genesis_only(&mut scan_request);
        }
        let raw_result = scan_with_material(&scan_request).expect("raw reference");
        let auth_request = authentication_request(raw_result.snapshot.clone());
        let expected =
            authenticate_snapshot(&auth_request).expect("monolithic snapshot authentication");
        assert_eq!(expected, raw_result.material);
        let indices = (0..action_count).collect::<Vec<_>>();
        let auth_input = authenticate_stream_input(&auth_request, &indices, &indices);
        let mut auth_output = Vec::new();
        authenticate_snapshot_framed(
            ChunkedReader {
                inner: Cursor::new(auth_input),
                chunk: 5,
            },
            &mut auth_output,
        )
        .expect("streamed snapshot authentication");

        let raw_input = stream_input(&scan_request, &indices);
        let mut raw_output = Vec::new();
        scan_framed(Cursor::new(raw_input), &mut raw_output).expect("streamed raw scan");
        assert_eq!(
            auth_output, raw_output,
            "both authenticated paths must emit the same output stream"
        );
        let frames = parse_stream_output(&auth_output);
        assert_eq!(
            frames[1]["snapshot"]["contentSha256"],
            expected.content_sha256
        );
        assert_eq!(
            frames[1]["material"]["contentSha256"],
            expected.content_sha256
        );
        assert_eq!(frames[0]["actionCount"], action_count.to_string());
        assert_eq!(frames.last().expect("end")["type"], "end");
    }
}

#[test]
fn framed_snapshot_authentication_rejects_truncation_reorder_count_hash_and_tip_drift() {
    let snapshot = scan(&make_fixture(1).request).expect("snapshot");
    let request = authentication_request(snapshot);
    let valid = authenticate_stream_input(&request, &[0, 1, 2], &[0, 1, 2]);

    let mut truncated = valid.clone();
    truncated.pop();
    assert!(
        authenticate_snapshot_framed(Cursor::new(truncated), Vec::new())
            .expect_err("truncated")
            .to_string()
            .contains("truncated")
    );

    let reordered = authenticate_stream_input(&request, &[1, 0, 2], &[0, 1, 2]);
    let reorder_error = authenticate_snapshot_framed(Cursor::new(reordered), Vec::new())
        .expect_err("reordered actions")
        .to_string();
    assert!(
        reorder_error.contains("contentSha256") || reorder_error.contains("packet bindings differ"),
        "{reorder_error}"
    );

    let reordered_index = authenticate_stream_input(&request, &[0, 1, 2], &[1, 0, 2]);
    assert!(
        authenticate_snapshot_framed(Cursor::new(reordered_index), Vec::new())
            .expect_err("reordered index")
            .to_string()
            .contains("reordered or duplicated")
    );

    let short_count = authenticate_stream_input(&request, &[0, 1], &[0, 1]);
    assert!(
        authenticate_snapshot_framed(Cursor::new(short_count), Vec::new())
            .expect_err("count")
            .to_string()
            .contains("differs from its compact snapshot")
    );

    let mut history_drift = request.clone();
    history_drift
        .snapshot
        .history_sha256
        .replace_range(0..2, "ff");
    history_drift.snapshot.content_sha256 = history_drift
        .snapshot
        .recompute_content_sha256()
        .expect("drifted snapshot hash");
    let history_input = authenticate_stream_input(&history_drift, &[0, 1, 2], &[0, 1, 2]);
    assert!(
        authenticate_snapshot_framed(Cursor::new(history_input), Vec::new())
            .expect_err("history hash drift")
            .to_string()
            .contains("historySha256")
    );

    let mut tip_drift = request;
    tip_drift.tip.transaction_id = "aa".repeat(32);
    let tip_input = authenticate_stream_input(&tip_drift, &[0, 1, 2], &[0, 1, 2]);
    assert!(
        authenticate_snapshot_framed(Cursor::new(tip_input), Vec::new())
            .expect_err("tip drift")
            .to_string()
            .contains("independently authenticated")
    );
}

#[test]
fn replays_all_actions_at_generic_carrier_counts_and_revalidates_snapshot() {
    for carrier_count in [1, 3] {
        let fixture = make_fixture(carrier_count);
        let snapshot = scan(&fixture.request).expect("scan");
        let raw_result =
            scan_with_material(&fixture.request).expect("one-pass raw scan materialization");
        assert_eq!(raw_result.schema, SCAN_RESULT_SCHEMA);
        assert_eq!(raw_result.snapshot, snapshot);
        assert_eq!(snapshot.action_count, "3");
        assert_eq!(snapshot.note_tree.count, "2");
        assert_eq!(snapshot.nullifier_tree.count, "2");
        assert_eq!(
            snapshot.instance_id,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert!(
            snapshot
                .actions
                .iter()
                .all(|action| action.packet_hex.len() == 1_104)
        );
        snapshot.authenticate_structure().expect("snapshot auth");
        let authenticated = authenticate_snapshot(&AuthenticateSnapshotRequest {
            schema: AUTHENTICATE_SNAPSHOT_SCHEMA.to_owned(),
            network_id: snapshot.network_id,
            profile_id: snapshot.profile_id.clone(),
            instance_id: snapshot.instance_id.clone(),
            denomination_sats: snapshot.denomination_sats.clone(),
            carrier_count: snapshot.carrier_count,
            runtime_materials_sha256: snapshot.runtime_materials_sha256.clone(),
            genesis: snapshot.genesis.clone(),
            tip: snapshot.tip.clone(),
            snapshot: snapshot.clone(),
        })
        .expect("anchored snapshot authentication");
        assert_eq!(authenticated.schema, AUTHENTICATED_MATERIAL_SCHEMA);
        assert_eq!(authenticated.content_sha256, snapshot.content_sha256);
        assert_eq!(authenticated.binding.profile_id, snapshot.profile_id);
        assert_eq!(authenticated.binding.instance_id, snapshot.instance_id);
        assert_eq!(authenticated.binding.network_id, snapshot.network_id);
        assert_eq!(
            authenticated.binding.denomination_sats,
            snapshot.denomination_sats
        );
        assert_eq!(authenticated.binding.carrier_count, snapshot.carrier_count);
        assert_eq!(authenticated.canonical.state, snapshot.state_hex);
        assert_eq!(
            authenticated.canonical.outpoint.txid,
            snapshot.tip.transaction_id
        );
        assert_eq!(
            authenticated.canonical.outpoint.vout,
            snapshot.tip.output_index
        );
        assert_eq!(authenticated.canonical.action_sequence, 3);
        assert_eq!(authenticated.canonical.height, snapshot.tip.height);
        assert_eq!(authenticated.canonical.block_hash, snapshot.tip.block_hash);
        assert_eq!(authenticated.note_nodes.len(), 34);
        assert_eq!(authenticated.note_frontier.len(), 1);
        assert_eq!(authenticated.note_frontier[0].depth, 1);
        assert_eq!(authenticated.note_leaves.len(), 2);
        assert_eq!(authenticated.note_leaves[0].note_index, 0);
        assert_eq!(authenticated.note_leaves[0].action_sequence, 1);
        assert_eq!(
            authenticated.note_leaves[0].transaction_id,
            snapshot.actions[0].transaction_id
        );
        assert_eq!(authenticated.note_leaves[1].note_index, 1);
        assert_eq!(authenticated.note_leaves[1].action_sequence, 2);
        assert_eq!(
            authenticated.note_leaves[1].transaction_id,
            snapshot.actions[1].transaction_id
        );
        assert_eq!(
            authenticated
                .note_nodes
                .iter()
                .find(|node| node.depth == 32 && node.node_index == 0)
                .expect("note root node")
                .node_hash,
            snapshot.note_tree.root
        );
        assert_eq!(authenticated.nullifier_nodes.len(), 37);
        assert_eq!(authenticated.nullifier_leaves.len(), 4);
        assert_eq!(authenticated.nullifier_leaves[0].leaf_type, 1);
        assert_eq!(authenticated.nullifier_leaves[1].leaf_type, 3);
        assert!(
            authenticated.nullifier_leaves[2..]
                .iter()
                .all(|leaf| leaf.leaf_type == 2)
        );
        assert_eq!(
            authenticated
                .nullifier_nodes
                .iter()
                .find(|node| node.depth == 32 && node.node_index == 0)
                .expect("nullifier root node")
                .node_hash,
            snapshot.nullifier_tree.root
        );
        assert_eq!(raw_result.material, authenticated);
        let verified = verify_snapshot(&VerifySnapshotRequest {
            schema: VERIFY_SCHEMA.to_owned(),
            scan: fixture.request,
            snapshot: snapshot.clone(),
        })
        .expect("independent raw replay");
        assert_eq!(verified, snapshot);
    }
}

#[test]
fn rejects_omitted_reordered_fork_and_highest_sequence_substitution() {
    let fixture = make_fixture(1);

    let mut omitted_middle = fixture.request.clone();
    omitted_middle.actions.remove(1);
    omitted_middle.funding_prevouts.remove(1);
    assert!(
        scan(&omitted_middle)
            .expect_err("omitted middle")
            .to_string()
            .contains("exact preceding")
    );

    let mut omitted_tip = fixture.request.clone();
    omitted_tip.actions.pop();
    omitted_tip.funding_prevouts.pop();
    assert!(
        scan(&omitted_tip)
            .expect_err("omitted tip")
            .to_string()
            .contains("expectedTip")
    );

    let mut reordered = fixture.request.clone();
    reordered.actions.swap(0, 1);
    assert!(
        scan(&reordered)
            .expect_err("reordered")
            .to_string()
            .contains("exact preceding")
    );

    let mut highest_first = fixture.request.clone();
    highest_first.actions = vec![highest_first.actions[2].clone()];
    highest_first.funding_prevouts = vec![highest_first.funding_prevouts[2].clone()];
    assert!(
        scan(&highest_first)
            .expect_err("unrelated highest sequence")
            .to_string()
            .contains("exact preceding")
    );

    let mut fork = fixture.request.clone();
    let mut fork_action = fork.actions[0].clone();
    let mut fork_raw = hex::decode(&fork_action.raw_transaction).expect("raw");
    let sequence = [0x01, 0x51, 0xff, 0xff, 0xff, 0xff];
    let funding_unlock = find(&fork_raw, &sequence, 2);
    fork_raw[funding_unlock + 1] = 0x52;
    fork_action.raw_transaction = hex::encode(&fork_raw);
    fork_action.transaction_id = txid(&fork_raw);
    fork.actions = vec![fork.actions[0].clone(), fork_action.clone()];
    fork.expected_tip = ExpectedTip {
        transaction_id: fork_action.transaction_id,
        output_index: 0,
        height: fork_action.height,
        block_hash: fork_action.block_hash,
    };
    assert!(
        scan(&fork)
            .expect_err("fork")
            .to_string()
            .contains("exact preceding")
    );
}

#[test]
fn rejects_wrong_txid_outpoint_category_state_packet_context_and_root() {
    let fixture = make_fixture(1);

    let mut wrong_txid = fixture.request.clone();
    wrong_txid.actions[0].transaction_id = "aa".repeat(32);
    assert!(
        scan(&wrong_txid)
            .expect_err("wrong txid")
            .to_string()
            .contains("computed txid")
    );

    let mut wrong_outpoint = fixture.request.clone();
    let mut raw = hex::decode(&wrong_outpoint.actions[0].raw_transaction).expect("raw");
    let genesis_wire =
        hash256(&hex::decode(&wrong_outpoint.genesis.raw_transaction).expect("genesis"));
    let state_hash_offset = find(&raw, &genesis_wire, 2);
    raw[state_hash_offset] ^= 1;
    wrong_outpoint.actions[0].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut wrong_outpoint, 0);
    assert!(
        scan(&wrong_outpoint)
            .expect_err("wrong outpoint")
            .to_string()
            .contains("exact preceding")
    );

    let mut wrong_category = fixture.request.clone();
    let last = wrong_category.actions.len() - 1;
    let mut raw = hex::decode(&wrong_category.actions[last].raw_transaction).expect("raw");
    let category = hex::decode(&wrong_category.instance_id).expect("category");
    let prefix_offset = find(&raw, &[&[0xef], &category[..]].concat(), 0);
    raw[prefix_offset + 1] ^= 1;
    wrong_category.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut wrong_category, last);
    assert!(
        scan(&wrong_category)
            .expect_err("wrong category")
            .to_string()
            .contains("state NFT")
    );

    let mut wrong_state = fixture.request.clone();
    let last = wrong_state.actions.len() - 1;
    let mut raw = hex::decode(&wrong_state.actions[last].raw_transaction).expect("raw");
    let state_offset = find(&raw, b"SKS2", 2);
    raw[state_offset + 4] ^= 1;
    wrong_state.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut wrong_state, last);
    assert!(
        scan(&wrong_state)
            .expect_err("wrong state")
            .to_string()
            .contains("state NFT")
    );

    let mut wrong_packet = fixture.request.clone();
    let last = wrong_packet.actions.len() - 1;
    let mut raw = hex::decode(&wrong_packet.actions[last].raw_transaction).expect("raw");
    let packet_offset = find(&raw, &[0x4d, 0x28, 0x02, b'S', b'D', b'A', b'2'], 0) + 3;
    raw[packet_offset + 551] ^= 1;
    wrong_packet.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut wrong_packet, last);
    assert!(
        scan(&wrong_packet)
            .expect_err("wrong packet")
            .to_string()
            .contains("transactionContextHash")
    );

    let mut wrong_context = fixture.request.clone();
    let last = wrong_context.actions.len() - 1;
    let mut raw = hex::decode(&wrong_context.actions[last].raw_transaction).expect("raw");
    let change_lock = p2pkh(0x72);
    let change_offset = find(&raw, &change_lock, 0);
    raw[change_offset + 3] ^= 1;
    wrong_context.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut wrong_context, last);
    assert!(
        scan(&wrong_context)
            .expect_err("wrong context")
            .to_string()
            .contains("transactionContextHash")
    );

    let mut wrong_root = fixture.request.clone();
    let last = wrong_root.actions.len() - 1;
    let mut raw = hex::decode(&wrong_root.actions[last].raw_transaction).expect("raw");
    let packet_offset = find(&raw, &[0x4d, 0x28, 0x02, b'S', b'D', b'A', b'2'], 0) + 3;
    let output_state_offset = find(&raw, b"SKS2", 2);
    raw[packet_offset + 168 + 36 + 31] ^= 1;
    raw[output_state_offset + 36 + 31] ^= 1;
    wrong_root.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut wrong_root, last);
    assert!(
        scan(&wrong_root)
            .expect_err("wrong root")
            .to_string()
            .contains("Poseidon reconstruction")
    );
}

#[test]
fn rejects_malformed_compact_size_push_token_truncation_and_trailing_bytes() {
    let fixture = make_fixture(1);

    let mut compact_size = fixture.request.clone();
    let mut raw = hex::decode(&compact_size.actions[0].raw_transaction).expect("raw");
    let input_count = raw[4];
    raw.splice(4..5, [0xfd, input_count, 0]);
    compact_size.actions[0].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut compact_size, 0);
    assert!(
        scan(&compact_size)
            .expect_err("compact size")
            .to_string()
            .contains("noncanonical CompactSize")
    );

    let mut push = fixture.request.clone();
    let last = push.actions.len() - 1;
    let mut raw = hex::decode(&push.actions[last].raw_transaction).expect("raw");
    let offset = find(&raw, &[0x4d, 0x28, 0x02, b'S', b'D', b'A', b'2'], 0);
    raw[offset + 1] = 0x27;
    push.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut push, last);
    assert!(
        scan(&push)
            .expect_err("push")
            .to_string()
            .contains("PUSHDATA2(552)")
    );

    let mut token = fixture.request.clone();
    let last = token.actions.len() - 1;
    let mut raw = hex::decode(&token.actions[last].raw_transaction).expect("raw");
    let category = hex::decode(&token.instance_id).expect("category");
    let offset = find(&raw, &[&[0xef], &category[..], &[0x61, 0x80]].concat(), 0);
    raw[offset + 33] = 0xe1;
    token.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut token, last);
    assert!(
        scan(&token)
            .expect_err("token")
            .to_string()
            .contains("reserved bit")
    );

    let mut truncated = fixture.request.clone();
    let last = truncated.actions.len() - 1;
    let mut raw = hex::decode(&truncated.actions[last].raw_transaction).expect("raw");
    raw.pop();
    truncated.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut truncated, last);
    assert!(
        scan(&truncated)
            .expect_err("truncated")
            .to_string()
            .contains("truncated")
    );

    let mut trailing = fixture.request.clone();
    let last = trailing.actions.len() - 1;
    let mut raw = hex::decode(&trailing.actions[last].raw_transaction).expect("raw");
    raw.push(0);
    trailing.actions[last].raw_transaction = hex::encode(&raw);
    update_action_identity(&mut trailing, last);
    assert!(
        scan(&trailing)
            .expect_err("trailing")
            .to_string()
            .contains("trailing bytes")
    );
}

#[test]
fn rejects_funding_prevout_and_snapshot_mutations() {
    let fixture = make_fixture(1);
    let mut wrong_funding = fixture.request.clone();
    wrong_funding.funding_prevouts[0].transaction_id = "ff".repeat(32);
    assert!(
        scan(&wrong_funding)
            .expect_err("funding txid")
            .to_string()
            .contains("computed txid")
    );

    let snapshot = scan(&fixture.request).expect("snapshot");
    let mut root_mutation = snapshot.clone();
    root_mutation.note_tree.root.replace_range(63..64, "0");
    assert!(root_mutation.authenticate_structure().is_err());

    let mut leaf_mutation = snapshot.clone();
    leaf_mutation.note_tree.leaves[0].replace_range(63..64, "f");
    assert!(leaf_mutation.authenticate_structure().is_err());

    let mut packet_mutation = snapshot.clone();
    packet_mutation.actions[0]
        .packet_hex
        .replace_range(8..10, "ff");
    packet_mutation.content_sha256 = packet_mutation
        .recompute_content_sha256()
        .expect("recompute mutated content hash");
    assert!(packet_mutation.authenticate_structure().is_err());

    let mut hash_mutation = snapshot.clone();
    hash_mutation.content_sha256.replace_range(0..2, "ff");
    assert!(hash_mutation.authenticate_structure().is_err());

    assert!(
        verify_snapshot(&VerifySnapshotRequest {
            schema: VERIFY_SCHEMA.to_owned(),
            scan: fixture.request,
            snapshot: hash_mutation,
        })
        .is_err()
    );

    let mut wrong_tip = snapshot.tip.clone();
    wrong_tip.transaction_id = "aa".repeat(32);
    assert!(
        authenticate_snapshot(&AuthenticateSnapshotRequest {
            schema: AUTHENTICATE_SNAPSHOT_SCHEMA.to_owned(),
            network_id: snapshot.network_id,
            profile_id: snapshot.profile_id.clone(),
            instance_id: snapshot.instance_id.clone(),
            denomination_sats: snapshot.denomination_sats.clone(),
            carrier_count: snapshot.carrier_count,
            runtime_materials_sha256: snapshot.runtime_materials_sha256.clone(),
            genesis: snapshot.genesis.clone(),
            tip: wrong_tip,
            snapshot,
        })
        .expect_err("self-consistent snapshot at an unexpected canonical tip")
        .to_string()
        .contains("independently authenticated")
    );
}
