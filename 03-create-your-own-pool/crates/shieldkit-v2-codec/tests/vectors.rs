use sha2::{Digest, Sha256};
use shieldkit_v2_codec::{
    ACTION_PACKET_BYTES, ActionKindV2, BN254_FR_MODULUS, CodecError,
    CommittedDirectV2TransactionContext, DIRECT_V2_ADDRESS_BYTES, DIRECT_V2_CONTEXT_HEADER_BYTES,
    DIRECT_V2_CONTEXT_INPUT_BYTES, DIRECT_V2_CONTEXT_OUTPUT_BYTES, DirectActionPacketV2,
    DirectV2Address, DirectV2ContextInput, DirectV2ContextOutput, DirectV2Role, DirectV2RoleKind,
    DirectV2TransactionContext, PoolStateV2, STATE_BYTES,
};

const DENOMINATION: u64 = 10_000_000;
const Q01_VECTORS: &str =
    include_str!("../../../packages/action/v2/vectors/q01-state-packet-public-input.json");

fn q01_string(field: &str) -> &str {
    let prefix = format!("\"{field}\": \"");
    let value = Q01_VECTORS
        .split_once(&prefix)
        .unwrap_or_else(|| panic!("Q01 vector is missing {field}"))
        .1;
    value
        .split_once('"')
        .unwrap_or_else(|| panic!("Q01 vector has unterminated {field}"))
        .0
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).expect("fixed test hex"))
        .collect()
}

fn array32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn state(
    note_count: u32,
    nullifier_count: u32,
    action_sequence: u64,
    note_root: u8,
    reserve_sats: u64,
) -> PoolStateV2 {
    let mut root = [0_u8; 32];
    root[31] = note_root;
    let mut nullifier_root = [0_u8; 32];
    nullifier_root[31] = 2;
    PoolStateV2 {
        profile_id: array32(0x11),
        note_root: root,
        nullifier_root,
        note_count,
        nullifier_count,
        maximum_live_notes: 7,
        reserve_sats,
        action_sequence,
    }
}

fn vector_packet() -> DirectActionPacketV2 {
    let mut leaf = [0_u8; 32];
    leaf[31] = 5;
    DirectActionPacketV2 {
        network_id: 2,
        kind: ActionKindV2::Deposit,
        instance_id: array32(0x22),
        pre_state: state(0, 0, 0, 1, 0),
        post_state: state(1, 0, 1, 3, DENOMINATION),
        public_nullifier: [0; 32],
        output_note_leaf: leaf,
        encrypted_record: [0x44; 128],
        withdrawal_locking_bytecode_hash: [0; 32],
        transaction_context_hash: array32(0x55),
    }
}

// Deliberately independent of the codec implementation: this frozen field
// contract classifies each one-byte replacement before decoder invocation.
fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("fixed u32 span"))
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("fixed u64 span"))
}

fn canonical_fr(bytes: &[u8]) -> bool {
    bytes < BN254_FR_MODULUS.as_slice()
}

fn frozen_state_accepted(bytes: &[u8]) -> bool {
    if bytes.len() != STATE_BYTES || &bytes[..4] != b"SKS2" {
        return false;
    }
    if !canonical_fr(&bytes[36..68]) || !canonical_fr(&bytes[68..100]) {
        return false;
    }
    let note_count = read_u32_le(&bytes[100..104]);
    let nullifier_count = read_u32_le(&bytes[104..108]);
    let maximum_live_notes = read_u32_le(&bytes[108..112]);
    let reserve_sats = read_u64_le(&bytes[112..120]);
    let action_sequence = read_u64_le(&bytes[120..128]);
    if nullifier_count > note_count || nullifier_count == u32::MAX || maximum_live_notes == 0 {
        return false;
    }
    if u64::from(maximum_live_notes) > 2_100_000_000_000_000_u64 / DENOMINATION {
        return false;
    }
    let live_notes = u64::from(note_count - nullifier_count);
    live_notes <= u64::from(maximum_live_notes)
        && reserve_sats == live_notes * DENOMINATION
        && action_sequence < (1_u64 << 33)
        && action_sequence >= u64::from(note_count.max(nullifier_count))
        && action_sequence <= u64::from(note_count) + u64::from(nullifier_count)
}

fn frozen_packet_accepted(bytes: &[u8]) -> bool {
    if bytes.len() != ACTION_PACKET_BYTES || &bytes[..4] != b"SDA2" {
        return false;
    }
    if !matches!(bytes[4], 1 | 2) || !matches!(bytes[5], 1..=3) || bytes[6] != 0 || bytes[7] != 0 {
        return false;
    }
    if !frozen_state_accepted(&bytes[40..168]) || !frozen_state_accepted(&bytes[168..296]) {
        return false;
    }
    if !canonical_fr(&bytes[296..328]) || !canonical_fr(&bytes[328..360]) {
        return false;
    }
    if bytes[44..76] != bytes[172..204] || bytes[148..152] != bytes[276..280] {
        return false;
    }
    match bytes[5] {
        1 => {
            bytes[296..328].iter().all(|byte| *byte == 0)
                && bytes[488..520].iter().all(|byte| *byte == 0)
        }
        2 => bytes[488..520].iter().all(|byte| *byte == 0),
        3 => {
            bytes[328..360].iter().all(|byte| *byte == 0)
                && bytes[360..488].iter().all(|byte| *byte == 0)
        }
        _ => false,
    }
}

#[test]
fn cross_language_fixed_state_packet_digest_and_limbs() {
    assert_eq!(
        q01_string("schema"),
        "shieldkit/v2-direct-q01-codec-vectors/v1"
    );
    assert_eq!(
        q01_string("denominationSats").parse::<u64>().unwrap(),
        DENOMINATION
    );
    let pre = vector_packet().pre_state;
    assert_eq!(
        pre.encode(DENOMINATION).unwrap().as_slice(),
        hex(q01_string("preStateHex"))
    );
    let post = vector_packet().post_state;
    assert_eq!(
        post.encode(DENOMINATION).unwrap().as_slice(),
        hex(q01_string("postStateHex"))
    );
    let packet = vector_packet();
    assert_eq!(
        packet.encode(DENOMINATION).unwrap().as_slice(),
        hex(q01_string("packetHex"))
    );
    assert_eq!(
        packet.sha256(DENOMINATION).unwrap(),
        hex(q01_string("packetSha256Hex")).as_slice()
    );
    assert_eq!(
        packet.public_input_limbs(DENOMINATION).unwrap(),
        (
            q01_string("publicInput0BeU128").parse().unwrap(),
            q01_string("publicInput1BeU128").parse().unwrap(),
        )
    );
    assert_eq!(
        DirectActionPacketV2::decode(&hex(q01_string("packetHex")), DENOMINATION).unwrap(),
        packet
    );
}

#[test]
fn q01_exhaustive_one_byte_mutations_are_rejected_or_canonical_distinct() {
    let baseline_state = vector_packet().post_state;
    let state_bytes = baseline_state.encode(DENOMINATION).unwrap();
    let mut state_accepted = 0_usize;
    let mut state_rejected = 0_usize;
    for offset in 0..STATE_BYTES {
        let original = state_bytes[offset];
        for replacement in 0_u16..=u16::from(u8::MAX) {
            let replacement = replacement as u8;
            if replacement == original {
                continue;
            }
            let mut changed = state_bytes;
            changed[offset] = replacement;
            let expected = frozen_state_accepted(&changed);
            match PoolStateV2::decode(&changed, DENOMINATION) {
                Ok(decoded) => {
                    assert!(
                        expected,
                        "state {offset}/{replacement}: frozen oracle requires rejection"
                    );
                    assert_ne!(
                        decoded, baseline_state,
                        "state {offset}/{replacement}: accepted mutation aliases baseline state"
                    );
                    assert_eq!(
                        decoded.encode(DENOMINATION).unwrap(),
                        changed,
                        "state {offset}/{replacement}: accepted mutation is not canonical"
                    );
                    state_accepted += 1;
                }
                Err(_) => {
                    assert!(
                        !expected,
                        "state {offset}/{replacement}: frozen oracle requires acceptance"
                    );
                    state_rejected += 1;
                }
            }
        }
    }
    assert_eq!(state_accepted + state_rejected, STATE_BYTES * 255);
    assert_eq!(state_accepted, 24_842);
    assert_eq!(state_rejected, 7_798);

    let baseline_packet = vector_packet();
    let packet_bytes = baseline_packet.encode(DENOMINATION).unwrap();
    let baseline_digest: [u8; 32] = Sha256::digest(packet_bytes).into();
    let baseline_limbs = baseline_packet.public_input_limbs(DENOMINATION).unwrap();
    let mut packet_accepted = 0_usize;
    let mut packet_rejected = 0_usize;
    let mut public_input_vectors = 0_usize;
    for offset in 0..ACTION_PACKET_BYTES {
        let original = packet_bytes[offset];
        for replacement in 0_u16..=u16::from(u8::MAX) {
            let replacement = replacement as u8;
            if replacement == original {
                continue;
            }
            let mut changed = packet_bytes;
            changed[offset] = replacement;
            let expected = frozen_packet_accepted(&changed);
            match DirectActionPacketV2::decode(&changed, DENOMINATION) {
                Ok(decoded) => {
                    assert!(
                        expected,
                        "packet {offset}/{replacement}: frozen oracle requires rejection"
                    );
                    assert_ne!(
                        decoded, baseline_packet,
                        "packet {offset}/{replacement}: accepted mutation aliases baseline packet"
                    );
                    assert_eq!(
                        decoded.encode(DENOMINATION).unwrap(),
                        changed,
                        "packet {offset}/{replacement}: accepted mutation is not canonical"
                    );
                    let digest: [u8; 32] = Sha256::digest(changed).into();
                    assert_eq!(
                        decoded.sha256(DENOMINATION).unwrap(),
                        digest,
                        "packet {offset}/{replacement}: SHA-256 mismatch"
                    );
                    assert_ne!(
                        digest, baseline_digest,
                        "packet {offset}/{replacement}: SHA-256 aliases baseline"
                    );
                    let limbs = decoded.public_input_limbs(DENOMINATION).unwrap();
                    assert_eq!(
                        limbs,
                        (
                            u128::from_be_bytes(digest[..16].try_into().unwrap()),
                            u128::from_be_bytes(digest[16..].try_into().unwrap())
                        ),
                        "packet {offset}/{replacement}: big-endian u128 limbs mismatch",
                    );
                    assert_ne!(
                        limbs, baseline_limbs,
                        "packet {offset}/{replacement}: public limbs alias baseline"
                    );
                    packet_accepted += 1;
                    public_input_vectors += 1;
                }
                Err(_) => {
                    assert!(
                        !expected,
                        "packet {offset}/{replacement}: frozen oracle requires acceptance"
                    );
                    packet_rejected += 1;
                }
            }
        }
    }
    assert_eq!(packet_accepted + packet_rejected, ACTION_PACKET_BYTES * 255);
    assert_eq!(packet_accepted, 88_727);
    assert_eq!(packet_rejected, 52_033);
    assert_eq!(public_input_vectors, packet_accepted);

    // CashToken category bytes are wire-order consensus data. Explorer txid
    // presentation is reverse-only display data and is never an SDA2 substitute.
    let category_wire = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
        0xfe, 0x0f,
    ];
    let mut explorer_display = category_wire;
    explorer_display.reverse();
    assert_eq!(
        hex(q01_string("categoryWireHex")).as_slice(),
        category_wire.as_slice()
    );
    assert_eq!(
        hex(q01_string("categoryExplorerDisplayHex")).as_slice(),
        explorer_display.as_slice()
    );
    let category_packet = DirectActionPacketV2 {
        instance_id: category_wire,
        ..baseline_packet
    };
    let category_bytes = category_packet.encode(DENOMINATION).unwrap();
    assert_eq!(&category_bytes[8..40], category_wire);
    assert_ne!(&category_bytes[8..40], explorer_display);
    assert_eq!(
        DirectActionPacketV2::decode(&category_bytes, DENOMINATION)
            .unwrap()
            .instance_id,
        category_wire
    );

    println!(
        "V2_STRICT_CODEC_QUALIFICATION={{\"schema\":\"shieldkit/v2-strict-codec-qualification/v1\",\"surface\":\"rust\",\"lengthsRejected\":{{\"state\":[127,129],\"packet\":[551,553]}},\"categoryByteOrder\":{{\"wireHex\":\"00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f\",\"explorerDisplayHex\":\"0ffeeddccbbaa9988776655443322110ffeeddccbbaa99887766554433221100\"}},\"sha256BeU128\":{{\"digestHex\":\"ded42d09831ea2f39e521ce62b5faf474cf70946a76e934b6d6abe2280559a18\",\"limbs\":[\"296190295460325907773963638825346379591\",\"102304013143187191688059162453337283096\"]}},\"state\":{{\"mutations\":32640,\"acceptedCanonicalDistinct\":24842,\"rejected\":7798}},\"packet\":{{\"mutations\":140760,\"acceptedCanonicalDistinct\":88727,\"rejected\":52033}},\"publicInputVectors\":88727}}"
    );
}

#[test]
fn rejects_exact_length_headers_network_kind_and_flags() {
    let state_bytes = vector_packet().pre_state.encode(DENOMINATION).unwrap();
    for length in [127, 129] {
        let mut bytes = vec![0; length];
        bytes[..length.min(STATE_BYTES)].copy_from_slice(&state_bytes[..length.min(STATE_BYTES)]);
        assert!(matches!(
            PoolStateV2::decode(&bytes, DENOMINATION),
            Err(CodecError::Length { .. })
        ));
    }
    let packet_bytes = vector_packet().encode(DENOMINATION).unwrap();
    for length in [551, 553] {
        let mut bytes = vec![0; length];
        bytes[..ACTION_PACKET_BYTES.min(length)]
            .copy_from_slice(&packet_bytes[..ACTION_PACKET_BYTES.min(length)]);
        assert!(matches!(
            DirectActionPacketV2::decode(&bytes, DENOMINATION),
            Err(CodecError::Length { .. })
        ));
    }
    for offset in 0..4 {
        let mut bytes = state_bytes;
        bytes[offset] ^= 1;
        assert!(matches!(
            PoolStateV2::decode(&bytes, DENOMINATION),
            Err(CodecError::Magic { .. })
        ));
    }
    for (offset, expected) in [
        (0, "magic"),
        (4, "network"),
        (5, "kind"),
        (6, "flags"),
        (7, "flags"),
    ] {
        let mut bytes = packet_bytes;
        bytes[offset] = 0xff;
        let error = DirectActionPacketV2::decode(&bytes, DENOMINATION)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected));
    }
}

#[test]
fn accepts_both_wire_network_ids_and_rejects_unknown_ids() {
    let mainnet = DirectActionPacketV2 {
        network_id: 1,
        ..vector_packet()
    };
    let encoded = mainnet.encode(DENOMINATION).unwrap();
    assert_eq!(
        DirectActionPacketV2::decode(&encoded, DENOMINATION).unwrap(),
        mainnet
    );
    for network_id in [0, 3, 255] {
        let invalid = DirectActionPacketV2 {
            network_id,
            ..vector_packet()
        };
        assert!(
            matches!(invalid.validate(DENOMINATION), Err(CodecError::Network(value)) if value == network_id)
        );
    }
}

#[test]
fn rejects_noncanonical_fields_and_state_invariants() {
    let mut bad_root = state(0, 0, 0, 1, 0);
    bad_root.note_root = BN254_FR_MODULUS;
    assert!(matches!(
        bad_root.validate(DENOMINATION),
        Err(CodecError::NoncanonicalFr(_))
    ));
    let bad_nullifier = DirectActionPacketV2 {
        public_nullifier: [0xff; 32],
        ..vector_packet()
    };
    assert!(matches!(
        bad_nullifier.validate(DENOMINATION),
        Err(CodecError::NoncanonicalFr(_))
    ));
    let bad_leaf = DirectActionPacketV2 {
        output_note_leaf: [0xff; 32],
        ..vector_packet()
    };
    assert!(matches!(
        bad_leaf.validate(DENOMINATION),
        Err(CodecError::NoncanonicalFr(_))
    ));
    assert!(matches!(
        state(0, 1, 0, 1, 0).validate(DENOMINATION),
        Err(CodecError::StateInvariant(_))
    ));
    assert!(matches!(
        state(0, 0, 0, 1, 0).validate(0),
        Err(CodecError::Denomination)
    ));
}

#[test]
fn permits_active_zeros_and_rejects_inactive_nonzero_fields() {
    let zero_active = DirectActionPacketV2 {
        output_note_leaf: [0; 32],
        encrypted_record: [0; 128],
        ..vector_packet()
    };
    assert!(zero_active.validate(DENOMINATION).is_ok());
    let bad_deposit = DirectActionPacketV2 {
        public_nullifier: array32(1),
        ..vector_packet()
    };
    assert!(matches!(
        bad_deposit.validate(DENOMINATION),
        Err(CodecError::PacketInvariant(_))
    ));
    let transfer = DirectActionPacketV2 {
        kind: ActionKindV2::Transfer,
        pre_state: state(1, 0, 1, 3, DENOMINATION),
        post_state: state(2, 1, 2, 4, DENOMINATION),
        public_nullifier: [0; 32],
        output_note_leaf: [0; 32],
        encrypted_record: [0; 128],
        ..vector_packet()
    };
    assert!(transfer.validate(DENOMINATION).is_ok());
    let withdrawal = DirectActionPacketV2 {
        kind: ActionKindV2::Withdrawal,
        pre_state: state(1, 0, 1, 3, DENOMINATION),
        post_state: state(1, 1, 2, 3, 0),
        output_note_leaf: [0; 32],
        encrypted_record: [0; 128],
        public_nullifier: [0; 32],
        withdrawal_locking_bytecode_hash: [0; 32],
        ..vector_packet()
    };
    assert!(withdrawal.validate(DENOMINATION).is_ok());
    let bad_withdrawal = DirectActionPacketV2 {
        output_note_leaf: array32(1),
        ..withdrawal
    };
    assert!(matches!(
        bad_withdrawal.validate(DENOMINATION),
        Err(CodecError::PacketInvariant(_))
    ));
}

fn context_role(kind: DirectV2RoleKind, ordinal: u8) -> DirectV2Role {
    DirectV2Role { kind, ordinal }
}

fn context_input(
    kind: DirectV2RoleKind,
    ordinal: u8,
    byte: u8,
    token: bool,
) -> DirectV2ContextInput {
    DirectV2ContextInput {
        role: context_role(kind, ordinal),
        outpoint_transaction_hash: [byte; 32],
        outpoint_index: u32::from(ordinal),
        sequence: u32::MAX,
        value_sats: 1_000,
        locking_bytecode: vec![byte],
        token_prefix: if token { vec![0xef, byte] } else { Vec::new() },
    }
}

fn context_output(
    kind: DirectV2RoleKind,
    ordinal: u8,
    byte: u8,
    token: bool,
) -> DirectV2ContextOutput {
    DirectV2ContextOutput {
        role: context_role(kind, ordinal),
        value_sats: 1_000,
        locking_bytecode: vec![byte],
        token_prefix: if token { vec![0xef, byte] } else { Vec::new() },
    }
}

fn context_fixture(kind: ActionKindV2) -> DirectV2TransactionContext {
    DirectV2TransactionContext {
        network_id: 2,
        kind,
        profile_id: [0x11; 32],
        instance_id: [0x22; 32],
        transaction_version: 2,
        locktime: 0,
        pre_action_sequence: 7,
        post_action_sequence: 8,
        inputs: vec![
            context_input(DirectV2RoleKind::Verifier, 0, 0x01, false),
            context_input(DirectV2RoleKind::Verifier, 1, 0x02, false),
            context_input(DirectV2RoleKind::Binding, 0, 0x0a, false),
            context_input(DirectV2RoleKind::State, 0, 0x0b, true),
            context_input(DirectV2RoleKind::Funding, 0, 0x0c, false),
        ],
        outputs: vec![
            context_output(DirectV2RoleKind::State, 0, 0x1a, true),
            context_output(DirectV2RoleKind::Verifier, 0, 0x11, false),
            context_output(DirectV2RoleKind::Verifier, 1, 0x12, false),
            context_output(DirectV2RoleKind::Binding, 0, 0x1d, false),
            context_output(DirectV2RoleKind::Change, 0, 0x1f, false),
        ],
    }
}

#[test]
fn cross_language_ska2_address_vector_and_rejections() {
    const SKA2: &str = "534b41320200000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222957cfd431b63e4a96bf4f3ef71dfb4c19c31f98958f2944495ae95220e6fd621dc4f6bf477ec17e8f19442c6730e701caaa89050edc595280d3155e00beed7820dc9831817e6c520d9a38d14c88e91d930a1f33179ac917b52f39bb83e125bbd";
    let encoded = hex(SKA2);
    assert_eq!(encoded.len(), DIRECT_V2_ADDRESS_BYTES);
    let decoded = DirectV2Address::decode(&encoded).unwrap();
    assert_eq!(decoded.network_id, 2);
    assert_eq!(decoded.profile_id, [0x11; 32]);
    assert_eq!(decoded.instance_id, [0x22; 32]);
    assert_eq!(decoded.encode().unwrap().as_slice(), encoded);
    for offset in [0, 1, 2, 3, 5, 6, 7, 72, 104, 136] {
        let mut malformed = encoded.clone();
        malformed[offset] ^= 1;
        assert!(
            DirectV2Address::decode(&malformed).is_err(),
            "offset {offset}"
        );
    }
    for length in [167, 169] {
        let mut malformed = vec![0; length];
        malformed[..length.min(encoded.len())]
            .copy_from_slice(&encoded[..length.min(encoded.len())]);
        assert!(matches!(
            DirectV2Address::decode(&malformed),
            Err(CodecError::Length { .. })
        ));
    }
}

#[test]
fn cross_language_sdc2_context_vector_decode_and_rejections() {
    let context = context_fixture(ActionKindV2::Deposit);
    context.validate_role_topology(2).unwrap();
    let encoded = context.encode_with_carrier_count(2).unwrap();
    assert_eq!(
        encoded.len(),
        DIRECT_V2_CONTEXT_HEADER_BYTES
            + (5 * DIRECT_V2_CONTEXT_INPUT_BYTES)
            + (5 * DIRECT_V2_CONTEXT_OUTPUT_BYTES)
    );
    assert_eq!(&encoded[..8], b"SDC2\x02\x01\x00\x00");
    assert_eq!(&encoded[80..84], &[5, 0, 5, 0]);
    assert_eq!(
        context.sha256_with_carrier_count(2).unwrap(),
        hex("9ce7bda7814769a8c9131e104174c01cad150c449a982a3d39c0e2335e12da5d").as_slice(),
    );
    let decoded = CommittedDirectV2TransactionContext::decode(&encoded).unwrap();
    decoded.validate_role_topology(2).unwrap();
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert_eq!(decoded.sha256().unwrap(), context.sha256().unwrap());
    for offset in [0, 1, 2, 3, 6, 7, 100, 102] {
        let mut malformed = encoded.clone();
        malformed[offset] = 0xff;
        assert!(
            CommittedDirectV2TransactionContext::decode(&malformed).is_err(),
            "offset {offset}"
        );
    }
    for length in [99, encoded.len() - 1, encoded.len() + 1] {
        let mut malformed = vec![0; length];
        malformed[..length.min(encoded.len())]
            .copy_from_slice(&encoded[..length.min(encoded.len())]);
        assert!(matches!(
            CommittedDirectV2TransactionContext::decode(&malformed),
            Err(CodecError::Length { .. })
        ));
    }
}

#[test]
fn rejects_sdc2_topology_and_sequence_ambiguity() {
    let mut context = context_fixture(ActionKindV2::Deposit);
    context.outputs[0].token_prefix.clear();
    assert!(context.validate_role_topology(2).is_err());
    let mut context = context_fixture(ActionKindV2::Deposit);
    context.post_action_sequence = 9;
    assert!(context.encode().is_err());
    let mut context = context_fixture(ActionKindV2::Withdrawal);
    context.outputs.insert(
        4,
        context_output(DirectV2RoleKind::Withdrawal, 0, 0x1e, false),
    );
    context.validate_role_topology(2).unwrap();
    assert_eq!(
        context.encode_with_carrier_count(2).unwrap().len(),
        DIRECT_V2_CONTEXT_HEADER_BYTES
            + (5 * DIRECT_V2_CONTEXT_INPUT_BYTES)
            + (6 * DIRECT_V2_CONTEXT_OUTPUT_BYTES)
    );
}

#[test]
fn committed_sdc2_topology_rejects_role_and_token_commitment_tampering() {
    let context = context_fixture(ActionKindV2::Deposit);
    let encoded = context.encode_with_carrier_count(2).unwrap();
    let decoded = CommittedDirectV2TransactionContext::decode(&encoded).unwrap();
    decoded.validate_role_topology(2).unwrap();

    let mut wrong_role = decoded.clone();
    wrong_role.inputs[0].role.kind = DirectV2RoleKind::Binding;
    assert!(wrong_role.validate_role_topology(2).is_err());

    let mut verifier_token = decoded.clone();
    verifier_token.inputs[0].token_prefix_hash = [0x42; 32];
    assert!(verifier_token.validate_role_topology(2).is_err());

    let mut missing_state_token = decoded.clone();
    missing_state_token.inputs[3].token_prefix_hash = Sha256::digest([]).into();
    assert!(missing_state_token.validate_role_topology(2).is_err());

    let mut wrong_count = decoded;
    wrong_count.outputs.pop();
    assert!(wrong_count.validate_role_topology(2).is_err());
}
