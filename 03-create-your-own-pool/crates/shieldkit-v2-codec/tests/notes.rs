use rand_core::{CryptoRng, Error as RandomError, RngCore};
use shieldkit_v2_codec::{
    BN254_FR_MODULUS, CodecError, DirectV2Account, DirectV2OutputRandomness,
    construct_direct_v2_output, derive_direct_v2_address, derive_direct_v2_note_commitment,
    derive_direct_v2_nullifier, derive_direct_v2_rho, hash_direct_v2_output_note_leaf,
    recover_direct_v2_output, sample_direct_v2_output_randomness,
};

const ENCRYPTED_RECORD_HEX: &str = "210f9eb1f917b8d07a49ba0f326ad4a058663b2b9ac7d1126e5f26f65d67c79a1ddabf2d7cdb587f50cdff2c24d9746dca2c329969b1085b3e63e55638bc9b4604775026554dac6457dfac915f510b27c67f93be2a78e5611e5ae2a2e6793b792829b5e0ebdf1c35bf199eb27d97fec9f9eb917bb70e1b8df78e9ae906519a96";

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).expect("fixed test hex"))
        .collect()
}

fn field(value: u64) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    encoded[24..].copy_from_slice(&value.to_be_bytes());
    encoded
}

struct FixedRng {
    values: Vec<[u8; 32]>,
    offset: usize,
}

impl FixedRng {
    fn new(values: Vec<[u8; 32]>) -> Self {
        Self { values, offset: 0 }
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        panic!("unused by the fixed 32-byte test source")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("unused by the fixed 32-byte test source")
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        assert_eq!(destination.len(), 32);
        destination.copy_from_slice(&self.values[self.offset]);
        self.offset += 1;
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

fn fixture() -> (
    DirectV2Account,
    DirectV2OutputRandomness,
    shieldkit_v2_codec::DirectV2ConstructedOutput,
) {
    let spend_secret = field(3);
    let incoming_view_secret = field(4);
    let address = derive_direct_v2_address(
        2,
        [0x11; 32],
        [0x22; 32],
        &spend_secret,
        &incoming_view_secret,
    )
    .unwrap();
    let randomness = DirectV2OutputRandomness {
        rho_blind: field(5),
        r: field(6),
        ephemeral_scalar: field(7),
    };
    let mut rng = FixedRng::new(vec![
        randomness.rho_blind,
        randomness.r,
        randomness.ephemeral_scalar,
    ]);
    let output = construct_direct_v2_output(&address, 1, &mut rng).unwrap();
    (
        DirectV2Account {
            address,
            spend_secret,
            incoming_view_secret,
        },
        randomness,
        output,
    )
}

#[test]
fn pins_complete_js_address_note_record_leaf_and_nullifier_vector() {
    let (account, randomness, output) = fixture();
    assert_eq!(
        account.address.spend_public_key,
        hex("957cfd431b63e4a96bf4f3ef71dfb4c19c31f98958f2944495ae95220e6fd621").as_slice()
    );
    assert_eq!(
        account.address.incoming_view_public_key,
        hex("dc4f6bf477ec17e8f19442c6730e701caaa89050edc595280d3155e00beed782").as_slice()
    );
    assert_eq!(
        account.address.authority,
        hex("0dc9831817e6c520d9a38d14c88e91d930a1f33179ac917b52f39bb83e125bbd").as_slice()
    );
    assert_eq!(
        output.witness.rho,
        hex("08b1cb9269cf911ed0bdf63ab77da6fbeb09042d8a4bfe27b78000091d514783").as_slice()
    );
    assert_eq!(output.witness.rho_blind, randomness.rho_blind);
    assert_eq!(output.witness.r, randomness.r);
    assert_eq!(
        output.public.note_commitment,
        hex("0d0f3580dd8101f05cdc4b07f17d3ce38ef23b4cdacac540cc912a4682fc3723").as_slice()
    );
    assert_eq!(
        output.public.encrypted_record,
        hex(ENCRYPTED_RECORD_HEX).as_slice()
    );
    assert_eq!(
        output.public.output_note_leaf,
        hex("063b2fb6fc17fff7200daefe163121f26bcf2fe1e79a33a2f7a81c3743a7ee28").as_slice()
    );

    let record_tag: [u8; 32] = output.public.encrypted_record[96..]
        .try_into()
        .unwrap();
    assert_eq!(
        hash_direct_v2_output_note_leaf(&output.public.note_commitment, &record_tag).unwrap(),
        output.public.output_note_leaf
    );
    assert_eq!(
        derive_direct_v2_rho(
            &account.address.profile_id,
            &account.address.instance_id,
            1,
            &randomness.rho_blind,
        )
        .unwrap(),
        output.witness.rho
    );
    assert_eq!(
        derive_direct_v2_note_commitment(
            &account.address.profile_id,
            &account.address.instance_id,
            &account.address.authority,
            &output.witness.rho,
            &randomness.r,
        )
        .unwrap(),
        output.public.note_commitment
    );

    let recovered = recover_direct_v2_output(
        &account,
        &output.public.output_note_leaf,
        &output.public.encrypted_record,
    )
    .unwrap();
    assert_eq!(recovered.authority, account.address.authority);
    assert_eq!(recovered.rho, output.witness.rho);
    assert_eq!(recovered.r, field(6));
    assert_eq!(recovered.note_commitment, output.public.note_commitment);
    assert_eq!(recovered.output_note_leaf, output.public.output_note_leaf);
    assert_eq!(recovered.encrypted_record, output.public.encrypted_record);
    assert_eq!(
        recovered.nullifier,
        hex("05862a6bb1b9f827f3283df7006a3db2a0e449e27e239c13856107cfd4fe4630").as_slice()
    );
    assert_eq!(
        derive_direct_v2_nullifier(
            &account.address.profile_id,
            &account.address.instance_id,
            &account.spend_secret,
            &recovered.rho,
            &recovered.note_commitment,
        )
        .unwrap(),
        recovered.nullifier
    );
}

#[test]
fn authenticates_every_record_byte_and_rejects_wrong_leaf_key_and_context_replay() {
    let (account, _, output) = fixture();
    for offset in 0..output.public.encrypted_record.len() {
        let mut malformed = output.public.encrypted_record;
        malformed[offset] ^= 1;
        assert!(
            recover_direct_v2_output(&account, &output.public.output_note_leaf, &malformed)
                .is_err(),
            "record byte {offset}"
        );
    }

    let mut wrong_leaf = output.public.output_note_leaf;
    wrong_leaf[31] ^= 1;
    assert!(matches!(
        recover_direct_v2_output(&account, &wrong_leaf, &output.public.encrypted_record),
        Err(CodecError::OutputLeafMismatch)
    ));

    let wrong_key = DirectV2Account {
        incoming_view_secret: field(8),
        ..account.clone()
    };
    assert!(matches!(
        recover_direct_v2_output(
            &wrong_key,
            &output.public.output_note_leaf,
            &output.public.encrypted_record
        ),
        Err(CodecError::AccountMismatch)
    ));

    let replay_address = derive_direct_v2_address(
        2,
        [0x12; 32],
        [0x22; 32],
        &account.spend_secret,
        &account.incoming_view_secret,
    )
    .unwrap();
    let replay_account = DirectV2Account {
        address: replay_address,
        spend_secret: account.spend_secret,
        incoming_view_secret: account.incoming_view_secret,
    };
    assert!(
        recover_direct_v2_output(
            &replay_account,
            &output.public.output_note_leaf,
            &output.public.encrypted_record,
        )
        .is_err()
    );
}

#[test]
fn rejects_malformed_noncanonical_zero_and_non_subgroup_inputs() {
    let (account, randomness, output) = fixture();

    for length in [127, 129] {
        let mut malformed = vec![0_u8; length];
        let copied = length.min(output.public.encrypted_record.len());
        malformed[..copied].copy_from_slice(&output.public.encrypted_record[..copied]);
        assert!(matches!(
            recover_direct_v2_output(&account, &output.public.output_note_leaf, &malformed),
            Err(CodecError::Length { .. })
        ));
    }

    let mut noncanonical_field = output.public.encrypted_record;
    noncanonical_field[32..64].copy_from_slice(&BN254_FR_MODULUS);
    assert!(matches!(
        recover_direct_v2_output(
            &account,
            &output.public.output_note_leaf,
            &noncanonical_field
        ),
        Err(CodecError::NoncanonicalFr(_))
    ));

    let mut identity = output.public.encrypted_record;
    identity[..32].fill(0);
    identity[0] = 1;
    assert!(matches!(
        recover_direct_v2_output(&account, &output.public.output_note_leaf, &identity),
        Err(CodecError::AddressInvariant(_))
    ));

    let mut non_subgroup = output.public.encrypted_record;
    non_subgroup[..32].fill(0);
    let non_subgroup_error =
        recover_direct_v2_output(&account, &output.public.output_note_leaf, &non_subgroup)
            .unwrap_err();
    assert!(matches!(
        &non_subgroup_error,
        CodecError::AddressInvariant(_)
    ));
    assert!(non_subgroup_error.to_string().contains("prime-subgroup"));

    let mut noncanonical_point = output.public.encrypted_record;
    let mut little_endian_modulus = BN254_FR_MODULUS;
    little_endian_modulus.reverse();
    noncanonical_point[..32].copy_from_slice(&little_endian_modulus);
    assert!(matches!(
        recover_direct_v2_output(
            &account,
            &output.public.output_note_leaf,
            &noncanonical_point
        ),
        Err(CodecError::AddressInvariant(_))
    ));

    for invalid_sequence in [0, 1_u64 << 33] {
        let mut rng = FixedRng::new(vec![field(5), field(6), field(7)]);
        let result = construct_direct_v2_output(&account.address, invalid_sequence, &mut rng);
        assert!(matches!(result, Err(CodecError::SequenceInvariant)));
        assert_eq!(rng.offset, 3);
    }

    let mut malformed_address = account.address.clone();
    malformed_address.authority[31] ^= 1;
    let mut untouched_rng = FixedRng::new(vec![field(5), field(6), field(7)]);
    assert!(matches!(
        construct_direct_v2_output(&malformed_address, 1, &mut untouched_rng),
        Err(CodecError::AddressInvariant(_))
    ));
    assert_eq!(untouched_rng.offset, 0);

    let mut zero_r = randomness.clone();
    zero_r.r = [0; 32];
    assert!(matches!(
        zero_r.validate(),
        Err(CodecError::ScalarInvariant(_))
    ));
    let mut zero_ephemeral = randomness.clone();
    zero_ephemeral.ephemeral_scalar = [0; 32];
    assert!(matches!(
        zero_ephemeral.validate(),
        Err(CodecError::ScalarInvariant(_))
    ));
    let mut noncanonical_rho_blind = randomness;
    noncanonical_rho_blind.rho_blind = BN254_FR_MODULUS;
    assert!(matches!(
        noncanonical_rho_blind.validate(),
        Err(CodecError::NoncanonicalFr(_))
    ));

    assert!(matches!(
        derive_direct_v2_address(2, [0x11; 32], [0x22; 32], &[0; 32], &field(4)),
        Err(CodecError::ScalarInvariant(_))
    ));
    let subgroup_order = <[u8; 32]>::try_from(hex(
        "060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1",
    ))
    .unwrap();
    assert!(matches!(
        derive_direct_v2_address(2, [0x11; 32], [0x22; 32], &subgroup_order, &field(4)),
        Err(CodecError::ScalarInvariant(_))
    ));
}

#[test]
fn mirrors_js_rejection_sampling_bounds_and_exhaustion() {
    let subgroup_order = <[u8; 32]>::try_from(hex(
        "060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1",
    ))
    .unwrap();
    let mut rng = FixedRng::new(vec![
        [0; 32],
        BN254_FR_MODULUS,
        field(5),
        field(6),
        subgroup_order,
        field(7),
    ]);
    assert_eq!(
        sample_direct_v2_output_randomness(&mut rng).unwrap(),
        DirectV2OutputRandomness {
            rho_blind: field(5),
            r: field(6),
            ephemeral_scalar: field(7),
        }
    );

    let mut zero_rng = FixedRng::new(vec![[0; 32]; 1024]);
    assert!(matches!(
        sample_direct_v2_output_randomness(&mut zero_rng),
        Err(CodecError::RandomnessFailure(_))
    ));
    assert_eq!(zero_rng.offset, 1024);
}

#[test]
fn q05_rejects_point_field_and_foreign_output_corpus_without_secret_emission() {
    let (account, _, output) = fixture();

    // Exercise a non-fixture secret canary through a fail-closed public
    // boundary. Codec errors are intentionally classified-only: neither this
    // scalar nor any derived key material may appear in diagnostic text.
    let secret_canary: [u8; 32] =
        hex("060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2")
            .try_into()
            .unwrap();
    let secret_canary_hex = secret_canary
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let canary_error =
        derive_direct_v2_address(2, [0x11; 32], [0x22; 32], &secret_canary, &field(4))
            .unwrap_err();
    assert!(matches!(canary_error, CodecError::ScalarInvariant("spend secret")));
    assert!(!canary_error.to_string().contains(&secret_canary_hex));

    // The valid fixture pins canonical, nonzero secrets. Each public-key case
    // below must reject before authority binding can make it look acceptable.
    for point in [
        {
            let mut point = [0_u8; 32];
            point[0] = 1; // identity
            point
        },
        [0_u8; 32], // non-subgroup
        {
            let mut point = [0_u8; 32];
            point[0] = 2; // compressed-y off-curve encoding
            point
        },
        {
            let mut point = BN254_FR_MODULUS;
            point.reverse(); // noncanonical compressed-y encoding
            point
        },
    ] {
        let mut malformed = account.address.clone();
        malformed.spend_public_key = point;
        assert!(matches!(
            malformed.validate(),
            Err(CodecError::AddressInvariant(_))
        ));
    }

    for offset in [32, 64, 96] {
        let mut malformed = output.public.encrypted_record;
        malformed[offset..offset + 32].fill(0xff);
        assert!(matches!(
            recover_direct_v2_output(&account, &output.public.output_note_leaf, &malformed),
            Err(CodecError::NoncanonicalFr(_))
        ));
    }

    for length in [0, 1, 127, 129] {
        let malformed = vec![0_u8; length];
        assert!(matches!(
            recover_direct_v2_output(&account, &output.public.output_note_leaf, &malformed),
            Err(CodecError::Length { .. })
        ));
    }

    // A Faerie-style record with a syntactically sized but invalid ephemeral
    // point must fail before any candidate plaintext can be returned.
    let mut faerie = output.public.encrypted_record;
    faerie[..32].fill(0);
    assert!(matches!(
        recover_direct_v2_output(&account, &output.public.output_note_leaf, &faerie),
        Err(CodecError::AddressInvariant(_))
    ));

    let foreign_spend_secret = field(9);
    let foreign_incoming_view_secret = field(10);
    let foreign_address = derive_direct_v2_address(
        2,
        [0x11; 32],
        [0x22; 32],
        &foreign_spend_secret,
        &foreign_incoming_view_secret,
    )
    .unwrap();
    let mut foreign_rng = FixedRng::new(vec![field(5), field(6), field(7)]);
    let foreign_output = construct_direct_v2_output(&foreign_address, 1, &mut foreign_rng).unwrap();
    assert!(matches!(
        recover_direct_v2_output(
            &account,
            &foreign_output.public.output_note_leaf,
            &foreign_output.public.encrypted_record,
        ),
        Err(CodecError::RecordAuthenticationFailed)
    ));

    // There is no global spent-randomness registry at this API boundary. The
    // only local detection available here is equality of the public outputs.
    let mut first_rng = FixedRng::new(vec![field(5), field(6), field(7)]);
    let mut repeated_rng = FixedRng::new(vec![field(5), field(6), field(7)]);
    let first = construct_direct_v2_output(&account.address, 1, &mut first_rng).unwrap();
    let repeated = construct_direct_v2_output(&account.address, 1, &mut repeated_rng).unwrap();
    assert_eq!(first.public.note_commitment, repeated.public.note_commitment);
    assert_eq!(first.public.output_note_leaf, repeated.public.output_note_leaf);
    assert_eq!(first.public.encrypted_record, repeated.public.encrypted_record);
}
