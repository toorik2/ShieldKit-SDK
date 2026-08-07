//! Native mirror of the frozen direct-V2 address, note, and encrypted-record
//! algorithms. Field and point encodings are wire-compatible with the
//! JavaScript implementation; no JavaScript runtime is used here.

use super::{
    BN254_FR_MODULUS, BabyJubPoint, CodecError, DirectV2Address, array16, babyjub_in_subgroup,
    babyjub_mul, babyjub_subgroup_order, bn254_modulus, canonical_fr, derive_address_authority,
    fr_from_biguint, fr_to_bytes, is_supported_network_id, unpack_babyjub_point,
};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use num_traits::Zero;
use rand_core::{CryptoRng, RngCore};

pub const DIRECT_V2_DENOMINATION_SATS: u64 = 10_000_000;
pub const DIRECT_V2_MAX_ACTION_SEQUENCE_EXCLUSIVE: u64 = 1_u64 << 33;

const DOMAIN_RHO: [u8; 32] = [
    0x0d, 0x16, 0x6c, 0x9d, 0x3f, 0x0e, 0x89, 0x1e, 0x85, 0xbb, 0x4a, 0x50, 0x2a, 0x6e, 0xc7, 0x30,
    0x39, 0x38, 0xd7, 0xbf, 0xc5, 0x6f, 0x1b, 0x6e, 0x6e, 0x44, 0x3f, 0xa8, 0x79, 0x3f, 0x8a, 0x82,
];
const DOMAIN_NOTE: [u8; 32] = [
    0x19, 0x4f, 0xd6, 0x68, 0x37, 0xe1, 0x46, 0xa0, 0xa8, 0xdd, 0xdf, 0xcc, 0x30, 0x9e, 0xb8, 0xbc,
    0x1a, 0x51, 0xde, 0xb3, 0x19, 0x24, 0xe0, 0x89, 0xb8, 0x96, 0x0a, 0xe1, 0x02, 0xc7, 0xc3, 0x49,
];
const DOMAIN_NULLIFIER: [u8; 32] = [
    0x23, 0x35, 0x88, 0x47, 0xff, 0xca, 0x53, 0x91, 0xad, 0x47, 0x1e, 0xf3, 0x21, 0xc1, 0x20, 0x99,
    0x07, 0x3b, 0xff, 0x61, 0x45, 0xa8, 0x67, 0xd1, 0x47, 0x00, 0xe8, 0xe9, 0x76, 0x37, 0x74, 0x60,
];
const DOMAIN_RECORD_MASK_RHO: [u8; 32] = [
    0x0d, 0xde, 0xf2, 0x2b, 0x3c, 0x03, 0x78, 0x81, 0x45, 0xc0, 0xae, 0xd1, 0xbf, 0xba, 0x5a, 0x21,
    0x1f, 0x13, 0x46, 0x6c, 0x81, 0x3c, 0x0a, 0x5d, 0x9e, 0xd2, 0xe9, 0x2a, 0xb1, 0x73, 0xf9, 0x66,
];
const DOMAIN_RECORD_MASK_R: [u8; 32] = [
    0x1a, 0xf2, 0x4b, 0xc8, 0xa8, 0x5a, 0xa4, 0xb0, 0x53, 0x69, 0x75, 0x6d, 0x4f, 0x60, 0x84, 0x3f,
    0xf6, 0xdc, 0x26, 0xf8, 0x86, 0x99, 0x9d, 0x21, 0x5e, 0xd6, 0x1e, 0x38, 0xa4, 0xae, 0x2d, 0xb0,
];
const DOMAIN_RECORD_TAG: [u8; 32] = [
    0x03, 0xdb, 0x9f, 0x4b, 0xba, 0xe2, 0x4d, 0xe0, 0xb9, 0x64, 0x66, 0x00, 0x16, 0x41, 0xdc, 0x57,
    0x53, 0x65, 0x1f, 0xea, 0xa5, 0x5a, 0x85, 0x41, 0xed, 0xed, 0xbc, 0xaf, 0x2b, 0xb2, 0xda, 0x7e,
];
const DOMAIN_NOTE_LEAF: [u8; 32] = [
    0x07, 0x65, 0xf4, 0x93, 0xbd, 0x37, 0x45, 0x85, 0xf9, 0xab, 0x5c, 0x4a, 0x1e, 0xfe, 0x55, 0xf4,
    0xd4, 0x00, 0xa1, 0xbc, 0x1c, 0x87, 0x65, 0x06, 0xef, 0x8c, 0x76, 0x44, 0x14, 0x5f, 0x37, 0x0a,
];
const BABYJUB_SUBGROUP_ORDER_BYTES: [u8; 32] = [
    0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b,
    0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2Account {
    /// Validated public recipient data.
    pub address: DirectV2Address,
    /// Nonzero canonical BabyJub prime-subgroup scalar.
    pub spend_secret: [u8; 32],
    /// Nonzero canonical BabyJub prime-subgroup scalar.
    pub incoming_view_secret: [u8; 32],
}

impl DirectV2Account {
    pub fn validate(&self) -> Result<(), CodecError> {
        self.address.validate()?;
        let spend_secret = babyjub_scalar(&self.spend_secret, "spend secret")?;
        let incoming_view_secret =
            babyjub_scalar(&self.incoming_view_secret, "incoming view secret")?;
        let modulus = bn254_modulus();
        let base = babyjub_base8();
        let spend_public = babyjub_mul(&base, &spend_secret, &modulus)
            .ok_or(CodecError::AddressInvariant("spend key multiplication"))?;
        let incoming_view_public = babyjub_mul(&base, &incoming_view_secret, &modulus).ok_or(
            CodecError::AddressInvariant("incoming view key multiplication"),
        )?;
        if pack_babyjub_point(&spend_public)? != self.address.spend_public_key
            || pack_babyjub_point(&incoming_view_public)? != self.address.incoming_view_public_key
        {
            return Err(CodecError::AccountMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One fresh output's three rejection-sampled values.
///
/// A tuple must never be reused for another output. Prefer
/// [`construct_direct_v2_output`], which samples internally from a caller-owned
/// `CryptoRng`.
pub struct DirectV2OutputRandomness {
    pub rho_blind: [u8; 32],
    pub r: [u8; 32],
    pub ephemeral_scalar: [u8; 32],
}

impl DirectV2OutputRandomness {
    pub fn validate(&self) -> Result<(), CodecError> {
        nonzero_fr(&self.rho_blind, "rho blind")?;
        nonzero_fr(&self.r, "note randomness")?;
        babyjub_scalar(&self.ephemeral_scalar, "ephemeral scalar")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2OutputPublic {
    pub note_commitment: [u8; 32],
    pub output_note_leaf: [u8; 32],
    pub encrypted_record: [u8; 128],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2OutputWitness {
    pub authority: [u8; 32],
    pub spend_public_key: [u8; 32],
    pub incoming_view_public_key: [u8; 32],
    pub rho: [u8; 32],
    pub rho_blind: [u8; 32],
    pub r: [u8; 32],
    pub ephemeral_scalar: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2ConstructedOutput {
    pub public: DirectV2OutputPublic,
    pub witness: DirectV2OutputWitness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredDirectV2Output {
    pub authority: [u8; 32],
    pub rho: [u8; 32],
    pub r: [u8; 32],
    pub note_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub output_note_leaf: [u8; 32],
    pub encrypted_record: [u8; 128],
}

#[derive(Clone, Debug)]
struct DecodedEncryptedRecord {
    bytes: [u8; 128],
    ephemeral_point: BabyJubPoint,
    encrypted_rho: Fr,
    encrypted_r: Fr,
    tag: Fr,
}

pub fn derive_direct_v2_address(
    network_id: u8,
    profile_id: [u8; 32],
    instance_id: [u8; 32],
    spend_secret: &[u8; 32],
    incoming_view_secret: &[u8; 32],
) -> Result<DirectV2Address, CodecError> {
    if !is_supported_network_id(network_id) {
        return Err(CodecError::Network(network_id));
    }
    let spend_secret = babyjub_scalar(spend_secret, "spend secret")?;
    let incoming_view_secret = babyjub_scalar(incoming_view_secret, "incoming view secret")?;
    let modulus = bn254_modulus();
    let base = babyjub_base8();
    let spend_public = babyjub_mul(&base, &spend_secret, &modulus)
        .ok_or(CodecError::AddressInvariant("spend key multiplication"))?;
    let incoming_view_public = babyjub_mul(&base, &incoming_view_secret, &modulus).ok_or(
        CodecError::AddressInvariant("incoming view key multiplication"),
    )?;
    let address = DirectV2Address {
        network_id,
        profile_id,
        instance_id,
        spend_public_key: pack_babyjub_point(&spend_public)?,
        incoming_view_public_key: pack_babyjub_point(&incoming_view_public)?,
        authority: derive_address_authority(
            &profile_id,
            &instance_id,
            &spend_public,
            &incoming_view_public,
        )?,
    };
    address.validate()?;
    Ok(address)
}

pub fn derive_direct_v2_rho(
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    post_action_sequence: u64,
    rho_blind: &[u8; 32],
) -> Result<[u8; 32], CodecError> {
    validate_sequence(post_action_sequence)?;
    let mut inputs = crypto_context(profile_id, instance_id).to_vec();
    inputs.push(Fr::from(post_action_sequence));
    inputs.push(nonzero_fr(rho_blind, "rho blind")?);
    poseidon_hash(&DOMAIN_RHO, &inputs)
}

pub fn derive_direct_v2_note_commitment(
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    authority: &[u8; 32],
    rho: &[u8; 32],
    r: &[u8; 32],
) -> Result<[u8; 32], CodecError> {
    let mut inputs = crypto_context(profile_id, instance_id).to_vec();
    inputs.push(Fr::from(DIRECT_V2_DENOMINATION_SATS));
    inputs.push(canonical_field(authority, "authority")?);
    inputs.push(canonical_field(rho, "rho")?);
    inputs.push(nonzero_fr(r, "note randomness")?);
    poseidon_hash(&DOMAIN_NOTE, &inputs)
}

pub fn derive_direct_v2_nullifier(
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    spend_secret: &[u8; 32],
    rho: &[u8; 32],
    note_commitment: &[u8; 32],
) -> Result<[u8; 32], CodecError> {
    let mut inputs = crypto_context(profile_id, instance_id).to_vec();
    inputs.push(fr_from_biguint(&babyjub_scalar(
        spend_secret,
        "spend secret",
    )?)?);
    inputs.push(canonical_field(rho, "rho")?);
    inputs.push(canonical_field(note_commitment, "note commitment")?);
    poseidon_hash(&DOMAIN_NULLIFIER, &inputs)
}

pub fn hash_direct_v2_output_note_leaf(
    note_commitment: &[u8; 32],
    record_tag: &[u8; 32],
) -> Result<[u8; 32], CodecError> {
    poseidon_hash(
        &DOMAIN_NOTE_LEAF,
        &[
            canonical_field(note_commitment, "note commitment")?,
            canonical_field(record_tag, "record tag")?,
        ],
    )
}

/// Run the same three independent, 1024-attempt rejection samplers as the
/// frozen JavaScript constructor.
pub fn sample_direct_v2_output_randomness<R>(
    rng: &mut R,
) -> Result<DirectV2OutputRandomness, CodecError>
where
    R: RngCore + CryptoRng,
{
    Ok(DirectV2OutputRandomness {
        rho_blind: sample_nonzero_below(rng, &BN254_FR_MODULUS, "canonical rho blind")?,
        r: sample_nonzero_below(rng, &BN254_FR_MODULUS, "canonical note randomness")?,
        ephemeral_scalar: sample_nonzero_below(
            rng,
            &BABYJUB_SUBGROUP_ORDER_BYTES,
            "canonical BabyJub scalar",
        )?,
    })
}

/// Construct and authenticate one output using only public address data and
/// fresh samples from a caller-owned cryptographic RNG.
pub fn construct_direct_v2_output<R>(
    address: &DirectV2Address,
    post_action_sequence: u64,
    rng: &mut R,
) -> Result<DirectV2ConstructedOutput, CodecError>
where
    R: RngCore + CryptoRng,
{
    address.validate()?;
    let randomness = sample_direct_v2_output_randomness(rng)?;
    construct_direct_v2_output_from_randomness(address, post_action_sequence, &randomness)
}

fn construct_direct_v2_output_from_randomness(
    address: &DirectV2Address,
    post_action_sequence: u64,
    randomness: &DirectV2OutputRandomness,
) -> Result<DirectV2ConstructedOutput, CodecError> {
    address.validate()?;
    validate_sequence(post_action_sequence)?;
    randomness.validate()?;

    let rho = derive_direct_v2_rho(
        &address.profile_id,
        &address.instance_id,
        post_action_sequence,
        &randomness.rho_blind,
    )?;
    let note_commitment = derive_direct_v2_note_commitment(
        &address.profile_id,
        &address.instance_id,
        &address.authority,
        &rho,
        &randomness.r,
    )?;
    let incoming_view_point = unpack_babyjub_point(&address.incoming_view_public_key)?;
    let ephemeral_scalar = babyjub_scalar(&randomness.ephemeral_scalar, "ephemeral scalar")?;
    let modulus = bn254_modulus();
    let ephemeral_point = babyjub_mul(&babyjub_base8(), &ephemeral_scalar, &modulus).ok_or(
        CodecError::RecordInvariant("ephemeral point multiplication"),
    )?;
    let shared_point = babyjub_mul(&incoming_view_point, &ephemeral_scalar, &modulus)
        .ok_or(CodecError::RecordInvariant("ECDH point multiplication"))?;
    let (mask_rho, mask_r) = derive_masks(
        &address.profile_id,
        &address.instance_id,
        &shared_point,
        &ephemeral_point,
    )?;
    let encrypted_rho = canonical_field(&rho, "rho")? + mask_rho;
    let encrypted_r = canonical_field(&randomness.r, "note randomness")? + mask_r;
    let tag = derive_record_tag(
        &address.profile_id,
        &address.instance_id,
        &shared_point,
        &ephemeral_point,
        &canonical_field(&note_commitment, "note commitment")?,
        &encrypted_rho,
        &encrypted_r,
    )?;
    let encrypted_record =
        encode_encrypted_record(&ephemeral_point, &encrypted_rho, &encrypted_r, &tag)?;
    let tag_bytes = fr_to_bytes(&tag)?;
    let output_note_leaf = hash_direct_v2_output_note_leaf(&note_commitment, &tag_bytes)?;

    Ok(DirectV2ConstructedOutput {
        public: DirectV2OutputPublic {
            note_commitment,
            output_note_leaf,
            encrypted_record,
        },
        witness: DirectV2OutputWitness {
            authority: address.authority,
            spend_public_key: address.spend_public_key,
            incoming_view_public_key: address.incoming_view_public_key,
            rho,
            rho_blind: randomness.rho_blind,
            r: randomness.r,
            ephemeral_scalar: randomness.ephemeral_scalar,
        },
    })
}

/// Recover and authenticate one output. Account-key binding, the record tag,
/// and the public output leaf must all agree.
pub fn recover_direct_v2_output(
    account: &DirectV2Account,
    output_note_leaf: &[u8; 32],
    encrypted_record: &[u8],
) -> Result<RecoveredDirectV2Output, CodecError> {
    account.validate()?;
    canonical_fr(output_note_leaf, "output note leaf")?;
    let decoded = decode_encrypted_record(encrypted_record)?;
    let incoming_view_secret =
        babyjub_scalar(&account.incoming_view_secret, "incoming view secret")?;
    let modulus = bn254_modulus();
    let shared_point = babyjub_mul(&decoded.ephemeral_point, &incoming_view_secret, &modulus)
        .ok_or(CodecError::RecordInvariant("ECDH point multiplication"))?;
    let (mask_rho, mask_r) = derive_masks(
        &account.address.profile_id,
        &account.address.instance_id,
        &shared_point,
        &decoded.ephemeral_point,
    )?;
    let rho = decoded.encrypted_rho - mask_rho;
    let r = decoded.encrypted_r - mask_r;
    if r.is_zero() {
        return Err(CodecError::RecordInvariant(
            "recovered note randomness is zero",
        ));
    }
    let rho_bytes = fr_to_bytes(&rho)?;
    let r_bytes = fr_to_bytes(&r)?;
    let note_commitment = derive_direct_v2_note_commitment(
        &account.address.profile_id,
        &account.address.instance_id,
        &account.address.authority,
        &rho_bytes,
        &r_bytes,
    )?;
    let expected_tag = derive_record_tag(
        &account.address.profile_id,
        &account.address.instance_id,
        &shared_point,
        &decoded.ephemeral_point,
        &canonical_field(&note_commitment, "note commitment")?,
        &decoded.encrypted_rho,
        &decoded.encrypted_r,
    )?;
    if expected_tag != decoded.tag {
        return Err(CodecError::RecordAuthenticationFailed);
    }
    let tag_bytes = fr_to_bytes(&decoded.tag)?;
    let actual_leaf = hash_direct_v2_output_note_leaf(&note_commitment, &tag_bytes)?;
    if &actual_leaf != output_note_leaf {
        return Err(CodecError::OutputLeafMismatch);
    }
    let nullifier = derive_direct_v2_nullifier(
        &account.address.profile_id,
        &account.address.instance_id,
        &account.spend_secret,
        &rho_bytes,
        &note_commitment,
    )?;
    Ok(RecoveredDirectV2Output {
        authority: account.address.authority,
        rho: rho_bytes,
        r: r_bytes,
        note_commitment,
        nullifier,
        output_note_leaf: actual_leaf,
        encrypted_record: decoded.bytes,
    })
}

fn validate_sequence(post_action_sequence: u64) -> Result<(), CodecError> {
    if post_action_sequence == 0 || post_action_sequence >= DIRECT_V2_MAX_ACTION_SEQUENCE_EXCLUSIVE
    {
        return Err(CodecError::SequenceInvariant);
    }
    Ok(())
}

fn sample_nonzero_below<R>(
    rng: &mut R,
    exclusive_upper_bound: &[u8; 32],
    label: &'static str,
) -> Result<[u8; 32], CodecError>
where
    R: RngCore + CryptoRng,
{
    for _ in 0..1024 {
        let mut candidate = [0_u8; 32];
        rng.try_fill_bytes(&mut candidate)
            .map_err(|_| CodecError::RandomnessFailure("random-byte source returned an error"))?;
        if candidate != [0_u8; 32] && &candidate < exclusive_upper_bound {
            return Ok(candidate);
        }
    }
    Err(CodecError::RandomnessFailure(label))
}

fn babyjub_scalar(value: &[u8; 32], label: &'static str) -> Result<BigUint, CodecError> {
    if value >= &BN254_FR_MODULUS {
        return Err(CodecError::NoncanonicalFr(label));
    }
    let scalar = BigUint::from_bytes_be(value);
    if scalar.is_zero() || scalar >= babyjub_subgroup_order() {
        return Err(CodecError::ScalarInvariant(label));
    }
    Ok(scalar)
}

fn nonzero_fr(value: &[u8; 32], label: &'static str) -> Result<Fr, CodecError> {
    let value = canonical_field(value, label)?;
    if value.is_zero() {
        return Err(CodecError::ScalarInvariant(label));
    }
    Ok(value)
}

fn canonical_field(value: &[u8; 32], label: &'static str) -> Result<Fr, CodecError> {
    canonical_fr(value, label)?;
    Ok(Fr::from_be_bytes_mod_order(value))
}

fn crypto_context(profile_id: &[u8; 32], instance_id: &[u8; 32]) -> [Fr; 4] {
    [
        Fr::from(u128::from_be_bytes(array16(&profile_id[..16]))),
        Fr::from(u128::from_be_bytes(array16(&profile_id[16..]))),
        Fr::from(u128::from_be_bytes(array16(&instance_id[..16]))),
        Fr::from(u128::from_be_bytes(array16(&instance_id[16..]))),
    ]
}

fn poseidon_hash(domain: &[u8; 32], inputs: &[Fr]) -> Result<[u8; 32], CodecError> {
    let mut all_inputs = Vec::with_capacity(inputs.len() + 1);
    all_inputs.push(canonical_field(domain, "domain separator")?);
    all_inputs.extend_from_slice(inputs);
    let mut poseidon = Poseidon::<Fr>::new_circom(all_inputs.len())
        .map_err(|_| CodecError::PoseidonInvariant("parameters"))?;
    let result = poseidon
        .hash(&all_inputs)
        .map_err(|_| CodecError::PoseidonInvariant("hash"))?;
    fr_to_bytes(&result)
}

fn babyjub_base8() -> BabyJubPoint {
    BabyJubPoint {
        x: BigUint::parse_bytes(
            b"5299619240641551281634865583518297030282874472190772894086521144482721001553",
            10,
        )
        .expect("fixed BabyJubJub Base8 x"),
        y: BigUint::parse_bytes(
            b"16950150798460657717958625567821834550301663161624707787222815936182638968203",
            10,
        )
        .expect("fixed BabyJubJub Base8 y"),
    }
}

fn pack_babyjub_point(point: &BabyJubPoint) -> Result<[u8; 32], CodecError> {
    let modulus = bn254_modulus();
    if !babyjub_in_subgroup(point, &modulus) {
        return Err(CodecError::AddressInvariant(
            "point is not a nonidentity prime-subgroup point",
        ));
    }
    let y = point.y.to_bytes_le();
    if y.len() > 32 {
        return Err(CodecError::AddressInvariant("point encoding width"));
    }
    let mut encoded = [0_u8; 32];
    encoded[..y.len()].copy_from_slice(&y);
    if point.x > ((&modulus - BigUint::from(1_u8)) >> 1_u8) {
        encoded[31] |= 0x80;
    }
    Ok(encoded)
}

fn derive_masks(
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    shared_point: &BabyJubPoint,
    ephemeral_point: &BabyJubPoint,
) -> Result<(Fr, Fr), CodecError> {
    let modulus = bn254_modulus();
    if !babyjub_in_subgroup(shared_point, &modulus)
        || !babyjub_in_subgroup(ephemeral_point, &modulus)
    {
        return Err(CodecError::RecordInvariant(
            "ECDH points must be nonidentity prime-subgroup points",
        ));
    }
    let mut inputs = crypto_context(profile_id, instance_id).to_vec();
    inputs.extend([
        fr_from_biguint(&shared_point.x)?,
        fr_from_biguint(&shared_point.y)?,
        fr_from_biguint(&ephemeral_point.x)?,
        fr_from_biguint(&ephemeral_point.y)?,
    ]);
    Ok((
        canonical_field(
            &poseidon_hash(&DOMAIN_RECORD_MASK_RHO, &inputs)?,
            "rho mask",
        )?,
        canonical_field(
            &poseidon_hash(&DOMAIN_RECORD_MASK_R, &inputs)?,
            "randomness mask",
        )?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn derive_record_tag(
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    shared_point: &BabyJubPoint,
    ephemeral_point: &BabyJubPoint,
    note_commitment: &Fr,
    encrypted_rho: &Fr,
    encrypted_r: &Fr,
) -> Result<Fr, CodecError> {
    let mut inputs = crypto_context(profile_id, instance_id).to_vec();
    inputs.extend([
        fr_from_biguint(&shared_point.x)?,
        fr_from_biguint(&shared_point.y)?,
        fr_from_biguint(&ephemeral_point.x)?,
        fr_from_biguint(&ephemeral_point.y)?,
        *note_commitment,
        *encrypted_rho,
        *encrypted_r,
    ]);
    canonical_field(&poseidon_hash(&DOMAIN_RECORD_TAG, &inputs)?, "record tag")
}

fn encode_encrypted_record(
    ephemeral_point: &BabyJubPoint,
    encrypted_rho: &Fr,
    encrypted_r: &Fr,
    tag: &Fr,
) -> Result<[u8; 128], CodecError> {
    let mut record = [0_u8; 128];
    record[..32].copy_from_slice(&pack_babyjub_point(ephemeral_point)?);
    record[32..64].copy_from_slice(&fr_to_bytes(encrypted_rho)?);
    record[64..96].copy_from_slice(&fr_to_bytes(encrypted_r)?);
    record[96..].copy_from_slice(&fr_to_bytes(tag)?);
    Ok(record)
}

fn decode_encrypted_record(record: &[u8]) -> Result<DecodedEncryptedRecord, CodecError> {
    if record.len() != 128 {
        return Err(CodecError::Length {
            label: "encrypted record",
            expected: 128,
            actual: record.len(),
        });
    }
    let mut bytes = [0_u8; 128];
    bytes.copy_from_slice(record);
    let mut encoded_point = [0_u8; 32];
    encoded_point.copy_from_slice(&record[..32]);
    let ephemeral_point = unpack_babyjub_point(&encoded_point)?;
    let mut encrypted_rho = [0_u8; 32];
    encrypted_rho.copy_from_slice(&record[32..64]);
    let mut encrypted_r = [0_u8; 32];
    encrypted_r.copy_from_slice(&record[64..96]);
    let mut tag = [0_u8; 32];
    tag.copy_from_slice(&record[96..]);
    Ok(DecodedEncryptedRecord {
        bytes,
        ephemeral_point,
        encrypted_rho: canonical_field(&encrypted_rho, "record encrypted rho")?,
        encrypted_r: canonical_field(&encrypted_r, "record encrypted randomness")?,
        tag: canonical_field(&tag, "record tag")?,
    })
}
