#![forbid(unsafe_code)]

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use core::fmt;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

mod notes;

pub use notes::{
    DIRECT_V2_DENOMINATION_SATS, DIRECT_V2_MAX_ACTION_SEQUENCE_EXCLUSIVE, DirectV2Account,
    DirectV2ConstructedOutput, DirectV2OutputPublic, DirectV2OutputRandomness,
    DirectV2OutputWitness, RecoveredDirectV2Output, construct_direct_v2_output,
    derive_direct_v2_address, derive_direct_v2_note_commitment, derive_direct_v2_nullifier,
    derive_direct_v2_rho, hash_direct_v2_output_note_leaf, recover_direct_v2_output,
    sample_direct_v2_output_randomness,
};

pub const STATE_BYTES: usize = 128;
pub const ACTION_PACKET_BYTES: usize = 552;
pub const ENCRYPTED_RECORD_BYTES: usize = 128;
pub const DIRECT_V2_ADDRESS_BYTES: usize = 168;
pub const DIRECT_V2_CONTEXT_HEADER_BYTES: usize = 100;
pub const DIRECT_V2_CONTEXT_INPUT_BYTES: usize = 116;
pub const DIRECT_V2_CONTEXT_OUTPUT_BYTES: usize = 76;
pub const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;
pub const NETWORK_MAINNET: u8 = 1;
pub const NETWORK_CHIPNET: u8 = 2;
pub const BN254_FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub mod state_offsets {
    pub const MAGIC: usize = 0;
    pub const PROFILE_ID: usize = 4;
    pub const NOTE_ROOT: usize = 36;
    pub const NULLIFIER_ROOT: usize = 68;
    pub const NOTE_COUNT: usize = 100;
    pub const NULLIFIER_COUNT: usize = 104;
    pub const MAXIMUM_LIVE_NOTES: usize = 108;
    pub const RESERVE_SATS: usize = 112;
    pub const ACTION_SEQUENCE: usize = 120;
}

pub mod packet_offsets {
    pub const MAGIC: usize = 0;
    pub const NETWORK_ID: usize = 4;
    pub const KIND: usize = 5;
    pub const FLAGS: usize = 6;
    pub const INSTANCE_ID: usize = 8;
    pub const PRE_STATE: usize = 40;
    pub const POST_STATE: usize = 168;
    pub const PUBLIC_NULLIFIER: usize = 296;
    pub const OUTPUT_NOTE_LEAF: usize = 328;
    pub const ENCRYPTED_RECORD: usize = 360;
    pub const WITHDRAWAL_LOCKING_BYTECODE_HASH: usize = 488;
    pub const TRANSACTION_CONTEXT_HASH: usize = 520;
}

pub mod address_offsets {
    pub const MAGIC: usize = 0;
    pub const NETWORK_ID: usize = 4;
    pub const FLAGS: usize = 5;
    pub const PROFILE_ID: usize = 8;
    pub const INSTANCE_ID: usize = 40;
    pub const SPEND_PUBLIC_KEY: usize = 72;
    pub const INCOMING_VIEW_PUBLIC_KEY: usize = 104;
    pub const AUTHORITY: usize = 136;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    Length {
        label: &'static str,
        expected: usize,
        actual: usize,
    },
    Magic {
        label: &'static str,
    },
    Network(u8),
    Kind(u8),
    Flags(u16),
    NoncanonicalFr(&'static str),
    Denomination,
    StateInvariant(&'static str),
    PacketInvariant(&'static str),
    AddressInvariant(&'static str),
    ScalarInvariant(&'static str),
    SequenceInvariant,
    RecordInvariant(&'static str),
    AccountMismatch,
    RecordAuthenticationFailed,
    OutputLeafMismatch,
    RandomnessFailure(&'static str),
    PoseidonInvariant(&'static str),
    ContextInvariant(&'static str),
    Role(u8),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length {
                label,
                expected,
                actual,
            } => write!(f, "{label} length {actual}, expected {expected}"),
            Self::Magic { label } => write!(f, "invalid {label} magic"),
            Self::Network(value) => write!(f, "unsupported network {value}"),
            Self::Kind(value) => write!(f, "unsupported action kind {value}"),
            Self::Flags(value) => write!(f, "nonzero packet flags {value}"),
            Self::NoncanonicalFr(label) => write!(f, "noncanonical BN254 Fr {label}"),
            Self::Denomination => write!(f, "invalid denomination"),
            Self::StateInvariant(label) => write!(f, "invalid state invariant: {label}"),
            Self::PacketInvariant(label) => write!(f, "invalid packet invariant: {label}"),
            Self::AddressInvariant(label) => write!(f, "invalid address invariant: {label}"),
            Self::ScalarInvariant(label) => write!(f, "invalid scalar invariant: {label}"),
            Self::SequenceInvariant => {
                write!(f, "post action sequence must be between 1 and 2^33-1")
            }
            Self::RecordInvariant(label) => write!(f, "invalid encrypted record: {label}"),
            Self::AccountMismatch => write!(f, "account secrets do not match recipient address"),
            Self::RecordAuthenticationFailed => {
                write!(f, "encrypted record authentication failed")
            }
            Self::OutputLeafMismatch => {
                write!(f, "encrypted record does not match output note leaf")
            }
            Self::RandomnessFailure(label) => write!(f, "CSPRNG failure: {label}"),
            Self::PoseidonInvariant(label) => write!(f, "Poseidon failure: {label}"),
            Self::ContextInvariant(label) => {
                write!(f, "invalid transaction context invariant: {label}")
            }
            Self::Role(value) => write!(f, "unsupported transaction context role {value}"),
        }
    }
}

impl std::error::Error for CodecError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolStateV2 {
    pub profile_id: [u8; 32],
    pub note_root: [u8; 32],
    pub nullifier_root: [u8; 32],
    pub note_count: u32,
    pub nullifier_count: u32,
    pub maximum_live_notes: u32,
    pub reserve_sats: u64,
    pub action_sequence: u64,
}

impl PoolStateV2 {
    pub fn validate(&self, denomination_sats: u64) -> Result<(), CodecError> {
        validate_denomination(denomination_sats)?;
        canonical_fr(&self.note_root, "note root")?;
        canonical_fr(&self.nullifier_root, "nullifier root")?;
        if self.nullifier_count > self.note_count {
            return Err(CodecError::StateInvariant(
                "nullifierCount exceeds noteCount",
            ));
        }
        if self.nullifier_count == u32::MAX {
            return Err(CodecError::StateInvariant(
                "nullifierCount exceeds 0xfffffffe",
            ));
        }
        if self.maximum_live_notes == 0 {
            return Err(CodecError::StateInvariant("maximumLiveNotes is zero"));
        }
        if u64::from(self.maximum_live_notes) > MAX_MONEY_SATS / denomination_sats {
            return Err(CodecError::StateInvariant(
                "maximumLiveNotes exceeds MAX_MONEY",
            ));
        }
        let live_note_count = u64::from(self.note_count - self.nullifier_count);
        if live_note_count > u64::from(self.maximum_live_notes) {
            return Err(CodecError::StateInvariant(
                "liveNoteCount exceeds maximumLiveNotes",
            ));
        }
        let expected_reserve =
            live_note_count
                .checked_mul(denomination_sats)
                .ok_or(CodecError::StateInvariant(
                    "reserve multiplication overflow",
                ))?;
        if self.reserve_sats != expected_reserve {
            return Err(CodecError::StateInvariant("reserveSats mismatch"));
        }
        if self.action_sequence >= (1_u64 << 33) {
            return Err(CodecError::StateInvariant("actionSequence exceeds 2^33"));
        }
        let counter_floor = u64::from(self.note_count.max(self.nullifier_count));
        let counter_ceiling = u64::from(self.note_count) + u64::from(self.nullifier_count);
        if self.action_sequence < counter_floor || self.action_sequence > counter_ceiling {
            return Err(CodecError::StateInvariant("actionSequence counter bounds"));
        }
        Ok(())
    }

    pub fn encode(&self, denomination_sats: u64) -> Result<[u8; STATE_BYTES], CodecError> {
        self.validate(denomination_sats)?;
        let mut bytes = [0_u8; STATE_BYTES];
        bytes[state_offsets::MAGIC..4].copy_from_slice(b"SKS2");
        bytes[state_offsets::PROFILE_ID..36].copy_from_slice(&self.profile_id);
        bytes[state_offsets::NOTE_ROOT..68].copy_from_slice(&self.note_root);
        bytes[state_offsets::NULLIFIER_ROOT..100].copy_from_slice(&self.nullifier_root);
        bytes[state_offsets::NOTE_COUNT..104].copy_from_slice(&self.note_count.to_le_bytes());
        bytes[state_offsets::NULLIFIER_COUNT..108]
            .copy_from_slice(&self.nullifier_count.to_le_bytes());
        bytes[state_offsets::MAXIMUM_LIVE_NOTES..112]
            .copy_from_slice(&self.maximum_live_notes.to_le_bytes());
        bytes[state_offsets::RESERVE_SATS..120].copy_from_slice(&self.reserve_sats.to_le_bytes());
        bytes[state_offsets::ACTION_SEQUENCE..128]
            .copy_from_slice(&self.action_sequence.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], denomination_sats: u64) -> Result<Self, CodecError> {
        if bytes.len() != STATE_BYTES {
            return Err(CodecError::Length {
                label: "state",
                expected: STATE_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes[state_offsets::MAGIC..4] != *b"SKS2" {
            return Err(CodecError::Magic { label: "state" });
        }
        let state = Self {
            profile_id: array32(&bytes[4..36]),
            note_root: array32(&bytes[36..68]),
            nullifier_root: array32(&bytes[68..100]),
            note_count: u32::from_le_bytes(array4(&bytes[100..104])),
            nullifier_count: u32::from_le_bytes(array4(&bytes[104..108])),
            maximum_live_notes: u32::from_le_bytes(array4(&bytes[108..112])),
            reserve_sats: u64::from_le_bytes(array8(&bytes[112..120])),
            action_sequence: u64::from_le_bytes(array8(&bytes[120..128])),
        };
        state.validate(denomination_sats)?;
        Ok(state)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionKindV2 {
    Deposit = 1,
    Transfer = 2,
    Withdrawal = 3,
}

impl TryFrom<u8> for ActionKindV2 {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Deposit),
            2 => Ok(Self::Transfer),
            3 => Ok(Self::Withdrawal),
            _ => Err(CodecError::Kind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectActionPacketV2 {
    pub network_id: u8,
    pub kind: ActionKindV2,
    pub instance_id: [u8; 32],
    pub pre_state: PoolStateV2,
    pub post_state: PoolStateV2,
    pub public_nullifier: [u8; 32],
    pub output_note_leaf: [u8; 32],
    pub encrypted_record: [u8; ENCRYPTED_RECORD_BYTES],
    pub withdrawal_locking_bytecode_hash: [u8; 32],
    pub transaction_context_hash: [u8; 32],
}

impl DirectActionPacketV2 {
    pub fn validate(&self, denomination_sats: u64) -> Result<(), CodecError> {
        if !is_supported_network_id(self.network_id) {
            return Err(CodecError::Network(self.network_id));
        }
        self.pre_state.validate(denomination_sats)?;
        self.post_state.validate(denomination_sats)?;
        canonical_fr(&self.public_nullifier, "public nullifier")?;
        canonical_fr(&self.output_note_leaf, "output note leaf")?;
        if self.pre_state.profile_id != self.post_state.profile_id {
            return Err(CodecError::PacketInvariant("profileId continuity"));
        }
        if self.pre_state.maximum_live_notes != self.post_state.maximum_live_notes {
            return Err(CodecError::PacketInvariant("maximumLiveNotes continuity"));
        }
        let zero32 = [0_u8; 32];
        let zero_record = [0_u8; ENCRYPTED_RECORD_BYTES];
        match self.kind {
            ActionKindV2::Deposit
                if self.public_nullifier != zero32
                    || self.withdrawal_locking_bytecode_hash != zero32 =>
            {
                Err(CodecError::PacketInvariant("deposit inactive fields"))
            }
            ActionKindV2::Transfer if self.withdrawal_locking_bytecode_hash != zero32 => {
                Err(CodecError::PacketInvariant("transfer inactive fields"))
            }
            ActionKindV2::Withdrawal
                if self.output_note_leaf != zero32 || self.encrypted_record != zero_record =>
            {
                Err(CodecError::PacketInvariant("withdrawal inactive fields"))
            }
            _ => Ok(()),
        }
    }

    pub fn encode(&self, denomination_sats: u64) -> Result<[u8; ACTION_PACKET_BYTES], CodecError> {
        self.validate(denomination_sats)?;
        let mut bytes = [0_u8; ACTION_PACKET_BYTES];
        bytes[packet_offsets::MAGIC..4].copy_from_slice(b"SDA2");
        bytes[packet_offsets::NETWORK_ID] = self.network_id;
        bytes[packet_offsets::KIND] = self.kind as u8;
        bytes[packet_offsets::FLAGS..8].copy_from_slice(&0_u16.to_le_bytes());
        bytes[packet_offsets::INSTANCE_ID..40].copy_from_slice(&self.instance_id);
        bytes[packet_offsets::PRE_STATE..168]
            .copy_from_slice(&self.pre_state.encode(denomination_sats)?);
        bytes[packet_offsets::POST_STATE..296]
            .copy_from_slice(&self.post_state.encode(denomination_sats)?);
        bytes[packet_offsets::PUBLIC_NULLIFIER..328].copy_from_slice(&self.public_nullifier);
        bytes[packet_offsets::OUTPUT_NOTE_LEAF..360].copy_from_slice(&self.output_note_leaf);
        bytes[packet_offsets::ENCRYPTED_RECORD..488].copy_from_slice(&self.encrypted_record);
        bytes[packet_offsets::WITHDRAWAL_LOCKING_BYTECODE_HASH..520]
            .copy_from_slice(&self.withdrawal_locking_bytecode_hash);
        bytes[packet_offsets::TRANSACTION_CONTEXT_HASH..552]
            .copy_from_slice(&self.transaction_context_hash);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], denomination_sats: u64) -> Result<Self, CodecError> {
        if bytes.len() != ACTION_PACKET_BYTES {
            return Err(CodecError::Length {
                label: "packet",
                expected: ACTION_PACKET_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes[packet_offsets::MAGIC..4] != *b"SDA2" {
            return Err(CodecError::Magic { label: "packet" });
        }
        if !is_supported_network_id(bytes[packet_offsets::NETWORK_ID]) {
            return Err(CodecError::Network(bytes[packet_offsets::NETWORK_ID]));
        }
        let flags = u16::from_le_bytes(array2(&bytes[packet_offsets::FLAGS..8]));
        if flags != 0 {
            return Err(CodecError::Flags(flags));
        }
        let packet = Self {
            network_id: bytes[packet_offsets::NETWORK_ID],
            kind: ActionKindV2::try_from(bytes[packet_offsets::KIND])?,
            instance_id: array32(&bytes[8..40]),
            pre_state: PoolStateV2::decode(&bytes[40..168], denomination_sats)?,
            post_state: PoolStateV2::decode(&bytes[168..296], denomination_sats)?,
            public_nullifier: array32(&bytes[296..328]),
            output_note_leaf: array32(&bytes[328..360]),
            encrypted_record: array128(&bytes[360..488]),
            withdrawal_locking_bytecode_hash: array32(&bytes[488..520]),
            transaction_context_hash: array32(&bytes[520..552]),
        };
        packet.validate(denomination_sats)?;
        Ok(packet)
    }

    pub fn sha256(&self, denomination_sats: u64) -> Result<[u8; 32], CodecError> {
        let bytes = self.encode(denomination_sats)?;
        Ok(Sha256::digest(bytes).into())
    }

    pub fn public_input_limbs(&self, denomination_sats: u64) -> Result<(u128, u128), CodecError> {
        let digest = self.sha256(denomination_sats)?;
        let mut first = [0_u8; 16];
        let mut second = [0_u8; 16];
        first.copy_from_slice(&digest[..16]);
        second.copy_from_slice(&digest[16..]);
        Ok((u128::from_be_bytes(first), u128::from_be_bytes(second)))
    }
}

fn validate_denomination(denomination_sats: u64) -> Result<(), CodecError> {
    if denomination_sats == 0 || denomination_sats > MAX_MONEY_SATS {
        return Err(CodecError::Denomination);
    }
    Ok(())
}

const fn is_supported_network_id(network_id: u8) -> bool {
    network_id == NETWORK_MAINNET || network_id == NETWORK_CHIPNET
}

fn canonical_fr(value: &[u8; 32], label: &'static str) -> Result<(), CodecError> {
    if value >= &BN254_FR_MODULUS {
        return Err(CodecError::NoncanonicalFr(label));
    }
    Ok(())
}

fn array2(bytes: &[u8]) -> [u8; 2] {
    let mut value = [0_u8; 2];
    value.copy_from_slice(bytes);
    value
}

fn array4(bytes: &[u8]) -> [u8; 4] {
    let mut value = [0_u8; 4];
    value.copy_from_slice(bytes);
    value
}

fn array8(bytes: &[u8]) -> [u8; 8] {
    let mut value = [0_u8; 8];
    value.copy_from_slice(bytes);
    value
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value.copy_from_slice(bytes);
    value
}

fn array128(bytes: &[u8]) -> [u8; 128] {
    let mut value = [0_u8; 128];
    value.copy_from_slice(bytes);
    value
}

/// Exact 168-byte `SKA2` recipient address. The two public keys use
/// circomlib's compressed BabyJubJub representation (little-endian y with the
/// x-sign bit in bit 7 of the final byte).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2Address {
    pub network_id: u8,
    pub profile_id: [u8; 32],
    pub instance_id: [u8; 32],
    pub spend_public_key: [u8; 32],
    pub incoming_view_public_key: [u8; 32],
    pub authority: [u8; 32],
}

impl DirectV2Address {
    pub fn validate(&self) -> Result<(), CodecError> {
        if !is_supported_network_id(self.network_id) {
            return Err(CodecError::Network(self.network_id));
        }
        let spend = unpack_babyjub_point(&self.spend_public_key)?;
        let incoming = unpack_babyjub_point(&self.incoming_view_public_key)?;
        canonical_fr(&self.authority, "address authority")?;
        let expected =
            derive_address_authority(&self.profile_id, &self.instance_id, &spend, &incoming)?;
        if self.authority != expected {
            return Err(CodecError::AddressInvariant(
                "authority does not bind public keys",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; DIRECT_V2_ADDRESS_BYTES], CodecError> {
        self.validate()?;
        let mut bytes = [0_u8; DIRECT_V2_ADDRESS_BYTES];
        bytes[address_offsets::MAGIC..4].copy_from_slice(b"SKA2");
        bytes[address_offsets::NETWORK_ID] = self.network_id;
        bytes[address_offsets::PROFILE_ID..40].copy_from_slice(&self.profile_id);
        bytes[address_offsets::INSTANCE_ID..72].copy_from_slice(&self.instance_id);
        bytes[address_offsets::SPEND_PUBLIC_KEY..104].copy_from_slice(&self.spend_public_key);
        bytes[address_offsets::INCOMING_VIEW_PUBLIC_KEY..136]
            .copy_from_slice(&self.incoming_view_public_key);
        bytes[address_offsets::AUTHORITY..168].copy_from_slice(&self.authority);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != DIRECT_V2_ADDRESS_BYTES {
            return Err(CodecError::Length {
                label: "address",
                expected: DIRECT_V2_ADDRESS_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes[address_offsets::MAGIC..4] != *b"SKA2" {
            return Err(CodecError::Magic { label: "address" });
        }
        if !is_supported_network_id(bytes[address_offsets::NETWORK_ID]) {
            return Err(CodecError::Network(bytes[address_offsets::NETWORK_ID]));
        }
        if bytes[address_offsets::FLAGS..8] != [0_u8; 3] {
            return Err(CodecError::AddressInvariant("flags must be zero"));
        }
        let address = Self {
            network_id: bytes[address_offsets::NETWORK_ID],
            profile_id: array32(&bytes[8..40]),
            instance_id: array32(&bytes[40..72]),
            spend_public_key: array32(&bytes[72..104]),
            incoming_view_public_key: array32(&bytes[104..136]),
            authority: array32(&bytes[136..168]),
        };
        address.validate()?;
        Ok(address)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DirectV2RoleKind {
    Verifier = 1,
    Binding = 2,
    State = 3,
    Funding = 4,
    Withdrawal = 5,
    Change = 6,
}

impl TryFrom<u8> for DirectV2RoleKind {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Verifier),
            2 => Ok(Self::Binding),
            3 => Ok(Self::State),
            4 => Ok(Self::Funding),
            5 => Ok(Self::Withdrawal),
            6 => Ok(Self::Change),
            _ => Err(CodecError::Role(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectV2Role {
    pub kind: DirectV2RoleKind,
    pub ordinal: u8,
}

impl DirectV2Role {
    fn validate(self) -> Result<(), CodecError> {
        if self.kind != DirectV2RoleKind::Verifier && self.ordinal != 0 {
            return Err(CodecError::ContextInvariant(
                "non-verifier role ordinal must be zero",
            ));
        }
        Ok(())
    }

    fn encode(self) -> Result<[u8; 4], CodecError> {
        self.validate()?;
        Ok([self.kind as u8, self.ordinal, 0, 0])
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != 4 {
            return Err(CodecError::Length {
                label: "role",
                expected: 4,
                actual: bytes.len(),
            });
        }
        if bytes[2..4] != [0_u8; 2] {
            return Err(CodecError::ContextInvariant(
                "role reserved bytes must be zero",
            ));
        }
        let role = Self {
            kind: DirectV2RoleKind::try_from(bytes[0])?,
            ordinal: bytes[1],
        };
        role.validate()?;
        Ok(role)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2ContextInput {
    pub role: DirectV2Role,
    /// BCH wire-order transaction hash, exactly as serialized in an outpoint.
    pub outpoint_transaction_hash: [u8; 32],
    pub outpoint_index: u32,
    pub sequence: u32,
    pub value_sats: u64,
    pub locking_bytecode: Vec<u8>,
    pub token_prefix: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2ContextOutput {
    pub role: DirectV2Role,
    pub value_sats: u64,
    pub locking_bytecode: Vec<u8>,
    pub token_prefix: Vec<u8>,
}

/// The preimage form used by an assembler. `SDC2` intentionally commits only
/// to SHA-256 digests of bytecode and token-prefix vectors, so decoding the
/// wire ABI yields [`CommittedDirectV2TransactionContext`] rather than this
/// preimage form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectV2TransactionContext {
    pub network_id: u8,
    pub kind: ActionKindV2,
    pub profile_id: [u8; 32],
    pub instance_id: [u8; 32],
    pub transaction_version: u32,
    pub locktime: u32,
    pub pre_action_sequence: u64,
    pub post_action_sequence: u64,
    pub inputs: Vec<DirectV2ContextInput>,
    pub outputs: Vec<DirectV2ContextOutput>,
}

/// The exact information recoverable from an `SDC2` ABI byte string. Hashes
/// are commitments to the source byte vectors; recovering those vectors is
/// cryptographically and information-theoretically impossible from this ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedDirectV2TransactionContext {
    pub network_id: u8,
    pub kind: ActionKindV2,
    pub profile_id: [u8; 32],
    pub instance_id: [u8; 32],
    pub transaction_version: u32,
    pub locktime: u32,
    pub pre_action_sequence: u64,
    pub post_action_sequence: u64,
    pub inputs: Vec<CommittedDirectV2ContextInput>,
    pub outputs: Vec<CommittedDirectV2ContextOutput>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedDirectV2ContextInput {
    pub role: DirectV2Role,
    pub outpoint_transaction_hash: [u8; 32],
    pub outpoint_index: u32,
    pub sequence: u32,
    pub value_sats: u64,
    pub locking_bytecode_hash: [u8; 32],
    pub token_prefix_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedDirectV2ContextOutput {
    pub role: DirectV2Role,
    pub value_sats: u64,
    pub locking_bytecode_hash: [u8; 32],
    pub token_prefix_hash: [u8; 32],
}

impl DirectV2TransactionContext {
    pub fn validate(&self) -> Result<(), CodecError> {
        validate_context_header(
            self.network_id,
            self.pre_action_sequence,
            self.post_action_sequence,
        )?;
        validate_context_counts(self.inputs.len(), self.outputs.len())?;
        for input in &self.inputs {
            input.role.validate()?;
            validate_context_vector(&input.locking_bytecode)?;
            validate_context_vector(&input.token_prefix)?;
        }
        for output in &self.outputs {
            output.role.validate()?;
            validate_context_vector(&output.locking_bytecode)?;
            validate_context_vector(&output.token_prefix)?;
        }
        Ok(())
    }

    pub fn validate_role_topology(&self, carrier_count: u8) -> Result<(), CodecError> {
        self.validate()?;
        validate_raw_role_topology(self, carrier_count)
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.encode_internal(None)
    }

    pub fn encode_with_carrier_count(&self, carrier_count: u8) -> Result<Vec<u8>, CodecError> {
        self.encode_internal(Some(carrier_count))
    }

    fn encode_internal(&self, carrier_count: Option<u8>) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        if let Some(count) = carrier_count {
            validate_raw_role_topology(self, count)?;
        }
        let mut bytes = encode_context_header(
            self.network_id,
            self.kind,
            &self.profile_id,
            &self.instance_id,
            self.transaction_version,
            self.locktime,
            self.inputs.len(),
            self.outputs.len(),
            self.pre_action_sequence,
            self.post_action_sequence,
        )?;
        for input in &self.inputs {
            bytes.extend_from_slice(&input.role.encode()?);
            bytes.extend_from_slice(&input.outpoint_transaction_hash);
            bytes.extend_from_slice(&input.outpoint_index.to_le_bytes());
            bytes.extend_from_slice(&input.sequence.to_le_bytes());
            bytes.extend_from_slice(&input.value_sats.to_le_bytes());
            bytes.extend_from_slice(&sha256(&input.locking_bytecode));
            bytes.extend_from_slice(&sha256(&input.token_prefix));
        }
        for output in &self.outputs {
            bytes.extend_from_slice(&output.role.encode()?);
            bytes.extend_from_slice(&output.value_sats.to_le_bytes());
            bytes.extend_from_slice(&sha256(&output.locking_bytecode));
            bytes.extend_from_slice(&sha256(&output.token_prefix));
        }
        Ok(bytes)
    }

    pub fn sha256(&self) -> Result<[u8; 32], CodecError> {
        Ok(sha256(&self.encode()?))
    }

    pub fn sha256_with_carrier_count(&self, carrier_count: u8) -> Result<[u8; 32], CodecError> {
        Ok(sha256(&self.encode_with_carrier_count(carrier_count)?))
    }
}

impl CommittedDirectV2TransactionContext {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < DIRECT_V2_CONTEXT_HEADER_BYTES {
            return Err(CodecError::Length {
                label: "transaction context",
                expected: DIRECT_V2_CONTEXT_HEADER_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes[..4] != *b"SDC2" {
            return Err(CodecError::Magic {
                label: "transaction context",
            });
        }
        let network_id = bytes[4];
        let kind = ActionKindV2::try_from(bytes[5])?;
        if bytes[6..8] != [0_u8; 2] {
            return Err(CodecError::ContextInvariant("context flags must be zero"));
        }
        let input_count = usize::from(u16::from_le_bytes(array2(&bytes[80..82])));
        let output_count = usize::from(u16::from_le_bytes(array2(&bytes[82..84])));
        validate_context_header(
            network_id,
            u64::from_le_bytes(array8(&bytes[84..92])),
            u64::from_le_bytes(array8(&bytes[92..100])),
        )?;
        validate_context_counts(input_count, output_count)?;
        let expected = DIRECT_V2_CONTEXT_HEADER_BYTES
            .checked_add(
                input_count
                    .checked_mul(DIRECT_V2_CONTEXT_INPUT_BYTES)
                    .ok_or(CodecError::ContextInvariant("input byte count overflow"))?,
            )
            .and_then(|value| {
                value.checked_add(output_count.checked_mul(DIRECT_V2_CONTEXT_OUTPUT_BYTES)?)
            })
            .ok_or(CodecError::ContextInvariant("context byte count overflow"))?;
        if bytes.len() != expected {
            return Err(CodecError::Length {
                label: "transaction context",
                expected,
                actual: bytes.len(),
            });
        }
        let mut offset = DIRECT_V2_CONTEXT_HEADER_BYTES;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let record = &bytes[offset..offset + DIRECT_V2_CONTEXT_INPUT_BYTES];
            inputs.push(CommittedDirectV2ContextInput {
                role: DirectV2Role::decode(&record[..4])?,
                outpoint_transaction_hash: array32(&record[4..36]),
                outpoint_index: u32::from_le_bytes(array4(&record[36..40])),
                sequence: u32::from_le_bytes(array4(&record[40..44])),
                value_sats: u64::from_le_bytes(array8(&record[44..52])),
                locking_bytecode_hash: array32(&record[52..84]),
                token_prefix_hash: array32(&record[84..116]),
            });
            offset += DIRECT_V2_CONTEXT_INPUT_BYTES;
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let record = &bytes[offset..offset + DIRECT_V2_CONTEXT_OUTPUT_BYTES];
            outputs.push(CommittedDirectV2ContextOutput {
                role: DirectV2Role::decode(&record[..4])?,
                value_sats: u64::from_le_bytes(array8(&record[4..12])),
                locking_bytecode_hash: array32(&record[12..44]),
                token_prefix_hash: array32(&record[44..76]),
            });
            offset += DIRECT_V2_CONTEXT_OUTPUT_BYTES;
        }
        let context = Self {
            network_id,
            kind,
            profile_id: array32(&bytes[8..40]),
            instance_id: array32(&bytes[40..72]),
            transaction_version: u32::from_le_bytes(array4(&bytes[72..76])),
            locktime: u32::from_le_bytes(array4(&bytes[76..80])),
            pre_action_sequence: u64::from_le_bytes(array8(&bytes[84..92])),
            post_action_sequence: u64::from_le_bytes(array8(&bytes[92..100])),
            inputs,
            outputs,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), CodecError> {
        validate_context_header(
            self.network_id,
            self.pre_action_sequence,
            self.post_action_sequence,
        )?;
        validate_context_counts(self.inputs.len(), self.outputs.len())?;
        for input in &self.inputs {
            input.role.validate()?;
        }
        for output in &self.outputs {
            output.role.validate()?;
        }
        Ok(())
    }

    /// Validate the fixed direct-V2 settlement topology from the committed
    /// `SDC2` representation. Unlike [`DirectV2TransactionContext`], this
    /// representation contains only SHA-256 commitments to token prefixes;
    /// consequently a tokenless role is recognized by the canonical
    /// `SHA256("")` commitment and a state role is required to differ from
    /// that commitment. This is deliberately a distinct check from raw-context
    /// validation: it must not pretend to recover unavailable token bytes.
    pub fn validate_role_topology(&self, carrier_count: u8) -> Result<(), CodecError> {
        self.validate()?;
        validate_committed_role_topology(self, carrier_count)
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut bytes = encode_context_header(
            self.network_id,
            self.kind,
            &self.profile_id,
            &self.instance_id,
            self.transaction_version,
            self.locktime,
            self.inputs.len(),
            self.outputs.len(),
            self.pre_action_sequence,
            self.post_action_sequence,
        )?;
        for input in &self.inputs {
            bytes.extend_from_slice(&input.role.encode()?);
            bytes.extend_from_slice(&input.outpoint_transaction_hash);
            bytes.extend_from_slice(&input.outpoint_index.to_le_bytes());
            bytes.extend_from_slice(&input.sequence.to_le_bytes());
            bytes.extend_from_slice(&input.value_sats.to_le_bytes());
            bytes.extend_from_slice(&input.locking_bytecode_hash);
            bytes.extend_from_slice(&input.token_prefix_hash);
        }
        for output in &self.outputs {
            bytes.extend_from_slice(&output.role.encode()?);
            bytes.extend_from_slice(&output.value_sats.to_le_bytes());
            bytes.extend_from_slice(&output.locking_bytecode_hash);
            bytes.extend_from_slice(&output.token_prefix_hash);
        }
        Ok(bytes)
    }

    pub fn sha256(&self) -> Result<[u8; 32], CodecError> {
        Ok(sha256(&self.encode()?))
    }
}

fn validate_context_header(
    network_id: u8,
    pre_action_sequence: u64,
    post_action_sequence: u64,
) -> Result<(), CodecError> {
    if !is_supported_network_id(network_id) {
        return Err(CodecError::Network(network_id));
    }
    if post_action_sequence
        != pre_action_sequence
            .checked_add(1)
            .ok_or(CodecError::ContextInvariant("action sequence overflows"))?
    {
        return Err(CodecError::ContextInvariant(
            "post action sequence must increment pre action sequence by one",
        ));
    }
    Ok(())
}

fn validate_context_counts(input_count: usize, output_count: usize) -> Result<(), CodecError> {
    if input_count == 0 || input_count > usize::from(u16::MAX) {
        return Err(CodecError::ContextInvariant(
            "input count must be nonzero u16",
        ));
    }
    if output_count == 0 || output_count > usize::from(u16::MAX) {
        return Err(CodecError::ContextInvariant(
            "output count must be nonzero u16",
        ));
    }
    Ok(())
}

fn validate_context_vector(value: &[u8]) -> Result<(), CodecError> {
    if value.len() > 10_000 {
        return Err(CodecError::ContextInvariant(
            "byte vector exceeds 10000 bytes",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_context_header(
    network_id: u8,
    kind: ActionKindV2,
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    transaction_version: u32,
    locktime: u32,
    input_count: usize,
    output_count: usize,
    pre_action_sequence: u64,
    post_action_sequence: u64,
) -> Result<Vec<u8>, CodecError> {
    validate_context_header(network_id, pre_action_sequence, post_action_sequence)?;
    validate_context_counts(input_count, output_count)?;
    let mut header = Vec::with_capacity(DIRECT_V2_CONTEXT_HEADER_BYTES);
    header.extend_from_slice(b"SDC2");
    header.push(network_id);
    header.push(kind as u8);
    header.extend_from_slice(&[0, 0]);
    header.extend_from_slice(profile_id);
    header.extend_from_slice(instance_id);
    header.extend_from_slice(&transaction_version.to_le_bytes());
    header.extend_from_slice(&locktime.to_le_bytes());
    header.extend_from_slice(&(input_count as u16).to_le_bytes());
    header.extend_from_slice(&(output_count as u16).to_le_bytes());
    header.extend_from_slice(&pre_action_sequence.to_le_bytes());
    header.extend_from_slice(&post_action_sequence.to_le_bytes());
    debug_assert_eq!(header.len(), DIRECT_V2_CONTEXT_HEADER_BYTES);
    Ok(header)
}

fn validate_raw_role_topology(
    context: &DirectV2TransactionContext,
    carrier_count: u8,
) -> Result<(), CodecError> {
    if carrier_count == 0 {
        return Err(CodecError::ContextInvariant(
            "carrier count must be from 1 to 255",
        ));
    }
    let carriers = usize::from(carrier_count);
    let expected_inputs = carriers + 3;
    let expected_outputs = carriers
        + if context.kind == ActionKindV2::Withdrawal {
            4
        } else {
            3
        };
    if context.inputs.len() != expected_inputs || context.outputs.len() != expected_outputs {
        return Err(CodecError::ContextInvariant("role topology count"));
    }
    for index in 0..carriers {
        assert_role(
            context.inputs[index].role,
            DirectV2RoleKind::Verifier,
            index as u8,
        )?;
        assert_role(
            context.outputs[index + 1].role,
            DirectV2RoleKind::Verifier,
            index as u8,
        )?;
        if !context.inputs[index].token_prefix.is_empty()
            || !context.outputs[index + 1].token_prefix.is_empty()
        {
            return Err(CodecError::ContextInvariant(
                "verifier carrier token prefix",
            ));
        }
    }
    assert_role(context.inputs[carriers].role, DirectV2RoleKind::Binding, 0)?;
    assert_role(
        context.inputs[carriers + 1].role,
        DirectV2RoleKind::State,
        0,
    )?;
    assert_role(
        context.inputs[carriers + 2].role,
        DirectV2RoleKind::Funding,
        0,
    )?;
    assert_role(context.outputs[0].role, DirectV2RoleKind::State, 0)?;
    assert_role(
        context.outputs[carriers + 1].role,
        DirectV2RoleKind::Binding,
        0,
    )?;
    for token in [
        &context.inputs[carriers].token_prefix,
        &context.inputs[carriers + 2].token_prefix,
        &context.outputs[carriers + 1].token_prefix,
    ] {
        if !token.is_empty() {
            return Err(CodecError::ContextInvariant(
                "binding or funding token prefix",
            ));
        }
    }
    if context.inputs[carriers + 1].token_prefix.is_empty()
        || context.outputs[0].token_prefix.is_empty()
    {
        return Err(CodecError::ContextInvariant("state token prefix"));
    }
    let tail = carriers + 2;
    if context.kind == ActionKindV2::Withdrawal {
        assert_role(context.outputs[tail].role, DirectV2RoleKind::Withdrawal, 0)?;
        assert_role(context.outputs[tail + 1].role, DirectV2RoleKind::Change, 0)?;
        if !context.outputs[tail].token_prefix.is_empty()
            || !context.outputs[tail + 1].token_prefix.is_empty()
        {
            return Err(CodecError::ContextInvariant(
                "withdrawal or change token prefix",
            ));
        }
    } else {
        assert_role(context.outputs[tail].role, DirectV2RoleKind::Change, 0)?;
        if !context.outputs[tail].token_prefix.is_empty() {
            return Err(CodecError::ContextInvariant("change token prefix"));
        }
    }
    Ok(())
}

fn validate_committed_role_topology(
    context: &CommittedDirectV2TransactionContext,
    carrier_count: u8,
) -> Result<(), CodecError> {
    if carrier_count == 0 {
        return Err(CodecError::ContextInvariant(
            "carrier count must be from 1 to 255",
        ));
    }
    let carriers = usize::from(carrier_count);
    let expected_inputs = carriers + 3;
    let expected_outputs = carriers
        + if context.kind == ActionKindV2::Withdrawal {
            4
        } else {
            3
        };
    if context.inputs.len() != expected_inputs || context.outputs.len() != expected_outputs {
        return Err(CodecError::ContextInvariant("role topology count"));
    }
    let empty_token_prefix_hash = sha256(&[]);
    for index in 0..carriers {
        assert_role(
            context.inputs[index].role,
            DirectV2RoleKind::Verifier,
            index as u8,
        )?;
        assert_role(
            context.outputs[index + 1].role,
            DirectV2RoleKind::Verifier,
            index as u8,
        )?;
        if context.inputs[index].token_prefix_hash != empty_token_prefix_hash
            || context.outputs[index + 1].token_prefix_hash != empty_token_prefix_hash
        {
            return Err(CodecError::ContextInvariant(
                "verifier carrier token prefix hash",
            ));
        }
    }
    assert_role(context.inputs[carriers].role, DirectV2RoleKind::Binding, 0)?;
    assert_role(
        context.inputs[carriers + 1].role,
        DirectV2RoleKind::State,
        0,
    )?;
    assert_role(
        context.inputs[carriers + 2].role,
        DirectV2RoleKind::Funding,
        0,
    )?;
    assert_role(context.outputs[0].role, DirectV2RoleKind::State, 0)?;
    assert_role(
        context.outputs[carriers + 1].role,
        DirectV2RoleKind::Binding,
        0,
    )?;
    for token_hash in [
        context.inputs[carriers].token_prefix_hash,
        context.inputs[carriers + 2].token_prefix_hash,
        context.outputs[carriers + 1].token_prefix_hash,
    ] {
        if token_hash != empty_token_prefix_hash {
            return Err(CodecError::ContextInvariant(
                "binding or funding token prefix hash",
            ));
        }
    }
    if context.inputs[carriers + 1].token_prefix_hash == empty_token_prefix_hash
        || context.outputs[0].token_prefix_hash == empty_token_prefix_hash
    {
        return Err(CodecError::ContextInvariant("state token prefix hash"));
    }
    let tail = carriers + 2;
    if context.kind == ActionKindV2::Withdrawal {
        assert_role(context.outputs[tail].role, DirectV2RoleKind::Withdrawal, 0)?;
        assert_role(context.outputs[tail + 1].role, DirectV2RoleKind::Change, 0)?;
        if context.outputs[tail].token_prefix_hash != empty_token_prefix_hash
            || context.outputs[tail + 1].token_prefix_hash != empty_token_prefix_hash
        {
            return Err(CodecError::ContextInvariant(
                "withdrawal or change token prefix hash",
            ));
        }
    } else {
        assert_role(context.outputs[tail].role, DirectV2RoleKind::Change, 0)?;
        if context.outputs[tail].token_prefix_hash != empty_token_prefix_hash {
            return Err(CodecError::ContextInvariant("change token prefix hash"));
        }
    }
    Ok(())
}

fn assert_role(
    actual: DirectV2Role,
    expected_kind: DirectV2RoleKind,
    expected_ordinal: u8,
) -> Result<(), CodecError> {
    if actual.kind != expected_kind || actual.ordinal != expected_ordinal {
        return Err(CodecError::ContextInvariant("wrong role"));
    }
    Ok(())
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[derive(Clone, Debug)]
struct BabyJubPoint {
    x: BigUint,
    y: BigUint,
}

#[derive(Clone, Debug)]
struct BabyJubExtendedPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

fn bn254_modulus() -> BigUint {
    BigUint::from_bytes_be(&BN254_FR_MODULUS)
}

fn babyjub_subgroup_order() -> BigUint {
    BigUint::parse_bytes(
        b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
        10,
    )
    .expect("fixed BabyJubJub subgroup order")
}

fn mod_sub(left: &BigUint, right: &BigUint, modulus: &BigUint) -> BigUint {
    if left >= right {
        (left - right) % modulus
    } else {
        (modulus - ((right - left) % modulus)) % modulus
    }
}

fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    if value.is_zero() {
        None
    } else {
        Some(value.modpow(&(modulus - BigUint::from(2_u8)), modulus))
    }
}

fn mod_sqrt(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let value = value % modulus;
    if value.is_zero() {
        return Some(BigUint::zero());
    }
    let one = BigUint::one();
    let legendre = value.modpow(&((modulus - &one) >> 1_u8), modulus);
    if legendre != one {
        return None;
    }
    let mut q = modulus - &one;
    let mut s = 0_u32;
    while (&q & &one).is_zero() {
        q >>= 1_u8;
        s += 1;
    }
    let minus_one = modulus - &one;
    let mut z = BigUint::from(2_u8);
    while z.modpow(&((modulus - &one) >> 1_u8), modulus) != minus_one {
        z += &one;
    }
    let mut c = z.modpow(&q, modulus);
    let mut x = value.modpow(&((&q + &one) >> 1_u8), modulus);
    let mut t = value.modpow(&q, modulus);
    let mut m = s;
    while t != one {
        let mut i = 1_u32;
        let mut probe = (&t * &t) % modulus;
        while probe != one {
            probe = (&probe * &probe) % modulus;
            i += 1;
            if i >= m {
                return None;
            }
        }
        let exponent = BigUint::one() << (m - i - 1);
        let b = c.modpow(&exponent, modulus);
        x = (&x * &b) % modulus;
        c = (&b * &b) % modulus;
        t = (&t * &c) % modulus;
        m = i;
    }
    Some(x)
}

fn extended_identity() -> BabyJubExtendedPoint {
    BabyJubExtendedPoint {
        x: BigUint::zero(),
        y: BigUint::one(),
        z: BigUint::one(),
    }
}

fn extended_from_affine(point: &BabyJubPoint) -> BabyJubExtendedPoint {
    BabyJubExtendedPoint {
        x: point.x.clone(),
        y: point.y.clone(),
        z: BigUint::one(),
    }
}

fn extended_add(
    left: &BabyJubExtendedPoint,
    right: &BabyJubExtendedPoint,
    modulus: &BigUint,
) -> BabyJubExtendedPoint {
    let a = BigUint::from(168_700_u32);
    let d = BigUint::from(168_696_u32);
    let z = (&left.z * &right.z) % modulus;
    let zz = (&z * &z) % modulus;
    let xx = (&left.x * &right.x) % modulus;
    let yy = (&left.y * &right.y) % modulus;
    let dxy = (((&d * &xx) % modulus) * &yy) % modulus;
    let minus = mod_sub(&zz, &dxy, modulus);
    let plus = (&zz + &dxy) % modulus;
    let sum = mod_sub(
        &(((&left.x + &left.y) * (&right.x + &right.y)) % modulus),
        &((&xx + &yy) % modulus),
        modulus,
    );
    BabyJubExtendedPoint {
        x: (((&z * &minus) % modulus) * sum) % modulus,
        y: (((&z * &plus) % modulus) * mod_sub(&yy, &((&a * &xx) % modulus), modulus)) % modulus,
        z: (&minus * &plus) % modulus,
    }
}

fn extended_to_affine(point: &BabyJubExtendedPoint, modulus: &BigUint) -> Option<BabyJubPoint> {
    let inverse = mod_inverse(&point.z, modulus)?;
    Some(BabyJubPoint {
        x: (&point.x * &inverse) % modulus,
        y: (&point.y * inverse) % modulus,
    })
}

fn babyjub_mul(point: &BabyJubPoint, scalar: &BigUint, modulus: &BigUint) -> Option<BabyJubPoint> {
    let mut result = extended_identity();
    let mut base = extended_from_affine(point);
    let mut remaining = scalar.clone();
    while !remaining.is_zero() {
        if (&remaining & BigUint::one()) == BigUint::one() {
            result = extended_add(&result, &base, modulus);
        }
        base = extended_add(&base, &base, modulus);
        remaining >>= 1_u8;
    }
    extended_to_affine(&result, modulus)
}

fn unpack_babyjub_point(encoded: &[u8; 32]) -> Result<BabyJubPoint, CodecError> {
    let modulus = bn254_modulus();
    let negative = (encoded[31] & 0x80) != 0;
    let mut y_bytes = *encoded;
    y_bytes[31] &= 0x7f;
    let y = BigUint::from_bytes_le(&y_bytes);
    if y >= modulus {
        return Err(CodecError::AddressInvariant("public key is noncanonical"));
    }
    let y_squared = (&y * &y) % &modulus;
    let numerator = mod_sub(&BigUint::one(), &y_squared, &modulus);
    let denominator = mod_sub(
        &BigUint::from(168_700_u32),
        &((BigUint::from(168_696_u32) * &y_squared) % &modulus),
        &modulus,
    );
    let inverse = mod_inverse(&denominator, &modulus).ok_or(CodecError::AddressInvariant(
        "public key has zero denominator",
    ))?;
    let x_squared = (numerator * inverse) % &modulus;
    let mut x = mod_sqrt(&x_squared, &modulus)
        .ok_or(CodecError::AddressInvariant("public key is off curve"))?;
    let half = (&modulus - BigUint::one()) >> 1_u8;
    if (x > half) != negative {
        x = mod_sub(&BigUint::zero(), &x, &modulus);
    }
    let point = BabyJubPoint { x, y };
    if !babyjub_in_subgroup(&point, &modulus) {
        return Err(CodecError::AddressInvariant(
            "public key is not a nonidentity prime-subgroup point",
        ));
    }
    Ok(point)
}

fn babyjub_in_subgroup(point: &BabyJubPoint, modulus: &BigUint) -> bool {
    if point.x >= *modulus || point.y >= *modulus || point.x.is_zero() {
        return false;
    }
    let x_squared = (&point.x * &point.x) % modulus;
    let y_squared = (&point.y * &point.y) % modulus;
    let left = ((BigUint::from(168_700_u32) * &x_squared) + &y_squared) % modulus;
    let right = (BigUint::one()
        + (((BigUint::from(168_696_u32) * x_squared) % modulus) * y_squared) % modulus)
        % modulus;
    if left != right {
        return false;
    }
    matches!(babyjub_mul(point, &babyjub_subgroup_order(), modulus), Some(result) if result.x.is_zero() && result.y == BigUint::one())
}

fn derive_address_authority(
    profile_id: &[u8; 32],
    instance_id: &[u8; 32],
    spend: &BabyJubPoint,
    incoming: &BabyJubPoint,
) -> Result<[u8; 32], CodecError> {
    let domain = fr_from_canonical_bytes(&[
        0x17, 0x4c, 0x18, 0xc7, 0x6e, 0x6b, 0x8e, 0x7e, 0x90, 0x35, 0x47, 0x6f, 0x04, 0x19, 0x29,
        0x3d, 0x25, 0xaa, 0xbb, 0x87, 0x22, 0x0e, 0x61, 0x39, 0x24, 0xe5, 0x83, 0x45, 0xd1, 0x19,
        0x14, 0xdf,
    ])?;
    let profile_high = Fr::from(u128::from_be_bytes(array16(&profile_id[..16])));
    let profile_low = Fr::from(u128::from_be_bytes(array16(&profile_id[16..])));
    let instance_high = Fr::from(u128::from_be_bytes(array16(&instance_id[..16])));
    let instance_low = Fr::from(u128::from_be_bytes(array16(&instance_id[16..])));
    let inputs = [
        domain,
        profile_high,
        profile_low,
        instance_high,
        instance_low,
        fr_from_biguint(&spend.x)?,
        fr_from_biguint(&spend.y)?,
        fr_from_biguint(&incoming.x)?,
        fr_from_biguint(&incoming.y)?,
    ];
    let mut poseidon = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|_| CodecError::AddressInvariant("Poseidon parameters"))?;
    let result = poseidon
        .hash(&inputs)
        .map_err(|_| CodecError::AddressInvariant("Poseidon address hash"))?;
    fr_to_bytes(&result)
}

fn fr_from_canonical_bytes(bytes: &[u8; 32]) -> Result<Fr, CodecError> {
    canonical_fr(bytes, "field")?;
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

fn fr_from_biguint(value: &BigUint) -> Result<Fr, CodecError> {
    let encoded = value.to_bytes_be();
    if encoded.len() > 32 {
        return Err(CodecError::AddressInvariant("field coordinate width"));
    }
    let mut bytes = [0_u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    fr_from_canonical_bytes(&bytes)
}

fn fr_to_bytes(value: &Fr) -> Result<[u8; 32], CodecError> {
    let encoded = value.into_bigint().to_bytes_be();
    if encoded.len() > 32 {
        return Err(CodecError::AddressInvariant("field output width"));
    }
    let mut bytes = [0_u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    Ok(bytes)
}

fn array16(bytes: &[u8]) -> [u8; 16] {
    let mut value = [0_u8; 16];
    value.copy_from_slice(bytes);
    value
}
