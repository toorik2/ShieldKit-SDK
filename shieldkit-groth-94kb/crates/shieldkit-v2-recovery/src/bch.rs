use crate::{RecoveryError, Result, decode_lower_hex};
use sha2::{Digest, Sha256};

pub const MAX_STANDARD_TRANSACTION_BYTES: usize = 100_000;
pub const MAX_STANDARD_UNLOCK_BYTES: usize = 10_000;
pub const MAX_TOKEN_AMOUNT: u64 = 9_223_372_036_854_775_807;
pub const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub raw: Vec<u8>,
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
    /// Double-SHA-256 bytes in the exact order serialized in a spending outpoint.
    pub hash: [u8; 32],
    /// Conventional explorer/display byte order.
    pub transaction_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Input {
    /// Exact 32 bytes serialized in the outpoint.
    pub outpoint_transaction_hash: [u8; 32],
    pub outpoint_index: u32,
    pub unlocking_bytecode: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    pub value_sats: u64,
    pub locking_bytecode: Vec<u8>,
    /// Exact prefix bytes, beginning with 0xef, or an empty vector.
    pub token_prefix: Vec<u8>,
    pub token: Option<Token>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    /// Exact category order found after 0xef in the serialized token prefix.
    pub category_wire: [u8; 32],
    pub amount: u64,
    pub nft: Option<Nft>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nft {
    /// none=0, mutable=1, minting=2.
    pub capability: u8,
    pub commitment: Vec<u8>,
}

pub fn parse_transaction_hex(value: &str, label: &str) -> Result<Transaction> {
    let raw = decode_lower_hex(value, label)?;
    parse_transaction(raw, label)
}

pub fn parse_transaction(raw: Vec<u8>, label: &str) -> Result<Transaction> {
    if raw.is_empty() {
        return Err(RecoveryError::new(format!("{label} is empty")));
    }
    let hash = hash256(&raw);
    let transaction_id = display_hash(&hash);
    let mut reader = Reader::new(&raw, label);
    let version = reader.u32_le("version")?;
    let input_count = reader.compact_size("input count")?;
    if input_count == 0 {
        return Err(reader.error("input count must be nonzero"));
    }
    let input_count = usize::try_from(input_count)
        .map_err(|_| reader.error("input count exceeds this platform"))?;
    if input_count > raw.len() {
        return Err(reader.error("input count exceeds the remaining transaction bytes"));
    }
    let mut inputs = Vec::with_capacity(input_count);
    for index in 0..input_count {
        let outpoint_transaction_hash = reader.array32(&format!("input {index} outpoint hash"))?;
        let outpoint_index = reader.u32_le(&format!("input {index} outpoint index"))?;
        let unlocking_length =
            reader.compact_size(&format!("input {index} unlocking bytecode length"))?;
        let unlocking_length = usize::try_from(unlocking_length)
            .map_err(|_| reader.error("unlocking bytecode length exceeds this platform"))?;
        let unlocking_bytecode = reader
            .bytes(
                unlocking_length,
                &format!("input {index} unlocking bytecode"),
            )?
            .to_vec();
        let sequence = reader.u32_le(&format!("input {index} sequence"))?;
        inputs.push(Input {
            outpoint_transaction_hash,
            outpoint_index,
            unlocking_bytecode,
            sequence,
        });
    }
    let output_count = reader.compact_size("output count")?;
    if output_count == 0 {
        return Err(reader.error("output count must be nonzero"));
    }
    let output_count = usize::try_from(output_count)
        .map_err(|_| reader.error("output count exceeds this platform"))?;
    if output_count > raw.len() {
        return Err(reader.error("output count exceeds the remaining transaction bytes"));
    }
    let mut outputs = Vec::with_capacity(output_count);
    for index in 0..output_count {
        let value_sats = reader.u64_le(&format!("output {index} value"))?;
        if value_sats > MAX_MONEY_SATS {
            return Err(reader.error(&format!("output {index} value exceeds MAX_MONEY_SATS")));
        }
        let content_length = reader.compact_size(&format!("output {index} content length"))?;
        let content_length = usize::try_from(content_length)
            .map_err(|_| reader.error("output content length exceeds this platform"))?;
        let contents = reader.bytes(content_length, &format!("output {index} contents"))?;
        outputs.push(parse_output_contents(
            value_sats,
            contents,
            &format!("{label} output {index}"),
        )?);
    }
    let locktime = reader.u32_le("locktime")?;
    if !reader.finished() {
        return Err(reader.error("transaction has trailing bytes"));
    }
    Ok(Transaction {
        raw,
        version,
        inputs,
        outputs,
        locktime,
        hash,
        transaction_id,
    })
}

fn parse_output_contents(value_sats: u64, contents: &[u8], label: &str) -> Result<Output> {
    if contents.first() != Some(&0xef) {
        return Ok(Output {
            value_sats,
            locking_bytecode: contents.to_vec(),
            token_prefix: Vec::new(),
            token: None,
        });
    }
    if contents.len() < 34 {
        return Err(RecoveryError::new(format!(
            "{label} has a truncated CashToken prefix"
        )));
    }
    let mut category_wire = [0_u8; 32];
    category_wire.copy_from_slice(&contents[1..33]);
    let bitfield = contents[33];
    if bitfield & 0x80 != 0 {
        return Err(RecoveryError::new(format!(
            "{label} CashToken reserved bit is set"
        )));
    }
    let capability = bitfield & 0x0f;
    if capability > 2 {
        return Err(RecoveryError::new(format!(
            "{label} CashToken NFT capability is invalid"
        )));
    }
    let has_amount = bitfield & 0x10 != 0;
    let has_nft = bitfield & 0x20 != 0;
    let has_commitment = bitfield & 0x40 != 0;
    if has_commitment && !has_nft {
        return Err(RecoveryError::new(format!(
            "{label} CashToken commitment has no NFT"
        )));
    }
    if !has_nft && capability != 0 {
        return Err(RecoveryError::new(format!(
            "{label} CashToken capability has no NFT"
        )));
    }
    if !has_nft && !has_amount {
        return Err(RecoveryError::new(format!(
            "{label} CashToken prefix encodes no token"
        )));
    }

    let mut cursor = SliceReader::new(contents, 34, label);
    let commitment = if has_commitment {
        let length = cursor.compact_size("NFT commitment length")?;
        if length == 0 {
            return Err(RecoveryError::new(format!(
                "{label} CashToken encoded commitment is empty"
            )));
        }
        let length = usize::try_from(length).map_err(|_| {
            RecoveryError::new(format!(
                "{label} CashToken commitment length exceeds this platform"
            ))
        })?;
        cursor.bytes(length, "NFT commitment")?.to_vec()
    } else {
        Vec::new()
    };
    let amount = if has_amount {
        let amount = cursor.compact_size("fungible amount")?;
        if amount == 0 || amount > MAX_TOKEN_AMOUNT {
            return Err(RecoveryError::new(format!(
                "{label} CashToken fungible amount is outside its canonical range"
            )));
        }
        amount
    } else {
        0
    };
    let prefix_end = cursor.position();
    Ok(Output {
        value_sats,
        token_prefix: contents[..prefix_end].to_vec(),
        locking_bytecode: contents[prefix_end..].to_vec(),
        token: Some(Token {
            category_wire,
            amount,
            nft: has_nft.then_some(Nft {
                capability,
                commitment,
            }),
        }),
    })
}

pub fn hash256(value: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(value);
    Sha256::digest(first).into()
}

pub fn display_hash(hash_wire: &[u8; 32]) -> String {
    let mut display = *hash_wire;
    display.reverse();
    hex::encode(display)
}

pub fn parse_display_hash(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = decode_lower_hex(value, label)?;
    if bytes.len() != 32 {
        return Err(RecoveryError::new(format!(
            "{label} must contain exactly 32 bytes"
        )));
    }
    let mut wire = [0_u8; 32];
    for (target, source) in wire.iter_mut().zip(bytes.iter().rev()) {
        *target = *source;
    }
    Ok(wire)
}

struct Reader<'a> {
    inner: SliceReader<'a>,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], label: &str) -> Self {
        Self {
            inner: SliceReader::new(bytes, 0, label),
        }
    }

    fn error(&self, message: &str) -> RecoveryError {
        RecoveryError::new(format!("{}: {message}", self.inner.label))
    }

    fn bytes(&mut self, length: usize, field: &str) -> Result<&'a [u8]> {
        self.inner.bytes(length, field)
    }

    fn array32(&mut self, field: &str) -> Result<[u8; 32]> {
        let mut value = [0_u8; 32];
        value.copy_from_slice(self.bytes(32, field)?);
        Ok(value)
    }

    fn compact_size(&mut self, field: &str) -> Result<u64> {
        self.inner.compact_size(field)
    }

    fn u32_le(&mut self, field: &str) -> Result<u32> {
        self.inner.u32_le(field)
    }

    fn u64_le(&mut self, field: &str) -> Result<u64> {
        self.inner.u64_le(field)
    }

    fn finished(&self) -> bool {
        self.inner.position == self.inner.bytes.len()
    }
}

struct SliceReader<'a> {
    bytes: &'a [u8],
    position: usize,
    label: String,
}

impl<'a> SliceReader<'a> {
    fn new(bytes: &'a [u8], position: usize, label: &str) -> Self {
        Self {
            bytes,
            position,
            label: label.to_owned(),
        }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn bytes(&mut self, length: usize, field: &str) -> Result<&'a [u8]> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            RecoveryError::new(format!("{}: {field} length overflows", self.label))
        })?;
        if end > self.bytes.len() {
            return Err(RecoveryError::new(format!(
                "{}: truncated {field}",
                self.label
            )));
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self, field: &str) -> Result<u8> {
        Ok(self.bytes(1, field)?[0])
    }

    fn u16_le(&mut self, field: &str) -> Result<u16> {
        let bytes = self.bytes(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32_le(&mut self, field: &str) -> Result<u32> {
        let bytes = self.bytes(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64_le(&mut self, field: &str) -> Result<u64> {
        let bytes = self.bytes(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn compact_size(&mut self, field: &str) -> Result<u64> {
        let prefix = self.byte(field)?;
        match prefix {
            0x00..=0xfc => Ok(u64::from(prefix)),
            0xfd => {
                let value = u64::from(self.u16_le(field)?);
                if value < 0xfd {
                    return Err(RecoveryError::new(format!(
                        "{}: noncanonical CompactSize for {field}",
                        self.label
                    )));
                }
                Ok(value)
            }
            0xfe => {
                let value = u64::from(self.u32_le(field)?);
                if value <= u64::from(u16::MAX) {
                    return Err(RecoveryError::new(format!(
                        "{}: noncanonical CompactSize for {field}",
                        self.label
                    )));
                }
                Ok(value)
            }
            0xff => {
                let value = self.u64_le(field)?;
                if value <= u64::from(u32::MAX) {
                    return Err(RecoveryError::new(format!(
                        "{}: noncanonical CompactSize for {field}",
                        self.label
                    )));
                }
                Ok(value)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hash_round_trip() {
        let wire = [0x42; 32];
        assert_eq!(
            parse_display_hash(&display_hash(&wire), "hash").expect("parse"),
            wire
        );
    }

    #[test]
    fn rejects_noncanonical_compact_size_and_trailing_bytes() {
        let mut transaction = vec![2, 0, 0, 0, 0xfd, 1, 0];
        assert!(
            parse_transaction(transaction.clone(), "tx")
                .expect_err("noncanonical")
                .to_string()
                .contains("noncanonical CompactSize")
        );
        transaction = vec![2, 0, 0, 0, 1];
        transaction.extend_from_slice(&[0; 32]);
        transaction.extend_from_slice(&u32::MAX.to_le_bytes());
        transaction.push(0);
        transaction.extend_from_slice(&u32::MAX.to_le_bytes());
        transaction.push(1);
        transaction.extend_from_slice(&0_u64.to_le_bytes());
        transaction.push(0);
        transaction.extend_from_slice(&0_u32.to_le_bytes());
        transaction.push(0);
        assert!(
            parse_transaction(transaction, "tx")
                .expect_err("trailing")
                .to_string()
                .contains("trailing bytes")
        );
    }
}
