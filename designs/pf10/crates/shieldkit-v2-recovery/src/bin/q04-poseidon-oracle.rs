#![forbid(unsafe_code)]

//! Audit-only Q-04 cross-oracle. This binary intentionally has no pool/tree
//! state access and imports neither JavaScript nor Circom parameter tables.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shieldkit_v2_codec::BN254_FR_MODULUS;

const DOMAIN_PREFIX: &[u8] = b"ShieldKit/PoolActionV2Direct/domain/v1/";
const FR_MODULUS_HEX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

const DOMAINS: [(&str, u32, &str); 6] = [
    (
        "NOTE_LEAF",
        1,
        "0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a",
    ),
    (
        "NOTE_TREE_EMPTY",
        9,
        "28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad",
    ),
    (
        "NOTE_TREE_NODE",
        9,
        "06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153",
    ),
    (
        "NULLIFIER_TREE_LEAF",
        5,
        "21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2",
    ),
    (
        "NULLIFIER_TREE_EMPTY",
        3,
        "2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb",
    ),
    (
        "NULLIFIER_TREE_NODE",
        0,
        "241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4",
    ),
];

const KATS: [(&str, &[&str], &str); 10] = [
    (
        "empty_note",
        &[
            "28fda61e6a38f74d91d7d8c4e279ba8e7b437a707948b9476bcfd650f5a60dad",
            "0",
        ],
        "24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081",
    ),
    (
        "note_parent",
        &[
            "06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153",
            "24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081",
            "24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081",
        ],
        "265399a22fcc1a8f382ddeec66cc3b4fee4e52a4352d5209fcad526fd21e769c",
    ),
    (
        "empty_nullifier",
        &[
            "2633488611f1ffb2708b6ebb8994794c45c27f56b5d0d87d67a841123e3f0acb",
            "0",
        ],
        "18df533689e5101f3e88e6e91339f278f68a84c86f22997b1bb28be7dec598a6",
    ),
    (
        "minimum_sentinel",
        &[
            "21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2",
            "1",
            "0",
            "0",
            "1",
            "0",
        ],
        "04b96bcec386361928f02ccd62ed02446db3d900d3ce3083f6dbd5007b8d20e5",
    ),
    (
        "nullifier_parent",
        &[
            "241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4",
            "04b96bcec386361928f02ccd62ed02446db3d900d3ce3083f6dbd5007b8d20e5",
            "18df533689e5101f3e88e6e91339f278f68a84c86f22997b1bb28be7dec598a6",
        ],
        "1fd573ef8ff8f6825abec3fe3b725941e4035344df59e31ee23a9766de8a9221",
    ),
    (
        "output_note_leaf",
        &[
            "0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a",
            "7",
            "11",
        ],
        "0cda43a183b48956f4e64cb87efdcd9a716e8ad1354640895240cc3f2ffb6f09",
    ),
    (
        "p2_zero_fr_minus_1",
        &[
            "0",
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
        ],
        "28b2de3348b15076cbe645321cd2abbd0d2812669574ed4d5f978fe4e7de98bc",
    ),
    (
        "p3_fr_minus_1_zero_7",
        &[
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            "0",
            "7",
        ],
        "23273fd701c327772475309dbcb4c09d0e078b2d9254e3de9d182900fd47944a",
    ),
    (
        "p6_1_through_6",
        &["1", "2", "3", "4", "5", "6"],
        "2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1",
    ),
    (
        "p6_all_fr_minus_1",
        &[
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
        ],
        "1864ca75de675b4d3295bd19b556bf2d3f46029f09a0fc5438ecb3d857ebc3e5",
    ),
];

fn field(value: &str) -> Result<Fr, String> {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        let decimal = value
            .parse::<u64>()
            .map_err(|_| "fixed decimal KAT field is invalid".to_owned())?;
        return Ok(Fr::from(decimal));
    }
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("fixed hexadecimal KAT field is malformed".to_owned());
    }
    let bytes = hex::decode(value).map_err(|_| "fixed KAT field is not hexadecimal".to_owned())?;
    let parsed = Fr::from_be_bytes_mod_order(&bytes);
    if field_hex(parsed) != value {
        return Err("fixed KAT field is not canonical BN254 Fr".to_owned());
    }
    Ok(parsed)
}

fn field_hex(value: Fr) -> String {
    format!("{:0>64}", hex::encode(value.into_bigint().to_bytes_be()))
}

fn poseidon(inputs: &[&str]) -> Result<String, String> {
    if !matches!(inputs.len(), 2 | 3 | 6) {
        return Err("oracle permits only production tree P2/P3/P6 arities".to_owned());
    }
    let fields = inputs
        .iter()
        .map(|value| field(value))
        .collect::<Result<Vec<_>, _>>()?;
    let mut hasher = Poseidon::<Fr>::new_circom(fields.len())
        .map_err(|_| "light-poseidon parameter selection failed".to_owned())?;
    Ok(field_hex(
        hasher
            .hash(&fields)
            .map_err(|_| "light-poseidon hash failed".to_owned())?,
    ))
}

fn derive_domain(label: &str) -> Result<(u32, String), String> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("domain label must be uppercase ASCII".to_owned());
    }
    for counter in 0_u32..=u32::MAX {
        let digest: [u8; 32] = Sha256::new()
            .chain_update(DOMAIN_PREFIX)
            .chain_update(label.as_bytes())
            .chain_update(counter.to_be_bytes())
            .finalize()
            .into();
        if digest != [0; 32] && digest < BN254_FR_MODULUS {
            return Ok((counter, hex::encode(digest)));
        }
    }
    Err("domain counter space exhausted".to_owned())
}

fn report() -> Result<Value, String> {
    let domains = DOMAINS
        .iter()
        .map(|(label, expected_counter, expected_hex)| {
            let (counter, hex) = derive_domain(label)?;
            if counter != *expected_counter || hex != *expected_hex {
                return Err(format!("derived domain mismatch: {label}"));
            }
            Ok(json!({"label": label, "counter": counter, "hex": hex}))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let kats = KATS
        .iter()
        .map(|(name, inputs, expected)| {
            let actual = poseidon(inputs)?;
            if actual != *expected {
                return Err(format!("Poseidon KAT mismatch: {name}"));
            }
            Ok(json!({"name": name, "arity": inputs.len(), "inputs": inputs, "output": actual}))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "schema": "shieldkit-v2-direct-q04-rust-cross-oracle-v1",
        "status": "kat-passed-local-only",
        "metadata": {
            "implementation": "rust-light-poseidon-bn254-x5",
            "lightPoseidonVersion": "0.4.0",
            "arkBn254Version": "0.5.0",
            "arkFfVersion": "0.5.0",
            "sha2Version": "0.10.9",
            "fieldModulusHex": FR_MODULUS_HEX,
            "inputOrdering": "state=[0, domain, payload...] ; new_circom(input_count) ; canonical big-endian Fr",
            "arities": [2, 3, 6]
        },
        "claims": {
            "independentImplementation": true,
            "independentEmbeddedParameterArtifact": true,
            "independentParameterGeneration": false,
            "importsJavaScript": false,
            "importsCircomTables": false,
            "productionQualification": false,
            "treeCampaign": false
        },
        "domains": domains,
        "knownAnswerTests": kats
    }))
}

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: q04-poseidon-oracle");
        std::process::exit(2);
    }
    match report()
        .and_then(|value| serde_json::to_string(&value).map_err(|error| error.to_string()))
    {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("q04-poseidon-oracle: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independently_derives_all_six_frozen_tree_domains() {
        for (label, counter, hex) in DOMAINS {
            assert_eq!(derive_domain(label).unwrap(), (counter, hex.to_owned()));
        }
    }

    #[test]
    fn reproduces_tree_and_fr_edge_known_answers() {
        for (name, inputs, expected) in KATS {
            assert_eq!(poseidon(inputs).unwrap(), expected, "{name}");
        }
    }

    #[test]
    fn emits_strict_nonqualification_metadata() {
        let value = report().unwrap();
        assert_eq!(
            value["schema"],
            "shieldkit-v2-direct-q04-rust-cross-oracle-v1"
        );
        assert_eq!(value["claims"]["importsJavaScript"], false);
        assert_eq!(value["claims"]["importsCircomTables"], false);
        assert_eq!(value["claims"]["independentParameterGeneration"], false);
        assert_eq!(value["claims"]["productionQualification"], false);
        assert_eq!(value["domains"].as_array().unwrap().len(), 6);
        assert_eq!(value["knownAnswerTests"].as_array().unwrap().len(), 10);
    }
}
