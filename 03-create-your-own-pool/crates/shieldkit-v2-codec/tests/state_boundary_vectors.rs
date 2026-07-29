use shieldkit_v2_codec::{PoolStateV2, STATE_BYTES};

const BOUNDARY_VECTORS: &str =
    include_str!("../../../packages/action/v2/vectors/q01-state-boundary-vectors.jsonl");
const DENOMINATION: u64 = 10_000_000;
const IDS: [&str; 26] = [
    "zero-roots-empty-live-set",
    "minimum-nonzero-roots-one-live",
    "maximum-canonical-roots-empty-live-set",
    "noncanonical-note-root-modulus",
    "noncanonical-nullifier-root-modulus",
    "count-and-nullifier-maximums",
    "nullifier-count-u32-maximum-rejected",
    "nullifier-count-exceeds-note-count",
    "maximum-live-notes-one-live-one",
    "live-count-exceeds-maximum-live-notes",
    "maximum-live-notes-210000000-and-maximum-reserve",
    "maximum-live-notes-above-denomination-cap",
    "maximum-live-notes-zero",
    "reserve-zero-empty-live-set",
    "reserve-mismatch-one-satoshi",
    "action-sequence-counter-floor",
    "action-sequence-counter-ceiling",
    "action-sequence-below-counter-floor",
    "action-sequence-above-counter-ceiling",
    "action-sequence-absolute-maximum-rejected-by-counter-ceiling",
    "action-sequence-absolute-range-limit",
    "u32-little-endian-pattern",
    "u64-reserve-little-endian-pattern",
    "u64-action-sequence-little-endian-pattern",
    "state-length-127",
    "state-length-129",
];

fn json_string<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("\"{field}\":\"");
    line.split_once(&prefix)?
        .1
        .split_once('"')
        .map(|(value, _)| value)
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "fixed vector hex length");
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).expect("fixed vector hex"))
        .collect()
}

fn array32(value: &str) -> [u8; 32] {
    hex(value).try_into().expect("fixed 32-byte vector field")
}

fn value<'a>(line: &'a str, defaults: &'a str, field: &str) -> &'a str {
    json_string(line, field)
        .or_else(|| json_string(defaults, field))
        .unwrap_or_else(|| panic!("boundary vector is missing {field}"))
}

fn state(line: &str, defaults: &str) -> PoolStateV2 {
    PoolStateV2 {
        profile_id: array32(value(line, defaults, "profileId")),
        note_root: array32(value(line, defaults, "noteRoot")),
        nullifier_root: array32(value(line, defaults, "nullifierRoot")),
        note_count: value(line, defaults, "noteCount")
            .parse()
            .expect("fixed u32"),
        nullifier_count: value(line, defaults, "nullifierCount")
            .parse()
            .expect("fixed u32"),
        maximum_live_notes: value(line, defaults, "maximumLiveNotes")
            .parse()
            .expect("fixed u32"),
        reserve_sats: value(line, defaults, "reserveSats")
            .parse()
            .expect("fixed u64"),
        action_sequence: value(line, defaults, "actionSequence")
            .parse()
            .expect("fixed u64"),
    }
}

#[test]
fn q01_state_boundary_vectors_exactly_validate_the_rust_sks2_codec() {
    let lines: Vec<&str> = BOUNDARY_VECTORS.trim_end().lines().collect();
    let header = lines.first().expect("boundary header");
    assert_eq!(
        json_string(header, "schema"),
        Some("shieldkit/v2-direct-q01-state-boundary-vectors/v1")
    );
    assert_eq!(json_string(header, "denominationSats"), Some("10000000"));
    assert!(header.contains("\"stateBytes\":128"));
    assert!(header.contains("\"vectorCount\":26"));
    assert_eq!(lines.len(), IDS.len() + 1);

    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    for (index, line) in lines.iter().skip(1).enumerate() {
        assert_eq!(json_string(line, "id"), Some(IDS[index]));
        let expected = json_string(line, "expect").expect("vector expectation");
        let bytes = hex(json_string(line, "stateHex").expect("vector bytes"));
        let has_state = line.contains("\"state\":");
        if !has_state {
            assert_eq!(expected, "reject");
            assert_ne!(bytes.len(), STATE_BYTES);
            assert!(
                PoolStateV2::decode(&bytes, DENOMINATION).is_err(),
                "{}",
                IDS[index]
            );
            rejected += 1;
            continue;
        }

        let vector_state = state(line, header);
        assert_eq!(bytes.len(), STATE_BYTES, "{}", IDS[index]);
        match expected {
            "accept" => {
                assert_eq!(
                    vector_state.encode(DENOMINATION).unwrap().as_slice(),
                    bytes,
                    "{}",
                    IDS[index]
                );
                assert_eq!(
                    PoolStateV2::decode(&bytes, DENOMINATION).unwrap(),
                    vector_state,
                    "{}",
                    IDS[index]
                );
                accepted += 1;
            }
            "reject" => {
                assert!(
                    vector_state.encode(DENOMINATION).is_err(),
                    "{} encoded",
                    IDS[index]
                );
                assert!(
                    PoolStateV2::decode(&bytes, DENOMINATION).is_err(),
                    "{} decoded",
                    IDS[index]
                );
                rejected += 1;
            }
            other => panic!("unexpected vector expectation {other}"),
        }
    }
    assert_eq!(accepted, 10);
    assert_eq!(rejected, 16);
}
