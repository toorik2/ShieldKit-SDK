use serde_json::Value;
use shieldkit_v2_recovery::q07_lifecycle::{
    Q07_LIFECYCLE_FULL_ACTIONS, verify_q07_lifecycle, verify_q07_lifecycle_reduced_for_test,
};
use std::io::{BufReader, Cursor};

const FIXTURE_3: &[u8] = include_bytes!("fixtures/q07-lifecycle-3.ndjson");
const FIXTURE_33: &[u8] = include_bytes!("fixtures/q07-lifecycle-33.ndjson");
const FIXTURE_64: &[u8] = include_bytes!("fixtures/q07-lifecycle-64.ndjson");

fn reduced(bytes: Vec<u8>, transfers: u64) -> bool {
    verify_q07_lifecycle_reduced_for_test(BufReader::new(Cursor::new(bytes)), transfers).is_ok()
}

fn lines(fixture: &[u8]) -> Vec<String> {
    String::from_utf8(fixture.to_vec())
        .expect("fixture UTF-8")
        .lines()
        .map(ToOwned::to_owned)
        .collect()
}

fn joined(lines: &[String]) -> Vec<u8> {
    format!("{}\n", lines.join("\n")).into_bytes()
}

#[test]
fn q07_locked_test_only_fixture_is_accepted_by_independent_rust_replay() {
    for (action_count, fixture) in [(3, FIXTURE_3), (33, FIXTURE_33), (64, FIXTURE_64)] {
        let result = verify_q07_lifecycle_reduced_for_test(
            BufReader::new(Cursor::new(fixture)),
            action_count - 2,
        )
        .expect("locked test-only Q07 fixture must replay");
        assert_eq!(result.status, "verified");
        assert!(result.q07_lifecycle_corpus_verified);
        assert!(!result.chain_authenticated);
        assert!(!result.q07_qualified);
        assert_eq!(result.action_count, action_count.to_string());
        assert_eq!(
            result.action_counts.transfer,
            (action_count - 2).to_string()
        );
        let stdout = serde_json::to_string(&result).expect("result JSON");
        let sorted: Value = serde_json::from_str(&stdout).expect("result JSON parses");
        assert_eq!(
            stdout,
            serde_json::to_string(&sorted).expect("sorted result JSON")
        );
    }
}

#[test]
fn q07_lifecycle_rejects_missing_and_noncanonical_streams_before_replay() {
    assert!(verify_q07_lifecycle(BufReader::new(Cursor::new(Vec::<u8>::new()))).is_err());
    assert!(verify_q07_lifecycle(BufReader::new(Cursor::new(b"{}\n".to_vec()))).is_err());
    assert!(
        verify_q07_lifecycle(BufReader::new(Cursor::new(b"\xef\xbb\xbf{}\n".to_vec()))).is_err()
    );
}

#[test]
fn q07_reduced_hook_is_strictly_test_only_and_bounded() {
    assert!(
        verify_q07_lifecycle_reduced_for_test(BufReader::new(Cursor::new(Vec::<u8>::new())), 0,)
            .is_err()
    );
    assert!(
        verify_q07_lifecycle_reduced_for_test(BufReader::new(Cursor::new(Vec::<u8>::new())), 63,)
            .is_err()
    );
    assert_eq!(Q07_LIFECYCLE_FULL_ACTIONS, 100_000);
}

#[test]
fn q07_locked_fixture_rejects_canonicalization_order_truncation_extra_and_binding_tampering() {
    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(FIXTURE_3);
    assert!(!reduced(noncanonical, 1));

    let mut reordered = lines(FIXTURE_3);
    reordered.swap(1, 2);
    assert!(!reduced(joined(&reordered), 1));

    let mut truncated = lines(FIXTURE_3);
    truncated.pop();
    assert!(!reduced(joined(&truncated), 1));

    let mut extra = FIXTURE_3.to_vec();
    extra.extend_from_slice(b"{}\n");
    assert!(!reduced(extra, 1));

    let mut context_tamper = lines(FIXTURE_3);
    let offset = context_tamper[1]
        .find("contextHex\":\"")
        .expect("context field")
        + "contextHex\":\"".len();
    context_tamper[1].replace_range(offset..offset + 1, "0");
    assert!(!reduced(joined(&context_tamper), 1));

    let mut packet_tamper = lines(FIXTURE_3);
    let offset = packet_tamper[2]
        .find("packetHex\":\"")
        .expect("packet field")
        + "packetHex\":\"".len();
    packet_tamper[2].replace_range(offset..offset + 1, "0");
    assert!(!reduced(joined(&packet_tamper), 1));

    let mut terminal_tamper = lines(FIXTURE_3);
    let end = terminal_tamper.last_mut().expect("end");
    let offset =
        end.find("terminalStateHex\":\"").expect("terminal state") + "terminalStateHex\":\"".len();
    end.replace_range(offset..offset + 1, "0");
    assert!(!reduced(joined(&terminal_tamper), 1));

    let mut unknown_chain_field = lines(FIXTURE_3);
    let mut action: Value = serde_json::from_str(&unknown_chain_field[1]).expect("action JSON");
    action
        .as_object_mut()
        .expect("action object")
        .insert("transactionId".into(), Value::String("00".repeat(32)));
    unknown_chain_field[1] = serde_json::to_string(&action).expect("canonical test JSON");
    assert!(!reduced(joined(&unknown_chain_field), 1));

    let mut wrong_schedule = lines(FIXTURE_3);
    wrong_schedule[2] =
        wrong_schedule[2].replacen("\"kind\":\"transfer\"", "\"kind\":\"withdrawal\"", 1);
    assert!(!reduced(joined(&wrong_schedule), 1));

    let account_tamper = String::from_utf8(FIXTURE_3.to_vec())
        .expect("fixture UTF-8")
        .replacen(
            "0000000000000000000000000000000000000000000000000000000000000007",
            "0000000000000000000000000000000000000000000000000000000000000009",
            1,
        )
        .into_bytes();
    assert!(!reduced(account_tamper, 1));

    let mut late_action_tamper = lines(FIXTURE_64);
    let late_action = late_action_tamper
        .get_mut(63)
        .expect("64-action fixture action 63");
    let offset = late_action.find("packetHex\":\"").expect("packet field") + "packetHex\":\"".len();
    let replacement = if &late_action[offset..offset + 1] == "0" {
        "1"
    } else {
        "0"
    };
    late_action.replace_range(offset..offset + 1, replacement);
    assert!(!reduced(joined(&late_action_tamper), 62));
}
