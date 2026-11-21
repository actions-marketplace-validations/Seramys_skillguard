use serde_json::Value;
use std::process::Command;

fn scan(fixture: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_skillguard"))
        .args(["scan", fixture, "--format", "json"])
        .output()
        .expect("run skillguard");
    assert!(
        output.status.code().is_some(),
        "scan did not run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid scan JSON")
}

fn rule_ids(value: &Value) -> Vec<String> {
    value["findings"]
        .as_array()
        .map(|findings| {
            findings
                .iter()
                .filter_map(|finding| finding["rule_id"].as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn detects_hidden_preflight_and_concealment() {
    let value = scan("tests/fixtures/p0-preflight");
    let ids = rule_ids(&value);
    assert!(ids.iter().any(|id| id == "SG-INIT-001"), "{ids:?}");
    assert!(ids.iter().any(|id| id == "SG-CONCEAL-001"), "{ids:?}");
    assert!(value["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|cap| cap["declared"] == true));
}

#[test]
fn detects_windows_account_and_persistence() {
    let ids = rule_ids(&scan("tests/fixtures/p0-account"));
    assert!(ids.iter().any(|id| id == "SG-ACCT-001"), "{ids:?}");
    assert!(ids.iter().any(|id| id == "SG-PERSIST-001"), "{ids:?}");
}

#[test]
fn detects_download_execute() {
    let ids = rule_ids(&scan("tests/fixtures/p0-download"));
    assert!(ids.iter().any(|id| id == "SG-DL-001"), "{ids:?}");
}

#[test]
fn detects_credential_exfiltration() {
    let ids = rule_ids(&scan("tests/fixtures/p0-credential"));
    assert!(ids.iter().any(|id| id == "SG-CRED-001"), "{ids:?}");
    assert!(ids.iter().any(|id| id == "SG-CRED-002"), "{ids:?}");
}

#[test]
fn detects_encoded_execution() {
    let ids = rule_ids(&scan("tests/fixtures/p0-encoded"));
    assert!(ids.iter().any(|id| id == "SG-EXEC-001"), "{ids:?}");
}

#[test]
fn benign_validation_has_no_p0_signals() {
    let value = scan("tests/fixtures/p0-benign");
    assert!(rule_ids(&value).is_empty(), "{value}");
}

#[test]
fn review_and_explain_show_capability_evidence() {
    for command in ["review", "explain"] {
        let output = Command::new(env!("CARGO_BIN_EXE_skillguard"))
            .args([command, "tests/fixtures/p0-credential"])
            .output()
            .expect("run review");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Capability evidence"), "{stdout}");
        assert!(stdout.contains("Review candidates"), "{stdout}");
    }
}

#[test]
fn github_format_emits_annotations() {
    let output = Command::new(env!("CARGO_BIN_EXE_skillguard"))
        .args(["scan", "tests/fixtures/p0-download", "--format", "github"])
        .output()
        .expect("run github format");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("::error file=SKILL.md"), "{stdout}");
}
