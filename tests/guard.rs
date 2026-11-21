use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_skillguard");

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn temp_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "skillguard-guard-test-{name}-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to run skillguard");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn lock_and_verify_detect_drift() {
    let root = temp_dir("lock");
    let lock = root.join("skillguard.lock");
    let (code, stdout, stderr) = run(&[
        "lock",
        fixture("clean-skill").to_str().unwrap(),
        "--output",
        lock.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "lock failed\nstdout: {stdout}\nstderr: {stderr}");
    assert!(lock.is_file());
    assert!(stdout.contains("fingerprint:"), "{stdout}");

    let (code, stdout, stderr) = run(&[
        "verify",
        fixture("clean-skill").to_str().unwrap(),
        "--lock",
        lock.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "verify failed\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("PASS"), "{stdout}");

    let skill_md = fixture("clean-skill").join("SKILL.md");
    let original = fs::read_to_string(&skill_md).unwrap();
    fs::write(&skill_md, format!("{original}\n<!-- drift -->\n")).unwrap();
    let (code, stdout, stderr) = run(&[
        "verify",
        fixture("clean-skill").to_str().unwrap(),
        "--lock",
        lock.to_str().unwrap(),
    ]);
    fs::write(&skill_md, original).unwrap();
    assert_eq!(
        code, 1,
        "drift should fail\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("modified"), "{stdout}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn policy_blocks_high_findings() {
    let root = temp_dir("policy");
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        r#"{"profile":"team","fail_on":"high","max_medium":10,"deny":[],"allow":[]}"#,
    )
    .unwrap();
    let (code, stdout, stderr) = run(&[
        "scan",
        fixture("dangerous-skill").to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 1,
        "policy should block\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stderr.contains("policy: BLOCK"), "{stderr}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn policy_exception_allows_high() {
    let root = temp_dir("policy-allow");
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        r#"{"profile":"team","fail_on":"high","allow":[{"rule":"*","owner":"alice","reason":"approved","expires":"2999-01-01"}]}"#,
    )
    .unwrap();
    let (code, stdout, stderr) = run(&[
        "scan",
        fixture("dangerous-skill").to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "active exception should allow\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("policy: ALLOW") || stderr.contains("policy: REVIEW"),
        "{stderr}"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn expired_exception_does_not_allow() {
    let root = temp_dir("policy-expired");
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        r#"{"profile":"team","fail_on":"high","allow":[{"rule":"*","owner":"alice","reason":"approved","expires":"2000-01-01"}]}"#,
    )
    .unwrap();
    let (code, _, stderr) = run(&[
        "scan",
        fixture("dangerous-skill").to_str().unwrap(),
        "--policy",
        policy.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 1, "expired exception must block\n{stderr}");
    assert!(stderr.contains("policy: BLOCK"), "{stderr}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn policy_fail_on_none_wins_over_cli() {
    let root = temp_dir("policy-none");
    let policy = root.join("policy.json");
    fs::write(&policy, r#"{"profile":"team","fail_on":"none"}"#).unwrap();
    let (code, stdout, stderr) = run(&[
        "scan",
        fixture("dangerous-skill").to_str().unwrap(),
        "--fail-on",
        "high",
        "--policy",
        policy.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "policy fail_on=none must win\nstdout: {stdout}\nstderr: {stderr}"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn invalid_policy_is_rejected() {
    let root = temp_dir("policy-invalid");
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        r#"{"profile":"team","fail_on":"high","allow":[{"rule":"*","owner":"alice","reason":"approved","expires":"not-a-date"}]}"#,
    )
    .unwrap();
    let (code, _, stderr) = run(&["policy", "validate", policy.to_str().unwrap()]);
    assert_eq!(code, 2, "invalid policy must fail closed\n{stderr}");
    assert!(stderr.contains("invalid expires date"), "{stderr}");

    fs::write(
        &policy,
        r#"{"profile":"team","fail_on":"high","typo":true}"#,
    )
    .unwrap();
    let (code, _, stderr) = run(&["policy", "validate", policy.to_str().unwrap()]);
    assert_eq!(code, 2, "unknown policy fields must fail closed\n{stderr}");
    assert!(stderr.contains("unknown field"), "{stderr}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn baseline_hides_known_findings() {
    let root = temp_dir("baseline");
    let baseline = root.join("baseline.json");
    let target = fixture("dangerous-skill");
    let (code, _, stderr) = run(&[
        "scan",
        target.to_str().unwrap(),
        "--write-baseline",
        baseline.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(code, 1, "initial scan should fail\n{stderr}");
    assert!(baseline.is_file());

    let (code, stdout, stderr) = run(&[
        "scan",
        target.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "baseline should hide findings\nstdout: {stdout}\nstderr: {stderr}"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn audit_appends_hash_chained_jsonl() {
    let root = temp_dir("audit");
    let audit = root.join("audit.jsonl");
    for _ in 0..2 {
        let (code, stdout, stderr) = run(&[
            "scan",
            fixture("clean-skill").to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--format",
            "json",
        ]);
        assert_eq!(code, 0, "scan failed\nstdout: {stdout}\nstderr: {stderr}");
    }
    let body = fs::read_to_string(&audit).unwrap();
    let lines: Vec<serde_json::Value> = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{body}");
    assert_eq!(lines[0]["schema"], "skillguard-audit/v2");
    assert_eq!(lines[0]["action"], "scan");
    assert!(lines[0]["entry_hash"].as_str().unwrap().len() == 64);
    assert_eq!(lines[1]["prev_hash"], lines[0]["entry_hash"]);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn lock_file_inside_root_does_not_drift() {
    let root = temp_dir("self-lock");
    fs::copy(
        fixture("clean-skill").join("SKILL.md"),
        root.join("SKILL.md"),
    )
    .unwrap();
    let lock = root.join("skillguard.lock");
    let (code, stdout, stderr) = run(&[
        "lock",
        root.to_str().unwrap(),
        "--output",
        lock.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "lock failed\nstdout: {stdout}\nstderr: {stderr}");
    let (code, stdout, stderr) = run(&[
        "verify",
        root.to_str().unwrap(),
        "--lock",
        lock.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 0,
        "lockfile must not include itself\nstdout: {stdout}\nstderr: {stderr}"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn mcp_risk_rules_fire() {
    let (code, stdout, stderr) = run(&[
        "scan",
        fixture("mcp-risk").to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 1,
        "MCP risk should fail\nstdout: {stdout}\nstderr: {stderr}"
    );
    for rule in ["SG-MCP-002", "SG-MCP-003", "SG-MCP-005"] {
        assert!(stdout.contains(rule), "missing {rule}\n{stdout}");
    }
}

#[test]
fn mcp_clean_stays_clean() {
    let (code, stdout, stderr) = run(&[
        "scan",
        fixture("mcp-clean").to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(
        code, 0,
        "clean MCP should pass\nstdout: {stdout}\nstderr: {stderr}"
    );
}
