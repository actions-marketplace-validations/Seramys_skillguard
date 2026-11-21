use crate::install::{fingerprint_tree_excluding, read_skill_name, Counts, FileEntry};
use crate::model::{Finding, Severity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const LOCK_SCHEMA: &str = "skillguard-lock/v2";
const BASELINE_SCHEMA: &str = "skillguard-baseline/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub schema: String,
    pub tool_version: String,
    pub skill: String,
    pub source: String,
    pub generated_at: u64,
    pub rules_hash: String,
    pub policy_hash: Option<String>,
    pub fingerprint: String,
    pub files: Vec<FileEntry>,
    pub findings: Counts,
    pub finding_digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LockDrift {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LockVerification {
    pub skill: String,
    pub path: PathBuf,
    pub ok: bool,
    pub expected: String,
    pub actual: String,
    pub drift: Vec<LockDrift>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub schema: String,
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    #[serde(default)]
    pub rule: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub max_medium: Option<usize>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub allow: Vec<Exception>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Decision {
    Allow,
    Warn,
    Block,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Warn => "REVIEW",
            Self::Block => "BLOCK",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyResult {
    pub decision: Decision,
    pub profile: String,
    pub reasons: Vec<String>,
    pub counts: Counts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub schema: String,
    pub timestamp_unix: u64,
    pub action: String,
    pub subject: String,
    pub decision: String,
    pub findings: Counts,
    pub finding_digests: Vec<String>,
    pub reasons: Vec<String>,
    pub policy: Option<String>,
    pub policy_hash: Option<String>,
    pub rules_hash: String,
    pub fingerprint: Option<String>,
    pub tool_version: String,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
}

pub fn builtin_rules_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(include_bytes!("../rules/core.json"));
    hex(&hasher.finalize())
}

pub fn file_hash(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex(&hasher.finalize()))
}

pub fn finding_digests(findings: &[Finding]) -> Vec<String> {
    let mut digests: Vec<String> = findings
        .iter()
        .map(fingerprint_finding)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    digests.sort();
    digests
}

pub fn write_lock(
    root: &Path,
    output: &Path,
    source: &str,
    findings: &[Finding],
    rules_hash: &str,
    policy_hash: Option<&str>,
) -> Result<Lockfile, String> {
    let (fingerprint, files) = fingerprint_tree_excluding(root, &[output])?;
    let lock = Lockfile {
        schema: LOCK_SCHEMA.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        skill: read_skill_name(root),
        source: source.to_string(),
        generated_at: now_unix(),
        rules_hash: rules_hash.to_string(),
        policy_hash: policy_hash.map(ToOwned::to_owned),
        fingerprint,
        files,
        findings: Counts::from_findings(findings),
        finding_digests: finding_digests(findings),
    };
    let body = serde_json::to_string_pretty(&lock)
        .map_err(|error| format!("lockfile 序列化失败: {error}"))?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(output, format!("{body}\n"))
        .map_err(|e| format!("cannot write {}: {e}", output.display()))?;
    Ok(lock)
}

pub fn verify_lock(root: &Path, lock_path: &Path) -> Result<LockVerification, String> {
    let text = fs::read_to_string(lock_path)
        .map_err(|e| format!("cannot read lockfile {}: {e}", lock_path.display()))?;
    let lock: Lockfile = serde_json::from_str(&text)
        .map_err(|e| format!("lockfile 解析失败 {}: {e}", lock_path.display()))?;
    if lock.schema != LOCK_SCHEMA {
        return Err(format!("不支持的 lockfile schema: {}", lock.schema));
    }
    let (actual, files) = fingerprint_tree_excluding(root, &[lock_path])?;
    let old: BTreeMap<String, FileEntry> = lock
        .files
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let new: BTreeMap<String, FileEntry> = files
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let mut drift = Vec::new();
    for path in old.keys() {
        if !new.contains_key(path) {
            drift.push(LockDrift {
                kind: "missing".to_string(),
                path: path.clone(),
            });
        }
    }
    for (path, entry) in &new {
        match old.get(path) {
            None => drift.push(LockDrift {
                kind: "added".to_string(),
                path: path.clone(),
            }),
            Some(expected) if expected.sha256 != entry.sha256 => drift.push(LockDrift {
                kind: "modified".to_string(),
                path: path.clone(),
            }),
            _ => {}
        }
    }
    Ok(LockVerification {
        skill: lock.skill,
        path: root.to_path_buf(),
        ok: drift.is_empty() && lock.fingerprint == actual,
        expected: lock.fingerprint,
        actual,
        drift,
    })
}

pub fn load_baseline(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
    let baseline: Baseline = serde_json::from_str(&text)
        .map_err(|e| format!("baseline 解析失败 {}: {e}", path.display()))?;
    if baseline.schema != BASELINE_SCHEMA {
        return Err(format!("不支持的 baseline schema: {}", baseline.schema));
    }
    Ok(baseline.fingerprints.into_iter().collect())
}

pub fn write_baseline(path: &Path, findings: &[Finding]) -> Result<(), String> {
    let mut fingerprints: Vec<String> = findings
        .iter()
        .map(fingerprint_finding)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    fingerprints.sort();
    let baseline = Baseline {
        schema: BASELINE_SCHEMA.to_string(),
        fingerprints,
    };
    let body = serde_json::to_string_pretty(&baseline)
        .map_err(|error| format!("baseline 序列化失败: {error}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    fs::write(path, format!("{body}\n"))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

pub fn fingerprint_finding(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update([0]);
    hasher.update(finding.file.as_bytes());
    hasher.update([0]);
    hasher.update(finding.title.as_bytes());
    hex(&hasher.finalize())
}

pub fn filter_baseline(findings: Vec<Finding>, baseline: &BTreeSet<String>) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| !baseline.contains(&fingerprint_finding(finding)))
        .collect()
}

pub fn merge_policies(policies: &[Policy]) -> Policy {
    let mut merged = Policy::default();
    let mut seen_allow = BTreeSet::new();
    for policy in policies {
        if !policy.profile.is_empty() {
            merged.profile = policy.profile.clone();
        }
        if policy.fail_on.is_some() {
            merged.fail_on = policy.fail_on.clone();
        }
        if policy.max_medium.is_some() {
            merged.max_medium = policy.max_medium;
        }
        for pattern in &policy.deny {
            if !merged.deny.contains(pattern) {
                merged.deny.push(pattern.clone());
            }
        }
        for exception in &policy.allow {
            let key = (
                exception.rule.clone(),
                exception.owner.clone(),
                exception.reason.clone(),
                exception.expires.clone(),
            );
            if seen_allow.insert(key) {
                merged.allow.push(exception.clone());
            }
        }
    }
    merged.deny.sort();
    merged
}

pub fn policy_bundle_hash(paths: &[PathBuf]) -> Result<Option<String>, String> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    for path in paths {
        hasher.update(file_hash(path)?.as_bytes());
        hasher.update([0]);
    }
    Ok(Some(hex(&hasher.finalize())))
}

pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {e}", path.display()))?;
    let policy: Policy = serde_json::from_str(&text)
        .map_err(|e| format!("policy 解析失败 {}: {e}", path.display()))?;
    validate_policy(&policy)?;
    Ok(policy)
}

fn parse_fail_on(value: &str) -> Result<Option<Severity>, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    Severity::parse(value)
        .map(Some)
        .ok_or_else(|| format!("invalid policy fail_on: {value}"))
}

fn validate_rule_pattern(pattern: &str, field: &str) -> Result<(), String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return Err(format!("policy {field} contains an empty rule pattern"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '*'))
    {
        return Err(format!(
            "policy {field} contains invalid rule pattern: {pattern}"
        ));
    }
    Ok(())
}

fn validate_policy(policy: &Policy) -> Result<(), String> {
    if let Some(value) = policy.fail_on.as_deref() {
        parse_fail_on(value)?;
    }
    for pattern in &policy.deny {
        validate_rule_pattern(pattern, "deny")?;
    }
    for exception in &policy.allow {
        validate_rule_pattern(&exception.rule, "allow.rule")?;
        if exception.owner.trim().is_empty() {
            return Err(format!(
                "policy allow.rule {} requires a non-empty owner",
                exception.rule
            ));
        }
        if exception.reason.trim().is_empty() {
            return Err(format!(
                "policy allow.rule {} requires a non-empty reason",
                exception.rule
            ));
        }
        if let Some(expires) = exception.expires.as_deref() {
            if parse_date_days(expires).is_none() {
                return Err(format!(
                    "policy allow.rule {} has invalid expires date: {expires}",
                    exception.rule
                ));
            }
        }
    }
    Ok(())
}

fn exception_is_active(exception: &Exception, rule_id: &str, today: i64) -> bool {
    if !rule_matches(&exception.rule, rule_id) {
        return false;
    }
    match exception.expires.as_deref() {
        None => true,
        Some(value) => parse_date_days(value)
            .map(|day| day >= today)
            .unwrap_or(false),
    }
}

pub fn evaluate(
    findings: &[Finding],
    policy: &Policy,
    default_fail_on: Option<Severity>,
) -> PolicyResult {
    let counts = Counts::from_findings(findings);
    let fail_on = match policy.fail_on.as_deref() {
        Some(value) => parse_fail_on(value).unwrap_or(None),
        None => default_fail_on,
    };
    let max_medium = policy.max_medium.unwrap_or(usize::MAX);
    let today = today_days();
    let mut reasons = Vec::new();
    let mut blocked = false;
    let mut warned = false;
    let mut effective_medium = 0usize;

    for finding in findings {
        if policy
            .deny
            .iter()
            .any(|pattern| rule_matches(pattern, &finding.rule_id))
        {
            blocked = true;
            reasons.push(format!(
                "deny {} at {}:{}",
                finding.rule_id, finding.file, finding.line
            ));
            continue;
        }
        let exception = policy
            .allow
            .iter()
            .find(|item| exception_is_active(item, &finding.rule_id, today));
        if let Some(exception) = exception {
            reasons.push(format!(
                "exception {} for {} ({})",
                finding.rule_id, exception.owner, exception.reason
            ));
            continue;
        }
        match fail_on {
            Some(threshold) if finding.severity >= threshold => {
                blocked = true;
                reasons.push(format!(
                    "{} {} at {}:{} reaches fail_on={}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file,
                    finding.line,
                    threshold.as_str()
                ));
            }
            _ if finding.severity == Severity::Medium => {
                warned = true;
                effective_medium += 1;
            }
            _ => {}
        }
    }
    if effective_medium > max_medium {
        blocked = true;
        reasons.push(format!(
            "medium findings {} exceed max_medium={}",
            effective_medium, max_medium
        ));
    }
    let decision = if blocked {
        Decision::Block
    } else if warned {
        Decision::Warn
    } else {
        Decision::Allow
    };
    PolicyResult {
        decision,
        profile: if policy.profile.is_empty() {
            "default".to_string()
        } else {
            policy.profile.clone()
        },
        reasons,
        counts,
    }
}

fn last_audit_hash(path: &Path) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read audit {}: {e}", path.display()))?;
    for line in text.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("audit chain is corrupt: {e}"))?;
        let hash = value
            .get("entry_hash")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "audit chain is corrupt: missing entry_hash".to_string())?;
        return Ok(Some(hash.to_string()));
    }
    Ok(None)
}

pub fn append_audit(path: &Path, mut entry: AuditEntry) -> Result<(), String> {
    entry.prev_hash = last_audit_hash(path)?;
    entry.entry_hash = None;
    let body =
        serde_json::to_string(&entry).map_err(|error| format!("audit 序列化失败: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    entry.entry_hash = Some(hex(&hasher.finalize()));
    let line =
        serde_json::to_string(&entry).map_err(|error| format!("audit 序列化失败: {error}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("cannot open audit {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("cannot write audit {}: {e}", path.display()))
}

#[allow(clippy::too_many_arguments)]
pub fn audit_entry(
    action: &str,
    subject: &str,
    decision: Decision,
    findings: &[Finding],
    reasons: &[String],
    policy: Option<&str>,
    policy_hash: Option<&str>,
    rules_hash: &str,
    fingerprint: Option<&str>,
) -> AuditEntry {
    AuditEntry {
        schema: "skillguard-audit/v2".to_string(),
        timestamp_unix: now_unix(),
        action: action.to_string(),
        subject: subject.to_string(),
        decision: decision.as_str().to_string(),
        findings: Counts::from_findings(findings),
        finding_digests: finding_digests(findings),
        reasons: reasons.to_vec(),
        policy: policy.map(ToOwned::to_owned),
        policy_hash: policy_hash.map(ToOwned::to_owned),
        rules_hash: rules_hash.to_string(),
        fingerprint: fingerprint.map(ToOwned::to_owned),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        prev_hash: None,
        entry_hash: None,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditVerification {
    pub path: String,
    pub entries: usize,
    pub ok: bool,
    pub errors: Vec<String>,
}

pub fn verify_audit(path: &Path) -> Result<AuditVerification, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read audit {}: {e}", path.display()))?;
    let mut previous: Option<String> = None;
    let mut entries = 0usize;
    let mut errors = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line)
            .map_err(|e| format!("audit entry {} is invalid JSON: {e}", index + 1))?;
        entries += 1;
        if entry.prev_hash != previous {
            errors.push(format!(
                "entry {} prev_hash does not match previous entry",
                index + 1
            ));
        }
        let actual = entry.entry_hash.clone();
        let mut unsigned = entry.clone();
        unsigned.entry_hash = None;
        let body = serde_json::to_string(&unsigned)
            .map_err(|e| format!("audit serialization failed: {e}"))?;
        let mut hasher = Sha256::new();
        hasher.update(body.as_bytes());
        let expected = hex(&hasher.finalize());
        if actual.as_deref() != Some(expected.as_str()) {
            errors.push(format!("entry {} hash mismatch", index + 1));
        }
        previous = actual;
    }
    Ok(AuditVerification {
        path: path.display().to_string(),
        entries,
        ok: errors.is_empty(),
        errors,
    })
}

pub fn export_audit(path: &Path, format: &str) -> Result<String, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("cannot read audit {}: {e}", path.display()))?;
    let entries: Vec<AuditEntry> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("audit entry is invalid JSON: {e}"))?;
    if format == "csv" {
        let mut out = String::from(
            "timestamp_unix,action,subject,decision,total,critical,high,medium,low,entry_hash\n",
        );
        for entry in entries {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                entry.timestamp_unix,
                csv_field(&entry.action),
                csv_field(&entry.subject),
                csv_field(&entry.decision),
                entry.findings.total,
                entry.findings.critical,
                entry.findings.high,
                entry.findings.medium,
                entry.findings.low,
                entry.entry_hash.unwrap_or_default()
            ));
        }
        return Ok(out);
    }
    serde_json::to_string_pretty(&entries).map_err(|e| format!("audit serialization failed: {e}"))
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn rule_matches(pattern: &str, rule_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return rule_id.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return rule_id.ends_with(suffix);
    }
    pattern == rule_id
}

fn parse_date_days(value: &str) -> Option<i64> {
    let mut parts = value.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

fn today_days() -> i64 {
    now_unix() as i64 / 86_400
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn finding(rule: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            title: rule.to_string(),
            severity,
            category: "test".to_string(),
            skill: "test".to_string(),
            file: "SKILL.md".to_string(),
            line: 1,
            column: 1,
            excerpt: "test".to_string(),
            message: "test".to_string(),
            remediation: "test".to_string(),
            references: Vec::new(),
        }
    }

    #[test]
    fn policy_blocks_high_and_expires_exception() {
        let policy = Policy {
            profile: "team".to_string(),
            fail_on: Some("high".to_string()),
            max_medium: Some(2),
            deny: Vec::new(),
            allow: vec![Exception {
                rule: "SG-PERM-001".to_string(),
                owner: "alice".to_string(),
                reason: "test".to_string(),
                expires: Some("2000-01-01".to_string()),
            }],
        };
        let result = evaluate(
            &[finding("SG-PERM-001", Severity::High)],
            &policy,
            Some(Severity::High),
        );
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn policy_warns_on_medium() {
        let policy = Policy {
            profile: "team".to_string(),
            fail_on: Some("high".to_string()),
            max_medium: Some(2),
            deny: Vec::new(),
            allow: Vec::new(),
        };
        let result = evaluate(
            &[finding("SG-PERM-001", Severity::Medium)],
            &policy,
            Some(Severity::High),
        );
        assert_eq!(result.decision, Decision::Warn);
    }

    #[test]
    fn active_exception_allows_high() {
        let policy = Policy {
            profile: "team".to_string(),
            fail_on: Some("high".to_string()),
            max_medium: None,
            deny: Vec::new(),
            allow: vec![Exception {
                rule: "SG-PERM-001".to_string(),
                owner: "alice".to_string(),
                reason: "approved".to_string(),
                expires: Some("2999-01-01".to_string()),
            }],
        };
        let result = evaluate(
            &[finding("SG-PERM-001", Severity::High)],
            &policy,
            Some(Severity::High),
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn policy_fail_on_none_overrides_default_threshold() {
        let policy = Policy {
            profile: "team".to_string(),
            fail_on: Some("none".to_string()),
            max_medium: None,
            deny: Vec::new(),
            allow: Vec::new(),
        };
        let result = evaluate(
            &[finding("SG-PERM-001", Severity::Critical)],
            &policy,
            Some(Severity::High),
        );
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn invalid_policy_expiry_is_rejected() {
        let policy = Policy {
            profile: "team".to_string(),
            fail_on: Some("high".to_string()),
            max_medium: None,
            deny: Vec::new(),
            allow: vec![Exception {
                rule: "SG-PERM-001".to_string(),
                owner: "alice".to_string(),
                reason: "approved".to_string(),
                expires: Some("not-a-date".to_string()),
            }],
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn unknown_policy_fields_are_rejected() {
        let parsed: Result<Policy, _> =
            serde_json::from_str(r#"{"profile":"team","fail_on":"high","typo":true}"#);
        assert!(parsed.is_err());
    }

    #[test]
    fn baseline_filters_matching_finding() {
        let finding = finding("SG-PERM-001", Severity::High);
        let mut set = BTreeSet::new();
        set.insert(fingerprint_finding(&finding));
        assert!(filter_baseline(vec![finding], &set).is_empty());
    }

    #[test]
    fn rule_prefix_matches() {
        assert!(rule_matches("SG-COMBO-*", "SG-COMBO-001"));
        assert!(rule_matches("*", "anything"));
        assert!(!rule_matches("SG-COMBO-*", "SG-PERM-001"));
    }

    #[test]
    fn date_parser_handles_iso_date() {
        assert!(parse_date_days("2026-11-20").is_some());
        assert!(parse_date_days("not-a-date").is_none());
    }
}
