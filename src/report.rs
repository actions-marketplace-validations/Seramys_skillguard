use crate::engine::ScanOutcome;
use crate::model::{Severity, Summary};
use crate::rules::CompiledRule;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Write};

pub fn summary(outcome: &ScanOutcome) -> Summary {
    Summary::from_findings(outcome.skills.len(), outcome.files, &outcome.findings)
}

fn display_root(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        text
    }
}

pub fn failed(summary: &Summary, threshold: Option<Severity>) -> bool {
    let Some(threshold) = threshold else {
        return false;
    };
    [
        (Severity::Critical, summary.critical),
        (Severity::High, summary.high),
        (Severity::Medium, summary.medium),
        (Severity::Low, summary.low),
    ]
    .iter()
    .any(|(severity, count)| *count > 0 && *severity >= threshold)
}

pub fn use_color(explicit_no_color: bool) -> bool {
    !explicit_no_color && io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

pub fn print_text(
    outcome: &ScanOutcome,
    version: &str,
    threshold: Option<Severity>,
    color: bool,
    quiet: bool,
) -> bool {
    let s = summary(outcome);
    let mut out = String::new();

    if !quiet {
        out.push_str(&format!(
            "SkillGuard {}  |  root: {}\n",
            version,
            display_root(&outcome.root)
        ));
        out.push_str(&format!(
            "scanned {} skill(s), {} file(s)\n\n",
            s.skills, s.files
        ));
    }

    if outcome.findings.is_empty() {
        out.push_str("No findings.\n");
    } else {
        for f in &outcome.findings {
            let label = if color {
                format!(
                    "{}{}\x1b[0m",
                    f.severity.ansi(),
                    f.severity.as_str().to_uppercase()
                )
            } else {
                f.severity.as_str().to_uppercase()
            };
            out.push_str(&format!("[{}] {}  {}\n", label, f.rule_id, f.title));
            out.push_str(&format!("  skill: {}\n", f.skill));
            out.push_str(&format!("  at: {}:{}:{}\n", f.file, f.line, f.column));
            if !f.excerpt.is_empty() {
                out.push_str(&format!("  excerpt: {}\n", f.excerpt));
            }
            if !f.message.is_empty() {
                out.push_str(&format!("  why: {}\n", f.message));
            }
            if !f.remediation.is_empty() {
                out.push_str(&format!("  fix: {}\n", f.remediation));
            }
            if !f.references.is_empty() {
                out.push_str(&format!("  ref: {}\n", f.references.join(", ")));
            }
            out.push('\n');
        }
    }

    if !quiet {
        out.push_str("────────────────────────────────────────\n");
        out.push_str(&format!(
            "{} skill(s), {} file(s), {} finding(s)\n",
            s.skills, s.files, s.total
        ));
        out.push_str(&format!(
            "critical {} | high {} | medium {} | low {}\n",
            s.critical, s.high, s.medium, s.low
        ));
        let fail = failed(&s, threshold);
        out.push_str(if fail {
            "Result: FAIL\n"
        } else {
            "Result: PASS\n"
        });
    }

    print!("{out}");
    let _ = io::stdout().flush();
    failed(&s, threshold)
}

pub fn print_review(
    outcome: &ScanOutcome,
    version: &str,
    decision: Option<&str>,
    reasons: &[String],
    detailed: bool,
    color: bool,
    quiet: bool,
) {
    let s = summary(outcome);
    let mut out = String::new();
    if !quiet {
        out.push_str(&format!(
            "SkillGuard {}  |  {}\n",
            version,
            if detailed { "explain" } else { "review" }
        ));
        out.push_str(&format!(
            "root: {}\nscanned {} skill(s), {} file(s)\n",
            display_root(&outcome.root),
            s.skills,
            s.files
        ));
        if let Some(decision) = decision {
            out.push_str(&format!("admission: {decision}"));
            if !reasons.is_empty() {
                out.push_str(&format!(" — {}", reasons.join("; ")));
            }
            out.push('\n');
        }
        out.push('\n');
    }

    if !outcome.capabilities.is_empty() {
        out.push_str("Capability evidence\n");
        for cap in &outcome.capabilities {
            let source = if cap.declared { "declared" } else { "observed" };
            out.push_str(&format!(
                "  [{}] {} -> {}  ({}:{})\n",
                source, cap.kind, cap.target, cap.file, cap.line
            ));
            if detailed {
                out.push_str(&format!("      evidence: {}\n", cap.evidence));
            }
        }
        out.push('\n');
    }

    if outcome.findings.is_empty() {
        out.push_str("No findings.\n");
    } else {
        out.push_str("Review candidates\n");
        for f in &outcome.findings {
            let label = if color {
                format!(
                    "{}{}\x1b[0m",
                    f.severity.ansi(),
                    f.severity.as_str().to_uppercase()
                )
            } else {
                f.severity.as_str().to_uppercase()
            };
            out.push_str(&format!(
                "  [{}] {}  {}  ({}:{})\n",
                label, f.rule_id, f.title, f.file, f.line
            ));
            if detailed {
                if !f.excerpt.is_empty() {
                    out.push_str(&format!("      excerpt: {}\n", f.excerpt));
                }
                if !f.message.is_empty() {
                    out.push_str(&format!("      why: {}\n", f.message));
                }
                if !f.remediation.is_empty() {
                    out.push_str(&format!("      fix: {}\n", f.remediation));
                }
                if !f.references.is_empty() {
                    out.push_str(&format!("      ref: {}\n", f.references.join(", ")));
                }
            }
        }
        out.push('\n');
    }

    if !quiet {
        out.push_str(&format!(
            "{} finding(s): critical {} | high {} | medium {} | low {}\n",
            s.total, s.critical, s.high, s.medium, s.low
        ));
    }
    print!("{out}");
    let _ = io::stdout().flush();
}

pub fn evidence_graph(outcome: &ScanOutcome) -> Value {
    let mut nodes: Vec<Value> = Vec::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut seen_nodes = BTreeSet::new();
    for skill in &outcome.skills {
        let id = format!("skill:{skill}");
        if seen_nodes.insert(id.clone()) {
            nodes.push(json!({"id": id, "type": "skill", "label": skill}));
        }
    }
    for cap in &outcome.capabilities {
        let id = format!(
            "capability:{}:{}:{}:{}",
            cap.skill, cap.kind, cap.target, cap.file
        );
        if seen_nodes.insert(id.clone()) {
            nodes.push(json!({
                "id": id,
                "type": cap.kind,
                "label": cap.target,
                "declared": cap.declared,
                "file": cap.file,
                "line": cap.line,
                "evidence": cap.evidence
            }));
        }
        edges.push(json!({
            "from": format!("skill:{}", cap.skill),
            "to": id,
            "relation": if cap.declared { "declares" } else { "observes" }
        }));
    }
    json!({"nodes": nodes, "edges": edges})
}

pub fn to_json(outcome: &ScanOutcome, version: &str, pretty: bool) -> String {
    let s = summary(outcome);
    let doc = json!({
        "tool": "skillguard",
        "version": version,
        "root": display_root(&outcome.root),
        "summary": &s,
        "findings": &outcome.findings,
        "capabilities": &outcome.capabilities,
        "evidence_graph": evidence_graph(outcome),
        "semantic": &outcome.semantic,
    });
    if pretty {
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    } else {
        serde_json::to_string(&doc).unwrap_or_default()
    }
}

pub fn to_github(outcome: &ScanOutcome) -> String {
    let mut out = String::new();
    for f in &outcome.findings {
        let level = match f.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "notice",
        };
        let message = if f.message.is_empty() {
            f.title.clone()
        } else {
            format!("{}: {}", f.title, f.message)
        };
        out.push_str(&format!(
            "::{level} file={},line={},col={}::{} {}\n",
            f.file.replace('%', "%25").replace('\n', "%0A"),
            f.line,
            f.column,
            f.rule_id,
            message
                .replace('%', "%25")
                .replace('\r', "%0D")
                .replace('\n', "%0A")
        ));
    }
    out
}

pub fn to_sarif(outcome: &ScanOutcome, version: &str, rules: &[CompiledRule]) -> String {
    let mut seen = BTreeSet::new();
    let mut rule_meta: Vec<Value> = Vec::new();
    for cr in rules {
        if !seen.insert(cr.rule.id.clone()) {
            continue;
        }
        rule_meta.push(json!({
            "id": &cr.rule.id,
            "name": &cr.rule.title,
            "shortDescription": { "text": &cr.rule.title },
            "fullDescription": { "text": &cr.rule.description },
            "help": {
                "text": if cr.rule.remediation.is_empty() {
                    cr.rule.description.clone()
                } else {
                    cr.rule.remediation.clone()
                }
            },
            "defaultConfiguration": { "level": cr.rule.severity.sarif_level() },
            "properties": {
                "category": &cr.rule.category,
                "severity": cr.rule.severity.as_str()
            }
        }));
    }

    let results: Vec<Value> = outcome
        .findings
        .iter()
        .map(|f| {
            let message = if f.message.is_empty() {
                f.title.clone()
            } else {
                format!("{}: {}", f.title, f.message)
            };
            json!({
                "ruleId": &f.rule_id,
                "level": f.severity.sarif_level(),
                "message": { "text": message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file.replace('\\', "/") },
                        "region": { "startLine": f.line, "startColumn": f.column }
                    }
                }],
                "partialFingerprints": {
                    "skillguard/v1": format!("{}:{}:{}", f.rule_id, f.file, f.line)
                }
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SkillGuard",
                    "version": version,
                    "informationUri": "https://github.com/Seramys/skillguard",
                    "rules": rule_meta
                }
            },
            "results": results
        }]
    });
    serde_json::to_string(&doc).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Finding;

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: "SG-TEST-001".into(),
            title: "test".into(),
            severity,
            category: "test".into(),
            skill: "demo".into(),
            file: "SKILL.md".into(),
            line: 1,
            column: 1,
            excerpt: String::new(),
            message: String::new(),
            remediation: String::new(),
            references: Vec::new(),
        }
    }

    #[test]
    fn fail_threshold_logic() {
        let s = Summary::from_findings(1, 1, &[finding(Severity::High)]);
        assert!(failed(&s, Some(Severity::High)));
        assert!(failed(&s, Some(Severity::Medium)));
        assert!(!failed(&s, Some(Severity::Critical)));
        assert!(!failed(&s, None));
    }

    #[test]
    fn summary_counts() {
        let findings = vec![
            finding(Severity::Critical),
            finding(Severity::High),
            finding(Severity::Low),
        ];
        let s = Summary::from_findings(1, 3, &findings);
        assert_eq!(
            (s.critical, s.high, s.medium, s.low, s.total),
            (1, 1, 0, 1, 3)
        );
    }
}
