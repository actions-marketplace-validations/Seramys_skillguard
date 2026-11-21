use crate::codeinsight;
use crate::guard::{self, Decision, Policy};
use crate::model::{Finding, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolCall {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeDecision {
    pub decision: String,
    pub reasons: Vec<String>,
    pub risk: u8,
}

#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub policy: Option<Policy>,
    pub audit: Option<PathBuf>,
}

fn risk_for(decision: Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::Warn => 50,
        Decision::Block => 90,
    }
}

fn rule_matches(pattern: &str, id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return id.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return id.ends_with(suffix);
    }
    pattern == id
}

fn today_iso() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn policy_allows(policy: &Policy, id: &str) -> bool {
    let today = today_iso();
    policy.allow.iter().any(|item| {
        if !rule_matches(&item.rule, id) {
            return false;
        }
        item.expires
            .as_deref()
            .map(|value| {
                let value = value.trim();
                value.len() == 10
                    && value.as_bytes().get(4) == Some(&b'-')
                    && value >= today.as_str()
            })
            .unwrap_or(true)
    })
}

fn policy_denies(policy: &Policy, id: &str) -> bool {
    policy.deny.iter().any(|pattern| rule_matches(pattern, id))
}

fn add_signal_reasons(reasons: &mut Vec<(String, Severity)>, text: &str, rule_prefix: &str) {
    if text.trim().is_empty() {
        return;
    }
    let analysis = codeinsight::analyze(text, true);
    for signal in analysis.signals {
        let severity = match signal.id {
            "credential_exfil" | "download_exec" => Severity::Critical,
            "hidden_bootstrap" | "windows_account" | "persistence" | "encoded_exec"
            | "credential_read" | "concealment" => Severity::High,
            _ => Severity::Medium,
        };
        reasons.push((
            format!("{rule_prefix}:{}:{}", signal.id, signal.message),
            severity,
        ));
    }
    let lower = text.to_ascii_lowercase();
    let destructive = [
        "rm -rf /",
        "rm -fr /",
        "format c:",
        "diskpart",
        "mkfs.",
        "shutdown /s",
        "shutdown -h",
        "remove-item -recurse",
        "del /f /s /q c:\\",
        "drop database",
        "truncate table",
    ];
    if destructive.iter().any(|needle| lower.contains(needle)) {
        reasons.push((
            format!("{rule_prefix}:destructive:破坏性命令"),
            Severity::Critical,
        ));
    }
}

fn evaluate_signals(call: &ToolCall) -> Vec<(String, Severity)> {
    let mut reasons = Vec::new();
    add_signal_reasons(&mut reasons, &call.command, "RT-CMD");
    add_signal_reasons(&mut reasons, &call.content, "RT-CONTENT");
    if !call.arguments.is_null() {
        let text = call.arguments.to_string();
        add_signal_reasons(&mut reasons, &text, "RT-ARGS");
    }

    if !call.command.trim().is_empty() {
        let tool = call.tool.to_ascii_lowercase();
        if tool.contains("shell")
            || tool.contains("bash")
            || tool.contains("exec")
            || tool.contains("terminal")
        {
            reasons.push((
                "RT-CMD:tool:shell tool invocation".to_string(),
                Severity::Medium,
            ));
        }
    }

    let path = call.path.to_ascii_lowercase();
    if !path.is_empty()
        && [
            ".ssh",
            "id_rsa",
            "id_ed25519",
            ".aws/credentials",
            ".env",
            ".npmrc",
            ".netrc",
            "/etc/passwd",
            "/etc/shadow",
            "wallet.dat",
            "login data",
            "cookies.sqlite",
        ]
        .iter()
        .any(|needle| path.contains(needle))
    {
        reasons.push((
            "RT-PATH:sensitive:读取敏感凭证/账户文件".to_string(),
            Severity::High,
        ));
    }

    if !call.url.trim().is_empty() {
        let lower = call.url.to_ascii_lowercase();
        if lower.starts_with("http://") {
            reasons.push((
                "RT-NET:plaintext:使用明文 HTTP 外联".to_string(),
                Severity::High,
            ));
        } else if !(lower.contains("127.0.0.1")
            || lower.contains("localhost")
            || lower.contains("::1"))
        {
            reasons.push(("RT-NET:external:外部网络外联".to_string(), Severity::Medium));
        }
    }

    if call.server.to_ascii_lowercase().contains("mcp")
        || call.tool.to_ascii_lowercase().contains("mcp")
    {
        reasons.push(("RT-MCP:tool:MCP/远程工具调用".to_string(), Severity::Medium));
    }
    reasons
}

pub fn evaluate_call(call: &ToolCall, options: &RuntimeOptions) -> RuntimeDecision {
    let mut reasons = Vec::new();
    let mut blocked = false;
    let mut review = false;
    let fail_on = options
        .policy
        .as_ref()
        .and_then(|policy| policy.fail_on.as_deref())
        .and_then(Severity::parse)
        .unwrap_or(Severity::High);
    let signals = evaluate_signals(call);

    for (reason, severity) in signals {
        let id = reason.split(':').take(3).collect::<Vec<_>>().join("-");
        if options
            .policy
            .as_ref()
            .map(|policy| policy_allows(policy, &id))
            .unwrap_or(false)
        {
            reasons.push(format!("allowed by policy: {reason}"));
            continue;
        }
        if options
            .policy
            .as_ref()
            .map(|policy| policy_denies(policy, &id))
            .unwrap_or(false)
        {
            blocked = true;
            reasons.push(format!("deny {id}: {reason}"));
            continue;
        }
        if severity >= fail_on {
            blocked = true;
            reasons.push(reason);
        } else {
            review = true;
            reasons.push(reason);
        }
    }

    let decision = if blocked {
        Decision::Block
    } else if review {
        Decision::Warn
    } else {
        Decision::Allow
    };
    RuntimeDecision {
        decision: decision.as_str().to_string(),
        reasons,
        risk: risk_for(decision),
    }
}

fn audit_runtime(
    path: &Path,
    call: &ToolCall,
    decision: &RuntimeDecision,
    options: &RuntimeOptions,
) -> Result<(), String> {
    let findings: Vec<Finding> = Vec::new();
    let entry = guard::audit_entry(
        "admit",
        if call.tool.is_empty() {
            "tool-call"
        } else {
            &call.tool
        },
        match decision.decision.as_str() {
            "BLOCK" => Decision::Block,
            "REVIEW" => Decision::Warn,
            _ => Decision::Allow,
        },
        &findings,
        &decision.reasons,
        options
            .policy
            .as_ref()
            .map(|policy| policy.profile.as_str()),
        None,
        &guard::builtin_rules_hash(),
        None,
    );
    guard::append_audit(path, entry)
}

pub fn run_admit_stdin(options: &RuntimeOptions) -> Result<i32, String> {
    let stdin = std::io::stdin();
    let mut blocked = false;
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("cannot read stdin: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let (call, decision) = match serde_json::from_str::<ToolCall>(&line) {
            Ok(call) => {
                let decision = evaluate_call(&call, options);
                (call, decision)
            }
            Err(error) => {
                blocked = true;
                let decision = RuntimeDecision {
                    decision: "BLOCK".to_string(),
                    reasons: vec![format!("invalid tool-call JSON: {error}")],
                    risk: 100,
                };
                (
                    ToolCall {
                        tool: "invalid-input".into(),
                        ..ToolCall::default()
                    },
                    decision,
                )
            }
        };
        if decision.decision == "BLOCK" {
            blocked = true;
        }
        if let Some(path) = &options.audit {
            audit_runtime(path, &call, &decision, options)?;
        }
        println!(
            "{}",
            serde_json::to_string(&decision)
                .map_err(|error| format!("cannot serialize runtime decision: {error}"))?
        );
    }
    Ok(if blocked { 1 } else { 0 })
}

fn http_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn handle_http(mut stream: std::net::TcpStream, options: &RuntimeOptions) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos;
                }
                if buffer.len() > 2 * 1024 * 1024 {
                    http_response(
                        &mut stream,
                        "413 Payload Too Large",
                        r#"{"error":"request too large"}"#,
                    );
                    return;
                }
            }
            Err(_) => return,
        }
    };
    let header = String::from_utf8_lossy(&buffer[..header_end]);
    let mut parts = header.lines().next().unwrap_or_default().split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if method == "GET" && path == "/health" {
        http_response(&mut stream, "200 OK", r#"{"ok":true}"#);
        return;
    }
    if method != "POST" || path != "/admit" {
        http_response(&mut stream, "404 Not Found", r#"{"error":"not found"}"#);
        return;
    }
    let content_length = header
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let body = String::from_utf8_lossy(
        &buffer[body_start..(body_start + content_length).min(buffer.len())],
    );
    let call = match serde_json::from_str::<ToolCall>(&body) {
        Ok(call) => call,
        Err(error) => {
            http_response(
                &mut stream,
                "400 Bad Request",
                &format!(
                    r#"{{"decision":"BLOCK","reasons":["invalid JSON: {}"]}}"#,
                    error.to_string().replace('"', "'")
                ),
            );
            return;
        }
    };
    let decision = evaluate_call(&call, options);
    if let Some(path) = &options.audit {
        let _ = audit_runtime(path, &call, &decision, options);
    }
    let body =
        serde_json::to_string(&decision).unwrap_or_else(|_| r#"{"decision":"BLOCK"}"#.to_string());
    let status = if decision.decision == "BLOCK" {
        "403 Forbidden"
    } else if decision.decision == "REVIEW" {
        "202 Accepted"
    } else {
        "200 OK"
    };
    http_response(&mut stream, status, &body);
}

pub fn run_gateway(bind: &str, once: bool, options: &RuntimeOptions) -> Result<i32, String> {
    let listener = TcpListener::bind(bind)
        .map_err(|error| format!("cannot bind runtime gateway on {bind}: {error}"))?;
    eprintln!("skillguard runtime gateway listening on http://{bind}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_http(stream, options);
                if once {
                    break;
                }
            }
            Err(error) => eprintln!("gateway connection error: {error}"),
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> RuntimeOptions {
        RuntimeOptions {
            policy: None,
            audit: None,
        }
    }

    #[test]
    fn blocks_destructive_command() {
        let call = ToolCall {
            tool: "shell".into(),
            command: "rm -rf / --no-preserve-root".into(),
            ..ToolCall::default()
        };
        let result = evaluate_call(&call, &options());
        assert_eq!(result.decision, "BLOCK");
    }

    #[test]
    fn reviews_external_network() {
        let call = ToolCall {
            tool: "http".into(),
            url: "https://example.com/upload".into(),
            ..ToolCall::default()
        };
        let result = evaluate_call(&call, &options());
        assert_eq!(result.decision, "REVIEW");
    }

    #[test]
    fn allows_local() {
        let call = ToolCall {
            tool: "read".into(),
            path: "./notes.md".into(),
            ..ToolCall::default()
        };
        let result = evaluate_call(&call, &options());
        assert_eq!(result.decision, "ALLOW");
    }

    #[test]
    fn blocks_sensitive_path() {
        let call = ToolCall {
            tool: "read".into(),
            path: "~/.ssh/id_rsa".into(),
            ..ToolCall::default()
        };
        let result = evaluate_call(&call, &options());
        assert_eq!(result.decision, "BLOCK");
    }
}
