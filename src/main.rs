mod codeinsight;
mod config;
mod engine;
mod frontmatter;
mod guard;
mod install;
mod model;
mod pyc;
mod report;
mod rules;
mod runtime;
mod semantic;

use engine::ScanOptions;
use model::Severity;
use regex::Regex;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BOOL_FLAGS: &[&str] = &[
    "no-color",
    "quiet",
    "json-pretty",
    "json",
    "force",
    "yes",
    "dry-run",
    "keep-quarantine",
    "semantic",
    "once",
    "help",
];

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        print_help();
        return 0;
    };
    let rest = &args[1..];
    let result = match command {
        "scan" => cmd_scan(rest),
        "review" => cmd_scan(&with_format(rest, "review")),
        "explain" => cmd_scan(&with_format(rest, "explain")),
        "lock" => cmd_lock(rest),
        "install" => cmd_install(rest),
        "verify" => cmd_verify(rest),
        "semantic" => cmd_semantic(rest),
        "admit" => cmd_admit(rest),
        "gateway" => cmd_gateway(rest),
        "audit" => cmd_audit(rest),
        "policy" => cmd_policy(rest),
        "rules" => cmd_rules(rest),
        "init" => cmd_init(rest),
        "version" | "--version" | "-V" => {
            println!("skillguard {VERSION}");
            Ok(0)
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(0)
        }
        other => Err(format!(
            "unknown command: {other}\nRun `skillguard help` for usage."
        )),
    };
    match result {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            2
        }
    }
}

fn print_help() {
    println!(
        r#"SkillGuard {VERSION} - AI Agent Skill supply-chain security scanner

Usage:
  skillguard scan <path> [options]
  skillguard review <path> [options]       Human review queue + capability evidence
  skillguard explain <path> [options]      Review queue with excerpts and remediation
  skillguard semantic check <path> [options]
  skillguard semantic embed <text> [options]
  skillguard admit [--policy file] [--audit file]       JSONL tool-call admission on stdin
  skillguard gateway [--bind 127.0.0.1:8787] [--once]   Local HTTP admission gateway
  skillguard audit verify <audit.jsonl>
  skillguard audit export <audit.jsonl> [--format json|csv]
  skillguard lock <path> [--output skillguard.lock]
  skillguard verify <path> [--lock skillguard.lock]
  skillguard policy validate <file.json>
  skillguard policy merge <base.json> <overlay.json> [--output file]
  skillguard install <source> [options]   (experimental: P1 install rail)
  skillguard rules list
  skillguard rules validate <file.json|dir>
  skillguard init [dir] [--force]
  skillguard version

Scan options:
  --format text|json|sarif|github|review|explain
                                 Output format (default: text)
  --fail-on none|low|medium|high|critical
                                 Exit 1 when a finding reaches this severity (default: high)
  --min-severity low|medium|high|critical
                                 Hide findings below this severity (default: low)
  --policy <file>                Policy gate (default: .skillguard-policy.json if present)
  --baseline <file>              Hide findings recorded in a baseline
  --write-baseline <file>        Write current findings as a baseline
  --audit <file>                 Append a JSONL audit record
  --ignore SG-XX-001[,SG-YY-*]   Ignore rules by id or prefix
  --allow-domain <domain>        Allow network findings for a domain (repeatable/comma)
  --rules <dir>                  Load extra JSON rule packs (overrides by id)
  --config <file>                Config file (default: .skillguard.json)
  --max-file-size <kb>           Skip text scanning above this size (default: 512)
  --no-color                     Disable ANSI colors
  --quiet                        Hide header and summary
  --json-pretty                  Pretty-print JSON output

Semantic options (optional; no model is bundled and no network is used by default):
  --semantic                     Enable the configured local/remote model layer
  --semantic-provider <name>     ollama | openai | custom (default: ollama)
  --semantic-endpoint <url>      OpenAI-compatible base URL
  --semantic-model <name>        Chat model (e.g. qwen2.5:3b-instruct-q4_K_M)
  --embedding-endpoint <url>     OpenAI-compatible embedding base URL
  --embedding-model <name>       Embedding model (e.g. bge-m3)
  --api-key-env <var>            Read the API key from this environment variable
  --semantic-timeout <secs>      Request timeout (default: 60)
  --min-risk <0-100>             Minimum semantic risk to emit a finding (default: 70)

Lock / verify options:
  --output <file>                Lockfile path (default: skillguard.lock)
  --source <label>               Source label stored in the lockfile
  --lock <file>                  Verify against a lockfile instead of an install receipt
  --json                         Machine-readable result
  --audit <file>                 Append a JSONL audit record

Policy file:
  {{
    "profile": "team",
    "fail_on": "high",
    "max_medium": 10,
    "deny": ["SG-COMBO-001"],
    "allow": [{{"rule": "SG-PERM-001", "owner": "alice",
               "reason": "approved", "expires": "2026-12-31"}}]
  }}

Examples:
  skillguard scan ./skills --policy .skillguard-policy.json --audit .skillguard-audit.jsonl
  skillguard scan ./skills --write-baseline baseline.json
  skillguard lock ./my-skill --output skillguard.lock
  skillguard verify ./my-skill --lock skillguard.lock
  skillguard install https://github.com/owner/repo --target claude --yes
"#
    );
}

struct ParsedArgs {
    positional: Vec<String>,
    flags: BTreeMap<String, Vec<String>>,
}

impl ParsedArgs {
    fn has(&self, key: &str) -> bool {
        self.flags.contains_key(key)
    }

    fn one(&self, key: &str) -> Option<&str> {
        self.flags
            .get(key)
            .and_then(|values| values.last())
            .map(String::as_str)
    }

    fn all(&self, key: &str) -> Vec<String> {
        self.flags.get(key).cloned().unwrap_or_default()
    }
}

fn with_format(args: &[String], format: &str) -> Vec<String> {
    let mut out = args.to_vec();
    out.push("--format".to_string());
    out.push(format.to_string());
    out
}

fn parse_args(args: &[String], known: &[&str]) -> Result<ParsedArgs, String> {
    let mut positional = Vec::new();
    let mut flags: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut index = 0usize;
    let mut after_separator = false;

    while index < args.len() {
        let arg = &args[index];
        if after_separator {
            positional.push(arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            after_separator = true;
            index += 1;
            continue;
        }
        if arg == "-h" || arg == "--help" {
            flags
                .entry("help".to_string())
                .or_default()
                .push("true".into());
            index += 1;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--") {
            let (key, inline) = match rest.split_once('=') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => (rest.to_string(), None),
            };
            if !known.contains(&key.as_str()) {
                return Err(format!("unknown option --{key}"));
            }
            if let Some(value) = inline {
                flags.entry(key).or_default().push(value);
            } else if BOOL_FLAGS.contains(&key.as_str()) {
                flags.entry(key).or_default().push("true".into());
            } else if index + 1 < args.len() && !args[index + 1].starts_with("--") {
                flags.entry(key).or_default().push(args[index + 1].clone());
                index += 1;
            } else {
                return Err(format!("option --{key} requires a value"));
            }
        } else if arg.starts_with('-') && arg != "-" {
            return Err(format!("unknown option {arg}"));
        } else {
            positional.push(arg.clone());
        }
        index += 1;
    }

    Ok(ParsedArgs { positional, flags })
}

fn cmd_lock(args: &[String]) -> Result<i32, String> {
    let parsed = parse_args(
        args,
        &["output", "source", "policy", "json", "audit", "help"],
    )?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }
    let target = parsed.positional.first().map(String::as_str).unwrap_or(".");
    let root = PathBuf::from(target);
    if !root.exists() {
        return Err(format!("path not found: {}", root.display()));
    }
    let output = PathBuf::from(parsed.one("output").unwrap_or("skillguard.lock"));
    let source = parsed.one("source").unwrap_or(target);
    let policy_path = parsed.one("policy").map(PathBuf::from);
    let policy_hash = match &policy_path {
        Some(path) => {
            guard::load_policy(path)?;
            Some(guard::file_hash(path)?)
        }
        None => None,
    };
    let rules_hash = guard::builtin_rules_hash();
    let findings = scan_for_guard(&root)?;
    let lock = guard::write_lock(
        &root,
        &output,
        source,
        &findings,
        &rules_hash,
        policy_hash.as_deref(),
    )?;
    if let Some(audit) = parsed.one("audit") {
        let entry = guard::audit_entry(
            "lock",
            &root.display().to_string(),
            guard::Decision::Allow,
            &findings,
            &[],
            policy_path
                .as_ref()
                .map(|path| path.display().to_string())
                .as_deref(),
            policy_hash.as_deref(),
            &rules_hash,
            Some(&lock.fingerprint),
        );
        guard::append_audit(Path::new(audit), entry)?;
    }
    if parsed.has("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&lock)
                .map_err(|error| format!("cannot serialize lockfile: {error}"))?
        );
    } else {
        println!("SkillGuard {VERSION}  |  lock");
        println!("skill: {}", lock.skill);
        println!("source: {}", lock.source);
        println!("files: {}", lock.files.len());
        println!("fingerprint: {}", lock.fingerprint);
        println!("findings: {} total", lock.findings.total);
        println!("lockfile: {}", output.display());
    }
    Ok(0)
}

fn cmd_audit(args: &[String]) -> Result<i32, String> {
    let subcommand = args.first().map(String::as_str).unwrap_or("verify");
    let rest = &args[1..];
    let parsed = parse_args(rest, &["format", "json", "help"])?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }
    let Some(path) = parsed.positional.first() else {
        return Err(format!(
            "usage: skillguard audit {subcommand} <audit.jsonl>"
        ));
    };
    let path = Path::new(path);
    match subcommand {
        "verify" => {
            let result = guard::verify_audit(path)?;
            if parsed.has("json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result)
                        .map_err(|error| format!("cannot serialize audit verification: {error}"))?
                );
            } else if result.ok {
                println!("OK: {} audit entries, hash chain valid", result.entries);
            } else {
                println!("FAIL: {} audit entries", result.entries);
                for error in &result.errors {
                    println!("  {error}");
                }
            }
            Ok(if result.ok { 0 } else { 1 })
        }
        "export" => {
            let format = parsed.one("format").unwrap_or("json");
            if !matches!(format, "json" | "csv") {
                return Err(format!("invalid audit export format: {format}"));
            }
            print!("{}", guard::export_audit(path, format)?);
            Ok(0)
        }
        other => Err(format!("unknown audit subcommand: {other}")),
    }
}

fn cmd_policy(args: &[String]) -> Result<i32, String> {
    let subcommand = args.first().map(String::as_str).unwrap_or("validate");
    match subcommand {
        "validate" => {
            let Some(path) = args.get(1) else {
                return Err("usage: skillguard policy validate <file.json>".into());
            };
            let policy = guard::load_policy(Path::new(path))?;
            println!(
                "OK: profile={} fail_on={} max_medium={} deny={} exceptions={}",
                if policy.profile.is_empty() {
                    "default"
                } else {
                    policy.profile.as_str()
                },
                policy.fail_on.as_deref().unwrap_or("high"),
                policy
                    .max_medium
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unlimited".to_string()),
                policy.deny.len(),
                policy.allow.len()
            );
            Ok(0)
        }
        "merge" => {
            let parsed = parse_args(&args[1..], &["output", "json", "help"])?;
            if parsed.has("help") {
                print_help();
                return Ok(0);
            }
            if parsed.positional.is_empty() {
                return Err(
                    "usage: skillguard policy merge <base.json> <overlay.json> [--output file]"
                        .into(),
                );
            }
            let policies = parsed
                .positional
                .iter()
                .map(|path| guard::load_policy(Path::new(path)))
                .collect::<Result<Vec<_>, _>>()?;
            let merged = guard::merge_policies(&policies);
            let body = serde_json::to_string_pretty(&merged)
                .map_err(|error| format!("cannot serialize merged policy: {error}"))?;
            match parsed.one("output") {
                Some(path) => {
                    fs::write(path, format!("{body}\n"))
                        .map_err(|error| format!("cannot write {path}: {error}"))?;
                }
                None => println!("{body}"),
            }
            Ok(0)
        }
        other => Err(format!("unknown policy subcommand: {other}")),
    }
}

fn apply_semantic_overrides(
    cfg: &mut semantic::SemanticConfig,
    parsed: &ParsedArgs,
) -> Result<(), String> {
    if let Some(value) = parsed.one("semantic-provider") {
        cfg.provider = Some(value.to_string());
    }
    if let Some(value) = parsed.one("semantic-endpoint") {
        cfg.endpoint = Some(value.to_string());
    }
    if let Some(value) = parsed.one("semantic-model") {
        cfg.model = Some(value.to_string());
    }
    if let Some(value) = parsed.one("embedding-endpoint") {
        cfg.embedding_endpoint = Some(value.to_string());
    }
    if let Some(value) = parsed.one("embedding-model") {
        cfg.embedding_model = Some(value.to_string());
    }
    if let Some(value) = parsed.one("api-key-env") {
        cfg.api_key_env = Some(value.to_string());
    }
    if let Some(value) = parsed.one("semantic-timeout") {
        cfg.timeout_secs = Some(
            value
                .parse()
                .map_err(|_| format!("invalid --semantic-timeout: {value}"))?,
        );
    }
    if let Some(value) = parsed.one("min-risk") {
        cfg.min_risk = Some(
            value
                .parse()
                .map_err(|_| format!("invalid --min-risk: {value}"))?,
        );
    }
    Ok(())
}

fn cmd_semantic(args: &[String]) -> Result<i32, String> {
    let subcommand = args.first().map(String::as_str).unwrap_or("check");
    let rest = &args[1..];
    let known = [
        "config",
        "json",
        "semantic-provider",
        "semantic-endpoint",
        "semantic-model",
        "embedding-endpoint",
        "embedding-model",
        "api-key-env",
        "semantic-timeout",
        "min-risk",
        "help",
    ];
    let parsed = parse_args(rest, &known)?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }
    let target = parsed.positional.first().map(PathBuf::from);
    let cfg_base = match parsed.one("config") {
        Some(path) => config::load(Path::new(path))?,
        None => match target.as_deref().and_then(config::discover) {
            Some(path) => config::load(&path)?,
            None => config::Config::default(),
        },
    };
    let mut semantic_cfg = cfg_base.semantic;
    apply_semantic_overrides(&mut semantic_cfg, &parsed)?;
    let settings = semantic::Settings::from_config(&semantic_cfg)?;

    match subcommand {
        "check" => {
            let Some(root) = target else {
                return Err("usage: skillguard semantic check <path> [options]".into());
            };
            let verdicts = semantic::check_path(&root, &settings)?;
            if parsed.has("json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&verdicts)
                        .map_err(|error| format!("cannot serialize verdicts: {error}"))?
                );
            } else {
                println!("SkillGuard {VERSION}  |  semantic check");
                println!(
                    "endpoint: {}  model: {}  provider: openai-compatible",
                    settings.endpoint, settings.model
                );
                for verdict in verdicts {
                    println!(
                        "{}  risk={}  labels={}  {}",
                        verdict.path,
                        verdict.risk,
                        if verdict.labels.is_empty() {
                            "-".to_string()
                        } else {
                            verdict.labels.join(",")
                        },
                        verdict.reason
                    );
                }
            }
            Ok(0)
        }
        "embed" => {
            let text = parsed.positional.join(" ");
            if text.trim().is_empty() {
                return Err("usage: skillguard semantic embed <text> [options]".into());
            }
            let value = semantic::embed_debug(&text, &semantic_cfg)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value)
                    .map_err(|error| format!("cannot serialize embedding: {error}"))?
            );
            Ok(0)
        }
        other => Err(format!("unknown semantic subcommand: {other}")),
    }
}

fn runtime_options(parsed: &ParsedArgs) -> Result<runtime::RuntimeOptions, String> {
    let policy = match parsed.one("policy") {
        Some(path) => Some(guard::load_policy(Path::new(path))?),
        None => None,
    };
    Ok(runtime::RuntimeOptions {
        policy,
        audit: parsed.one("audit").map(PathBuf::from),
    })
}

fn cmd_admit(args: &[String]) -> Result<i32, String> {
    let parsed = parse_args(args, &["policy", "audit", "help"])?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }
    let options = runtime_options(&parsed)?;
    runtime::run_admit_stdin(&options)
}

fn cmd_gateway(args: &[String]) -> Result<i32, String> {
    let parsed = parse_args(args, &["policy", "audit", "bind", "once", "help"])?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }
    let options = runtime_options(&parsed)?;
    let bind = parsed.one("bind").unwrap_or("127.0.0.1:8787");
    if !bind.starts_with("127.0.0.1:")
        && !bind.starts_with("localhost:")
        && !bind.starts_with("[::1]:")
    {
        return Err(
            "gateway 默认只允许绑定本机回环地址；如需暴露到网络，请在前面加一层受控反向代理".into(),
        );
    }
    runtime::run_gateway(bind, parsed.has("once"), &options)
}

fn scan_for_guard(root: &Path) -> Result<Vec<model::Finding>, String> {
    let compiled = rules::compile_all(rules::load_builtin()?)?;
    let opts = ScanOptions {
        min_severity: Severity::Low,
        fail_on: Some(Severity::High),
        ignore_rules: Vec::new(),
        allow_domains: Vec::new(),
        max_file_size: 512 * 1024,
        exclude: Vec::new(),
    };
    Ok(engine::scan(root, &compiled, &opts)?.findings)
}

fn cmd_install(args: &[String]) -> Result<i32, String> {
    let known = [
        "dest",
        "target",
        "ref",
        "path",
        "rules",
        "policy",
        "audit",
        "allow-domain",
        "ignore",
        "yes",
        "force",
        "dry-run",
        "keep-quarantine",
        "json",
        "help",
    ];
    let parsed = parse_args(args, &known)?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }
    let Some(source) = parsed.positional.first().cloned() else {
        return Err("usage: skillguard install <source> --dest <dir>|--target <agent>".into());
    };
    if parsed.positional.len() > 1 {
        return Err("install 只接受一个 source 参数".into());
    }
    let opts = install::InstallOptions {
        source,
        git_ref: parsed.one("ref").map(ToOwned::to_owned),
        subpath: parsed.one("path").map(ToOwned::to_owned),
        dest: parsed.one("dest").map(PathBuf::from),
        target: parsed.one("target").map(ToOwned::to_owned),
        rules_dir: parsed.one("rules").map(PathBuf::from),
        policy: parsed.one("policy").map(PathBuf::from),
        audit: parsed.one("audit").map(PathBuf::from),
        allow_domains: split_csv(&parsed.all("allow-domain")),
        ignore_rules: split_csv(&parsed.all("ignore")),
        yes: parsed.has("yes"),
        force: parsed.has("force"),
        dry_run: parsed.has("dry-run"),
        keep_quarantine: parsed.has("keep-quarantine"),
    };
    let outcome = install::install(opts)?;
    if parsed.has("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&outcome)
                .map_err(|error| format!("cannot serialize install result: {error}"))?
        );
    } else {
        println!(
            "SkillGuard {VERSION}  |  install\nsource: {}\nskill: {}",
            outcome.source, outcome.skill
        );
        if let Some(reference) = &outcome.resolved_ref {
            println!("resolved: {reference}");
        }
        println!(
            "scan: {} ({} critical, {} high, {} medium, {} low)",
            outcome.verdict,
            outcome.counts.critical,
            outcome.counts.high,
            outcome.counts.medium,
            outcome.counts.low
        );
        for finding in &outcome.findings {
            println!(
                "  [{}] {} {}:{}  {}",
                finding.severity.to_uppercase(),
                finding.rule_id,
                finding.file,
                finding.line,
                finding.title
            );
        }
        if outcome.dry_run {
            println!("dry-run: no files written");
        } else {
            if let Some(destination) = &outcome.destination {
                println!("destination: {}", destination.display());
            }
            println!("fingerprint: {}", outcome.fingerprint);
            println!("result: INSTALLED");
        }
    }
    Ok(0)
}

fn cmd_verify(args: &[String]) -> Result<i32, String> {
    let parsed = parse_args(args, &["lock", "json", "audit", "help"])?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }
    let Some(path) = parsed.positional.first() else {
        return Err("usage: skillguard verify <path> [--lock skillguard.lock]".into());
    };
    let root = if Path::new(path).is_file() {
        Path::new(path)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf()
    } else {
        PathBuf::from(path)
    };

    if let Some(lock) = parsed.one("lock") {
        let outcome = guard::verify_lock(&root, Path::new(lock))?;
        if let Some(audit) = parsed.one("audit") {
            let entry = guard::audit_entry(
                "verify-lock",
                &root.display().to_string(),
                if outcome.ok {
                    guard::Decision::Allow
                } else {
                    guard::Decision::Block
                },
                &[],
                &outcome
                    .drift
                    .iter()
                    .map(|item| format!("{} {}", item.kind, item.path))
                    .collect::<Vec<_>>(),
                None,
                None,
                &guard::builtin_rules_hash(),
                Some(&outcome.actual),
            );
            guard::append_audit(Path::new(audit), entry)?;
        }
        if parsed.has("json") {
            println!(
                "{}",
                serde_json::to_string_pretty(&outcome)
                    .map_err(|error| format!("cannot serialize verify result: {error}"))?
            );
        } else {
            println!("SkillGuard {VERSION}  |  verify --lock");
            println!("skill: {}", outcome.skill);
            println!("path: {}", outcome.path.display());
            println!("expected: {}", outcome.expected);
            println!("actual:   {}", outcome.actual);
            if outcome.ok {
                println!("result: PASS (lockfile matches)");
            } else {
                println!("result: FAIL ({} drift item(s))", outcome.drift.len());
                for item in &outcome.drift {
                    println!("  {}  {}", item.kind, item.path);
                }
            }
        }
        return Ok(if outcome.ok { 0 } else { 1 });
    }

    let outcome = install::verify(&root)?;
    if let Some(audit) = parsed.one("audit") {
        let entry = guard::audit_entry(
            "verify",
            &root.display().to_string(),
            if outcome.ok {
                guard::Decision::Allow
            } else {
                guard::Decision::Block
            },
            &[],
            &outcome
                .drift
                .iter()
                .map(|item| format!("{} {}", item.kind, item.path))
                .collect::<Vec<_>>(),
            None,
            None,
            &guard::builtin_rules_hash(),
            Some(&outcome.actual),
        );
        guard::append_audit(Path::new(audit), entry)?;
    }
    if parsed.has("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&outcome)
                .map_err(|error| format!("cannot serialize verify result: {error}"))?
        );
    } else {
        println!("SkillGuard {VERSION}  |  verify");
        println!("skill: {}", outcome.skill);
        println!("path: {}", outcome.path.display());
        println!("expected: {}", outcome.expected);
        println!("actual:   {}", outcome.actual);
        if outcome.ok {
            println!("result: PASS (no drift)");
        } else {
            println!("result: FAIL ({} drift item(s))", outcome.drift.len());
            for item in &outcome.drift {
                println!("  {}  {}", item.kind, item.path);
            }
        }
    }
    Ok(if outcome.ok { 0 } else { 1 })
}

fn cmd_scan(args: &[String]) -> Result<i32, String> {
    let known = [
        "format",
        "fail-on",
        "min-severity",
        "ignore",
        "allow-domain",
        "rules",
        "config",
        "max-file-size",
        "no-color",
        "quiet",
        "json-pretty",
        "policy",
        "baseline",
        "write-baseline",
        "audit",
        "semantic",
        "semantic-provider",
        "semantic-endpoint",
        "semantic-model",
        "embedding-endpoint",
        "embedding-model",
        "api-key-env",
        "semantic-timeout",
        "min-risk",
        "help",
    ];
    let parsed = parse_args(args, &known)?;
    if parsed.has("help") {
        print_help();
        return Ok(0);
    }

    let target = parsed.positional.first().map(String::as_str).unwrap_or(".");
    let root = PathBuf::from(target);
    if !root.exists() {
        return Err(format!("path not found: {}", root.display()));
    }

    let cfg = match parsed.one("config") {
        Some(path) => config::load(Path::new(path))?,
        None => match config::discover(&root) {
            Some(path) => config::load(&path)?,
            None => config::Config::default(),
        },
    };

    let format = parsed.one("format").unwrap_or("text").to_ascii_lowercase();
    if !matches!(
        format.as_str(),
        "text" | "json" | "sarif" | "github" | "review" | "explain"
    ) {
        return Err(format!("invalid --format: {format}"));
    }

    let fail_on = match parsed.one("fail-on").or(cfg.fail_on.as_deref()) {
        Some("none") => None,
        Some(value) => {
            Some(Severity::parse(value).ok_or_else(|| format!("invalid --fail-on: {value}"))?)
        }
        None => Some(Severity::High),
    };

    let min_severity = match parsed.one("min-severity").or(cfg.min_severity.as_deref()) {
        Some(value) => {
            Severity::parse(value).ok_or_else(|| format!("invalid --min-severity: {value}"))?
        }
        None => Severity::Low,
    };

    let mut ignore_rules = cfg.ignore_rules.clone();
    ignore_rules.extend(split_csv(&parsed.all("ignore")));
    ignore_rules.sort();
    ignore_rules.dedup();

    let mut allow_domains = cfg.allow_domains.clone();
    allow_domains.extend(split_csv(&parsed.all("allow-domain")));
    allow_domains.sort();
    allow_domains.dedup();

    let max_kb = match parsed.one("max-file-size") {
        Some(value) => value
            .parse::<u64>()
            .map_err(|_| format!("invalid --max-file-size: {value}"))?,
        None => cfg.max_file_size_kb.unwrap_or(512),
    };

    let rules_dir = parsed
        .one("rules")
        .map(PathBuf::from)
        .or_else(|| cfg.rules_dir.as_ref().map(PathBuf::from));

    let builtin = rules::load_builtin()?;
    let external = match &rules_dir {
        Some(dir) => rules::load_dir(dir)?,
        None => Vec::new(),
    };
    let (merged, warnings) = rules::merge(builtin, external);
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    if merged.is_empty() {
        return Err("no rules loaded".into());
    }
    let compiled = rules::compile_all(merged)?;

    let opts = ScanOptions {
        min_severity,
        fail_on,
        ignore_rules,
        allow_domains,
        max_file_size: max_kb.saturating_mul(1024),
        exclude: compile_excludes(&cfg.exclude)?,
    };

    let mut outcome = engine::scan(&root, &compiled, &opts)?;

    let semantic_enabled = parsed.has("semantic") || cfg.semantic.enabled;
    if semantic_enabled {
        let mut semantic_cfg = cfg.semantic.clone();
        if let Some(value) = parsed.one("semantic-provider") {
            semantic_cfg.provider = Some(value.to_string());
        }
        if let Some(value) = parsed.one("semantic-endpoint") {
            semantic_cfg.endpoint = Some(value.to_string());
        }
        if let Some(value) = parsed.one("semantic-model") {
            semantic_cfg.model = Some(value.to_string());
        }
        if let Some(value) = parsed.one("embedding-endpoint") {
            semantic_cfg.embedding_endpoint = Some(value.to_string());
        }
        if let Some(value) = parsed.one("embedding-model") {
            semantic_cfg.embedding_model = Some(value.to_string());
        }
        if let Some(value) = parsed.one("api-key-env") {
            semantic_cfg.api_key_env = Some(value.to_string());
        }
        if let Some(value) = parsed.one("semantic-timeout") {
            semantic_cfg.timeout_secs = Some(
                value
                    .parse()
                    .map_err(|_| format!("invalid --semantic-timeout: {value}"))?,
            );
        }
        if let Some(value) = parsed.one("min-risk") {
            semantic_cfg.min_risk = Some(
                value
                    .parse()
                    .map_err(|_| format!("invalid --min-risk: {value}"))?,
            );
        }
        let settings = semantic::Settings::from_config(&semantic_cfg)?;
        let verdicts = semantic::check_path(&root, &settings)?;
        for verdict in &verdicts {
            if verdict.risk < settings.min_risk {
                continue;
            }
            if let Some(cr) = compiled.iter().find(|item| item.rule.id == "SG-SEM-001") {
                let severity = if verdict.risk >= 85 {
                    Severity::Critical
                } else if verdict.risk >= 70 {
                    Severity::High
                } else {
                    Severity::Medium
                };
                outcome.findings.push(model::Finding {
                    rule_id: cr.rule.id.clone(),
                    title: cr.rule.title.clone(),
                    severity,
                    category: cr.rule.category.clone(),
                    skill: verdict.skill.clone(),
                    file: verdict.path.clone(),
                    line: 1,
                    column: 1,
                    excerpt: verdict.labels.join(", "),
                    message: format!(
                        "{} (risk {}, model {})",
                        verdict.reason, verdict.risk, verdict.model
                    ),
                    remediation: cr.rule.remediation.clone(),
                    references: cr.rule.references.clone(),
                });
            }
        }
        outcome.semantic = verdicts;
        outcome.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.skill.cmp(&b.skill))
                .then(a.file.cmp(&b.file))
                .then(a.line.cmp(&b.line))
        });
    }

    if let Some(path) = parsed.one("write-baseline") {
        guard::write_baseline(Path::new(path), &outcome.findings)?;
    }
    if let Some(path) = parsed.one("baseline") {
        let baseline = guard::load_baseline(Path::new(path))?;
        outcome.findings = guard::filter_baseline(outcome.findings, &baseline);
    }

    let mut policy_paths: Vec<PathBuf> = parsed
        .all("policy")
        .into_iter()
        .map(PathBuf::from)
        .collect();
    if policy_paths.is_empty() {
        let local = root.join(".skillguard-policy.json");
        if local.is_file() {
            policy_paths.push(local);
        }
    }
    if policy_paths.iter().any(|path| !path.is_file()) {
        let missing = policy_paths
            .iter()
            .find(|path| !path.is_file())
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        return Err(format!("policy file not found: {missing}"));
    }
    let threshold = opts.fail_on;
    let merged_policy = if policy_paths.is_empty() {
        None
    } else {
        let policies = policy_paths
            .iter()
            .map(|path| guard::load_policy(path))
            .collect::<Result<Vec<_>, _>>()?;
        Some(guard::merge_policies(&policies))
    };
    let policy_result = merged_policy
        .as_ref()
        .map(|policy| guard::evaluate(&outcome.findings, policy, threshold));

    let color = report::use_color(parsed.has("no-color"));
    let summary = report::summary(&outcome);
    let failed = match &policy_result {
        Some(result) => result.decision == guard::Decision::Block,
        None => report::failed(&summary, threshold),
    };
    let report_threshold = match &policy_result {
        Some(result) if result.decision == guard::Decision::Block => Some(Severity::Low),
        Some(_) => None,
        None => threshold,
    };

    if let Some(result) = &policy_result {
        if !parsed.has("quiet") {
            eprintln!(
                "policy: {} (profile {}){}",
                result.decision.as_str(),
                result.profile,
                if result.reasons.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", result.reasons.join("; "))
                }
            );
        }
    }

    if let Some(audit) = parsed.one("audit") {
        let decision = policy_result
            .as_ref()
            .map(|result| result.decision)
            .unwrap_or(if failed {
                guard::Decision::Block
            } else {
                guard::Decision::Allow
            });
        let policy_hash = guard::policy_bundle_hash(&policy_paths)?;
        let policy_label = if policy_paths.is_empty() {
            None
        } else {
            Some(
                policy_paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            )
        };
        let reasons = policy_result
            .as_ref()
            .map(|result| result.reasons.clone())
            .unwrap_or_default();
        let entry = guard::audit_entry(
            "scan",
            &root.display().to_string(),
            decision,
            &outcome.findings,
            &reasons,
            policy_label.as_deref(),
            policy_hash.as_deref(),
            &guard::builtin_rules_hash(),
            None,
        );
        guard::append_audit(Path::new(audit), entry)?;
    }

    match format.as_str() {
        "json" => println!(
            "{}",
            report::to_json(&outcome, VERSION, parsed.has("json-pretty"))
        ),
        "sarif" => println!("{}", report::to_sarif(&outcome, VERSION, &compiled)),
        "github" => print!("{}", report::to_github(&outcome)),
        "review" | "explain" => {
            let decision = policy_result
                .as_ref()
                .map(|result| result.decision.as_str());
            let empty = Vec::new();
            let reasons = policy_result
                .as_ref()
                .map(|result| result.reasons.as_slice())
                .unwrap_or(&empty);
            report::print_review(
                &outcome,
                VERSION,
                decision,
                reasons,
                format == "explain",
                color,
                parsed.has("quiet"),
            );
            return Ok(0);
        }
        _ => {
            report::print_text(
                &outcome,
                VERSION,
                report_threshold,
                color,
                parsed.has("quiet"),
            );
        }
    }

    Ok(if failed { 1 } else { 0 })
}

fn cmd_rules(args: &[String]) -> Result<i32, String> {
    let subcommand = args.first().map(String::as_str).unwrap_or("list");
    match subcommand {
        "list" => {
            let compiled = rules::compile_all(rules::load_builtin()?)?;
            println!("{:<14} {:<9} {:<18} TITLE", "ID", "SEVERITY", "CATEGORY");
            for cr in compiled {
                println!(
                    "{:<14} {:<9} {:<18} {}",
                    cr.rule.id,
                    cr.rule.severity.as_str(),
                    cr.rule.category,
                    cr.rule.title
                );
            }
            Ok(0)
        }
        "validate" => {
            let Some(path) = args.get(1) else {
                return Err("usage: skillguard rules validate <file.json|dir>".into());
            };
            let path = Path::new(path);
            let loaded = if path.is_dir() {
                rules::load_dir(path)?
            } else {
                rules::load_file(path)?
            };
            let compiled = rules::compile_all(loaded)?;
            println!("OK: {} rule(s) loaded and compiled", compiled.len());
            Ok(0)
        }
        other => Err(format!("unknown rules subcommand: {other}")),
    }
}

fn cmd_init(args: &[String]) -> Result<i32, String> {
    let parsed = parse_args(args, &["force", "help"])?;
    if parsed.has("help") {
        println!(
            "Usage: skillguard init [dir] [--force]\nWrites .skillguard.json and a GitHub Actions workflow."
        );
        return Ok(0);
    }
    let dir = parsed
        .positional
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let force = parsed.has("force");

    let config_path = dir.join(".skillguard.json");
    if config_path.exists() && !force {
        eprintln!("skip existing {}", config_path.display());
    } else {
        let body = r#"{
  "fail_on": "high",
  "min_severity": "low",
  "ignore_rules": [],
  "allow_domains": [],
  "max_file_size_kb": 512,
  "exclude": ["node_modules", ".git", "dist", "vendor"]
}
"#;
        fs::write(&config_path, body)
            .map_err(|e| format!("cannot write {}: {e}", config_path.display()))?;
        println!("wrote {}", config_path.display());
    }

    let workflow_dir = dir.join(".github").join("workflows");
    fs::create_dir_all(&workflow_dir)
        .map_err(|e| format!("cannot create {}: {e}", workflow_dir.display()))?;
    let workflow_path = workflow_dir.join("skillguard.yml");
    if workflow_path.exists() && !force {
        eprintln!("skip existing {}", workflow_path.display());
    } else {
        let body = r#"name: SkillGuard
on:
  push:
  pull_request:
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Scan agent skills
        run: npx --yes seramys-skillguard@0.1.0 scan . --format sarif --fail-on high > skillguard.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillguard.sarif
"#;
        fs::write(&workflow_path, body)
            .map_err(|e| format!("cannot write {}: {e}", workflow_path.display()))?;
        println!("wrote {}", workflow_path.display());
    }

    println!("done. Run: skillguard scan .");
    Ok(0)
}

fn split_csv(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn compile_excludes(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|pattern| {
            let mut regex = String::from(".*");
            for ch in pattern.chars() {
                match ch {
                    '*' => regex.push_str(".*"),
                    '?' => regex.push('.'),
                    _ => regex.push_str(&regex::escape(&ch.to_string())),
                }
            }
            regex.push_str(".*");
            Regex::new(&regex).map_err(|e| format!("invalid exclude pattern {pattern}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flags_and_positionals() {
        let args = vec![
            "skills".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--fail-on=high".to_string(),
            "--ignore".to_string(),
            "SG-A,SG-B".to_string(),
            "--quiet".to_string(),
        ];
        let parsed = parse_args(&args, &["format", "fail-on", "ignore", "quiet"]).unwrap();
        assert_eq!(parsed.positional, vec!["skills"]);
        assert_eq!(parsed.one("format"), Some("json"));
        assert_eq!(parsed.one("fail-on"), Some("high"));
        assert!(parsed.has("quiet"));
    }

    #[test]
    fn rejects_unknown_flag() {
        let args = vec!["--nope".to_string()];
        assert!(parse_args(&args, &["format"]).is_err());
    }

    #[test]
    fn splits_csv_values() {
        assert_eq!(
            split_csv(&["a, b".to_string(), "c".to_string()]),
            vec!["a", "b", "c"]
        );
    }
}
