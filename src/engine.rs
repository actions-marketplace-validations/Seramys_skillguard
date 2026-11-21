use crate::codeinsight;
use crate::frontmatter;
use crate::model::{Capability, Finding, Severity, Skill};
use crate::rules::{CompiledRule, MatchSpec, Rule, Scope};
use crate::semantic::SemanticVerdict;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};
use zip::ZipArchive;

pub struct ScanOptions {
    pub min_severity: Severity,
    pub fail_on: Option<Severity>,
    pub ignore_rules: Vec<String>,
    pub allow_domains: Vec<String>,
    pub max_file_size: u64,
    pub exclude: Vec<Regex>,
}

pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub capabilities: Vec<Capability>,
    pub semantic: Vec<SemanticVerdict>,
    pub skills: Vec<String>,
    pub files: usize,
    pub root: PathBuf,
}

const IGNORED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    ".venv",
    "venv",
    "vendor",
    ".idea",
    ".vscode",
    ".next",
    "coverage",
];

const MAX_DEPTH: usize = 32;
const MAX_SKILLS: usize = 1000;
const MAX_FILES: usize = 5000;
const MAX_CONTAINER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONTAINER_ENTRY_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONTAINER_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTAINER_ENTRIES: usize = 200;

static SECRET_ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_\-\.\/+=]{16,})["']?"#,
    )
    .unwrap()
});

static B64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{120,}={0,2}").unwrap());

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://([^/\s:'"]+)"#).unwrap());

pub fn scan(
    root: &Path,
    rules: &[CompiledRule],
    opts: &ScanOptions,
) -> Result<ScanOutcome, String> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if !root.exists() {
        return Err(format!("path not found: {}", root.display()));
    }
    let skills = discover_skills(&root, opts)?;
    let base_ignores = load_ignore_file(&root);
    let mut findings = Vec::new();
    let mut capabilities = Vec::new();
    let mut files = 0usize;
    let mut names = Vec::new();

    for skill in &skills {
        names.push(skill.name.clone());
        files += skill.files.len();
        findings.extend(scan_skill(skill, rules, opts, &base_ignores)?);
        capabilities.extend(codeinsight::capabilities(skill));
    }

    let mut seen = HashSet::new();
    findings
        .retain(|f| seen.insert((f.rule_id.clone(), f.file.clone(), f.line, f.message.clone())));
    findings.retain(|f| f.severity >= opts.min_severity);
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.skill.cmp(&b.skill))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });

    Ok(ScanOutcome {
        findings,
        capabilities,
        semantic: Vec::new(),
        skills: names,
        files,
        root,
    })
}

fn discover_skills(root: &Path, opts: &ScanOptions) -> Result<Vec<Skill>, String> {
    if root.is_file() {
        let is_skill_md = root.file_name().and_then(|s| s.to_str()) == Some("SKILL.md");
        let skill_root = root
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(root)
            .to_path_buf();
        let files = if is_skill_md {
            collect_files(&skill_root, opts)?
        } else {
            vec![root.to_path_buf()]
        };
        return Ok(vec![make_skill(&skill_root, files)]);
    }

    if root.join("SKILL.md").is_file() {
        return Ok(vec![make_skill(root, collect_files(root, opts)?)]);
    }

    let mut roots = Vec::new();
    find_skill_roots(root, root, 0, &mut roots, opts)?;
    if roots.is_empty() {
        return Ok(vec![make_skill(root, collect_files(root, opts)?)]);
    }
    roots.sort();
    roots.dedup();

    let mut skills = Vec::new();
    for r in roots {
        skills.push(make_skill(&r, collect_files(&r, opts)?));
    }
    Ok(skills)
}

fn find_skill_roots(
    base: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    opts: &ScanOptions,
) -> Result<(), String> {
    if depth > MAX_DEPTH || out.len() >= MAX_SKILLS {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        if is_ignored_dir(&path) {
            continue;
        }
        let rel = rel_path(base, &path);
        if path_excluded(&rel, opts) {
            continue;
        }
        if path.join("SKILL.md").is_file() {
            out.push(path);
        } else {
            find_skill_roots(base, &path, depth + 1, out, opts)?;
        }
    }
    Ok(())
}

fn make_skill(root: &Path, files: Vec<PathBuf>) -> Skill {
    let skill_md_path = root.join("SKILL.md");
    if skill_md_path.is_file() {
        let content = fs::read_to_string(&skill_md_path).unwrap_or_default();
        let fm = frontmatter::parse(&content);
        let name = fm
            .get("name")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| dir_name(root));
        Skill {
            name,
            root: root.to_path_buf(),
            skill_md: Some(skill_md_path),
            files,
        }
    } else {
        Skill {
            name: dir_name(root),
            root: root.to_path_buf(),
            skill_md: None,
            files,
        }
    }
}

fn dir_name(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("skill")
        .to_string()
}

fn collect_files(root: &Path, opts: &ScanOptions) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    walk_files(root, root, 0, &mut files, opts)?;
    files.sort();
    files.dedup();
    Ok(files)
}

fn walk_files(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    opts: &ScanOptions,
) -> Result<(), String> {
    if depth > MAX_DEPTH || out.len() >= MAX_FILES {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        let rel = rel_path(root, &path);
        if path_excluded(&rel, opts) {
            continue;
        }
        if ft.is_dir() {
            if is_ignored_dir(&path) {
                continue;
            }
            walk_files(root, &path, depth + 1, out, opts)?;
        } else if ft.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn is_ignored_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    IGNORED_DIRS.contains(&name)
}

fn path_excluded(rel: &str, opts: &ScanOptions) -> bool {
    opts.exclude.iter().any(|re| re.is_match(rel))
}

fn rel_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn load_ignore_file(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for name in [".skillguardignore", ".skillguard-ignore"] {
        if let Ok(text) = fs::read_to_string(root.join(name)) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                out.push(line.to_string());
            }
        }
    }
    out
}

fn scan_skill(
    skill: &Skill,
    rules: &[CompiledRule],
    opts: &ScanOptions,
    base_ignores: &[String],
) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    let mut ignore_patterns = base_ignores.to_vec();
    ignore_patterns.extend(opts.ignore_rules.iter().cloned());
    ignore_patterns.extend(load_ignore_file(&skill.root));

    let fm = skill
        .skill_md
        .as_ref()
        .and_then(|p| fs::read_to_string(p).ok())
        .map(|c| frontmatter::parse(&c));

    if let Some(fm) = &fm {
        for cr in rules {
            if let MatchSpec::FrontmatterMissing { fields } = &cr.rule.matcher {
                if !rule_applies_to_skill_md(&cr.rule) {
                    continue;
                }
                for field in fields {
                    let present = fm.get(field).map(|v| !v.trim().is_empty()).unwrap_or(false);
                    if present {
                        continue;
                    }
                    let msg = format!("missing frontmatter field `{field}`");
                    let f = finding_from_rule(
                        &cr.rule,
                        &skill.name,
                        "SKILL.md",
                        1,
                        1,
                        msg.clone(),
                        msg,
                    );
                    push_finding(&mut findings, f, &ignore_patterns, opts);
                }
            }
        }
    }

    for file in &skill.files {
        let rel = rel_path(&skill.root, file);
        let scope = scope_for(&rel);

        for cr in rules {
            if let Some(re) = &cr.path_regex {
                if !rule_path_applies(&cr.rule) {
                    continue;
                }
                if re.is_match(&rel) {
                    let msg = format!("path matched: {rel}");
                    let f = finding_from_rule(&cr.rule, &skill.name, &rel, 1, 1, rel.clone(), msg);
                    push_finding(&mut findings, f, &ignore_patterns, opts);
                }
            }
        }

        let Ok(meta) = fs::metadata(file) else {
            continue;
        };
        let container_like = is_container_name(&rel) || has_zip_magic(file);
        if container_like {
            if meta.len() > MAX_CONTAINER_BYTES {
                continue;
            }
        } else if meta.len() > opts.max_file_size {
            continue;
        }
        let Ok(bytes) = fs::read(file) else {
            continue;
        };

        if is_zip_bytes(&bytes) {
            if let Some(entries) = read_container(&bytes) {
                scan_container_entries(
                    &skill.name,
                    &rel,
                    &entries,
                    rules,
                    &ignore_patterns,
                    opts,
                    &mut findings,
                    0,
                );
                continue;
            }
        }

        if is_pyc_file(&rel, &bytes) {
            scan_pyc(
                &skill.name,
                &rel,
                file,
                &bytes,
                rules,
                &ignore_patterns,
                opts,
                &mut findings,
            );
            continue;
        }

        if is_pdf_bytes(&bytes) {
            let text = extract_printable(&bytes, 4);
            scan_text_content(
                &skill.name,
                &format!("{rel}::strings"),
                Scope::Pdf,
                &text,
                rules,
                &ignore_patterns,
                opts,
                &mut findings,
            );
            continue;
        }

        if is_binary(&bytes) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        scan_text_content(
            &skill.name,
            &rel,
            scope,
            text.as_ref(),
            rules,
            &ignore_patterns,
            opts,
            &mut findings,
        );
    }

    let snapshot = findings.clone();
    for cr in rules {
        if let MatchSpec::Combo { groups, none_of } = &cr.rule.matcher {
            if groups.is_empty() {
                continue;
            }
            let ids: HashSet<&str> = snapshot.iter().map(|f| f.rule_id.as_str()).collect();
            if none_of.iter().any(|id| ids.contains(id.as_str())) {
                continue;
            }
            let mut signals = Vec::new();
            let mut satisfied = true;
            for group in groups {
                match group.iter().find(|id| ids.contains(id.as_str())) {
                    Some(id) => signals.push(id.clone()),
                    None => {
                        satisfied = false;
                        break;
                    }
                }
            }
            if !satisfied {
                continue;
            }
            if snapshot.iter().any(|f| f.rule_id == cr.rule.id) {
                continue;
            }
            let (file, line) = if skill.skill_md.is_some() {
                ("SKILL.md".to_string(), 1)
            } else if let Some(first) = skill.files.first() {
                (rel_path(&skill.root, first), 1)
            } else {
                (skill.name.clone(), 1)
            };
            let msg = format!("combined signals: {}", signals.join(", "));
            let f = finding_from_rule(
                &cr.rule,
                &skill.name,
                &file,
                line,
                1,
                format!("signals: {}", signals.join(", ")),
                msg,
            );
            push_finding(&mut findings, f, &ignore_patterns, opts);
        }
    }

    Ok(findings)
}

struct ContainerEntry {
    name: String,
    bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn scan_text_content(
    skill: &str,
    rel: &str,
    scope: Scope,
    content: &str,
    rules: &[CompiledRule],
    ignore: &[String],
    opts: &ScanOptions,
    out: &mut Vec<Finding>,
) {
    let lines: Vec<&str> = content.lines().collect();
    let suppression = collect_file_suppression(&lines);
    let code_analysis = if matches!(
        scope,
        Scope::SkillMd | Scope::Markdown | Scope::Script | Scope::Text
    ) && rules
        .iter()
        .any(|cr| matches!(&cr.rule.matcher, MatchSpec::CodeSignal { .. }))
    {
        Some(codeinsight::analyze(
            content,
            matches!(scope, Scope::Script),
        ))
    } else {
        None
    };

    for cr in rules {
        if !rule_text_applies(&cr.rule, scope) {
            continue;
        }
        match &cr.rule.matcher {
            MatchSpec::Regex { .. } => {
                if let Some(re) = &cr.regex {
                    scan_regex(cr, re, skill, rel, &lines, &suppression, ignore, opts, out);
                }
            }
            MatchSpec::SecretEntropy {
                min_length,
                threshold,
                prefixes,
            } => {
                scan_secrets(
                    cr,
                    *min_length,
                    *threshold,
                    prefixes,
                    skill,
                    rel,
                    &lines,
                    &suppression,
                    ignore,
                    opts,
                    out,
                );
            }
            MatchSpec::HiddenUnicode => {
                scan_hidden(cr, skill, rel, &lines, &suppression, ignore, opts, out);
            }
            MatchSpec::Base64Blob { min_length } => {
                scan_base64(
                    cr,
                    *min_length,
                    skill,
                    rel,
                    &lines,
                    &suppression,
                    ignore,
                    opts,
                    out,
                );
            }
            MatchSpec::CodeSignal { signal } => {
                let Some(analysis) = &code_analysis else {
                    continue;
                };
                for found in analysis.signals.iter().filter(|s| s.id == signal) {
                    let f = finding_from_rule(
                        &cr.rule,
                        skill,
                        rel,
                        found.line,
                        found.column,
                        found.excerpt.clone(),
                        found.message.clone(),
                    );
                    push_finding(out, f, ignore, opts);
                }
            }
            MatchSpec::Padding {
                min_lines,
                max_nonempty_ratio,
            } => {
                if lines.len() < *min_lines {
                    continue;
                }
                let nonempty = lines.iter().filter(|line| !line.trim().is_empty()).count();
                let ratio = nonempty as f64 / lines.len() as f64;
                if ratio > *max_nonempty_ratio {
                    continue;
                }
                let msg = format!(
                    "文件有 {} 行，其中仅 {} 行非空（{:.2}%），疑似用空白填充隐藏尾部载荷",
                    lines.len(),
                    nonempty,
                    ratio * 100.0
                );
                let excerpt = format!("padding: {nonempty}/{} non-empty", lines.len());
                let f = finding_from_rule(&cr.rule, skill, rel, 1, 1, excerpt, msg);
                push_finding(out, f, ignore, opts);
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_container_entries(
    skill: &str,
    outer: &str,
    entries: &[ContainerEntry],
    rules: &[CompiledRule],
    ignore: &[String],
    opts: &ScanOptions,
    out: &mut Vec<Finding>,
    depth: usize,
) {
    for entry in entries {
        let vrel = format!("{outer}::{}", entry.name);
        let scope = scope_for(&entry.name);

        for cr in rules {
            if let Some(re) = &cr.path_regex {
                if !rule_path_applies(&cr.rule) {
                    continue;
                }
                if re.is_match(&vrel) {
                    let msg = format!("path matched inside container: {vrel}");
                    let f = finding_from_rule(&cr.rule, skill, &vrel, 1, 1, vrel.clone(), msg);
                    push_finding(out, f, ignore, opts);
                }
            }
        }

        for cr in rules {
            if let MatchSpec::ContainerScript { extensions } = &cr.rule.matcher {
                if is_script_entry(&entry.name, extensions) {
                    let msg = format!(
                        "Office/ZIP 容器内嵌脚本或可执行文件：{}，常规文档审查不可见",
                        entry.name
                    );
                    let f =
                        finding_from_rule(&cr.rule, skill, &vrel, 1, 1, entry.name.clone(), msg);
                    push_finding(out, f, ignore, opts);
                }
            }
            if matches!(&cr.rule.matcher, MatchSpec::ContainerOle) && is_ole_bytes(&entry.bytes) {
                let msg = format!("容器内嵌 OLE/复合文档对象：{}", entry.name);
                let f = finding_from_rule(&cr.rule, skill, &vrel, 1, 1, entry.name.clone(), msg);
                push_finding(out, f, ignore, opts);
            }
        }

        if depth < 3 && is_zip_bytes(&entry.bytes) {
            if let Some(nested) = read_container(&entry.bytes) {
                scan_container_entries(skill, &vrel, &nested, rules, ignore, opts, out, depth + 1);
                continue;
            }
        }

        if is_binary(&entry.bytes) {
            continue;
        }
        let text = String::from_utf8_lossy(&entry.bytes);
        scan_text_content(skill, &vrel, scope, text.as_ref(), rules, ignore, opts, out);
    }
}

fn is_ole_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
}

fn read_container(bytes: &[u8]) -> Option<Vec<ContainerEntry>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).ok()?;
    let mut out = Vec::new();
    let mut total = 0usize;
    let limit = archive.len().min(MAX_CONTAINER_ENTRIES);
    for index in 0..limit {
        let Ok(mut entry) = archive.by_index(index) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        if name.is_empty() || name.contains("..") {
            continue;
        }
        let declared = entry.size() as usize;
        if declared > MAX_CONTAINER_ENTRY_BYTES
            || total.saturating_add(declared) > MAX_CONTAINER_TOTAL_BYTES
        {
            continue;
        }
        let mut data = Vec::with_capacity(declared.min(64 * 1024));
        if entry.read_to_end(&mut data).is_err() || data.len() > MAX_CONTAINER_ENTRY_BYTES {
            continue;
        }
        total += data.len();
        out.push(ContainerEntry { name, bytes: data });
    }
    Some(out)
}

#[allow(clippy::too_many_arguments)]
fn scan_pyc(
    skill: &str,
    rel: &str,
    file: &Path,
    bytes: &[u8],
    rules: &[CompiledRule],
    ignore: &[String],
    opts: &ScanOptions,
    out: &mut Vec<Finding>,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut detail = None;

    if bytes.len() < 16 {
        detail = Some("pyc 头部被截断".to_string());
    } else {
        let flags = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let source = find_pyc_source(file);
        if flags & 1 == 0 {
            let mtime = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let source_size = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
            match source {
                Some(src) => {
                    let actual = fs::metadata(&src).map(|m| m.len() as u32).unwrap_or(0);
                    if source_size != actual {
                        detail = Some(format!(
                            "pyc 记录的源码大小是 {source_size} 字节，实际源码是 {actual} 字节"
                        ));
                    } else if mtime > now.saturating_add(86_400) {
                        detail = Some("pyc 的源码时间戳位于未来，疑似伪造".to_string());
                    }
                }
                None => detail = Some("pyc 找不到对应的 .py 源码".to_string()),
            }
        } else {
            match source {
                Some(src) => match fs::read(&src) {
                    Ok(source_bytes) => {
                        let digest = Sha256::digest(&source_bytes);
                        if bytes[8..16] != digest[..8] {
                            detail = Some("pyc 的源码哈希与实际 .py 不一致".to_string());
                        }
                    }
                    Err(_) => detail = Some("无法读取 pyc 对应的 .py 源码".to_string()),
                },
                None => detail = Some("pyc 找不到对应的 .py 源码".to_string()),
            }
        }
    }

    if let Some(detail) = detail {
        if let Some(cr) = rules
            .iter()
            .find(|r| matches!(&r.rule.matcher, MatchSpec::BytecodeIntegrity))
        {
            let msg = format!("Python 字节码与源码不一致：{detail}");
            let f = finding_from_rule(&cr.rule, skill, rel, 1, 1, format!("pyc: {detail}"), msg);
            push_finding(out, f, ignore, opts);
        }
    }

    if let Some(report) = crate::pyc::inspect(bytes) {
        if !report.dangers.is_empty() {
            if let Some(cr) = rules
                .iter()
                .find(|r| matches!(&r.rule.matcher, MatchSpec::BytecodeDanger))
            {
                let msg = format!("Python 字节码危险特征：{}", report.dangers.join("；"));
                let excerpt = report
                    .names
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                let f = finding_from_rule(&cr.rule, skill, rel, 1, 1, excerpt, msg);
                push_finding(out, f, ignore, opts);
            }
        }
    }

    let strings = extract_printable(bytes, 4);
    if !strings.is_empty() {
        scan_text_content(
            skill,
            &format!("{rel}::strings"),
            Scope::Script,
            &strings,
            rules,
            ignore,
            opts,
            out,
        );
    }
}

fn find_pyc_source(pyc: &Path) -> Option<PathBuf> {
    let dir = pyc.parent()?;
    let parent = if dir.file_name().and_then(|name| name.to_str()) == Some("__pycache__") {
        dir.parent()?
    } else {
        dir
    };
    let name = pyc.file_name()?.to_str()?;
    let stem = name.split('.').next()?;
    let source = parent.join(format!("{stem}.py"));
    source.is_file().then_some(source)
}

fn extract_printable(bytes: &[u8], min_length: usize) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for &byte in bytes {
        if (0x20..=0x7e).contains(&byte) || byte == b'\t' {
            run.push(byte as char);
        } else {
            if run.len() >= min_length {
                out.push_str(&run);
                out.push('\n');
            }
            run.clear();
        }
        if out.len() > 64 * 1024 {
            break;
        }
    }
    if run.len() >= min_length {
        out.push_str(&run);
    }
    out
}

fn is_zip_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
}

fn has_zip_magic(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && is_zip_bytes(&magic)
}

fn is_container_name(rel: &str) -> bool {
    let ext = rel.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "docx"
            | "docm"
            | "xlsx"
            | "xlsm"
            | "pptx"
            | "pptm"
            | "zip"
            | "jar"
            | "apk"
            | "odt"
            | "ods"
            | "odp"
    )
}

fn is_pyc_file(rel: &str, _bytes: &[u8]) -> bool {
    rel.to_ascii_lowercase().ends_with(".pyc")
}

fn is_script_entry(name: &str, extra: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pyc") {
        return true;
    }
    let ext = lower.rsplit('.').next().unwrap_or("");
    const DEFAULT: &[&str] = &[
        "sh", "bash", "zsh", "py", "js", "mjs", "cjs", "ts", "ps1", "bat", "cmd", "vbs", "hta",
        "exe", "dll", "so", "dylib", "jar", "bin", "scr", "msi", "pkg", "apk", "com", "wsf",
    ];
    DEFAULT.contains(&ext)
        || extra
            .iter()
            .any(|item| item.trim_start_matches('.').eq_ignore_ascii_case(ext))
}

#[allow(clippy::too_many_arguments)]
fn scan_regex(
    cr: &CompiledRule,
    re: &Regex,
    skill: &str,
    rel: &str,
    lines: &[&str],
    suppression: &Suppression,
    ignore: &[String],
    opts: &ScanOptions,
    out: &mut Vec<Finding>,
) {
    let max = cr.rule.max_matches.unwrap_or(10);
    let mut count = 0usize;
    'outer: for (idx, line) in lines.iter().enumerate() {
        if is_suppressed(lines, idx, &cr.rule.id, suppression) {
            continue;
        }
        for m in re.find_iter(line) {
            if let Some(absent) = &cr.absent {
                if absent.is_match(line) {
                    continue;
                }
            }
            let col = line[..m.start()].chars().count() + 1;
            let excerpt = excerpt(line, m.start(), m.end(), cr.rule.category == "secret");
            let msg = if cr.rule.description.is_empty() {
                cr.rule.title.clone()
            } else {
                cr.rule.description.clone()
            };
            let f = finding_from_rule(&cr.rule, skill, rel, idx + 1, col, excerpt, msg);
            push_finding(out, f, ignore, opts);
            count += 1;
            if count >= max {
                break 'outer;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_secrets(
    cr: &CompiledRule,
    min_length: usize,
    threshold: f64,
    prefixes: &[String],
    skill: &str,
    rel: &str,
    lines: &[&str],
    suppression: &Suppression,
    ignore: &[String],
    opts: &ScanOptions,
    out: &mut Vec<Finding>,
) {
    let mut count = 0usize;
    for (idx, line) in lines.iter().enumerate() {
        if is_suppressed(lines, idx, &cr.rule.id, suppression) {
            continue;
        }
        for cap in SECRET_ASSIGN_RE.captures_iter(line) {
            let Some(m) = cap.get(1) else { continue };
            let value = m.as_str();
            if value.chars().count() < min_length || is_placeholder(value) {
                continue;
            }
            if !prefixes.is_empty() && !prefixes.iter().any(|p| value.starts_with(p.as_str())) {
                continue;
            }
            let entropy = shannon_entropy(value);
            if entropy < threshold {
                continue;
            }
            let col = line[..m.start()].chars().count() + 1;
            let excerpt = excerpt(line, m.start(), m.end(), true);
            let msg = format!("high-entropy secret-like value (entropy {entropy:.2})");
            let f = finding_from_rule(&cr.rule, skill, rel, idx + 1, col, excerpt, msg);
            push_finding(out, f, ignore, opts);
            count += 1;
            if count >= 3 {
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_hidden(
    cr: &CompiledRule,
    skill: &str,
    rel: &str,
    lines: &[&str],
    suppression: &Suppression,
    ignore: &[String],
    opts: &ScanOptions,
    out: &mut Vec<Finding>,
) {
    for (idx, line) in lines.iter().enumerate() {
        if is_suppressed(lines, idx, &cr.rule.id, suppression) {
            continue;
        }
        if let Some((col, ch)) = find_hidden(line, idx == 0) {
            let excerpt = format!("hidden character U+{:04X}", ch as u32);
            let msg = "invisible or bidirectional control character detected".to_string();
            let f = finding_from_rule(&cr.rule, skill, rel, idx + 1, col, excerpt, msg);
            push_finding(out, f, ignore, opts);
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_base64(
    cr: &CompiledRule,
    min_length: usize,
    skill: &str,
    rel: &str,
    lines: &[&str],
    suppression: &Suppression,
    ignore: &[String],
    opts: &ScanOptions,
    out: &mut Vec<Finding>,
) {
    for (idx, line) in lines.iter().enumerate() {
        if is_suppressed(lines, idx, &cr.rule.id, suppression) {
            continue;
        }
        for m in B64_RE.find_iter(line) {
            let blob = m.as_str();
            if blob.len() < min_length {
                continue;
            }
            let Some(decoded) = decode_base64(blob) else {
                continue;
            };
            if decoded.len() < 20 {
                continue;
            }
            let text = String::from_utf8_lossy(&decoded).to_ascii_lowercase();
            let suspicious = [
                "curl",
                "wget",
                "bash",
                "powershell",
                "iex",
                "eval",
                "exec",
                "http://",
                "https://",
                "ssh-rsa",
                "chmod +x",
                "/dev/tcp",
            ]
            .iter()
            .any(|k| text.contains(k));
            let col = line[..m.start()].chars().count() + 1;
            let excerpt = excerpt(line, m.start(), m.end(), true);
            let (severity, msg) = if suspicious {
                (
                    Severity::Critical,
                    "base64 blob decodes to a suspicious executable payload".to_string(),
                )
            } else {
                (
                    cr.rule.severity,
                    "large base64-encoded blob (possible obfuscation)".to_string(),
                )
            };
            let mut f = finding_from_rule(&cr.rule, skill, rel, idx + 1, col, excerpt, msg);
            f.severity = severity;
            push_finding(out, f, ignore, opts);
            return;
        }
    }
}

fn finding_from_rule(
    rule: &Rule,
    skill: &str,
    file: &str,
    line: usize,
    column: usize,
    excerpt: String,
    message: String,
) -> Finding {
    Finding {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity,
        category: rule.category.clone(),
        skill: skill.to_string(),
        file: file.to_string(),
        line,
        column,
        excerpt,
        message,
        remediation: rule.remediation.clone(),
        references: rule.references.clone(),
    }
}

fn push_finding(out: &mut Vec<Finding>, f: Finding, ignore: &[String], opts: &ScanOptions) {
    if rule_ignored(&f.rule_id, ignore) {
        return;
    }
    if f.category == "network" {
        if f.rule_id == "SG-NET-002" && private_ip_only(&f) {
            return;
        }
        if network_allowed(&f, &opts.allow_domains) {
            return;
        }
    }
    out.push(f);
}

fn rule_ignored(id: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        let p = p.trim();
        if p.is_empty() {
            return false;
        }
        if p == "*" {
            return true;
        }
        match p.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => id == p,
        }
    })
}

fn rule_text_applies(rule: &Rule, scope: Scope) -> bool {
    if rule.applies_to.is_empty() {
        return true;
    }
    rule.applies_to.iter().any(|s| match s {
        Scope::All | Scope::Text => true,
        Scope::Path => false,
        other => *other == scope,
    })
}

fn rule_path_applies(rule: &Rule) -> bool {
    rule.applies_to.is_empty()
        || rule
            .applies_to
            .iter()
            .any(|s| matches!(s, Scope::Path | Scope::All))
}

fn rule_applies_to_skill_md(rule: &Rule) -> bool {
    rule.applies_to.is_empty()
        || rule.applies_to.iter().any(|s| {
            matches!(
                s,
                Scope::SkillMd | Scope::Markdown | Scope::Text | Scope::All
            )
        })
}

pub(crate) fn scope_for(rel: &str) -> Scope {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if name.eq_ignore_ascii_case("SKILL.md") {
        return Scope::SkillMd;
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "md" | "mdx" => Scope::Markdown,
        "sh" | "bash" | "zsh" | "ps1" | "bat" | "cmd" | "py" | "js" | "mjs" | "cjs" | "ts"
        | "go" | "rb" | "php" | "pl" | "lua" | "rs" => Scope::Script,
        "json" | "yaml" | "yml" | "toml" | "ini" | "env" | "conf" | "cfg" => Scope::Config,
        "pdf" => Scope::Pdf,
        _ => Scope::Text,
    }
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

fn is_pdf_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF-") || bytes.windows(5).take(1024).any(|window| window == b"%PDF-")
}

#[derive(Default)]
struct Suppression {
    file_all: bool,
    file_ids: HashSet<String>,
}

fn collect_file_suppression(lines: &[&str]) -> Suppression {
    let mut s = Suppression::default();
    for line in lines {
        if let Some(rest) = directive_after(line, "skillguard-disable-file") {
            let tokens = directive_tokens(rest);
            if tokens.is_empty() {
                s.file_all = true;
            }
            for t in tokens {
                if t == "*" {
                    s.file_all = true;
                } else {
                    s.file_ids.insert(t);
                }
            }
        }
    }
    s
}

fn is_suppressed(lines: &[&str], idx: usize, rule_id: &str, suppression: &Suppression) -> bool {
    if suppression.file_all || suppression.file_ids.contains(rule_id) {
        return true;
    }
    if let Some(line) = lines.get(idx) {
        if let Some(rest) = directive_after(line, "skillguard-disable-line") {
            if directive_matches(rest, rule_id) {
                return true;
            }
        }
    }
    if idx > 0 {
        if let Some(prev) = lines.get(idx - 1) {
            if let Some(rest) = directive_after(prev, "skillguard-disable-next-line") {
                if directive_matches(rest, rule_id) {
                    return true;
                }
            }
        }
    }
    false
}

fn directive_after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.find(key).map(|pos| &line[pos + key.len()..])
}

fn directive_tokens(rest: &str) -> Vec<String> {
    let cleaned = rest
        .trim()
        .trim_start_matches(':')
        .trim()
        .trim_end_matches("-->")
        .trim();
    cleaned
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

fn directive_matches(rest: &str, rule_id: &str) -> bool {
    let tokens = directive_tokens(rest);
    if tokens.is_empty() {
        return true;
    }
    tokens.iter().any(|t| t == "*" || t == rule_id)
}

fn find_hidden(line: &str, first_line: bool) -> Option<(usize, char)> {
    let chars: Vec<char> = line.chars().collect();
    for (idx, &ch) in chars.iter().enumerate() {
        if !is_hidden_char(ch) {
            continue;
        }
        if first_line && idx == 0 && ch == '\u{feff}' {
            continue;
        }
        if ch == '\u{200d}' && is_emoji_joiner(&chars, idx) {
            continue;
        }
        return Some((idx + 1, ch));
    }
    None
}

fn is_emoji_joiner(chars: &[char], idx: usize) -> bool {
    let prev = chars[..idx].iter().rev().find(|ch| **ch != '\u{fe0f}');
    let next = chars[idx + 1..].iter().find(|ch| **ch != '\u{fe0f}');
    matches!((prev, next), (Some(prev), Some(next)) if is_emoji_like(*prev) && is_emoji_like(*next))
}

fn is_emoji_like(ch: char) -> bool {
    matches!(
        ch as u32,
        0x1F000..=0x1FAFF
            | 0x2600..=0x27BF
            | 0x2190..=0x21FF
            | 0x2300..=0x23FF
            | 0x2B00..=0x2BFF
    )
}

fn is_hidden_char(ch: char) -> bool {
    matches!(
        ch as u32,
        0x061C
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0xFEFF
            | 0xE0000..=0xE007F
    )
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "example",
        "your",
        "changeme",
        "placeholder",
        "redacted",
        "xxxx",
        "****",
        "${",
        "{{",
        "<",
        ">",
        "os.",
        "process.",
        "env.",
        "none",
        "null",
        "todo",
        "dummy",
        "sample",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in value.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.bytes() {
        if c == b'=' {
            break;
        }
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buf = (buf << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn excerpt(line: &str, start: usize, end: usize, mask: bool) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mstart = line[..start].chars().count();
    let mend = line[..end].chars().count();
    let from = mstart.saturating_sub(40);
    let to = (mend + 40).min(chars.len());
    let mut buf = String::new();
    if from > 0 {
        buf.push('…');
    }
    let mut i = from;
    while i < to {
        if mask && i >= mstart && i < mend {
            let value: String = chars[mstart..mend].iter().collect();
            buf.push_str(&mask_value(&value));
            i = mend;
            continue;
        }
        buf.push(chars[i]);
        i += 1;
    }
    if to < chars.len() {
        buf.push('…');
    }
    let mut s = buf.replace('\t', " ").trim().to_string();
    if s.chars().count() > 180 {
        s = s.chars().take(180).collect::<String>();
        s.push('…');
    }
    s
}

fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len().max(4));
    }
    format!(
        "{}…{}",
        chars[..4].iter().collect::<String>(),
        chars[chars.len() - 4..].iter().collect::<String>()
    )
}

fn extract_hosts(text: &str) -> Vec<String> {
    URL_RE
        .captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_ascii_lowercase()))
        .collect()
}

fn domain_allowed(host: &str, allow: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    allow.iter().any(|d| {
        let d = d.trim().to_ascii_lowercase();
        !d.is_empty() && (host == d || host.ends_with(&format!(".{d}")))
    })
}

fn network_allowed(f: &Finding, allow: &[String]) -> bool {
    if allow.is_empty() {
        return false;
    }
    let hosts = extract_hosts(&f.excerpt);
    !hosts.is_empty() && hosts.iter().all(|h| domain_allowed(h, allow))
}

fn private_ip_only(f: &Finding) -> bool {
    let hosts = extract_hosts(&f.excerpt);
    !hosts.is_empty() && hosts.iter().all(|h| is_private_host(h))
}

fn is_private_host(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") || host == "::1" {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut nums = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        match p.parse::<u8>() {
            Ok(n) => nums[i] = n,
            Err(_) => return false,
        }
    }
    nums[0] == 10
        || nums[0] == 127
        || (nums[0] == 192 && nums[1] == 168)
        || (nums[0] == 172 && (16..=31).contains(&nums[1]))
        || (nums[0] == 169 && nums[1] == 254)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_distinguishes_random_from_words() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("aB3xK9mQ2pL7vR4tY8wZ") > 3.5);
    }

    #[test]
    fn decodes_base64() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
    }

    #[test]
    fn masks_secrets() {
        assert_eq!(mask_value("abcdefghijkl"), "abcd…ijkl");
        assert_eq!(mask_value("short"), "*****");
    }

    #[test]
    fn detects_private_hosts() {
        assert!(is_private_host("127.0.0.1"));
        assert!(is_private_host("192.168.1.10"));
        assert!(!is_private_host("8.8.8.8"));
    }

    #[test]
    fn matches_ignore_patterns() {
        assert!(rule_ignored("SG-PI-001", &["SG-PI-*".to_string()]));
        assert!(rule_ignored("SG-PI-001", &["*".to_string()]));
        assert!(!rule_ignored("SG-PI-001", &["SG-NET-*".to_string()]));
    }

    #[test]
    fn inline_suppression_works() {
        let lines = vec![
            "# skillguard-disable-next-line SG-CMD-001",
            "rm -rf /",
            "# skillguard-disable-line SG-NET-002",
        ];
        let supp = collect_file_suppression(&lines);
        assert!(is_suppressed(&lines, 1, "SG-CMD-001", &supp));
        assert!(is_suppressed(&lines, 2, "SG-NET-002", &supp));
        assert!(!is_suppressed(&lines, 1, "SG-NET-002", &supp));
    }

    #[test]
    fn emoji_joiner_is_not_hidden() {
        assert!(find_hidden("\u{1f9d1}\u{200d}\u{2696}\u{fe0f}", false).is_none());
        assert!(find_hidden("a\u{200d}b", false).is_some());
        assert!(find_hidden("hello\u{200b}world", false).is_some());
    }

    #[test]
    fn classifies_scopes() {
        assert_eq!(scope_for("SKILL.md"), Scope::SkillMd);
        assert_eq!(scope_for("scripts/run.sh"), Scope::Script);
        assert_eq!(scope_for("config/.env"), Scope::Config); // skillguard-disable-line SG-PERM-002
        assert_eq!(scope_for("README.md"), Scope::Markdown);
    }
}
