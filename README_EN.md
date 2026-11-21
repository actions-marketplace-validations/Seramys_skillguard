<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/logo-dark.svg">
  <img src="docs/assets/brand/logo.svg" width="150" alt="SkillGuard logo">
</picture>

# SkillGuard

**Offline admission layer for AI Agent Skills**

Deterministic rules block high-confidence threats; capability evidence and a review queue cover uncertain samples; policy, audit, and lockfiles make every decision reproducible.

Run SkillGuard before you install a Skill.

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE) [![Rust stable](https://img.shields.io/badge/Rust-stable-orange?logo=rust&style=flat-square)](https://www.rust-lang.org/) [![Node 18+](https://img.shields.io/badge/Node-18%2B-339933?logo=node.js&logoColor=white&style=flat-square)](packages/npm) [![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white&style=flat-square)](packages/python) [![Tests](https://img.shields.io/badge/tests-100%20passing-17A673?style=flat-square)](#verification) [![Rules](https://img.shields.io/badge/rules-59-5B6CFF?style=flat-square)](rules/core.json) [![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-8B7CF6?style=flat-square)](#output-formats) [![CI](https://github.com/Seramys/skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Seramys/skillguard/actions/workflows/ci.yml)

[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

[Quick start](#quick-start) · [What it scans](#what-it-scans) · [Rules](#built-in-rules-59) · [Benchmark](#benchmark) · [Architecture](#architecture) · [Verification](#verification)

</div>

<p align="center">
  <img src="docs/assets/screenshots/scan-exfil.png" width="920" alt="SkillGuard scan output: critical combo finding">
</p>
<p align="center"><sub>Real output: a Skill that reads <code>~/.ssh/id_rsa</code> and sends it out is flagged as <b>critical</b> by a combo rule.</sub></p>
<p align="center"><sub>Rule titles and remediation text are currently Chinese; the CLI, JSON, and SARIF schemas are language-neutral. English rule text is planned.</sub></p>

---

## Why SkillGuard

An Agent Skill is usually a directory:

```text
my-skill/
├── SKILL.md          # frontmatter + instructions for the agent
├── scripts/          # sh / py / js / ps1 ...
├── config/           # json / yaml / env ...
└── assets/
```

Installing a Skill often means handing the agent **instructions, tool permissions, scripts, and network access** at the same time. A malicious or careless Skill can:

- tell the agent to ignore previous system instructions, or not to tell the user;
- read `~/.ssh/id_rsa`, cloud credentials, cookies, or wallet files;
- exfiltrate data through Discord/Telegram/Slack webhooks, bare IPs, or tunnels;
- execute remote code with `curl ... | bash`, download-and-`chmod +x`, or encoded PowerShell;
- add `preinstall` / `postinstall` hooks or pull unpinned dependencies;
- hide instructions with zero-width characters, bidirectional controls, or large Base64 blobs.

SkillGuard performs a static check **before installation and before CI**: it only reads files, never executes them, never goes online, and turns suspicious instructions, permissions, secrets, network calls, and combined signals into findings you can locate, suppress, and export to Code Scanning.

It is not a runtime sandbox or an antivirus. It is the first static gate in the Skill supply chain.

### Three admission states and evidence

- **Block**: high-confidence, offline, no execution, immediate stop;
- **Review**: suspicious but not certain, queued for a human or policy decision;
- **Allow**: released through policy, baseline, exception, and an audit record.

Every result also exposes declared vs observed capabilities: what the Skill says it can do, which sensitive files it actually reads, and which external endpoint it targets. JSON scans and `review` / `explain` include `capabilities` and `evidence_graph`.

---

## Quick start

Requires Rust stable. From a clone:

```bash
cargo build --release
./target/release/skillguard scan ./tests/fixtures/exfil-skill --no-color
```

Windows PowerShell:

```powershell
cargo build --release
.\target\release\skillguard.exe scan .\tests\fixtures\exfil-skill --no-color
```

You will see one `critical` combo, two `high` findings, and one `medium`, with exit code `1`:

```text
[CRITICAL] SG-COMBO-001  Combo: sensitive access + external network
[HIGH]     SG-NET-001    Suspicious egress: webhook / tunnel
[HIGH]     SG-PERM-002   Sensitive path access
[MEDIUM]   SG-PERM-001   Excessive permission: shell execution
Result: FAIL
```

For CI, only the exit code matters:

```bash
./target/release/skillguard scan ./skills --fail-on high
echo $?   # 0 = pass, 1 = threshold reached, 2 = argument/config/rule/IO error
```

Generate SARIF for GitHub Code Scanning:

```bash
./target/release/skillguard scan ./skills --format sarif --fail-on high > skillguard.sarif
```

---

## Admission and evidence

```bash
skillguard lock ./my-skill --output skillguard.lock
skillguard verify ./my-skill --lock skillguard.lock
skillguard scan ./my-skill --policy .skillguard-policy.json --audit .skillguard-audit.jsonl
skillguard scan ./my-skill --write-baseline baseline.json
skillguard scan ./my-skill --baseline baseline.json
```

When a policy is supplied, its decision is authoritative: `fail_on` overrides the CLI threshold, `fail_on: none` disables severity blocking, and active exceptions are excluded from the decision. Expired exceptions are inactive. Unknown fields, an invalid `fail_on`, empty owner/reason, or an invalid expiry fail closed with exit code 2.

`lock` writes `skillguard-lock/v2` with content fingerprints, rules/policy hashes, tool version, and finding digests. Metadata files (lock, baseline, audit, receipt) are excluded from the fingerprint, so `lock .` does not invalidate itself. `--audit` writes `skillguard-audit/v2` with reasons and a `prev_hash`/`entry_hash` chain. `install` receipts use `skillguard-receipt/v2` with `receipt_hash` and an optional HMAC-SHA256 signature when `SKILLGUARD_RECEIPT_KEY` is set.

The experimental `install` rail accepts only HTTPS GitHub sources with a 40-character commit SHA, enforces timeouts/redirect limits, caps ZIP entries, per-entry/total size and compression ratio, and rejects absolute paths, `..`, drive letters, and escaping paths.

---

## Installation

> **Version status**: **0.3.0 is published to npm / PyPI / [GitHub Release](https://github.com/Seramys/skillguard/releases/tag/v0.3.0)**. It contains 59 rules, P0–P3 admission features, capability evidence, optional semantic providers, and runtime admission. Release v0.3.0 ships four platform binaries and SHA256SUMS.

### Option 1: single-file binary (recommended)

One file, no runtime dependencies. Best for local scans and CI.

**Download from Releases** (v0.3.0): grab the `skillguard` / `skillguard.exe` for your platform and put it on `PATH` or in your project.

**Build from source**:

```bash
git clone https://github.com/Seramys/skillguard.git
cd skillguard
cargo build --release

# POSIX
./target/release/skillguard version
./target/release/skillguard scan ./tests/fixtures/clean-skill
```

```powershell
# Windows
.\target\release\skillguard.exe version
.\target\release\skillguard.exe scan .\tests\fixtures\clean-skill
```

`scripts/build.sh` copies the current platform artifact to `dist/<platform>-<arch>/`:

```bash
bash scripts/build.sh
# dist/win32-x64/skillguard.exe
# dist/linux-x64/skillguard
# dist/macos-arm64/skillguard
```

<p align="center">
  <img src="docs/assets/screenshots/scan-clean.png" width="880" alt="Scanning a clean Skill: PASS">
</p>
<p align="center"><sub>Scanning a clean Skill: 0 findings, exit code 0.</sub></p>

### Option 2: Node ecosystem

Published (multi-platform):

```bash
npx --yes seramys-skillguard@0.3.0 scan ./skills --fail-on high
```

> If your npm mirror has not synced 0.3.0 yet, add `--registry=https://registry.npmjs.org/` or wait for the mirror.

Global install:

```bash
npm install -g seramys-skillguard
skillguard scan ./skills --fail-on high
```

**Repository verification** (no npm publish required):

```bash
node packages/npm/bin/skillguard.js version
node packages/npm/bin/skillguard.js scan ./tests/fixtures/clean-skill --no-color
```

<p align="center">
  <img src="docs/assets/screenshots/node-launcher.png" width="880" alt="Node launcher running SkillGuard">
</p>
<p align="center"><sub>The Node launcher is a thin shim; scanning is still done by the same Rust binary.</sub></p>

The 0.3.0 npm package stores four platform binaries under `vendor/<platform>-<arch>/`: `win32-x64`, `linux-x64`, `darwin-x64`, and `darwin-arm64`. `packages/npm/lib/resolve.js` selects the current platform.

### Option 3: Python ecosystem

Published (multi-platform):

```bash
pip install seramys-skillguard
skillguard scan ./skills --fail-on high
```

> 0.3.0 publishes separate platform wheels for Windows, Linux, and macOS (win_amd64, manylinux_2_17_x86_64, macOS x86_64/arm64) on PyPI.

**Repository verification**:

```bash
python -m venv .venv

# Windows
.venv\Scripts\python -m pip install --upgrade pip setuptools wheel
.venv\Scripts\python -m pip install -e packages/python --no-build-isolation
.venv\Scripts\skillguard version
.venv\Scripts\skillguard scan tests\fixtures\clean-skill --no-color

# macOS / Linux
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -e packages/python --no-build-isolation
.venv/bin/skillguard version
.venv/bin/skillguard scan tests/fixtures/clean-skill --no-color
```

<p align="center">
  <img src="docs/assets/screenshots/python-launcher.png" width="880" alt="Python launcher running SkillGuard">
</p>
<p align="center"><sub>The Python launcher reuses the Rust engine, with identical rules and output formats.</sub></p>

The Python wheel bundles the binary under `skillguard/_bin/`; build it with `scripts/package-python.sh`.

### Option 4: source development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
bash scripts/build-all.sh     # cross-compilation matrix; skips missing toolchains
```

All three entry points share the same `rules/core.json` and `engine.rs`; there is no “Node rule set” or “Python rule set”.

---

## What it scans

| Category | Rules | Typical signals |
|---|---:|---|
| Prompt injection | 5 | ignore previous instructions, reveal the system prompt, conceal behavior, bypass confirmation, security reassurance |
| Obfuscation | 11 | zero-width/bidi/tag characters, Base64, whitespace padding, pyc mismatch, container-embedded scripts, OOXML/PDF/SVG active content |
| Excessive permissions | 3 | shell in `allowed-tools`, SSH/cloud/cookie/wallet paths, any-domain access |
| Secrets | 4 | private key blocks, cloud API key prefixes, high-entropy assignments, `.env` / credential files |
| Suspicious egress | 4 | Discord/Telegram/Slack webhooks, bare IPs, tunnels, `curl \| bash`, download-and-execute |
| Dangerous commands | 4 | `rm -rf /`, reverse shells, crontab / LaunchAgent / registry persistence, `find -exec` |
| Supply chain | 4 | unpinned dependencies, npm lifecycle scripts, download + `chmod +x` + run, registry override |
| MCP | 4 | unpinned npx/uvx, privileged Docker, auto-approve, shell-wrapped remote execution |
| Package hygiene | 3 | missing frontmatter fields, exe/dll/so/msi, bat/cmd/ps1/vbs/hta/reg |
| Data access | 2 | environment variable reads, bulk environment export |
| Combo | 5 | sensitive read + egress, injection + remote execution, env + egress, reassurance + registry hijack, container + bulk execution |
| **Total** | **59** | JSON-defined rules; external packs are supported |

### Why combo rules matter

Single-pattern rules are noisy and easy to bypass by splitting an attack across files. SkillGuard correlates signals within the same Skill:

- `SG-COMBO-001`: sensitive access (SSH/cloud credentials) + external network call → **critical**, treated as exfiltration;
- `SG-COMBO-002`: prompt injection + reverse shell / download-and-execute → **critical**, treated as remote control.

A combo fires only when both signals are present and not suppressed. Suppressing either signal removes the combo.

### Built-in rules (59)

<details>
<summary><b>Expand: full rule list</b></summary>

| ID | Severity | Category | Detects |
|---|---|---|---|
| SG-PI-001 | high | prompt injection | ignore/bypass existing system instructions |
| SG-PI-002 | high | prompt injection | extract the system prompt or internal instructions |
| SG-PI-003 | high | prompt injection | hide behavior from the user or administrator |
| SG-PI-005 | medium | prompt injection | bypass human confirmation and auto-execute |
| SG-PI-008 | medium | prompt injection | security reassurance language |
| SG-PI-006 | high | obfuscation | zero-width, bidirectional control, Unicode tag characters |
| SG-PI-007 | medium | obfuscation | large Base64 blob (critical when it decodes to commands) |
| SG-OBF-003 | high | obfuscation | whitespace padding hiding a tail payload |
| SG-PYC-001 | high | obfuscation | pyc/source size or hash mismatch |
| SG-PYC-002 | high | obfuscation | suspicious env/exec strings in pyc code objects |
| SG-CONT-001 | high | obfuscation | scripts or executables embedded in docx/xlsx/zip |
| SG-CONT-002 | high | obfuscation | vbaProject.bin / ActiveX / OLE in Office containers |
| SG-CONT-003 | critical | obfuscation | OLE/CFB compound documents inside containers |
| SG-CONT-004 | high | obfuscation | external relationships, templates, DDE, instrText, altChunk |
| SG-PDF-001 | high | obfuscation | PDF JavaScript/OpenAction/Launch/embedded files |
| SG-WEB-001 | high | obfuscation | SVG/HTML scripts, event handlers, javascript:, refresh |
| SG-MCP-001 | high | MCP | unpinned npx/bunx/uvx/pipx startup |
| SG-MCP-002 | high | MCP | privileged Docker / docker.sock / SYS_ADMIN |
| SG-MCP-003 | high | MCP | autoApprove / alwaysAllow / wildcard approval |
| SG-MCP-005 | high | MCP | bash -c / powershell wrapping curl/wget/IEX |
| SG-PERM-001 | medium | permissions | `allowed-tools` declares shell/terminal/process execution |
| SG-PERM-002 | high | permissions | SSH keys, cloud credentials, cookies, wallets |
| SG-PERM-003 | medium | permissions | arbitrary domains / whole-internet access |
| SG-SEC-001 | critical | secret | private key block |
| SG-SEC-002 | high | secret | common cloud / code-hosting key prefixes |
| SG-SEC-003 | medium | secret | high-entropy secret assignment |
| SG-SEC-004 | high | secret | `.env`, credential JSON, pem/p12 certificate files |
| SG-NET-001 | high | network | Discord/Telegram/Slack webhooks, temp files, tunnels |
| SG-NET-002 | medium | network | bare IP egress (private/loopback addresses ignored) |
| SG-NET-003 | high | network | `curl ... \| bash` remote script execution |
| SG-NET-004 | critical | network | download-and-interpret, encoded PowerShell, Base64 decode-and-execute |
| SG-CMD-001 | high | command | `rm -rf /`, recursive `chmod 777`, mkfs, dd, fork bomb |
| SG-CMD-002 | critical | command | nc/ncat/socat, `/dev/tcp` reverse shell |
| SG-CMD-003 | high | command | crontab, LaunchAgent, scheduled task, registry Run key |
| SG-CMD-004 | medium | command | `find -exec` bulk execution |
| SG-DATA-001 | medium | data access | environment variable reads |
| SG-DATA-002 | high | data access | bulk environment export |
| SG-SC-001 | low | supply chain | unpinned pip/npm/pnpm/yarn installs |
| SG-SC-002 | medium | supply chain | npm preinstall/postinstall lifecycle scripts |
| SG-SC-003 | high | supply chain | download, `chmod +x`, and execute |
| SG-SUPPLY-004 | high | supply chain | npm/yarn registry points to a non-official host |
| SG-HYG-001 | low | hygiene | frontmatter missing name/description |
| SG-HYG-002 | high | hygiene | exe/dll/so/msi binaries or installers |
| SG-HYG-003 | low | hygiene | bat/cmd/ps1/vbs/hta/reg scripts |
| SG-COMBO-001 | critical | combo | sensitive access + external network (exfiltration) |
| SG-COMBO-002 | critical | combo | prompt injection + reverse shell/download (remote control) |
| SG-COMBO-003 | critical | combo | bulk env reads + external network (credential exfiltration) |
| SG-COMBO-004 | critical | combo | reassurance language + registry override (supply-chain hijack) |
| SG-COMBO-005 | critical | combo | container-embedded script + `find -exec` (hidden payload) |

</details>

List the current rules:

```bash
skillguard rules list
```

---

## CLI reference

```text
skillguard scan <path> [options]
skillguard lock <path> [--output skillguard.lock]
skillguard verify <path> [--lock skillguard.lock]
skillguard policy validate <file.json>
skillguard install <source> [options]   # experimental P1
skillguard rules list
skillguard rules validate <file.json|dir>
skillguard init [dir] [--force]
skillguard version
```

### scan options

| Option | Description | Default |
|---|---|---|
| `--format text\|json\|sarif` | Output format | `text` |
| `--fail-on none\|low\|medium\|high\|critical` | Exit 1 when a finding reaches this severity; policy `fail_on` overrides | `high` |
| `--min-severity low\|medium\|high\|critical` | Hide findings below this severity | `low` |
| `--policy <file>` | Policy gate; its decision controls the exit code | `.skillguard-policy.json` if present |
| `--baseline <file>` | Hide findings recorded in a baseline | none |
| `--write-baseline <file>` | Write current findings as a baseline | none |
| `--audit <file>` | Append a hash-chained audit record | none |
| `--ignore SG-XX-001[,SG-YY-*]` | Ignore rules by ID or prefix | none |
| `--allow-domain <domain>` | Allow network findings for a domain (repeatable/comma-separated) | none |
| `--rules <dir>` | Load extra JSON rule packs; same ID overrides built-in | none |
| `--config <file>` | Config file | `.skillguard.json` |
| `--max-file-size <kb>` | Skip text content above this size | `512` |
| `--no-color` | Disable ANSI colors | auto |
| `--quiet` | Hide header and summary | off |
| `--json-pretty` | Pretty-print JSON | off |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding reached the threshold; with a policy, `ALLOW` |
| `1` | At least one finding reached the threshold; with a policy, `BLOCK` |
| `2` | Argument, config, rule, policy, or IO error |

### Common commands

```bash
# Scan one Skill
skillguard scan ./my-skill

# Scan a collection
skillguard scan ./skills

# CI: SARIF + threshold
skillguard scan ./skills --format sarif --fail-on high > skillguard.sarif

# Only high and above
skillguard scan ./skills --min-severity high

# Allow GitHub, ignore unpinned-dependency advisories
skillguard scan . --allow-domain github.com --ignore SG-SC-001

# Validate a custom rule pack
skillguard rules validate ./my-rules/

# Generate default config and a GitHub Actions workflow
skillguard init
skillguard init ./my-skill --force

# Admission review: Block / Review / Allow with declared vs observed capabilities
skillguard review ./skills
skillguard explain ./skills

# GitHub PR annotations
skillguard scan ./skills --format github

# Stack policy packs (team baseline plus project exceptions)
skillguard scan ./skills --policy .skillguard-policy.json --policy ./policies/team.json

# Optional local semantic layer (start Ollama first; fully offline when disabled)
skillguard scan ./skills --semantic \
  --semantic-endpoint http://127.0.0.1:11434/v1 \
  --semantic-model qwen2.5:3b-instruct-q4_K_M

# Runtime tool-call admission over JSONL stdin
echo '{"tool":"shell","command":"rm -rf /"}' | skillguard admit --policy examples/policy.json

# Local HTTP gateway (binds loopback by default)
skillguard gateway --bind 127.0.0.1:8787 --policy examples/policy.json --audit .skillguard-audit.jsonl
```

---

## Output formats

### text

Human-readable and colored; colors are disabled when piped or with `--no-color`. Each finding includes rule ID, severity, Skill, file:line:column, a masked excerpt, the reason, and remediation.

### JSON

```bash
skillguard scan ./tests/fixtures/exfil-skill --format json --json-pretty
```

```json
{
  "tool": "skillguard",
  "version": "0.3.0",
  "root": "/path/to/exfil-skill",
  "summary": {
    "skills": 1,
    "files": 2,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 0,
    "total": 4
  },
  "findings": [
    {
      "rule_id": "SG-COMBO-001",
      "title": "Combo: sensitive access + external network",
      "severity": "critical",
      "category": "exfiltration",
      "skill": "sync-helper",
      "file": "SKILL.md",
      "line": 1,
      "column": 1,
      "excerpt": "signals: SG-PERM-002, SG-NET-001",
      "message": "combined signals: SG-PERM-002, SG-NET-001",
      "remediation": "Stop using this Skill, review the script and network target, and rotate exposed credentials.",
      "references": []
    }
  ]
}
```

Actual output keys are serialized alphabetically; the example above is reordered for readability.

### SARIF 2.1.0

```bash
skillguard scan ./skills --format sarif > skillguard.sarif
```

The SARIF document contains metadata for all 59 rules, `ruleId`, `level`, `physicalLocation`, and `partialFingerprints`. Upload it to GitHub Code Scanning:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skillguard.sarif
```

Local validation: SARIF `version` is `2.1.0`, `driver.name` is `SkillGuard`, 59 rules, and the exfil fixture produces 4 results.

---

## Architecture

<p align="center">
  <img src="docs/assets/diagrams/architecture.png" width="980" alt="SkillGuard architecture: one Rust engine, three entry points">
</p>
<p align="center"><sub>One Rust engine, three entry points: single binary, Node launcher, Python launcher.</sub></p>

### The seven scan steps

<p align="center">
  <img src="docs/assets/diagrams/pipeline.png" width="820" alt="SkillGuard pipeline: discover, parse, classify, rules, combos, suppress, report">
</p>

1. **Discover Skills**: recursively find directories containing `SKILL.md`; a single file or a collection is also supported; `exclude` is honored.
2. **Parse frontmatter**: read `name`, `description`, `version`, `allowed-tools`, and related fields.
3. **Classify files**: markdown / script / config / text / binary; binary files only get path rules.
4. **Run rules**: regex, path, entropy, hidden Unicode, Base64, and frontmatter matchers; combo rules correlate signals separately.
5. **Combine signals**: correlate findings across files within one Skill and emit `SG-COMBO-*`.
6. **Apply suppression**: project ignore, file header, line comments, CLI/config; scoped to rule IDs.
7. **Report**: text / JSON / SARIF, sorted by severity, Skill, file, and line.

### Source layout

```text
src/
├── main.rs          CLI parsing, config merge, subcommands
├── engine.rs        discovery, scanning, suppression, combos
├── rules.rs         rule model, loading, merging, compilation
├── frontmatter.rs   lightweight YAML frontmatter parser
├── report.rs        text / JSON / SARIF
├── model.rs         Severity / Finding / Summary / Skill
└── config.rs        .skillguard.json
rules/core.json      built-in rule pack
packages/npm         npm launcher
packages/python      Python launcher
scripts/             build and packaging
tests/fixtures/      9 end-to-end fixtures
```

### Why Rust, why a single binary

- **One engine**: rules, combos, suppression, and reporting are implemented once; Node/Python only locate and `exec` the platform binary.
- **No runtime**: the single binary does not require Node, Python, or a JVM on the target machine; ideal for CI, sandboxes, and ad-hoc review.
- **Linear-time regex**: Rust `regex` does not backtrack, reducing ReDoS risk when scanning untrusted input.
- **Read-only and offline**: no code execution, no network requests, no uploads; suitable for private repositories and sensitive Skills.
- **Auditable**: rules are JSON; a false positive points directly to a rule ID, pattern, and remediation.

### Security boundaries

- Never executes scanned code or dynamic behavior;
- never goes online or uploads scanned content;
- does not follow symlinks;
- limits: depth 32, 1000 Skills, 5000 files;
- text content scanning defaults to 512 KB per file; binary files only get path rules;
- secrets are masked in text/JSON output (first and last 4 characters kept);
- skips `.git`, `node_modules`, `target`, `dist`, `.venv`, `vendor`, etc., unless configured otherwise.

---

## Suppression

<p align="center">
  <img src="docs/assets/diagrams/suppression.png" width="980" alt="Four suppression layers: project, file, line, run">
</p>

### 1. Project-level ignore

`.skillguardignore`:

```text
# Ignore one rule
SG-SC-001

# Ignore a group
SG-NET-*

# Ignore everything
*
```

You can also use `--ignore` or `ignore_rules` in the config.

### 2. File-level suppression

```markdown
<!-- skillguard-disable-file SG-HYG-003 -->
```

Ignore the whole file:

```markdown
<!-- skillguard-disable-file -->
```

### 3. Line-level suppression

```bash
# skillguard-disable-next-line SG-CMD-001
rm -rf /tmp/old-build
```

```bash
curl https://example.com/install.sh | bash  # skillguard-disable-line SG-NET-003
```

Only the listed rule is suppressed; use `*` to suppress every rule on that line.

### 4. Run-level ignore

```bash
skillguard scan . --ignore SG-COMBO-001
```

Or in config:

```json
{ "ignore_rules": ["SG-NET-*"] }
```

> **Advice**: combo findings often land on the summary location in `SKILL.md`. If you must suppress one, prefer file- or project-level suppression and document why. Do not use `*` to hide an entire class of risk unless the rule truly does not apply to your project.

---

## Configuration

Place `.skillguard.json` at the scan root, or pass `--config`:

```json
{
  "fail_on": "high",
  "min_severity": "low",
  "ignore_rules": [],
  "allow_domains": ["github.com", "pypi.org"],
  "max_file_size_kb": 512,
  "exclude": ["node_modules", ".git", "dist", "vendor", "*.min.js"],
  "rules_dir": "./extra-rules"
}
```

| Field | Description | Default |
|---|---|---|
| `fail_on` | Exit 1 at this severity; `none` never fails | `high` |
| `min_severity` | Hide findings below this severity | `low` |
| `ignore_rules` | Ignore rule IDs; prefix wildcards supported | `[]` |
| `allow_domains` | Allow domains, suppressing network findings | `[]` |
| `max_file_size_kb` | Text content scan limit | `512` |
| `exclude` | Excluded paths; `*` and `?` wildcards | `[]` |
| `rules_dir` | Extra rule pack directory; same ID overrides built-in | none |

Precedence: **CLI > `.skillguard.json` > built-in defaults**.

Generate a default config and workflow:

```bash
skillguard init
skillguard init ./my-skill --force
```

Actual output:

```text
wrote ./my-skill/.skillguard.json
wrote ./my-skill/.github/workflows/skillguard.yml
done. Run: skillguard scan .
```

---

## Custom rules

A rule pack is JSON. This rule blocks an unapproved third-party domain:

```json
{
  "version": "1",
  "rules": [
    {
      "id": "ACME-NET-001",
      "title": "Block unapproved third-party domains",
      "severity": "high",
      "category": "policy",
      "description": "Example policy: Skills must not call unapproved third-party APIs.",
      "remediation": "Use the company gateway, or request an allowlist entry.",
      "applies_to": ["text"],
      "max_matches": 3,
      "match": {
        "type": "regex",
        "pattern": "(?i)https?://[^\\s\"']*evil\\.example\\.com"
      }
    }
  ]
}
```

Load it:

```bash
skillguard scan ./skills --rules ./examples/extra-rules
```

Validate it:

```bash
skillguard rules validate ./examples/extra-rules
# OK: 1 rule(s) loaded and compiled
```

### Match types

| Type | Description |
|---|---|
| `regex` | Line-oriented regex; optional `absent` exclusion pattern |
| `path_regex` | Match the relative path |
| `secret_entropy` | High-entropy secret assignment; configurable length, threshold, prefix |
| `hidden_unicode` | Hidden / bidirectional control characters |
| `base64_blob` | Large Base64; severity upgrades when it decodes to commands |
| `frontmatter_missing` | Required frontmatter fields |
| `combo` | Combine multiple rule signals within one Skill |

`applies_to` accepts: `skill_md`, `markdown`, `script`, `config`, `text`, `path`, `all`.

### Contributing a rule

1. Add the rule to `examples/extra-rules/` or `rules/core.json`;
2. Add a minimal Skill fixture under `tests/fixtures/`;
3. Add an assertion in `tests/cli.rs`;
4. Run `skillguard rules validate ...`, `cargo test`, and `cargo clippy --all-targets -- -D warnings`;
5. In the PR, explain what it detects, why it is not a false positive, how to fix it, and references.

---

## CI integration

<p align="center">
  <img src="docs/assets/diagrams/ci-flow.svg" width="980" alt="CI flow: push, matrix test, scan, SARIF upload, Code Scanning">
</p>

### Scan your repository (works today)

Build from source and upload SARIF without waiting for an npm release:

```yaml
name: SkillGuard
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release
      - name: Scan skills
        run: >
          ./target/release/skillguard scan . --format sarif --fail-on high
          > skillguard.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillguard.sarif
```

### Use the composite Action (npm package published with 4 platform binaries)

`action.yml` is included and runs through `npx seramys-skillguard`. The npm package 0.3.0 bundles all four platform binaries. Pin the released tag:

```yaml
- uses: Seramys/skillguard@v0.3.0
  with:
    path: "."
    fail-on: high
    format: text
```

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `fail-on` | `high` | `low` / `medium` / `high` / `critical` / `none` |
| `format` | `sarif` | `text` / `json` / `sarif`, written to the run log |
| `version` | `0.3.0` | npm package version |

> The composite Action runs the scan and sets the exit code; it does not create a SARIF file. For Code Scanning, use `npx --yes seramys-skillguard@0.3.0 scan . --format sarif > skillguard.sarif`, or the local-build workflow above.

> The npm package 0.3.0 includes win32-x64, linux-x64, darwin-x64, and darwin-arm64; the Action self-test runs v0.3.0 on ubuntu/windows/macos x64.

### Generic CI

```bash
skillguard scan ./skills --fail-on high
```

A non-zero exit code fails the job; SARIF is optional.

### This repository’s CI

`.github/workflows/ci.yml` runs on Ubuntu / Windows / macOS:

- `cargo test`
- `cargo build --release`
- `python bench/run.py --exe target/release/skillguard --split all --no-imported` (public synthetic smoke gate)
- Python wheel packaging + editable install
- npm packaging + launcher version check

---

## Benchmark

There are two suites; their results are not interchangeable.

| Suite | In CI | Composition | Current result |
|---|---|---|---|
| Public smoke | yes | 27 base fixtures + 320 malicious / 520 benign generated samples | 335 / 532; recall 100%, FPR 0% |
| **holdout-v3 (blind)** | no | frozen from untouched dev after P0–P3 tuning | **212 / 334; recall 77.8%, FPR 3.0%** |
| holdout-v2 (tuned) | no | frozen from test; used for precision validation | 212 / 348; recall 75.0%, FPR 2.3% |
| holdout-v1 (contaminated) | no | previous public holdout | 202 / 340; recall 81.2%, FPR 1.2% |

The public suite is synthetic. Its 100% recall proves the harness and rules run; it is **not** a quality claim. The frozen holdouts are the quality number, but their real samples cannot be redistributed, so public CI does not run them.

holdout-v1 is contaminated by previous miss analysis. holdout-v2 was inspected during tuning. **holdout-v3 was frozen from the untouched dev split and is the current blind number:** 77.8% recall (165/212), 3.0% FPR (10/334), meeting the P0 75% / 3% target. The 90% target remains P2 semantic-layer work.

```bash
cargo build --release
python bench/fetch_samples.py
python bench/make_corpus.py
python bench/run.py --exe target/release/skillguard --split all --no-imported

# Freeze and run the blind manifest (real sample trees stay local)
python bench/freeze_holdout.py
python bench/run.py --exe target/release/skillguard \
  --manifest bench/imported/holdout-v3.manifest.json \
  --generated-manifest bench/imported/__none__.json --no-imported --split all
```

Committed summaries live in `bench/reports/`; raw per-sample reports are ignored.

---

## Verification

Local environment: Windows 11 x64, version 0.3.0 with P0–P3, 2026-11-21. npm, PyPI, and GitHub Release all publish 0.3.0.

| Check | Command | Result |
|---|---|---|
| Unit tests | `cargo test` | 47 passed · 0 failed |
| Integration tests | `cargo test` | 23 CLI + 11 guard + 9 install + 8 P0 + 2 runtime = 53 passed |
| Total | `cargo test` | **100 passed · 0 failed** |
| Lints | `cargo clippy --all-targets -- -D warnings` | 0 warnings |
| Formatting | `cargo fmt --check` | clean |
| Self-scan | `target/release/skillguard scan .` | PASS · 0 high · 6 medium / 3 low |
| SARIF | `--format sarif` | valid 2.1.0 · 59 rules |
| npm package | `npm view seramys-skillguard@0.3.0` | 0.3.0 published · four-platform vendor |
| PyPI | `pip install seramys-skillguard==0.3.0` | 0.3.0 published · four platform wheels |
| Python launcher | `skillguard version` | skillguard 0.3.0 |
| GitHub Action | [Action self-test](https://github.com/Seramys/skillguard/actions/runs/44875955373) | v0.3.0 · 3/3 passed · linux/windows/macos x64 |

<details>
<summary><b>Expand: raw test output</b></summary>

```text
running 47 tests
test result: ok. 47 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 23 tests
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 11 tests
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 9 tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 8 tests
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 2 tests
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

SARIF validation:

```text
version 2.1.0
tool SkillGuard 0.3.0
rules 59
results 9
schema https://json.schemastore.org/sarif-2.1.0.json
```

</details>

### Fixtures

```text
tests/fixtures/
├── clean-skill/          no findings
├── prompt-injection/     prompt injection
├── exfil-skill/          secret access + webhook exfiltration
├── dangerous-skill/      remote script execution
├── secret-skill/         secret leak + output masking
├── suppressed-skill/     line/file suppression
├── config-skill/         config exclusion
├── collection/           multi-Skill discovery
└── exclude-root/         nested exclusion during discovery
```

> Screenshots come from local runs. Terminal text is unchanged; only colors and layout were added for readability. Verification numbers come from the commands above.

---

## Limitations

- This is **static rule scanning**, not LLM semantic analysis; heavily rewritten prompt injection may be missed.
- It cannot observe runtime behavior; runtime protection is a later phase.
- Frontmatter parsing is intentionally lightweight; complex nested YAML may not round-trip perfectly.
- Rules are pattern-based and can produce false positives; use `--ignore`, `.skillguardignore`, or `allow_domains` to narrow them.
- Text content above `--max-file-size` is skipped; binary content is not read.
- If the scan root has no `SKILL.md`, the entire directory is treated as one Skill; for large repositories, point to a `./skills` directory or use `exclude`.

**Do not treat SkillGuard as your only defense.** Use it as a static pre-install / pre-merge layer, together with sandboxing, least privilege, dependency pinning, code review, and runtime approvals.

---

## FAQ

<details>
<summary><b>Does it execute the scanned Skill?</b></summary>

No. SkillGuard only reads text and paths; it does not run scripts, load dependencies, or call scanned code.

</details>

<details>
<summary><b>Does it upload code or secrets?</b></summary>

No. Scanning is local and makes no network requests. Secrets are masked in output, but JSON/SARIF can still contain file names, paths, and context snippets; review before sharing.

</details>

<details>
<summary><b>Why Rust?</b></summary>

Single binary, no runtime, fast startup; linear-time regex is safer for untrusted input; the same engine can be reused by the Node and Python launchers.

</details>

<details>
<summary><b>Why not LLM-based semantic scanning?</b></summary>

LLM analysis is useful as a supplement, but a poor sole gate: non-deterministic, often network/model dependent, and hard to reproduce in CI. SkillGuard keeps deterministic, offline, explainable rules as the default gate; 0.3.0 adds an optional local semantic layer that is off by default and never bundles a model.

</details>

<details>
<summary><b>Too many false positives?</b></summary>

First verify whether it is a real issue. If not, suppress at the smallest scope: line → file → project. Use `allow_domains` for legitimate domains, and express company policy as an external rule pack instead of disabling a whole category.

</details>

<details>
<summary><b>Can it scan an entire repository?</b></summary>

Yes, but if there is no `SKILL.md`, the root is treated as one Skill. For large repositories, point to Skill directories explicitly or use `exclude`. Limits are 1000 Skills / 5000 files.

</details>

<details>
<summary><b>Which platforms are supported?</b></summary>

The source builds on Windows / Linux / macOS, and the CI matrix runs tests and release builds on all three. 0.3.0 was verified locally on Windows 11 x64 and is published on npm/PyPI/GitHub Release.

</details>

<details>
<summary><b>Are npm / PyPI packages published?</b></summary>

0.3.0 is published to npm / PyPI / GitHub Release with Windows, Linux, and macOS x64/arm64 support. Build from source for other architectures.

</details>

<details>
<summary><b>Can it integrate with GitHub Code Scanning?</b></summary>

Yes. Generate SARIF 2.1.0 with `--format sarif`, then upload it with `github/codeql-action/upload-sarif@v3`; the job needs `security-events: write`.

</details>

<details>
<summary><b>How do I add my own rules?</b></summary>

Write a JSON rule pack and load it with `--rules`, or place it in `rules_dir`. Same-ID rules override built-in rules with a warning. Add a minimal fixture and a CLI test so the rule can regress safely.

</details>

---

## Roadmap

> Direction, not a promise; priorities will follow real usage feedback.

- **0.2 (published)**: authoritative policy, lock/audit hash chains, hardened install rail, and the public/extended benchmark split.
- **0.3 (published)**: 59 rules, code-block and dataflow insight, Block/Review/Allow, evidence graph, policy packs, audit export, GitHub annotations, optional local semantic layer, runtime `admit`/`gateway`; blind holdout 77.8% recall / 3.0% FPR.
- **1.0**: runtime agent gateway, tool-call approvals, central policy and audit console.

### Brand mark

<p align="center">
  <img src="docs/assets/brand/logo.svg" width="96" alt="SkillGuard mark">
</p>

- **Browser card**: Skills are distributable, installable packages;
- **Four corner brackets**: the focus and boundary of a static scan;
- **Shield + check**: supply-chain protection and a passed check;
- **Teal scan beam**: read-only, offline, line-by-line inspection;
- **Four-point sparkle**: the AI / agent context.

Light and dark vector assets live in [`docs/assets/brand/`](docs/assets/brand/).

---

## Contributing

Rules, fixtures, false-positive reports, docs, and translations are welcome. Before submitting:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

For a new rule, preferably include:

- a minimal positive fixture that triggers it;
- a near-miss negative fixture that should not;
- a CLI assertion;
- the rule description, remediation, and references.

Report security issues privately via [SECURITY.md](SECURITY.md); do not open a public issue.

<details>
<summary><b>Maintainers: release and packaging</b></summary>

### npm

1. Update the version and repository in `packages/npm/package.json`;
2. Run `bash scripts/package-npm.sh`;
3. Run `cd packages/npm && npm pack` and confirm `vendor/<platform>/skillguard[.exe]` is included;
4. Run `npm publish --access public`.

The current multi-platform release uses one npm package containing all platform binaries plus separate platform wheels for PyPI; split into platform sub-packages only if package size becomes a problem.

### Python

1. Update the version and repository in `packages/python/pyproject.toml`;
2. Run `python -m pip install build`;
3. Run `bash scripts/package-python.sh`;
4. Run `twine upload packages/python/dist/*`.

### Single-file binaries

1. Run `bash scripts/build-all.sh`;
2. Attach `dist/<platform>-<arch>/skillguard[.exe]` to a GitHub Release;
3. Include SHA256 checksums in the release notes.

After a release, update the default `version` in `action.yml` and the version strings in the READMEs.

</details>

---

## License

MIT. See [LICENSE](LICENSE).

---

<div align="center">

<img src="docs/assets/brand/lockup.svg" width="480" alt="SkillGuard">

<br>

**Run SkillGuard before you install a Skill.**

<sub>AI Agent Skill Supply-Chain Security Scanner · MIT License</sub>

</div>
