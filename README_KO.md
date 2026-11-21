<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/logo-dark.svg">
  <img src="docs/assets/brand/logo.svg" width="150" alt="SkillGuard logo">
</picture>

# SkillGuard

**AI Agent Skill 공급망 보안 스캐너**

Skill을 설치하기 전에 SkillGuard를 먼저 실행하세요.

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE) [![Tests](https://img.shields.io/badge/tests-100%20passing-17A673?style=flat-square)](README_EN.md#verification) [![Rules](https://img.shields.io/badge/rules-59-5B6CFF?style=flat-square)](rules/core.json) [![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-8B7CF6?style=flat-square)](README_EN.md#output-formats)

[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

[빠른 시작](#빠른-시작) · [검사 항목](#검사-항목) · [아키텍처](#아키텍처) · [검증](#검증)

</div>

<p align="center">
  <img src="docs/assets/screenshots/scan-exfil.png" width="920" alt="SkillGuard 스캔 결과">
</p>
<p align="center"><sub>실제 출력: <code>~/.ssh/id_rsa</code>를 읽고 외부로 전송하는 Skill을 조합 규칙이 <b>critical</b>로 판정.</sub></p>
<p align="center"><sub>규칙 문구는 현재 중국어입니다. CLI와 JSON/SARIF 스키마는 언어 중립적입니다.</sub></p>

> 이 페이지는 한국어 간단 가이드입니다. 전체 설정, 규칙 목록, CI 연동은 [English](README_EN.md) 또는 [简体中文](README.md)를 참고하세요.

---

## SkillGuard란

Agent Skill은 보통 다음과 같은 디렉터리입니다.

```text
my-skill/
├── SKILL.md          # frontmatter + 에이전트 지시
├── scripts/          # sh / py / js / ps1 ...
├── config/           # json / yaml / env ...
└── assets/
```

Skill을 설치한다는 것은 **지시, 도구 권한, 스크립트, 네트워크 접근**을 동시에 Agent에 넘기는 일입니다. 악성 Skill은 SSH 키나 클라우드 자격 증명을 읽고, Webhook으로 데이터를 보내고, `curl | bash`로 원격 코드를 실행하거나, 프롬프트 인젝션으로 시스템 지시를 덮어쓸 수 있습니다.

SkillGuard는 **설치 전 / CI 전**에 정적 검사를 수행합니다. 파일을 읽기만 하고 코드를 실행하지 않으며 네트워크에 연결하지 않습니다. 결과는 text / JSON / SARIF로 출력하고 GitHub Code Scanning에 연동할 수 있습니다.

런타임 샌드박스나 백신이 아닙니다. Skill 공급망의 첫 번째 정적 게이트입니다.

---

## 빠른 시작

Rust stable이 필요합니다.

```bash
git clone https://github.com/Seramys/skillguard.git
cd skillguard
cargo build --release

./target/release/skillguard scan ./tests/fixtures/exfil-skill --no-color
```

Windows PowerShell:

```powershell
cargo build --release
.\target\release\skillguard.exe scan .\tests\fixtures\exfil-skill --no-color
```

예상 결과: `critical` 조합 1건, `high` 2건, `medium` 1건, 종료 코드 `1`.

```bash
# CI: high 이상이면 실패
./target/release/skillguard scan ./skills --fail-on high

# SARIF 출력
./target/release/skillguard scan ./skills --format sarif --fail-on high > skillguard.sarif
```

---

## 설치

> **0.3.0 현재 상태**: npm / PyPI / GitHub Release 0.3.0이 공개되었으며 win32-x64, linux-x64, darwin-x64, darwin-arm64를 포함합니다. Release v0.3.0에는 4개 플랫폼 바이너리와 SHA256SUMS가 있습니다.

### 1. 단일 바이너리 (권장)

```bash
cargo build --release
./target/release/skillguard version
bash scripts/build.sh     # dist/<platform>-<arch>/ 에 복사
```

### 2. Node

공개됨 (멀티 플랫폼):

```bash
npx --yes seramys-skillguard@0.3.0 scan ./skills --fail-on high
```

저장소 내 검증:

```bash
node packages/npm/bin/skillguard.js scan ./tests/fixtures/clean-skill --no-color
```

### 3. Python

공개됨 (Windows x64):

```bash
pip install seramys-skillguard
skillguard scan ./skills --fail-on high
```

저장소 내 검증:

```bash
python -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip setuptools wheel
.venv/Scripts/python -m pip install -e packages/python --no-build-isolation
.venv/Scripts/skillguard scan tests/fixtures/clean-skill --no-color
```

Node / Python 런처는 얇은 래퍼이며, 동일한 Rust 엔진과 `rules/core.json`을 사용합니다.

---

## 검사 항목

| 카테고리 | 규칙 수 | 주요 신호 |
|---|---:|---|
| 프롬프트 인젝션 | 5 | 기존 지시 무시, 시스템 프롬프트 추출, 사용자 은폐, 확인 우회 |
| 난독화 | 11 | 제로폭/양방향/Unicode 태그, Base64, 공백 패딩, pyc 변조, 컨테이너 내 스크립트, OOXML/PDF/SVG |
| 과도한 권한 | 3 | Shell 실행, SSH/클라우드/Cookie/지갑 접근, 임의 도메인 |
| 비밀 정보 | 4 | 개인 키, API 키 프리픽스, 고엔트로피 값, `.env` / 자격 증명 파일 |
| 의심스러운 통신 | 4 | Discord/Telegram/Slack Webhook, 원시 IP, 터널, `curl \| bash` |
| 위험한 명령 | 4 | `rm -rf /`, 리버스 셸, crontab / LaunchAgent / 레지스트리 지속성, `find -exec` |
| 공급망 | 4 | 버전 미고정, npm 라이프사이클 스크립트, 다운로드 후 실행, registry 덮어쓰기 |
| MCP | 4 | 미고정 npx/uvx, 권한 높은 Docker, 자동 승인, shell 래핑 원격 실행 |
| 패키지 위생 | 3 | frontmatter 누락, exe/dll/so/msi, bat/cmd/ps1/vbs/hta/reg |
| 데이터 접근 | 2 | 환경 변수 읽기, 일괄 내보내기 |
| 조합 | 5 | 민감 읽기+외부 통신, 주입+원격 실행, env+통신, 안심 문구+registry, 컨테이너+일괄 실행 |
| **합계** | **59** | JSON 정의, 외부 규칙 팩 지원 |

조합 규칙(`SG-COMBO-001` / `SG-COMBO-002`)은 단일 문자열이 아니라 동일 Skill 내의 여러 신호를 연관시킵니다. 한 신호를 억제하면 조합 위험도 사라집니다.

---

## CLI

```text
skillguard scan <path> [options]
skillguard rules list
skillguard rules validate <file.json|dir>
skillguard init [dir] [--force]
skillguard version
```

| 옵션 | 설명 |
|---|---|
| `--format text\|json\|sarif` | 출력 형식 |
| `--fail-on none\|low\|medium\|high\|critical` | 해당 심각도에서 종료 코드 1 |
| `--min-severity ...` | 낮은 심각도 숨김 |
| `--ignore SG-XX-001[,SG-YY-*]` | 규칙 무시 (접두사 지원) |
| `--allow-domain <domain>` | 허용할 도메인 |
| `--rules <dir>` | 추가 JSON 규칙 팩 |
| `--config <file>` | 설정 파일 |
| `--max-file-size <kb>` | 텍스트 내용 상한 |
| `--no-color` / `--quiet` / `--json-pretty` | 출력 제어 |

종료 코드: `0` = 통과, `1` = 임계값 도달, `2` = 인자/설정/규칙/IO 오류.

---

## 아키텍처

<p align="center">
  <img src="docs/assets/diagrams/architecture.png" width="980" alt="SkillGuard 아키텍처">
</p>

<p align="center">
  <img src="docs/assets/diagrams/pipeline.png" width="820" alt="SkillGuard 스캔 파이프라인">
</p>

1. `SKILL.md`가 있는 디렉터리를 재귀적으로 탐색
2. frontmatter 파싱
3. 파일을 markdown / script / config / text / binary로 분류
4. regex, 경로, 엔트로피, 숨은 문자, Base64, frontmatter 규칙 실행
5. 동일 Skill 내 신호 조합
6. 프로젝트 / 파일 / 라인 / CLI 억제 적용
7. text / JSON / SARIF 출력

**보안 경계**: 코드를 실행하지 않음, 네트워크 연결 없음, 심볼릭 링크를 따르지 않음, 깊이 32 / Skill 1000 / 파일 5000 제한, 파일당 512 KB 내용 상한, 비밀 정보는 출력에서 마스킹.

---

## 검증

<p align="center">
  <img src="docs/assets/screenshots/verification-en.png" width="980" alt="로컬 검증 보고서">
</p>

환경: Windows 11 x64, 0.3.0, 2026-11-21. npm / PyPI / GitHub Release 모두 0.3.0을 공개했습니다.

- 테스트: 100개 통과 (47 유닛 + 53 통합)
- Clippy: 경고 0
- 자체 스캔: PASS (high 0, medium 6, low 3)
- SARIF: 2.1.0, 59개 규칙, 9개 결과

자세한 수치와 원본 로그는 [English README](README_EN.md#verification)를 참고하세요.

---

## 제한 사항

- 정적 규칙 스캔이며 LLM 의미 분석이 아닙니다. 재작성된 프롬프트 인젝션은 놓칠 수 있습니다.
- 런타임 동작은 탐지할 수 없습니다.
- 패턴 매칭이므로 오탐이 있습니다. `--ignore`, `.skillguardignore`, `allow_domains`로 조정하세요.
- 바이너리 내용이나 상한을 초과한 텍스트는 읽지 않습니다.

**SkillGuard만 의존하지 마세요.** 샌드박스, 최소 권한, 의존성 고정, 코드 리뷰, 런타임 승인과 함께 사용하세요.

---

## 링크

- 전체 중국어 문서: [README.md](README.md)
- 전체 영어 문서: [README_EN.md](README_EN.md)
- 보안 정책: [SECURITY.md](SECURITY.md)
- 라이선스: [MIT](LICENSE)

<div align="center">

<img src="docs/assets/brand/lockup.svg" width="480" alt="SkillGuard">

<br>

**Skill을 설치하기 전에, SkillGuard를.**

</div>
