<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/logo-dark.svg">
  <img src="docs/assets/brand/logo.svg" width="150" alt="SkillGuard logo">
</picture>

# SkillGuard

**AI Agent Skill のサプライチェーン・セキュリティスキャナー**

Skill をインストールする前に、SkillGuard を一度走らせてください。

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE) [![Tests](https://img.shields.io/badge/tests-100%20passing-17A673?style=flat-square)](README_EN.md#verification) [![Rules](https://img.shields.io/badge/rules-59-5B6CFF?style=flat-square)](rules/core.json) [![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-8B7CF6?style=flat-square)](README_EN.md#output-formats)

[简体中文](README.md) · [English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md)

[クイックスタート](#クイックスタート) · [検出内容](#検出内容) · [アーキテクチャ](#アーキテクチャ) · [検証](#検証)

</div>

<p align="center">
  <img src="docs/assets/screenshots/scan-exfil.png" width="920" alt="SkillGuard のスキャン結果">
</p>
<p align="center"><sub>実際の出力：<code>~/.ssh/id_rsa</code> を読み取り外部送信する Skill を、組み合わせルールが <b>critical</b> と判定。</sub></p>
<p align="center"><sub>ルール文言は現在中国語です。CLI と JSON/SARIF のスキーマは言語非依存です。</sub></p>

> このページは日本語の簡易ガイドです。詳細なリファレンス、設定、ルール一覧、CI 連携は [English](README_EN.md) または [简体中文](README.md) を参照してください。

---

## SkillGuard とは

Agent Skill は通常、次のようなディレクトリです。

```text
my-skill/
├── SKILL.md          # frontmatter + エージェントへの指示
├── scripts/          # sh / py / js / ps1 ...
├── config/           # json / yaml / env ...
└── assets/
```

Skill のインストールは、**指示・ツール権限・スクリプト・ネットワークアクセス**を同時に Agent へ渡すことを意味します。悪意のある Skill は、SSH 鍵やクラウド認証情報を読み取ったり、Webhook で外部送信したり、`curl | bash` でリモートコードを実行したり、プロンプトインジェクションでシステム指示を上書きしたりできます。

SkillGuard は**インストール前 / CI 前**に静的検査を行います。ファイルを読むだけで、コードを実行せず、ネットワークにも接続しません。検出結果は text / JSON / SARIF で出力でき、GitHub Code Scanning にも連携できます。

ランタイムサンドボックスやアンチウイルスではありません。Skill サプライチェーンの最初の静的ゲートです。

---

## クイックスタート

Rust stable が必要です。

```bash
git clone https://github.com/Seramys/skillguard.git
cd skillguard
cargo build --release

./target/release/skillguard scan ./tests/fixtures/exfil-skill --no-color
```

Windows PowerShell：

```powershell
cargo build --release
.\target\release\skillguard.exe scan .\tests\fixtures\exfil-skill --no-color
```

期待される結果：`critical` の組み合わせリスク 1 件、`high` 2 件、`medium` 1 件、終了コード `1`。

```bash
# CI 向け：high 以上で失敗
./target/release/skillguard scan ./skills --fail-on high

# SARIF 出力
./target/release/skillguard scan ./skills --format sarif --fail-on high > skillguard.sarif
```

---

## インストール

> **0.3.0 の現状**：npm / PyPI / GitHub Release の 0.3.0 は公開済みで、win32-x64 / linux-x64 / darwin-x64 / darwin-arm64 を含みます。Release v0.3.0 には 4 つのプラットフォームバイナリと SHA256SUMS があります。

### 1. 単一バイナリ（推奨）

```bash
cargo build --release
./target/release/skillguard version
bash scripts/build.sh     # dist/<platform>-<arch>/ にコピー
```

### 2. Node

公開済み（マルチプラットフォーム）：

```bash
npx --yes seramys-skillguard@0.3.0 scan ./skills --fail-on high
```

リポジトリ内での検証：

```bash
node packages/npm/bin/skillguard.js scan ./tests/fixtures/clean-skill --no-color
```

### 3. Python

公開済み（Windows x64）：

```bash
pip install seramys-skillguard
skillguard scan ./skills --fail-on high
```

リポジトリ内での検証：

```bash
python -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip setuptools wheel
.venv/Scripts/python -m pip install -e packages/python --no-build-isolation
.venv/Scripts/skillguard scan tests/fixtures/clean-skill --no-color
```

Node / Python は薄いランチャーで、同じ Rust エンジンと `rules/core.json` を使います。

---

## 検出内容

| カテゴリ | ルール数 | 主なシグナル |
|---|---:|---|
| プロンプトインジェクション | 5 | 既存指示の無視、システムプロンプトの取得、ユーザーへの隠蔽、確認の回避 |
| 難読化 | 11 | ゼロ幅/双方向/Unicode タグ、Base64、空白パディング、pyc 改ざん、コンテナ内スクリプト、OOXML/PDF/SVG |
| 過剰な権限 | 3 | Shell 実行、SSH/クラウド/Cookie/ウォレットへのアクセス、任意ドメイン |
| 秘密情報 | 4 | 秘密鍵、API キー、高エントロピー値、`.env` / 認証情報ファイル |
| 不審な通信 | 4 | Discord/Telegram/Slack Webhook、生 IP、トンネル、`curl \| bash` |
| 危険なコマンド | 4 | `rm -rf /`、リバースシェル、crontab / LaunchAgent / レジストリ永続化、`find -exec` |
| サプライチェーン | 4 | バージョン未固定、npm ライフサイクルスクリプト、ダウンロード後の実行、registry 上書き |
| MCP | 4 | 未固定 npx/uvx、特権 Docker、自動承認、shell 経由のリモート実行 |
| パッケージ衛生 | 3 | frontmatter 不足、exe/dll/so/msi、bat/cmd/ps1/vbs/hta/reg |
| データアクセス | 2 | 環境変数の読み取り、一括エクスポート |
| 組み合わせ | 5 | 機密読取+外部通信、注入+実行、env+通信、安心文言+registry、コンテナ+一括実行 |
| **合計** | **59** | JSON 定義、外部ルールパック対応 |

組み合わせルール（`SG-COMBO-001` / `SG-COMBO-002`）は、単一の文字列ではなく複数シグナルを同一 Skill 内で関連付けます。片方のシグナルを抑制すると、組み合わせリスクも消えます。

---

## CLI

```text
skillguard scan <path> [options]
skillguard rules list
skillguard rules validate <file.json|dir>
skillguard init [dir] [--force]
skillguard version
```

| オプション | 説明 |
|---|---|
| `--format text\|json\|sarif` | 出力形式 |
| `--fail-on none\|low\|medium\|high\|critical` | この重要度で終了コード 1 |
| `--min-severity ...` | 低い重要度を非表示 |
| `--ignore SG-XX-001[,SG-YY-*]` | ルールを無視（プレフィックス対応） |
| `--allow-domain <domain>` | 許可するドメイン |
| `--rules <dir>` | 追加の JSON ルールパック |
| `--config <file>` | 設定ファイル |
| `--max-file-size <kb>` | テキスト内容の上限 |
| `--no-color` / `--quiet` / `--json-pretty` | 出力制御 |

終了コード：`0` = 合格、`1` = しきい値到達、`2` = 引数/設定/ルール/IO エラー。

---

## アーキテクチャ

<p align="center">
  <img src="docs/assets/diagrams/architecture.png" width="980" alt="SkillGuard アーキテクチャ">
</p>

<p align="center">
  <img src="docs/assets/diagrams/pipeline.png" width="820" alt="SkillGuard スキャンパイプライン">
</p>

1. `SKILL.md` を含むディレクトリを再帰的に発見
2. frontmatter を解析
3. ファイルを markdown / script / config / text / binary に分類
4. regex、パス、エントロピー、隠し文字、Base64、frontmatter のルールを実行
5. 同一 Skill 内のシグナルを組み合わせ
6. プロジェクト / ファイル / 行 / CLI の抑制を適用
7. text / JSON / SARIF で出力

**安全境界**：コードを実行しない、ネットワークに接続しない、シンボリックリンクを追わない、深度 32 / Skill 1000 / ファイル 5000 の上限、単一ファイル 512 KB の内容上限、秘密情報は出力でマスク。

---

## 検証

<p align="center">
  <img src="docs/assets/screenshots/verification-en.png" width="980" alt="ローカル検証レポート">
</p>

環境：Windows 11 x64、0.3.0、2026-11-21。npm / PyPI / GitHub Release はすべて 0.3.0 を公開済みです。

- テスト：100 件成功（47 ユニット + 53 統合）
- Clippy：警告 0
- 自己スキャン：PASS（high 0、medium 6、low 3）
- SARIF：2.1.0、59 ルール、9 結果

その他の数値と生ログは [English README](README_EN.md#verification) を参照してください。

---

## 制限事項

- 静的ルールスキャンであり、LLM による意味解析ではありません。書き換えられたプロンプトインジェクションは見逃す可能性があります。
- 実行時の挙動は検出できません。
- パターンマッチのため誤検知があります。`--ignore`、`.skillguardignore`、`allow_domains` で調整してください。
- バイナリ内容や上限を超えるテキストは読みません。

**SkillGuard だけに依存しないでください。** サンドボックス、最小権限、依存関係の固定、コードレビュー、実行時承認と組み合わせてください。

---

## リンク

- 完全な中国語版：[README.md](README.md)
- 完全な英語版：[README_EN.md](README_EN.md)
- セキュリティポリシー：[SECURITY.md](SECURITY.md)
- ライセンス：[MIT](LICENSE)

<div align="center">

<img src="docs/assets/brand/lockup.svg" width="480" alt="SkillGuard">

<br>

**Skill をインストールする前に、SkillGuard を。**

</div>
