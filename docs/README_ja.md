# clanet - Claude Code ネットワーク自動化プラグイン

[Netmiko](https://github.com/ktbyers/netmiko) を活用した、Claude Code 向けネットワーク自動化プラグインです。

[English](../README.md) | **日本語**

## 特徴

- **15 のスラッシュコマンド** — show コマンドからコンフィグ投入まで
- **リスク評価** — 設定変更前に Claude が影響度を分析
- **自己ロックアウト防止** — SSH アクセスを遮断する変更を自動検知・ブロック
- **マルチエージェント** — 4 つの専門エージェント（プランナー / コンプライアンス / オペレータ / バリデータ）が、動的にスケーリングしながら連携
- **憲法ルール** — `--skip-compliance` でもスキップ不可の絶対的安全ルール
- **コンプライアンス監査** — 正規表現 + 自然言語（LLM 評価）のカスタマイズ可能なポリシールール
- **Pre/Post 検証** — 変更前後のスナップショット自動取得と差分比較
- **マルチベンダー** — Cisco IOS/XR/NX-OS、Juniper、Arista 他、Netmiko 対応機器全般

## インストール

**ステップ 1** — リポジトリをクローンして依存パッケージをインストール

```bash
git clone https://github.com/takumina/clanet.git
cd clanet
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**ステップ 2** — インベントリを作成

```bash
cp templates/inventory.yaml inventory.yaml
```

`inventory.yaml` を開いて、デバイス情報（`host`, `username`, `password`, `device_type`）を入力します。

```bash
nano inventory.yaml
```

> **セキュリティ推奨**: パスワードは `${ENV_VAR}` 形式で環境変数から読み込めます。詳しくは「[セキュリティに関する注意事項](#セキュリティに関する注意事項)」を参照してください。

**ステップ 3** — Claude Code を起動してプラグインをインストール

```bash
claude    # clanet ディレクトリから起動
```

Claude Code 内で以下を実行:

```
/plugin install clanet@clanet-marketplace
```

## クイックスタート

```bash
/clanet:check router01
/clanet:cmd router01 show ip route
/clanet:health --all
```

## コマンド一覧

### 基本

| コマンド | 説明 |
|---------|------|
| `/clanet:check <device>` | 接続してデバイス基本情報を表示（show version） |

### コマンド実行

| コマンド | 説明 |
|---------|------|
| `/clanet:cmd <device> <command>` | show / 運用コマンドを実行 |
| `/clanet:cmd-interact <device>` | 対話型コマンドを実行（yes/no プロンプト対応） |
| `/clanet:config <device>` | Pre/Post 検証付きの設定変更（ロールバック対応） |
| `/clanet:config-quick <device>` | スナップショットなしの軽量設定変更 |
| `/clanet:config-load <device> <file>` | ファイルからコンフィグを読み込み |

### 監視・運用

| コマンド | 説明 |
|---------|------|
| `/clanet:health [device\|--all]` | ヘルスチェック — Claude がコマンドを選択して分析 |
| `/clanet:health-template [device\|--all]` | ヘルスチェック — テンプレートのコマンドを実行、Claude が分析 |

### その他

| コマンド | 説明 |
|---------|------|
| `/clanet:backup [device\|--all]` | running-config をバックアップ |
| `/clanet:save [device\|--all]` | running-config を startup に保存 |
| `/clanet:commit [device\|--all]` | 変更をコミット（IOS-XR, Junos） |

### 分析・コンプライアンス

| コマンド | 説明 |
|---------|------|
| `/clanet:why <device> <problem>` | トラブルシューティング — Claude がデバイス出力から問題を診断 |
| `/clanet:audit [device\|--all]` | コンプライアンス監査（セキュリティ・ベストプラクティス） |

### マルチエージェントチーム

| コマンド | 説明 |
|---------|------|
| `/clanet:team <device\|all> <task>` | マルチエージェントによる安全な設定変更（計画 → コンプライアンス → 実行 → 検証） |

## 使い方

### 1. デバイスのヘルスチェック

```bash
# Claude がコマンドを選択して分析（推奨）
/clanet:health router01
/clanet:health --all

# テンプレート駆動（templates/health.yaml を使用）
/clanet:health-template router01
/clanet:health-template --all
```

### 2. show コマンドの実行

```bash
/clanet:cmd router01 show ip route
/clanet:cmd router01 show bgp summary
```

### 3. 障害の切り分け

```bash
/clanet:why router01 BGP neighbor 10.0.0.2 is down
```

Claude がデバイスの状態を読み取り、根本原因を診断し、修正案を提示します。

### 4. コンフィグ変更（Pre/Post 検証付き）

```bash
/clanet:config router01
# 1. 構文検証（デバイスの ? ヘルプで確認）
# 2. 変更前スナップショット取得
# 3. コンフィグ適用（承認後）
# 4. 変更後スナップショット取得
# 5. 差分比較して PASS/FAIL 判定
# 6. FAIL の場合ロールバックを提案
```

スナップショットなしの軽量版:

```bash
/clanet:config-quick router01
```

### 5. マルチエージェントチーム（最も安全）

```bash
/clanet:team router01 GigabitEthernet0/0/0/0 に description "Uplink to core-sw01" を設定
# planner            → 状態調査、計画作成、手順書作成
# compliance-checker → ポリシー違反チェック（正規表現 + LLM）
# operator(s)        → コンフィグ生成・適用（動的スケーリング）
# validator          → 変更後のヘルスチェック
```

マルチデバイス変更では、オペレータが自動的にスケーリングされます:

```bash
/clanet:team all すべての WAN インターフェースの OSPF コストを 100 に変更
# デバイス数に基づいて 1〜4 のオペレータを並列実行
```

### 6. 運用コンテキストの活用

複数ステップの作業では、事前にコンテキストを定義できます:

```bash
cp templates/context.yaml context.yaml
# context.yaml を編集
```

```yaml
# context.yaml
topology: |
  router01 (IOS-XR) --- eBGP --- router02 (IOS)
constraints:
  - OSPF 設定は変更しないこと
success_criteria:
  - BGP neighbor 10.0.0.2 が Established であること
```

コンテキストを定義すると、各コマンドが自動的に参照します:

```bash
/clanet:config router01      # success_criteria で PASS/FAIL 判定
/clanet:why router01 BGP down # topology + symptoms で診断
/clanet:team router01 Fix BGP # 全エージェントが constraints を遵守
```

### 7. コンプライアンス監査

```bash
# 基本監査
/clanet:audit router01

# セキュリティ重視の全デバイス監査
/clanet:audit --all --profile security
```

## 安全設計

すべてのコンフィグ変更は **「表示 → 説明 → 確認 → 検証」** のワークフローに従います:

```
1. 表示    適用されるコマンドを明示
2. 説明    Claude が影響度とリスク（LOW/MEDIUM/HIGH/CRITICAL）を分析
3. 確認    人間が承認してから実行
4. 検証    変更後の自動ヘルスチェック
```

組み込みの安全機能:
- **憲法ルール** — `constitution.yaml` の絶対ルール。`--skip-compliance` でもスキップ不可
- **自己ロックアウト防止** — 管理インターフェースや VTY ACL を遮断する変更をブロック
- **二層コンプライアンス** — CLI が正規表現ルールを自動適用 + Claude（LLM）が自然言語 `rule` フィールドを評価
- **リスク評価** — Claude が変更ごとにリスクレベルを判定
- **操作ログ** — すべての変更を `logs/clanet_operations.log` に記録
- **変更後検証** — コンフィグ適用後に自動ヘルスチェック

## マルチエージェントモード

複雑な操作では、`/clanet:team` が 4 つの専門エージェントを、オペレータを動的にスケーリングしながら連携させます:

```bash
/clanet:team router01 GigabitEthernet0/0/0/0 に description "Uplink to core-sw01" を設定
```

```
Phase 1（常に実行）:
         ┌──────────────┐
         │   Planner     │  状態調査 → 計画 → 手順書 → 承認
         └──────┬───────┘
                ↓ 承認済み計画

Phase 2（動的スケーリング）:
   ┌────────────┐  ┌────────────┐
   │ operator-1  │  │ operator-2  │ ...（1-4 オペレータ）
   │ Group 1     │  │ Group 2     │    デバイス数に応じてスケール
   └──────┬─────┘  └──────┬─────┘
          ↓                ↓
         ┌──────────────────────┐
         │  Compliance Checker   │  ポリシー + 憲法チェック
         │                      │  → PASS / WARN / BLOCK
         └──────────────────────┘
          ↓                ↓
         ┌──────────────────────┐
         │     Validator         │  変更後のヘルスチェック
         └──────────────────────┘
```

| エージェント | 役割 | 絶対条件 |
|------------|------|---------|
| **planner** | 状態調査、計画作成、手順書作成 | コンフィグコマンドの実行は禁止。 |
| **compliance-checker** | ポリシーに基づく設定検証（正規表現 + LLM） | コマンド実行は禁止。判定のみ。 |
| **network-operator** | ベンダーごとに正しいコンフィグを生成・実行 | 計画 + コンプライアンス PASS + 人間の承認なしでは実行禁止。 |
| **validator** | 変更後のヘルス検証 | 設定変更は禁止。show コマンドのみ。 |

### 動的オペレータスケーリング

マルチデバイス変更では、オペレータが自動的にスケーリングされます:

| デバイス数 | オペレータ数 | 戦略 |
|-----------|------------|------|
| 1 | 1 | 並列化不要 |
| 2-4 | 2 | 適度な並列化 |
| 5+ | min(4, グループ数) | リソース上限 4 オペレータ |

### 二層コンプライアンス

compliance-checker は 2 層でルールを評価します:

| レイヤー | ルール種別 | 評価者 |
|---------|-----------|--------|
| **正規表現** | `pattern_deny`, `require` など | CLI エンジン（自動） |
| **セマンティック** | 自然言語 `rule` フィールド | LLM 推論（compliance-checker） |

設計思想（[JANOG 57 NETCON エージェントチーム](https://zenn.dev/takumina/articles/01d5d284aa5eef) に着想を得た考え方）:
- **役割分離による安全性** — 各エージェントが実行できる操作を厳密に制限
- **自律ワークフロー** — エージェント間は SendMessage で通信、手動の調整は不要
- **手順書** — Planner が実行前に Markdown の手順書を作成

コンプライアンスポリシーは `templates/policy.yaml`、憲法ルールは `templates/constitution.yaml` で定義されます。

## カスタマイズ

プロジェクトルート（または `~/.clanet.yaml`）に `.clanet.yaml` を配置すると、デフォルト設定を上書きできます。
プラグインの更新でこのファイルが上書きされることはありません。

```yaml
# .clanet.yaml
inventory: ./my-inventory.yaml
policy_file: ./my-policy.yaml
default_profile: security
auto_backup: true
```

| 設定項目 | 説明 | デフォルト |
|---------|------|---------|
| `inventory` | デバイスインベントリファイルのパス | `./inventory.yaml` |
| `policy_file` | コンプライアンスポリシー YAML のパス | `templates/policy.yaml` |
| `default_profile` | デフォルトの監査プロファイル（`basic`/`security`/`full`） | `basic` |
| `auto_backup` | コンフィグ変更前に自動バックアップ | `false` |
| `health_file` | ヘルスチェック / スナップショットコマンドの YAML パス | `templates/health.yaml` |
| `context_file` | 運用コンテキスト YAML のパス | `./context.yaml` |

詳細は `templates/clanet.yaml` を参照してください。

### 運用コンテキスト

`context.yaml` でタスク固有のネットワーク構成、症状、制約、成功条件を定義できます。
定義すると、`/clanet:config`、`/clanet:why`、`/clanet:health`、`/clanet:team` が自動的に参照します。

```bash
cp templates/context.yaml context.yaml
# context.yaml を編集
python3 lib/clanet_cli.py context   # 読み込み確認
```

```yaml
# context.yaml
topology: |
  router01 (IOS-XR) --- eBGP --- router02 (IOS)
symptoms:
  - BGP neighbor 10.0.0.2 が Idle 状態
constraints:
  - OSPF 設定は変更しないこと
success_criteria:
  - BGP neighbor 10.0.0.2 が Established であること
```

| セクション | 使用コマンド |
|-----------|------------|
| `topology` | `/clanet:why`, planner, network-operator |
| `symptoms` | `/clanet:why` |
| `constraints` | planner, compliance-checker, network-operator |
| `success_criteria` | `/clanet:config`, `/clanet:health`, validator |

### カスタムヘルスチェックコマンド

`/clanet:health-template` と `/clanet:snapshot` で実行されるコマンドは `templates/health.yaml` で定義されています。
コード変更なしで自由にカスタマイズできます（例: OSPF チェックの削除、MPLS チェックの追加）。

```bash
cp templates/health.yaml my-health.yaml
# my-health.yaml を編集
```

`.clanet.yaml` で指定:

```yaml
health_file: ./my-health.yaml
```

### カスタムコンプライアンスポリシー

`templates/policy.yaml` をコピーして独自ルールを追加:

```bash
cp templates/policy.yaml my-policy.yaml
# my-policy.yaml を編集
```

`.clanet.yaml` で指定:

```yaml
policy_file: ./my-policy.yaml
```

ルールは 3 つのパターンをサポート:
- **`pattern_deny` のみ** — CLI が自動チェック（高速・決定論的）
- **`rule` のみ** — Claude（LLM）が自然言語ルールを評価
- **両方** — CLI が正規表現をチェック + Claude がセマンティック推論

compliance-checker エージェントと `/clanet:audit` が自動的にカスタムポリシーを使用します。

### 憲法ルール

憲法ルールは**絶対的でスキップ不可**です — `--skip-compliance` でもスキップできません。

```bash
cp templates/constitution.yaml constitution.yaml
# constitution.yaml を編集
```

プロジェクトルートまたは `~/.constitution.yaml` に配置します。`.clanet.yaml` でのパス指定は不要です。

```yaml
# constitution.yaml
rules:
  safety:
    - id: CONST-SAF-001
      name: No write erase
      severity: CRITICAL
      reason: デバイス設定を全消去する破壊的操作。
      pattern_deny: 'write\s+erase'
```

## 対応ベンダー

Netmiko に対応しているもの。

## インベントリ形式

```yaml
devices:
  router01:
    host: 192.168.1.1
    device_type: cisco_ios
    username: admin
    password: admin
    port: 22  # 省略可、デフォルト: 22
```

パスワードに環境変数を使用（推奨）:

```yaml
devices:
  router01:
    host: 192.168.1.1
    device_type: cisco_ios
    username: ${NET_USER}
    password: ${NET_PASSWORD}
```

```bash
export NET_USER='admin'
export NET_PASSWORD='your-secure-password'
```

## アーキテクチャ

```
clanet/
├── .claude-plugin/plugin.json    # プラグインマニフェスト
├── commands/                     # 15 のスラッシュコマンド
├── agents/                       # 4 つの専門エージェント
│   ├── planner.md                # 状態調査、計画作成、手順書作成
│   ├── compliance-checker.md     # ポリシー検証（読み取り専用）
│   ├── network-operator.md       # コンフィグ生成・実行
│   └── validator.md              # 変更後のヘルス検証
├── skills/team/SKILL.md          # マルチエージェントオーケストレーション
├── lib/clanet_cli.py             # 共通 CLI エンジン（単一ソースオブトゥルース）
├── tests/test_cli.py             # ユニットテスト（ネットワーク不要）
├── templates/                    # ユーザーがカスタマイズする設定テンプレート
│   ├── inventory.yaml            # デバイスインベントリ
│   ├── context.yaml              # 運用コンテキスト
│   ├── clanet.yaml               # プラグイン設定
│   ├── policy.yaml               # コンプライアンスルール（正規表現 + LLM）
│   ├── constitution.yaml         # 憲法ルール（スキップ不可）
│   └── health.yaml               # ヘルスチェックコマンド
└── requirements.txt              # Python 依存パッケージ
```

全 15 コマンドと 4 エージェントが `lib/clanet_cli.py` を共有し、接続・パースロジックの重複を排除しています。

### clanet の実装と Claude の役割

| レイヤー | 実装 | 例 |
|---------|------|-----|
| **SSH・デバイス自動化** | Python (Netmiko) `lib/clanet_cli.py` | 接続、コマンド実行、バックアップ、スナップショット、ログ |
| **ポリシーエンジン** | Python 正規表現 `_evaluate_rule()` | `pattern_deny`, `require`, `recommend` — 決定論的ルール評価; `rule` フィールド → LLM 評価 |
| **安全ワークフロー** | プロンプト定義 `commands/` | 「表示→説明→確認→検証」— 構造化されたプロンプトシーケンス |
| **リスク評価・診断** | Claude の LLM 推論（プロンプトで誘導） | `/clanet:why` のトラブルシューティング、変更リスク判定 |
| **エージェント連携** | Claude Code エージェントフレームワーク `agents/` | ツール制限付きの役割分離エージェント |

clanet は Claude Code プラグインです。プロンプト設計とツール連携により、Claude の推論能力をネットワーク運用に活用します。「知性」は Claude 自身が提供し、clanet はドメイン知識・安全ガードレール・デバイス自動化レイヤーを提供します。

## セキュリティに関する注意事項

- **認証情報**: `inventory.yaml` にはデバイスの認証情報が含まれるため、デフォルトで gitignore 対象です。絶対にコミットしないでください。
- **環境変数**: `inventory.yaml` 内で `${VAR_NAME}` 構文を使用してパスワードやユーザー名を指定できます（例: `password: ${NET_PASSWORD}`）。平文での保存を回避できます。
- **SSH のみ**: すべてのデバイス通信は Netmiko 経由の SSH です。Telnet や HTTP は使用しません。
- **外部通信なし**: clanet は外部サービスへのデータ送信を一切行いません。すべての操作はローカルの SSH セッションです。
- **人間の承認プロセス**: コンフィグ変更には必ず人間の明示的な承認が必要です。Claude はリスクを評価しますが、HIGH/CRITICAL の変更を自動適用することはありません。
- **監査証跡**: すべてのコンフィグ操作がタイムスタンプ・デバイス名・アクション・ステータスとともに `logs/clanet_operations.log` に記録されます。

## トラブルシューティング

| 問題 | 原因 | 解決方法 |
|-----|------|---------|
| `ERROR: inventory.yaml not found` | インベントリファイルが見つからない | `cp templates/inventory.yaml inventory.yaml` して編集 |
| `ERROR: Netmiko is not installed` | Python 依存パッケージ不足 | `pip install netmiko` |
| `ERROR: device 'xxx' not found` | デバイス名がインベントリにない | `inventory.yaml` のデバイス名を確認。正確な名前か IP を使用 |
| `SSH connection timeout` | デバイスに到達できない | inventory のホスト/ポートを確認。`ssh user@host -p port` でテスト |
| `${VAR_NAME} not expanded` | 環境変数が未設定 | clanet 実行前に `export VAR_NAME='value'` |
| `WARN: policy file not found` | カスタムポリシーパスが無効 | `.clanet.yaml` の `policy_file` を確認、またはデフォルトを使用 |

## 要件

- Python 3.10+
- 依存パッケージ: `pip install -r requirements.txt`（Netmiko, PyYAML）
- ネットワークデバイスへの SSH アクセス

## 作者

[takumina](https://github.com/takumina) 作成

## ライセンス

MIT License
