# clanet - Claude Code ネットワーク自動化プラグイン

[Netmiko](https://github.com/ktbyers/netmiko) を活用した、Claude Code 向けネットワーク自動化プラグインです。

[English](../README.md) | **日本語**

## 特徴

- **16 のスラッシュコマンド** — show コマンドからコンフィグ投入まで
- **リスク評価** — 設定変更前に Claude が影響度を分析
- **自己ロックアウト防止** — SSH アクセスを遮断する変更を自動検知・ブロック
- **マルチエージェント** — 3 つの専門エージェント（コンプライアンス / オペレータ / バリデータ）が自律連携
- **コンプライアンス監査** — カスタマイズ可能なポリシールールと重大度レベル
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

`inventory.yaml` を開いて、自分のデバイス情報（host, username, password, device_type）を入力します:

```bash
nano inventory.yaml
```

> **セキュリティ推奨**: パスワードは `${ENV_VAR}` 形式で環境変数から読み込めます。詳しくは「[インベントリ形式](#インベントリ形式)」を参照してください。

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
/clanet:clanet router01
/clanet:cmd router01 show ip route
/clanet:check --all
```

## コマンド一覧

### 基本

| コマンド | 説明 |
|---------|------|
| `/clanet:clanet <device>` | 接続してデバイス基本情報を表示（show version） |

### コマンド実行

| コマンド | 説明 |
|---------|------|
| `/clanet:cmd <device> <command>` | show / 運用コマンドを実行 |
| `/clanet:config <device>` | コンフィグコマンドを投入 |
| `/clanet:deploy <device> <file>` | ファイルからコンフィグを投入 |
| `/clanet:interactive <device>` | 対話型コマンドを実行（yes/no プロンプト対応） |

### 監視・運用

| コマンド | 説明 |
|---------|------|
| `/clanet:check [device\|--all]` | ヘルスチェック（インターフェース、BGP、OSPF） |
| `/clanet:backup [device\|--all]` | running-config のバックアップ |
| `/clanet:session [device\|--all]` | 接続性・セッション状態を確認 |

### モード・設定管理

| コマンド | 説明 |
|---------|------|
| `/clanet:mode <device> <action>` | モード切替（enable, config, exit-config, check） |
| `/clanet:save [device\|--all]` | running-config を startup に保存 |
| `/clanet:commit [device\|--all]` | 変更をコミット（IOS-XR, Junos） |

### 分析・コンプライアンス

| コマンド | 説明 |
|---------|------|
| `/clanet:why <device> <problem>` | トラブルシューティング — Claude がデバイス出力から問題を診断 |
| `/clanet:validate <device>` | Pre/Post 検証と自動ロールバック |
| `/clanet:audit [device\|--all]` | コンプライアンス監査（セキュリティ・ベストプラクティス） |

### マルチエージェントチーム

| コマンド | 説明 |
|---------|------|
| `/clanet:team <device> <task>` | 3 エージェントによる安全な設定変更（コンプライアンス → 実行 → 検証） |

## 使い方

### 1. デバイスのヘルスチェック

```bash
# 単一デバイス
/clanet:check router01

# 全デバイス
/clanet:check --all
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

### 4. コンフィグ変更（単発）

```bash
/clanet:config router01
# Claude が設定内容を確認 → リスク評価 → 承認確認 → 適用
```

### 5. Pre/Post 検証付きコンフィグ変更

```bash
/clanet:validate router01
# 1. 変更前スナップショット取得
# 2. コンフィグ適用（承認後）
# 3. 変更後スナップショット取得
# 4. 差分比較して PASS/FAIL 判定
# 5. FAIL の場合ロールバックを提案
```

### 6. マルチエージェントチーム（最も安全）

```bash
/clanet:team router01 GigabitEthernet0/0/0/0 に description "Uplink to core-sw01" を設定
# compliance-checker → ポリシー違反チェック
# network-operator   → コンフィグ生成・適用
# validator          → 変更後のヘルスチェック
```

### 7. 運用コンテキストの活用

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
/clanet:validate router01    # success_criteria で PASS/FAIL 判定
/clanet:why router01 BGP down # topology + symptoms で診断
/clanet:team router01 Fix BGP # 3 エージェントが constraints を遵守
```

### 8. コンプライアンス監査

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
- **自己ロックアウト防止** — 管理インターフェースや VTY ACL を遮断する変更をブロック
- **リスク評価** — Claude が変更ごとにリスクレベルを判定
- **操作ログ** — すべての変更を `logs/clanet_operations.log` に記録
- **変更後検証** — コンフィグ適用後に自動ヘルスチェック

## マルチエージェントモード

複雑な操作では、`/clanet:team` が役割分離された 3 つの Claude Code エージェントを連携させます:

```bash
/clanet:team router01 GigabitEthernet0/0/0/0 に description "Uplink to core-sw01" を設定
```

3 つの専門エージェントが自律的に連携:

```
         ┌──────────────┐
         │  Operator     │  コンフィグ生成 → 実行
         └──────┬───────┘
                ↓ コンプライアンスチェック依頼
         ┌──────────────┐
         │  Compliance   │  ポリシー違反チェック
         │  Checker      │  → PASS / WARN / BLOCK
         └──────┬───────┘
                ↓ コンフィグ適用後
         ┌──────────────┐
         │  Validator    │  変更後のヘルスチェック
         │               │  → PASS / FAIL
         └──────────────┘
```

| エージェント | 役割 | 絶対条件 |
|------------|------|---------|
| **compliance-checker** | ポリシーに基づく設定検証 | コマンド実行は禁止。判定のみ。 |
| **network-operator** | ベンダー正確なコンフィグ生成・実行 | コンプライアンス PASS なしでは実行禁止。 |
| **validator** | 変更後のヘルス検証 | 設定変更は禁止。show コマンドのみ。 |

設計思想（[JANOG 57 NETCON エージェントチーム](https://zenn.dev/takumina/articles/01d5d284aa5eef) に着想を得ています）:
- **役割分離による安全性** — 各エージェントが実行できる操作を厳密に制限
- **自律ワークフロー** — エージェント間は SendMessage で通信、手動の調整は不要

コンプライアンスポリシーは `templates/policy.yaml` で定義され、自由にカスタマイズできます。

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
定義すると、`/clanet:validate`、`/clanet:why`、`/clanet:check`、`/clanet:team` が自動的に参照します。

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
| `topology` | `/clanet:why`, network-operator |
| `symptoms` | `/clanet:why` |
| `constraints` | compliance-checker, network-operator |
| `success_criteria` | `/clanet:validate`, `/clanet:check`, validator |

### カスタムヘルスチェックコマンド

`/clanet:check` と `/clanet:snapshot` で実行されるコマンドは `templates/health.yaml` で定義されています。
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

compliance-checker エージェントと `/clanet:audit` が自動的にカスタムポリシーを使用します。

## 対応ベンダー

[Netmiko](https://github.com/ktbyers/netmiko) を使用。[対応プラットフォーム一覧](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md):

| ベンダー | device_type | テスト済 |
|---------|-------------|---------|
| Cisco IOS | `cisco_ios` | - |
| Cisco IOS-XR | `cisco_xr` | Yes |
| Cisco NX-OS | `cisco_nxos` | - |
| Juniper Junos | `juniper_junos` | - |
| Arista EOS | `arista_eos` | - |
| その他多数 | [一覧](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md) | - |

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
├── commands/                     # 16 のスラッシュコマンド
├── agents/                       # 3 つの専門エージェント
├── skills/team/SKILL.md          # マルチエージェントオーケストレーション
├── lib/clanet_cli.py             # 共通 CLI エンジン（単一ソースオブトゥルース）
├── tests/test_cli.py             # ユニットテスト（ネットワーク不要）
├── templates/                    # ユーザーがカスタマイズする設定テンプレート
│   ├── inventory.yaml            # デバイスインベントリ
│   ├── context.yaml              # 運用コンテキスト
│   ├── clanet.yaml               # プラグイン設定
│   ├── policy.yaml               # コンプライアンスルール
│   └── health.yaml               # ヘルスチェックコマンド
└── requirements.txt              # Python 依存パッケージ
```

全 16 コマンドと 3 エージェントが `lib/clanet_cli.py` を共有 — 接続・パースロジックの重複はゼロです。

### clanet の実装と Claude の役割

| レイヤー | 実装 | 例 |
|---------|------|-----|
| **SSH・デバイス自動化** | Python (Netmiko) `lib/clanet_cli.py` | 接続、コマンド実行、バックアップ、スナップショット、ログ |
| **ポリシーエンジン** | Python 正規表現 `_evaluate_rule()` | `pattern_deny`, `require`, `recommend` — 決定論的ルール評価 |
| **安全ワークフロー** | プロンプト定義 `commands/` | 「表示→説明→確認→検証」— 構造化されたプロンプトシーケンス |
| **リスク評価・診断** | Claude の LLM 推論（プロンプトで誘導） | `/clanet:why` のトラブルシューティング、変更リスク判定 |
| **エージェント連携** | Claude Code エージェントフレームワーク `agents/` | ツール制限付きの役割分離エージェント |

clanet は Claude Code プラグインです。プロンプト設計とツール連携により、Claude の推論能力をネットワーク運用に活用します。「知性」は Claude 自身が提供し、clanet はドメイン知識・安全ガードレール・デバイス自動化レイヤーを提供します。

## セキュリティに関する注意事項

- **認証情報**: `inventory.yaml` にはデバイスの認証情報が含まれるため、デフォルトで gitignore 対象です。絶対にコミットしないでください。
- **環境変数**: `inventory.yaml` 内で `${VAR_NAME}` 構文を使用してパスワードやユーザー名を指定できます（例: `password: ${NET_PASSWORD}`）。平文での保存を回避できます。
- **SSH のみ**: すべてのデバイス通信は Netmiko 経由の SSH です。Telnet や HTTP は使用しません。
- **外部通信なし**: clanet は外部サービスへのデータ送信を一切行いません。すべての操作はローカルの SSH セッションです。
- **Human-in-the-loop**: コンフィグ変更には必ず人間の明示的な承認が必要です。Claude はリスクを評価しますが、HIGH/CRITICAL の変更を自動適用することはありません。
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
- Netmiko (`pip install netmiko`)
- PyYAML (`pip install pyyaml`)
- ネットワークデバイスへの SSH アクセス

## 作者

Created by [takumina](https://github.com/takumina)

## ライセンス

MIT License
