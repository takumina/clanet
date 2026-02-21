# clanet 改善計画

評価結果 (B+) で挙がった課題を優先度順に整理。
各項目の影響範囲と実装方針を記載する。

---

## Phase 1: 例外設計の改善 (コード品質 B → A-)

**課題**: `get_device()`, `load_inventory()`, `connect()`, `_load_health_config()` が
`sys.exit(1)` を直接呼ぶためライブラリとして再利用不可。テストも `pytest.raises(SystemExit)` を強いられている。

**方針**:
1. `lib/clanet_cli.py` 先頭にカスタム例外クラスを追加
   ```python
   class ClanetError(Exception):
       """Base exception for clanet."""

   class DeviceNotFoundError(ClanetError):
       """Device not found in inventory."""

   class InventoryNotFoundError(ClanetError):
       """Inventory file not found."""

   class ConnectionError(ClanetError):
       """Device connection failed."""

   class ConfigError(ClanetError):
       """Configuration loading failed."""
   ```

2. 各関数を `sys.exit(1)` → `raise XxxError(message)` に変更
   - `load_inventory()` → `raise InventoryNotFoundError`
   - `get_device()` → `raise DeviceNotFoundError`
   - `connect()` → `raise ConnectionError`
   - `_load_health_config()` → `raise ConfigError`

3. `main()` で例外をキャッチして `sys.exit(1)` に変換
   ```python
   def main():
       try:
           args.func(args)
       except ClanetError as e:
           print(f"ERROR: {e}", file=sys.stderr)
           sys.exit(1)
   ```

4. テストを `pytest.raises(SystemExit)` → `pytest.raises(DeviceNotFoundError)` 等に修正

**変更ファイル**: `lib/clanet_cli.py`, `tests/test_cli.py`, `CLAUDE.md`
**テスト影響**: 既存テスト 8件の assert 修正 + 新規テスト追加

---

## Phase 2: CI パイプライン追加 (出荷品質 B+ → A-)

**課題**: CI なし。テスト不通過のまま出荷されるリスクがある。

**方針**:
1. `.github/workflows/test.yml` を作成
   ```yaml
   name: Test
   on: [push, pull_request]
   jobs:
     test:
       runs-on: ubuntu-latest
       strategy:
         matrix:
           python-version: ["3.10", "3.11", "3.12"]
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with:
             python-version: ${{ matrix.python-version }}
         - run: pip install -r requirements-dev.txt
         - run: python -m pytest tests/ -v --tb=short
   ```

2. `requirements-dev.txt` に `pytest-cov` 追加
3. CI にカバレッジレポート出力を追加
   ```yaml
   - run: python -m pytest tests/ -v --cov=lib --cov-report=term-missing
   ```

**変更ファイル**: `.github/workflows/test.yml` (新規), `requirements-dev.txt`
**テスト影響**: なし (CI が既存テストを実行するだけ)

---

## Phase 3: 統合テスト拡充 (テスト B → A-)

**課題**: `cmd_deploy`, `cmd_session`, `cmd_mode`, `cmd_save`, `cmd_commit`,
`cmd_snapshot`, `cmd_audit` の統合テストが未実装。

**方針**: 既存の `TestSubcommandIntegration` パターンを踏襲し、Netmiko モックで追加

1. `test_cmd_deploy` — ファイルからのコンフィグ投入、XR commit 動作
2. `test_cmd_save` — IOS の write memory、XR での SKIP 動作
3. `test_cmd_commit` — XR の commit、IOS での SKIP 動作
4. `test_cmd_mode` — enable/config/exit-config/check
5. `test_cmd_snapshot` — pre/post スナップショット保存
6. `test_cmd_audit` — ポリシー評価のエンドツーエンド (モックした running-config に対して)
7. `test_cmd_session` — TCP ソケットモックでの接続チェック

**変更ファイル**: `tests/test_cli.py`
**テスト影響**: 約 10-12 テスト追加。目標: 87 → 100 テスト前後

---

## Phase 4: タイムアウト設定化 (コード品質)

**課題**: `read_timeout=30` / `read_timeout=60` がハードコード。

**方針**:
1. `DEFAULT_CONFIG` に追加
   ```python
   DEFAULT_CONFIG = {
       ...
       "read_timeout": 30,
       "read_timeout_long": 60,
   }
   ```

2. 各 `send_command()` 呼び出しで設定値を参照
   ```python
   config = get_config()
   timeout = config.get("read_timeout", 30)
   output = conn.send_command(command, read_timeout=timeout)
   ```

3. `.clanet.yaml` でオーバーライド可能に
   ```yaml
   read_timeout: 45
   read_timeout_long: 120
   ```

**変更ファイル**: `lib/clanet_cli.py`, `examples/clanet.yaml`, `CLAUDE.md`
**テスト影響**: 既存統合テストの `read_timeout=30` アサーションを設定値に更新

---

## Phase 5: リンター導入 (出荷品質)

**課題**: コード品質チェックツールなし。

**方針**:
1. `pyproject.toml` を作成 (ruff 設定)
   ```toml
   [tool.ruff]
   target-version = "py310"
   line-length = 100

   [tool.ruff.lint]
   select = ["E", "F", "W", "I"]
   ```

2. CI に ruff チェックを追加
   ```yaml
   - run: pip install ruff
   - run: ruff check lib/ tests/
   ```

3. 既存コードを ruff で修正 (import 順序等の軽微な修正のみ)

**変更ファイル**: `pyproject.toml` (新規), `.github/workflows/test.yml`
**テスト影響**: なし

---

## 実施順序と理由

| 順序 | Phase | 理由 |
|------|-------|------|
| 1 | 例外設計 | 他の改善の基盤。テスト追加時に正しい例外パターンが必要 |
| 2 | CI | Phase 3 以降のテスト追加をCI で自動検証するため先に整備 |
| 3 | 統合テスト | 例外設計の変更を検証しつつカバレッジ向上 |
| 4 | タイムアウト | コード変更は小規模。テストで検証可能な状態で実施 |
| 5 | リンター | 最後に全体のコード品質を統一 |

## 期待される最終状態

- **テスト**: 100 前後 (全通過)
- **カバレッジ**: 70%+ (CI で可視化)
- **例外設計**: カスタム例外。`sys.exit()` は `main()` のみ
- **CI**: PR ごとに Python 3.10/3.11/3.12 でテスト + ruff
- **評価**: B+ → A-
