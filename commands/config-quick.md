---
description: Quick config change without pre/post snapshots (lightweight)
argument-hint: <device-name>
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:config-quick - Quick Configuration (No Snapshots)

Send configuration commands to a device without pre/post snapshots.
For full validation with snapshots and rollback, use `/clanet:config` instead.
**Follows the clanet Safety Guide: Show → Explain → Confirm → Verify.**

## Instructions

1. Parse the argument to get the device name.
2. Get device info:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py device-info "$DEVICE_NAME"
```

3. Ask the user for the configuration commands if not provided.

4. **SYNTAX DISCOVERY** - Verify config command syntax with the device before applying.

   **When to use:**
   - User gives a natural language request (e.g., "日本時間に設定して") → **必須**
   - You are constructing commands from your own knowledge → **必須**
   - User provides exact CLI commands verbatim → **スキップ可**（ユーザーが構文を把握している。隠しコマンド等の可能性もある）

   Use `syntax-help` to progressively query the device's context-sensitive help (`?`):

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py syntax-help "$DEVICE_NAME" "partial command"
```

   Query `?` step by step until the command is confirmed complete. Example:
   - `syntax-help router01 "clock"` → discover `timezone` subcommand
   - `syntax-help router01 "clock timezone"` → discover timezone names (e.g., `JST`)
   - `syntax-help router01 "clock timezone JST"` → discover required args (e.g., `Asia/Tokyo`)
   - Final command: `clock timezone JST Asia/Tokyo`

   **Rules:**
   - Do NOT rely on your own knowledge of CLI syntax — **verify with the device**
   - Start from the top-level command keyword and drill down
   - Stop when `?` shows `<cr>` (carriage return) — that means the command is complete
   - If `?` shows additional required arguments, keep querying until `<cr>` appears

5. **SHOW** - Present the change request:

   ```
   +----------------------------------------------------------+
   |  clanet: Configuration Change Request                     |
   +----------------------------------------------------------+
   |  Device:    <name> (<host>)                              |
   |  Type:      <device_type>                                |
   |  Commands:  <count> lines                                |
   +----------------------------------------------------------+
   |    1. <command 1>                                        |
   |    2. <command 2>                                        |
   +----------------------------------------------------------+
   ```

6. **EXPLAIN** - Analyze and explain:
   - What each command does in plain language
   - Risk level: LOW / MEDIUM / HIGH / CRITICAL
   - What services or traffic may be affected
   - **Self-lockout check**: If commands touch management interface, VTY ACL, or management routing → **BLOCK**

   Risk criteria:
   | Level | Examples |
   |-------|---------|
   | LOW | `description`, `ntp server`, `banner` |
   | MEDIUM | `ospf cost`, `bgp timers`, `mtu` |
   | HIGH | `router ospf`, `neighbor`, `shutdown` |
   | CRITICAL | management IP, VTY ACL, `no router`, `reload` |

7. **CONFIRM** - Ask user with AskUserQuestion:
   - For LOW/MEDIUM: [Apply + Verify] / [Apply] / [Cancel]
   - For HIGH/CRITICAL: Show explicit warning, require device name confirmation

8. **EXECUTE** - Apply the configuration:

   > **Note:** 憲法ルール (`constitution.yaml`) は CLI が自動的に強制します。
   > 違反するコマンドは `--skip-compliance` を付けてもブロックされます。

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py config "$DEVICE_NAME" --commands "$CONFIG_JSON"
```

9. **VERIFY** - After execution:
   - Run relevant show command to confirm the change took effect:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py check "$DEVICE_NAME"
```

   - Report: `[OK] <what was verified>` or `[WARN] <unexpected result>`
