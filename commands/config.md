---
description: Send configuration commands with pre/post validation and rollback
argument-hint: <device-name>
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:config - Configuration Change (with Validation)

Apply configuration changes with pre/post snapshots, diff analysis, and rollback support.
**Follows the clanet Safety Guide: Show → Explain → Confirm → Verify.**

## Instructions

### Step 1: Parse and get device info

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py device-info "$DEVICE_NAME"
```

### Step 2: Ask for configuration

Ask the user for the configuration commands if not provided.
Optionally ask for validation criteria.

### Step 3: SYNTAX DISCOVERY

Verify config command syntax with the device before applying.

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

### Step 4: Pre-change snapshot

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py snapshot "$DEVICE_NAME" --phase pre
```

### Step 5: SHOW — Present the change request

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

### Step 6: EXPLAIN — Analyze and explain

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

### Step 7: CONFIRM — Ask user

- For LOW/MEDIUM: [Apply + Verify] / [Apply] / [Cancel]
- For HIGH/CRITICAL: Show explicit warning, require device name confirmation

### Step 8: EXECUTE — Apply the configuration

> **Note:** 憲法ルール (`constitution.yaml`) は CLI が自動的に強制します。
> 違反するコマンドは `--skip-compliance` を付けてもブロックされます。

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py config "$DEVICE_NAME" --commands "$CONFIG_JSON"
```

### Step 9: Post-change snapshot

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py snapshot "$DEVICE_NAME" --phase post
```

### Step 10: VERIFY — Compare and analyze

First, check if `context.yaml` exists (use `Read` tool or `python3 lib/clanet_cli.py context`).
If not found, skip to the default checks below.

Then read both snapshot files from `snapshots/` and analyze:

**If `success_criteria` is defined in context.yaml:**
- Evaluate each criterion against the post-change state
- Report PASS/FAIL per criterion

**If `success_criteria` is NOT defined (fallback):**
- **Interface changes**: Any interface went down?
- **BGP changes**: Any neighbor lost?
- **OSPF changes**: Any adjacency lost?
- **Route changes**: Significant route count change?
- **Config diff**: What exactly changed in running-config?

### Step 11: Present validation report

```
## Validation Report: <device-name>

| Check | Pre | Post | Status |
|-------|-----|------|--------|
| Interfaces Up | 5 | 5 | OK |
| BGP Neighbors Established | 1 | 1 | OK |
| OSPF Neighbors Full | 2 | 2 | OK |
| Total Routes | 15 | 16 | OK (+1) |

**Config Changes:**
(diff of running-config)

**Overall: PASS / FAIL**
```

### Step 12: If FAIL — Offer rollback

- For commit-based platforms: use `rollback configuration`
- For IOS: apply reverse config commands
- Always confirm before rollback
