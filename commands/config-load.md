---
description: Load configuration from a file to a network device (with safety checks)
argument-hint: <device-name> <config-file>
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:config-load - Load Configuration from File

Load configuration from a file to a device.
**Follows the clanet Safety Guide: Show → Explain → Confirm → Verify.**

## Instructions

1. Parse the argument: device name and config file path.
   - Example: `/clanet:config-load router01 configs/bgp_update.cfg`

2. Get device info:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py device-info "$DEVICE_NAME"
```

3. **SHOW** - Read the config file and present:

   ```
   +----------------------------------------------------------+
   |  clanet: Config Load Request                              |
   +----------------------------------------------------------+
   |  Device:    <name> (<host>)                              |
   |  Type:      <device_type>                                |
   |  File:      <filename>                                   |
   |  Lines:     <count>                                      |
   +----------------------------------------------------------+
   |  File contents:                                          |
   |    1. <line 1>                                           |
   |    2. <line 2>                                           |
   +----------------------------------------------------------+
   ```

4. **EXPLAIN** - Analyze the file contents:
   - What the configuration does in plain language
   - Risk level: LOW / MEDIUM / HIGH / CRITICAL
   - What services or traffic may be affected
   - **Self-lockout check**: If file contains management interface changes → **BLOCK**

5. **CONFIRM** - Ask user with AskUserQuestion:
   - For LOW/MEDIUM: [Apply + Verify] / [Apply] / [Cancel]
   - For HIGH/CRITICAL: Show explicit warning, require device name confirmation

6. **EXECUTE** - Load the config file:

   > **Note:** 憲法ルール (`constitution.yaml`) は CLI が自動的に強制します。
   > 違反するコマンドは `--skip-compliance` を付けてもブロックされます。

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py config-load "$DEVICE_NAME" "$CONFIG_FILE"
```

7. **VERIFY** - After loading:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py check "$DEVICE_NAME"
```

   - Report: `[OK]` or `[WARN]`
   - Recommend `/clanet:save` (IOS) or note that commit was automatic (IOS-XR/Junos)
