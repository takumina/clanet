---
description: Send configuration commands to a network device (with safety checks)
argument-hint: <device-name>
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:config - Send Configuration Commands

Send configuration commands to a device.
**Follows the clanet Safety Guide: Show → Explain → Confirm → Verify.**

## Instructions

1. Parse the argument to get the device name.
2. Get device info:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py device-info "$DEVICE_NAME"
```

3. Ask the user for the configuration commands if not provided.

4. **SHOW** - Present the change request:

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

5. **EXPLAIN** - Analyze and explain:
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

6. **CONFIRM** - Ask user with AskUserQuestion:
   - For LOW/MEDIUM: [Apply + Verify] / [Apply] / [Cancel]
   - For HIGH/CRITICAL: Show explicit warning, require device name confirmation

7. **EXECUTE** - Apply the configuration:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py config "$DEVICE_NAME" --commands "$CONFIG_JSON"
```

8. **VERIFY** - After execution:
   - Run relevant show command to confirm the change took effect:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py check "$DEVICE_NAME"
```

   - Report: `[OK] <what was verified>` or `[WARN] <unexpected result>`
