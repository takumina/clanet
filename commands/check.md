---
description: Run health check on one or all devices
argument-hint: "[<device-name> | --all] [--summary] [--quiet]"
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:check - Health Check

Run health checks on network devices (interfaces, BGP, OSPF).

## Instructions

1. Parse the argument: device name or `--all` (default: `--all`).

2. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py check "${ARGUMENT:---all}"
```

3. Analyze the output and present a summary:
   - Interface status (up/down count)
   - BGP neighbor status (Established / down)
   - OSPF neighbor status (Full / not found)
   - Overall health: HEALTHY / WARNING / CRITICAL

4. If `context.yaml` exists, read it (use `Read` tool or `python3 lib/clanet_cli.py context`).
   If `success_criteria` is defined, also evaluate each criterion and include in the summary.

## Flags

- `--summary` : Compact one-line-per-device output (no per-device detail)
- `--quiet` / `-q` : Suppress plaintext password security warnings
- `--all` : Check all devices in inventory

## Examples

- `/clanet:check TokyoPE01` - Single device health check
- `/clanet:check --all --summary` - All devices, compact view
- `/clanet:check --all --summary --quiet` - All devices, compact, no warnings

## Available subcommands

### Command Execution
- `/clanet:cmd` - Execute any show/operational command
- `/clanet:config` - Send configuration commands (with safety checks)
- `/clanet:config-load` - Load configuration from a file (with safety checks)
- `/clanet:cmd-interact` - Execute interactive commands (yes/no prompts)

### Monitoring & Operations
- `/clanet:health` - Health check (Claude selects commands and analyzes)
- `/clanet:health-template` - Health check (template-driven commands, Claude analyzes)
- `/clanet:backup` - Backup running configuration

### Configuration Management
- `/clanet:save` - Save running config to startup
- `/clanet:commit` - Commit changes (IOS-XR, Junos)

### Analysis & Compliance
- `/clanet:why` - Troubleshooting (Claude diagnoses issues from device output)
- `/clanet:audit` - Compliance audit (security & best practices check)

### Multi-Agent Team
- `/clanet:team` - 3-agent team for safe config changes (compliance → execute → validate)
