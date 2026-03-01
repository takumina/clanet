---
description: Connect to a device and show basic info (show version)
argument-hint: <device-name>
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:check - Device Check

Connect to a network device and show basic information.

## Instructions

1. Parse the argument to get the device name.

2. Connect and run `show version`:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py info "$ARGUMENT"
```

3. Present the output clearly.
4. Summarize: hostname, OS version, uptime, model.

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
