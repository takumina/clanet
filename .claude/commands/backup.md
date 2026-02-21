---
description: Backup running config from one or all devices
argument-hint: [device-name | --all]
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:backup - Backup Configuration

Backup the running configuration from network devices to `backups/` directory.

## Instructions

1. Parse the argument: device name or `--all` (default: `--all`).

2. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py backup "${ARGUMENT:---all}"
```

3. Report results:
   - List successful backups with file paths
   - List any failures with error messages
   - Show total backed up vs total devices
