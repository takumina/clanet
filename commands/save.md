---
description: Save running configuration to startup (write memory)
argument-hint: [device-name | --all]
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:save - Save Configuration

Save the running configuration to startup. Commit-based platforms (IOS-XR, Junos) are auto-skipped.

## Instructions

1. Parse the argument: device name or `--all`.
2. **Ask for confirmation before saving** using AskUserQuestion.
3. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py save "${ARGUMENT:---all}"
```

4. Report results for each device.
