---
description: Commit configuration changes (IOS-XR, Junos, etc.)
argument-hint: [device-name | --all]
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:commit - Commit Configuration

Commit pending configuration changes. For commit-based platforms (IOS-XR, Junos).
Non-commit platforms are auto-skipped with guidance to use `/clanet:save`.

## Instructions

1. Parse the argument: device name or `--all`.
2. **Ask for confirmation before committing** using AskUserQuestion.
3. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py commit "${ARGUMENT:---all}"
```

4. Report results for each device.
