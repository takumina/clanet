---
description: Session management - check connectivity and session status
argument-hint: [device-name | --all] [status|prompt|alive]
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:session - Session Management

Check SSH connectivity and session status for network devices.

## Instructions

1. Parse the argument: device name (or `--all`) and optional action.
   - `/clanet:session router01` → default status check
   - `/clanet:session router01 prompt` → get current prompt
   - `/clanet:session --all` → check all devices

2. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py session $ARGUMENT
```

3. Present results as a clear status table.
