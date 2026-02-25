---
description: Run health check on one or all devices
argument-hint: [device-name | --all]
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:health - Health Check

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
