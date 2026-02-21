---
description: Mode switching - enter/exit enable mode, config mode, check current mode
argument-hint: <device-name> <enable|config|exit-config|check>
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:mode - Mode Switching

Switch between operational modes on a network device.

## Instructions

1. Parse the argument: device name and action.
   - `/clanet:mode router01 enable` → enter enable (privileged) mode
   - `/clanet:mode router01 config` → enter configuration mode
   - `/clanet:mode router01 exit-config` → exit configuration mode
   - `/clanet:mode router01 check` → check current mode

2. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py mode $ARGUMENT
```

3. Present the mode status clearly.
