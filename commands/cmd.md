---
description: Execute a show/operational command on a network device
argument-hint: <device-name> <command>
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:cmd - Execute command

Execute any show/operational command on a network device.

**Note**: Destructive and config-mode commands (configure, reload, write erase, delete, etc.) are blocked by the CLI safety filter. Use `/clanet:config` for configuration changes or `/clanet:cmd-interact` for interactive commands.

## Instructions

1. Parse the argument: first word = device name, rest = command.
   - Example: `/clanet:cmd router01 show ip route`
   - `DEVICE_NAME` = `router01`
   - `COMMAND` = `show ip route`

2. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py show "$DEVICE_NAME" "$COMMAND"
```

3. Present the output clearly. If it's a routing table, BGP table, etc., add brief analysis.
