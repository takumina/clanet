---
description: Run health check using predefined template commands
argument-hint: [device-name | --all]
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:health-template - Health Check (Template-Driven)

Run health checks using predefined commands from the health template (`templates/health.yaml`).
Commands are selected per vendor; results are analyzed by Claude.

## Instructions

### Step 1: Identify targets

- If argument is a device name: that device only
- If `--all` or no argument: get all devices via:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py list
```

### Step 2: For each device, get health commands from template

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py health-commands "$DEVICE"
```

This returns JSON with `commands` list for the device's vendor type.

### Step 3: Execute commands in batch

Use the `commands` array from Step 2 as-is:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py show "$DEVICE" --commands '$COMMANDS_JSON'
```

### Step 4: Analyze results

Review all command output and assess:
- Interface status (up/down count)
- BGP neighbor status (Established / down)
- OSPF neighbor status (Full / other)
- Route table health
- Log anomalies (errors, warnings, flaps)

### Step 5: Deep investigation if needed (up to 4 additional rounds)

If you detect anomalies or need more detail, run additional commands. Examples:
- BGP neighbor down → `show bgp neighbor X.X.X.X detail`
- Interface errors → `show interface GiX/X/X/X` for detailed counters
- OSPF not FULL → `show ospf neighbor X.X.X.X detail`
- Routing issue → `show route X.X.X.X/X` for specific prefix

Each additional round uses `--commands` for batch execution. **Minimize the number of rounds** — gather related commands into a single batch.

**Maximum 5 total rounds** (1 initial + up to 4 follow-up).

### Step 6: Present summary

For each device, present:

1. **Interface status**: up/down counts
2. **BGP status**: neighbor states (or "not configured")
3. **OSPF status**: adjacency states (or "not configured")
4. **Route summary**: total routes by protocol
5. **Anomalies**: any issues found with details
6. **Overall health**: HEALTHY / WARNING / CRITICAL

### Step 7: Check context (optional)

If `context.yaml` exists, read it (use `Read` tool or `python3 lib/clanet_cli.py context`).
If `success_criteria` is defined, evaluate each criterion and include in the summary.
