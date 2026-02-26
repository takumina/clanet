---
description: Run health check on one or all devices
argument-hint: [device-name | --all]
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:health - Health Check (Claude-Driven)

Run health checks on network devices. You autonomously select the right commands based on your network knowledge.

## Instructions

### Step 1: Identify targets

- If argument is a device name: that device only
- If `--all` or no argument: get all devices via:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py list
```

### Step 2: For each device, get vendor info

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py device-info "$DEVICE"
```

This returns JSON with `device_type` (e.g., `cisco_xr`, `cisco_ios`, `juniper_junos`, `arista_eos`).

### Step 3: Select commands using YOUR network knowledge

Based on the `device_type`, decide which show commands to run. Use your knowledge of that vendor's CLI syntax. Typical areas to check:

- **Interfaces**: up/down status, errors, CRC
- **Routing protocols**: BGP neighbors, OSPF adjacencies
- **Routing table**: route summary, default route presence
- **Logs**: recent syslog messages for errors/warnings

Build a JSON array of commands and execute them in a single batch (1 SSH connection):

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py show "$DEVICE" --commands '["cmd1", "cmd2", "cmd3"]'
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
