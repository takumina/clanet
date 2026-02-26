---
description: Network troubleshooting - Claude diagnoses issues or explains configurations from device output
argument-hint: <device-name> <question-or-problem>
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:why - Network Troubleshooting & Explanation (Claude-Driven)

Diagnose network issues or explain existing configurations using device output.
You autonomously select the right commands based on your network knowledge.

## Instructions

### Step 1: Load context

If `context.yaml` exists, read it (use `Read` tool or `python3 lib/clanet_cli.py context`):
- `topology` — Understand the network layout to guide diagnosis
- `symptoms` — Combine with user input to prioritize investigation

### Step 2: Parse argument and determine mode

Parse the argument: device name and question/problem description.

- **Mode A: Troubleshooting** — keywords like "down", "fail", "error", "cannot", "not working", "flapping", "high CPU"
- **Mode B: Config explanation** — keywords like "why is ... configured", "what does ... do", "explain"

### Step 3: Get device info

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py device-info "$DEVICE_NAME"
```

This returns JSON with `device_type`. Use this to select vendor-correct command syntax.

### Step 4: Select commands using YOUR network knowledge

Based on the `device_type`, the user's problem/question, and context, decide which commands to run.

**Mode A (Troubleshooting):** Think about what a senior network engineer would check.
Consider: protocol state, interface counters, routing table, logs, specific neighbor details.

**Mode B (Config explanation):** Think about what config sections are relevant.
Consider: running-config sections, interface config, route-policy, ACL, protocol config.

Build a JSON array and execute in a single batch (1 SSH connection):

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py show "$DEVICE_NAME" --commands '["cmd1", "cmd2", "cmd3"]'
```

### Step 5: Analyze and investigate further (up to 4 additional rounds)

Review the output. If you need more detail, run additional commands.
Examples:
- BGP neighbor down → check specific neighbor detail, route advertisements
- OSPF stuck in INIT → check interface MTU, area config, authentication
- Interface CRC errors → check controller details, cable/optic status
- Routing loop suspected → trace the path, check route-policy on multiple hops

Each additional round uses `--commands` for batch execution. **Minimize the number of rounds** — gather related commands into a single batch.

**Maximum 5 total rounds** (1 initial + up to 4 follow-up).

### Step 6: Present results

**Mode A — Diagnosis:**

```
## Diagnosis: <device-name>

**Problem:** <user's description>
**Root Cause:** <identified root cause>

**Evidence:**
- <finding 1 with specific data>
- <finding 2>

**Recommended Fix:**
1. <step 1>
2. <step 2>

**Suggested commands:**
/clanet:config <device> (with specific commands)
```

**Mode B — Config explanation:**

```
## Config Analysis: <device-name>

**Question:** <user's question>
**Relevant Config:** (extracted config section)

**Explanation:**
- <what this config does, in plain language>
- <why this is typically configured this way>
- <any best practice notes>

**Related concepts:**
- <brief explanation of underlying protocol/feature>
```

### Step 7: Cross-device investigation

If the problem spans multiple devices, suggest checking the peer device too.
