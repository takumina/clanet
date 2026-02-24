---
description: Multi-agent team for safe config changes - 3 agents (compliance-checker, operator, validator) coordinate automatically
argument-hint: "<device> <task-description>"
allowed-tools: [Read, Bash, Glob, Grep, SendMessage, Task, TeamCreate, TeamDelete, AskUserQuestion]
---

# /clanet:team - Multi-Agent Config Change

3 specialized agents coordinate to execute config changes safely.

```
         ┌──────────────┐
         │   Operator    │  Generate config → Execute
         └──────┬───────┘
                ↓ Send proposed config
         ┌──────────────┐
         │  Compliance   │  Policy check
         │  Checker      │  → PASS / WARN / BLOCK
         └──────┬───────┘
                ↓ After execution
         ┌──────────────┐
         │  Validator    │  Post-change health check
         └──────────────┘
```

## Instructions

Parse the argument:
- First word = device name
- Remaining words = task description (e.g., "Add NTP server 10.0.0.1")

### Step 1: Create Team

Use TeamCreate:
- team_name: `clanet-change`
- description: `clanet: <task-description> on <device>`

### Step 2: Spawn 3 Agents in Parallel

Use the Task tool to spawn all three agents **simultaneously** (parallel):

**Agent 1: compliance-checker**
```
subagent_type: compliance-checker
team_name: clanet-change
name: compliance-checker
prompt: |
  You are the compliance checker for team clanet-change.
  Wait for a COMPLIANCE CHECK REQUEST from network-operator.
  When received:
  1. Read templates/policy.yaml
  2. Check each proposed command against all rules
  3. Send COMPLIANCE CHECK RESULT with verdict (PASS/WARN/BLOCK) back to network-operator via SendMessage
```

**Agent 2: network-operator**
```
subagent_type: network-operator
team_name: clanet-change
name: network-operator
prompt: |
  You are the network operator for team clanet-change.
  Your task: <task-description>
  Target device: <device>

  Follow your autonomous workflow:
  1. Read inventory to get device info (device_type, host)
  2. Generate vendor-correct config commands for the task
  3. Send COMPLIANCE CHECK REQUEST to compliance-checker via SendMessage
  4. Wait for verdict from compliance-checker
  5. If PASS/WARN: take pre-change snapshot, execute config, log to operations log
  6. If BLOCK: send message to team lead explaining the block, do NOT execute
  7. After successful execution: send CONFIG APPLIED to validator via SendMessage
  8. Wait for validation result
  9. Report final status to team lead
```

**Agent 3: validator**
```
subagent_type: validator
team_name: clanet-change
name: validator
prompt: |
  You are the validator for team clanet-change.
  Wait for CONFIG APPLIED notification from network-operator.
  When received:
  1. Connect to the device and run validation commands (show commands only)
  2. Check pre-change snapshot in snapshots/ directory if available
  3. Compare pre vs post state
  4. Send VALIDATION RESULT (PASS/FAIL) to team lead via SendMessage
```

### Step 3: Monitor Progress

Messages arrive automatically from agents. Watch for:
1. **compliance-checker** → COMPLIANCE CHECK RESULT (PASS/WARN/BLOCK)
2. **network-operator** → Config execution status
3. **validator** → VALIDATION RESULT (PASS/FAIL)

### Step 4: Report to User

When all agents complete, present a summary:

```
## clanet Team Change Report

**Device:** <name>
**Task:** <description>

| Phase | Agent | Result |
|-------|-------|--------|
| Compliance Check | compliance-checker | PASS (0 violations) |
| Config Execution | network-operator | SUCCESS (3 commands applied) |
| Post-Change Validation | validator | PASS (all checks OK) |

**Overall: SUCCESS**
```

If any phase failed:
```
**Overall: BLOCKED** (compliance violation)
```
or
```
**Overall: FAILED** (validation detected issues)
Recommend: `/clanet:validate <device>` for rollback
```

### Step 5: Cleanup

Send shutdown_request to all three agents, then use TeamDelete.

## Example Usage

```
/clanet:team router01 Add NTP server 10.0.0.1
/clanet:team router01 Set interface Gi0/0/0/1 description "Uplink to Core"
/clanet:team router01 Add static route 192.168.100.0/24 via 10.0.0.1
```
