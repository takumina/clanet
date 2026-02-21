---
name: team
description: 3-agent team (compliance-checker, network-operator, validator) for safe config changes
---

# /clanet:team - Multi-Agent Config Change

3 specialized agents coordinate to execute config changes safely.

## Architecture

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
- Remaining = task description (e.g., "Add NTP server 10.0.0.1")

Then execute the following orchestration:

### Step 1: Create Team

Use TeamCreate to create a team:
- team_name: `clanet-change`
- description: `clanet config change: <task-description> on <device>`

### Step 2: Spawn 3 Agents in Parallel

Use the Task tool to spawn all three agents simultaneously:

**Agent 1: compliance-checker**
```
subagent_type: compliance-checker
team_name: clanet-change
name: compliance-checker
prompt: |
  You are the compliance checker for team clanet-change.
  First, use the Read tool to read context.yaml for task-specific constraints (skip if not found).
  Wait for a compliance check request from network-operator.
  When you receive it, load policies/default.yaml and validate the proposed commands.
  If context.yaml has constraints, also check against those.
  Send your verdict (PASS/WARN/BLOCK) back to network-operator via SendMessage.
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
  0. First, read context.yaml to understand topology and constraints
  1. Read inventory to get device info
  2. Generate vendor-correct config commands (respecting any constraints from context.yaml)
  3. Send to compliance-checker for validation via SendMessage
  4. Wait for verdict
  5. If PASS/WARN: take pre-change snapshot, execute config, log it
  6. If BLOCK: report to team lead, do NOT execute
  7. After execution: notify validator via SendMessage
```

**Agent 3: validator**
```
subagent_type: validator
team_name: clanet-change
name: validator
prompt: |
  You are the validator for team clanet-change.
  First, read context.yaml to check for task-specific success criteria.
  Wait for notification from network-operator that a change was applied.
  When notified, run post-change health checks on the device.
  Compare with pre-change snapshot if available.
  If context.yaml has success_criteria, use those for PASS/FAIL judgment.
  Report PASS or FAIL to the team lead via SendMessage.
```

### Step 3: Monitor Progress

Watch for messages from the agents:
- **compliance-checker** → PASS/WARN/BLOCK verdict
- **network-operator** → Config applied successfully / BLOCKED
- **validator** → PASS / FAIL with details

### Step 4: Report to User

When all agents complete, present a summary:

```
## clanet Team Change Report

**Device:** <name>
**Task:** <description>

| Phase | Agent | Result |
|-------|-------|--------|
| Compliance | compliance-checker | PASS (0 violations) |
| Execution | network-operator | SUCCESS (3 commands applied) |
| Validation | validator | PASS (all checks OK) |

**Overall: SUCCESS**
```

### Step 5: Cleanup

Send shutdown_request to all agents and delete the team.
