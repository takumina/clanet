---
description: Multi-agent team for safe config changes - dynamic operator scaling for parallel execution across multiple devices
argument-hint: "<device> <task-description>"
allowed-tools: [Read, Bash, Glob, Grep, SendMessage, Task, TeamCreate, TeamDelete, AskUserQuestion]
---

# /clanet:team - Multi-Agent Config Change

Specialized agents coordinate to execute config changes safely. Operators are dynamically scaled based on device count for parallel execution.

```
Phase 1 (always):
         ┌──────────────┐
         │   Planner     │  Investigate → Plan → Procedure → Approve
         └──────┬───────┘
                ↓ Send approved plan to team lead

Phase 2 (dynamic):
   ┌────────────┐  ┌────────────┐
   │ operator-1  │  │ operator-2  │ ... (1-4 operators)
   │ Group 1     │  │ Group 2     │     scaled by device count
   └──────┬─────┘  └──────┬─────┘
          ↓                ↓   Send proposed config
         ┌──────────────────────┐
         │  Compliance Checker   │  Policy + Constitution check
         │                      │  → PASS / WARN / BLOCK
         └──────────────────────┘
          ↓                ↓   After execution
         ┌──────────────────────┐
         │     Validator         │  Post-change health check
         └──────────────────────┘
```

## Dynamic Operator Scaling

| Device Count | Operators | Rationale |
|-------------|-----------|-----------|
| 1 | 1 (operator-1) | No parallelism needed |
| 2-4 | 2 (operator-1, operator-2) | Moderate parallelism |
| 5+ | min(4, group_count) | Resource cap at 4 operators |

## Two-Layer Compliance Checking

`/clanet:team` provides the deepest compliance checking:

| Layer | Evaluator | Rule Source | Rule Type | When |
|-------|-----------|------------|-----------|------|
| **Layer 1: Regex** | CLI engine | Constitution + Policy | `pattern_deny` | Always (automatic) |
| **Layer 2: Semantic** | compliance-checker (LLM) | Constitution | Natural language `rule` | `/clanet:config` Step 6 or `/clanet:team` |
| **Layer 2: Semantic** | compliance-checker (LLM) | Policy | Natural language `rule` | `/clanet:config` Step 6 or `/clanet:team` |

### When to use `/clanet:team` instead of `/clanet:config`

- Constitution or policy has **`rule`-only entries** (natural language rules without regex)
- The change requires **intent-level validation** (e.g., "does this create a single point of failure?")
- You want **autonomous config generation** — the operator generates vendor-correct commands
- You want **dedicated post-change validation** — the validator agent checks health independently
- You want **a procedure document** — the planner creates a Markdown procedure before execution
- You want **parallel execution** — multiple operators handle different device groups simultaneously

## Instructions

Parse the argument:
- First word = device name (or "all" for multi-device tasks)
- Remaining words = task description (e.g., "Add NTP server 10.0.0.1")

### Step 1: Create Team

Use TeamCreate:
- team_name: `clanet-change`
- description: `clanet: <task-description> on <device>`

### Step 2: Spawn Phase-1 Agents (planner, compliance-checker, validator)

Use the Agent tool to spawn **three** agents simultaneously (parallel). Operators are NOT spawned yet — they will be spawned dynamically in Step 4 after the planner delivers Device Groups.

**Agent 1: planner**
```
subagent_type: planner
team_name: clanet-change
name: planner
prompt: |
  You are the planner for team clanet-change.
  Your task: <task-description>
  Target device: <device>

  Follow your autonomous workflow:
  1. Load context.yaml (if exists) for topology and constraints
  2. Investigate current device state via show commands
  3. Design the change plan (scope, approach, Device Groups, execution order, risk, rollback)
  4. Create a procedure document in procedures/ directory
  5. Try to get plan approval from the user via AskUserQuestion
  6. Send plan to team lead via SendMessage:
     - If AskUserQuestion succeeded: prefix with "APPROVED CHANGE PLAN"
     - If AskUserQuestion was unavailable: prefix with "CHANGE PLAN (PENDING APPROVAL)"
  7. Do NOT wait for a response from team lead. Your work is done after sending.
```

**Agent 2: compliance-checker**
```
subagent_type: compliance-checker
team_name: clanet-change
name: compliance-checker
prompt: |
  You are the compliance checker for team clanet-change.
  Wait for a COMPLIANCE CHECK REQUEST from any operator (operator-1, operator-2, etc.).
  When received:
  1. Run `python3 lib/clanet_cli.py constitution-rules` to load constitutional rules
  2. Run `python3 lib/clanet_cli.py policy-rules` to load policy rules as JSON
  3. Check each proposed command against all regex-based rules (pattern_deny, require, etc.)
  4. For constitutional rules with 'rule' field: evaluate using LLM reasoning
     - Read the natural language rule text
     - Analyze proposed commands semantically (intent, scope, redundancy)
     - Mark each as PASS/BLOCK/WARN with reasoning
  4.5. For policy rules with 'rule' field: evaluate using LLM reasoning
     - Run `python3 lib/clanet_cli.py policy-rules --llm-only` to get LLM-evaluable policy rules
     - Analyze proposed commands against each natural language rule
     - Mark each as PASS/BLOCK/WARN with reasoning
  5. Include Source column (CLI regex / LLM rule / Policy / Policy LLM) in the result table
  6. Send COMPLIANCE CHECK RESULT with verdict (PASS/WARN/BLOCK) back to the requesting operator via SendMessage
```

**Agent 3: validator**
```
subagent_type: validator
team_name: clanet-change
name: validator
prompt: |
  You are the validator for team clanet-change.
  Wait for CONFIG APPLIED notification from any operator (operator-1, operator-2, etc.).
  When received:
  1. Connect to the device and run validation commands (show commands only)
  2. Check pre-change snapshot in snapshots/ directory if available
  3. Compare pre vs post state
  4. Send VALIDATION RESULT (PASS/FAIL) to team lead via SendMessage
```

### Step 3: Receive Plan from Planner and Ensure Approval

Wait for the planner to send the change plan via SendMessage. The plan contains:
- Task description, risk level, procedure document path
- **Device Groups** (for multi-device plans) or a single device entry
- Rollback procedure

**Check the plan prefix to determine approval status:**

1. **`APPROVED CHANGE PLAN`** — planner already obtained user approval via AskUserQuestion. Proceed directly to Step 4.

2. **`CHANGE PLAN (PENDING APPROVAL)`** — planner could not use AskUserQuestion. You (team lead) must present the plan to the user via AskUserQuestion:
   - Show scope, approach, risk level, rollback, procedure document
   - Options: [Approve Plan] / [Cancel]
   - If **Cancel** → report cancellation to user, skip to Step 7 (Cleanup)
   - If **Approve** → proceed to Step 4

**Do NOT send anything back to the planner.** The planner's work is done after Step 7. This eliminates round-trip delays.

Parse the plan to determine the device count and groups.

### Step 4: Spawn Phase-2 Operators (Dynamic)

Based on the received plan, determine how many operators to spawn:

```
Count all devices across all Device Groups.

if device_count == 1:
    operator_count = 1
elif device_count <= 4:
    operator_count = 2
else:
    operator_count = min(4, group_count)

Assign Device Groups to operators round-robin:
- operator-1 gets Group 1, Group 3, ...
- operator-2 gets Group 2, Group 4, ...
```

**Fallback**: If the planner did not include Device Groups (single device or omitted), spawn 1 operator and send the entire plan.

Spawn `operator_count` operators in **parallel** using the Agent tool:

**For each operator-N:**
```
subagent_type: network-operator
team_name: clanet-change
name: operator-<N>
prompt: |
  You are network operator-<N> for team clanet-change.

  APPROVED CHANGE PLAN (Your Assignment)
  Task: <task description>
  Risk Level: <risk level>
  Procedure Document: <path>

  Your Devices:
  1. Device: <device-A>
     Device Type: <device_type-A>
     Changes: <what to configure on A>
  2. Device: <device-B>
     Device Type: <device_type-B>
     Changes: <what to configure on B>

  Rollback:
  - <rollback for device-A>
  - <rollback for device-B>

  Follow your autonomous workflow for EACH device in order:
  1. Generate vendor-correct config commands
  2. Send COMPLIANCE CHECK REQUEST to compliance-checker
  3. Wait for verdict
  4. If PASS/WARN: present config to user via AskUserQuestion
  5. If BLOCK: report to team lead, do NOT execute
  6. Take pre-change snapshot, execute config
  7. Send CONFIG APPLIED to validator
  8. After all devices done: send OPERATOR COMPLETE to team lead

  Please generate vendor-correct config commands and proceed.
```

After spawning, send a brief status to the user:
```
Spawned <operator_count> operator(s) for <device_count> device(s).
```

### Step 5: Monitor Progress

Messages arrive automatically from agents. Watch for:
1. **planner** → Plan designed, procedure created, plan approved (or cancelled)
2. **operator-1..N** → Compliance check requests, execution status, OPERATOR COMPLETE
3. **compliance-checker** → COMPLIANCE CHECK RESULT (PASS/WARN/BLOCK) per device
4. **validator** → VALIDATION RESULT (PASS/FAIL) per device

**Error handling:**
- If an operator reports BLOCK → note it in the final report, other operators continue
- If an operator is cancelled by user → note it, other operators continue
- If validator reports FAIL for a device → note it as PARTIAL, recommend rollback

### Step 6: Report to User

When **all operators** have reported OPERATOR COMPLETE (or stopped due to BLOCK/Cancel), present the summary:

```
## clanet Team Change Report

**Task:** <description>
**Procedure:** procedures/<filename>.md
**Operators:** <count> operator(s) for <device_count> device(s)

| Device | Operator | Compliance | Execution | Validation |
|--------|----------|------------|-----------|------------|
| TokyoP01 | operator-1 | PASS | SUCCESS | PASS |
| TokyoP02 | operator-1 | PASS | SUCCESS | PASS |
| OsakaP01 | operator-2 | PASS | SUCCESS | PASS |
| OsakaP02 | operator-2 | WARN | SUCCESS | PASS |

**Overall: SUCCESS**
```

Overall status logic:
- All SUCCESS + PASS → **SUCCESS**
- Any FAIL validation → **PARTIAL** (recommend rollback for failed devices)
- Any BLOCK → **BLOCKED** (list blocked devices)
- All cancelled → **CANCELLED**

### Step 7: Cleanup

Send shutdown_request to **all** agents (planner, compliance-checker, validator, operator-1..N), then use TeamDelete.

## Example Usage

```
/clanet:team router01 Add NTP server 10.0.0.1
/clanet:team router01 Set interface Gi0/0/0/1 description "Uplink to Core"
/clanet:team all Change OSPF cost to 100 on all WAN interfaces
```
