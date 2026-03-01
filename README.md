# clanet - Network Automation for Claude Code

Network automation plugin for Claude Code. Powered by [Netmiko](https://github.com/ktbyers/netmiko).

**English** | [日本語](docs/README_ja.md)

## Features

- **15 slash commands** — from `show` commands to full config deployment
- **Risk assessment** — Claude analyzes every config change for impact before execution
- **Self-lockout prevention** — blocks changes that would cut your SSH access
- **Multi-agent teams** — 4 specialized agents (planner / compliance / operator / validator) with dynamic operator scaling
- **Constitutional rules** — unskippable safety rules that override everything
- **Compliance auditing** — customizable policy rules with regex + natural language (LLM-evaluated)
- **Pre/post validation** — automatic snapshots and diff for change verification
- **Multi-vendor** — Cisco IOS/XR/NX-OS, Juniper, Arista, and more via Netmiko

## Installation

**Step 1** — Clone the repository and install dependencies

```bash
git clone https://github.com/takumina/clanet.git
cd clanet
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Step 2** — Create your inventory

```bash
cp templates/inventory.yaml inventory.yaml
```

Edit `inventory.yaml` with your device info (host, username, password, device_type):

```bash
nano inventory.yaml
```

> **Security tip**: Use `${ENV_VAR}` syntax for passwords instead of plain text. See [Security Considerations](#security-considerations).

**Step 3** — Start Claude Code and install the plugin

```bash
claude    # Start Claude Code from the clanet directory
```

In Claude Code, run:

```
/plugin install clanet@clanet-marketplace
```

## Quick Start

```bash
/clanet:check router01
/clanet:cmd router01 show ip route
/clanet:health --all
```

## Commands

### Basic

| Command | Description |
|---------|-------------|
| `/clanet:check <device>` | Connect and show basic device info (show version) |

### Command Execution

| Command | Description |
|---------|-------------|
| `/clanet:cmd <device> <command>` | Execute any show/operational command |
| `/clanet:config <device>` | Configuration change with pre/post validation and rollback |
| `/clanet:config-quick <device>` | Quick config change without snapshots (lightweight) |
| `/clanet:config-load <device> <file>` | Load configuration from a file |
| `/clanet:cmd-interact <device>` | Execute interactive commands (yes/no prompts) |

### Monitoring & Operations

| Command | Description |
|---------|-------------|
| `/clanet:health [device\|--all]` | Health check — Claude selects commands and analyzes results |
| `/clanet:health-template [device\|--all]` | Health check — template-driven commands, Claude analyzes results |
| `/clanet:backup [device\|--all]` | Backup running configuration |

### Configuration Management

| Command | Description |
|---------|-------------|
| `/clanet:save [device\|--all]` | Save running config to startup |
| `/clanet:commit [device\|--all]` | Commit changes (IOS-XR, Junos) |

### Analysis & Compliance

| Command | Description |
|---------|-------------|
| `/clanet:why <device> <problem>` | Troubleshooting — Claude diagnoses issues from device output |
| `/clanet:audit [device\|--all]` | Compliance audit (security & best practices) |

### Multi-Agent Team

| Command | Description |
|---------|-------------|
| `/clanet:team <device\|all> <task>` | Multi-agent team for safe config changes (plan → compliance → execute → validate) |

## How to Use

### 1. Check device health

```bash
# Claude selects commands and analyzes (recommended)
/clanet:health router01
/clanet:health --all

# Template-driven (uses templates/health.yaml)
/clanet:health-template router01
/clanet:health-template --all
```

### 2. Run show commands

```bash
/clanet:cmd router01 show ip route
/clanet:cmd router01 show bgp summary
```

### 3. Troubleshoot an issue

```bash
/clanet:why router01 BGP neighbor 10.0.0.2 is down
```

Claude reads device state, diagnoses the root cause, and suggests a fix.

### 4. Apply a config change (with validation)

```bash
/clanet:config router01
# 1. Syntax discovery (verifies commands with device)
# 2. Takes pre-change snapshot
# 3. Applies config (after confirmation)
# 4. Takes post-change snapshot
# 5. Compares and reports PASS/FAIL
# 6. Offers rollback if FAIL
```

For quick changes without snapshots:

```bash
/clanet:config-quick router01
```

### 5. Multi-agent team change (safest)

```bash
/clanet:team router01 Set description "Uplink to core-sw01" on GigabitEthernet0/0/0/0
# planner            → investigates state, designs plan, creates procedure
# compliance-checker → validates against policy (regex + LLM)
# operator(s)        → generates and applies config (scaled dynamically)
# validator          → verifies health after change
```

For multi-device changes, operators are scaled automatically:

```bash
/clanet:team all Change OSPF cost to 100 on all WAN interfaces
# Spawns 1-4 operators based on device count for parallel execution
```

### 6. Use operation context for complex tasks

For multi-step operations, define context upfront:

```bash
cp templates/context.yaml context.yaml
# Edit context.yaml with your topology, constraints, and success criteria
```

```yaml
# context.yaml
topology: |
  router01 (IOS-XR) --- eBGP --- router02 (IOS)
constraints:
  - Do not modify OSPF configuration
success_criteria:
  - BGP neighbor 10.0.0.2 must be Established
```

Then run any command as usual — clanet automatically reads the context:

```bash
/clanet:config router01      # Uses success_criteria for PASS/FAIL
/clanet:why router01 BGP down # Uses topology + symptoms for diagnosis
/clanet:team router01 Fix BGP # All agents respect constraints
```

### 7. Compliance audit

```bash
# Basic audit
/clanet:audit router01

# Security-focused audit on all devices
/clanet:audit --all --profile security
```

## Safety First

Every configuration change follows the **"Show, Explain, Confirm, Verify"** workflow:

```
1. SHOW      What commands will be applied
2. EXPLAIN   Claude analyzes impact and risk (LOW/MEDIUM/HIGH/CRITICAL)
3. CONFIRM   Human approves before execution
4. VERIFY    Automatic post-change verification
```

Built-in safety features:
- **Constitutional rules** - Absolute rules in `constitution.yaml` that can NEVER be skipped, even with `--skip-compliance`
- **Self-lockout prevention** - Blocks changes that would cut SSH access to the device
- **Two-layer compliance** - Regex rules enforced by CLI + natural language `rule` fields evaluated by Claude (LLM)
- **Risk assessment** - Claude evaluates each change before execution
- **Operation logging** - Every change is recorded in `logs/clanet_operations.log`
- **Post-change verification** - Automatic health check after config changes

## Multi-Agent Mode

For complex operations, `/clanet:team` coordinates four specialized agents with dynamic operator scaling:

```bash
/clanet:team router01 Set description "Uplink to core-sw01" on GigabitEthernet0/0/0/0
```

```
Phase 1 (always):
         ┌──────────────┐
         │   Planner     │  Investigate → Plan → Procedure → Approve
         └──────┬───────┘
                ↓ Approved plan

Phase 2 (dynamic):
   ┌────────────┐  ┌────────────┐
   │ operator-1  │  │ operator-2  │ ... (1-4 operators)
   │ Group 1     │  │ Group 2     │     scaled by device count
   └──────┬─────┘  └──────┬─────┘
          ↓                ↓
         ┌──────────────────────┐
         │  Compliance Checker   │  Policy + Constitution check
         │                      │  → PASS / WARN / BLOCK
         └──────────────────────┘
          ↓                ↓
         ┌──────────────────────┐
         │     Validator         │  Post-change health check
         └──────────────────────┘
```

| Agent | Role | Hard Constraint |
|-------|------|-----------------|
| **planner** | Investigates state, designs plan, creates procedure docs | NEVER executes config commands. |
| **compliance-checker** | Validates config against policy (regex + LLM) | NEVER executes commands. Judgment only. |
| **network-operator** | Generates vendor-correct config and executes | NEVER applies without plan + compliance PASS + human approval. |
| **validator** | Post-change health verification | NEVER makes config changes. Show commands only. |

### Dynamic Operator Scaling

For multi-device changes, operators are scaled automatically:

| Device Count | Operators | Strategy |
|-------------|-----------|----------|
| 1 | 1 | No parallelism needed |
| 2-4 | 2 | Moderate parallelism |
| 5+ | min(4, group_count) | Resource cap at 4 operators |

### Two-Layer Compliance

The compliance-checker evaluates two layers of rules:

| Layer | Rule Type | Evaluator |
|-------|-----------|-----------|
| **Regex** | `pattern_deny`, `require`, etc. | CLI engine (automatic) |
| **Semantic** | Natural language `rule` field | LLM reasoning (compliance-checker) |

Design principles (inspired by [JANOG 57 NETCON Agent Teams](https://zenn.dev/takumina/articles/01d5d284aa5eef)):
- **Safety through role separation** - Each agent has strict constraints on what it can/cannot do
- **Autonomous workflow** - Agents communicate via SendMessage, no manual coordination needed
- **Procedure documents** - Planner creates a Markdown procedure before any execution

Compliance policies are defined in `templates/policy.yaml` and constitutional rules in `templates/constitution.yaml`.

## Customization

Place a `.clanet.yaml` in your project root (or `~/.clanet.yaml`) to override default settings.
Plugin updates will never overwrite this file.

```yaml
# .clanet.yaml
inventory: ./my-inventory.yaml
policy_file: ./my-policy.yaml
default_profile: security
auto_backup: true
```

| Setting | Description | Default |
|---------|-------------|---------|
| `inventory` | Path to device inventory file | `./inventory.yaml` |
| `policy_file` | Path to compliance policy YAML | `templates/policy.yaml` |
| `default_profile` | Default audit profile (`basic`/`security`/`full`) | `basic` |
| `auto_backup` | Auto-backup before config changes | `false` |
| `health_file` | Path to health check / snapshot commands YAML | `templates/health.yaml` |
| `context_file` | Path to operation context YAML | `./context.yaml` |

See `templates/clanet.yaml` for a full template.

### Operation Context

Define task-specific network topology, symptoms, constraints, and success criteria in `context.yaml`.
When present, `/clanet:config`, `/clanet:why`, `/clanet:health`, and `/clanet:team` automatically reference it.

```bash
cp templates/context.yaml context.yaml
# Edit context.yaml for your task
python3 lib/clanet_cli.py context   # Verify loading
```

```yaml
# context.yaml
topology: |
  router01 (IOS-XR) --- eBGP --- router02 (IOS)
symptoms:
  - BGP neighbor 10.0.0.2 is in Idle state
constraints:
  - Do not modify OSPF configuration
success_criteria:
  - BGP neighbor 10.0.0.2 must be Established
```

| Section | Used by |
|---------|---------|
| `topology` | `/clanet:why`, planner, network-operator |
| `symptoms` | `/clanet:why` |
| `constraints` | planner, compliance-checker, network-operator |
| `success_criteria` | `/clanet:config`, `/clanet:health`, validator |

To use a custom path, set `context_file` in `.clanet.yaml`.

### Custom Health Check Commands

Commands executed by `/clanet:health-template` and `/clanet:snapshot` are defined in `templates/health.yaml`.
Customize freely (e.g., remove OSPF checks, add MPLS checks) without code changes.

```bash
cp templates/health.yaml my-health.yaml
# Edit my-health.yaml
```

Then point to it in `.clanet.yaml`:

```yaml
health_file: ./my-health.yaml
```

### Custom Compliance Policy

Copy `templates/policy.yaml` and add your own rules:

```bash
cp templates/policy.yaml my-policy.yaml
# Edit my-policy.yaml with your rules
```

Then point to it in `.clanet.yaml`:

```yaml
policy_file: ./my-policy.yaml
```

Rules support three patterns:
- **`pattern_deny` only** — CLI checks automatically (fast, deterministic)
- **`rule` only** — natural language rule evaluated by Claude (LLM)
- **Both** — CLI does regex; Claude also does semantic reasoning

The compliance-checker agent and `/clanet:audit` will automatically use your custom policy.

### Constitutional Rules

Constitutional rules are **absolute and cannot be skipped** — not even with `--skip-compliance`.

```bash
cp templates/constitution.yaml constitution.yaml
# Edit constitution.yaml with your absolute rules
```

Place it in the project root or `~/.constitution.yaml`. No `.clanet.yaml` entry needed.

```yaml
# constitution.yaml
rules:
  safety:
    - id: CONST-SAF-001
      name: No write erase
      severity: CRITICAL
      reason: Destructive operation that wipes the entire device configuration.
      pattern_deny: 'write\s+erase'
```

## Supported Vendors

Powered by [Netmiko](https://github.com/ktbyers/netmiko). See [supported platforms](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md) for the full list:

| Vendor | device_type | Tested |
|--------|-------------|--------|
| Cisco IOS | `cisco_ios` | - |
| Cisco IOS-XR | `cisco_xr` | Yes |
| Cisco NX-OS | `cisco_nxos` | - |
| Juniper Junos | `juniper_junos` | - |
| Arista EOS | `arista_eos` | - |
| And many more... | [Full list](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md) | - |

## Inventory Format

```yaml
devices:
  router01:
    host: 192.168.1.1
    device_type: cisco_ios
    username: admin
    password: admin
    port: 22  # optional, default: 22
```

## Architecture

```
clanet/
├── .claude-plugin/plugin.json    # Plugin manifest
├── commands/                     # 15 slash commands
├── agents/                       # 4 specialized agents
│   ├── planner.md                # Investigation, planning, procedure docs
│   ├── compliance-checker.md     # Policy validation (read-only)
│   ├── network-operator.md       # Config generation + execution
│   └── validator.md              # Post-change health verification
├── skills/team/SKILL.md          # Multi-agent orchestration skill
├── lib/clanet_cli.py             # Common CLI engine (single source of truth)
├── tests/test_cli.py             # Unit tests (no network required)
├── templates/                    # User-customizable config templates
│   ├── inventory.yaml            # Device inventory
│   ├── context.yaml              # Operation context
│   ├── clanet.yaml               # Plugin config
│   ├── policy.yaml               # Compliance rules (regex + LLM)
│   ├── constitution.yaml         # Constitutional rules (unskippable)
│   └── health.yaml               # Health check commands
└── requirements.txt              # Python dependencies
```

All 15 commands and 4 agents share `lib/clanet_cli.py` — no duplicated connection or parsing logic.

### What clanet builds vs. what Claude provides

| Layer | Implementation | Examples |
|-------|---------------|----------|
| **SSH & device automation** | Python (Netmiko) in `lib/clanet_cli.py` | Connection, command execution, backup, snapshot, logging |
| **Policy engine** | Python regex engine in `_evaluate_rule()` | `pattern_deny`, `require`, `recommend` — deterministic rule evaluation; `rule` field → LLM evaluation |
| **Safety workflows** | Prompt definitions in `commands/` | "Show, Explain, Confirm, Verify" — structured prompt sequences |
| **Risk assessment & diagnosis** | Claude's LLM reasoning, directed by prompts | `/clanet:why` troubleshooting, config change risk levels |
| **Agent coordination** | Claude Code agent framework (`agents/`) | Role-separated agents with tool restrictions |

clanet is a Claude Code plugin — it structures prompts and orchestrates tools to leverage Claude's reasoning for network operations. The "intelligence" comes from Claude itself; clanet provides the domain expertise, safety guardrails, and device automation layer.

## Security Considerations

- **Credentials**: `inventory.yaml` contains device credentials and is gitignored by default. Never commit it.
- **Environment variables**: Use `${VAR_NAME}` syntax in `inventory.yaml` for passwords and usernames (e.g., `password: ${NET_PASSWORD}`). This avoids storing credentials in plain text.
- **SSH only**: All device communication uses SSH via Netmiko. No telnet, no HTTP.
- **No external calls**: clanet does not phone home or send data to any external service. All operations are local SSH sessions.
- **Human-in-the-loop**: Config changes always require explicit user confirmation. Claude assesses risk but never auto-applies HIGH/CRITICAL changes.
- **Audit trail**: Every config operation is logged to `logs/clanet_operations.log` with timestamp, device, action, and status.

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `ERROR: inventory.yaml not found` | No inventory file in search paths | `cp templates/inventory.yaml inventory.yaml` and edit |
| `ERROR: Netmiko is not installed` | Missing Python dependency | `pip install netmiko` |
| `ERROR: device 'xxx' not found` | Device name not in inventory | Check `inventory.yaml` device names; use exact name or IP |
| `SSH connection timeout` | Device unreachable or wrong port | Verify host/port in inventory; test with `ssh user@host -p port` |
| `${VAR_NAME} not expanded` | Environment variable not set | `export VAR_NAME='value'` before running clanet |
| `WARN: policy file not found` | Custom policy path invalid | Check `policy_file` in `.clanet.yaml` or use default |

## Requirements

- Python 3.10+
- Dependencies: `pip install -r requirements.txt` (Netmiko, PyYAML)
- SSH access to network devices

## Author

Created by [takumina](https://github.com/takumina)

## License

MIT License
