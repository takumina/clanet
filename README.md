# clanet - Network Automation for Claude Code

Network automation plugin for Claude Code. Powered by [Netmiko](https://github.com/ktbyers/netmiko).

**English** | [日本語](docs/README_ja.md)

## Features

- **16 slash commands** — from `show` commands to full config deployment
- **Risk assessment** — Claude analyzes every config change for impact before execution
- **Self-lockout prevention** — blocks changes that would cut your SSH access
- **Multi-agent teams** — 3 specialized agents (compliance / operator / validator) coordinate autonomously
- **Compliance auditing** — customizable policy rules with severity levels
- **Pre/post validation** — automatic snapshots and diff for change verification
- **Multi-vendor** — Cisco IOS/XR/NX-OS, Juniper, Arista, and more via Netmiko

## Quick Start

```bash
# Requirements: Python 3.10+

# 1. Install dependencies
pip install -r requirements.txt

# 2. Create your inventory
cp examples/inventory.yaml inventory.yaml
# Edit inventory.yaml with your device info

# 3. Use the commands
/clanet router01
/clanet:cmd router01 show ip route
/clanet:check --all
```

## Commands

### Basic

| Command | Description |
|---------|-------------|
| `/clanet <device>` | Connect and show basic device info (show version) |

### Command Execution

| Command | Description |
|---------|-------------|
| `/clanet:cmd <device> <command>` | Execute any show/operational command |
| `/clanet:config <device>` | Send configuration commands |
| `/clanet:deploy <device> <file>` | Deploy configuration from a file |
| `/clanet:interactive <device>` | Execute interactive commands (yes/no prompts) |

### Monitoring & Operations

| Command | Description |
|---------|-------------|
| `/clanet:check [device\|--all]` | Health check (interfaces, BGP, OSPF) |
| `/clanet:backup [device\|--all]` | Backup running configuration |
| `/clanet:session [device\|--all]` | Check connectivity and session status |

### Mode & Configuration Management

| Command | Description |
|---------|-------------|
| `/clanet:mode <device> <action>` | Switch modes (enable, config, exit-config, check) |
| `/clanet:save [device\|--all]` | Save running config to startup |
| `/clanet:commit [device\|--all]` | Commit changes (IOS-XR, Junos) |

### Analysis & Compliance

| Command | Description |
|---------|-------------|
| `/clanet:why <device> <problem>` | Troubleshooting — Claude diagnoses issues from device output |
| `/clanet:validate <device>` | Pre/post change validation with auto-rollback |
| `/clanet:audit [device\|--all]` | Compliance audit (security & best practices) |

### Multi-Agent Team

| Command | Description |
|---------|-------------|
| `/clanet:team <device> <task>` | 3-agent team for safe config changes (compliance → execute → validate) |

## How to Use

### 1. Check device health

```bash
# Single device
/clanet:check router01

# All devices
/clanet:check --all
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

### 4. Apply a config change (single command)

```bash
/clanet:config router01
# Claude will ask what to configure, assess risk, and confirm before applying
```

### 5. Validated config change (with snapshot diff)

```bash
/clanet:validate router01
# 1. Takes pre-change snapshot
# 2. Applies config (after confirmation)
# 3. Takes post-change snapshot
# 4. Compares and reports PASS/FAIL
# 5. Offers rollback if FAIL
```

### 6. Multi-agent team change (safest)

```bash
/clanet:team router01 Set description "Uplink to core-sw01" on GigabitEthernet0/0/0/0
# compliance-checker → validates against policy
# network-operator   → generates and applies config
# validator          → verifies health after change
```

### 7. Use operation context for complex tasks

For multi-step operations, define context upfront:

```bash
cp examples/context.yaml context.yaml
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
/clanet:validate router01    # Uses success_criteria for PASS/FAIL
/clanet:why router01 BGP down # Uses topology + symptoms for diagnosis
/clanet:team router01 Fix BGP # All 3 agents respect constraints
```

### 8. Compliance audit

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
- **Self-lockout prevention** - Blocks changes that would cut SSH access to the device
- **Risk assessment** - Claude evaluates each change before execution
- **Operation logging** - Every change is recorded in `logs/clanet_operations.log`
- **Post-change verification** - Automatic health check after config changes

## Multi-Agent Mode

For complex operations, `/clanet:team` coordinates three Claude Code agents with strict role separation:

```bash
/clanet:team router01 Set description "Uplink to core-sw01" on GigabitEthernet0/0/0/0
```

Three specialized agents coordinate automatically:

```
         ┌──────────────┐
         │   Operator    │  Generate config → Execute
         └──────┬───────┘
                ↓ COMPLIANCE CHECK REQUEST
         ┌──────────────┐
         │  Compliance   │  Policy violation check
         │  Checker      │  → PASS / WARN / BLOCK
         └──────┬───────┘
                ↓ CONFIG APPLIED
         ┌──────────────┐
         │  Validator    │  Post-change health check
         │              │  → PASS / FAIL
         └──────────────┘
```

| Agent | Role | Hard Constraint |
|-------|------|-----------------|
| **compliance-checker** | Validates config against policy | NEVER executes commands. Judgment only. |
| **network-operator** | Generates vendor-correct config and executes | NEVER deploys without compliance PASS. |
| **validator** | Post-change health verification | NEVER makes config changes. Show commands only. |

Design principles (inspired by [JANOG 57 NETCON Agent Teams](https://zenn.dev/takumina/articles/01d5d284aa5eef)):
- **Safety through role separation** - Each agent has strict constraints on what it can/cannot do
- **Autonomous workflow** - Agents communicate via SendMessage, no manual coordination needed

Compliance policies are defined in `policies/example.yaml` and are fully customizable.

## Customization

Place a `.clanet.yaml` in your project root (or `~/.clanet.yaml`) to override default settings.
Plugin updates will never overwrite this file.

```yaml
# .clanet.yaml
inventory: ./my-inventory.yaml
policy_file: ./policies/my-company-policy.yaml
default_profile: security
auto_backup: true
```

| Setting | Description | Default |
|---------|-------------|---------|
| `inventory` | Path to device inventory file | `./inventory.yaml` |
| `policy_file` | Path to compliance policy YAML | `policies/example.yaml` |
| `default_profile` | Default audit profile (`basic`/`security`/`full`) | `basic` |
| `auto_backup` | Auto-backup before config changes | `false` |
| `health_file` | Path to health check / snapshot commands YAML | `policies/health.yaml` |
| `context_file` | Path to operation context YAML | `./context.yaml` |

See `examples/clanet.yaml` for a full template.

### Operation Context

Define task-specific network topology, symptoms, constraints, and success criteria in `context.yaml`.
When present, `/clanet:validate`, `/clanet:why`, `/clanet:check`, and `/clanet:team` automatically reference it.

```bash
cp examples/context.yaml context.yaml
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
| `topology` | `/clanet:why`, network-operator |
| `symptoms` | `/clanet:why` |
| `constraints` | compliance-checker, network-operator |
| `success_criteria` | `/clanet:validate`, `/clanet:check`, validator |

To use a custom path, set `context_file` in `.clanet.yaml`.

### Custom Health Check Commands

Commands executed by `/clanet:check` and `/clanet:snapshot` are defined in `policies/health.yaml`.
Customize freely (e.g., remove OSPF checks, add MPLS checks) without code changes.

```bash
cp policies/health.yaml policies/my-health.yaml
# Edit policies/my-health.yaml
```

Then point to it in `.clanet.yaml`:

```yaml
health_file: ./policies/my-health.yaml
```

### Custom Compliance Policy

Copy `policies/example.yaml` and add your own rules:

```bash
cp policies/example.yaml policies/my-policy.yaml
# Edit policies/my-policy.yaml with your rules
```

Then point to it in `.clanet.yaml`:

```yaml
policy_file: ./policies/my-policy.yaml
```

The compliance-checker agent and `/clanet:audit` will automatically use your custom policy.

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
clanet-plugin/
├── .claude-plugin/plugin.json    # Marketplace metadata
├── .claude/
│   ├── commands/                 # 16 slash commands
│   ├── agents/                   # 3 specialized agents
│   └── skills/team/SKILL.md      # Multi-agent orchestration skill
├── lib/clanet_cli.py             # Common CLI engine (single source of truth)
├── tests/test_cli.py             # Unit tests (no network required)
├── policies/
│   ├── example.yaml              # Compliance rules (customizable)
│   └── health.yaml               # Health check & snapshot commands
├── examples/
│   ├── inventory.yaml            # Device inventory template
│   ├── context.yaml              # Operation context template
│   └── clanet.yaml               # Plugin config template
└── requirements.txt              # Python dependencies
```

All 16 commands and 3 agents share `lib/clanet_cli.py` — no duplicated connection or parsing logic.

### What clanet builds vs. what Claude provides

| Layer | Implementation | Examples |
|-------|---------------|----------|
| **SSH & device automation** | Python (Netmiko) in `lib/clanet_cli.py` | Connection, command execution, backup, snapshot, logging |
| **Policy engine** | Python regex engine in `_evaluate_rule()` | `pattern_deny`, `require`, `recommend` — deterministic rule evaluation |
| **Safety workflows** | Prompt definitions in `.claude/commands/` | "Show, Explain, Confirm, Verify" — structured prompt sequences |
| **Risk assessment & diagnosis** | Claude's LLM reasoning, directed by prompts | `/clanet:why` troubleshooting, config change risk levels |
| **Agent coordination** | Claude Code agent framework (`.claude/agents/`) | Role-separated agents with tool restrictions |

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
| `ERROR: inventory.yaml not found` | No inventory file in search paths | `cp examples/inventory.yaml inventory.yaml` and edit |
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
