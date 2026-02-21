# clanet - Network Automation for Claude Code

**Safety-first** network automation plugin for Claude Code.
Run commands, backup configs, deploy changes with AI-powered risk assessment, and audit compliance — all through slash commands.

Powered by [Netmiko](https://github.com/ktbyers/netmiko). Tested on Cisco IOS-XR (Containerlab XRd).

## Features

- **16 slash commands** — from `show` commands to full config deployment
- **AI risk assessment** — every config change is analyzed for impact before execution
- **Self-lockout prevention** — blocks changes that would cut your SSH access
- **Multi-agent teams** — 3 specialized agents (compliance / operator / validator) coordinate autonomously
- **Compliance auditing** — customizable policy rules with severity levels
- **Pre/post validation** — automatic snapshots and diff for change verification
- **Multi-vendor** — Cisco IOS/XR/NX-OS, Juniper, Arista, and more via Netmiko

## Quick Start

```bash
# Requirements: Python 3.10+

# 1. Install dependencies
pip install netmiko pyyaml

# 2. Create your inventory
cp inventory.example.yaml inventory.yaml
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

### AI-Powered Analysis

| Command | Description |
|---------|-------------|
| `/clanet:why <device> <problem>` | AI troubleshooting - diagnose issues intelligently |
| `/clanet:validate <device>` | Pre/post change validation with auto-rollback |
| `/clanet:audit [device\|--all]` | Compliance audit (security & best practices) |

### Multi-Agent Team

| Command | Description |
|---------|-------------|
| `/clanet:team <device> <task>` | 3-agent team for safe config changes (compliance → execute → validate) |

## Safety First

Every configuration change follows the **"Show, Explain, Confirm, Verify"** workflow:

```
1. SHOW      What commands will be applied
2. EXPLAIN   AI analyzes impact and risk (LOW/MEDIUM/HIGH/CRITICAL)
3. CONFIRM   Human approves before execution
4. VERIFY    Automatic post-change verification
```

Built-in safety features:
- **Self-lockout prevention** - Blocks changes that would cut SSH access to the device
- **Risk assessment** - AI evaluates each change before execution
- **Operation logging** - Every change is recorded in `logs/clanet_operations.log`
- **Post-change verification** - Automatic health check after config changes

## Multi-Agent Mode

clanet includes AI agent teams for complex operations. Run `/clanet:team` to activate:

```bash
/clanet:team router01 Add NTP server 10.0.0.1
```

Three specialized agents coordinate automatically:

```
         ┌──────────────┐
         │   Operator    │  Generate config → Execute
         │   (Sonnet)    │
         └──────┬───────┘
                ↓ COMPLIANCE CHECK REQUEST
         ┌──────────────┐
         │  Compliance   │  Policy violation check
         │  (Haiku)      │  → PASS / WARN / BLOCK
         └──────┬───────┘
                ↓ CONFIG APPLIED
         ┌──────────────┐
         │  Validator    │  Post-change health check
         │  (Sonnet)     │  → PASS / FAIL
         └──────────────┘
```

| Agent | Model | Role | Hard Constraint |
|-------|-------|------|-----------------|
| **compliance-checker** | Haiku | Validates config against policy | NEVER executes commands. Judgment only. |
| **network-operator** | Sonnet | Generates vendor-correct config and executes | NEVER deploys without compliance PASS. |
| **validator** | Sonnet | Post-change health verification | NEVER makes config changes. Show commands only. |

Design principles (inspired by [JANOG 57 NETCON Agent Teams](https://zenn.dev/takumina/articles/01d5d284aa5eef)):
- **Safety through role separation** - Each agent has strict constraints on what it can/cannot do
- **Cost optimization** - Compliance checker uses Haiku (lightweight model, judgment only)
- **Autonomous workflow** - Agents communicate via SendMessage, no manual coordination needed

Compliance policies are defined in `policies/default.yaml` and are fully customizable.

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
| `policy_file` | Path to compliance policy YAML | `policies/default.yaml` |
| `default_profile` | Default audit profile (`basic`/`security`/`full`) | `basic` |
| `auto_backup` | Auto-backup before config changes | `false` |

See `.clanet.example.yaml` for a full template.

### Custom Compliance Policy

Copy `policies/default.yaml` and add your own rules:

```bash
cp policies/default.yaml policies/my-policy.yaml
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
│   ├── commands/                 # 15 slash commands
│   ├── agents/                   # 3 specialized agents
│   └── skills/team/SKILL.md      # Multi-agent orchestration skill
├── lib/clanet_cli.py             # Common CLI engine (single source of truth)
├── tests/test_cli.py             # 40 unit tests (no network required)
├── policies/default.yaml         # Compliance rules (customizable)
├── inventory.example.yaml        # Inventory template
└── .clanet.example.yaml          # Config template
```

All 16 commands and 3 agents share `lib/clanet_cli.py` — no duplicated connection or parsing logic.

## Security Considerations

- **Credentials**: `inventory.yaml` contains device credentials and is gitignored by default. Never commit it.
- **Environment variables**: Use `${VAR_NAME}` syntax in `inventory.yaml` for passwords and usernames (e.g., `password: ${NET_PASSWORD}`). This avoids storing credentials in plain text.
- **SSH only**: All device communication uses SSH via Netmiko. No telnet, no HTTP.
- **No external calls**: clanet does not phone home or send data to any external service. All operations are local SSH sessions.
- **Human-in-the-loop**: Config changes always require explicit user confirmation. The AI assesses risk but never auto-applies HIGH/CRITICAL changes.
- **Audit trail**: Every config operation is logged to `logs/clanet_operations.log` with timestamp, device, action, and status.

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `ERROR: inventory.yaml not found` | No inventory file in search paths | `cp inventory.example.yaml inventory.yaml` and edit |
| `ERROR: Netmiko is not installed` | Missing Python dependency | `pip install netmiko` |
| `ERROR: device 'xxx' not found` | Device name not in inventory | Check `inventory.yaml` device names; use exact name or IP |
| `SSH connection timeout` | Device unreachable or wrong port | Verify host/port in inventory; test with `ssh user@host -p port` |
| `${VAR_NAME} not expanded` | Environment variable not set | `export VAR_NAME='value'` before running clanet |
| `WARN: policy file not found` | Custom policy path invalid | Check `policy_file` in `.clanet.yaml` or use default |

## Requirements

- Python 3.10+
- Netmiko (`pip install netmiko`)
- PyYAML (`pip install pyyaml`)
- SSH access to network devices

## Author

Created by [takumina](https://github.com/takumina)

## License

MIT License
