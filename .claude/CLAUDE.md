# CLAUDE.md

This file provides guidance for AI assistants working on the clanet codebase.

## Project Overview

clanet is a **Claude Code plugin** for network automation, powered by [Netmiko](https://github.com/ktbyers/netmiko). It provides 16 slash commands, 3 specialized Claude Code agents, and a multi-agent team orchestration skill for safely managing network devices (Cisco IOS/XR/NX-OS, Juniper, Arista, etc.) via SSH.

- **Version**: 0.2.1
- **License**: MIT
- **Author**: [takumina](https://github.com/takumina)
- **Python**: 3.10+

## Repository Structure

```
clanet/
├── .claude/
│   └── CLAUDE.md              # Developer guide (hidden from GitHub root)
├── .claude-plugin/
│   └── plugin.json            # Claude Code plugin manifest
├── commands/                  # 16 slash command definitions (Markdown)
│   ├── check.md               # /clanet:check — connect and show version
│   ├── cmd.md                 # /clanet:cmd — execute show commands
│   ├── config.md              # /clanet:config — apply config (with safety)
│   ├── deploy.md              # /clanet:deploy — deploy config from file
│   ├── interactive.md         # /clanet:interactive — interactive commands
│   ├── health.md              # /clanet:health — health check
│   ├── backup.md              # /clanet:backup — backup running-config
│   ├── session.md             # /clanet:session — connectivity check
│   ├── mode.md                # /clanet:mode — enable/config mode switching
│   ├── save.md                # /clanet:save — write memory
│   ├── commit.md              # /clanet:commit — commit (IOS-XR/Junos)
│   ├── validate.md            # /clanet:validate — pre/post snapshot diff
│   ├── why.md                 # /clanet:why — network troubleshooting
│   ├── audit.md               # /clanet:audit — compliance audit
│   ├── team.md                # /clanet:team — multi-agent team change
│   └── safety-guide.md        # [internal] shared safety framework
├── agents/                    # 3 specialized agent definitions
│   ├── compliance-checker.md  # Policy validation (read-only)
│   ├── network-operator.md    # Config generation + execution
│   └── validator.md           # Post-change health verification
├── skills/
│   └── team/SKILL.md          # Multi-agent orchestration skill
├── lib/
│   └── clanet_cli.py          # Core CLI engine (single source of truth)
├── templates/                 # User-facing config templates (copy & customize)
│   ├── inventory.yaml         # Device inventory template
│   ├── context.yaml           # Operation context template
│   ├── clanet.yaml            # Plugin config (.clanet.yaml) template
│   ├── policy.yaml            # Compliance policy rules template
│   └── health.yaml            # Health check & snapshot commands (per-vendor)
├── tests/
│   └── test_cli.py            # Unit tests (pytest, no network required)
├── requirements.txt           # Runtime dependencies (netmiko, pyyaml)
├── requirements-dev.txt       # Dev dependencies (adds pytest)
├── .gitignore
├── LICENSE
└── README.md
```

## Key Architecture Decisions

### Single CLI Engine

All 16 slash commands and 3 agents delegate to `lib/clanet_cli.py`. There is no duplicated connection, parsing, or artifact logic. When adding new functionality, extend this single file rather than creating new scripts.

### Agent Role Separation

The three agents have strict boundaries:

| Agent | Can Do | Cannot Do |
|-------|--------|-----------|
| **compliance-checker** | Read policies, analyze commands, send verdicts | Execute commands, connect to devices |
| **network-operator** | Generate config, execute approved changes | Deploy without compliance PASS |
| **validator** | Run show commands, compare snapshots | Make config changes |

### Safety-First Config Changes

All config-changing commands follow the **"Show, Explain, Confirm, Verify"** pattern defined in `commands/safety-guide.md`. Self-lockout prevention blocks changes to management interfaces, VTY ACLs, and management routing.

### External-Only Policy Rules

Compliance rules live entirely in YAML files (`templates/policy.yaml`). The audit engine (`_evaluate_rule`) supports these rule types:
- `pattern_deny` / `pattern_allow` — regex deny with optional exceptions
- `require` / `require_on` — required pattern, optionally scoped to a config section
- `require_in_running` — must exist in running-config
- `recommend` — advisory (WARN only)
- `scope` — when to evaluate (`config_commands` | `interface_config`)

## Development Guide

### Exception Handling

All recoverable errors use a custom exception hierarchy rooted at `ClanetError`:

| Exception | Raised by |
|-----------|-----------|
| `InventoryNotFoundError` | `load_inventory()` |
| `DeviceNotFoundError` | `get_device()` |
| `DeviceConnectionError` | `connect()` |
| `ConfigError` | `_load_health_config()`, `cmd_config()`, `cmd_deploy()`, `cmd_interact()`, `cmd_audit()` |

`main()` catches `ClanetError` and converts to `sys.exit(1)`. Library consumers can catch specific exceptions without `SystemExit`.

### Dependencies

```bash
pip install -r requirements.txt       # Runtime (netmiko, pyyaml)
pip install -r requirements-dev.txt   # Dev (adds pytest)
```

### Running Tests

```bash
python3 -m pytest tests/test_cli.py -v
```

### Linting

```bash
pip install ruff
ruff check lib/ tests/
```

Configuration is in `pyproject.toml`. No CI is currently configured. Run linting locally before committing.

Tests are fully offline — no network devices needed. They use fixtures, monkeypatching, and `tmp_path` to test inventory loading, argument parsing, policy evaluation, artifact management, and more.

All tests should pass in a clean checkout. `templates/health.yaml` ships with the repo and defines per-vendor health check and snapshot commands.

### Adding a New Slash Command

1. Create `commands/<name>.md` with frontmatter (`description`, `argument-hint`, `allowed-tools`)
2. The command markdown should instruct Claude to call `python3 lib/clanet_cli.py <subcommand> ...`
3. If the command changes device config, reference the safety-guide.md framework
4. Add the corresponding subcommand handler in `lib/clanet_cli.py` (function `cmd_<name>`)
5. Register the subcommand in `build_parser()`
6. Add tests in `tests/test_cli.py`

### Adding a New Agent

1. Create `agents/<name>.md` with frontmatter (`name`, `description`, `tools`)
2. Define hard constraints (what the agent must NEVER do)
3. Define the autonomous workflow as numbered steps
4. If the agent participates in team orchestration, update `skills/team/SKILL.md`

### Code Conventions

- **Python 3.10+** — uses `dict | None` union syntax, `list[tuple]` generics
- **Single file engine** — all CLI logic in `lib/clanet_cli.py`, no multi-file package structure
- **argparse subcommands** — each subcommand has a `cmd_<name>(args)` function and is registered in `build_parser()`
- **YAML for all config** — inventory, policies, health checks, operation context, plugin config
- **Timestamped artifacts** — backups, snapshots, audit reports saved with `YYYYMMDD_HHMMSS` format
- **Operation logging** — all config changes logged to `logs/clanet_operations.log`
- **Environment variable expansion** — `${VAR_NAME}` syntax in inventory for credentials
- **Error handling** — functions call `sys.exit(1)` on fatal errors with descriptive messages to stderr

### File Naming and Output Directories

| Directory | Contents | Gitignored |
|-----------|----------|------------|
| `logs/` | `clanet_operations.log` | Yes |
| `backups/` | `<device>_YYYYMMDD_HHMMSS.cfg` | Yes |
| `snapshots/` | `<device>_<pre|post>_YYYYMMDD_HHMMSS.json` | Yes |
| `audit/` | `<device>_YYYYMMDD_HHMMSS.md` | Yes |

### Configuration Search Order

| Config | Search Order |
|--------|-------------|
| Plugin config | `./.clanet.yaml` → `~/.clanet.yaml` → built-in defaults |
| Inventory | `inventory` key in config → `./inventory.yaml` → `~/.net-inventory.yaml` |
| Policy | `--policy` flag → `policy_file` in config → `templates/policy.yaml` |
| Health checks | `health_file` in config → `templates/health.yaml` |
| Context | `context_file` in config → `./context.yaml` (optional) |
| Timeouts | `read_timeout` / `read_timeout_long` in config → defaults (30s / 60s) |

### Commit Platforms

Platforms requiring explicit `commit` after config changes: `cisco_xr`, `juniper_junos`. Detected by `needs_commit()`. All other platforms auto-save or use `write memory` via `/clanet:save`.

## Security Notes

- `inventory.yaml` contains device credentials and is **gitignored** — never commit it
- Use `${VAR_NAME}` environment variable syntax for passwords in inventory
- All device communication is SSH only (Netmiko) — no telnet, no HTTP
- No external network calls — all operations are local SSH sessions
- Config changes always require explicit human confirmation
- HIGH/CRITICAL risk changes require device name confirmation

## Common Patterns

### CLI invocation from slash commands

All commands activate a virtualenv if present, then call the CLI:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py <subcommand> [args]
```

### Config application with commit handling

```python
commit = needs_commit(dev)
output = conn.send_config_set(commands, exit_config_mode=not commit)
if commit:
    conn.commit()
    conn.exit_config_mode()
```

### Multi-device operations

Commands supporting `--all` use `resolve_targets()` which returns `list[tuple[str, dict]]` of `(name, device_config)` pairs, sorted alphabetically.
