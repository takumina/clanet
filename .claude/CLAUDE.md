# CLAUDE.md

This file provides guidance for AI assistants working on the clanet codebase.

## Project Overview

clanet is a **Claude Code plugin** for network automation, powered by [Netmiko](https://github.com/ktbyers/netmiko). It provides 15 slash commands, 4 specialized Claude Code agents, and a multi-agent team orchestration skill for safely managing network devices (Cisco IOS/XR/NX-OS, Juniper, Arista, etc.) via SSH.

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
├── commands/                  # 15 slash command definitions (Markdown)
│   ├── check.md               # /clanet:check — connect and show version
│   ├── cmd.md                 # /clanet:cmd — execute show commands
│   ├── config.md              # /clanet:config — config change with pre/post validation
│   ├── config-load.md         # /clanet:config-load — load config from file
│   ├── cmd-interact.md        # /clanet:cmd-interact — interactive commands
│   ├── health.md              # /clanet:health — health check (Claude-driven)
│   ├── health-template.md     # /clanet:health-template — health check (template-driven)
│   ├── backup.md              # /clanet:backup — backup running-config
│   ├── save.md                # /clanet:save — write memory
│   ├── commit.md              # /clanet:commit — commit (IOS-XR/Junos)
│   ├── config-quick.md        # /clanet:config-quick — quick config (no snapshots)
│   ├── why.md                 # /clanet:why — network troubleshooting
│   ├── audit.md               # /clanet:audit — compliance audit
│   ├── team.md                # /clanet:team — multi-agent team change
│   └── safety-guide.md        # [internal] shared safety framework
├── agents/                    # 4 specialized agent definitions
│   ├── planner.md             # Investigation, planning, procedure docs
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
│   ├── constitution.yaml      # Constitutional rules template (unskippable)
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

All 15 slash commands and 4 agents delegate to `lib/clanet_cli.py`. There is no duplicated connection, parsing, or artifact logic. When adding new functionality, extend this single file rather than creating new scripts.

### Agent Role Separation

The four agents have strict boundaries:

| Agent | Can Do | Cannot Do |
|-------|--------|-----------|
| **planner** | Investigate state, design plans, create procedure docs, get plan approval | Execute config commands |
| **compliance-checker** | Read policies, analyze commands, send verdicts | Execute commands, connect to devices |
| **network-operator** | Generate config, execute approved changes | Apply config without plan + compliance PASS + human approval |
| **validator** | Run show commands, compare snapshots | Make config changes |

### Dynamic Operator Scaling

When `/clanet:team` handles multi-device changes, operators are dynamically scaled for parallel execution:

```
Phase 1: Spawn planner + compliance-checker + validator
         ↓ planner sends APPROVED CHANGE PLAN with Device Groups
Phase 2: Spawn operator-1..N based on device count
         ↓ each operator handles its assigned group in parallel
```

| Device Count | Operators | Assignment |
|-------------|-----------|------------|
| 1 | 1 (operator-1) | All devices |
| 2-4 | 2 (operator-1, operator-2) | Round-robin by group |
| 5+ | min(4, group_count) | Round-robin by group |

Key behaviors:
- Planner groups devices in the plan (by dependency → site → role → balance)
- Team lead spawns operators in Phase 2 and assigns Device Groups
- Each operator independently runs Steps 2-8 per device (generate → compliance → approve → execute → validate)
- Operators report OPERATOR COMPLETE to team lead when all assigned devices are done
- If planner omits Device Groups, team lead falls back to alphabetical split

### Safety-First Config Changes

All config-changing commands follow the **"Show, Explain, Confirm, Verify"** pattern defined in `commands/safety-guide.md`. Self-lockout prevention blocks changes to management interfaces, VTY ACLs, and management routing.

### Two-Layer Rule System (Constitution & Policy)

Both `constitution.yaml` and `policy.yaml` support three evaluation patterns:

| Field | Evaluator | When |
|-------|-----------|------|
| `pattern_deny` | CLI (regex) | Always — fast, deterministic |
| `rule` | Claude / compliance-checker (LLM) | `/clanet:config` Step 6 or `/clanet:team` |
| Both | CLI does regex; LLM also does semantic reasoning | Best of both worlds |

- **CLI**: Evaluates `pattern_deny` rules. Warns about `rule`-only entries (CLI cannot evaluate natural language).
- **`/clanet:config`**: Claude evaluates `rule` fields in Step 6 (EXPLAIN phase) when CLI warnings indicate LLM rules exist.
- **`/clanet:team`**: compliance-checker agent evaluates both regex and natural language `rule` fields using LLM reasoning.
- `cmd_constitution_rules` / `cmd_policy_rules` subcommands provide rules as JSON for agent consumption.

### External-Only Policy Rules

Compliance rules live entirely in YAML files (`templates/policy.yaml`). The audit engine (`_evaluate_rule`) supports these rule types:
- `pattern_deny` / `pattern_allow` — regex deny with optional exceptions
- `require` / `require_on` — required pattern, optionally scoped to a config section
- `require_in_running` — must exist in running-config
- `recommend` — advisory (WARN only)
- `rule` — natural language rule for LLM evaluation
- `scope` — when to evaluate (`config_commands` | `interface_config`)

## Development Guide

### Exception Handling

All recoverable errors use a custom exception hierarchy rooted at `ClanetError`:

| Exception | Raised by |
|-----------|-----------|
| `InventoryNotFoundError` | `load_inventory()` |
| `DeviceNotFoundError` | `get_device()` |
| `DeviceConnectionError` | `connect()` |
| `ConfigError` | `_load_health_config()`, `cmd_config()`, `cmd_config_load()`, `cmd_interact()` (cmd-interact), `cmd_audit()` |

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
| `procedures/` | `<task-summary>_YYYYMMDD_HHMMSS.md` | Yes |

### Configuration Search Order

| Config | Search Order |
|--------|-------------|
| Plugin config | `./.clanet.yaml` → `~/.clanet.yaml` → built-in defaults |
| Inventory | `inventory` key in config → `./inventory.yaml` → `~/.net-inventory.yaml` |
| Constitution | `./constitution.yaml` → `~/.constitution.yaml` (optional, NEVER skippable) |
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
