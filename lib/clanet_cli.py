#!/usr/bin/env python3
"""clanet CLI - Common network automation engine for clanet plugin.

All slash commands delegate to this single CLI for:
- Inventory loading and device connection
- Command execution (show / config / interactive)
- Health checks, backups, snapshots
- Operation logging and artifact management

Usage:
    python3 clanet_cli.py <subcommand> [options]

Subcommands:
    info      <device>                  Show device info (show version)
    show      <device> <command>        Execute a show/operational command
    config    <device> --commands JSON  Apply config commands
    deploy    <device> <file>           Deploy config from file
    interact  <device> --commands JSON  Interactive commands (expect patterns)
    check     <device|--all>            Health check
    backup    <device|--all>            Backup running config
    session   <device|--all>            Check connectivity
    mode      <device> <action>         Mode switching (enable/config/exit-config/check)
    save      <device|--all>            Save running to startup
    commit    <device|--all>            Commit (IOS-XR/Junos)
    snapshot  <device>                  Capture state snapshot (for validate)
    audit     <device|--all> [--profile basic|security|full]
    device-info <device>                  Print device metadata as JSON
    list                                  List all devices in inventory
    context                               Display loaded operation context
"""

import argparse
import json
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ClanetError(Exception):
    """Base exception for all clanet errors."""


class InventoryNotFoundError(ClanetError):
    """Inventory file not found in any search path."""


class DeviceNotFoundError(ClanetError):
    """Device not found in inventory."""


class DeviceConnectionError(ClanetError):
    """Failed to connect to a device."""


class ConfigError(ClanetError):
    """Configuration or health file loading failed."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INVENTORY_PATHS = ["inventory.yaml", os.path.expanduser("~/.net-inventory.yaml")]

CONFIG_PATHS = [".clanet.yaml", os.path.expanduser("~/.clanet.yaml")]
DEFAULT_CONFIG: dict = {
    "inventory": None,
    "policy_file": None,
    "health_file": None,
    "context_file": None,
    "default_profile": "basic",
    "auto_backup": False,
    "read_timeout": 30,
    "read_timeout_long": 60,
    "connect_timeout": 5,
    "session_test_delay": 1,
}

COMMIT_PLATFORMS = {"cisco_xr", "juniper_junos"}

# ---------------------------------------------------------------------------
# Self-lockout detection patterns (per vendor)
# ---------------------------------------------------------------------------
# Each entry: (interface_pattern, dangerous_sub_pattern, description)
# interface_pattern matches the 'interface ...' line for management interfaces.
# dangerous_sub_pattern matches commands under that interface that would cause lockout.
_LOCKOUT_MGMT_INTERFACE: dict[str, str] = {
    "cisco_ios": r"interface\s+(Management\S*|Mgmt\S*|GigabitEthernet0/0)\s*$",
    "cisco_xr": r"interface\s+MgmtEth\S*",
    "cisco_nxos": r"interface\s+mgmt0\s*$",
    "juniper_junos": r"delete\s+interfaces\s+(em0|fxp0|me0|irb)\S*",
    "arista_eos": r"interface\s+Management1\s*$",
}

_LOCKOUT_DANGEROUS_SUB = re.compile(
    r"^\s*(shutdown|no\s+ip\s+address|no\s+ipv4\s+address)", re.IGNORECASE,
)

_LOCKOUT_STANDALONE: dict[str, list[tuple[re.Pattern, str]]] = {
    "cisco_ios": [
        (re.compile(r"no\s+ip\s+route\s+0\.0\.0\.0", re.IGNORECASE),
         "removing default route may cut management access"),
    ],
    "cisco_xr": [
        (re.compile(r"no\s+router\s+(ospf|bgp|static)", re.IGNORECASE),
         "removing routing protocol may cut management access"),
    ],
}

# Standard output directory structure
DIRS = {
    "logs": "logs",
    "backups": "backups",
    "snapshots": "snapshots",
    "audit": "audit",
}

# Default file paths (used when .clanet.yaml does not specify overrides)
DEFAULT_SSH_PORT = 22
DEFAULT_HEALTH_PATH = "templates/health.yaml"
DEFAULT_POLICY_PATH = "templates/policy.yaml"
LOG_FILENAME = "clanet_operations.log"

# Standard timestamp formats
TS_LOG = "%Y-%m-%d %H:%M:%S"
TS_FILE = "%Y%m%d_%H%M%S"

# Display formatting
DISPLAY_WIDTH = 62

# Patterns matching sensitive values to redact in logs and artifacts
_SENSITIVE_RE = re.compile(
    r'(?i)((?:password|secret|community|key-string|tacacs-key|radius-key'
    r'|authentication-key|crypto\s+key)\s+(?:\d+\s+)?)\S+'
)

# ---------------------------------------------------------------------------
# Core: Inventory & Connection
# ---------------------------------------------------------------------------


def load_config() -> dict:
    """Load user configuration from .clanet.yaml.

    Search order: ./.clanet.yaml → ~/.clanet.yaml → defaults.
    """
    config = dict(DEFAULT_CONFIG)
    for path in CONFIG_PATHS:
        try:
            with open(path) as f:
                user = yaml.safe_load(f) or {}
            config.update(user)
            config["_config_path"] = path
            return config
        except FileNotFoundError:
            continue
    return config


# Module-level config (loaded once)
_config: dict | None = None


def get_config() -> dict:
    """Get the loaded config (singleton)."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def _load_health_config() -> dict:
    """Load health check / snapshot command definitions from YAML.

    Search order: health_file in .clanet.yaml → templates/health.yaml.
    Returns dict with keys: health_commands, snapshot_commands, fallback.
    """
    config = get_config()
    health_path = config.get("health_file")
    if not health_path:
        health_path = DEFAULT_HEALTH_PATH

    try:
        with open(health_path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ConfigError(
                f"invalid health config format in {health_path}: must be a YAML mapping"
            )
        return data
    except FileNotFoundError:
        raise ConfigError(
            f"health config not found: {health_path}"
            " (create one: cp templates/health.yaml my-health.yaml"
            " or specify health_file in .clanet.yaml)"
        )


CONTEXT_PATHS = ["context.yaml"]


def _load_context() -> dict | None:
    """Load operation context from context.yaml.

    Search order: context_file in .clanet.yaml → ./context.yaml.
    Returns None if no context file is found (task-specific context is optional).
    """
    config = get_config()
    context_path = config.get("context_file")
    if context_path:
        paths = [context_path]
    else:
        paths = list(CONTEXT_PATHS)

    for path in paths:
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return data
        except FileNotFoundError:
            continue
    return None


def _expand_env_vars(value: str) -> str:
    """Expand ${VAR_NAME} patterns in a string using environment variables.

    Undefined variables are left as-is (connect() will catch missing fields).
    """
    def _replace(match):
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))
    return re.sub(r"\$\{([^}]+)\}", _replace, value)


def _redact_sensitive(text: str) -> str:
    """Redact sensitive values (passwords, secrets, community strings) in text.

    Replaces the value portion of password/secret/community/key-string
    patterns with '***'.
    """
    return _SENSITIVE_RE.sub(r'\1***', text)


def _warn_plaintext_passwords(inv: dict) -> None:
    """Warn to stderr when devices use plaintext passwords instead of env vars."""
    for name, dev in inv.get("devices", {}).items():
        pw = dev.get("password", "")
        if isinstance(pw, str) and pw and not re.search(r'\$\{.+\}', pw):
            print(
                f"[SECURITY] {name}: password is plaintext in inventory. "
                f"Use ${{ENV_VAR}} syntax instead.",
                file=sys.stderr,
            )


def load_inventory() -> dict:
    """Load device inventory from standard paths.

    If .clanet.yaml specifies an inventory path, it is searched first.
    Environment variables (${VAR_NAME}) in password/username fields are expanded.
    """
    config = get_config()
    paths = list(INVENTORY_PATHS)
    if config.get("inventory"):
        paths.insert(0, config["inventory"])

    for path in paths:
        try:
            with open(path) as f:
                inv = yaml.safe_load(f)
            if not isinstance(inv, dict) or not isinstance(inv.get("devices"), dict):
                raise ConfigError(
                    f"invalid inventory format in {path}: "
                    "'devices' must be a YAML mapping"
                )
            _warn_plaintext_passwords(inv)
            for dev in inv["devices"].values():
                for field in ("password", "username", "secret"):
                    if field in dev and isinstance(dev[field], str):
                        dev[field] = _expand_env_vars(dev[field])
            return inv
        except FileNotFoundError:
            continue
    raise InventoryNotFoundError(
        f"inventory.yaml not found (searched: {', '.join(paths)})"
    )


def get_device(inv: dict, name: str) -> dict:
    """Resolve device by name or IP. Exits on not found."""
    devices = inv.get("devices", {})

    # Direct name match
    if name in devices:
        return devices[name]

    # IP/host match
    for dev in devices.values():
        if dev.get("host") == name:
            return dev

    available = ", ".join(sorted(devices.keys()))
    raise DeviceNotFoundError(
        f"device '{name}' not found in inventory (available: {available})"
    )


def resolve_targets(inv: dict, target: str) -> list[tuple[str, dict]]:
    """Resolve target to list of (name, device_config) pairs.

    Supports:
        - Single device name: "router01"
        - All devices: "--all"
    """
    if target == "--all":
        return sorted(inv.get("devices", {}).items())
    return [(target, get_device(inv, target))]


def connect(dev: dict):
    """Create a Netmiko ConnectHandler from device config."""
    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise ConfigError(
            "Netmiko is not installed. Run: pip install netmiko"
        )

    required = ["device_type", "host", "username", "password"]
    missing = [f for f in required if f not in dev]
    if missing:
        raise ConfigError(
            f"device config missing required fields: {', '.join(missing)}"
        )

    config = get_config()
    return ConnectHandler(
        device_type=dev["device_type"],
        host=dev["host"],
        username=dev["username"],
        password=dev["password"],
        port=dev.get("port", DEFAULT_SSH_PORT),
        timeout=config["connect_timeout"],
    )


def needs_commit(dev: dict) -> bool:
    """Check if device platform requires explicit commit."""
    return dev["device_type"] in COMMIT_PLATFORMS


# ---------------------------------------------------------------------------
# Core: Logging & Artifacts
# ---------------------------------------------------------------------------


def ensure_dir(dir_type: str) -> Path:
    """Ensure output directory exists and return path."""
    path = Path(DIRS[dir_type])
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_operation(device: str, action: str, detail: str = "", status: str = "SUCCESS"):
    """Append to the operation log."""
    log_dir = ensure_dir("logs")
    ts = datetime.now().strftime(TS_LOG)
    entry = f"[{ts}] DEVICE={device} ACTION={action} STATUS={status}"
    if detail:
        entry += f" DETAIL={_redact_sensitive(detail)}"
    log_file = log_dir / LOG_FILENAME
    fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(entry + "\n")


def save_artifact(dir_type: str, device: str, content: str, suffix: str = "",
                  ext: str = ".txt") -> str:
    """Save a timestamped artifact file. Returns the file path."""
    out_dir = ensure_dir(dir_type)
    ts = datetime.now().strftime(TS_FILE)
    suffix_str = f"_{suffix}" if suffix else ""
    filename = f"{device}{suffix_str}_{ts}{ext}"
    filepath = out_dir / filename
    fd = os.open(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return str(filepath)


# ---------------------------------------------------------------------------
# Subcommand: info
# ---------------------------------------------------------------------------


def _get_vendor_command(hc: dict, section: str, device_type: str, fallback_key: str) -> str:
    """Resolve a per-vendor command string from health config.

    Looks up hc[section][device_type], falling back to hc['fallback'][fallback_key].
    """
    cmd = hc.get(section, {}).get(device_type)
    if cmd:
        return cmd
    return hc.get("fallback", {}).get(fallback_key, "show version")


def cmd_info(args):
    """Show device info (show version)."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    config = get_config()
    hc = _load_health_config()
    info_cmd = _get_vendor_command(hc, "info_command", dev["device_type"], "info_command")
    conn = connect(dev)
    try:
        output = conn.send_command(info_cmd, read_timeout=config["read_timeout"])
        print(output)
    finally:
        conn.disconnect()


# ---------------------------------------------------------------------------
# Subcommand: show
# ---------------------------------------------------------------------------


def cmd_show(args):
    """Execute a show/operational command."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    config = get_config()
    command = " ".join(args.command)
    conn = connect(dev)
    try:
        output = conn.send_command(command, read_timeout=config["read_timeout"])
        print(output)
    finally:
        conn.disconnect()


# ---------------------------------------------------------------------------
# Subcommand: config
# ---------------------------------------------------------------------------


def _validate_json_commands(raw: str) -> list[str]:
    """Parse and validate JSON command list from --commands argument."""
    try:
        commands = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(
            f'--commands is not valid JSON: {e}'
            ' (expected format: --commands \'["cmd1", "cmd2"]\')'
        )
    if not isinstance(commands, list):
        raise ConfigError(
            f"--commands must be a JSON array, got {type(commands).__name__}"
        )
    if not commands:
        raise ConfigError("--commands list is empty")
    for i, cmd in enumerate(commands):
        if not isinstance(cmd, str):
            raise ConfigError(
                f"command #{i + 1} must be a string, got {type(cmd).__name__}"
            )
    return commands


def _auto_backup(device_name: str, dev: dict) -> str | None:
    """Take a backup before config change if auto_backup is enabled.

    Returns the backup file path, or None if skipped.
    """
    config = get_config()
    if not config.get("auto_backup"):
        return None

    hc = _load_health_config()
    running_cmd = _get_vendor_command(
        hc, "running_config_command", dev["device_type"], "running_config_command")
    conn = connect(dev)
    try:
        output = conn.send_command(running_cmd, read_timeout=config["read_timeout_long"])
    finally:
        conn.disconnect()

    filepath = save_artifact("backups", device_name, output, suffix="pre_change", ext=".cfg")
    log_operation(device_name, "auto_backup", f"file={filepath}")
    print(f"[AUTO-BACKUP] {device_name}: saved to {filepath}")
    return filepath


def _check_lockout(commands: list[str], device_type: str) -> None:
    """Block config commands that would cause SSH self-lockout.

    Raises ConfigError if a dangerous pattern is detected.
    """
    # Check management interface + dangerous sub-command combination
    mgmt_pattern_str = _LOCKOUT_MGMT_INTERFACE.get(device_type)
    if mgmt_pattern_str:
        mgmt_re = re.compile(mgmt_pattern_str, re.IGNORECASE)
        in_mgmt_block = False
        for cmd in commands:
            stripped = cmd.strip()
            # Junos 'delete interfaces ...' is standalone (not a block)
            if device_type == "juniper_junos" and mgmt_re.search(stripped):
                raise ConfigError(
                    f"[LOCKOUT BLOCKED] '{stripped}' — "
                    "deleting management interface would cut SSH access"
                )
            if re.match(r"^interface\s+", stripped, re.IGNORECASE):
                in_mgmt_block = bool(mgmt_re.search(stripped))
            elif in_mgmt_block and _LOCKOUT_DANGEROUS_SUB.match(stripped):
                raise ConfigError(
                    f"[LOCKOUT BLOCKED] '{stripped}' on management interface — "
                    "this would cut SSH access to the device"
                )

    # Check standalone dangerous commands
    for pattern, desc in _LOCKOUT_STANDALONE.get(device_type, []):
        for cmd in commands:
            if pattern.search(cmd.strip()):
                raise ConfigError(
                    f"[LOCKOUT BLOCKED] '{cmd.strip()}' — {desc}"
                )


def cmd_config(args):
    """Apply configuration commands."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    commands = _validate_json_commands(args.commands)

    # Safety gate 1: self-lockout detection
    _check_lockout(commands, dev["device_type"])

    # Safety gate 2: compliance check (skip with --skip-compliance)
    if not getattr(args, "skip_compliance", False):
        violations = _pre_apply_compliance(commands)
        if violations:
            for v in violations:
                print(f"[COMPLIANCE FAIL] {v['rule']} ({v['severity']}): {v['detail']}",
                      file=sys.stderr)
            raise ConfigError(
                f"config blocked: {len(violations)} compliance violation(s). "
                "Use --skip-compliance to override (logged)."
            )
    else:
        log_operation(args.device, "config", "compliance check skipped by --skip-compliance")

    # Safety gate 3: auto-backup
    if not getattr(args, "no_backup", False):
        _auto_backup(args.device, dev)

    conn = connect(dev)
    try:
        commit = needs_commit(dev)
        output = conn.send_config_set(commands, exit_config_mode=not commit)
        print(output)

        if commit:
            print("--- Committing ---")
            print(conn.commit())
            conn.exit_config_mode()
    finally:
        conn.disconnect()

    log_operation(args.device, "config", "; ".join(commands))
    print(f"\n[OK] Configuration applied to {args.device}")


# ---------------------------------------------------------------------------
# Subcommand: deploy
# ---------------------------------------------------------------------------


def cmd_deploy(args):
    """Deploy configuration from file."""
    inv = load_inventory()
    dev = get_device(inv, args.device)

    config_file = Path(args.file)
    if not config_file.exists():
        raise ConfigError(f"config file '{args.file}' not found")

    # Read file to run safety checks
    file_commands = [
        line.strip() for line in config_file.read_text().splitlines()
        if line.strip() and not line.strip().startswith("!")
    ]

    # Safety gate 1: self-lockout detection
    _check_lockout(file_commands, dev["device_type"])

    # Safety gate 2: compliance check
    if not getattr(args, "skip_compliance", False):
        violations = _pre_apply_compliance(file_commands)
        if violations:
            for v in violations:
                print(f"[COMPLIANCE FAIL] {v['rule']} ({v['severity']}): {v['detail']}",
                      file=sys.stderr)
            raise ConfigError(
                f"deploy blocked: {len(violations)} compliance violation(s). "
                "Use --skip-compliance to override (logged)."
            )
    else:
        log_operation(args.device, "deploy", "compliance check skipped by --skip-compliance")

    # Safety gate 3: auto-backup
    if not getattr(args, "no_backup", False):
        _auto_backup(args.device, dev)

    conn = connect(dev)
    try:
        commit = needs_commit(dev)
        output = conn.send_config_from_file(str(config_file), exit_config_mode=not commit)
        print(output)

        if commit:
            print("--- Committing ---")
            print(conn.commit())
            conn.exit_config_mode()
    finally:
        conn.disconnect()

    log_operation(args.device, "deploy", f"file={args.file}")
    print(f"\n[OK] Configuration deployed to {args.device}")


# ---------------------------------------------------------------------------
# Subcommand: interact
# ---------------------------------------------------------------------------


def cmd_interact(args):
    """Execute interactive commands with expect patterns."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    commands = _validate_json_commands(args.commands)

    conn = connect(dev)
    try:
        output = conn.send_multiline(commands)
        print(output)
    finally:
        conn.disconnect()


# ---------------------------------------------------------------------------
# Subcommand: check
# ---------------------------------------------------------------------------


def _resolve_device_arg(args) -> str:
    """Resolve device from args supporting both positional and --all flag."""
    if getattr(args, "all_devices", False):
        return "--all"
    if args.device is None:
        return "--all"
    return args.device


def cmd_check(args):
    """Health check on device(s)."""
    inv = load_inventory()
    config = get_config()
    targets = resolve_targets(inv, _resolve_device_arg(args))
    hc = _load_health_config()
    fallback = hc.get("fallback", {}).get("health_commands", ["show ip interface brief"])

    for name, dev in targets:
        print(f"\n{'=' * DISPLAY_WIDTH}")
        print(f"Health Check: {name} ({dev['host']})")
        print(f"{'=' * DISPLAY_WIDTH}")

        commands = hc.get("health_commands", {}).get(dev["device_type"], fallback)

        try:
            conn = connect(dev)
            try:
                for cmd in commands:
                    print(f"\n--- {cmd} ---")
                    try:
                        print(conn.send_command(cmd, read_timeout=config["read_timeout"]))
                    except Exception as e:
                        print(f"[WARN] {cmd}: {e}")
            finally:
                conn.disconnect()
            print(f"\n[OK] {name}: health check complete")
        except ClanetError as e:
            print(f"\n[FAIL] {name}: {e}")
        except Exception as e:
            print(f"\n[FAIL] {name}: unexpected error — {e}")


# ---------------------------------------------------------------------------
# Subcommand: backup
# ---------------------------------------------------------------------------


def cmd_backup(args):
    """Backup running configuration."""
    inv = load_inventory()
    config = get_config()
    hc = _load_health_config()
    targets = resolve_targets(inv, _resolve_device_arg(args))

    for name, dev in targets:
        try:
            running_cmd = _get_vendor_command(
                hc, "running_config_command", dev["device_type"], "running_config_command")
            conn = connect(dev)
            try:
                output = conn.send_command(running_cmd,
                                           read_timeout=config["read_timeout_long"])
            finally:
                conn.disconnect()

            filepath = save_artifact("backups", name, output, ext=".cfg")
            log_operation(name, "backup", f"file={filepath}")
            print(f"[OK] {name}: backup saved to {filepath}")
        except ClanetError as e:
            print(f"[FAIL] {name}: {e}")
        except Exception as e:
            print(f"[FAIL] {name}: unexpected error — {e}")


# ---------------------------------------------------------------------------
# Subcommand: session
# ---------------------------------------------------------------------------


def cmd_session(args):
    """Check connectivity and session status."""
    inv = load_inventory()
    config = get_config()
    targets = resolve_targets(inv, _resolve_device_arg(args))

    for name, dev in targets:
        host = dev["host"]
        port = dev.get("port", DEFAULT_SSH_PORT)

        # TCP port check
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(config["connect_timeout"])
                result = s.connect_ex((host, port))

            if result == 0:
                print(f"[OK] {name} ({host}:{port}) - SSH port open")
            else:
                print(f"[FAIL] {name} ({host}:{port}) - SSH port closed")
                continue
        except Exception as e:
            print(f"[FAIL] {name} ({host}:{port}) - {e}")
            continue

        # Netmiko connection test (if action requires it)
        if args.action in ("prompt", "alive"):
            time.sleep(config["session_test_delay"])
            try:
                conn = connect(dev)
                if args.action == "prompt":
                    print(f"  Prompt: {conn.find_prompt()}")
                elif args.action == "alive":
                    print(f"  Alive: {conn.is_alive()}")
                conn.disconnect()
            except Exception as e:
                print(f"  [WARN] Connection test failed: {e}")


# ---------------------------------------------------------------------------
# Subcommand: mode
# ---------------------------------------------------------------------------


def cmd_mode(args):
    """Mode switching."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    action = args.action

    conn = connect(dev)
    try:
        if action == "enable":
            conn.enable()
            print(f"[OK] {args.device}: enable mode")
            print(f"Prompt: {conn.find_prompt()}")
        elif action == "config":
            conn.config_mode()
            print(f"[OK] {args.device}: config mode")
            print(f"Prompt: {conn.find_prompt()}")
        elif action == "exit-config":
            conn.exit_config_mode()
            print(f"[OK] {args.device}: exited config mode")
            print(f"Prompt: {conn.find_prompt()}")
        elif action == "check":
            print(f"Enable mode: {conn.check_enable_mode()}")
            print(f"Config mode: {conn.check_config_mode()}")
            print(f"Prompt: {conn.find_prompt()}")
        else:
            raise ClanetError(
                f"unknown action '{action}' (valid: enable, config, exit-config, check)"
            )
    finally:
        conn.disconnect()


# ---------------------------------------------------------------------------
# Subcommand: save
# ---------------------------------------------------------------------------


def cmd_save(args):
    """Save running config to startup."""
    inv = load_inventory()
    targets = resolve_targets(inv, _resolve_device_arg(args))

    for name, dev in targets:
        if needs_commit(dev):
            print(f"[SKIP] {name}: commit-based platform ({dev['device_type']})"
                  " - config is auto-saved on commit. Use /clanet:commit instead.")
            continue

        try:
            conn = connect(dev)
            try:
                output = conn.save_config()
            finally:
                conn.disconnect()
            log_operation(name, "save")
            print(f"[OK] {name}: config saved")
            print(output)
        except ClanetError as e:
            print(f"[FAIL] {name}: {e}")
        except Exception as e:
            print(f"[FAIL] {name}: unexpected error — {e}")


# ---------------------------------------------------------------------------
# Subcommand: commit
# ---------------------------------------------------------------------------


def cmd_commit(args):
    """Commit configuration changes."""
    inv = load_inventory()
    targets = resolve_targets(inv, _resolve_device_arg(args))

    for name, dev in targets:
        if not needs_commit(dev):
            print(f"[SKIP] {name}: {dev['device_type']} does not use commit."
                  " Use /clanet:save instead.")
            continue

        try:
            conn = connect(dev)
            try:
                output = conn.commit()
            finally:
                conn.disconnect()
            log_operation(name, "commit")
            print(f"[OK] {name}: committed")
            print(output)
        except ClanetError as e:
            print(f"[FAIL] {name}: {e}")
        except Exception as e:
            print(f"[FAIL] {name}: unexpected error — {e}")


# ---------------------------------------------------------------------------
# Subcommand: snapshot
# ---------------------------------------------------------------------------


def cmd_snapshot(args):
    """Capture device state snapshot (pre or post change)."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    config = get_config()
    phase = args.phase  # "pre" or "post"

    hc = _load_health_config()
    fallback = hc.get("fallback", {}).get(
        "snapshot_commands", ["show ip interface brief", "show running-config"]
    )
    commands = hc.get("snapshot_commands", {}).get(dev["device_type"], fallback)

    conn = connect(dev)
    snapshot = {}
    try:
        for cmd in commands:
            print(f"--- {cmd} ---")
            try:
                output = conn.send_command(cmd, read_timeout=config["read_timeout_long"])
                redacted = _redact_sensitive(output)
                snapshot[cmd] = redacted
                print(redacted)
            except Exception as e:
                snapshot[cmd] = f"error: {e}"
                print(f"[WARN] {e}")
            print()
    finally:
        conn.disconnect()

    filepath = save_artifact("snapshots", args.device, json.dumps(snapshot, indent=2),
                             suffix=phase, ext=".json")
    print(f"\n[OK] Snapshot saved: {filepath}")


# ---------------------------------------------------------------------------
# Subcommand: audit
# ---------------------------------------------------------------------------


def _parse_policy_rules(policy: dict) -> list[dict]:
    """Parse policy YAML into a flat list of rules from all categories."""
    rules_section = policy.get("rules", {})
    flat = []
    for category, rule_list in rules_section.items():
        if not isinstance(rule_list, list):
            continue
        for rule in rule_list:
            rule = dict(rule)  # shallow copy
            rule["_category"] = category
            flat.append(rule)
    return flat


def _filter_rules_by_profile(rules: list[dict], profile: str) -> list[dict]:
    """Filter rules by audit profile.

    - basic: standards only
    - security: security + standards
    - full: all categories
    """
    if profile == "full":
        return rules
    if profile == "security":
        allowed = {"security", "standards"}
    else:  # basic
        allowed = {"standards"}
    return [r for r in rules if r.get("_category") in allowed]


def _safe_regex(pattern: str, text: str, flags: int = 0):
    """Compile and search regex, raising ConfigError on invalid pattern."""
    try:
        return re.search(pattern, text, flags)
    except re.error as e:
        raise ConfigError(f"invalid regex in policy rule: '{pattern}' — {e}")


def _safe_finditer(pattern: str, text: str, flags: int = 0):
    """Compile and finditer regex, raising ConfigError on invalid pattern."""
    try:
        return list(re.finditer(pattern, text, flags))
    except re.error as e:
        raise ConfigError(f"invalid regex in policy rule: '{pattern}' — {e}")


def _evaluate_rule(rule: dict, running_config: str) -> tuple[str, str]:
    """Evaluate a single policy rule against running-config.

    Returns (status, detail) where status is PASS/FAIL/WARN/SKIP.
    """
    # scope: config_commands / interface_config → SKIP during audit
    scope = rule.get("scope")
    if scope in ("config_commands", "interface_config"):
        return "SKIP", f"scope={scope} (evaluated during config changes)"

    # recommend: advisory check → WARN if not found
    recommend = rule.get("recommend")
    if recommend and not scope:
        if _safe_regex(recommend, running_config):
            return "PASS", f"recommend pattern '{recommend}' found"
        return "WARN", f"recommend pattern '{recommend}' not found"

    # pattern_deny + pattern_allow
    pattern_deny = rule.get("pattern_deny")
    if pattern_deny:
        pattern_allow = rule.get("pattern_allow")
        deny_matches = _safe_finditer(pattern_deny, running_config, re.MULTILINE)
        if deny_matches:
            # Check if all deny matches are covered by allow exceptions
            violations = []
            for m in deny_matches:
                matched_line = m.group(0)
                if pattern_allow and _safe_regex(pattern_allow, matched_line):
                    continue  # allowed exception
                violations.append(matched_line.strip())
            if violations:
                return "FAIL", f"deny pattern matched: {violations[0]}"
            return "PASS", "deny pattern matched but covered by allow exceptions"
        return "PASS", "no deny pattern matches"

    # require_in_running: pattern must exist in running-config
    require_in_running = rule.get("require_in_running")
    if require_in_running:
        if _safe_regex(require_in_running, running_config):
            return "PASS", f"pattern '{require_in_running}' found"
        return "FAIL", f"pattern '{require_in_running}' not found in running-config"

    # require + require_on: section-scoped check
    require = rule.get("require")
    require_on = rule.get("require_on")
    if require and require_on:
        # Extract section starting with require_on
        section_pattern = rf"^{require_on}.*?(?=^\S|\Z)"
        section_match = _safe_regex(section_pattern, running_config, re.MULTILINE | re.DOTALL)
        if section_match:
            section_text = section_match.group(0)
            if _safe_regex(require, section_text):
                return "PASS", f"'{require}' found in '{require_on}' section"
            return "FAIL", f"'{require}' not found in '{require_on}' section"
        return "FAIL", f"section '{require_on}' not found in running-config"

    # require (global, without require_on)
    if require:
        if _safe_regex(require, running_config):
            return "PASS", f"pattern '{require}' found"
        return "FAIL", f"pattern '{require}' not found in running-config"

    return "SKIP", "no evaluation criteria defined"


def _evaluate_rule_for_commands(rule: dict, commands_text: str) -> tuple[str, str]:
    """Evaluate a scope:config_commands rule against proposed config commands.

    Returns (status, detail) where status is PASS/FAIL/WARN/SKIP.
    Only evaluates pattern_deny rules with scope=config_commands.
    """
    scope = rule.get("scope")
    if scope != "config_commands":
        return "SKIP", "not a config_commands rule"

    pattern_deny = rule.get("pattern_deny")
    if not pattern_deny:
        return "SKIP", "no pattern_deny defined"

    pattern_allow = rule.get("pattern_allow")
    deny_matches = _safe_finditer(pattern_deny, commands_text, re.MULTILINE | re.IGNORECASE)
    if deny_matches:
        violations = []
        for m in deny_matches:
            matched_line = m.group(0)
            if pattern_allow and _safe_regex(pattern_allow, matched_line):
                continue
            violations.append(matched_line.strip())
        if violations:
            return "FAIL", f"policy violation: {violations[0]}"
        return "PASS", "denied pattern matched but covered by allow exceptions"
    return "PASS", "no policy violations"


def _pre_apply_compliance(commands: list[str]) -> list[dict]:
    """Run compliance check on proposed config commands before applying.

    Returns list of violations (empty = all clear).
    Loads policy from .clanet.yaml or default path.
    """
    config = get_config()
    policy_path = config.get("policy_file") or DEFAULT_POLICY_PATH
    try:
        with open(policy_path) as f:
            policy = yaml.safe_load(f)
    except FileNotFoundError:
        return []  # No policy file = no violations
    if not isinstance(policy, dict):
        return []

    rules_section = policy.get("rules", {})
    commands_text = "\n".join(commands)
    violations = []

    for _category, rule_list in rules_section.items():
        if not isinstance(rule_list, list):
            continue
        for rule in rule_list:
            if not isinstance(rule, dict):
                continue
            if rule.get("scope") != "config_commands":
                continue
            status, detail = _evaluate_rule_for_commands(rule, commands_text)
            if status == "FAIL":
                violations.append({
                    "rule": rule.get("name", "unnamed"),
                    "severity": rule.get("severity", "high"),
                    "detail": detail,
                })
    return violations


def _load_policy(args) -> dict | None:
    """Load compliance policy from --policy flag, .clanet.yaml, or default."""
    # 1. --policy flag
    policy_path = getattr(args, "policy", None)
    # 2. policy_file from .clanet.yaml
    if not policy_path:
        config = get_config()
        policy_path = config.get("policy_file")
    # 3. Default
    if not policy_path:
        policy_path = DEFAULT_POLICY_PATH

    try:
        with open(policy_path) as f:
            policy = yaml.safe_load(f)
        if not isinstance(policy, dict):
            raise ConfigError(
                f"invalid policy format in {policy_path}: must be a YAML mapping"
            )
        print(f"Policy: {policy_path}")
        return policy
    except FileNotFoundError:
        print(f"WARN: policy file not found: {policy_path}", file=sys.stderr)
        return None


def cmd_audit(args):
    """Compliance audit."""
    inv = load_inventory()
    targets = resolve_targets(inv, _resolve_device_arg(args))

    config = get_config()
    hc = _load_health_config()
    profile = args.profile or config.get("default_profile", "basic")

    # Load policy (required — all rules come from external YAML)
    policy = _load_policy(args)
    if not policy:
        raise ConfigError(
            "No policy file found. Audit requires a policy YAML."
            " (create one: cp templates/policy.yaml my-policy.yaml"
            " or specify: --policy path/to/policy.yaml)"
        )

    policy_name = policy.get("policy", {}).get("name", "unknown")
    print(f"Policy name: {policy_name}")
    policy_rules = _parse_policy_rules(policy)
    if not policy_rules:
        raise ConfigError("Policy file contains no rules.")

    for name, dev in targets:
        print(f"\n{'=' * DISPLAY_WIDTH}")
        print(f"Audit: {name} ({dev['host']}) - profile: {profile}")
        print(f"{'=' * DISPLAY_WIDTH}")

        try:
            running_cmd = _get_vendor_command(
                hc, "running_config_command", dev["device_type"], "running_config_command")
            conn = connect(dev)
            running = conn.send_command(running_cmd,
                                       read_timeout=config["read_timeout_long"])
            conn.disconnect()
        except Exception as e:
            print(f"[FAIL] {name}: cannot connect - {e}")
            continue

        results = []  # list of (check_name, status, severity, detail)
        pass_count = 0

        filtered = _filter_rules_by_profile(policy_rules, profile)
        for rule in filtered:
            status, detail = _evaluate_rule(rule, running)
            severity = rule.get("severity", "MEDIUM")
            results.append((rule.get("name", rule.get("id", "?")), status, severity, detail))
            if status == "PASS":
                pass_count += 1

        total = len(results)
        score = int((pass_count / total) * 100) if total > 0 else 0

        print("\n| # | Check | Severity | Status |")
        print("|---|-------|----------|--------|")
        for i, (check_name, status, severity, _detail) in enumerate(results, 1):
            if status == "PASS":
                marker = "[OK]"
            elif status == "FAIL":
                marker = "[FAIL]"
            elif status == "WARN":
                marker = "[WARN]"
            else:
                marker = "[SKIP]"
            print(f"| {i} | {check_name} | {severity} | {marker} |")
        print(f"\nScore: {score}% ({pass_count}/{total} passed)")

        # Save audit report
        report_lines = [f"# Audit Report: {name}", f"Date: {datetime.now().strftime(TS_LOG)}",
                        f"Profile: {profile}", f"Score: {score}%", ""]
        for check_name, status, severity, detail in results:
            line = f"- [{status}] {check_name} (severity: {severity})"
            if detail:
                line += f" — {detail}"
            report_lines.append(line)
        filepath = save_artifact("audit", name, "\n".join(report_lines), ext=".md")
        print(f"Report saved: {filepath}")


# ---------------------------------------------------------------------------
# Subcommand: device-info (for agent use)
# ---------------------------------------------------------------------------


def cmd_device_info(args):
    """Print device metadata as JSON (for agent coordination)."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    info = {
        "device_type": dev["device_type"],
        "host": dev["host"],
        "port": dev.get("port", DEFAULT_SSH_PORT),
        "needs_commit": needs_commit(dev),
    }
    print(json.dumps(info, indent=2))


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------


def cmd_list(args):
    """List all devices in inventory."""
    inv = load_inventory()
    devices = inv.get("devices", {})
    print(f"{'Name':<20} {'Host':<18} {'Type':<18} {'Port':<6}")
    print("-" * DISPLAY_WIDTH)
    for name, dev in sorted(devices.items()):
        print(f"{name:<20} {dev['host']:<18} {dev['device_type']:<18} {dev.get('port', 22):<6}")


# ---------------------------------------------------------------------------
# Subcommand: context
# ---------------------------------------------------------------------------


def cmd_context(args):
    """Display loaded operation context."""
    ctx = _load_context()
    if ctx is None:
        print("No context file found.")
        print("Create one: cp templates/context.yaml context.yaml")
        return

    for key in ("topology", "symptoms", "constraints", "success_criteria"):
        value = ctx.get(key)
        if value is None:
            continue
        print(f"--- {key} ---")
        if isinstance(value, list):
            for item in value:
                print(f"  - {item}")
        else:
            print(f"  {value.rstrip()}")
        print()


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clanet_cli",
        description="clanet - Network automation CLI engine",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # info
    p = sub.add_parser("info", help="Show device info (show version)")
    p.add_argument("device")
    p.set_defaults(func=cmd_info)

    # show
    p = sub.add_parser("show", help="Execute a show/operational command")
    p.add_argument("device")
    p.add_argument("command", nargs="+", help="Command to execute")
    p.set_defaults(func=cmd_show)

    # config
    p = sub.add_parser("config", help="Apply configuration commands")
    p.add_argument("device")
    p.add_argument("--commands", required=True, help="JSON array of config commands")
    p.add_argument("--skip-compliance", dest="skip_compliance", action="store_true",
                   help="Skip pre-apply compliance check (logged)")
    p.add_argument("--no-backup", dest="no_backup", action="store_true",
                   help="Skip auto-backup before config change")
    p.set_defaults(func=cmd_config)

    # deploy
    p = sub.add_parser("deploy", help="Deploy configuration from file")
    p.add_argument("device")
    p.add_argument("file", help="Config file path")
    p.add_argument("--skip-compliance", dest="skip_compliance", action="store_true",
                   help="Skip pre-apply compliance check (logged)")
    p.add_argument("--no-backup", dest="no_backup", action="store_true",
                   help="Skip auto-backup before config change")
    p.set_defaults(func=cmd_deploy)

    # interact
    p = sub.add_parser("interact", help="Execute interactive commands")
    p.add_argument("device")
    p.add_argument("--commands", required=True, help="JSON array of interactive commands")
    p.set_defaults(func=cmd_interact)

    # check
    p = sub.add_parser("check", help="Health check")
    p.add_argument("device", nargs="?", default=None, help="Device name")
    p.add_argument("--all", dest="all_devices", action="store_true", help="All devices")
    p.set_defaults(func=cmd_check)

    # backup
    p = sub.add_parser("backup", help="Backup running config")
    p.add_argument("device", nargs="?", default=None, help="Device name")
    p.add_argument("--all", dest="all_devices", action="store_true", help="All devices")
    p.set_defaults(func=cmd_backup)

    # session
    p = sub.add_parser("session", help="Check connectivity")
    p.add_argument("device", nargs="?", default=None, help="Device name")
    p.add_argument("--all", dest="all_devices", action="store_true", help="All devices")
    p.add_argument("action", nargs="?", default="status",
                   choices=["status", "prompt", "alive"])
    p.set_defaults(func=cmd_session)

    # mode
    p = sub.add_parser("mode", help="Mode switching")
    p.add_argument("device")
    p.add_argument("action", choices=["enable", "config", "exit-config", "check"])
    p.set_defaults(func=cmd_mode)

    # save
    p = sub.add_parser("save", help="Save running config to startup")
    p.add_argument("device", nargs="?", default=None, help="Device name")
    p.add_argument("--all", dest="all_devices", action="store_true", help="All devices")
    p.set_defaults(func=cmd_save)

    # commit
    p = sub.add_parser("commit", help="Commit configuration changes")
    p.add_argument("device", nargs="?", default=None, help="Device name")
    p.add_argument("--all", dest="all_devices", action="store_true", help="All devices")
    p.set_defaults(func=cmd_commit)

    # snapshot
    p = sub.add_parser("snapshot", help="Capture state snapshot")
    p.add_argument("device")
    p.add_argument("--phase", default="pre", choices=["pre", "post"],
                   help="Snapshot phase (pre or post change)")
    p.set_defaults(func=cmd_snapshot)

    # audit
    p = sub.add_parser("audit", help="Compliance audit")
    p.add_argument("device", nargs="?", default=None, help="Device name")
    p.add_argument("--all", dest="all_devices", action="store_true", help="All devices")
    p.add_argument("--profile", choices=["basic", "security", "full"], default=None)
    p.add_argument("--policy", default=None, help="Path to custom policy YAML file")
    p.set_defaults(func=cmd_audit)

    # device-info (for agent use)
    p = sub.add_parser("device-info", help="Print device metadata as JSON")
    p.add_argument("device")
    p.set_defaults(func=cmd_device_info)

    # list
    p = sub.add_parser("list", help="List all devices in inventory")
    p.set_defaults(func=cmd_list)

    # context
    p = sub.add_parser("context", help="Display loaded operation context")
    p.set_defaults(func=cmd_context)

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except ClanetError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
