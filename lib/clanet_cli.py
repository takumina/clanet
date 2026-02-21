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
import yaml
from datetime import datetime
from pathlib import Path

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
}

COMMIT_PLATFORMS = {"cisco_xr", "juniper_junos"}

# Standard output directory structure
DIRS = {
    "logs": "logs",
    "backups": "backups",
    "snapshots": "snapshots",
    "audit": "audit",
}

# Standard timestamp formats
TS_LOG = "%Y-%m-%d %H:%M:%S"
TS_FILE = "%Y%m%d_%H%M%S"

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

    Search order: health_file in .clanet.yaml → policies/health.yaml.
    Returns dict with keys: health_commands, snapshot_commands, fallback.
    """
    config = get_config()
    health_path = config.get("health_file")
    if not health_path:
        health_path = "policies/health.yaml"

    try:
        with open(health_path) as f:
            data = yaml.safe_load(f) or {}
        return data
    except FileNotFoundError:
        print(f"ERROR: health config not found: {health_path}", file=sys.stderr)
        print("  Create one: cp policies/health.yaml policies/my-health.yaml", file=sys.stderr)
        print("  Or specify: health_file in .clanet.yaml", file=sys.stderr)
        sys.exit(1)


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
            if inv and "devices" in inv:
                for dev in inv["devices"].values():
                    for field in ("password", "username"):
                        if field in dev and isinstance(dev[field], str):
                            dev[field] = _expand_env_vars(dev[field])
                return inv
        except FileNotFoundError:
            continue
    print("ERROR: inventory.yaml not found", file=sys.stderr)
    print("Searched:", ", ".join(paths), file=sys.stderr)
    sys.exit(1)


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

    print(f"ERROR: device '{name}' not found in inventory", file=sys.stderr)
    available = ", ".join(sorted(devices.keys()))
    print(f"Available devices: {available}", file=sys.stderr)
    sys.exit(1)


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
        print("ERROR: Netmiko is not installed. Run: pip install netmiko", file=sys.stderr)
        sys.exit(1)

    required = ["device_type", "host", "username", "password"]
    missing = [f for f in required if f not in dev]
    if missing:
        print(f"ERROR: device config missing required fields: {', '.join(missing)}",
              file=sys.stderr)
        sys.exit(1)

    return ConnectHandler(
        device_type=dev["device_type"],
        host=dev["host"],
        username=dev["username"],
        password=dev["password"],
        port=dev.get("port", 22),
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
        entry += f" DETAIL={detail}"
    with open(log_dir / "clanet_operations.log", "a") as f:
        f.write(entry + "\n")


def save_artifact(dir_type: str, device: str, content: str, suffix: str = "",
                  ext: str = ".txt") -> str:
    """Save a timestamped artifact file. Returns the file path."""
    out_dir = ensure_dir(dir_type)
    ts = datetime.now().strftime(TS_FILE)
    suffix_str = f"_{suffix}" if suffix else ""
    filename = f"{device}{suffix_str}_{ts}{ext}"
    filepath = out_dir / filename
    with open(filepath, "w") as f:
        f.write(content)
    return str(filepath)


# ---------------------------------------------------------------------------
# Subcommand: info
# ---------------------------------------------------------------------------


def cmd_info(args):
    """Show device info (show version)."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    conn = connect(dev)
    try:
        output = conn.send_command("show version", read_timeout=30)
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
    command = " ".join(args.command)
    conn = connect(dev)
    try:
        output = conn.send_command(command, read_timeout=30)
        print(output)
    finally:
        conn.disconnect()


# ---------------------------------------------------------------------------
# Subcommand: config
# ---------------------------------------------------------------------------


def cmd_config(args):
    """Apply configuration commands."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
    commands = json.loads(args.commands)

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
        print(f"ERROR: config file '{args.file}' not found", file=sys.stderr)
        sys.exit(1)

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
    commands = json.loads(args.commands)

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
    targets = resolve_targets(inv, _resolve_device_arg(args))
    hc = _load_health_config()
    fallback = hc.get("fallback", {}).get("health_commands", ["show ip interface brief"])

    for name, dev in targets:
        print(f"\n{'='*60}")
        print(f"Health Check: {name} ({dev['host']})")
        print(f"{'='*60}")

        commands = hc.get("health_commands", {}).get(dev["device_type"], fallback)

        try:
            conn = connect(dev)
            for cmd in commands:
                print(f"\n--- {cmd} ---")
                try:
                    print(conn.send_command(cmd, read_timeout=30))
                except Exception as e:
                    print(f"[WARN] {e}")
            conn.disconnect()
            print(f"\n[OK] {name} health check complete")
        except Exception as e:
            print(f"\n[FAIL] {name}: {e}")


# ---------------------------------------------------------------------------
# Subcommand: backup
# ---------------------------------------------------------------------------


def cmd_backup(args):
    """Backup running configuration."""
    inv = load_inventory()
    targets = resolve_targets(inv, _resolve_device_arg(args))

    for name, dev in targets:
        try:
            conn = connect(dev)
            output = conn.send_command("show running-config", read_timeout=60)
            conn.disconnect()

            filepath = save_artifact("backups", name, output, ext=".cfg")
            log_operation(name, "backup", f"file={filepath}")
            print(f"[OK] {name} → {filepath}")
        except Exception as e:
            print(f"[FAIL] {name}: {e}")


# ---------------------------------------------------------------------------
# Subcommand: session
# ---------------------------------------------------------------------------


def cmd_session(args):
    """Check connectivity and session status."""
    inv = load_inventory()
    targets = resolve_targets(inv, _resolve_device_arg(args))

    for name, dev in targets:
        host = dev["host"]
        port = dev.get("port", 22)

        # TCP port check
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((host, port))
            s.close()

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
            time.sleep(1)
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
            print(f"ERROR: unknown action '{action}'", file=sys.stderr)
            print("Valid actions: enable, config, exit-config, check", file=sys.stderr)
            sys.exit(1)
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
            output = conn.save_config()
            conn.disconnect()
            log_operation(name, "save")
            print(f"[OK] {name}: config saved")
            print(output)
        except Exception as e:
            print(f"[FAIL] {name}: {e}")


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
            output = conn.commit()
            conn.disconnect()
            log_operation(name, "commit")
            print(f"[OK] {name}: committed")
            print(output)
        except Exception as e:
            print(f"[FAIL] {name}: {e}")


# ---------------------------------------------------------------------------
# Subcommand: snapshot
# ---------------------------------------------------------------------------


def cmd_snapshot(args):
    """Capture device state snapshot (pre or post change)."""
    inv = load_inventory()
    dev = get_device(inv, args.device)
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
                output = conn.send_command(cmd, read_timeout=60)
                snapshot[cmd] = output
                print(output)
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
        if re.search(recommend, running_config):
            return "PASS", f"recommend pattern '{recommend}' found"
        return "WARN", f"recommend pattern '{recommend}' not found"

    # pattern_deny + pattern_allow
    pattern_deny = rule.get("pattern_deny")
    if pattern_deny:
        pattern_allow = rule.get("pattern_allow")
        deny_matches = list(re.finditer(pattern_deny, running_config, re.MULTILINE))
        if deny_matches:
            # Check if all deny matches are covered by allow exceptions
            violations = []
            for m in deny_matches:
                matched_line = m.group(0)
                if pattern_allow and re.search(pattern_allow, matched_line):
                    continue  # allowed exception
                violations.append(matched_line.strip())
            if violations:
                return "FAIL", f"deny pattern matched: {violations[0]}"
            return "PASS", "deny pattern matched but covered by allow exceptions"
        return "PASS", "no deny pattern matches"

    # require_in_running: pattern must exist in running-config
    require_in_running = rule.get("require_in_running")
    if require_in_running:
        if re.search(require_in_running, running_config):
            return "PASS", f"pattern '{require_in_running}' found"
        return "FAIL", f"pattern '{require_in_running}' not found in running-config"

    # require + require_on: section-scoped check
    require = rule.get("require")
    require_on = rule.get("require_on")
    if require and require_on:
        # Extract section starting with require_on
        section_pattern = rf"^{require_on}.*?(?=^\S|\Z)"
        section_match = re.search(section_pattern, running_config, re.MULTILINE | re.DOTALL)
        if section_match:
            section_text = section_match.group(0)
            if re.search(require, section_text):
                return "PASS", f"'{require}' found in '{require_on}' section"
            return "FAIL", f"'{require}' not found in '{require_on}' section"
        return "FAIL", f"section '{require_on}' not found in running-config"

    # require (global, without require_on)
    if require:
        if re.search(require, running_config):
            return "PASS", f"pattern '{require}' found"
        return "FAIL", f"pattern '{require}' not found in running-config"

    return "SKIP", "no evaluation criteria defined"


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
        policy_path = "policies/example.yaml"

    try:
        with open(policy_path) as f:
            policy = yaml.safe_load(f)
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
    profile = args.profile or config.get("default_profile", "basic")

    # Load policy (required — all rules come from external YAML)
    policy = _load_policy(args)
    if not policy:
        print("ERROR: No policy file found. Audit requires a policy YAML.", file=sys.stderr)
        print("  Create one: cp policies/example.yaml policies/my-policy.yaml", file=sys.stderr)
        print("  Or specify: --policy path/to/policy.yaml", file=sys.stderr)
        sys.exit(1)

    policy_name = policy.get("policy", {}).get("name", "unknown")
    print(f"Policy name: {policy_name}")
    policy_rules = _parse_policy_rules(policy)
    if not policy_rules:
        print("ERROR: Policy file contains no rules.", file=sys.stderr)
        sys.exit(1)

    for name, dev in targets:
        print(f"\n{'='*60}")
        print(f"Audit: {name} ({dev['host']}) - profile: {profile}")
        print(f"{'='*60}")

        try:
            conn = connect(dev)
            running = conn.send_command("show running-config", read_timeout=60)
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

        print(f"\n| # | Check | Severity | Status |")
        print(f"|---|-------|----------|--------|")
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
        "port": dev.get("port", 22),
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
    print("-" * 62)
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
        print("Create one: cp context.example.yaml context.yaml")
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
    p.set_defaults(func=cmd_config)

    # deploy
    p = sub.add_parser("deploy", help="Deploy configuration from file")
    p.add_argument("device")
    p.add_argument("file", help="Config file path")
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
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
