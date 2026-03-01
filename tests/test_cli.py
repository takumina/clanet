"""Tests for clanet_cli.py - no network connection required.

Tests cover:
- Inventory loading and device resolution
- Argument parsing
- Vendor-specific command selection
- Commit platform detection
- Target resolution (device vs --all)
- Artifact path generation
- Operation logging
"""

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add lib/ to path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
import clanet_cli  # noqa: E402, I001


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_inventory(tmp_path):
    """Create a temporary inventory file."""
    inv = {
        "devices": {
            "router01": {
                "host": "192.168.1.1",
                "device_type": "cisco_ios",
                "username": "admin",
                "password": "admin",
                "port": 22,
            },
            "router02": {
                "host": "192.168.1.2",
                "device_type": "cisco_xr",
                "username": "admin",
                "password": "admin",
            },
            "switch01": {
                "host": "192.168.1.3",
                "device_type": "juniper_junos",
                "username": "admin",
                "password": "admin",
            },
        }
    }
    inv_file = tmp_path / "inventory.yaml"
    import yaml
    inv_file.write_text(yaml.dump(inv))
    return str(inv_file), inv


@pytest.fixture
def mock_inventory(sample_inventory, monkeypatch):
    """Patch INVENTORY_PATHS to use sample inventory."""
    inv_path, inv_data = sample_inventory
    monkeypatch.setattr(clanet_cli, "INVENTORY_PATHS", [inv_path])
    return inv_data


# ---------------------------------------------------------------------------
# Inventory & Device Resolution
# ---------------------------------------------------------------------------


class TestInventory:
    def test_load_inventory(self, mock_inventory):
        inv = clanet_cli.load_inventory()
        assert "devices" in inv
        assert "router01" in inv["devices"]
        assert "router02" in inv["devices"]

    def test_load_inventory_not_found(self, monkeypatch):
        monkeypatch.setattr(clanet_cli, "INVENTORY_PATHS", ["/nonexistent.yaml"])
        with pytest.raises(clanet_cli.InventoryNotFoundError):
            clanet_cli.load_inventory()

    def test_get_device_by_name(self, mock_inventory):
        inv = clanet_cli.load_inventory()
        dev = clanet_cli.get_device(inv, "router01")
        assert dev["host"] == "192.168.1.1"
        assert dev["device_type"] == "cisco_ios"

    def test_get_device_by_ip(self, mock_inventory):
        inv = clanet_cli.load_inventory()
        dev = clanet_cli.get_device(inv, "192.168.1.2")
        assert dev["device_type"] == "cisco_xr"

    def test_get_device_not_found(self, mock_inventory):
        inv = clanet_cli.load_inventory()
        with pytest.raises(clanet_cli.DeviceNotFoundError):
            clanet_cli.get_device(inv, "nonexistent")


# ---------------------------------------------------------------------------
# Target Resolution (device vs --all)
# ---------------------------------------------------------------------------


class TestResolveTargets:
    def test_single_device(self, mock_inventory):
        inv = clanet_cli.load_inventory()
        targets = clanet_cli.resolve_targets(inv, "router01")
        assert len(targets) == 1
        assert targets[0][0] == "router01"

    def test_all_devices(self, mock_inventory):
        inv = clanet_cli.load_inventory()
        targets = clanet_cli.resolve_targets(inv, "--all")
        assert len(targets) == 3
        # Should be sorted
        names = [t[0] for t in targets]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# Commit Platform Detection
# ---------------------------------------------------------------------------


class TestCommitPlatform:
    def test_cisco_xr_needs_commit(self):
        assert clanet_cli.needs_commit({"device_type": "cisco_xr"}) is True

    def test_juniper_needs_commit(self):
        assert clanet_cli.needs_commit({"device_type": "juniper_junos"}) is True

    def test_cisco_ios_no_commit(self):
        assert clanet_cli.needs_commit({"device_type": "cisco_ios"}) is False

    def test_arista_no_commit(self):
        assert clanet_cli.needs_commit({"device_type": "arista_eos"}) is False


# ---------------------------------------------------------------------------
# Vendor-Specific Command Selection
# ---------------------------------------------------------------------------


class TestHealthConfig:
    """Tests that templates/health.yaml is valid and has expected structure."""

    @pytest.fixture
    def health_config(self):
        import yaml
        health_path = Path(__file__).parent.parent / "templates" / "health.yaml"
        with open(health_path) as f:
            return yaml.safe_load(f)

    def test_health_commands_cisco_ios(self, health_config):
        cmds = health_config["health_commands"]["cisco_ios"]
        assert "show ip interface brief" in cmds
        assert "show ip bgp summary" in cmds

    def test_health_commands_cisco_xr(self, health_config):
        cmds = health_config["health_commands"]["cisco_xr"]
        assert "show ip interface brief" in cmds
        assert "show bgp summary" in cmds  # No "ip" prefix for XR

    def test_health_commands_juniper(self, health_config):
        cmds = health_config["health_commands"]["juniper_junos"]
        assert "show interfaces terse" in cmds  # Juniper-specific
        assert "show bgp summary" in cmds

    def test_snapshot_commands_include_running_config(self, health_config):
        for vendor, cmds in health_config["snapshot_commands"].items():
            has_config = any("config" in cmd or "configuration" in cmd for cmd in cmds)
            assert has_config, f"{vendor} snapshot missing running-config command"

    def test_load_health_config_success(self, monkeypatch):
        """_load_health_config() should load from templates/health.yaml."""
        monkeypatch.setattr(clanet_cli, "_config", {"health_file": None})
        monkeypatch.chdir(Path(__file__).parent.parent)
        hc = clanet_cli._load_health_config()
        assert "health_commands" in hc
        assert "snapshot_commands" in hc
        assert "cisco_ios" in hc["health_commands"]

    def test_load_health_config_not_found(self, monkeypatch):
        """_load_health_config() should raise ConfigError when health file is not found."""
        monkeypatch.setattr(clanet_cli, "_config", {"health_file": "/nonexistent/health.yaml"})
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli._load_health_config()

    def test_load_health_config_custom_path(self, tmp_path, monkeypatch):
        """_load_health_config() should respect health_file from config."""
        import yaml
        custom = {"health_commands": {"test_vendor": ["show test"]}}
        custom_file = tmp_path / "custom-health.yaml"
        custom_file.write_text(yaml.dump(custom))
        monkeypatch.setattr(clanet_cli, "_config", {"health_file": str(custom_file)})
        hc = clanet_cli._load_health_config()
        assert hc["health_commands"]["test_vendor"] == ["show test"]


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------


class TestArgParser:
    def setup_method(self):
        self.parser = clanet_cli.build_parser()

    def test_show_command(self):
        args = self.parser.parse_args(["show", "router01", "show", "ip", "route"])
        assert args.device == "router01"
        assert args.command == ["show", "ip", "route"]

    def test_show_batch_commands(self):
        args = self.parser.parse_args([
            "show", "router01", "--commands",
            '["show ip interface brief", "show ip route"]'
        ])
        assert args.device == "router01"
        assert args.commands == '["show ip interface brief", "show ip route"]'
        assert args.command == []

    def test_config_command(self):
        args = self.parser.parse_args([
            "config", "router01", "--commands", '["ntp server 10.0.0.1"]'
        ])
        assert args.device == "router01"
        assert args.commands == '["ntp server 10.0.0.1"]'

    def test_syntax_help_parser(self):
        args = self.parser.parse_args(["syntax-help", "router01", "clock timezone"])
        assert args.device == "router01"
        assert args.partial_command == "clock timezone"
        assert args.mode == "config"

    def test_syntax_help_parser_exec_mode(self):
        args = self.parser.parse_args([
            "syntax-help", "router01", "show ip", "--mode", "exec"
        ])
        assert args.device == "router01"
        assert args.partial_command == "show ip"
        assert args.mode == "exec"

    def test_syntax_help_parser_both_mode(self):
        args = self.parser.parse_args([
            "syntax-help", "router01", "clock timezone", "--mode", "both"
        ])
        assert args.device == "router01"
        assert args.partial_command == "clock timezone"
        assert args.mode == "both"

    def test_health_commands_parser(self):
        args = self.parser.parse_args(["health-commands", "router01"])
        assert args.device == "router01"

    def test_backup_single(self):
        args = self.parser.parse_args(["backup", "router01"])
        assert args.device == "router01"

    def test_snapshot_pre(self):
        args = self.parser.parse_args(["snapshot", "router01", "--phase", "pre"])
        assert args.phase == "pre"

    def test_snapshot_default_phase(self):
        args = self.parser.parse_args(["snapshot", "router01"])
        assert args.phase == "pre"

    def test_audit_with_profile(self):
        args = self.parser.parse_args(["audit", "--all", "--profile", "security"])
        assert args.all_devices is True
        assert args.profile == "security"

    def test_config_load_command(self):
        args = self.parser.parse_args(["config-load", "router01", "config.cfg"])
        assert args.device == "router01"
        assert args.file == "config.cfg"

    def test_list_command(self):
        args = self.parser.parse_args(["list"])
        assert args.command == "list"

    def test_device_info(self):
        args = self.parser.parse_args(["device-info", "router01"])
        assert args.device == "router01"


# ---------------------------------------------------------------------------
# _resolve_device_arg
# ---------------------------------------------------------------------------


class TestResolveDeviceArg:
    def setup_method(self):
        self.parser = clanet_cli.build_parser()

    def test_all_flag(self):
        args = self.parser.parse_args(["backup", "--all"])
        assert clanet_cli._resolve_device_arg(args) == "--all"

    def test_device_name(self):
        args = self.parser.parse_args(["backup", "router01"])
        assert clanet_cli._resolve_device_arg(args) == "router01"

    def test_no_args_defaults_to_all(self):
        args = self.parser.parse_args(["backup"])
        assert clanet_cli._resolve_device_arg(args) == "--all"


# ---------------------------------------------------------------------------
# Artifact Management
# ---------------------------------------------------------------------------


class TestArtifacts:
    def test_save_artifact(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
            "backups": str(tmp_path / "backups"),
            "snapshots": str(tmp_path / "snapshots"),
            "audit": str(tmp_path / "audit"),
        })
        filepath = clanet_cli.save_artifact("backups", "router01", "config content", ext=".cfg")
        assert Path(filepath).exists()
        assert "router01" in filepath
        assert filepath.endswith(".cfg")

    def test_save_artifact_with_suffix(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "snapshots": str(tmp_path / "snapshots"),
        })
        filepath = clanet_cli.save_artifact(
            "snapshots", "router01", "{}", suffix="pre", ext=".json"
        )
        assert "_pre_" in filepath

    def test_log_operation(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        clanet_cli.log_operation("router01", "config", "ntp server 10.0.0.1")
        log_file = tmp_path / "logs" / "clanet_operations.log"
        assert log_file.exists()
        content = log_file.read_text()
        assert "DEVICE=router01" in content
        assert "ACTION=config" in content
        assert "STATUS=SUCCESS" in content


# ---------------------------------------------------------------------------
# Default Policy File
# ---------------------------------------------------------------------------


class TestDefaultPolicyFile:
    """Tests that templates/policy.yaml is valid YAML with expected structure."""

    @pytest.fixture
    def default_policy(self):
        import yaml
        policy_path = Path(__file__).parent.parent / "templates" / "policy.yaml"
        with open(policy_path) as f:
            return yaml.safe_load(f)

    def test_policy_file_loads(self, default_policy):
        """example.yaml must be valid YAML with policy and rules sections."""
        assert "policy" in default_policy
        assert "rules" in default_policy

    def test_policy_has_expected_categories(self, default_policy):
        """example.yaml must define security, safety, standards, and semantic categories."""
        rules = default_policy["rules"]
        assert "security" in rules
        assert "safety" in rules
        assert "standards" in rules
        assert "semantic" in rules

    def test_policy_has_severity_levels(self, default_policy):
        """example.yaml must define severity levels."""
        assert "severity_levels" in default_policy
        levels = default_policy["severity_levels"]
        assert "CRITICAL" in levels
        assert "HIGH" in levels
        assert "MEDIUM" in levels
        assert "LOW" in levels


# ---------------------------------------------------------------------------
# Constants Consistency
# ---------------------------------------------------------------------------


class TestConstants:
    def test_commit_platforms_set(self):
        assert "cisco_xr" in clanet_cli.COMMIT_PLATFORMS
        assert "juniper_junos" in clanet_cli.COMMIT_PLATFORMS
        assert "cisco_ios" not in clanet_cli.COMMIT_PLATFORMS

    def test_all_dirs_defined(self):
        assert "logs" in clanet_cli.DIRS
        assert "backups" in clanet_cli.DIRS
        assert "snapshots" in clanet_cli.DIRS
        assert "audit" in clanet_cli.DIRS


# ---------------------------------------------------------------------------
# Exception Hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Verify custom exceptions inherit from ClanetError."""

    def test_inventory_not_found_is_clanet_error(self):
        assert issubclass(clanet_cli.InventoryNotFoundError, clanet_cli.ClanetError)

    def test_device_not_found_is_clanet_error(self):
        assert issubclass(clanet_cli.DeviceNotFoundError, clanet_cli.ClanetError)

    def test_device_connection_error_is_clanet_error(self):
        assert issubclass(clanet_cli.DeviceConnectionError, clanet_cli.ClanetError)

    def test_config_error_is_clanet_error(self):
        assert issubclass(clanet_cli.ConfigError, clanet_cli.ClanetError)

    def test_clanet_error_is_exception(self):
        assert issubclass(clanet_cli.ClanetError, Exception)

    def test_main_catches_clanet_error(self, monkeypatch):
        """main() should convert ClanetError to sys.exit(1)."""
        monkeypatch.setattr(clanet_cli, "INVENTORY_PATHS", ["/nonexistent.yaml"])
        monkeypatch.setattr(clanet_cli, "_config", None)
        with pytest.raises(SystemExit) as exc_info:
            monkeypatch.setattr("sys.argv", ["clanet_cli", "list"])
            clanet_cli.main()
        assert exc_info.value.code == 1



# ---------------------------------------------------------------------------
# Connect Error Handling
# ---------------------------------------------------------------------------


class TestConnect:
    def test_connect_missing_netmiko(self, monkeypatch):
        """connect() should raise DeviceConnectionError when Netmiko is not installed."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "netmiko":
                raise ImportError("No module named 'netmiko'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.connect({"device_type": "cisco_ios", "host": "1.1.1.1",
                                "username": "admin", "password": "admin"})

    def test_connect_missing_fields(self):
        """connect() should raise ConfigError when required fields are missing."""
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.connect({"host": "1.1.1.1"})

    def test_connect_missing_password(self):
        """connect() should raise ConfigError when password is missing."""
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.connect({"device_type": "cisco_ios", "host": "1.1.1.1",
                                "username": "admin"})


# ---------------------------------------------------------------------------
# Config Loading
# ---------------------------------------------------------------------------


class TestConfigLoading:
    def test_load_config_default(self, monkeypatch):
        """load_config() should return defaults when no config file exists."""
        monkeypatch.setattr(clanet_cli, "CONFIG_PATHS", ["/nonexistent/.clanet.yaml"])
        monkeypatch.setattr(clanet_cli, "_config", None)
        config = clanet_cli.load_config()
        assert config["default_profile"] == "basic"
        assert config["auto_backup"] is False

    def test_load_config_default_timeouts(self, monkeypatch):
        """load_config() should include default timeout values."""
        monkeypatch.setattr(clanet_cli, "CONFIG_PATHS", ["/nonexistent/.clanet.yaml"])
        monkeypatch.setattr(clanet_cli, "_config", None)
        config = clanet_cli.load_config()
        assert config["read_timeout"] == 30
        assert config["read_timeout_long"] == 60

    def test_load_config_custom(self, tmp_path, monkeypatch):
        """load_config() should load settings from .clanet.yaml."""
        config_file = tmp_path / ".clanet.yaml"
        config_file.write_text("default_profile: security\nauto_backup: true\n")
        monkeypatch.setattr(clanet_cli, "CONFIG_PATHS", [str(config_file)])
        monkeypatch.setattr(clanet_cli, "_config", None)
        config = clanet_cli.load_config()
        assert config["default_profile"] == "security"
        assert config["auto_backup"] is True

    def test_load_config_custom_timeouts(self, tmp_path, monkeypatch):
        """load_config() should allow overriding timeout values."""
        config_file = tmp_path / ".clanet.yaml"
        config_file.write_text("read_timeout: 45\nread_timeout_long: 120\n")
        monkeypatch.setattr(clanet_cli, "CONFIG_PATHS", [str(config_file)])
        monkeypatch.setattr(clanet_cli, "_config", None)
        config = clanet_cli.load_config()
        assert config["read_timeout"] == 45
        assert config["read_timeout_long"] == 120


# ---------------------------------------------------------------------------
# Policy Loading
# ---------------------------------------------------------------------------


class TestPolicyLoading:
    def test_load_policy_not_found(self, monkeypatch, capsys):
        """_load_policy() should warn when policy file is not found."""
        monkeypatch.setattr(clanet_cli, "_config", {"policy_file": None})
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["audit", "--all"])
        args.policy = "/nonexistent/policy.yaml"
        result = clanet_cli._load_policy(args)
        assert result is None
        captured = capsys.readouterr()
        assert "WARN" in captured.err


# ---------------------------------------------------------------------------
# Audit Profile (using default policy YAML)
# ---------------------------------------------------------------------------


class TestAuditProfile:
    """Tests for profile filtering logic using inline test data."""

    AUDIT_POLICY = {
        "rules": {
            "security": [
                {"id": "SEC-001", "name": "No plaintext passwords", "severity": "CRITICAL",
                 "pattern_deny": r"password \S+$"},
                {"id": "SEC-002", "name": "SSH v2 required", "severity": "HIGH",
                 "require_in_running": r"ssh.*v(ersion)?\s*2"},
            ],
            "safety": [
                {"id": "SAF-001", "name": "No bulk protocol removal", "severity": "CRITICAL",
                 "pattern_deny": r"no router (ospf|bgp|isis|eigrp)"},
            ],
            "standards": [
                {"id": "STD-001", "name": "NTP configured", "severity": "MEDIUM",
                 "require_in_running": "ntp server"},
                {"id": "STD-002", "name": "Logging configured", "severity": "MEDIUM",
                 "require_in_running": r"logging.*\d+\.\d+\.\d+\.\d+"},
            ],
        }
    }

    @pytest.fixture
    def rules(self):
        return clanet_cli._parse_policy_rules(self.AUDIT_POLICY)

    def test_full_profile_includes_all_categories(self, rules):
        """full profile should include rules from all categories."""
        filtered = clanet_cli._filter_rules_by_profile(rules, "full")
        assert len(filtered) == len(rules)
        categories = {r["_category"] for r in filtered}
        assert categories == {"security", "safety", "standards"}

    def test_security_profile_subset_of_full(self, rules):
        """security profile should be a subset of full."""
        full = clanet_cli._filter_rules_by_profile(rules, "full")
        security = clanet_cli._filter_rules_by_profile(rules, "security")
        assert len(security) <= len(full)
        assert len(security) > 0

    def test_basic_profile_smallest(self, rules):
        """basic profile should be the smallest subset."""
        basic = clanet_cli._filter_rules_by_profile(rules, "basic")
        security = clanet_cli._filter_rules_by_profile(rules, "security")
        full = clanet_cli._filter_rules_by_profile(rules, "full")
        assert len(basic) <= len(security) <= len(full)


# ---------------------------------------------------------------------------
# Policy Parsing
# ---------------------------------------------------------------------------


class TestPolicyParsing:
    """Tests for _parse_policy_rules and _filter_rules_by_profile."""

    SAMPLE_POLICY = {
        "rules": {
            "security": [
                {"id": "SEC-001", "name": "No plaintext", "severity": "CRITICAL",
                 "pattern_deny": "password \\S+$"},
                {"id": "SEC-002", "name": "SSH v2", "severity": "HIGH",
                 "require": "ssh server v2"},
            ],
            "standards": [
                {"id": "STD-001", "name": "NTP required", "severity": "MEDIUM",
                 "require_in_running": "ntp server"},
            ],
            "safety": [
                {"id": "SAF-001", "name": "Mgmt protection", "severity": "CRITICAL",
                 "pattern_deny": "interface Mgmt", "scope": "config_commands"},
            ],
        }
    }

    def test_parse_policy_rules_flat_list(self):
        rules = clanet_cli._parse_policy_rules(self.SAMPLE_POLICY)
        assert len(rules) == 4

    def test_parse_policy_rules_categories(self):
        rules = clanet_cli._parse_policy_rules(self.SAMPLE_POLICY)
        categories = {r["_category"] for r in rules}
        assert categories == {"security", "standards", "safety"}

    def test_parse_policy_rules_empty(self):
        rules = clanet_cli._parse_policy_rules({"rules": {}})
        assert rules == []

    def test_filter_basic_profile(self):
        rules = clanet_cli._parse_policy_rules(self.SAMPLE_POLICY)
        filtered = clanet_cli._filter_rules_by_profile(rules, "basic")
        assert all(r["_category"] == "standards" for r in filtered)
        assert len(filtered) == 1

    def test_filter_security_profile(self):
        rules = clanet_cli._parse_policy_rules(self.SAMPLE_POLICY)
        filtered = clanet_cli._filter_rules_by_profile(rules, "security")
        categories = {r["_category"] for r in filtered}
        assert categories == {"security", "standards"}
        assert len(filtered) == 3

    def test_filter_full_profile(self):
        rules = clanet_cli._parse_policy_rules(self.SAMPLE_POLICY)
        filtered = clanet_cli._filter_rules_by_profile(rules, "full")
        assert len(filtered) == 4


# ---------------------------------------------------------------------------
# Rule Evaluation
# ---------------------------------------------------------------------------


class TestEvaluateRule:
    """Tests for _evaluate_rule with different rule types."""

    RUNNING_CONFIG = """\
hostname router01
!
ntp server 10.0.0.1
!
logging 10.0.0.2
!
banner motd ^Authorized access only^
!
ip ssh version 2
!
snmp-server community mycommunity RO
!
line vty 0 4
 access-class 10 in
 transport input ssh
!
line con 0
 exec-timeout 5 0
!
interface GigabitEthernet0/0
 description Uplink
 ip address 192.168.1.1 255.255.255.0
!
password 7 045802150C2E
"""

    def test_pattern_deny_pass(self):
        rule = {"pattern_deny": "snmp-server community (public|private)"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "PASS"

    def test_pattern_deny_fail(self):
        config_with_public = self.RUNNING_CONFIG + "\nsnmp-server community public RO\n"
        rule = {"pattern_deny": "snmp-server community (public|private)"}
        status, _ = clanet_cli._evaluate_rule(rule, config_with_public)
        assert status == "FAIL"

    def test_pattern_deny_with_allow(self):
        rule = {"pattern_deny": r"password \S+$", "pattern_allow": r"password \d+ \S+"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "PASS"

    def test_require_in_running_pass(self):
        rule = {"require_in_running": "ntp server"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "PASS"

    def test_require_in_running_fail(self):
        rule = {"require_in_running": "aaa authentication"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "FAIL"

    def test_require_on_pass(self):
        rule = {"require_on": "line vty", "require": "access-class"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "PASS"

    def test_require_on_fail(self):
        rule = {"require_on": "line con", "require": "access-class"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "FAIL"

    def test_scope_config_commands_skip(self):
        rule = {"pattern_deny": "interface Mgmt", "scope": "config_commands"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "SKIP"

    def test_scope_interface_config_skip(self):
        rule = {"recommend": "description", "scope": "interface_config"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "SKIP"

    def test_recommend_warn(self):
        rule = {"recommend": "service timestamps"}
        status, _ = clanet_cli._evaluate_rule(rule, self.RUNNING_CONFIG)
        assert status == "WARN"


# ---------------------------------------------------------------------------
# Environment Variable Expansion
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Context Loading
# ---------------------------------------------------------------------------


class TestContextLoading:
    def test_load_context_file_exists(self, tmp_path, monkeypatch):
        """_load_context() should load context when file exists."""
        import yaml
        context = {
            "topology": "router01 --- router02",
            "symptoms": ["BGP neighbor down"],
            "constraints": ["OSPF changes prohibited"],
            "success_criteria": ["BGP Established"],
        }
        ctx_file = tmp_path / "context.yaml"
        ctx_file.write_text(yaml.dump(context, allow_unicode=True))
        monkeypatch.setattr(clanet_cli, "CONTEXT_PATHS", [str(ctx_file)])
        monkeypatch.setattr(clanet_cli, "_config", {"context_file": None})
        result = clanet_cli._load_context()
        assert result is not None
        assert result["topology"] == "router01 --- router02"
        assert result["symptoms"] == ["BGP neighbor down"]
        assert result["constraints"] == ["OSPF changes prohibited"]
        assert result["success_criteria"] == ["BGP Established"]

    def test_load_context_file_not_found(self, monkeypatch):
        """_load_context() should return None when no context file exists."""
        monkeypatch.setattr(clanet_cli, "CONTEXT_PATHS", ["/nonexistent/context.yaml"])
        monkeypatch.setattr(clanet_cli, "_config", {"context_file": None})
        result = clanet_cli._load_context()
        assert result is None

    def test_load_context_custom_path(self, tmp_path, monkeypatch):
        """_load_context() should respect context_file from config."""
        import yaml
        context = {"success_criteria": ["All interfaces Up"]}
        custom_file = tmp_path / "my-context.yaml"
        custom_file.write_text(yaml.dump(context))
        monkeypatch.setattr(clanet_cli, "_config", {"context_file": str(custom_file)})
        result = clanet_cli._load_context()
        assert result is not None
        assert result["success_criteria"] == ["All interfaces Up"]

    def test_load_context_empty_file(self, tmp_path, monkeypatch):
        """_load_context() should return empty dict for empty YAML file."""
        ctx_file = tmp_path / "context.yaml"
        ctx_file.write_text("")
        monkeypatch.setattr(clanet_cli, "CONTEXT_PATHS", [str(ctx_file)])
        monkeypatch.setattr(clanet_cli, "_config", {"context_file": None})
        result = clanet_cli._load_context()
        # empty YAML returns None from safe_load, converted to {}
        assert result == {}


# ---------------------------------------------------------------------------
# Context Subcommand Parser
# ---------------------------------------------------------------------------


class TestContextSubcommand:
    def test_context_parser(self):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["context"])
        assert args.command == "context"


class TestEnvVarExpansion:
    """Tests for _expand_env_vars."""

    def test_expand_defined_var(self, monkeypatch):
        monkeypatch.setenv("TEST_PASSWORD", "secret123")
        result = clanet_cli._expand_env_vars("${TEST_PASSWORD}")
        assert result == "secret123"

    def test_expand_undefined_var_left_as_is(self, monkeypatch):
        monkeypatch.delenv("UNDEFINED_VAR_XYZ", raising=False)
        result = clanet_cli._expand_env_vars("${UNDEFINED_VAR_XYZ}")
        assert result == "${UNDEFINED_VAR_XYZ}"

    def test_no_expansion_for_plain_string(self):
        result = clanet_cli._expand_env_vars("plainpassword")
        assert result == "plainpassword"

    def test_expand_multiple_vars(self, monkeypatch):
        monkeypatch.setenv("USER1", "admin")
        monkeypatch.setenv("PASS1", "secret")
        result = clanet_cli._expand_env_vars("${USER1}:${PASS1}")
        assert result == "admin:secret"

    def test_expand_partial_undefined(self, monkeypatch):
        monkeypatch.setenv("DEFINED_VAR", "ok")
        monkeypatch.delenv("UNDEF_VAR", raising=False)
        result = clanet_cli._expand_env_vars("${DEFINED_VAR}-${UNDEF_VAR}")
        assert result == "ok-${UNDEF_VAR}"


# ---------------------------------------------------------------------------
# JSON Error Handling (cmd_config / cmd_interact)
# ---------------------------------------------------------------------------


class TestJsonErrorHandling:
    """Tests that invalid JSON in --commands produces a clear error."""

    def test_config_invalid_json(self, mock_inventory):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["config", "router01", "--commands", "not-json"])
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.cmd_config(args)

    def test_cmd_interact_invalid_json(self, mock_inventory):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["cmd-interact", "router01", "--commands", "{bad}"])
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.cmd_interact(args)


# ---------------------------------------------------------------------------
# Subcommand Integration Tests (with mocked Netmiko)
# ---------------------------------------------------------------------------


class TestSubcommandIntegration:
    """Integration tests that mock Netmiko to verify end-to-end subcommand flow."""

    @pytest.fixture
    def mock_conn(self):
        """Create a mock Netmiko connection."""
        conn = MagicMock()
        conn.send_command.return_value = "mocked output"
        conn.send_config_set.return_value = "config applied"
        conn.commit.return_value = ""
        conn.is_alive.return_value = True
        conn.find_prompt.return_value = "router01#"
        conn.save_config.return_value = "[OK]"
        return conn

    @pytest.fixture
    def patched_env(self, mock_inventory, mock_conn, monkeypatch):
        """Patch connect() and inventory for integration tests."""
        monkeypatch.setattr(clanet_cli, "connect", lambda dev: mock_conn)
        return mock_conn

    def test_cmd_show(self, patched_env, capsys):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["show", "router01", "show", "ip", "route"])
        clanet_cli.cmd_show(args)
        captured = capsys.readouterr()
        assert "mocked output" in captured.out
        config = clanet_cli.get_config()
        patched_env.send_command.assert_called_once_with(
            "show ip route", read_timeout=config["read_timeout"]
        )

    def test_cmd_show_batch(self, patched_env, capsys):
        parser = clanet_cli.build_parser()
        args = parser.parse_args([
            "show", "router01", "--commands",
            '["show ip interface brief", "show ip route"]'
        ])
        clanet_cli.cmd_show(args)
        captured = capsys.readouterr()
        assert "--- show ip interface brief ---" in captured.out
        assert "--- show ip route ---" in captured.out
        assert patched_env.send_command.call_count == 2

    def test_cmd_show_batch_invalid_json(self, patched_env):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["show", "router01", "--commands", "{bad}"])
        with pytest.raises(Exception):
            clanet_cli.cmd_show(args)

    def test_cmd_show_batch_not_array(self, patched_env):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["show", "router01", "--commands", '"just a string"'])
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.cmd_show(args)

    def test_cmd_syntax_help_config_mode(self, patched_env, capsys, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda s: None)
        patched_env.read_channel.side_effect = [
            "",  # バッファクリア（config_mode 後の残出力排除）
            "clock timezone ?\r\n  JST  UTC 9:00\r\n  UTC  UTC 0:00\r\n"
            "RP/0/RP0/CPU0:router(config)#clock timezone",
            "",  # ポーリング終了（空で break）
            "",  # Ctrl-U 後の cleanup read
        ]
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["syntax-help", "router01", "clock timezone"])
        clanet_cli.cmd_syntax_help(args)
        patched_env.config_mode.assert_called_once()
        patched_env.write_channel.assert_any_call("clock timezone ?")
        patched_env.exit_config_mode.assert_called_once()
        patched_env.disconnect.assert_called_once()
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["device"] == "router01"
        assert result["query"] == "clock timezone"
        assert "JST" in result["help_output"]
        # options フィールドの検証
        assert "options" in result
        assert len(result["options"]) >= 2
        names = [o["name"] for o in result["options"]]
        assert "JST" in names
        assert "UTC" in names

    def test_cmd_syntax_help_exec_mode(self, patched_env, capsys, monkeypatch):
        monkeypatch.setattr("time.sleep", lambda s: None)
        patched_env.read_channel.side_effect = [
            "",  # バッファクリア
            "show ip ?\r\n  route  IP routing table\r\nrouter01#show ip ",
            "",  # ポーリング終了
            "",  # cleanup read
        ]
        parser = clanet_cli.build_parser()
        args = parser.parse_args([
            "syntax-help", "router01", "show ip", "--mode", "exec"
        ])
        clanet_cli.cmd_syntax_help(args)
        patched_env.config_mode.assert_not_called()
        patched_env.exit_config_mode.assert_not_called()
        patched_env.disconnect.assert_called_once()
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "route" in result["help_output"]
        assert "options" in result
        assert result["options"][0]["name"] == "route"

    def test_cmd_syntax_help_both_mode(self, patched_env, capsys, monkeypatch):
        """--mode both should return config_mode and exec_mode results."""
        monkeypatch.setattr("time.sleep", lambda s: None)
        patched_env.read_channel.side_effect = [
            # config mode run
            "",  # バッファクリア
            "clock ?\r\n  timezone  Configure time zone\r\n"
            "RP/0/RP0/CPU0:router(config)#clock",
            "",  # ポーリング終了
            "",  # cleanup read
            # exec mode run
            "",  # バッファクリア
            "clock ?\r\n  read-calendar  Read calendar\r\nrouter01#clock",
            "",  # ポーリング終了
            "",  # cleanup read
        ]
        parser = clanet_cli.build_parser()
        args = parser.parse_args([
            "syntax-help", "router01", "clock", "--mode", "both"
        ])
        clanet_cli.cmd_syntax_help(args)
        patched_env.config_mode.assert_called_once()
        patched_env.exit_config_mode.assert_called_once()
        patched_env.disconnect.assert_called_once()
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "config_mode" in result
        assert "exec_mode" in result
        assert "timezone" in result["config_mode"]["help_output"]
        assert len(result["config_mode"]["options"]) >= 1
        assert "read-calendar" in result["exec_mode"]["help_output"]
        assert len(result["exec_mode"]["options"]) >= 1

    def test_cmd_syntax_help_disconnects_on_error(self, patched_env):
        patched_env.config_mode.side_effect = Exception("connection error")
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["syntax-help", "router01", "clock"])
        with pytest.raises(Exception):
            clanet_cli.cmd_syntax_help(args)
        patched_env.disconnect.assert_called_once()

    def test_cmd_info(self, patched_env, capsys):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["info", "router01"])
        clanet_cli.cmd_info(args)
        captured = capsys.readouterr()
        assert "mocked output" in captured.out

    def test_cmd_config_ios(self, patched_env, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        parser = clanet_cli.build_parser()
        args = parser.parse_args([
            "config", "router01", "--commands", '["ntp server 10.0.0.1"]'
        ])
        clanet_cli.cmd_config(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        patched_env.send_config_set.assert_called_once()

    def test_cmd_config_xr_commits(self, mock_inventory, mock_conn, monkeypatch,
                                    capsys, tmp_path):
        """IOS-XR devices should call commit() after config."""
        monkeypatch.setattr(clanet_cli, "connect", lambda dev: mock_conn)
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        parser = clanet_cli.build_parser()
        args = parser.parse_args([
            "config", "router02", "--commands", '["ntp server 10.0.0.1"]'
        ])
        clanet_cli.cmd_config(args)
        mock_conn.commit.assert_called_once()
        mock_conn.exit_config_mode.assert_called_once()

    def test_cmd_config_error_detected(self, patched_env, capsys, tmp_path, monkeypatch):
        """Config with error output should print [WARN] instead of [OK]."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        patched_env.send_config_set.return_value = (
            "configure terminal\n"
            "router01(config)#clock timezone JST 9\n"
            "                                    ^\n"
            "% Invalid input detected at '^' marker.\n"
        )
        parser = clanet_cli.build_parser()
        args = parser.parse_args([
            "config", "router01", "--commands", '["clock timezone JST 9"]'
        ])
        clanet_cli.cmd_config(args)
        captured = capsys.readouterr()
        assert "[OK]" not in captured.out
        assert "[WARN]" in captured.err
        assert "[HINT]" in captured.err
        assert "syntax-help" in captured.err

    def test_cmd_config_error_hint_partial(self, patched_env, capsys, tmp_path, monkeypatch):
        """HINT should suggest correct partial command for syntax-help."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        patched_env.send_config_set.return_value = (
            "router01(config)#clock timezone JST 9\n"
            "% Invalid input detected at '^' marker.\n"
        )
        parser = clanet_cli.build_parser()
        args = parser.parse_args([
            "config", "router01", "--commands", '["clock timezone JST 9"]'
        ])
        clanet_cli.cmd_config(args)
        captured = capsys.readouterr()
        assert '"clock timezone JST"' in captured.err

    def test_cmd_config_load_error_detected(self, patched_env, capsys, tmp_path, monkeypatch):
        """config-load with error output should print [WARN] instead of [OK]."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        config_file = tmp_path / "load.cfg"
        config_file.write_text("clock timezone JST 9\n")
        patched_env.send_config_from_file.return_value = (
            "router01(config)#clock timezone JST 9\n"
            "% Invalid input detected at '^' marker.\n"
        )
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["config-load", "router01", str(config_file)])
        clanet_cli.cmd_config_load(args)
        captured = capsys.readouterr()
        assert "[OK]" not in captured.out
        assert "[WARN]" in captured.err

    def test_cmd_backup(self, patched_env, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
            "backups": str(tmp_path / "backups"),
        })
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["backup", "router01"])
        clanet_cli.cmd_backup(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        # Verify backup file was created
        backup_files = list((tmp_path / "backups").glob("router01_*.cfg"))
        assert len(backup_files) == 1

    def test_cmd_list(self, mock_inventory, capsys):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["list"])
        clanet_cli.cmd_list(args)
        captured = capsys.readouterr()
        assert "router01" in captured.out
        assert "router02" in captured.out
        assert "switch01" in captured.out

    def test_cmd_device_info(self, mock_inventory, capsys):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["device-info", "router01"])
        clanet_cli.cmd_device_info(args)
        captured = capsys.readouterr()
        info = json.loads(captured.out)
        assert info["device_type"] == "cisco_ios"
        assert info["host"] == "192.168.1.1"
        assert info["needs_commit"] is False

    def test_cmd_context_no_file(self, monkeypatch, capsys):
        monkeypatch.setattr(clanet_cli, "CONTEXT_PATHS", ["/nonexistent"])
        monkeypatch.setattr(clanet_cli, "_config", {"context_file": None})
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["context"])
        clanet_cli.cmd_context(args)
        captured = capsys.readouterr()
        assert "No context file found" in captured.out

    def test_cmd_config_load_ios(self, patched_env, capsys, tmp_path, monkeypatch):
        """config-load from file to IOS device."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        config_file = tmp_path / "load.cfg"
        config_file.write_text("ntp server 10.0.0.1\n")
        patched_env.send_config_from_file.return_value = "config applied from file"
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["config-load", "router01", str(config_file)])
        clanet_cli.cmd_config_load(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        patched_env.send_config_from_file.assert_called_once()

    def test_cmd_config_load_xr_commits(self, mock_inventory, mock_conn, monkeypatch,
                                         capsys, tmp_path):
        """config-load to IOS-XR should call commit()."""
        monkeypatch.setattr(clanet_cli, "connect", lambda dev: mock_conn)
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        config_file = tmp_path / "load.cfg"
        config_file.write_text("router ospf 1\n")
        mock_conn.send_config_from_file.return_value = "config applied"
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["config-load", "router02", str(config_file)])
        clanet_cli.cmd_config_load(args)
        mock_conn.commit.assert_called_once()
        mock_conn.exit_config_mode.assert_called_once()

    def test_cmd_config_load_file_not_found(self, mock_inventory, capsys):
        """config-load with nonexistent file should raise ConfigError."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["config-load", "router01", "/nonexistent/config.cfg"])
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.cmd_config_load(args)

    def test_cmd_save_ios(self, patched_env, capsys, tmp_path, monkeypatch):
        """Save should call save_config() for IOS devices."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["save", "router01"])
        clanet_cli.cmd_save(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        patched_env.save_config.assert_called_once()

    def test_cmd_save_xr_skip(self, mock_inventory, mock_conn, monkeypatch, capsys):
        """Save should skip commit-based platforms (XR)."""
        monkeypatch.setattr(clanet_cli, "connect", lambda dev: mock_conn)
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["save", "router02"])
        clanet_cli.cmd_save(args)
        captured = capsys.readouterr()
        assert "[SKIP]" in captured.out

    def test_cmd_commit_xr(self, mock_inventory, mock_conn, monkeypatch,
                            capsys, tmp_path):
        """Commit should call commit() for XR devices."""
        monkeypatch.setattr(clanet_cli, "connect", lambda dev: mock_conn)
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["commit", "router02"])
        clanet_cli.cmd_commit(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        mock_conn.commit.assert_called_once()

    def test_cmd_commit_ios_skip(self, patched_env, capsys):
        """Commit should skip non-commit platforms (IOS)."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["commit", "router01"])
        clanet_cli.cmd_commit(args)
        captured = capsys.readouterr()
        assert "[SKIP]" in captured.out

    def test_cmd_snapshot_pre(self, patched_env, capsys, tmp_path, monkeypatch):
        """Snapshot pre should save snapshot JSON."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "snapshots": str(tmp_path / "snapshots"),
        })
        monkeypatch.setattr(clanet_cli, "_config", {
            "health_file": None, "read_timeout": 30, "read_timeout_long": 60,
        })
        monkeypatch.chdir(Path(__file__).parent.parent)
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["snapshot", "router01", "--phase", "pre"])
        clanet_cli.cmd_snapshot(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        snapshot_files = list((tmp_path / "snapshots").glob("router01_pre_*.json"))
        assert len(snapshot_files) == 1
        # Verify JSON content
        content = json.loads(snapshot_files[0].read_text())
        assert isinstance(content, dict)

    def test_cmd_health_commands(self, patched_env, capsys, monkeypatch):
        """health-commands should return JSON with commands list."""
        monkeypatch.setattr(clanet_cli, "_config", {
            "health_file": None, "read_timeout": 30, "read_timeout_long": 60,
        })
        monkeypatch.chdir(Path(__file__).parent.parent)
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["health-commands", "router01"])
        clanet_cli.cmd_health_commands(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["device"] == "router01"
        assert result["device_type"] == "cisco_ios"
        assert isinstance(result["commands"], list)
        assert len(result["commands"]) > 0

    def test_cmd_audit_with_policy(self, patched_env, capsys, tmp_path, monkeypatch):
        """Audit should evaluate rules against running-config."""
        import yaml
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
            "audit": str(tmp_path / "audit"),
        })
        monkeypatch.setattr(clanet_cli, "_config", {
            "policy_file": None, "default_profile": "full",
            "read_timeout": 30, "read_timeout_long": 60,
        })
        # Mock running config with NTP
        patched_env.send_command.return_value = (
            "hostname router01\nntp server 10.0.0.1\nlogging 10.0.0.2\n"
        )
        policy = {
            "policy": {"name": "test-policy"},
            "rules": {
                "standards": [
                    {"id": "STD-001", "name": "NTP configured", "severity": "MEDIUM",
                     "require_in_running": "ntp server"},
                ]
            }
        }
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["audit", "router01", "--policy", str(policy_file)])
        clanet_cli.cmd_audit(args)
        captured = capsys.readouterr()
        assert "Score:" in captured.out
        assert "[OK]" in captured.out
        # Verify audit report saved
        audit_files = list((tmp_path / "audit").glob("router01_*.md"))
        assert len(audit_files) == 1


# ---------------------------------------------------------------------------
# Sensitive Data Redaction
# ---------------------------------------------------------------------------


class TestRedactSensitive:
    """Tests for _redact_sensitive()."""

    def test_redact_plaintext_password(self):
        assert clanet_cli._redact_sensitive("password Cisco123") == "password ***"

    def test_redact_type7_password(self):
        assert clanet_cli._redact_sensitive("password 7 045802150C2E") == "password 7 ***"

    def test_redact_enable_secret(self):
        result = clanet_cli._redact_sensitive("enable secret 5 $1$abc$hash")
        assert result == "enable secret 5 ***"

    def test_redact_snmp_community(self):
        result = clanet_cli._redact_sensitive("snmp-server community public RO")
        assert "public" not in result
        assert "community ***" in result

    def test_redact_key_string(self):
        result = clanet_cli._redact_sensitive("key-string MySecretKey")
        assert result == "key-string ***"

    def test_no_redact_safe_command(self):
        safe = "ntp server 10.0.0.1"
        assert clanet_cli._redact_sensitive(safe) == safe

    def test_no_redact_interface(self):
        safe = "interface GigabitEthernet0/0"
        assert clanet_cli._redact_sensitive(safe) == safe

    def test_redact_multiline(self):
        config = "hostname R1\npassword Cisco123\nntp server 10.0.0.1"
        result = clanet_cli._redact_sensitive(config)
        assert "Cisco123" not in result
        assert "ntp server 10.0.0.1" in result

    def test_redact_case_insensitive(self):
        assert "Secret123" not in clanet_cli._redact_sensitive("Password Secret123")


# ---------------------------------------------------------------------------
# Plaintext Password Warning
# ---------------------------------------------------------------------------


class TestPlaintextPasswordWarning:
    """Tests for _warn_plaintext_passwords()."""

    def test_warns_on_plaintext(self, capsys):
        inv = {"devices": {"r1": {"password": "admin123"}}}
        clanet_cli._warn_plaintext_passwords(inv)
        captured = capsys.readouterr()
        assert "[SECURITY]" in captured.err
        assert "r1" in captured.err

    def test_no_warn_on_env_var(self, capsys):
        inv = {"devices": {"r1": {"password": "${DEVICE_PASSWORD}"}}}
        clanet_cli._warn_plaintext_passwords(inv)
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_no_warn_on_empty_password(self, capsys):
        inv = {"devices": {"r1": {"password": ""}}}
        clanet_cli._warn_plaintext_passwords(inv)
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_warns_multiple_devices(self, capsys):
        inv = {"devices": {
            "r1": {"password": "plain1"},
            "r2": {"password": "${SAFE}"},
            "r3": {"password": "plain3"},
        }}
        clanet_cli._warn_plaintext_passwords(inv)
        captured = capsys.readouterr()
        assert "r1" in captured.err
        assert "r2" not in captured.err
        assert "r3" in captured.err

    def test_load_inventory_warns(self, mock_inventory, capsys):
        """load_inventory() should emit warnings for plaintext passwords."""
        clanet_cli.load_inventory()
        captured = capsys.readouterr()
        assert "[SECURITY]" in captured.err


# ---------------------------------------------------------------------------
# Log Redaction
# ---------------------------------------------------------------------------


class TestLogRedaction:
    """Tests that log_operation() redacts sensitive values."""

    def test_log_redacts_password_command(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        clanet_cli.log_operation(
            "router01", "config",
            "username admin password 0 Cisco123; enable secret MySecret"
        )
        log_file = tmp_path / "logs" / "clanet_operations.log"
        content = log_file.read_text()
        assert "Cisco123" not in content
        assert "MySecret" not in content
        assert "password 0 ***" in content
        assert "secret ***" in content

    def test_log_keeps_safe_commands(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        clanet_cli.log_operation("router01", "config", "ntp server 10.0.0.1")
        log_file = tmp_path / "logs" / "clanet_operations.log"
        content = log_file.read_text()
        assert "ntp server 10.0.0.1" in content


# ---------------------------------------------------------------------------
# Artifact File Permissions
# ---------------------------------------------------------------------------


class TestArtifactPermissions:
    """Tests that saved artifacts have restricted file permissions."""

    def test_artifact_permission_0600(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "backups": str(tmp_path / "backups"),
        })
        filepath = clanet_cli.save_artifact("backups", "r1", "content", ext=".cfg")
        import stat
        mode = stat.S_IMODE(Path(filepath).stat().st_mode)
        assert mode == 0o600

    def test_log_file_permission_0600(self, tmp_path, monkeypatch):
        """log_operation() should create log file with 0600 permissions."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        clanet_cli.log_operation("r1", "config", "test")
        import stat
        log_file = tmp_path / "logs" / "clanet_operations.log"
        mode = stat.S_IMODE(log_file.stat().st_mode)
        assert mode == 0o600

    def test_log_file_permission_preserved_on_append(self, tmp_path, monkeypatch):
        """Appending to log should not change permissions."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        clanet_cli.log_operation("r1", "config", "first")
        clanet_cli.log_operation("r1", "config", "second")
        import stat
        log_file = tmp_path / "logs" / "clanet_operations.log"
        mode = stat.S_IMODE(log_file.stat().st_mode)
        assert mode == 0o600
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# Snapshot Redaction
# ---------------------------------------------------------------------------


class TestSnapshotRedaction:
    """Tests that snapshots redact sensitive config output."""

    def _run_snapshot(self, mock_inventory, tmp_path, monkeypatch):
        """Helper: run snapshot with sensitive output and return (file_content, stdout)."""
        mock_conn = MagicMock()
        mock_conn.send_command.return_value = (
            "hostname R1\npassword 7 045802150C2E\n"
            "snmp-server community public RO\n"
        )
        monkeypatch.setattr(clanet_cli, "connect", lambda dev: mock_conn)
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "snapshots": str(tmp_path / "snapshots"),
        })
        monkeypatch.setattr(clanet_cli, "_config", {
            "health_file": None, "read_timeout": 30, "read_timeout_long": 60,
        })
        monkeypatch.chdir(Path(__file__).parent.parent)
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["snapshot", "router01", "--phase", "pre"])
        clanet_cli.cmd_snapshot(args)
        snapshot_files = list((tmp_path / "snapshots").glob("router01_pre_*.json"))
        return snapshot_files[0].read_text()

    def test_snapshot_redacts_passwords(self, mock_inventory, tmp_path, monkeypatch):
        content = self._run_snapshot(mock_inventory, tmp_path, monkeypatch)
        assert "045802150C2E" not in content
        assert "public" not in content
        assert "***" in content

    def test_snapshot_console_output_redacted(self, mock_inventory, tmp_path,
                                              monkeypatch, capsys):
        """Console output during snapshot must also be redacted."""
        self._run_snapshot(mock_inventory, tmp_path, monkeypatch)
        captured = capsys.readouterr()
        assert "045802150C2E" not in captured.out
        assert "public" not in captured.out
        assert "***" in captured.out


# ---------------------------------------------------------------------------
# Validate JSON Commands
# ---------------------------------------------------------------------------


class TestValidateJsonCommands:
    """Tests for _validate_json_commands input validation."""

    def test_valid_json_list(self):
        result = clanet_cli._validate_json_commands('["cmd1", "cmd2"]')
        assert result == ["cmd1", "cmd2"]

    def test_json_dict_rejected(self):
        with pytest.raises(clanet_cli.ConfigError, match="JSON array"):
            clanet_cli._validate_json_commands('{"key": "value"}')

    def test_empty_list_rejected(self):
        with pytest.raises(clanet_cli.ConfigError, match="empty"):
            clanet_cli._validate_json_commands('[]')

    def test_non_string_elements_rejected(self):
        with pytest.raises(clanet_cli.ConfigError, match="string"):
            clanet_cli._validate_json_commands('[1, 2, 3]')

    def test_invalid_json_rejected(self):
        with pytest.raises(clanet_cli.ConfigError, match="not valid JSON"):
            clanet_cli._validate_json_commands('not json')


# ---------------------------------------------------------------------------
# Inventory YAML Validation
# ---------------------------------------------------------------------------


class TestInventoryValidation:
    """Tests that load_inventory rejects malformed YAML structures."""

    def test_devices_not_dict_rejected(self, tmp_path, monkeypatch):
        inv_file = tmp_path / "inventory.yaml"
        inv_file.write_text("devices: not_a_dict\n")
        monkeypatch.setattr(clanet_cli, "INVENTORY_PATHS", [str(inv_file)])
        monkeypatch.setattr(clanet_cli, "_config", {"inventory": None})
        with pytest.raises(clanet_cli.ConfigError, match="YAML mapping"):
            clanet_cli.load_inventory()

    def test_null_yaml_rejected(self, tmp_path, monkeypatch):
        inv_file = tmp_path / "inventory.yaml"
        inv_file.write_text("null\n")
        monkeypatch.setattr(clanet_cli, "INVENTORY_PATHS", [str(inv_file)])
        monkeypatch.setattr(clanet_cli, "_config", {"inventory": None})
        with pytest.raises(clanet_cli.ConfigError, match="YAML mapping"):
            clanet_cli.load_inventory()


# ---------------------------------------------------------------------------
# Policy YAML Validation
# ---------------------------------------------------------------------------


class TestPolicyValidation:
    """Tests that _load_policy rejects malformed policy YAML."""

    def test_null_policy_rejected(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("null\n")
        args = argparse.Namespace(policy=str(policy_file))
        with pytest.raises(clanet_cli.ConfigError, match="YAML mapping"):
            clanet_cli._load_policy(args)

    def test_string_policy_rejected(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text('"just a string"\n')
        args = argparse.Namespace(policy=str(policy_file))
        with pytest.raises(clanet_cli.ConfigError, match="YAML mapping"):
            clanet_cli._load_policy(args)


# ---------------------------------------------------------------------------
# Invalid Regex Handling
# ---------------------------------------------------------------------------


class TestInvalidRegexHandling:
    """Tests that invalid regex in policy rules raises ConfigError."""

    def test_invalid_pattern_deny(self):
        rule = {"pattern_deny": "([invalid"}
        with pytest.raises(clanet_cli.ConfigError, match="invalid regex"):
            clanet_cli._evaluate_rule(rule, "some config text")

    def test_invalid_require_in_running(self):
        rule = {"require_in_running": "([invalid"}
        with pytest.raises(clanet_cli.ConfigError, match="invalid regex"):
            clanet_cli._evaluate_rule(rule, "some config text")

    def test_invalid_recommend(self):
        rule = {"recommend": "([invalid"}
        with pytest.raises(clanet_cli.ConfigError, match="invalid regex"):
            clanet_cli._evaluate_rule(rule, "some config text")


# ---------------------------------------------------------------------------
# Self-lockout detection
# ---------------------------------------------------------------------------


class TestCheckLockout:
    """Tests for _check_lockout() self-lockout prevention."""

    def test_safe_commands_pass(self):
        """Normal commands should not raise."""
        commands = [
            "interface GigabitEthernet0/1",
            "description Uplink to core",
            "no shutdown",
        ]
        clanet_cli._check_lockout(commands, "cisco_ios")  # Should not raise

    def test_ios_mgmt_shutdown_blocked(self):
        """Shutdown on management interface should be blocked (IOS)."""
        commands = ["interface Management0", "shutdown"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "cisco_ios")

    def test_ios_mgmt_no_ip_blocked(self):
        """Removing IP from management interface should be blocked (IOS)."""
        commands = ["interface GigabitEthernet0/0", "no ip address"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "cisco_ios")

    def test_ios_default_route_removal_blocked(self):
        """Removing default route should be blocked (IOS)."""
        commands = ["no ip route 0.0.0.0 0.0.0.0 10.0.0.1"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "cisco_ios")

    def test_xr_mgmteth_shutdown_blocked(self):
        """Shutdown on MgmtEth should be blocked (IOS-XR)."""
        commands = ["interface MgmtEth0/RP0/CPU0/0", "shutdown"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "cisco_xr")

    def test_xr_no_router_blocked(self):
        """Removing routing protocol should be blocked (IOS-XR)."""
        commands = ["no router ospf 1"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "cisco_xr")

    def test_nxos_mgmt0_shutdown_blocked(self):
        """Shutdown on mgmt0 should be blocked (NX-OS)."""
        commands = ["interface mgmt0", "shutdown"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "cisco_nxos")

    def test_junos_delete_mgmt_blocked(self):
        """Deleting management interface should be blocked (Junos)."""
        commands = ["delete interfaces fxp0"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "juniper_junos")

    def test_eos_management1_shutdown_blocked(self):
        """Shutdown on Management1 should be blocked (EOS)."""
        commands = ["interface Management1", "shutdown"]
        with pytest.raises(clanet_cli.ConfigError, match="LOCKOUT BLOCKED"):
            clanet_cli._check_lockout(commands, "arista_eos")

    def test_non_mgmt_interface_allowed(self):
        """Shutdown on a non-management interface should be allowed."""
        commands = ["interface GigabitEthernet0/1", "shutdown"]
        clanet_cli._check_lockout(commands, "cisco_ios")  # Should not raise

    def test_mgmt_block_resets_on_new_interface(self):
        """Entering a new non-mgmt interface resets the mgmt block tracking."""
        commands = [
            "interface Management0",
            "description mgmt",
            "interface GigabitEthernet0/1",
            "shutdown",  # This is on Gi0/1, not Management0
        ]
        clanet_cli._check_lockout(commands, "cisco_ios")  # Should not raise

    def test_unknown_vendor_passes(self):
        """Unknown device_type should not block anything."""
        commands = ["interface Management0", "shutdown"]
        clanet_cli._check_lockout(commands, "unknown_vendor")  # Should not raise


# ---------------------------------------------------------------------------
# Pre-apply compliance check
# ---------------------------------------------------------------------------


class TestEvaluateRuleForCommands:
    """Tests for _evaluate_rule_for_commands()."""

    def test_non_config_scope_skipped(self):
        rule = {"scope": "running_config", "pattern_deny": "shutdown"}
        status, _ = clanet_cli._evaluate_rule_for_commands(rule, "shutdown")
        assert status == "SKIP"

    def test_config_commands_deny_match(self):
        rule = {"scope": "config_commands", "pattern_deny": r"write\s+erase"}
        status, _ = clanet_cli._evaluate_rule_for_commands(rule, "write erase")
        assert status == "FAIL"

    def test_config_commands_deny_no_match(self):
        rule = {"scope": "config_commands", "pattern_deny": r"write\s+erase"}
        status, _ = clanet_cli._evaluate_rule_for_commands(
            rule, "interface Gi0/1\nno shutdown")
        assert status == "PASS"

    def test_config_commands_deny_with_allow(self):
        rule = {
            "scope": "config_commands",
            "pattern_deny": r"^shutdown$",
            "pattern_allow": r"no\s+shutdown",
        }
        # "no shutdown" should not match "^shutdown$" deny pattern
        status, _ = clanet_cli._evaluate_rule_for_commands(rule, "no shutdown")
        assert status == "PASS"

    def test_config_commands_deny_with_allow_line_match(self):
        rule = {
            "scope": "config_commands",
            "pattern_deny": r"(?m)^\s*shutdown\s*$",
            "pattern_allow": r"no\s+shutdown",
        }
        # "shutdown" (bare) should FAIL, "no shutdown" in the same text won't cover it
        status, _ = clanet_cli._evaluate_rule_for_commands(rule, "shutdown")
        assert status == "FAIL"

    def test_no_pattern_deny_skipped(self):
        rule = {"scope": "config_commands"}
        status, _ = clanet_cli._evaluate_rule_for_commands(rule, "anything")
        assert status == "SKIP"


class TestPreApplyCompliance:
    """Tests for _pre_apply_compliance()."""

    def test_no_policy_file_returns_empty(self, tmp_path, monkeypatch):
        """Missing policy file should return no violations."""
        monkeypatch.setattr(clanet_cli, "get_config",
                            lambda: {"policy_file": str(tmp_path / "nonexistent.yaml")})
        result = clanet_cli._pre_apply_compliance(["interface Gi0/1", "shutdown"])
        assert result == []

    def test_violation_detected(self, tmp_path, monkeypatch):
        """Policy violation should be returned."""
        policy = {
            "rules": {
                "security": [
                    {
                        "name": "no-write-erase",
                        "scope": "config_commands",
                        "pattern_deny": r"write\s+erase",
                        "severity": "critical",
                    }
                ]
            }
        }
        policy_file = tmp_path / "policy.yaml"
        import yaml
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "get_config",
                            lambda: {"policy_file": str(policy_file)})
        result = clanet_cli._pre_apply_compliance(["write erase"])
        assert len(result) == 1
        assert result[0]["rule"] == "no-write-erase"

    def test_no_violation_passes(self, tmp_path, monkeypatch):
        """Safe commands should produce no violations."""
        policy = {
            "rules": {
                "security": [
                    {
                        "name": "no-write-erase",
                        "scope": "config_commands",
                        "pattern_deny": r"write\s+erase",
                        "severity": "critical",
                    }
                ]
            }
        }
        policy_file = tmp_path / "policy.yaml"
        import yaml
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "get_config",
                            lambda: {"policy_file": str(policy_file)})
        result = clanet_cli._pre_apply_compliance(["interface Gi0/1", "description test"])
        assert result == []


# ---------------------------------------------------------------------------
# Auto-backup
# ---------------------------------------------------------------------------


class TestAutoBackup:
    """Tests for _auto_backup()."""

    def test_skipped_when_disabled(self, monkeypatch):
        """auto_backup=False should return None without connecting."""
        monkeypatch.setattr(clanet_cli, "get_config",
                            lambda: {**clanet_cli.DEFAULT_CONFIG, "auto_backup": False})
        result = clanet_cli._auto_backup("router01", {"device_type": "cisco_ios"})
        assert result is None

    def test_runs_when_enabled(self, tmp_path, monkeypatch):
        """auto_backup=True should create a backup file."""
        config = {**clanet_cli.DEFAULT_CONFIG, "auto_backup": True}
        monkeypatch.setattr(clanet_cli, "get_config", lambda: config)
        monkeypatch.setattr(clanet_cli, "_load_health_config", lambda: {
            "running_config_command": {"cisco_ios": "show running-config"},
            "fallback": {"running_config_command": "show running-config"},
        })

        class FakeConn:
            def send_command(self, *a, **kw):
                return "! fake running-config\nhostname router01"
            def disconnect(self):
                pass

        monkeypatch.setattr(clanet_cli, "connect", lambda dev: FakeConn())
        monkeypatch.setattr(clanet_cli, "DIRS", {**clanet_cli.DIRS, "backups": str(tmp_path)})

        result = clanet_cli._auto_backup("router01", {"device_type": "cisco_ios"})
        assert result is not None
        assert "pre_change" in result
        assert Path(result).exists()


class TestCleanHelpOutput:
    """Tests for _clean_help_output() helper."""

    def test_basic_cleaning(self):
        raw = (
            "clock timezone JST ?\r\n"
            "  Asia/Tokyo  9:00 DST_ACTIV NO \r\n"
            "  Japan       9:00 DST_ACTIV NO \r\n"
            "RP/0/RP0/CPU0:router(config)#clock timezone JST "
        )
        cleaned = clanet_cli._clean_help_output(raw, "clock timezone JST")
        assert "Asia/Tokyo" in cleaned
        assert "Japan" in cleaned
        assert "RP/0/RP0/CPU0" not in cleaned

    def test_removes_ansi_sequences(self):
        raw = "\x1b[4mclock\x1b[0m timezone ?\r\n  JST  UTC 9:00\r\nrouter#clock timezone "
        cleaned = clanet_cli._clean_help_output(raw, "clock timezone")
        assert "\x1b" not in cleaned
        assert "JST" in cleaned

    def test_empty_output(self):
        cleaned = clanet_cli._clean_help_output("", "clock")
        assert cleaned == ""

    def test_preserves_help_content(self):
        raw = (
            "clock ?\r\n"
            "  timezone  Configure time zone\r\n"
            "RP/0/RP0/CPU0:router(config)#clock "
        )
        cleaned = clanet_cli._clean_help_output(raw, "clock")
        assert "timezone" in cleaned
        assert "Configure time zone" in cleaned


# ---------------------------------------------------------------------------
# Parse Help Options
# ---------------------------------------------------------------------------


class TestParseHelpOptions:
    """Tests for _parse_help_options() structured output."""

    def test_basic_parsing(self):
        text = "  timezone  Configure time zone\n  ntp       NTP configuration"
        options = clanet_cli._parse_help_options(text)
        assert len(options) == 2
        assert options[0] == {"name": "timezone", "description": "Configure time zone"}
        assert options[1] == {"name": "ntp", "description": "NTP configuration"}

    def test_cr_token(self):
        options = clanet_cli._parse_help_options("  <cr>")
        assert options == [{"name": "<cr>", "description": ""}]

    def test_empty_input(self):
        assert clanet_cli._parse_help_options("") == []

    def test_multiword_description(self):
        text = "  Asia/Tokyo  9:00 DST_ACTIV NO"
        options = clanet_cli._parse_help_options(text)
        assert len(options) == 1
        assert options[0]["name"] == "Asia/Tokyo"
        assert options[0]["description"] == "9:00 DST_ACTIV NO"

    def test_no_description(self):
        options = clanet_cli._parse_help_options("  keyword")
        assert options == [{"name": "keyword", "description": ""}]

    def test_mixed_lines(self):
        text = "  JST  UTC 9:00\n  <cr>\n  UTC  UTC 0:00"
        options = clanet_cli._parse_help_options(text)
        assert len(options) == 3
        assert options[0] == {"name": "JST", "description": "UTC 9:00"}
        assert options[1] == {"name": "<cr>", "description": ""}
        assert options[2] == {"name": "UTC", "description": "UTC 0:00"}


# ---------------------------------------------------------------------------
# Detect Config Errors
# ---------------------------------------------------------------------------


class TestDetectConfigErrors:
    """Tests for _detect_config_errors() error detection."""

    def test_no_errors_in_clean_output(self):
        output = "configure terminal\nntp server 10.0.0.1\nend"
        assert clanet_cli._detect_config_errors(output) == []

    def test_invalid_input_detected(self):
        output = (
            "configure terminal\n"
            "RP/0/RP0/CPU0:router(config)#clock timezone JST 9\n"
            "                                                  ^\n"
            "% Invalid input detected at '^' marker.\n"
        )
        errors = clanet_cli._detect_config_errors(output)
        assert len(errors) == 1
        assert errors[0]["error"] == "Invalid input detected"
        assert "clock timezone JST 9" in errors[0]["command"]
        assert errors[0]["partial"] == "clock timezone JST"

    def test_incomplete_command(self):
        output = (
            "router(config)#router ospf\n"
            "% Incomplete command.\n"
        )
        errors = clanet_cli._detect_config_errors(output)
        assert len(errors) == 1
        assert errors[0]["error"] == "Incomplete command"

    def test_multiple_errors(self):
        output = (
            "router(config)#bad cmd1\n"
            "% Invalid input detected at '^' marker.\n"
            "router(config)#bad cmd2\n"
            "% Ambiguous command: bad cmd2\n"
        )
        errors = clanet_cli._detect_config_errors(output)
        assert len(errors) == 2

    def test_error_with_no_preceding_command(self):
        output = "% Error something went wrong\n"
        errors = clanet_cli._detect_config_errors(output)
        assert len(errors) == 1
        assert errors[0]["command"] == ""
        assert errors[0]["partial"] == ""

    def test_prompt_stripped_from_command(self):
        output = (
            "RP/0/RP0/CPU0:TokyoP01(config)#clock timezone JST 9\n"
            "% Invalid input detected at '^' marker.\n"
        )
        errors = clanet_cli._detect_config_errors(output)
        assert errors[0]["command"] == "clock timezone JST 9"
        assert errors[0]["partial"] == "clock timezone JST"


# ---------------------------------------------------------------------------
# Constitution loading
# ---------------------------------------------------------------------------


class TestConstitutionLoading:
    """Tests for _load_constitution() file loading."""

    def test_not_found_returns_none(self, monkeypatch):
        """No constitution file should return None."""
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS",
                            ["/nonexistent/path/constitution.yaml"])
        assert clanet_cli._load_constitution() is None

    def test_valid_file_loaded(self, tmp_path, monkeypatch):
        """Valid constitution file should be loaded."""
        import yaml
        const = {
            "constitution": {"name": "test", "version": "1.0"},
            "rules": {
                "safety": [{
                    "id": "CONST-SAF-001",
                    "name": "test rule",
                    "severity": "CRITICAL",
                    "reason": "test reason",
                    "pattern_deny": "write\\s+erase",
                }]
            },
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])
        result = clanet_cli._load_constitution()
        assert result is not None
        assert result["constitution"]["name"] == "test"

    def test_invalid_yaml_returns_empty(self, tmp_path, monkeypatch):
        """Empty/invalid YAML should return empty dict, not crash."""
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text("")
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])
        result = clanet_cli._load_constitution()
        assert result == {}

    def test_search_order_first_wins(self, tmp_path, monkeypatch):
        """First found file should be used."""
        import yaml
        first = tmp_path / "first.yaml"
        second = tmp_path / "second.yaml"
        first.write_text(yaml.dump({"constitution": {"name": "first"}}))
        second.write_text(yaml.dump({"constitution": {"name": "second"}}))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS",
                            [str(first), str(second)])
        result = clanet_cli._load_constitution()
        assert result["constitution"]["name"] == "first"


# ---------------------------------------------------------------------------
# Constitution check
# ---------------------------------------------------------------------------


class TestConstitutionCheck:
    """Tests for _constitution_check() enforcement."""

    def _make_constitution(self, tmp_path, monkeypatch, rules):
        """Helper to set up a constitution file with given rules."""
        import yaml
        const = {
            "constitution": {"name": "test", "version": "1.0"},
            "rules": rules,
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])

    def test_no_file_passes(self, monkeypatch):
        """No constitution file → no check, no error."""
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS",
                            ["/nonexistent/path/constitution.yaml"])
        clanet_cli._constitution_check(["write erase"])  # Should not raise

    def test_violation_detected(self, tmp_path, monkeypatch):
        """Violating command should raise ConfigError."""
        self._make_constitution(tmp_path, monkeypatch, {
            "safety": [{
                "id": "CONST-SAF-002",
                "name": "No write erase",
                "severity": "CRITICAL",
                "reason": "Destroys all config.",
                "pattern_deny": r"write\s+erase",
            }]
        })
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli._constitution_check(["write erase"])

    def test_safe_commands_pass(self, tmp_path, monkeypatch):
        """Safe commands should pass without error."""
        self._make_constitution(tmp_path, monkeypatch, {
            "safety": [{
                "id": "CONST-SAF-002",
                "name": "No write erase",
                "severity": "CRITICAL",
                "reason": "Destroys all config.",
                "pattern_deny": r"write\s+erase",
            }]
        })
        clanet_cli._constitution_check(["interface Gi0/1", "description test"])

    def test_pattern_allow_exception(self, tmp_path, monkeypatch):
        """pattern_allow should override pattern_deny."""
        self._make_constitution(tmp_path, monkeypatch, {
            "security": [{
                "id": "CONST-SEC-001",
                "name": "No telnet",
                "severity": "CRITICAL",
                "reason": "Telnet is insecure.",
                "pattern_deny": r"transport input.*telnet",
                "pattern_allow": r"transport input ssh",
            }]
        })
        # "transport input ssh" matches allow → should pass
        clanet_cli._constitution_check(["transport input ssh"])
        # "transport input telnet" → should fail
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli._constitution_check(["transport input telnet"])

    def test_multiple_violations(self, tmp_path, monkeypatch, capsys):
        """Multiple violations should all be reported."""
        self._make_constitution(tmp_path, monkeypatch, {
            "safety": [
                {
                    "id": "CONST-SAF-002",
                    "name": "No write erase",
                    "severity": "CRITICAL",
                    "reason": "Destroys all config.",
                    "pattern_deny": r"write\s+erase",
                },
                {
                    "id": "CONST-SAF-003",
                    "name": "No reload",
                    "severity": "CRITICAL",
                    "reason": "Unsafe reload.",
                    "pattern_deny": r"^\s*reload\s*$",
                },
            ]
        })
        with pytest.raises(clanet_cli.ConfigError, match="2 constitutional violation"):
            clanet_cli._constitution_check(["write erase", "reload"])
        captured = capsys.readouterr()
        assert "CONST-SAF-002" in captured.err
        assert "CONST-SAF-003" in captured.err

    def test_reason_displayed(self, tmp_path, monkeypatch, capsys):
        """Reason field should be printed to stderr."""
        self._make_constitution(tmp_path, monkeypatch, {
            "safety": [{
                "id": "CONST-SAF-002",
                "name": "No write erase",
                "severity": "CRITICAL",
                "reason": "Destroys all config.",
                "pattern_deny": r"write\s+erase",
            }]
        })
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli._constitution_check(["write erase"])
        captured = capsys.readouterr()
        assert "Destroys all config." in captured.err

    def test_empty_rules_passes(self, tmp_path, monkeypatch):
        """Constitution with empty rules section should pass."""
        self._make_constitution(tmp_path, monkeypatch, {})
        clanet_cli._constitution_check(["write erase"])  # Should not raise


# ---------------------------------------------------------------------------
# Constitution integration with cmd_config / cmd_config_load
# ---------------------------------------------------------------------------


class TestConstitutionIntegration:
    """Integration tests: constitution blocks config commands."""

    def _setup(self, tmp_path, monkeypatch):
        """Set up inventory + constitution for integration tests."""
        import yaml
        # Inventory
        inv = {
            "devices": {
                "router01": {
                    "host": "192.168.1.1",
                    "device_type": "cisco_ios",
                    "username": "admin",
                    "password": "admin",
                }
            }
        }
        inv_file = tmp_path / "inventory.yaml"
        inv_file.write_text(yaml.dump(inv))
        monkeypatch.setattr(clanet_cli, "INVENTORY_PATHS", [str(inv_file)])

        # Constitution
        const = {
            "rules": {
                "safety": [{
                    "id": "CONST-SAF-002",
                    "name": "No write erase",
                    "severity": "CRITICAL",
                    "reason": "Destroys config.",
                    "pattern_deny": r"write\s+erase",
                }]
            }
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])

    def test_cmd_config_blocked(self, tmp_path, monkeypatch):
        """cmd_config should be blocked by constitution."""
        self._setup(tmp_path, monkeypatch)
        args = argparse.Namespace(
            device="router01",
            commands='["write erase"]',
            skip_compliance=False,
            no_backup=True,
        )
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli.cmd_config(args)

    def test_cmd_config_not_skippable(self, tmp_path, monkeypatch):
        """--skip-compliance should NOT skip constitution check."""
        self._setup(tmp_path, monkeypatch)
        args = argparse.Namespace(
            device="router01",
            commands='["write erase"]',
            skip_compliance=True,
            no_backup=True,
        )
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli.cmd_config(args)

    def test_cmd_config_load_blocked(self, tmp_path, monkeypatch):
        """cmd_config_load should be blocked by constitution."""
        self._setup(tmp_path, monkeypatch)
        config_file = tmp_path / "bad.cfg"
        config_file.write_text("write erase\n")
        args = argparse.Namespace(
            device="router01",
            file=str(config_file),
            skip_compliance=False,
            no_backup=True,
        )
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli.cmd_config_load(args)

    def test_cmd_config_load_not_skippable(self, tmp_path, monkeypatch):
        """--skip-compliance should NOT skip constitution check on config-load."""
        self._setup(tmp_path, monkeypatch)
        config_file = tmp_path / "bad.cfg"
        config_file.write_text("write erase\n")
        args = argparse.Namespace(
            device="router01",
            file=str(config_file),
            skip_compliance=True,
            no_backup=True,
        )
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli.cmd_config_load(args)


# ---------------------------------------------------------------------------
# Default constitution template validation
# ---------------------------------------------------------------------------


class TestDefaultConstitutionTemplate:
    """Validate the shipped constitution template."""

    def test_template_is_valid_yaml(self):
        """templates/constitution.yaml should be valid YAML."""
        import yaml
        template_path = Path(__file__).parent.parent / "templates" / "constitution.yaml"
        with open(template_path) as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)
        assert "rules" in data

    def test_all_rules_have_required_fields(self):
        """Every rule must have id, name, reason, and pattern_deny or rule."""
        import yaml
        template_path = Path(__file__).parent.parent / "templates" / "constitution.yaml"
        with open(template_path) as f:
            data = yaml.safe_load(f)
        for category, rule_list in data["rules"].items():
            for rule in rule_list:
                assert "id" in rule, f"rule in {category} missing 'id'"
                assert "name" in rule, f"{rule.get('id', '?')} missing 'name'"
                assert "reason" in rule, f"{rule['id']} missing 'reason'"
                has_pattern = "pattern_deny" in rule
                has_rule = "rule" in rule
                assert has_pattern or has_rule, (
                    f"{rule['id']} missing both 'pattern_deny' and 'rule'"
                )

    def test_all_ids_are_unique(self):
        """Rule IDs must be globally unique."""
        import yaml
        template_path = Path(__file__).parent.parent / "templates" / "constitution.yaml"
        with open(template_path) as f:
            data = yaml.safe_load(f)
        ids = []
        for _category, rule_list in data["rules"].items():
            for rule in rule_list:
                ids.append(rule["id"])
        assert len(ids) == len(set(ids)), f"duplicate IDs: {ids}"

    def test_patterns_are_valid_regex(self):
        """All pattern_deny and pattern_allow must be valid regex."""
        import yaml
        template_path = Path(__file__).parent.parent / "templates" / "constitution.yaml"
        with open(template_path) as f:
            data = yaml.safe_load(f)
        import re
        for _category, rule_list in data["rules"].items():
            for rule in rule_list:
                if "pattern_deny" not in rule:
                    continue  # rule-only entries have no regex
                re.compile(rule["pattern_deny"])
                if "pattern_allow" in rule:
                    re.compile(rule["pattern_allow"])


# ---------------------------------------------------------------------------
# Constitution LLM rules (rule-only entries)
# ---------------------------------------------------------------------------


class TestConstitutionLLMRules:
    """Tests for rule-only (natural language) constitution entries."""

    def _make_constitution(self, tmp_path, monkeypatch, rules):
        """Helper to set up a constitution file with given rules."""
        import yaml
        const = {
            "constitution": {"name": "test", "version": "1.0"},
            "rules": rules,
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])

    def test_rule_only_does_not_block(self, tmp_path, monkeypatch):
        """rule-only entry should NOT raise ConfigError (CLI cannot evaluate)."""
        self._make_constitution(tmp_path, monkeypatch, {
            "intent": [{
                "id": "CONST-INT-001",
                "name": "No single point of failure",
                "severity": "CRITICAL",
                "reason": "Redundancy required.",
                "rule": "Reject any config that creates a single point of failure.",
            }]
        })
        # Should not raise
        clanet_cli._constitution_check(["no ntp server 10.0.0.1"])

    def test_rule_only_prints_warning(self, tmp_path, monkeypatch, capsys):
        """rule-only entry should print a warning to stderr."""
        self._make_constitution(tmp_path, monkeypatch, {
            "intent": [{
                "id": "CONST-INT-001",
                "name": "No single point of failure",
                "severity": "CRITICAL",
                "reason": "Redundancy required.",
                "rule": "Reject any config that creates a single point of failure.",
            }]
        })
        clanet_cli._constitution_check(["no ntp server 10.0.0.1"])
        captured = capsys.readouterr()
        assert "1 rule(s) require LLM evaluation" in captured.err
        assert "CONST-INT-001" in captured.err
        assert "/clanet:team" in captured.err

    def test_hybrid_rule_still_checks_regex(self, tmp_path, monkeypatch):
        """Hybrid entry (pattern_deny + rule) should still enforce regex."""
        self._make_constitution(tmp_path, monkeypatch, {
            "safety": [{
                "id": "CONST-SAF-003",
                "name": "No wildcard ACL",
                "severity": "CRITICAL",
                "reason": "Security hole.",
                "pattern_deny": r"permit\s+(ip\s+)?any\s+any",
                "rule": "Reject overly permissive ACLs.",
            }]
        })
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli._constitution_check(["permit ip any any"])

    def test_hybrid_rule_passes_when_no_regex_match(self, tmp_path, monkeypatch):
        """Hybrid entry should pass when regex does not match."""
        self._make_constitution(tmp_path, monkeypatch, {
            "safety": [{
                "id": "CONST-SAF-003",
                "name": "No wildcard ACL",
                "severity": "CRITICAL",
                "reason": "Security hole.",
                "pattern_deny": r"permit\s+(ip\s+)?any\s+any",
                "rule": "Reject overly permissive ACLs.",
            }]
        })
        # Specific ACL should pass regex check
        clanet_cli._constitution_check(["permit ip host 10.0.0.1 any"])

    def test_multiple_rule_only_entries_all_warned(self, tmp_path, monkeypatch, capsys):
        """Multiple rule-only entries should all appear in warnings."""
        self._make_constitution(tmp_path, monkeypatch, {
            "intent": [
                {
                    "id": "CONST-INT-001",
                    "name": "No single point of failure",
                    "severity": "CRITICAL",
                    "reason": "Redundancy required.",
                    "rule": "Reject single point of failure.",
                },
                {
                    "id": "CONST-INT-002",
                    "name": "Change scope must match task",
                    "severity": "CRITICAL",
                    "reason": "Scope check.",
                    "rule": "Reject unrelated changes.",
                },
            ]
        })
        clanet_cli._constitution_check(["ntp server 10.0.0.1"])
        captured = capsys.readouterr()
        assert "2 rule(s) require LLM evaluation" in captured.err
        assert "CONST-INT-001" in captured.err
        assert "CONST-INT-002" in captured.err

    def test_rule_only_with_pattern_deny_violation(self, tmp_path, monkeypatch):
        """pattern_deny violation blocks regardless of rule field presence elsewhere."""
        self._make_constitution(tmp_path, monkeypatch, {
            "safety": [{
                "id": "CONST-SAF-001",
                "name": "No write erase",
                "severity": "CRITICAL",
                "reason": "Destructive.",
                "pattern_deny": r"write\s+erase",
            }],
            "intent": [{
                "id": "CONST-INT-001",
                "name": "No single point of failure",
                "severity": "CRITICAL",
                "reason": "Redundancy.",
                "rule": "Reject single point of failure.",
            }],
        })
        with pytest.raises(clanet_cli.ConfigError, match="constitutional violation"):
            clanet_cli._constitution_check(["write erase"])


# ---------------------------------------------------------------------------
# has_llm_rules()
# ---------------------------------------------------------------------------


class TestHasLLMRules:
    """Tests for has_llm_rules() function."""

    def test_no_file_returns_empty(self, monkeypatch):
        """No constitution file → empty list."""
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS",
                            ["/nonexistent/constitution.yaml"])
        assert clanet_cli.has_llm_rules() == []

    def test_no_rule_field_returns_empty(self, tmp_path, monkeypatch):
        """Constitution with only pattern_deny → empty list."""
        import yaml
        const = {
            "rules": {
                "safety": [{
                    "id": "CONST-SAF-001",
                    "name": "No write erase",
                    "severity": "CRITICAL",
                    "reason": "Destructive.",
                    "pattern_deny": r"write\s+erase",
                }]
            }
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])
        assert clanet_cli.has_llm_rules() == []

    def test_rule_field_detected(self, tmp_path, monkeypatch):
        """Rules with 'rule' field should be returned."""
        import yaml
        const = {
            "rules": {
                "safety": [{
                    "id": "CONST-SAF-001",
                    "name": "No write erase",
                    "severity": "CRITICAL",
                    "reason": "Destructive.",
                    "pattern_deny": r"write\s+erase",
                }],
                "intent": [{
                    "id": "CONST-INT-001",
                    "name": "No SPOF",
                    "severity": "CRITICAL",
                    "reason": "Redundancy.",
                    "rule": "Reject single point of failure.",
                }],
            }
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])
        result = clanet_cli.has_llm_rules()
        assert len(result) == 1
        assert result[0]["id"] == "CONST-INT-001"


# ---------------------------------------------------------------------------
# constitution-rules subcommand
# ---------------------------------------------------------------------------


class TestConstitutionRulesCommand:
    """Tests for cmd_constitution_rules subcommand."""

    def test_no_file_returns_empty_json(self, monkeypatch, capsys):
        """No constitution file → empty JSON output."""
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS",
                            ["/nonexistent/constitution.yaml"])
        args = argparse.Namespace(llm_only=False)
        clanet_cli.cmd_constitution_rules(args)
        output = json.loads(capsys.readouterr().out)
        assert output["constitution"] is None
        assert output["rules"] == []
        assert output["total"] == 0

    def test_all_rules_returned(self, tmp_path, monkeypatch, capsys):
        """All rules should be returned as JSON."""
        import yaml
        const = {
            "constitution": {"name": "test", "version": "1.0"},
            "rules": {
                "safety": [{
                    "id": "CONST-SAF-001",
                    "name": "No write erase",
                    "severity": "CRITICAL",
                    "reason": "Destructive.",
                    "pattern_deny": r"write\s+erase",
                }],
                "intent": [{
                    "id": "CONST-INT-001",
                    "name": "No SPOF",
                    "severity": "CRITICAL",
                    "reason": "Redundancy.",
                    "rule": "Reject single point of failure.",
                }],
            },
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])
        args = argparse.Namespace(llm_only=False)
        clanet_cli.cmd_constitution_rules(args)
        output = json.loads(capsys.readouterr().out)
        assert output["total"] == 2
        assert output["constitution"]["name"] == "test"
        ids = [r["id"] for r in output["rules"]]
        assert "CONST-SAF-001" in ids
        assert "CONST-INT-001" in ids

    def test_llm_only_filter(self, tmp_path, monkeypatch, capsys):
        """--llm-only should only return rules with 'rule' field."""
        import yaml
        const = {
            "constitution": {"name": "test", "version": "1.0"},
            "rules": {
                "safety": [{
                    "id": "CONST-SAF-001",
                    "name": "No write erase",
                    "severity": "CRITICAL",
                    "reason": "Destructive.",
                    "pattern_deny": r"write\s+erase",
                }],
                "intent": [{
                    "id": "CONST-INT-001",
                    "name": "No SPOF",
                    "severity": "CRITICAL",
                    "reason": "Redundancy.",
                    "rule": "Reject single point of failure.",
                }],
            },
        }
        const_file = tmp_path / "constitution.yaml"
        const_file.write_text(yaml.dump(const))
        monkeypatch.setattr(clanet_cli, "CONSTITUTION_PATHS", [str(const_file)])
        args = argparse.Namespace(llm_only=True)
        clanet_cli.cmd_constitution_rules(args)
        output = json.loads(capsys.readouterr().out)
        assert output["total"] == 1
        assert output["rules"][0]["id"] == "CONST-INT-001"


# ---------------------------------------------------------------------------
# Policy LLM rules (rule-only entries)
# ---------------------------------------------------------------------------


class TestPolicyLLMRules:
    """Tests for rule-only (natural language) policy entries."""

    def test_rule_only_skipped_in_evaluate_rule(self):
        """rule-only entry should return SKIP in _evaluate_rule."""
        rule = {
            "id": "SEM-001",
            "name": "Semantic check",
            "severity": "MEDIUM",
            "rule": "Check something with LLM.",
        }
        status, detail = clanet_cli._evaluate_rule(rule, "hostname router01")
        assert status == "SKIP"
        assert "LLM" in detail

    def test_rule_only_skipped_in_evaluate_rule_for_commands(self):
        """rule-only entry with scope=config_commands should SKIP in _evaluate_rule_for_commands."""
        rule = {
            "id": "SEM-001",
            "name": "Semantic check",
            "scope": "config_commands",
            "rule": "Check something with LLM.",
        }
        status, detail = clanet_cli._evaluate_rule_for_commands(
            rule, "interface Gi0/1\ndescription test"
        )
        assert status == "SKIP"
        assert "LLM" in detail

    def test_hybrid_rule_still_checks_regex(self):
        """Hybrid entry (pattern_deny + rule) should still enforce regex."""
        rule = {
            "scope": "config_commands",
            "pattern_deny": r"no logging\b.*",
            "pattern_allow": r"no logging console",
            "rule": "Reject config that disables all logging.",
        }
        # "no logging 10.0.0.1" matches deny but not allow → FAIL
        status, _ = clanet_cli._evaluate_rule_for_commands(
            rule, "no logging 10.0.0.1"
        )
        assert status == "FAIL"

    def test_hybrid_rule_passes_when_allowed(self):
        """Hybrid entry should pass when allow exception matches."""
        rule = {
            "scope": "config_commands",
            "pattern_deny": r"no logging\b.*",
            "pattern_allow": r"no logging console",
            "rule": "Reject config that disables all logging.",
        }
        status, _ = clanet_cli._evaluate_rule_for_commands(
            rule, "no logging console"
        )
        assert status == "PASS"

    def test_audit_rule_only_skipped(self):
        """rule-only entry without scope should SKIP in _evaluate_rule (audit)."""
        rule = {
            "id": "SEM-099",
            "name": "Audit semantic check",
            "rule": "Check running config semantically.",
        }
        status, detail = clanet_cli._evaluate_rule(
            rule, "hostname router01\nntp server 10.0.0.1"
        )
        assert status == "SKIP"
        assert "rule-only" in detail


# ---------------------------------------------------------------------------
# has_policy_llm_rules()
# ---------------------------------------------------------------------------


class TestHasPolicyLLMRules:
    """Tests for has_policy_llm_rules() function."""

    def test_no_file_returns_empty(self, tmp_path, monkeypatch):
        """No policy file → empty list."""
        monkeypatch.setattr(clanet_cli, "_config",
                            {"policy_file": str(tmp_path / "nonexistent.yaml")})
        assert clanet_cli.has_policy_llm_rules() == []

    def test_no_rule_field_returns_empty(self, tmp_path, monkeypatch):
        """Policy with only regex rules → empty list."""
        import yaml
        policy = {
            "rules": {
                "safety": [{
                    "id": "SAF-001",
                    "name": "Mgmt protection",
                    "severity": "CRITICAL",
                    "pattern_deny": "interface Mgmt",
                    "scope": "config_commands",
                }]
            }
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "_config",
                            {"policy_file": str(policy_file)})
        assert clanet_cli.has_policy_llm_rules() == []

    def test_rule_field_detected(self, tmp_path, monkeypatch):
        """Rules with 'rule' field should be returned."""
        import yaml
        policy = {
            "rules": {
                "safety": [{
                    "id": "SAF-001",
                    "name": "Mgmt protection",
                    "severity": "CRITICAL",
                    "pattern_deny": "interface Mgmt",
                    "scope": "config_commands",
                }],
                "semantic": [{
                    "id": "SEM-001",
                    "name": "Semantic check",
                    "severity": "MEDIUM",
                    "rule": "Check something with LLM.",
                    "scope": "config_commands",
                }],
            }
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "_config",
                            {"policy_file": str(policy_file)})
        result = clanet_cli.has_policy_llm_rules()
        assert len(result) == 1
        assert result[0]["id"] == "SEM-001"

    def test_hybrid_rule_detected(self, tmp_path, monkeypatch):
        """Hybrid rules (pattern_deny + rule) should also be returned."""
        import yaml
        policy = {
            "rules": {
                "safety": [{
                    "id": "SAF-003",
                    "name": "No disabling logging",
                    "severity": "HIGH",
                    "pattern_deny": "no logging",
                    "rule": "Reject config that disables all logging.",
                    "scope": "config_commands",
                }],
            }
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "_config",
                            {"policy_file": str(policy_file)})
        result = clanet_cli.has_policy_llm_rules()
        assert len(result) == 1
        assert result[0]["id"] == "SAF-003"

    def test_default_policy_has_llm_rules(self, monkeypatch):
        """Default templates/policy.yaml should have LLM rules after update."""
        monkeypatch.setattr(clanet_cli, "_config", {"policy_file": None})
        monkeypatch.chdir(Path(__file__).parent.parent)
        result = clanet_cli.has_policy_llm_rules()
        assert len(result) >= 2  # SEM-001, SEM-002, and possibly SAF-003
        ids = [r["id"] for r in result]
        assert "SEM-001" in ids
        assert "SEM-002" in ids


# ---------------------------------------------------------------------------
# Pre-apply compliance warning for rule-only entries
# ---------------------------------------------------------------------------


class TestPreApplyComplianceWarning:
    """Tests that _pre_apply_compliance() warns about rule-only policy entries."""

    def test_rule_only_warning_printed(self, tmp_path, monkeypatch, capsys):
        """rule-only entries should produce a warning to stderr."""
        import yaml
        policy = {
            "rules": {
                "semantic": [{
                    "id": "SEM-001",
                    "name": "Interface description check",
                    "severity": "MEDIUM",
                    "rule": "Check interface has description.",
                    "scope": "config_commands",
                }]
            }
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "get_config",
                            lambda: {"policy_file": str(policy_file)})
        clanet_cli._pre_apply_compliance(["interface Gi0/1", "no shutdown"])
        captured = capsys.readouterr()
        assert "[POLICY]" in captured.err
        assert "1 rule(s) require LLM evaluation" in captured.err
        assert "SEM-001" in captured.err

    def test_no_warning_when_no_rule_only(self, tmp_path, monkeypatch, capsys):
        """No rule-only entries → no warning."""
        import yaml
        policy = {
            "rules": {
                "safety": [{
                    "id": "SAF-001",
                    "name": "Mgmt protection",
                    "severity": "CRITICAL",
                    "pattern_deny": "interface Mgmt",
                    "scope": "config_commands",
                }]
            }
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "get_config",
                            lambda: {"policy_file": str(policy_file)})
        clanet_cli._pre_apply_compliance(["interface Gi0/1", "no shutdown"])
        captured = capsys.readouterr()
        assert "[POLICY]" not in captured.err

    def test_hybrid_not_warned_as_rule_only(self, tmp_path, monkeypatch, capsys):
        """Hybrid rules (pattern_deny + rule) should NOT be warned as rule-only."""
        import yaml
        policy = {
            "rules": {
                "safety": [{
                    "id": "SAF-003",
                    "name": "No disabling logging",
                    "severity": "HIGH",
                    "pattern_deny": "no logging",
                    "pattern_allow": "no logging console",
                    "rule": "Reject config that disables all logging.",
                    "scope": "config_commands",
                }]
            }
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "get_config",
                            lambda: {"policy_file": str(policy_file)})
        clanet_cli._pre_apply_compliance(["ntp server 10.0.0.1"])
        captured = capsys.readouterr()
        assert "[POLICY]" not in captured.err


# ---------------------------------------------------------------------------
# policy-rules subcommand
# ---------------------------------------------------------------------------


class TestPolicyRulesCommand:
    """Tests for cmd_policy_rules subcommand."""

    def test_no_file_returns_empty_json(self, tmp_path, monkeypatch, capsys):
        """No policy file → empty JSON output."""
        monkeypatch.setattr(clanet_cli, "_config",
                            {"policy_file": str(tmp_path / "nonexistent.yaml")})
        args = argparse.Namespace(llm_only=False)
        clanet_cli.cmd_policy_rules(args)
        output = json.loads(capsys.readouterr().out)
        assert output["policy"] is None
        assert output["rules"] == []
        assert output["total"] == 0

    def test_all_rules_returned(self, tmp_path, monkeypatch, capsys):
        """All rules should be returned as JSON."""
        import yaml
        policy = {
            "policy": {"name": "test-policy", "version": "1.0"},
            "rules": {
                "safety": [{
                    "id": "SAF-001",
                    "name": "Mgmt protection",
                    "severity": "CRITICAL",
                    "pattern_deny": "interface Mgmt",
                    "scope": "config_commands",
                }],
                "semantic": [{
                    "id": "SEM-001",
                    "name": "Semantic check",
                    "severity": "MEDIUM",
                    "rule": "Check with LLM.",
                    "scope": "config_commands",
                }],
            },
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "_config",
                            {"policy_file": str(policy_file)})
        args = argparse.Namespace(llm_only=False)
        clanet_cli.cmd_policy_rules(args)
        output = json.loads(capsys.readouterr().out)
        assert output["total"] == 2
        assert output["policy"]["name"] == "test-policy"
        ids = [r["id"] for r in output["rules"]]
        assert "SAF-001" in ids
        assert "SEM-001" in ids

    def test_llm_only_filter(self, tmp_path, monkeypatch, capsys):
        """--llm-only should only return rules with 'rule' field."""
        import yaml
        policy = {
            "policy": {"name": "test-policy", "version": "1.0"},
            "rules": {
                "safety": [{
                    "id": "SAF-001",
                    "name": "Mgmt protection",
                    "severity": "CRITICAL",
                    "pattern_deny": "interface Mgmt",
                    "scope": "config_commands",
                }],
                "semantic": [{
                    "id": "SEM-001",
                    "name": "Semantic check",
                    "severity": "MEDIUM",
                    "rule": "Check with LLM.",
                    "scope": "config_commands",
                }],
            },
        }
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml.dump(policy))
        monkeypatch.setattr(clanet_cli, "_config",
                            {"policy_file": str(policy_file)})
        args = argparse.Namespace(llm_only=True)
        clanet_cli.cmd_policy_rules(args)
        output = json.loads(capsys.readouterr().out)
        assert output["total"] == 1
        assert output["rules"][0]["id"] == "SEM-001"

    def test_parser_registered(self):
        """policy-rules subcommand should be registered in build_parser."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["policy-rules"])
        assert args.command == "policy-rules"

    def test_parser_llm_only_flag(self):
        """--llm-only flag should be parsed."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["policy-rules", "--llm-only"])
        assert args.llm_only is True
