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
    """Tests that policies/health.yaml is valid and has expected structure."""

    @pytest.fixture
    def health_config(self):
        import yaml
        health_path = Path(__file__).parent.parent / "policies" / "health.yaml"
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
        """_load_health_config() should load from policies/health.yaml."""
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

    def test_config_command(self):
        args = self.parser.parse_args([
            "config", "router01", "--commands", '["ntp server 10.0.0.1"]'
        ])
        assert args.device == "router01"
        assert args.commands == '["ntp server 10.0.0.1"]'

    def test_check_all(self):
        args = self.parser.parse_args(["check", "--all"])
        assert args.all_devices is True

    def test_backup_single(self):
        args = self.parser.parse_args(["backup", "router01"])
        assert args.device == "router01"

    def test_session_with_action(self):
        args = self.parser.parse_args(["session", "router01", "prompt"])
        assert args.device == "router01"
        assert args.action == "prompt"

    def test_session_default_action(self):
        args = self.parser.parse_args(["session", "router01"])
        assert args.action == "status"

    def test_mode_command(self):
        args = self.parser.parse_args(["mode", "router01", "config"])
        assert args.device == "router01"
        assert args.action == "config"

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

    def test_deploy_command(self):
        args = self.parser.parse_args(["deploy", "router01", "config.cfg"])
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
        args = self.parser.parse_args(["check", "--all"])
        assert clanet_cli._resolve_device_arg(args) == "--all"

    def test_device_name(self):
        args = self.parser.parse_args(["check", "router01"])
        assert clanet_cli._resolve_device_arg(args) == "router01"

    def test_no_args_defaults_to_all(self):
        args = self.parser.parse_args(["check"])
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
    """Tests that policies/example.yaml is valid YAML with expected structure."""

    @pytest.fixture
    def default_policy(self):
        import yaml
        policy_path = Path(__file__).parent.parent / "policies" / "example.yaml"
        with open(policy_path) as f:
            return yaml.safe_load(f)

    def test_policy_file_loads(self, default_policy):
        """example.yaml must be valid YAML with policy and rules sections."""
        assert "policy" in default_policy
        assert "rules" in default_policy

    def test_policy_has_expected_categories(self, default_policy):
        """example.yaml must define security, safety, and standards categories."""
        rules = default_policy["rules"]
        assert "security" in rules
        assert "safety" in rules
        assert "standards" in rules

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
        with pytest.raises(clanet_cli.DeviceConnectionError):
            clanet_cli.connect({"device_type": "cisco_ios", "host": "1.1.1.1",
                                "username": "admin", "password": "admin"})

    def test_connect_missing_fields(self):
        """connect() should raise DeviceConnectionError when required fields are missing."""
        with pytest.raises(clanet_cli.DeviceConnectionError):
            clanet_cli.connect({"host": "1.1.1.1"})

    def test_connect_missing_password(self):
        """connect() should raise DeviceConnectionError when password is missing."""
        with pytest.raises(clanet_cli.DeviceConnectionError):
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

    def test_interact_invalid_json(self, mock_inventory):
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["interact", "router01", "--commands", "{bad}"])
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

    def test_cmd_deploy_ios(self, patched_env, capsys, tmp_path, monkeypatch):
        """Deploy config from file to IOS device."""
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        config_file = tmp_path / "deploy.cfg"
        config_file.write_text("ntp server 10.0.0.1\n")
        patched_env.send_config_from_file.return_value = "config applied from file"
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["deploy", "router01", str(config_file)])
        clanet_cli.cmd_deploy(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        patched_env.send_config_from_file.assert_called_once()

    def test_cmd_deploy_xr_commits(self, mock_inventory, mock_conn, monkeypatch,
                                    capsys, tmp_path):
        """Deploy to IOS-XR should call commit()."""
        monkeypatch.setattr(clanet_cli, "connect", lambda dev: mock_conn)
        monkeypatch.setattr(clanet_cli, "DIRS", {
            "logs": str(tmp_path / "logs"),
        })
        config_file = tmp_path / "deploy.cfg"
        config_file.write_text("router ospf 1\n")
        mock_conn.send_config_from_file.return_value = "config applied"
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["deploy", "router02", str(config_file)])
        clanet_cli.cmd_deploy(args)
        mock_conn.commit.assert_called_once()
        mock_conn.exit_config_mode.assert_called_once()

    def test_cmd_deploy_file_not_found(self, mock_inventory, capsys):
        """Deploy with nonexistent file should raise ConfigError."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["deploy", "router01", "/nonexistent/config.cfg"])
        with pytest.raises(clanet_cli.ConfigError):
            clanet_cli.cmd_deploy(args)

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

    def test_cmd_mode_enable(self, patched_env, capsys):
        """Mode enable should call conn.enable()."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["mode", "router01", "enable"])
        clanet_cli.cmd_mode(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        patched_env.enable.assert_called_once()

    def test_cmd_mode_config(self, patched_env, capsys):
        """Mode config should call conn.config_mode()."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["mode", "router01", "config"])
        clanet_cli.cmd_mode(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        patched_env.config_mode.assert_called_once()

    def test_cmd_mode_exit_config(self, patched_env, capsys):
        """Mode exit-config should call conn.exit_config_mode()."""
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["mode", "router01", "exit-config"])
        clanet_cli.cmd_mode(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        patched_env.exit_config_mode.assert_called_once()

    def test_cmd_mode_check(self, patched_env, capsys):
        """Mode check should report enable/config mode status."""
        patched_env.check_enable_mode.return_value = True
        patched_env.check_config_mode.return_value = False
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["mode", "router01", "check"])
        clanet_cli.cmd_mode(args)
        captured = capsys.readouterr()
        assert "Enable mode: True" in captured.out
        assert "Config mode: False" in captured.out

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

    def test_cmd_session_status(self, mock_inventory, monkeypatch, capsys):
        """Session status should check TCP port."""
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0

        def mock_socket_cls(*args, **kwargs):
            return mock_socket

        monkeypatch.setattr(clanet_cli.socket, "socket", mock_socket_cls)
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["session", "router01"])
        clanet_cli.cmd_session(args)
        captured = capsys.readouterr()
        assert "[OK]" in captured.out
        assert "SSH port open" in captured.out

    def test_cmd_session_port_closed(self, mock_inventory, monkeypatch, capsys):
        """Session should report closed port."""
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1

        def mock_socket_cls(*args, **kwargs):
            return mock_socket

        monkeypatch.setattr(clanet_cli.socket, "socket", mock_socket_cls)
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["session", "router01"])
        clanet_cli.cmd_session(args)
        captured = capsys.readouterr()
        assert "[FAIL]" in captured.out

    def test_cmd_check_health(self, patched_env, capsys, monkeypatch):
        """Health check should run vendor-specific commands."""
        monkeypatch.setattr(clanet_cli, "_config", {
            "health_file": None, "read_timeout": 30, "read_timeout_long": 60,
        })
        monkeypatch.chdir(Path(__file__).parent.parent)
        parser = clanet_cli.build_parser()
        args = parser.parse_args(["check", "router01"])
        clanet_cli.cmd_check(args)
        captured = capsys.readouterr()
        assert "Health Check: router01" in captured.out
        assert "[OK]" in captured.out

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
