---
description: "[internal] Safety framework for all config-changing commands"
argument-hint: ""
allowed-tools: []
---

# clanet Safety Guide

**This file is NOT a user-facing command.** It is referenced by all config-changing commands
(config, config-load, cmd-interact, save, commit) as a shared safety framework.

## Safety First Philosophy

clanet follows the principle: **"Show, Explain, Confirm, Verify"**.
Every configuration change goes through 4 phases before and after execution.

---

## Phase 1: SHOW - Display exactly what will be applied

Before any config change, present a clear change summary:

```
+----------------------------------------------------------+
|  clanet: Configuration Change Request                     |
+----------------------------------------------------------+
|  Device:    router01 (192.168.1.1)                       |
|  Type:      cisco_xr                                     |
|  Action:    Send 3 configuration commands                |
+----------------------------------------------------------+
|                                                          |
|  Commands to apply:                                      |
|                                                          |
|    1. interface GigabitEthernet0/0/0/0                   |
|    2.   description Link-to-OsakaP01                     |
|    3.   mtu 9000                                         |
|                                                          |
+----------------------------------------------------------+
```

## Phase 2: EXPLAIN - Impact analysis

Claude MUST analyze and explain:

- **What changes**: Plain language description of what each command does
- **What is affected**: Which interfaces, protocols, or services will be impacted
- **Risk level**: LOW / MEDIUM / HIGH / CRITICAL

### Risk Level Criteria

| Level | Criteria | Examples |
|-------|----------|---------|
| **LOW** | Description changes, logging, NTP, cosmetic | `description`, `ntp server`, `banner` |
| **MEDIUM** | Protocol parameters, timers, metrics | `ospf cost`, `bgp timers`, `mtu` |
| **HIGH** | Enable/disable protocols, add/remove neighbors | `router ospf`, `neighbor x.x.x.x`, `shutdown` |
| **CRITICAL** | Management access, routing table impact, reload | management IP, VTY ACL, `no router`, `reload` |

Example output:
```
Risk Assessment: MEDIUM

What this change does:
- Sets interface description to "Link-to-OsakaP01" (cosmetic, no impact)
- Changes MTU from 1514 to 9000 (will cause brief traffic drop during MTU change)

Affected services:
- Traffic on GigabitEthernet0/0/0/0 may drop for 1-2 seconds during MTU change
- OSPF adjacency on this interface may flap if neighbor MTU doesn't match
```

## Phase 3: CONFIRM - Explicit user approval

Use AskUserQuestion with clear options:

```
Apply this configuration to router01?

  [Apply]          - Execute the configuration change
  [Apply + Verify] - Execute and run post-change verification (recommended)
  [Edit]           - Modify the commands before applying
  [Cancel]         - Abort without changes
```

**For HIGH/CRITICAL risk changes, add extra warning:**
```
WARNING: This is a HIGH risk change.
- OSPF adjacency may flap
- Traffic disruption expected on Gi0/0/0/0

Type the device name "router01" to confirm:
```

## Phase 4: VERIFY - Post-change check

After successful application, automatically run:

1. Check the changed interface/feature is in expected state
2. Verify no unexpected protocol flaps
3. Show before/after comparison if applicable

```
Post-Change Verification:
  [OK] Interface Gi0/0/0/0: Up/Up, MTU 9000
  [OK] OSPF neighbor on Gi0/0/0/0: FULL
  [OK] No errors in last 30 seconds
```

---

## Constitutional Rules

**Constitutional rules are absolute and cannot be skipped.**

Unlike compliance policies (which can be bypassed with `--skip-compliance`), constitutional rules defined in `constitution.yaml` are enforced unconditionally by the CLI engine. No flag, option, or override can bypass them.

### How It Works

1. Place `constitution.yaml` in the project root or `~/.constitution.yaml`
2. Define rules with `pattern_deny` (and optional `pattern_allow`)
3. The CLI checks all config commands against constitutional rules **before** any other safety gate
4. If a violation is found, the operation is blocked with `[CONSTITUTION VIOLATION]`

### Safety Gate Order

```
0. _constitution_check()        ← Constitutional rules (NEVER skippable)
1. _check_lockout()             ← Self-lockout prevention (not skippable)
2. _pre_apply_compliance()      ← Policy compliance (--skip-compliance to override)
3. _auto_backup()               ← Auto-backup (--no-backup to skip)
4. send_config_set()            ← Execution
```

See `templates/constitution.yaml` for the template and example rules.

---

## Self-Lockout Prevention

**CRITICAL**: Before applying ANY configuration, check for self-lockout patterns.

### Dangerous Patterns to Detect

| Pattern | Risk | Action |
|---------|------|--------|
| Changing MgmtEth IP/mask | BLOCK | "This would change management IP. SSH will be lost." |
| `shutdown` on MgmtEth | BLOCK | "This would disable management interface." |
| ACL on VTY that excludes current source | BLOCK | "This ACL would block your current SSH session." |
| Changing management VRF routing | WARN | "Management reachability may be affected." |
| Removing the only route to this device | WARN | "No alternate path exists. Access may be lost." |
| `no router ospf/bgp` (management relies on it) | WARN | "Routing protocol removal may affect reachability." |

### Detection Patterns by Platform

Check every proposed command against these regex patterns. If any match → **BLOCK**.

| Platform | Pattern (regex) | What it catches |
|----------|----------------|-----------------|
| `cisco_ios` | `interface\s+(Management\|Mgmt\|GigabitEthernet0/0)` + `(shutdown\|no ip address)` | Disabling management interface |
| `cisco_ios` | `no\s+ip\s+route\s+0\.0\.0\.0` (when only default route exists) | Removing only path to device |
| `cisco_ios` | `access-list.*deny.*<mgmt-source-ip>` | Blocking current SSH source in VTY ACL |
| `cisco_ios` | `line\s+vty.*\n.*access-class.*` (changed ACL) | Modifying VTY access control |
| `cisco_xr` | `interface\s+MgmtEth` + `(shutdown\|no ipv4 address)` | Disabling XR management interface |
| `cisco_xr` | `no\s+router\s+(ospf\|bgp\|static)` (management depends on it) | Removing management routing |
| `cisco_nxos` | `interface\s+mgmt0` + `(shutdown\|no ip address)` | Disabling NX-OS management interface |
| `juniper_junos` | `delete\s+interfaces\s+(em0\|fxp0\|me0\|irb)` | Deleting Junos management interface |
| `juniper_junos` | `delete\s+routing-options\s+static` (management route) | Removing management route |
| `arista_eos` | `interface\s+Management1` + `(shutdown\|no ip address)` | Disabling EOS management interface |

### Detection Logic

Before executing config commands, gather:
1. Current management interface: `show ip interface brief` → find MgmtEth / Management / mgmt0
2. Current SSH source IP: shown in connection info
3. Current VTY ACL: `show running-config | section vty`

Then check if any proposed command would:
- Modify the management interface (match interface name patterns above)
- Change VTY access rules to exclude the current source IP
- Remove routing that reaches the management subnet

If detected → **BLOCK** with clear explanation and do NOT proceed.

---

## Operation Logging

Every config-changing operation MUST be logged. After each operation, append to `logs/clanet_operations.log`:

```
[2026-02-21 03:45:12] DEVICE=router01 ACTION=config RISK=MEDIUM USER=clab STATUS=SUCCESS
  COMMANDS: interface Gi0/0/0/0; description Link-to-OsakaP01; mtu 9000
  VERIFY: OK (interface up, OSPF full)
```

Create the `logs/` directory if it doesn't exist.
