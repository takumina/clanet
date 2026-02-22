---
description: "[internal] Safety framework for all config-changing commands"
argument-hint: ""
allowed-tools: []
---

# clanet Safety Guide

**This file is NOT a user-facing command.** It is referenced by all config-changing commands
(config, deploy, interactive, save, commit) as a shared safety framework.

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

### Detection Logic

Before executing config commands, gather:
1. Current management interface: `show ip interface brief` → find MgmtEth
2. Current SSH source IP: shown in connection info
3. Current VTY ACL: `show running-config | section vty`

Then check if any proposed command would:
- Modify the management interface
- Change VTY access rules
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
