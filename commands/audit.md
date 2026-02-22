---
description: Compliance audit - check security and best practices across all devices
argument-hint: [device-name | --all] [--profile basic|security|full]
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:audit - Compliance Audit

Audit network devices against security and operational best practices.

## Instructions

1. Parse the argument:
   - Device name or `--all`
   - Optional profile: `--profile security`, `--profile basic`, `--profile full`
   - Optional custom policy: `--policy <path>`
   - Default profile is read from `.clanet.yaml` (`default_profile`), falling back to `basic`
   - Custom policy path is read from `.clanet.yaml` (`policy_file`), falling back to `policies/example.yaml`

2. Execute the automated audit:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py audit "${DEVICE:---all}" --profile "${PROFILE}" --policy "${POLICY}"
```

3. The CLI runs these checks per profile:

   **basic**: NTP, Logging, Banner
   **security**: basic + SSH v2, plaintext passwords, default SNMP, VTY ACL, AAA, console timeout, telnet
   **full**: security + OSPF auth, BGP auth, control-plane protection, loopback, redundant routes

4. **Present the audit report:**

   ```
   ## Compliance Audit Report

   **Profile:** basic | **Devices:** 6 | **Date:** YYYY-MM-DD

   ### Summary
   | Device | Pass | Fail | Score |
   |--------|------|------|-------|
   | router01 | 5 | 1 | 83% |
   | router02 | 4 | 2 | 67% |

   ### Detail: router01
   | # | Check | Status | Detail |
   |---|-------|--------|--------|
   | 1 | NTP configured | PASS | ntp server 10.0.0.1 |
   | 2 | SSH v2 | PASS | ssh server v2 |
   | 3 | IF descriptions | FAIL | Gi0/0/0/2 has no description |

   ### Recommendations
   1. **router01**: Add description to Gi0/0/0/2
   2. **router02**: Configure NTP server, Add VTY ACL
   ```

5. Audit reports are auto-saved to `audit/` directory.
6. Offer to auto-fix common issues using `/clanet:config`.
