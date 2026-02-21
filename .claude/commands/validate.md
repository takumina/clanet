---
description: Validate changes - snapshot before/after config deployment with automatic rollback
argument-hint: <device-name>
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:validate - Change Validation

Take a pre-change snapshot, apply configuration, take post-change snapshot, compare, and optionally rollback.

## Instructions

1. Parse the argument to get the device name.
2. Ask the user for:
   - The configuration commands to apply
   - Validation criteria (optional)

3. **Phase 1: Pre-change snapshot**

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py snapshot "$DEVICE_NAME" --phase pre
```

4. **Phase 2: Apply configuration**

   Follow the Safety Guide (Show → Explain → Confirm) then execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py config "$DEVICE_NAME" --commands "$CONFIG_JSON"
```

5. **Phase 3: Post-change snapshot**

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py snapshot "$DEVICE_NAME" --phase post
```

6. **Phase 4: Compare and analyze**

   First, check if `context.yaml` exists (use `Read` tool or `python3 lib/clanet_cli.py context`).
   If not found, skip to the default checks below.

   Then read both snapshot files from `snapshots/` and analyze:

   **If `success_criteria` is defined in context.yaml:**
   - Evaluate each criterion against the post-change state
   - Report PASS/FAIL per criterion

   **If `success_criteria` is NOT defined (fallback):**
   - **Interface changes**: Any interface went down?
   - **BGP changes**: Any neighbor lost?
   - **OSPF changes**: Any adjacency lost?
   - **Route changes**: Significant route count change?
   - **Config diff**: What exactly changed in running-config?

7. **Present validation report:**

   ```
   ## Validation Report: <device-name>

   | Check | Pre | Post | Status |
   |-------|-----|------|--------|
   | Interfaces Up | 5 | 5 | OK |
   | BGP Neighbors Established | 1 | 1 | OK |
   | OSPF Neighbors Full | 2 | 2 | OK |
   | Total Routes | 15 | 16 | OK (+1) |

   **Config Changes:**
   (diff of running-config)

   **Overall: PASS / FAIL**
   ```

8. **If FAIL**: Ask the user if they want to rollback.
   - For commit-based platforms: use `rollback configuration`
   - For IOS: apply reverse config commands
   - Always confirm before rollback
