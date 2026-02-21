---
description: Execute interactive commands that require confirmation (e.g. copy, reload)
argument-hint: <device-name>
allowed-tools: [Read, Bash, Glob, Grep, AskUserQuestion]
---

# /clanet:interactive - Interactive Commands

Execute commands that require interactive responses (yes/no, filename, etc.).

## Instructions

1. Parse the argument to get the device name.
2. Ask the user for:
   - The command to execute
   - Expected prompts and responses (e.g., "confirm?" -> "yes")
3. Build a JSON array of `[command, expect_string]` pairs.
4. **Confirm with the user before executing**, especially for destructive commands like `reload` or `write erase`.
5. Execute:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py interact "$DEVICE_NAME" --commands "$CMD_JSON"
```

## Examples

- `copy running-config startup-config` (responds "yes" to confirmation)
- `reload` (responds to confirmation prompt)
- `crypto key generate rsa` (responds with key size)
