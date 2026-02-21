---
description: Network troubleshooting - Claude diagnoses issues or explains configurations from device output
argument-hint: <device-name> <question-or-problem>
allowed-tools: [Read, Bash, Glob, Grep]
---

# /clanet:why - Network Troubleshooting & Explanation

Diagnose network issues or explain existing configurations using device output.

## Instructions

1. First, read `context.yaml` if it exists (use `Read` tool or `python3 lib/clanet_cli.py context`):
   - `topology` — Understand the network layout to guide diagnosis
   - `symptoms` — Combine with user input to prioritize which commands to run

2. Parse the argument: device name and question/problem description.
   Determine the **mode** based on the user's question:

   ### Mode A: Troubleshooting
   Keywords: "down", "fail", "error", "high", "cannot", "not working", "flapping"

   ### Mode B: Config explanation
   Keywords: "why is ... configured", "what does ... do", "explain", "what is ... for"

3. Based on the mode, determine which commands to run.

   **Mode A - Troubleshooting commands:**

   | Problem keyword | Commands to gather |
   |---|---|
   | BGP | `show bgp summary`, `show bgp neighbor <ip>`, `show route <peer-ip>`, `show log last 50` |
   | OSPF | `show ospf neighbor`, `show ospf interface`, `show route ospf`, `show log last 50` |
   | interface down | `show interface <if>`, `show log last 50`, `show run interface <if>` |
   | high CPU | `show processes cpu`, `show processes memory`, `show log last 50` |
   | cannot reach | `show route <ip>`, `show ip interface brief`, `show arp`, `show log last 50` |
   | CRC / errors | `show interface <if>`, `show controllers <if>` |
   | flapping | `show log last 100`, `show interface <if>` |
   | general | `show ip interface brief`, `show log last 50`, `show processes cpu` |

   **Mode B - Config explanation commands:**

   | Question about | Commands to gather |
   |---|---|
   | specific feature | `show running-config \| section <feature>` |
   | specific interface | `show running-config interface <if>`, `show interface <if>` |
   | route-policy | `show running-config route-policy <name>` |
   | ACL / prefix-list | `show running-config \| section <acl-name>` |
   | general | `show running-config` |

   Adapt commands to vendor type (cisco_ios, cisco_xr, juniper_junos, arista_eos).

4. Execute each command:

```bash
source .venv/bin/activate 2>/dev/null || true
python3 lib/clanet_cli.py show "$DEVICE_NAME" $COMMAND
```

5. **Mode A - Present diagnosis:**

   ```
   ## Diagnosis: <device-name>

   **Problem:** <user's description>
   **Root Cause:** <identified root cause>

   **Evidence:**
   - <finding 1 with specific data>
   - <finding 2>

   **Recommended Fix:**
   1. <step 1>
   2. <step 2>

   **Suggested commands:**
   /clanet:config <device> (with specific commands)
   ```

6. **Mode B - Present config analysis:**

   ```
   ## Config Analysis: <device-name>

   **Question:** <user's question>
   **Relevant Config:** (extracted config section)

   **Explanation:**
   - <what this config does, in plain language>
   - <why this is typically configured this way>
   - <any best practice notes>

   **Related concepts:**
   - <brief explanation of underlying protocol/feature>
   ```

7. If initial commands are insufficient, run additional commands.
8. If the problem spans multiple devices, suggest checking the peer device too.
