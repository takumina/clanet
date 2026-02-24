---
name: team
description: 3-agent team (compliance-checker, network-operator, validator) for safe config changes
---

# /clanet:team - Multi-Agent Config Change (Skill)

This skill extends the `/clanet:team` command with operation context awareness.

## Instructions

1. **Load context** (if available): Read `context.yaml` using `python3 lib/clanet_cli.py context` to understand topology, constraints, and success criteria.

2. **Follow the orchestration steps in `commands/team.md`** — use all steps (Create Team, Spawn Agents, Monitor, Report, Cleanup).

3. **Context-aware agent prompts**: When spawning agents, include the following additions to the base prompts defined in `commands/team.md`:
   - **compliance-checker**: "Also read `context.yaml` for task-specific constraints. Check proposed commands against both global policy and context constraints."
   - **network-operator**: "Also read `context.yaml` to understand topology and constraints. Respect constraints when generating config."
   - **validator**: "Also read `context.yaml` for `success_criteria`. If defined, use those criteria for PASS/FAIL judgment instead of the defaults."

If `context.yaml` does not exist, proceed without context — the orchestration in `commands/team.md` works without it.
