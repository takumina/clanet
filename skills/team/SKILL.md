---
name: team
description: 3-agent team (compliance-checker, network-operator, validator) for safe config changes
---

# /clanet:team - Multi-Agent Config Change (Skill)

This skill extends the `/clanet:team` command with operation context awareness.

## Instructions

1. **Load context** (if available): Read `context.yaml` using `python3 lib/clanet_cli.py context` to understand topology, constraints, and success criteria.

2. **Follow the 2-phase orchestration steps in `commands/team.md`**:
   - **Phase 1**: Spawn planner, compliance-checker, and validator. Wait for planner's APPROVED CHANGE PLAN.
   - **Phase 2**: Dynamically spawn operator-1..N based on Device Groups and device count. Assign each operator its device group.

3. **Context-aware agent prompts**: When spawning agents, include the following additions to the base prompts defined in `commands/team.md`:
   - **planner**: "Also read `context.yaml` to understand topology, constraints, and existing relationships between devices. Use topology info to identify all affected devices and links. Group devices by site/role for Device Groups."
   - **compliance-checker**: "Also read `context.yaml` for task-specific constraints. Check proposed commands against both global policy and context constraints. Run `python3 lib/clanet_cli.py constitution-rules` to load constitutional rules, then evaluate any natural language `rule` fields using LLM reasoning."
   - **validator**: "Also read `context.yaml` for `success_criteria`. If defined, use those criteria for PASS/FAIL judgment instead of the defaults."
   - **operator-1..N** (Phase 2): "Also read `context.yaml` to understand topology and constraints. Respect constraints when generating config for your assigned devices."

4. **Dynamic operator context**: When spawning Phase-2 operators, include relevant `context.yaml` information in each operator's prompt:
   - Topology relationships relevant to the operator's assigned devices
   - Constraints that affect the assigned device group
   - Any site-specific or role-specific notes from the context

If `context.yaml` does not exist, proceed without context — the orchestration in `commands/team.md` works without it.
