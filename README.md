# VulnScope Claude Code kit

Drop this folder's contents into an empty git repo. It contains the project memory, design docs, subagent definitions, slash commands, gate templates and the prompts to run.

## Setup
1. `git init` a new repo and copy everything here into it (keep the `.claude/` folder).
2. Open Claude Code in the repo root. `CLAUDE.md` loads automatically.
3. Send `prompts/00-first-message.md`. Review the plan it returns.
4. When you approve, send `prompts/01-slice0-kickoff.md`.
5. For every later slice use `prompts/02-slice-template.md`.

## Layout
- `CLAUDE.md`: permanent rules and context
- `docs/`: architecture, contracts, threat model, roadmap, agent workflow, stress tests, ADRs, gate templates
- `.claude/agents/`: architect, implementer, security-reviewer, stress-tester, verifier, lab-engineer
- `.claude/commands/`: `/slice-start`, `/gate-pre`, `/gate-post`, `/slice-close`
- `prompts/`: what you paste, in order

## Honest limits
The design is enterprise-grade; the implementation grows slice by slice. `docs/architecture.md` marks which capabilities are built in which phase. Nothing here has been run yet.
