---
name: openwiki-init
description: Generate initial OpenWiki documentation (openwiki/ directory) for
  the current repository — quickstart entrypoint plus focused section pages,
  grounded in source and git evidence. Use when the user wants to initialize,
  bootstrap, or (re)generate a repository wiki from scratch.
---
# Wiki Init

Generate first-pass documentation for this repository under `openwiki/`, useful for both humans and future coding agents.

**First, read `references/core.md` in this skill's directory** — it defines the quality rules, structure requirements, security rules, and the AGENTS.md/CLAUDE.md reference template that all output must follow.

This is an initial documentation run: assume `openwiki/` does not yet contain useful documentation and build the structure from scratch. If the user gave additional instructions with the invocation, they take priority within these rules.

## Workflow

1. **Gather git context.** Run `git status --short`, `git rev-parse HEAD`, `git log --max-count=20 --name-status --oneline`, and `git diff --name-status HEAD` to understand the repo's current state and recent evolution.

2. **Build a repository inventory:** existing docs, app entrypoints, package/config files, major domain folders, tests/evals, data/schema files, skill/playbook files, and operational scripts. Follow the discovery discipline in core.md; use read-only research subagents when the repo has multiple substantial domains. Use git evidence (recent commits, targeted `git blame`/`git show` on high-signal files) to understand how important workflows came to be.

3. **Plan before writing.** Draft a plan listing the intended wiki pages, the source evidence for each page, and remaining questions. Keep the plan out of the repository: hold it in your working notes or a temporary file outside the repo (e.g. a scratchpad or temp directory if your environment provides one) — never leave plan files inside `openwiki/`. Keep the set focused: quickstart plus the smallest set of section pages needed to explain the repo clearly — at most 8 pages unless the repository is clearly tiny.

4. **Write the docs.** Create `openwiki/quickstart.md` first, then the linked section pages. If the repo already has substantial docs, make the wiki an opinionated map and synthesis layer over them rather than a duplicate. Do not try to document every source file — cover the main architecture, workflows, domain concepts, data models, integrations, operations, tests, and known extension points at the right level of detail.

5. **Review the tree.** Re-check the `openwiki/` tree against the section quality rules in core.md: merge, move, or remove low-value single-file directories and stub pages.

6. **Update root agent instruction files** (`AGENTS.md`/`CLAUDE.md`) with the exact OpenWiki reference section from core.md.

7. **Record run metadata** in `openwiki/.last-update.json` with `"command": "init"` (see core.md for the format).

Finish by summarizing the documentation created and any important caveats or open questions. Create a strong first-pass wiki that is accurate and navigable, then stop — it can be refined by later `/openwiki-update` runs.
