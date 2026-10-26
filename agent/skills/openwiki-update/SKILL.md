---
name: openwiki-update
description: Update existing OpenWiki documentation (openwiki/ directory) after
  source changes — surgical, git-diff-driven edits to only the affected pages,
  with a no-op check when nothing changed. Use when the user wants to refresh,
  sync, or maintain the repository wiki.
---
# Wiki Update

Refresh the existing `openwiki/` documentation so it stays accurate after recent repository changes. Update runs must be **surgical**: touch only what the source changes made stale.

**First, read `references/core.md` in this skill's directory** — it defines the quality rules, structure requirements, security rules, and the AGENTS.md/CLAUDE.md reference template that all output must follow.

If `openwiki/quickstart.md` does not exist, stop and tell the user to run `/openwiki-init` first. If the user gave additional instructions with the invocation, skip the no-op check and treat their instruction as the driver of the update.

## Workflow

1. **No-op check.** Read `openwiki/.last-update.json`. Skip the entire run — report that no repository changes were detected since the last update and stop without editing anything — when ALL of the following hold:
   - the metadata records a `gitHead`;
   - `git status --short --untracked-files=all` is empty (ignoring `openwiki/.last-update.json` itself);
   - either `git rev-parse HEAD` equals the recorded `gitHead`, or every path in `git diff --name-only <gitHead>..HEAD` is inside `openwiki/` (and that list is non-empty).

2. **Gather git evidence.** Run `git status --short`, `git rev-parse HEAD`, and `git diff --name-status HEAD`. Inspect commits added since the previous successful run: prefer `git log <lastGitHead>..HEAD --name-status --oneline`; fall back to `git log --since <updatedAt>` if no gitHead was recorded, or the last 20 commits if there is no metadata at all. Use `git show` on high-signal commits to understand what actually changed.

3. **Build a docs impact plan** from the changed source files: source change → docs affected → edit needed → why. Read the affected `openwiki/` pages before editing. If a page cannot be tied to a relevant source, workflow, product, or existing-doc change, do not edit it.

4. **Apply surgical edits**, following these constraints:
   - Preserve useful existing structure and wording when it remains accurate. Prefer replacing one stale sentence over adding new paragraphs.
   - Only edit pages whose content is inaccurate, incomplete, or misleading because of the recent changes. Do not refresh every page.
   - Keep each concept in one canonical page; make other mentions brief or link-only.
   - No formatting-only edits: do not reformat tables, normalize blank lines, reorder source lists, or polish wording unless the surrounding content is already being changed for accuracy.
   - Do not update Source Map sections, git evidence lists, or generic "things to watch" sections unless they are materially wrong because of the source changes.
   - Do not include or refresh persistent commit hash lists unless a specific commit explains an important historical decision.
   - **Soft diff budget:** if fewer than about 5 source files changed, update at most 1-2 wiki pages. Avoid touching quickstart unless top-level product behavior, setup, or navigation changed. If you believe more than 3 wiki pages need edits, think very deeply about why before making broad changes.
   - Update stale pages, add missing pages, remove obsolete claims, and fix quickstart links only when the impact plan requires it.
   - An update may legitimately be a no-op: if the wiki is already accurate, do not edit files and say the wiki is already current.

5. **Check root agent instruction files.** Inspect the OpenWiki reference section in top-level `AGENTS.md`/`CLAUDE.md` and refresh it only if missing or semantically stale (exact template in core.md). This check is required even when the wiki itself is current.

6. **Record run metadata.** Only if you changed `openwiki/` content, rewrite `openwiki/.last-update.json` with `"command": "update"` (see core.md for the format).

Finish by summarizing which pages changed and why — or stating that the wiki was already current.
