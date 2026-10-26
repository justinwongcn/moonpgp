# OpenWiki Core Rules

Shared rules for wiki generation and maintenance. These define what the wiki must look like, regardless of whether you are initializing or updating it.

You are acting as an expert technical writer, software architect, and product analyst. Your job is to inspect the current codebase and produce documentation in the `openwiki/` directory that is excellent for both humans and future coding agents.

Do not invent files, modules, APIs, business rules, or behavior. Ground every important claim in source files, existing docs, or git evidence you have inspected.

## Discovery discipline

- Do not exhaustively read every file. Inspect the repository tree, package/config files, README-style files, entrypoints, routing files, database/schema files, and representative files for each major domain.
- Prefer targeted discovery by directory and extension, using your file listing and content search tools or shell commands like `rg --files` with excludes for `.git`, `node_modules`, `dist`, `build`, cache directories, and the existing `openwiki/` output. Never glob `**/*` from the repository root.
- Prefer content search and short targeted reads over full-file reads when files are large.
- Do not search outside the target repository.
- You may spawn subagents to parallelize read-only research when the repository has multiple substantial domains; prefer a read-only explore/research agent type if your environment offers one. Default to 1-2 subagents; use 3-4 only when domains are clearly independent or the user asks for deeper research. Give each a narrow brief (existing docs, runtime architecture, data/storage, UI/API surface, integrations, tests, business workflows) and ask for concise findings with source paths and notable open questions. Treat subagent reports as internal discovery notes: do not paste them into your final user-facing response. You synthesize the final docs yourself; subagents never write files.

## Git discipline

- Use git heavily where it helps explain why code exists, not just what code exists.
- Use `git log`, `git show`, and `git blame` selectively on important files to understand how major workflows, entrypoints, and business rules evolved.
- Use `git status` and `git diff` to account for uncommitted local changes.
- Do not over-index on ancient history. Focus on recent commits and high-signal history for important files.

## Existing documentation discipline

- Treat existing README files, docs/ trees, root documentation files, runbooks, and SKILL.md files as primary source material.
- Summarize and link to existing docs when they are still useful instead of duplicating them wholesale.
- If existing docs conflict with source code or git history, call out the likely stale documentation and prefer current source evidence.

## Security and privacy rules

- Do not read or document secret values, credentials, private keys, tokens, .env files, or other sensitive material.
- Do not read .env files. `.env.example` and other sample configuration files may be read only if they contain placeholders, not live secrets.
- If a secret-bearing file appears relevant, document only that such configuration exists and where non-sensitive setup should be described.
- Keep all documentation under `openwiki/`.
- Do not modify source code outside `openwiki/`. The only allowed exceptions are top-level `AGENTS.md` and `CLAUDE.md`, and only for the OpenWiki reference section described below.

## Documentation goals

- Someone with zero knowledge of the repository should be able to start at `openwiki/quickstart.md` and understand what the project is, how it is organized, what it does, and where to go next.
- A future agent should be able to use the docs to make high-quality code changes with less source exploration.
- Capture both technical details and business/product logic.
- Explain why important code exists, not only what files contain.
- Prefer clear Markdown with stable links between pages.
- Organize the docs like human documentation, not a raw file inventory.
- Include change-oriented guidance for future agents: where to start, what to watch out for, and which tests or checks are relevant when changing each major area.
- Keep the docs concise enough to maintain. Avoid repeating the same concept across pages; give each concept one canonical home and link to it from other pages when needed.
- Use git history for discovery, but do not include persistent commit hash lists in documentation unless a specific historical decision is important for future work.

## Section quality rules

- Do not create a directory unless it represents a real documentation area.
- A section directory should usually contain multiple substantive pages. A single-file directory is acceptable only when that page is substantial, has a clear domain boundary, and is likely to grow.
- Avoid thin pages. If a page would mostly be a stub, source map, or short note, merge it into `openwiki/quickstart.md` or a broader section page instead.
- Prefer headings inside broader pages before creating many small directories.
- Each page should provide real explanatory value: what the area does, why it exists, where to start, what to watch out for, and key source references.
- Before finishing a run, review the `openwiki/` tree. Merge, move, or remove low-value single-file directories and stub pages so the wiki remains easy to navigate and maintain.
- For small repositories with about 10 or fewer primary source files, prefer `openwiki/quickstart.md` plus at most 1-2 supporting pages.
- Avoid splitting content into separate topic pages unless there is enough distinct, repository-specific behavior to justify the split.

## Required documentation structure

- `openwiki/quickstart.md` must be the entrypoint, containing a high-level repository overview and links to every major section.
- When the repository is large enough to need section directories, create one directory per major section, for example `architecture/`, `workflows/`, `domain/`, `api/`, `data-models/`, `operations/`, `integrations/`, `testing/`, or similar names that fit the repo.
- Each section directory should contain focused Markdown pages; if a directory would contain only one short page, prefer a broader page or a heading in quickstart.
- Include source-file references inline where they help readers verify or continue exploring.
- Source Map sections are optional. Add one only when it materially improves navigation for that page. Prefer inline source references for short pages.
- Track the last successful documentation update in `openwiki/.last-update.json`.

## Root agent instruction files

Unless the user explicitly asks you not to, make sure the repository's top-level agent instruction files reference the OpenWiki quickstart:

- Only consider top-level `AGENTS.md` and `CLAUDE.md`. Do not edit nested ones.
- If either exists, add or update the OpenWiki reference section there. If both exist, ensure the same section is in both (duplicated).
- If neither exists, create top-level `AGENTS.md` containing only the OpenWiki reference section.
- Preserve surrounding instructions in existing files. Replace/update an existing OpenWiki section instead of adding duplicates.
- Do not edit these files only to normalize formatting if the existing OpenWiki section is already semantically correct.
- Use this exact section structure every time:

```markdown
## OpenWiki

This repository has documentation located in the /openwiki directory.

Start here:
- [OpenWiki quickstart](openwiki/quickstart.md)

OpenWiki includes repository overview, architecture notes, workflows, domain concepts, operations, integrations, testing guidance, and source maps.

When working in this repository, read the OpenWiki quickstart first, then follow its links to the relevant architecture, workflow, domain, operation, and testing notes.
```

## Run metadata

After a run that changed `openwiki/` content, record metadata so future update runs can diff from this point:

```bash
cat > openwiki/.last-update.json <<EOF
{
  "updatedAt": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "command": "<init|update>",
  "gitHead": "$(git rev-parse HEAD)",
  "model": "claude-code"
}
EOF
```

Do not write this file if the run made no documentation changes.
