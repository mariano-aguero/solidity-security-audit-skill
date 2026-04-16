# Spec: Add .npmignore for Clean Package Publication

- **Traceability ID:** `2026-04-16-ssas-npmignore-publish`
- **Type:** improvement
- **Criticality:** low
- **Created:** 2026-04-16T09:10:00-03:00
- **Project:** solidity-security-audit-skill

## Context

The project is published to npm as `@mariano-aguero/solidity-security-audit-skill` (`package.json` has `"private": false`). Users install it via `npx skills add mariano-aguero/solidity-security-audit-skill`.

## Problem

There is no `.npmignore` file. Without it, `npm pack` includes everything not in `.gitignore`, including:

- `.github/` (CI workflows, issue templates)
- `docs/` (specs, pending-issues, plans — internal project management)
- `.claude/` (if present — AI agent configuration)
- Any editor config files (`.editorconfig`, `.vscode/`, `.idea/`)

The published tarball is larger than necessary and exposes internal project management artifacts to consumers.

**Impact:** Users downloading the skill get unnecessary files, increasing install size and potentially causing confusion. The `docs/` directory in particular contains internal specs and issue tracking that are not relevant to skill consumers.

## Objectives

- Create a `.npmignore` that excludes non-essential files from the npm package.
- Keep the published package focused on `SKILL.md`, `references/`, `package.json`, `README.md`, and `LICENSE`.

## Non-Objectives

- Switching to the `files` field in `package.json` (`.npmignore` is simpler for this project).
- Changing the publishing workflow.

## Proposed Design

Create `.npmignore` at project root:

```
.github/
.claude/
docs/
.editorconfig
.vscode/
.idea/
*.log
CLAUDE.md
```

## Implementation Plan

1. Create `.npmignore` with the contents above.
2. Run `npm pack --dry-run` to verify the package contents.
3. Confirm `SKILL.md`, `references/`, `package.json`, `README.md`, and `LICENSE` are included.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Accidentally excluding needed files | Low | High | `npm pack --dry-run` before publishing |

## Testing

- `npm pack --dry-run` shows only essential files.
- Package size is reasonable (should be under 500KB).

## Rollback

Delete `.npmignore` file.

## Acceptance Criteria

- [ ] `.npmignore` exists at project root.
- [ ] `npm pack --dry-run` excludes `.github/`, `docs/`, `.claude/`.
- [ ] `npm pack --dry-run` includes `SKILL.md`, `references/`, `package.json`, `README.md`, `LICENSE`.
