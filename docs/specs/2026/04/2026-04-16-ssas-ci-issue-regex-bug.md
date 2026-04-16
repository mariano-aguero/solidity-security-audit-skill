# Spec: Fix create-issues.yml INDEX.md Regex Bug

- **Traceability ID:** `2026-04-16-ssas-ci-issue-regex-bug`
- **Type:** bug
- **Criticality:** high
- **Created:** 2026-04-16T09:10:00-03:00
- **Project:** solidity-security-audit-skill

## Context

The `create-issues.yml` GitHub Actions workflow automates issue creation from `docs/pending-issues.json` and updates `docs/specs/INDEX.md` with the resulting issue URLs. This is the primary traceability mechanism for the `find-tasks` scheduled task.

## Problem

The Python regex in the "Update specs INDEX.md with issue URLs" step uses `(?:[^|]*\|){4}` to skip columns after the `traceability_id` before reaching the `issue` column. However, the INDEX.md table has **8 columns**:

```
| traceability_id | title | type | criticality | created_at | spec | issue | status |
```

After matching `traceability_id`, 4 column skips land on `created_at`, not `issue`. The regex needs to skip **5** columns (title, type, criticality, created_at, spec) to reach the `issue` column containing `—`.

**Impact:** Issue URLs are never populated in `docs/specs/INDEX.md`, breaking traceability between specs and GitHub issues. Every previous `find-tasks` run has silently failed to link issues.

## Objectives

- Fix the regex quantifier from `{4}` to `{5}` in `create-issues.yml`.
- Ensure the regex correctly matches and replaces `—` in the `issue` column.

## Non-Objectives

- Rewriting the workflow in a different language.
- Adding additional columns to the INDEX.md table.

## Proposed Design

Change line 89 of `.github/workflows/create-issues.yml`:

```python
# Before
r'(\| ' + re.escape(tid) + r' \|(?:[^|]*\|){4}) — (\|)'
# After
r'(\| ' + re.escape(tid) + r' \|(?:[^|]*\|){5}) — (\|)'
```

## Implementation Plan

1. Edit `.github/workflows/create-issues.yml`, line 89: change `{4}` to `{5}`.
2. Validate with a dry-run against the current `INDEX.md` content using a local Python snippet.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Regex still fails if INDEX.md format changes | Low | High | Add a CI test that validates the regex against a sample INDEX.md |

## Testing

- Run the updated regex against the current `docs/specs/INDEX.md` locally to confirm matches.
- Push a test `pending-issues.json` to a feature branch and verify the workflow updates INDEX.md correctly.

## Rollback

Revert the single-line change in the workflow file.

## Acceptance Criteria

- [ ] Regex in `create-issues.yml` uses `{5}` quantifier.
- [ ] Running the regex against current INDEX.md rows with `—` in the issue column produces correct replacements.
- [ ] After workflow execution, INDEX.md shows `[#N](url)` in the issue column for processed entries.
