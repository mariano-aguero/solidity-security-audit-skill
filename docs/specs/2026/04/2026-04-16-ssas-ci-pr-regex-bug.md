# Spec: Fix create-prs.yml INDEX.md Regex Bug

- **Traceability ID:** `2026-04-16-ssas-ci-pr-regex-bug`
- **Type:** bug
- **Criticality:** high
- **Created:** 2026-04-16T09:10:00-03:00
- **Project:** solidity-security-audit-skill

## Context

The `create-prs.yml` GitHub Actions workflow automates PR creation from `docs/pending-prs.json` and updates `docs/specs/INDEX.md` by changing the `status` column from `open` to `in-review`.

## Problem

The Python regex in the "Update INDEX.md with PR URLs" step uses `(?:[^|]*\|){5}` to skip columns after the `traceability_id` before reaching the `status` column. However, the INDEX.md table has **8 columns**:

```
| traceability_id | title | type | criticality | created_at | spec | issue | status |
```

After matching `traceability_id`, 5 column skips land on `spec`, not `status`. The regex needs to skip **6** columns (title, type, criticality, created_at, spec, issue) to reach the `status` column containing `open`.

**Impact:** PR status updates are never applied to `docs/specs/INDEX.md`. The status column remains `open` even after PRs are created, breaking the lifecycle tracking of specs.

## Objectives

- Fix the regex quantifier from `{5}` to `{6}` in `create-prs.yml`.
- Ensure the regex correctly matches and replaces `open` with `in-review` in the `status` column.

## Non-Objectives

- Adding PR URL tracking to the INDEX.md table (would require a new column).
- Changing the status lifecycle values.

## Proposed Design

Change line 73 of `.github/workflows/create-prs.yml`:

```python
# Before
r'(\| ' + re.escape(tid) + r' \|(?:[^|]*\|){5}) open (\|)'
# After
r'(\| ' + re.escape(tid) + r' \|(?:[^|]*\|){6}) open (\|)'
```

## Implementation Plan

1. Edit `.github/workflows/create-prs.yml`, line 73: change `{5}` to `{6}`.
2. Validate with a dry-run against the current `INDEX.md` content.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Regex still fails if INDEX.md format changes | Low | High | Add a CI validation test |

## Testing

- Run the updated regex against the current `docs/specs/INDEX.md` locally to confirm matches on rows with `open` status.
- Push a test `pending-prs.json` and verify the workflow updates INDEX.md correctly.

## Rollback

Revert the single-line change in the workflow file.

## Acceptance Criteria

- [ ] Regex in `create-prs.yml` uses `{6}` quantifier.
- [ ] Running the regex against current INDEX.md rows with `open` status produces correct replacements.
- [ ] After workflow execution, INDEX.md shows `in-review` in the status column for processed entries.
