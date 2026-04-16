# Spec: Fix README Version Badge Pointing to v1.0.0

- **Traceability ID:** `2026-04-16-ssas-readme-version-badge`
- **Type:** docs
- **Criticality:** medium
- **Created:** 2026-04-16T09:10:00-03:00
- **Project:** solidity-security-audit-skill

## Context

The README.md header contains shield badges for Claude Code compatibility, MIT license, and a version badge. The version badge is the primary indicator of the project's maturity for users visiting the GitHub repository.

## Problem

Line 4 of `README.md` contains:
```html
<a href="https://github.com/mariano-aguero/solidity-security-audit-skill/releases/tag/v1.0.0">
  <img src="https://img.shields.io/badge/v2.0-improvements-blue?style=for-the-badge" alt="v2 improvements">
</a>
```

This has three issues:
1. Links to release `v1.0.0` but `package.json` is at `v3.10.0`.
2. Badge text says `v2.0-improvements` — outdated.
3. No corresponding GitHub release tag for v3.10.0 may exist.

**Impact:** Users see a misleading version badge suggesting the project is at v2.0 when it's actually v3.10.0, understating the project's maturity and feature coverage.

## Objectives

- Update the version badge to reflect the current version (v3.10.0).
- Link to the correct release tag or the releases page if no tag exists.

## Non-Objectives

- Creating GitHub releases for all intermediate versions.
- Adding automated version syncing (covered by a separate potential improvement).

## Proposed Design

Replace the badge with a dynamic version badge from shields.io that reads from package.json, or a static badge matching the current version:

```html
<a href="https://github.com/mariano-aguero/solidity-security-audit-skill/releases">
  <img src="https://img.shields.io/badge/v3.10.0-latest-blue?style=for-the-badge" alt="v3.10.0">
</a>
```

## Implementation Plan

1. Edit `README.md` line 4: update href and badge text.
2. Optionally create a GitHub release tag for v3.10.0.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Badge goes stale again on next version bump | High | Low | Consider using a dynamic npm badge or adding a version-sync check to CI |

## Testing

- Visual inspection of the README on GitHub after push.

## Rollback

Revert the line change.

## Acceptance Criteria

- [ ] README badge displays `v3.10.0` (or current version).
- [ ] Badge links to a valid releases URL.
- [ ] Badge text matches `package.json` version.
