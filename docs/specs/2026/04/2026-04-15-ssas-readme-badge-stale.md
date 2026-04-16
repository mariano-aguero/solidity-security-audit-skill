# Spec: Fix Stale README Version Badge

**traceability_id:** `2026-04-15-ssas-readme-badge-stale`  
**type:** bug  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-04-22  
**project:** solidity-security-audit-skill  
**source:** `README.md:4`  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

`README.md` displays a shields.io badge communicating the skill's version to visitors on GitHub and npm. This badge is the first visual indicator of recency that users see.

## Problem

The badge URL is frozen at `v2.0-improvements-blue`, which corresponds to a version milestone from over a year ago. The skill is now at v3.10.0. New users seeing this badge may doubt whether the repository is actively maintained or may underestimate the content's maturity.

## Objectives

- Update the shields.io badge in `README.md` to reflect the current major version (v3.10.0).
- Optionally switch to a dynamic npm version badge so the badge self-updates on future releases.

## Non-Objectives

- Full README restructuring.
- Changing other badges (Claude Code compatible, MIT license) — those remain accurate.

## Proposed Design

**Option A (static, minimal change):**
```diff
- <a href="https://github.com/mariano-aguero/solidity-security-audit-skill/releases/tag/v1.0.0"><img src="https://img.shields.io/badge/v2.0-improvements-blue?style=for-the-badge" alt="v2 improvements"></a>
+ <a href="https://github.com/mariano-aguero/solidity-security-audit-skill/releases/tag/v3.10.0"><img src="https://img.shields.io/badge/v3.10.0-latest-blue?style=for-the-badge" alt="v3.10.0 latest"></a>
```

**Option B (dynamic npm badge — preferred):**
```html
<a href="https://www.npmjs.com/package/@mariano-aguero/solidity-security-audit-skill"><img src="https://img.shields.io/npm/v/@mariano-aguero/solidity-security-audit-skill?style=for-the-badge&label=npm" alt="npm version"></a>
```

Option B is preferred as it eliminates future staleness automatically.

## Implementation Plan

1. Open `README.md`.
2. Replace the stale badge with Option B (dynamic npm badge).
3. Commit: `fix(readme): replace stale v2.0 badge with dynamic npm version badge`.

## Risks

- Low. Cosmetic change. If the npm package name differs from the expected one, the badge would show "N/A" — verify package name before merging.

## Testing / Acceptance Criteria

- Badge renders a version number in the GitHub README preview.
- Link from badge points to the correct npm page or release tag.

## Rollback

Revert commit if badge URL is incorrect.
