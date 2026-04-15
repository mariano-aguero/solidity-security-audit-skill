# Spec: Fix Stale package.json Version

**traceability_id:** `2026-04-15-ssas-package-version-stale`  
**type:** bug  
**criticality:** high  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-04-22  
**project:** solidity-security-audit-skill  
**source:** `package.json:4`  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

The `solidity-security-audit-skill` is a documentation-only npm package installed via `npx skills add mariano-aguero/solidity-security-audit-skill`. The version field in `package.json` is the source of truth for `npm publish` and `npx` installs.

## Problem

`package.json` declares `"version": "3.3.0"` while the git history contains commits explicitly referencing v3.5.0, v3.6.0, v3.8.0, v3.9.0, and v3.10.0 feature additions. If someone runs `npm publish` today, the npm registry would publish stale v3.3.0, misleading users into installing outdated content. Additionally, users who check the package version to understand what skill content they have will see incorrect data.

## Objectives

- Update `package.json` `"version"` to `"3.10.0"` to match the actual content state.
- Ensure version accuracy as a baseline before future releases.

## Non-Objectives

- Does not include a full release pipeline or npm publish.
- Does not introduce semver automation tooling in this spec.

## Proposed Design

Single-line change in `package.json`:
```diff
-  "version": "3.3.0",
+  "version": "3.10.0",
```

## Implementation Plan

1. Open `package.json`.
2. Change `"version": "3.3.0"` → `"3.10.0"`.
3. Commit: `fix(package): bump version to 3.10.0 to match actual content state`.

## Risks

- Low risk. Pure metadata change with no functional impact on skill behavior.

## Testing / Acceptance Criteria

- `cat package.json | grep version` outputs `"version": "3.10.0"`.
- No other package.json fields are altered.

## Rollback

Revert commit if the intended release version differs from 3.10.0.
