# Spec: Fix CLAUDE.md Vulnerability Count Mismatch

- **Traceability ID:** `2026-04-16-ssas-claude-md-vuln-count`
- **Type:** docs
- **Criticality:** low
- **Created:** 2026-04-16T09:10:00-03:00
- **Project:** solidity-security-audit-skill

## Context

`CLAUDE.md` is the primary instruction file for AI agents working on this repository. Its architecture section describes the reference files and their contents. Accuracy here is critical because AI agents use these descriptions to decide which files to read.

## Problem

Line 16 of `CLAUDE.md` states:
```
├── vulnerability-taxonomy.md   # 50+ vulnerability types with code (incl. ERC-7702, V4 hooks)
```

However, `README.md` (lines 19 and 56) states "100+ vulnerability types" and the actual file contains 25 major sections (§1–§25) with 138+ subsections. The "50+" figure is outdated from an earlier version.

**Impact:** An AI agent reading only `CLAUDE.md` underestimates the scope of `vulnerability-taxonomy.md`, potentially choosing not to reference it for certain vulnerability categories that are actually covered.

## Objectives

- Update CLAUDE.md line 16 to match the actual vulnerability count.
- Ensure consistency between CLAUDE.md, README.md, and actual file contents.

## Non-Objectives

- Automating count synchronization across files.
- Updating the vulnerability-taxonomy.md content itself.

## Proposed Design

Change line 16 of `CLAUDE.md`:
```
├── vulnerability-taxonomy.md   # 100+ vulnerability types with code (incl. ERC-7702, V4 hooks)
```

## Implementation Plan

1. Edit `CLAUDE.md` line 16: change "50+" to "100+".

## Testing

- Grep for "50+" across all markdown files to ensure no other stale references.

## Rollback

Revert the single-word change.

## Acceptance Criteria

- [ ] CLAUDE.md references "100+ vulnerability types" for vulnerability-taxonomy.md.
- [ ] No other files reference "50+" vulnerability types.
