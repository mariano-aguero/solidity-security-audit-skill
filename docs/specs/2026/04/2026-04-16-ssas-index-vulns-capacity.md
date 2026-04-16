# Spec: INDEX-vulns.md at Maximum Line Limit

- **Traceability ID:** `2026-04-16-ssas-index-vulns-capacity`
- **Type:** design
- **Criticality:** medium
- **Created:** 2026-04-16T09:10:00-03:00
- **Project:** solidity-security-audit-skill

## Context

The project maintains split sub-indexes to prevent LLM context overflow (originally identified in `2026-04-15-ssas-index-context-overflow`). `CLAUDE.md` line 63 establishes a maintenance guideline to keep each sub-index under 150 lines.

## Problem

`references/INDEX-vulns.md` is currently exactly **150 lines**, hitting the maintenance ceiling with zero buffer. Any new vulnerability section added to `vulnerability-taxonomy.md` cannot be indexed without violating the guideline.

Upcoming planned features (`fusaka-eof-reference`, `rwa-protocols-reference`, new severity trees) will require new entries in vulnerability-related indexes, making this a blocking issue for the project roadmap.

**Impact:** Blocks the addition of new vulnerability categories to the index, reducing discoverability for AI agents. Without indexing, new vulnerability patterns won't be loaded on-demand.

## Objectives

- Create headroom in INDEX-vulns.md for at least 20 more entries.
- Maintain the sub-150-line constraint per file.

## Non-Objectives

- Changing the 150-line limit itself.
- Restructuring the entire index hierarchy.

## Proposed Design

**Option A (recommended):** Consolidate entries in INDEX-vulns.md by grouping related vulnerability types into fewer lines. For example, merge individual lines for similar ERC-related vulnerabilities into grouped entries.

**Option B:** Split INDEX-vulns.md into `INDEX-vulns-core.md` (established patterns: reentrancy, access control, etc.) and `INDEX-vulns-emerging.md` (ERC-7702, transient storage, ePBS, etc.). Update `INDEX.md` master to point to both.

## Implementation Plan

1. Audit current INDEX-vulns.md for entries that can be consolidated.
2. Group related entries (target: reduce to ~120 lines).
3. Update cross-references in INDEX.md if file is split.
4. Verify all section references still resolve correctly.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Consolidated entries reduce discoverability | Medium | Medium | Keep grouped entries descriptive; include all section numbers |
| Split creates navigation overhead | Low | Low | Clear naming convention and master index pointers |

## Testing

- `wc -l references/INDEX-vulns.md` < 150.
- Verify all `§N` references in the index match actual sections in vulnerability-taxonomy.md.

## Rollback

Restore original INDEX-vulns.md from git.

## Acceptance Criteria

- [ ] INDEX-vulns.md is under 130 lines (20-line buffer).
- [ ] All vulnerability sections remain discoverable via the index.
- [ ] INDEX.md master index updated if any file was renamed or split.
