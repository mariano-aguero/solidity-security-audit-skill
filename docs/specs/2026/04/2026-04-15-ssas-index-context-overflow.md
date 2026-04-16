# Spec: Split INDEX.md to Prevent LLM Context Overflow

**traceability_id:** `2026-04-15-ssas-index-context-overflow`  
**type:** bug  
**criticality:** high  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-04-29  
**project:** solidity-security-audit-skill  
**source:** `references/INDEX.md` (459 lines, ~12k tokens)  
**status:** in-progress  
**started_at:** 2026-04-15T21:50:00-03:00  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

`references/INDEX.md` is the fast-lookup navigation map for the entire skill. SKILL.md instructs agents to load it during audits to find which file:section covers a given topic. The file is 459 lines long (~12k tokens) and growing with each new reference file added.

## Problem

LLM context windows and the `Read` tool have practical limits. At 459 lines, INDEX.md already strains the 10,000-token threshold. As new reference files (rwa-protocols, fusaka-eof, safe-modules, etc.) are added, it will continue growing. A single monolithic file defeats the purpose of a "fast lookup" tool if loading it itself becomes a bottleneck or causes truncation errors.

## Objectives

- Split INDEX.md into logical sub-indexes, each under 150 lines / ~4k tokens.
- Preserve a lightweight master INDEX.md (under 80 lines) that lists categories and points to sub-indexes.
- Update SKILL.md to load the appropriate sub-index based on audit phase/context rather than always loading the full index.

## Non-Objectives

- Does not change the content of individual reference files.
- Does not restructure the reference file hierarchy beyond adding INDEX sub-files.

## Proposed Design

```
references/
├── INDEX.md              # Master: 70-line category table → points to sub-indexes
├── INDEX-vulns.md        # Vulnerability type → file:section (§1–§13)
├── INDEX-defi.md         # DeFi protocol/token → file:section
├── INDEX-tools.md        # Tooling, L2, AA, standards → file:section
└── INDEX-advanced.md     # ZK, intents, perps, newer categories → file:section
```

**Master INDEX.md** contains one-line entries per category:
```markdown
| Vulnerability Types (§1–§13) | [INDEX-vulns.md](INDEX-vulns.md) | Classic EVM vulns |
| DeFi Protocols & Tokens      | [INDEX-defi.md](INDEX-defi.md)   | AMM, lending, bridges |
| Tools & Workflows             | [INDEX-tools.md](INDEX-tools.md) | Slither, Foundry, severity |
| Advanced Topics               | [INDEX-advanced.md](INDEX-advanced.md) | ZK, intents, perps |
```

**SKILL.md Phase 3 (Manual Review)** loads `INDEX-vulns.md` by default; `INDEX-defi.md` loads during Phase 4 (Protocol-Specific). SKILL.md top section loads master `INDEX.md` only.

## Implementation Plan

1. Create `references/INDEX-vulns.md` with vulnerability-type rows from current INDEX.md.
2. Create `references/INDEX-defi.md` with DeFi/protocol rows.
3. Create `references/INDEX-tools.md` with tools, workflows, and standards rows.
4. Create `references/INDEX-advanced.md` with advanced/emerging tech rows.
5. Rewrite `references/INDEX.md` as a lightweight master pointing to the four sub-indexes.
6. Update SKILL.md `## Phase 3` and `## Phase 4` load instructions to reference sub-indexes.
7. Update CLAUDE.md architecture table to list the four INDEX sub-files.

## Risks

- Medium. SKILL.md changes require testing to ensure agents still find the right section.
- Existing integrations that hard-link to `INDEX.md` anchor headings will need to be updated (grep for `INDEX.md#`).

## Testing / Acceptance Criteria

- Each sub-index is under 150 lines.
- Master INDEX.md is under 80 lines.
- An agent asked to "find the section on oracle manipulation" loads INDEX-vulns.md and navigates to the correct row.
- SKILL.md Phase 3 references `INDEX-vulns.md` directly.

## Rollback

Restore the original `INDEX.md` from git history and revert SKILL.md changes.


## Implementation Notes

- Implemented 2026-04-15 by automated execute-tasks run.
- Created 4 sub-index files: INDEX-vulns.md (150L), INDEX-defi.md (97L), INDEX-tools.md (80L), INDEX-advanced.md (141L). All under 150-line limit.
- Master INDEX.md rewritten as 29-line category guide. Under 80-line limit.
- SKILL.md Phase 3 and Phase 4 updated with explicit sub-index load instructions. Navigation section expanded with 4 sub-index entries.
- CLAUDE.md architecture table updated with 4 new INDEX sub-files at [v3.5]. Maintenance guideline updated.
- Deviations: "By Secure Pattern / Fix" rows placed in INDEX-vulns.md (not a separate file) as they are closely related to vulnerability remediation — stays under 150L limit.
- Slither FP rows that were in the "By Protocol" section moved to INDEX-defi.md since they appear in DeFi audit context.
