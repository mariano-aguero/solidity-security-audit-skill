# Spec: Create references/safe-modules.md

**traceability_id:** `2026-04-15-ssas-safe-modules-reference`  
**type:** feature  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-13  
**project:** solidity-security-audit-skill  
**source:** `references/defi-checklist.md` (Safe module checklist entries)  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

Gnosis Safe is the most widely deployed smart account infrastructure in DeFi. Safe modules extend Safe's functionality but introduce significant attack surface. Currently the skill covers Safe security only through brief checklist entries in `defi-checklist.md`. SKILL.md lists Safe-related keywords without a backing reference file.

## Problem

Safe module audits require understanding of the Safe Guard interface, module enablement/disablement attacks, fallback handler hijacking, and Zodiac compatibility. These are not covered by generic access control or proxy vulnerability documentation. As Safe adoption grows and the Safe{Core} Protocol v1 matures, dedicated reference material is increasingly necessary.

## Objectives

- Create `references/safe-modules.md` with comprehensive Safe module security coverage.
- Update CLAUDE.md, INDEX.md, and SKILL.md.

## Non-Objectives

- Does not duplicate account abstraction coverage from `account-abstraction.md`.
- Does not cover generic multisig patterns not specific to Safe.

## Proposed Design

### Sections

1. **Safe Architecture Overview** — Guard interface, module system, fallback handler chain
2. **Module Enablement Attacks** — Malicious `enableModule()`, module ordering manipulation
3. **Guard Bypass via Delegatecall** — `execTransactionFromModule` bypasses checkAfterExecution
4. **Safe Storage Collisions** — Custom module storage colliding with Safe slots
5. **Fallback Handler Hijacking** — Overriding the fallback handler, selector clash in handler
6. **Threshold Manipulation** — Threshold set to 0 by malicious module, owner removal attacks
7. **Zodiac Module Compatibility** — Reality.eth module, Exit Module, Delay Module edge cases
8. **Social Recovery Module Attacks** — Guardian spoofing, recovery cooldown bypass
9. **Safe Modules Audit Checklist** — Checkbox list for Safe module engagements

## Implementation Plan

1. Draft `references/safe-modules.md` following the account-abstraction.md template structure.
2. Add INDEX.md entry.
3. Add to CLAUDE.md architecture table.
4. Update SKILL.md trigger keywords and Phase 4.
5. Cross-reference from `defi-checklist.md` Safe entries.

## Risks

- Medium effort. Safe internals require accurate understanding of the Safe{Core} Protocol.
- Content must be accurate for Safe v1.3+ (current most deployed version) and note differences for v1.4.

## Testing / Acceptance Criteria

- `references/safe-modules.md` exists with all 9 sections.
- File is 400–600 lines.
- Vulnerable + secure code patterns for module enablement, guard bypass, and storage collision.
- INDEX.md and CLAUDE.md updated.
- `defi-checklist.md` Safe entries cross-reference the new file.

## Rollback

Delete file and revert cross-file changes.
