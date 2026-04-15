# Spec: Create references/options-protocols.md

**traceability_id:** `2026-04-15-ssas-options-protocols-reference`  
**type:** feature  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-13  
**project:** solidity-security-audit-skill  
**source:** `references/defi-checklist.md` (options entries), `SKILL.md` (trigger keywords)  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

Options protocols (Ribbon Finance, Dopex, Lyra, Opyn, Hegic, Premia) are covered only by checklist entries in `defi-checklist.md`. SKILL.md has many options-related trigger keywords but no deep reference material.

## Problem

Auditors reviewing options protocols need specialized knowledge: settlement oracle design, implied volatility manipulation, margin model correctness, and option exercise logic. A checklist is insufficient for this complexity. The lack of a reference file means auditors rely only on general DeFi vulnerability knowledge, potentially missing options-specific attack vectors.

## Objectives

- Create `references/options-protocols.md` covering all major options security vectors.
- Provide code examples for vulnerable and secure patterns.
- Update CLAUDE.md, INDEX.md, and SKILL.md.

## Non-Objectives

- Does not duplicate generic oracle or AMM coverage from other reference files.
- Does not cover prediction markets (separate spec).

## Proposed Design

### Sections

1. **Options Protocol Architecture** — American vs European, onchain vs hybrid settlement
2. **Settlement Oracle Manipulation** — IV oracle attacks, expiry price manipulation
3. **Undercollateralized Writing** — margin calculation bypass, covered call vault drain
4. **Expiry Timing Manipulation** — miner-extractable expiry, block timestamp sensitivity
5. **Put Vault Margin Cascades** — liquidation cascade in put selling vaults
6. **Strike Price Oracle Reliability** — spot vs TWAP for strike anchoring
7. **Protocol-Specific Patterns** — Ribbon vault-of-vaults, Dopex SSOVs, Lyra delta hedge
8. **Options Audit Checklist** — Checkbox list for options engagement

## Implementation Plan

1. Draft `references/options-protocols.md` following the perpetual-dex.md template structure.
2. Add INDEX.md entry.
3. Add to CLAUDE.md architecture table.
4. Update SKILL.md Phase 4 with options reference.
5. Cross-reference from `defi-checklist.md` options entries.

## Risks

- Medium effort. Options math and margin models require domain accuracy.

## Testing / Acceptance Criteria

- `references/options-protocols.md` exists with all 8 sections.
- File is 400–600 lines.
- Each attack vector has vulnerable + secure code example.
- INDEX.md and CLAUDE.md updated.

## Rollback

Delete file and revert cross-file changes.
