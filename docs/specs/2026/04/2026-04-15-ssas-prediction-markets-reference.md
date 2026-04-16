# Spec: Create references/prediction-markets.md

**traceability_id:** `2026-04-15-ssas-prediction-markets-reference`  
**type:** feature  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-13  
**project:** solidity-security-audit-skill  
**source:** `references/defi-checklist.md` (prediction market entries), `SKILL.md` (trigger keywords)  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

Prediction markets (Polymarket, Gnosis CTF, Azuro) are referenced in SKILL.md keywords and briefly in `defi-checklist.md`, but no deep reference exists. These protocols use unique mechanics (conditional tokens, LMSR AMMs, resolver-based oracles) that differ from standard DeFi and deserve dedicated coverage.

## Problem

Auditors reviewing prediction market contracts face resolver manipulation, conditional token transfer attacks, LMSR invariant breaks, and market resolution griefing — none of which are covered by generic DeFi vulnerability knowledge. Without a reference file, auditors may miss entire categories of attack.

## Objectives

- Create `references/prediction-markets.md` with comprehensive prediction market security coverage.
- Update CLAUDE.md, INDEX.md, and SKILL.md.

## Non-Objectives

- Does not cover options protocols (separate spec).
- Does not duplicate generic oracle coverage.

## Proposed Design

### Sections

1. **Architecture Patterns** — Conditional tokens (ERC-1155 CTF), LMSR AMM, parimutuel models
2. **Resolver Manipulation** — Centralized resolver risk, UMA escalation game attacks
3. **Market Resolution Griefing** — Liquidity removal before resolution, invalid market creation
4. **LMSR Invariant Breaks** — Rounding in cost function, precision attacks in market maker
5. **Conditional Token Transfer Attacks** — ERC-1155 hook reentrancy in CTF markets
6. **Oracle Bribe Vectors** — Market resolution bribe economics, Schelling game failure
7. **Prediction Market Checklist** — Audit checklist for prediction market engagements

## Implementation Plan

1. Draft `references/prediction-markets.md` following the perpetual-dex.md structure.
2. Add INDEX.md entry.
3. Add to CLAUDE.md architecture table.
4. Update SKILL.md trigger keywords and Phase 4.

## Risks

- Medium effort. LMSR math requires domain accuracy.
- Limited public post-mortems make case studies harder to source.

## Testing / Acceptance Criteria

- `references/prediction-markets.md` exists with all 7 sections.
- File is 350–500 lines.
- At least 3 sections include code examples.
- INDEX.md and CLAUDE.md updated.

## Rollback

Delete file and revert cross-file changes.
