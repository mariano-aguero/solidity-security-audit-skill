# Spec: Create references/rwa-protocols.md

**traceability_id:** `2026-04-15-ssas-rwa-protocols-reference`  
**type:** feature  
**criticality:** high  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-04-29  
**project:** solidity-security-audit-skill  
**source:** `references/defi-checklist.md` (scattered RWA entries), `SKILL.md` (trigger keywords)  
**status:** in-progress  
**started_at:** 2026-04-16T00:00:00-03:00  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

Real World Asset (RWA) protocols have grown significantly: Centrifuge, Maple Finance, Goldfinch, TrueFi, OpenTrade, and tokenized T-bill vaults are now significant DeFi TVL holders. The skill currently covers RWA security only through scattered checklist entries in `defi-checklist.md` (NAV manipulation, tranche accounting, KYC transfer restrictions, ERC-1400/ERC-3643). SKILL.md lists many RWA-related trigger keywords but they have no corresponding deep-reference material.

## Problem

Auditors working on RWA protocols have no dedicated reference file. They must piece together guidance from DeFi checklist entries and hope the vulnerability taxonomy covers relevant cases. This creates gaps in coverage and inconsistent audit quality for this growing protocol category.

## Objectives

- Create `references/rwa-protocols.md` as a comprehensive deep-reference for RWA protocol security.
- Cover all major attack vectors specific to RWA: off-chain asset valuation, NAV manipulation, epoch redemptions, KYC bypass, tranche accounting.
- Update `CLAUDE.md`, `references/INDEX.md`, and `SKILL.md` to register the new file.

## Non-Objectives

- Does not replace or duplicate existing DeFi checklist entries (cross-reference them instead).
- Does not cover generic lending protocol vulnerabilities already in `defi-checklist.md`.

## Proposed Design

Use `references/perpetual-dex.md` as the structural template (similar depth and format). The file should cover:

### Sections

1. **Trust Model & Architecture** — off-chain asset custodian trust, pool manager privilege escalation
2. **NAV Oracle Manipulation** — price feed manipulation for illiquid assets, stale NAV vectors
3. **Epoch Redemption Race Conditions** — front-running redemption windows, queue manipulation
4. **Tranche Accounting Attacks** — senior/junior tranche rounding, bad debt allocation
5. **KYC/Transfer Restriction Bypass** — ERC-1400/ERC-3643 transfer hook bypass, whitelist manipulation
6. **Default Handling** — late repayment grace period abuse, write-down timing manipulation
7. **Protocol-Specific Case Studies** — anonymized findings from Centrifuge/Maple-style audits
8. **RWA Audit Checklist** — structured checklist (checkbox format) for auditors

### Format

Each section follows the pattern established in `perpetual-dex.md`:
- Brief explanation of the attack vector
- Vulnerable code pattern (if applicable)
- Secure pattern / mitigation
- Reference to related vulnerability taxonomy entry where applicable

## Implementation Plan

1. Research and draft `references/rwa-protocols.md` following the perpetual-dex.md template.
2. Add entry to `references/INDEX.md` (or the appropriate sub-index after BUG-04 is resolved).
3. Add `rwa-protocols.md` to the architecture table in `CLAUDE.md` under references.
4. Add any new trigger keywords to `SKILL.md` trigger keyword list.
5. Update `SKILL.md` Phase 4 (Protocol-Specific) to mention loading `rwa-protocols.md` for RWA audits.
6. Remove duplicate scattered entries from `defi-checklist.md` and replace with cross-references to the new file.

## Risks

- Medium effort. Content quality depends on accurate understanding of RWA protocol architecture.
- Risk of inaccurate "case study" data — use only confirmed public audit findings, no speculation.

## Testing / Acceptance Criteria

- `references/rwa-protocols.md` exists and has all 8 sections.
- File is under 700 lines (comparable to `perpetual-dex.md` at 646 lines).
- INDEX.md has a row for the new file.
- CLAUDE.md architecture table lists the file.
- SKILL.md Phase 4 references rwa-protocols.md.
- No duplicate RWA content between `defi-checklist.md` and the new file (cross-references instead).

## Rollback

Delete `references/rwa-protocols.md` and revert INDEX.md/CLAUDE.md/SKILL.md changes.
