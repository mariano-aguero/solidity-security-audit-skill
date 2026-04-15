# Spec: Add Move/Sui Security Supplement

**traceability_id:** `2026-04-15-ssas-move-security-supplement`  
**type:** feature  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-20  
**project:** solidity-security-audit-skill  
**source:** `references/zkvm-specific.md`, `references/exploit-case-studies.md` (Cetus exploit)  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

The skill includes a case study on the Cetus DEX exploit on Sui ($223M) in `exploit-case-studies.md`, but has no reference material for auditing Move/Sui or Aptos contracts. The skill's `zkvm-specific.md` covers zkSync/Polygon zkEVM/Scroll but not Move-based chains. As Move ecosystem TVL grows, auditors are increasingly asked to review Move contracts.

## Problem

Auditors who trigger the skill for Sui or Aptos contract reviews get no Move-specific guidance — the skill's entire reference library is EVM/Solidity focused. The Cetus case study exists as an isolated reference without any surrounding framework for how to approach Move security.

## Objectives

- Create `references/move-security.md` covering Move language security patterns for Aptos and Sui.
- Cover the key differences from Solidity that affect security: resource ownership, linear types, capability pattern, borrow checker.
- Update CLAUDE.md, INDEX.md, and SKILL.md.

## Non-Objectives

- Does not cover Move formal verification tooling in depth (brief mention only).
- Does not attempt full parity with the EVM-focused reference depth — this is a supplement.

## Proposed Design

### Sections

1. **Move vs Solidity Security Model** — Resource ownership, linear types, no null pointers
2. **Resource Ownership Attacks** — Acquiring resources without authorization, phantom resources
3. **Borrow Checker Bypass Patterns** — Mutable reference aliasing, borrow scope extension
4. **Object Capability Misuse (Sui)** — ObjectCap transfer attacks, owned object forgery
5. **Arithmetic in Move** — No built-in overflow check in old Aptos/Sui; u64/u128 wrapping
6. **Sui Move vs Aptos Move Differences** — Object model, consensus differences, security implications
7. **Common Audit Findings in Move** — Based on public audit reports from Move protocols
8. **Move Security Audit Checklist** — Checkbox list for Move engagement setup

## Implementation Plan

1. Draft `references/move-security.md` using Cetus case study as the anchor case.
2. Add INDEX.md entry under "Advanced Topics".
3. Add to CLAUDE.md architecture table.
4. Add `sui`, `aptos`, `move language`, `resource ownership`, `linear types` to SKILL.md triggers.
5. Cross-reference from `exploit-case-studies.md` Cetus entry.
6. Cross-reference from `zkvm-specific.md` intro section.

## Risks

- Medium effort. Move language semantics require accurate domain knowledge.
- Less public post-mortem data available compared to EVM. Use only verified findings.

## Testing / Acceptance Criteria

- `references/move-security.md` exists with all 8 sections.
- File is 300–500 lines.
- Audit checklist has at least 10 items specific to Move.
- INDEX.md, CLAUDE.md, and SKILL.md updated.
- Cetus case study in `exploit-case-studies.md` cross-references the new file.

## Rollback

Delete file and revert cross-file changes.
