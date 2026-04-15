# Spec: Create references/fusaka-eof.md

**traceability_id:** `2026-04-15-ssas-fusaka-eof-reference`  
**type:** feature  
**criticality:** high  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-04-29  
**project:** solidity-security-audit-skill  
**source:** `references/vulnerability-taxonomy.md §22`, `references/glamsterdam.md`  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

The Fusaka upgrade introduces EVM Object Format (EOF / EIP-7692) — a major EVM change comparable in scope to Pectra. EOF changes how contracts are deployed and executed: it removes the `GAS`, `EXTCODESIZE`, and `SELFDESTRUCT` opcodes, introduces `EXTDELEGATECALL` (with compatibility constraints), and adds deploy-time bytecode validation. The skill currently covers EOF in `vulnerability-taxonomy.md §22` (4 sub-items) and in `glamsterdam.md` (ePBS/BALs focus), but these are insufficient for auditors encountering EOF-targeting contracts.

## Problem

Auditors reviewing EOF contracts or contracts that interact with EOF contracts have no dedicated reference. The 4 entries in `vulnerability-taxonomy.md §22` are too brief. Unlike Pectra's EIPs which were incremental additions, EOF fundamentally changes the EVM execution model. This warrants the same dedicated treatment as `staking-consensus.md` or `account-abstraction.md`.

## Objectives

- Create `references/fusaka-eof.md` as a comprehensive reference for EOF/Fusaka security.
- Cover the full EOF bundle EIPs, opcode removal implications, factory patterns, cross-format interactions.
- Include an audit checklist and migration guidance for auditors reviewing pre-EOF to post-EOF migrations.
- Update CLAUDE.md, INDEX.md, and SKILL.md.

## Non-Objectives

- Does not replace the brief EOF entries in `vulnerability-taxonomy.md §22` — cross-reference instead.
- Does not cover non-EOF Fusaka changes (EIP-7825 gas cap is referenced but not the primary focus).

## Proposed Design

Use `glamsterdam.md` as the structural template. Target 300–400 lines.

### Sections

1. **EOF Overview** — What is EOF, why it matters, activation timeline
2. **EOF Container Format** — Header, code sections, data sections, validation rules
3. **EIP Bundle** — Brief table: EIP-3540, EIP-3670, EIP-4200, EIP-4750, EIP-5450, EIP-7692 and what each changes
4. **Gas Observability Removal** — GAS opcode removed; contracts relying on `gasleft()` for reentrancy guards break
5. **Code Observability Removal** — EXTCODESIZE always returns 0 for EOF contracts; EOA checks via code size fail
6. **EXTDELEGATECALL Restrictions** — Cannot delegatecall into legacy contracts from EOF; incompatibility matrix
7. **Deploy-time Validation** — Factory pattern implications; create2 with EOF bytecode validation
8. **Cross-format Interaction** — Legacy contract calling EOF contract; EOF calling legacy; event ordering
9. **Per-transaction Gas Cap (EIP-7825)** — Fusaka adds a per-tx gas limit; implications for batch operations
10. **Audit Checklist** — Checkbox list for EOF-targeting audit engagements
11. **Migration Guidance** — How to audit a codebase migrating from legacy to EOF

### Vulnerable Pattern Example (Section 4)

```solidity
// VULNERABLE: reentrancy guard uses gasleft() — breaks in EOF
function withdraw() external {
    require(gasleft() > 10000, "insufficient gas for reentrancy guard"); // GAS opcode removed in EOF
    // ...
}

// SECURE: use a boolean lock instead
bool private _locked;
modifier nonReentrant() {
    require(!_locked, "ReentrancyGuard: reentrant call");
    _locked = true;
    _;
    _locked = false;
}
```

## Implementation Plan

1. Draft `references/fusaka-eof.md` following the glamsterdam.md template structure.
2. Expand from `vulnerability-taxonomy.md §22` content as the starting skeleton.
3. Add INDEX.md entry under "Advanced Topics".
4. Add to CLAUDE.md architecture table.
5. Add EOF-specific trigger keywords to SKILL.md (beyond those already present).
6. Add cross-reference in `vulnerability-taxonomy.md §22` pointing to the new file.

## Risks

- High effort but well-bounded scope. EOF spec is finalized in EIP-7692.
- Risk of content becoming stale quickly if Fusaka activation timeline changes.
- Content must accurately represent final EIP specifications, not drafts.

## Testing / Acceptance Criteria

- `references/fusaka-eof.md` exists with all 11 sections.
- File is 300–450 lines.
- Each removed opcode has at least one vulnerable + secure code example.
- Audit checklist has at least 10 actionable checkboxes.
- INDEX.md has a row for the file.
- `vulnerability-taxonomy.md §22` cross-references the new file.

## Rollback

Delete `references/fusaka-eof.md` and revert cross-file changes.
