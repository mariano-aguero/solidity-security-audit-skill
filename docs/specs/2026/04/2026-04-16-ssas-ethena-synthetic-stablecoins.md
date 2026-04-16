# Spec: Add Ethena / Synthetic Stablecoins DeFi Coverage

- **Traceability ID:** `2026-04-16-ssas-ethena-synthetic-stablecoins`
- **Type:** feature
- **Criticality:** medium
- **Created:** 2026-04-16T09:10:00-03:00
- **Project:** solidity-security-audit-skill

## Context

The skill provides DeFi protocol checklists (`defi-checklist.md`) and integration patterns (`defi-integrations.md`) for common protocol types. Ethena (USDe) and the broader category of synthetic/delta-neutral stablecoins emerged as major DeFi primitives in 2024-2025, with billions in TVL and unique security properties.

## Problem

Synthetic stablecoin protocols like Ethena combine multiple DeFi primitives (derivatives, restaking, insurance funds, basis trading) into novel architectures not fully covered by existing checklists. The skill covers restaking (via `staking-consensus.md`) and derivatives (via `perpetual-dex.md`) separately but doesn't address:

- Delta-neutral position management (CEX + DEX hybrid custody)
- Funding rate dependency and negative funding scenarios
- Insurance/reserve fund solvency under extreme conditions
- Custodian risk and proof-of-reserves integration
- USDe depeg vectors and redemption queue attacks
- sUSDe staking yield manipulation

**Impact:** Auditors using this skill may miss synthetic stablecoin-specific vulnerabilities when reviewing protocols that integrate USDe or similar assets, or when auditing the protocols themselves.

## Objectives

- Add a "Synthetic Stablecoins / Delta-Neutral Protocols" section to `defi-checklist.md`.
- Add Ethena-specific integration patterns to `defi-integrations.md`.
- Cross-reference from relevant sub-indexes.

## Non-Objectives

- Covering centralized stablecoins (USDT, USDC) — already handled by token checklists.
- Creating a standalone reference file (scope doesn't warrant it yet).

## Proposed Design

### In `defi-checklist.md`:

New section "Synthetic Stablecoins / Delta-Neutral" with checklist items:
- Funding rate risk: negative funding scenarios, insurance fund drawdown
- Custody/collateral: proof of reserves, custodian diversification
- Redemption mechanics: queue fairness, NAV calculation, depeg thresholds
- Yield distribution: sUSDe-style staking, yield source transparency
- Oracle dependency: mark price vs. index price for position valuation

### In `defi-integrations.md`:

New subsection under "Protocol Integration Patterns":
- USDe as collateral: rebasing behavior, depeg impact on borrowing protocols
- sUSDe yield: integration with lending markets, vault strategies

## Implementation Plan

1. Add ~30-line checklist section to `defi-checklist.md`.
2. Add ~20-line integration pattern to `defi-integrations.md`.
3. Add entries to `INDEX-defi.md`.
4. Update SKILL.md protocol routing table if applicable.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Ethena-specific details become outdated | Medium | Low | Keep patterns generic (delta-neutral, not just Ethena) |
| INDEX-defi.md exceeds 150 lines | Low | Medium | Check current line count before adding |

## Testing

- Verify new sections are reachable from INDEX-defi.md.
- Verify no duplicate content with existing restaking or perpetual-dex sections.

## Rollback

Remove added sections from both files and INDEX-defi.md entries.

## Acceptance Criteria

- [ ] `defi-checklist.md` includes a "Synthetic Stablecoins / Delta-Neutral" section.
- [ ] `defi-integrations.md` includes USDe/sUSDe integration patterns.
- [ ] New sections indexed in `INDEX-defi.md`.
- [ ] No overlap with existing restaking/perpetual-dex content.
