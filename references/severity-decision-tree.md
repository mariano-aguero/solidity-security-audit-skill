# Severity Decision Tree & Classification Framework

Severity classification is the most consequential — and most subjective — part of an audit.
This reference provides structured decision trees, impact/likelihood matrices, and concrete
comparables to minimize inconsistency across findings.

Standard: **Immunefi / Sherlock / Code4rena** (see `industry-standards.md`)

---

## The Core Formula

```
Severity = f(Impact, Likelihood, Constraints)

Where:
  Impact     = maximum damage if exploited (funds, protocol integrity, user harm)
  Likelihood = ease of exploitation + required conditions
  Constraints = privileges needed, external dependencies, chain of events
```

No formula is perfect. Use the trees below as a starting point, then apply the
escalation/de-escalation factors to reach the final severity.

---

## Step 1: Determine Maximum Impact

```
What is the worst-case outcome if this vulnerability is exploited?

├─ Direct theft or permanent loss of user/protocol funds
│   └─ IMPACT: CRITICAL
│
├─ Theft possible but requires specific conditions (specific block, specific state)
│   └─ IMPACT: HIGH
│
├─ Funds temporarily frozen / locked (recoverable by admin or time)
│   └─ IMPACT: HIGH
│
├─ Protocol logic incorrect — incorrect calculations, wrong state
│   but no direct fund loss
│   └─ IMPACT: MEDIUM
│
├─ Degraded user experience, griefing, DoS (not permanent)
│   └─ IMPACT: MEDIUM or LOW depending on severity of disruption
│
├─ Best practice violation, no real-world exploitability
│   └─ IMPACT: LOW or INFORMATIONAL
│
└─ Code quality, readability, gas efficiency
    └─ IMPACT: INFORMATIONAL
```

---

## Step 2: Determine Likelihood

```
Who can trigger this, and how hard is it?

├─ Any unprivileged user, no special setup, one transaction
│   └─ LIKELIHOOD: CERTAIN
│
├─ Any user, but requires a specific contract state or prior action
│   └─ LIKELIHOOD: HIGH
│
├─ Requires flashloan or capital (accessible to any funded actor)
│   └─ LIKELIHOOD: HIGH
│
├─ Requires compromised privileged key (owner, admin, multisig)
│   └─ LIKELIHOOD: MEDIUM (centralization risk)
│
├─ Requires two or more independent conditions to align
│   └─ LIKELIHOOD: MEDIUM
│
├─ Requires very specific timing, block conditions, or MEV
│   └─ LIKELIHOOD: LOW-MEDIUM
│
├─ Theoretically possible but no known economic incentive
│   └─ LIKELIHOOD: LOW
│
└─ Requires breaking cryptographic assumptions or protocol consensus
    └─ LIKELIHOOD: NEGLIGIBLE
```

---

## Step 3: Severity Matrix

```
              │  CERTAIN  │   HIGH    │  MEDIUM   │    LOW    │ NEGLIGIBLE
──────────────┼───────────┼───────────┼───────────┼───────────┼───────────
   CRITICAL   │ CRITICAL  │ CRITICAL  │   HIGH    │  MEDIUM   │    LOW
──────────────┼───────────┼───────────┼───────────┼───────────┼───────────
     HIGH     │ CRITICAL  │   HIGH    │   HIGH    │  MEDIUM   │    LOW
──────────────┼───────────┼───────────┼───────────┼───────────┼───────────
    MEDIUM    │   HIGH    │  MEDIUM   │  MEDIUM   │    LOW    │   INFO
──────────────┼───────────┼───────────┼───────────┼───────────┼───────────
     LOW      │  MEDIUM   │    LOW    │    LOW    │   INFO    │   INFO
──────────────┼───────────┼───────────┼───────────┼───────────┼───────────
     INFO     │    LOW    │   INFO    │   INFO    │   INFO    │   INFO
```

---

## Step 4: Apply Escalation Factors

These factors can **raise** severity by one level:

| Factor | Reason |
|--------|--------|
| Loss affects all users, not just the attacker | Systemic impact |
| Protocol cannot recover without full redeploy | Permanent damage |
| Exploit cascades to integrated protocols | Contagion risk |
| No admin/emergency intervention possible | No recovery path |
| Attack is gas-efficient (low cost, high profit) | Economic incentive |
| Publicly known similar exploit (1-day) | Reduced time-to-exploit |
| Vulnerable function called by other contracts | Wider blast radius |

---

## Step 5: Apply De-escalation Factors

These factors can **lower** severity by one level:

| Factor | Reason |
|--------|--------|
| Requires compromised multisig (3/5 or more signers) | High operational barrier |
| Attack only profitable below break-even gas cost | No economic incentive |
| Requires months of accumulated state to be exploitable | Very long setup time |
| Admin can pause and fix within the exploit window | Recoverable |
| Loss capped at a small, bounded amount | Limited blast radius |
| Already mitigated by protocol's own circuit breaker | Defense in depth |
| Token is non-transferable / no secondary market | Low real-world value at risk |

---

## Decision Trees by Vulnerability Type

### Reentrancy

```
Is external call made before state update? (violates CEI)
│
├─ YES: Is the external call to user-controlled address?
│   ├─ YES: Can the callback drain funds or manipulate critical state?
│   │   ├─ YES → CRITICAL
│   │   └─ NO (state-only manipulation) → HIGH
│   └─ NO (fixed address, trusted contract): → MEDIUM (cross-contract reentrancy risk)
│
├─ NO (CEI followed): Is there a reentrancy guard?
│   ├─ YES → INFORMATIONAL (belt-and-suspenders note)
│   └─ NO: Can read-only reentrancy affect price calculations elsewhere?
│       ├─ YES → HIGH (read-only reentrancy)
│       └─ NO → LOW (informational CEI note)
```

### Access Control

```
Is there a missing or bypassable access control check?
│
├─ On a privileged function (mint, drain, upgrade, pause)?
│   ├─ Callable by anyone → CRITICAL
│   └─ Callable by specific role that should not have it → HIGH
│
├─ On an admin function (fee setting, parameter update)?
│   ├─ No timelock, no multisig → MEDIUM (centralization)
│   └─ Has timelock and multisig → LOW (informational)
│
└─ On a view function (read-only)?
    └─ INFORMATIONAL (unless it leaks sensitive data)
```

### Oracle Manipulation

```
How is the price obtained?
│
├─ spot price from AMM reserves (getReserves, slot0, getSqrtTwapX96 with twapInterval=0)
│   ├─ Used for critical operation (liquidation, borrowing, minting)?
│   │   └─ CRITICAL (flashloan-manipulable)
│   └─ Used for non-critical (display, approximate calculation)?
│       └─ MEDIUM
│
├─ TWAP but interval is too short (< 30 min for low liquidity pairs)?
│   └─ HIGH (economically manipulable)
│
├─ Chainlink but no staleness check?
│   ├─ Feed known to go stale (e.g., low-volume tokens)?
│   │   └─ HIGH
│   └─ Highly liquid, active feed?
│       └─ MEDIUM
│
└─ Chainlink with full validation (round, staleness, sequencer)?
    └─ INFORMATIONAL (review completeness)
```

### Integer Arithmetic

```
Is there unchecked or potentially overflowing arithmetic?
│
├─ Solidity >= 0.8.0 without `unchecked`?
│   └─ LOW-INFORMATIONAL (reverts on overflow, no fund loss)
│
├─ Inside `unchecked {}` block?
│   ├─ Can overflow path be triggered by user?
│   │   ├─ YES → Leads to fund theft or protocol break? → HIGH/CRITICAL
│   │   └─ YES → Leads to incorrect accounting only? → MEDIUM
│   └─ NO (internal, bounded input) → INFORMATIONAL
│
└─ Division before multiplication (precision loss)?
    ├─ Affects fee/reward calculation?
    │   └─ MEDIUM (systematic loss for users)
    └─ Rounding in protocol's favor, bounded amount?
        └─ LOW
```

### Flash Loans

```
Is the vulnerability exploitable with a flash loan?
│
├─ Governance voting with live token balance?
│   └─ CRITICAL (no capital required in practice)
│
├─ Price oracle manipulation during single transaction?
│   └─ CRITICAL (if used for fund-extracting operations)
│
├─ Collateral manipulation for undercollateralized borrow?
│   └─ CRITICAL
│
└─ Flash loan only amplifies an existing small issue?
    └─ Inherit the base severity (usually HIGH if funds at risk)
```

### Upgrade / Proxy

```
Is there an upgrade-related vulnerability?
│
├─ Uninitialized implementation contract?
│   ├─ UUPS or custom — attacker can call initialize and selfdestruct?
│   │   └─ CRITICAL
│   └─ TransparentProxy — impl not directly callable?
│       └─ MEDIUM
│
├─ Storage collision between proxy and implementation?
│   └─ CRITICAL (arbitrary storage write)
│
├─ Missing `_disableInitializers()` in constructor?
│   └─ HIGH (implementation can be taken over)
│
├─ No timelock on upgrade?
│   └─ MEDIUM (centralization/rug risk)
│
└─ Missing authorization on `upgradeTo` (UUPS)?
    └─ CRITICAL (anyone can upgrade)
```

### Signature / EIP-712

```
Is there a signature validation issue?
│
├─ Missing nonce → replay attack possible?
│   └─ HIGH/CRITICAL (depends on what is signed)
│
├─ Missing chainId → cross-chain replay?
│   └─ HIGH
│
├─ Missing contract address → cross-contract replay?
│   └─ HIGH
│
├─ Using ecrecover directly (not checking address(0))?
│   └─ HIGH (zero address may pass)
│
├─ Malleable signature not rejected?
│   └─ MEDIUM (depends on usage context)
│
└─ Missing EIP-712 domain separator?
    └─ MEDIUM (signature phishing possible)
```

---

## Severity Definitions with Concrete Examples

### Critical
**Criteria**: Direct and unconditional loss of user or protocol funds; permanent
corruption of contract state; anyone can exploit with no special setup.

**Examples**:
- Reentrancy draining a vault in a single transaction
- Missing `onlyOwner` on `mint()` allowing infinite token creation
- Storage collision corrupting the proxy's admin slot
- Flash loan governance takeover in one block
- Uninitialized UUPS proxy allowing `selfdestruct`

**Report language**: "An attacker can steal all funds from the protocol in a single
transaction without any special permissions."

---

### High
**Criteria**: Conditional fund loss; significant protocol disruption; requires specific
conditions but those conditions can be manufactured by an attacker.

**Examples**:
- Price oracle uses spot price; exploitable with capital > $X but possible
- Flash loan needed but the profit significantly exceeds the fee
- Liquidation logic allows bad debt accumulation under specific market conditions
- ERC-4626 first depositor inflation attack (requires being first)
- Signature replay across chains (requires the same contract on multiple chains)

**Report language**: "Under [specific condition], an attacker can cause [damage].
This condition can be triggered by the attacker."

---

### Medium
**Criteria**: Indirect or bounded loss; requires multiple conditions; protocol
recoverable without full redeploy; centralization risk.

**Examples**:
- No slippage protection on a swap (user-facing, not protocol-extracting)
- Missing event emission on critical state change
- Chainlink feed used without staleness check (unlikely to go stale on this feed)
- Admin can set fee to 100% (centralization, not a protocol bug)
- Interest rate rounding direction favors protocol over users by small amounts

**Report language**: "Under [specific conditions], users may experience [bounded
impact]. The protocol can recover by [action]."

---

### Low
**Criteria**: Best practice violations; theoretical edge cases; no realistic path to
exploitation; minor code quality issues with possible adverse effects.

**Examples**:
- Missing zero-address check on non-critical setter
- Floating pragma (`^0.8.0`)
- Use of `tx.origin` for display purposes (not authentication)
- Missing indexed fields in events
- Gas inefficiency in a cold path

**Report language**: "While this does not represent an immediate security risk,
[recommendation] to align with best practices."

---

### Informational
**Criteria**: No security impact; code quality, documentation, gas optimization,
or architectural suggestions.

**Examples**:
- Unused imports
- Variable shadowing (no functional impact in context)
- Inconsistent naming conventions
- Missing NatSpec
- Gas: use `calldata` instead of `memory` for read-only params

**Report language**: "For code quality and maintainability, consider [suggestion]."

---

## Common Misclassification Traps

| Pattern | Common Mistake | Correct Reasoning |
|---------|---------------|-------------------|
| Centralization / admin rug | Marked CRITICAL | Usually MEDIUM unless admin key is EOA with no multisig |
| Missing event | Marked LOW | Usually INFORMATIONAL unless event drives off-chain logic |
| Front-running | Always CRITICAL | Depends on profitability and whether MEV bots will actually run it |
| Griefing / DoS | Always HIGH | MEDIUM if recoverable, LOW if gas cost to grief > damage |
| Rounding error | INFORMATIONAL | Can be MEDIUM if systematic and cumulative across many users |
| Theoretical attack (no PoC possible) | Keeps original severity | Should be de-escalated one level without a working PoC |
| Protocol works as designed but design is bad | HIGH | Usually MEDIUM/LOW unless clearly harmful to users |

---

## Severity Inflation / Deflation Checklist

Before finalizing, ask:

```
Inflation checks (am I overstating severity?):
[ ] Does my PoC actually work, or is it theoretical?
[ ] Did I account for the full attack cost (gas, capital, time)?
[ ] Is the admin fix actually difficult? (e.g., pause + patch takes hours)
[ ] Is the condition I need actually triggerable in production state?
[ ] Am I double-counting with another finding?

Deflation checks (am I understating severity?):
[ ] Can this be combined with another finding to increase impact?
[ ] Does this affect ALL users or only one?
[ ] Is there a flash loan or MEV amplification path I missed?
[ ] Does this finding bypass an existing security control?
[ ] Is the "specific condition" actually the normal operating state?
```

---

## Cross-References

- `vulnerability-taxonomy.md` — Vulnerability patterns with code examples
- `industry-standards.md` — Official severity definitions and SWC registry
- `exploit-case-studies.md` — Real-world examples calibrated against these severities
- `report-template.md` — How to write up a finding at each severity level
