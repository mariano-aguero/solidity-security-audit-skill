# Audit Report Template

Standard format for professional security audit reports.

---

## Report Structure

```markdown
# Security Audit Report

**Protocol**: [Protocol Name]
**Repository**: [GitHub URL]
**Commit**: [Commit Hash]
**Audit Date**: [Start Date] - [End Date]
**Auditor**: [Auditor Name/Team]

---

## Executive Summary

Brief overview of:
- What was audited (scope)
- Key findings summary
- Overall risk assessment

### Findings Summary

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Informational | X |

### Risk Rating

[Critical / High / Medium / Low]

Overall assessment of protocol security posture.

---

## Scope

### Contracts Reviewed

| Contract | SLOC | Purpose |
|----------|------|---------|
| `Contract1.sol` | XXX | Description |
| `Contract2.sol` | XXX | Description |

### Out of Scope

- External dependencies
- Deployment scripts
- Test files
- [Other exclusions]

---

## Findings

### [C-01] Critical Finding Title

**Severity**: Critical
**Status**: [Open / Acknowledged / Fixed]
**File**: `Contract.sol`
**Lines**: L42-L58

#### Description

Clear explanation of the vulnerability, including:
- What the issue is
- Why it exists
- Technical details

#### Impact

Concrete damage description:
- Funds at risk (quantify if possible)
- Protocol disruption
- User impact

#### Proof of Concept

```solidity
// Step-by-step exploit or test demonstrating the issue
function test_Exploit() public {
    // Setup
    // Attack steps
    // Assert damage
}
```

Or written steps:
1. Attacker does X
2. Contract responds with Y
3. Result: Z damage

#### Recommendation

Specific fix with code:

```solidity
// Before (vulnerable)
function withdraw() external {
    (bool success,) = msg.sender.call{value: balances[msg.sender]}("");
    balances[msg.sender] = 0;
}

// After (fixed)
function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}
```

#### Team Response

[Team's response to the finding]

---

### [H-01] High Finding Title

[Same structure as above]

---

### [M-01] Medium Finding Title

[Same structure as above]

---

### [L-01] Low Finding Title

[Same structure as above]

---

### [I-01] Informational Finding Title

[Same structure as above]

---

## Recommendations

### Immediate Actions

1. Fix all Critical and High findings before deployment
2. [Specific recommendation]

### Suggested Improvements

1. Consider adding [feature]
2. Improve test coverage for [area]

---

## Appendix

### Threat Model Summary

_Produced during Phase 0. Include only for Full Audit mode._

| Dimension | Assessment |
|-----------|------------|
| **Actors** | [e.g., users, liquidators, keepers, governance, MEV bots] |
| **Crown Jewels** | [e.g., user funds in Vault.sol ~$XM TVL] |
| **Critical Invariants** | [e.g., totalBorrows ≤ totalAssets at all times] |
| **Trust Boundaries** | [e.g., Chainlink ETH/USD feed, Uniswap V3 TWAP, 3/5 multisig] |
| **MEV Surface** | [e.g., liquidations are MEV-able; swaps have no deadline] |
| **Admin Blast Radius** | [e.g., owner can upgrade + pause; no timelock → high risk] |

### Methodology

Tools and techniques used:
- Manual code review
- Static analysis (Slither, Aderyn)
- Dynamic testing (Foundry invariant + fuzz)
- [Other tools used]

### Test Coverage

| Contract | Line Coverage | Branch Coverage |
|----------|--------------|-----------------|
| Contract1.sol | XX% | XX% |
| Contract2.sol | XX% | XX% |

### Disclaimer

This audit is not a guarantee of security. It represents a point-in-time review
based on the code provided. The auditor makes no warranties about the code's
fitness for purpose.
```

---

## Finding Format Examples

### Critical Finding Example

```markdown
### [C-01] Unprotected Initialize Allows Attacker to Take Ownership

**Severity**: Critical
**Status**: Open
**File**: `VaultV1.sol`
**Lines**: L15-L20

#### Description

The `initialize` function lacks access control, allowing anyone to call it
and set themselves as the owner of the implementation contract.

```solidity
function initialize(address _owner) external {
    owner = _owner; // No protection!
}
```

Since the implementation contract is not initialized at deployment, an attacker
can call `initialize` directly on it, become the owner, and potentially
`selfdestruct` the implementation, bricking all proxies.

#### Impact

- Complete loss of protocol
- All user funds locked permanently
- No recovery possible

#### Proof of Concept

```solidity
function test_StealOwnership() public {
    // Get implementation address
    address impl = getImplementation(proxy);

    // Attacker initializes implementation
    vm.prank(attacker);
    VaultV1(impl).initialize(attacker);

    // Attacker is now owner
    assertEq(VaultV1(impl).owner(), attacker);

    // Attacker can selfdestruct
    vm.prank(attacker);
    VaultV1(impl).destroy(); // Bricks all proxies
}
```

#### Recommendation

Add `_disableInitializers()` in constructor:

```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}
```
```

---

### High Finding Example

```markdown
### [H-01] Flash Loan Price Manipulation in Collateral Valuation

**Severity**: High
**Status**: Open
**File**: `LendingPool.sol`
**Lines**: L89-L95

#### Description

The `getCollateralValue` function uses spot prices from Uniswap reserves,
which can be manipulated within a single transaction using flash loans.

```solidity
function getCollateralValue(address user) public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    uint256 price = reserve1 * 1e18 / reserve0; // Spot price!
    return userCollateral[user] * price / 1e18;
}
```

#### Impact

An attacker can:
1. Flash borrow tokens to manipulate reserves
2. Inflate collateral value
3. Borrow more than entitled
4. Return flash loan
5. Leave protocol with bad debt

Estimated loss: Up to entire pool TVL

#### Recommendation

Use Chainlink oracle with staleness checks instead of spot reserves:

```solidity
// Before (vulnerable)
function getCollateralValue(address user) public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    uint256 price = reserve1 * 1e18 / reserve0; // manipulatable
    return userCollateral[user] * price / 1e18;
}

// After (secure)
function getCollateralValue(address user) public view returns (uint256) {
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(price > 0, "Invalid price");
    require(block.timestamp - updatedAt < 1 hours, "Stale price");
    return userCollateral[user] * uint256(price) / 1e8; // Chainlink 8 decimals
}
```

#### Team Response

[Team's response to the finding]
```

---

### Medium Finding Example

```markdown
### [M-01] Missing Slippage Protection in Swap Function

**Severity**: Medium
**Status**: Open
**File**: `Router.sol`
**Lines**: L45-L52

#### Description

The `swap` function does not enforce a minimum output amount, making users
vulnerable to sandwich attacks.

```solidity
function swap(address tokenIn, uint256 amountIn) external {
    // No minAmountOut parameter
    uint256 amountOut = _calculateOutput(tokenIn, amountIn);
    IERC20(tokenOut).transfer(msg.sender, amountOut);
}
```

#### Impact

MEV bots can sandwich user transactions, extracting value from their slippage
tolerance. Users receive fewer tokens than expected.

#### Recommendation

Add `minAmountOut` and `deadline` parameters:

```solidity
function swap(
    address tokenIn,
    uint256 amountIn,
    uint256 minAmountOut,
    uint256 deadline
) external {
    require(block.timestamp <= deadline, "Expired");
    uint256 amountOut = _calculateOutput(tokenIn, amountIn);
    require(amountOut >= minAmountOut, "Slippage");
    IERC20(tokenOut).transfer(msg.sender, amountOut);
}
```
```

---

### Low Finding Example

```markdown
### [L-01] Missing Zero Address Check in Constructor

**Severity**: Low
**Status**: Open
**File**: `Token.sol`
**Lines**: L12

#### Description

The constructor does not validate that `_treasury` is not the zero address.
If deployed with zero address, fees would be permanently burned.

```solidity
constructor(address _treasury) {
    treasury = _treasury; // No validation
}
```

#### Recommendation

```solidity
constructor(address _treasury) {
    require(_treasury != address(0), "Zero address");
    treasury = _treasury;
}
```
```

---

### Informational Finding Example

```markdown
### [I-01] Floating Pragma Version

**Severity**: Informational
**Status**: Open
**File**: All contracts

#### Description

Contracts use floating pragma `^0.8.20` which could compile with different
versions, potentially introducing inconsistencies.

#### Recommendation

Lock pragma to specific version: `pragma solidity 0.8.20;`
```

---

## Gas Finding Format

Gas findings use `[G-XX]` prefix. They are optional in private audits but
required in Code4rena, Cyfrin, and Sherlock contests.

```markdown
### [G-01] Gas Finding Title

**Severity**: Gas
**Status**: Open
**File**: `Contract.sol`
**Lines**: L10-L15

#### Description

Explanation of the inefficiency and why it wastes gas.

#### Gas Saved

Estimated savings: ~X gas per call / ~X gas per deployment

#### Recommendation

```solidity
// Before
for (uint256 i = 0; i < array.length; i++) { ... }

// After — cache length
uint256 len = array.length;
for (uint256 i = 0; i < len; i++) { ... }
```
```

---

## Severity Guidelines

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct theft of funds, permanent protocol corruption, bypass of all access controls |
| **High** | Conditional theft of funds, significant protocol disruption, privilege escalation |
| **Medium** | Indirect loss, griefing with cost, issues requiring specific conditions |
| **Low** | Minor issues, best practice violations, theoretical edge cases |
| **Informational** | Code quality, gas optimizations, documentation gaps |
| **Gas** | Unnecessary gas consumption with no security impact |

---

## Contest Submission Format

Competitive audit platforms (Code4rena, Sherlock, Cantina) use specific formats
that differ from private audit reports. Below are the canonical formats.

---

### Code4rena

Each finding is a separate GitHub issue. PoC is required for H/M.

```markdown
## [H-01] Concise, specific finding title

**Lines of code**: https://github.com/[org]/[repo]/blob/[commit]/src/Contract.sol#L42-L67

### Impact

Direct statement of what an attacker achieves. Use dollar amounts where possible.
Example: "An attacker can drain the entire vault by reentering `withdraw()` before
state is updated. At current TVL of ~$2M this is a complete loss of user funds."

### Proof of Concept

Step-by-step attack, then Foundry PoC:

1. Attacker deploys `AttackContract` pointing at the vulnerable vault
2. Calls `attack()`, which deposits 1 ETH then calls `withdraw()`
3. Vault sends ETH before updating `balances` — attacker re-enters in `receive()`
4. Repeats until vault is drained

```solidity
function testExploit() public {
    vm.deal(address(attacker), 1 ether);
    uint256 vaultBefore = address(vault).balance;
    attacker.attack{value: 1 ether}();
    assertEq(address(vault).balance, 0);
    assertGt(address(attacker).balance, vaultBefore);
}
```

### Recommended Mitigation

```diff
 function withdraw() external {
+    require(!locked, "Reentrant");
+    locked = true;
     uint256 amount = balances[msg.sender];
+    balances[msg.sender] = 0;
     (bool ok,) = msg.sender.call{value: amount}("");
     require(ok);
-    balances[msg.sender] = 0;
+    locked = false;
 }
```
```

**Severity labels**: `[H-01]`, `[M-01]`, `[L-01]`, `[N-01]` (non-critical), `[G-01]` (gas)
**QA/Gas**: bundled into a single report file, not individual issues
**Duplicates**: same root cause = duplicate; highest-quality unique submission earns full reward

---

### Sherlock

Findings are markdown files in the contest repo under `findings/`. Strict structure required.

```markdown
## [H-01] Finding Title

**Severity**: High

**Summary**
One paragraph: what the vulnerability is, where it lives, what it enables.

**Root Cause**
In [Contract.sol#L42](https://github.com/[org]/[repo]/blob/[commit]/src/Contract.sol#L42),
`_validateSignature()` does not check for `address(0)` from `ecrecover`, allowing
any signature to pass when `trustedSigner` is uninitialized.

**Internal pre-conditions**
1. `trustedSigner` is `address(0)` (possible during initialization window)
2. Protocol is not paused

**External pre-conditions**
1. None — attacker only needs to send a transaction

**Attack Path**
1. Attacker observes `trustedSigner == address(0)` on-chain
2. Calls `claimReward(anyHash, randomSig)` — `ecrecover` returns `address(0)`
3. `require(signer == trustedSigner)` passes (both are `address(0)`)
4. Attacker receives full reward pool

**Impact**
High — complete drain of reward pool (~$500k at current rates) with no preconditions.

**Proof of Concept**
```solidity
function test_claimWithoutValidSig() public {
    assertEq(protocol.trustedSigner(), address(0)); // Uninitialized
    bytes memory fakeSig = new bytes(65);
    protocol.claimReward(keccak256("any"), fakeSig); // Passes
    assertGt(rewardToken.balanceOf(attacker), 0);
}
```

**Recommended Mitigation**
```solidity
function claimReward(bytes32 hash, bytes calldata sig) external {
+   require(trustedSigner != address(0), "Signer not configured");
    address signer = ECDSA.recover(hash, sig); // reverts on address(0)
    require(signer == trustedSigner, "Wrong signer");
    _payReward(msg.sender);
}
```
```

**Severity**: Only H/M findings are rewarded; Low/Informational receive no payout
**Duplicates**: Grouped by root cause; lowest SLOC PoC wins the group
**Escalation**: Watson escalation system — disputed findings go to senior Watsons

---

### Cantina / Cyfrin CodeHawks

```markdown
**Title**: [Severity] Concise finding title

**Severity**: Critical / High / Medium / Low / Informational

**Context**: `src/Contract.sol#L42-L67`

**Description**
Technical explanation referencing specific code. State the violated invariant.

**Proof of Concept**
[Foundry test or numbered attack steps]

**Recommendation**
[Specific fix with code diff if applicable]

**[Protocol Response]**: Fixed / Acknowledged / Won't Fix
**Fix**: [commit hash or PR link]
```

---

### Severity Comparison Across Platforms

| Severity | Code4rena | Sherlock | Cantina/Cyfrin |
|----------|-----------|----------|----------------|
| Highest | High | High | Critical |
| Second | Medium | Medium | High |
| Third | Low (QA) | Low (no reward) | Medium |
| Notes | Gas / NC | Gas / Info | Low / Info |

---

### Common Rejection Reasons

1. **No PoC for H/M** — judges require a working Foundry test
2. **Invalid preconditions** — attack requires conditions prevented elsewhere
3. **Known issue** — check `README.md`, prior audits, bot race findings
4. **Wrong severity** — H needs direct loss; M needs conditional loss or griefing
5. **Duplicate root cause** — even with a different attack path, same root = duplicate
6. **Out of scope** — test files, deployment scripts, external dependencies
7. **Admin trust assumption** — if admin is trusted, admin-abuse findings are typically Low
