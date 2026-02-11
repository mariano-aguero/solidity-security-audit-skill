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

### Methodology

Tools and techniques used:
- Manual code review
- Static analysis (Slither, Aderyn)
- Dynamic testing (Foundry)
- [Other tools]

### Test Coverage

| Contract | Coverage |
|----------|----------|
| Contract1.sol | XX% |
| Contract2.sol | XX% |

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

Use Chainlink oracle with staleness checks, or implement TWAP with minimum
observation window of 30 minutes.
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

## Severity Guidelines

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct theft of funds, permanent protocol corruption, bypass of all access controls |
| **High** | Conditional theft of funds, significant protocol disruption, privilege escalation |
| **Medium** | Indirect loss, griefing with cost, issues requiring specific conditions |
| **Low** | Minor issues, best practice violations, theoretical edge cases |
| **Informational** | Code quality, gas optimizations, documentation gaps |
