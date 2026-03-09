# Automated Detection Patterns

Comprehensive pattern-based detection rules for common Solidity vulnerabilities.
These patterns can be used for automated scanning without requiring compilation.

Source: Extracted from mcp-audit-server detection engine.

---

## Table of Contents

1. [DeFi-Specific Detectors](#defi-specific-detectors)
2. [Web3 General Detectors](#web3-general-detectors)
3. [SWC Registry Patterns](#swc-registry-patterns)

---

## DeFi-Specific Detectors

High-priority patterns for DeFi protocol audits.

### Oracle Manipulation (HIGH)

**Description**: Using spot prices from DEX pools without time-weighted averaging
is vulnerable to flash loan manipulation.

**Detection Pattern**:
```regex
(getReserves\s*\(|spot[Pp]rice|getAmountOut\s*\([^)]*\)|token[01]\.balanceOf\s*\(\s*address\s*\(\s*pair)
```

**Vulnerable Code**:
```solidity
function getPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
    return reserve1 * 1e18 / reserve0; // Spot price - manipulable!
}
```

**Recommendation**: Use Chainlink oracles or implement TWAP with sufficient
observation window (e.g., 30 minutes). Never rely on single-block spot prices.

---

### Flash Loan Attack Vector (HIGH)

**Description**: Functions that read token balance and perform critical operations
in the same transaction without flash loan protection.

**Detection Pattern**:
```regex
(balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\).*(?:transfer|mint|burn|withdraw|deposit|swap)|
(?:transfer|mint|burn|withdraw|deposit|swap).*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\))
```

**Recommendation**:
1. Use share-based accounting instead of balanceOf
2. Add reentrancy guards
3. Implement minimum lock time
4. Use before/after balance deltas instead of absolute balances

---

### Missing Slippage Protection (HIGH)

**Description**: Swap operations without minimum output amount are vulnerable
to sandwich attacks and MEV extraction.

**Detection Pattern**:
```regex
(swap|exchange|swapExact)\w*\s*\([^)]*\)(?![^{]*(?:min|minimum|slippage|deadline))
```

**Vulnerable Code**:
```solidity
function swap(address tokenIn, uint256 amountIn) external {
    // No minAmountOut - vulnerable to sandwich attack
    router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
}
```

**Recommendation**:
1. Add minAmountOut/maxAmountIn parameters
2. Implement deadline checks
3. Consider using private mempools or MEV protection services

---

### ERC777 Reentrancy Risk (HIGH)

**Description**: ERC777 tokens have send/receive hooks that enable reentrancy attacks.

**Detection Pattern**:
```regex
(IERC777|ERC777|tokensReceived|tokensToSend|_callTokensReceived|_callTokensToSend|implementer.*777)
```

**Recommendation**:
1. Always use ReentrancyGuard with ERC777 tokens
2. Follow checks-effects-interactions pattern
3. Update state before external calls
4. Consider using ERC20 wrapper contracts for ERC777 tokens

---

### Donation Attack Vector (HIGH)

**Description**: Contracts using `balanceOf(address(this))` for share calculations
are vulnerable to first-depositor inflation attacks.

**Detection Pattern**:
```regex
(balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*[/*]|
[/*]\s*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|
totalAssets.*balanceOf|shares.*balanceOf\s*\(\s*address\s*\(\s*this)
```

**Recommendation**: Use internal accounting or ERC4626 with virtual offset.
See `vulnerability-taxonomy.md` Section 11.5 for full attack scenario.

---

### Precision Loss in Division (MEDIUM)

**Description**: Division before multiplication leads to precision loss.

**Detection Pattern**:
```regex
\w+\s*/\s*\w+\s*\*\s*\w+(?!\s*/)
```

**Vulnerable Code**:
```solidity
// BAD: precision loss
uint256 result = a / b * c;

// GOOD: multiply first
uint256 result = a * c / b;
```

**Recommendation**: Always multiply before dividing. Use fixed-point math
libraries like PRBMath or ABDKMath for complex calculations.

---

### Missing Oracle Staleness Check (HIGH)

**Description**: Chainlink oracle responses must be checked for staleness.

**Detection Pattern**:
```regex
latestRoundData\s*\(\s*\)(?![\s\S]{0,200}updatedAt)
```

**Recommendation**: Check `updatedAt`, `answeredInRound`, and `price > 0`.
See `vulnerability-taxonomy.md` Section 4.2 for secure code example.

---

### Unchecked ERC20 Transfer (MEDIUM)

**Description**: Some ERC20 tokens (USDT, BNB) don't return boolean on transfer.

**Detection Pattern**:
```regex
(?<!safe)[Tt]ransfer(From)?\s*\([^)]+\)\s*;(?!\s*//.*safe)
```

**Recommendation**: Use OpenZeppelin's SafeERC20:
```solidity
using SafeERC20 for IERC20;
token.safeTransfer(to, amount);
token.safeTransferFrom(from, to, amount);
```

---

### Front-Running Vulnerability (MEDIUM)

**Description**: Functions that reveal valuable information can be front-run.

**Detection Pattern**:
```regex
function\s+(reveal|claim|redeem|settle|execute|finalize)\w*\s*\([^)]*\)\s*(external|public)
```

**Recommendation**:
1. Commit-reveal schemes
2. Use private mempools (Flashbots Protect)
3. Add minimum time delays
4. Implement submarine sends for sensitive reveals

---

### Unrestricted Liquidity Removal (MEDIUM)

**Description**: Admin functions that can remove liquidity without timelock
enable rug pulls.

**Detection Pattern**: Functions with `onlyOwner` that modify state and can
withdraw significant funds.

**Recommendation**:
1. Timelock delays for large withdrawals
2. Maximum withdrawal limits per period
3. Multi-sig requirements
4. Vesting schedules for protocol-owned liquidity

---

## Web3 General Detectors

Common patterns for all Solidity projects.

### Hardcoded Addresses (LOW)

**Detection Pattern**:
```regex
(?<!//.*)(0x[a-fA-F0-9]{40})
```

**Recommendation**: Use constructor parameters, immutable variables, or
registry pattern for addresses.

---

### Magic Numbers (INFORMATIONAL)

**Detection Pattern**:
```regex
(?<!0x)(?<![a-zA-Z_])([3-9]\d{2,}|[1-9]\d{3,})(?![a-fA-F0-9]|\s*\])
```

**Recommendation**: Extract to named constants:
```solidity
uint256 constant MAX_SUPPLY = 1000000;
uint256 constant FEE_DENOMINATOR = 10000;
```

---

### Console.log in Production (MEDIUM)

**Detection Pattern**:
```regex
(import\s+["']hardhat/console\.sol["']|console\.(log|logInt|logUint|logString|logBool|logAddress|logBytes)\s*\()
```

**Recommendation**: Remove all console.sol imports before deployment.

---

### TODO/FIXME Comments (LOW)

**Detection Pattern**:
```regex
//\s*(TODO|FIXME|HACK|XXX|BUG)\b
```

**Recommendation**: Resolve all TODO/FIXME before deployment.

---

### Floating Pragma (LOW)

**Detection Pattern**:
```regex
pragma\s+solidity\s*[\^>=<]
```

**Recommendation**: Use fixed pragma: `pragma solidity 0.8.20;`

---

### Centralization Risk (MEDIUM)

Admin functions with `onlyOwner` that can pause, mint, change fees, or modify
critical parameters.

**Recommendation**:
1. Timelock delays for critical operations
2. Multi-sig requirements
3. Maximum bounds for parameter changes
4. Decentralized governance for sensitive functions

---

### Missing Zero Address Check (LOW)

**Detection Pattern**:
```regex
function\s+\w+\s*\([^)]*address\s+(?!.*address\s*\(\s*0\s*\))[^)]*\)\s*(external|public)
```

**Recommendation**:
```solidity
require(addr != address(0), "Zero address");
```

---

### Unlimited Token Approval (MEDIUM)

**Detection Pattern**:
```regex
\.approve\s*\([^,]+,\s*type\s*\(\s*uint256\s*\)\s*\.\s*max\s*\)
```

**Recommendation**:
1. Approve only exact amount needed
2. Use increaseAllowance/decreaseAllowance
3. Implement approval reset mechanisms

---

## ERC-7702 Account Vulnerability Patterns

Patterns specific to EIP-7702 (set-code transactions) introduced in the Pectra upgrade.
A user can delegate their EOA to execute arbitrary bytecode, opening new attack surfaces.

### ERC-7702 Delegatecall in receive() / fallback() (CRITICAL)

**Description**: When an EOA is delegated to a contract that has a `receive()` or `fallback()`
with `delegatecall`, ETH sends to the EOA can trigger arbitrary code in the EOA's storage context.

**Detection Pattern**:
```regex
(receive\s*\(\s*\)|fallback\s*\([^)]*\))\s*\{[^}]*delegatecall
```

**Vulnerable Code**:
```solidity
// Malicious delegation target — receive() performs delegatecall
contract MaliciousDelegate {
    receive() external payable {
        address target = 0xdeadbeef...;
        (bool ok,) = target.delegatecall(abi.encodeWithSignature("drain()"));
    }
}
// When Alice sets her EOA code to MaliciousDelegate, any ETH transfer
// to Alice triggers drain() in Alice's storage context.
```

**Recommendation**:
1. Legitimate delegation contracts must not have `receive()` or `fallback()` with `delegatecall`
2. Audit wallet UIs that support EIP-7702 for blind-signing of authorization tuples
3. See `vulnerability-taxonomy.md` Section 17 for full ERC-7702 threat model

---

### ERC-7702 Nonce Replay / Stale Authorization (HIGH)

**Description**: EIP-7702 authorization tuples include `nonce` and `chain_id`. Stale
authorizations (saved by attackers) can be replayed if the EOA nonce resets, or
cross-chain if `chain_id = 0`.

**Detection Pattern**:
```regex
(chainId\s*==\s*0|chain_id.*0x00|authorization.*nonce.*0x0)
```

**Recommendation**:
1. Wallets must increment EOA nonce after each authorization to invalidate prior tuples
2. Never sign authorizations with `chain_id = 0` (valid on all chains)
3. Verify nonce monotonicity in any on-chain authorization verifier

---

### ERC-7702 Delegation Phishing (HIGH)

**Description**: Users can be tricked into signing an EIP-7702 authorization tuple that
delegates their EOA to attacker-controlled code, granting the attacker full control of
the EOA's assets and storage.

**Detection Pattern**:
```regex
(setCode|AUTHCALL|eip7702|EIP7702|authorization.*tuple|delegate.*eoa)
```

**Recommendation**:
1. Wallets must display human-readable description of delegation target before signing
2. Restrict `setCode` to audited, well-known contracts (delegation registries)
3. Off-chain: scan authorization relays for unverified contract bytecode

---

## Transient Storage Patterns

Patterns for EIP-1153 (`tload`/`tstore`) introduced in Solidity 0.8.24 (Cancun).
Transient storage clears at transaction end but persists across internal calls in the same tx.

### Transient Storage Without Cleanup (MEDIUM)

**Description**: Using `tstore` without a corresponding cleanup `tstore(slot, 0)` at the
end of a function can leak state across internal calls or composable interactions within
the same transaction. This is the most common transient storage misuse pattern.

**Detection Pattern**:
```regex
tstore\s*\([^)]+\)(?![\s\S]{0,500}tstore\s*\([^,]+,\s*0\s*\))
```

**Vulnerable Code**:
```solidity
// BAD: tstore without cleanup — value persists for rest of transaction
function lockOperation() internal {
    assembly { tstore(LOCK_SLOT, 1) }
    _doWork();
    // Missing: assembly { tstore(LOCK_SLOT, 0) }
    // If _doWork() calls another contract that checks LOCK_SLOT,
    // they will see stale value 1 even after lockOperation() returns
}
```

**Secure Code**:
```solidity
// GOOD: always clean up transient storage
function lockOperation() internal {
    assembly { tstore(LOCK_SLOT, 1) }
    _doWork();
    assembly { tstore(LOCK_SLOT, 0) } // explicit cleanup
}
```

**Recommendation**:
1. Always pair `tstore(slot, value)` with `tstore(slot, 0)` in a `finally`-equivalent pattern
2. Use try-catch or assembly to ensure cleanup even on revert paths
3. Prefer OpenZeppelin's `ReentrancyGuardTransient` over manual `tstore` for locks

---

### Permit Frontrunning (MEDIUM)

**Description**: ERC-20 `permit()` signatures can be front-run: an attacker extracts the
signature from a pending `depositWithPermit()` call and calls `permit()` first, then
the original tx fails if the protocol checks for allowance via `transferFrom` only.
Alternatively, MEV bots consume the permit to grief the user.

**Detection Pattern**:
```regex
function\s+\w*[Pp]ermit\w*\s*\([^)]*uint8\s+v[^)]*bytes32\s+r[^)]*bytes32\s+s[^)]*\)\s*(external|public)(?![^{]*try)
```

**Vulnerable Code**:
```solidity
// BAD: if permit is front-run, this reverts — DoS on deposit
function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s);
    IERC20(token).transferFrom(msg.sender, address(this), amount); // reverts if allowance already consumed
}
```

**Secure Code**:
```solidity
// GOOD: use try-catch around permit — allowance already set is also acceptable
function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    try IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
    // Falls back to existing allowance if permit was already consumed
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
}
```

**Recommendation**:
1. Wrap `permit()` calls in `try-catch` — a consumed permit is not an error
2. Never revert if allowance is already sufficient
3. Cross-reference `vulnerability-taxonomy.md` Section 10.3 for full permit attack taxonomy

---

## SWC Registry Patterns

See `industry-standards.md` for the complete SWC Registry reference table.

**Quick severity guide for triage:**
- **Critical**: SWC-105, SWC-106, SWC-112, SWC-124, SWC-135
- **High**: SWC-101, SWC-104, SWC-107, SWC-115, SWC-120
- **Medium**: SWC-100, SWC-110, SWC-113, SWC-114, SWC-117, SWC-128, SWC-133
- **Low**: SWC-103, SWC-108, SWC-116, SWC-129, SWC-134

---

## Automated Scan Workflow

### Quick Scan Commands

```bash
# Run Slither for static analysis
slither . --json slither-report.json

# Run Aderyn for Rust-based detection
aderyn . -o aderyn-report.md

# Run custom pattern matching
# (use regex patterns above with grep or custom tooling)
grep -rn "getReserves\|spotPrice" src/
grep -rn "balanceOf.*address.*this" src/
grep -rn "delegatecall\|selfdestruct" src/
```

### Severity-Based Triage

1. **Critical First**: SWC-105, SWC-106, SWC-112, SWC-124, SWC-135
2. **High Priority**: SWC-101, SWC-104, SWC-107, SWC-115, SWC-120
3. **Medium Review**: DeFi-specific patterns, SWC-100, SWC-113, SWC-117
4. **Low/Info**: Code quality, gas optimizations, style issues

### False Positive Indicators

Look for these patterns that indicate the issue is handled:

| Vulnerability | Safe Pattern |
|--------------|--------------|
| Reentrancy | `nonReentrant` modifier, CEI pattern |
| Access Control | `onlyOwner`, `onlyRole`, `require(msg.sender ==` |
| Unchecked Call | `(bool success, ) =`, followed by `require(success)` |
| Signature Issues | `SignatureChecker`, ECDSA library |
| tx.origin | Using `msg.sender` for auth |
