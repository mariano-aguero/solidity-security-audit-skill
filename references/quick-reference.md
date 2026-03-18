# Quick Reference Card

One-page cheat sheet for rapid security assessment. Use for initial scan before deep dive.

---

## 60-Second Red Flags

Scan for these patterns immediately:

```
.call{value:          → Reentrancy risk
.delegatecall(        → Code injection risk
selfdestruct(         → Contract destruction
tx.origin             → Phishing vulnerability
block.timestamp       → Miner manipulation
block.number          → Timing dependency
ecrecover(            → Signature issues
abi.encodePacked(     → Hash collision (if 2+ dynamic types)
transfer(             → 2300 gas limit: no longer blocks reentrancy if callee uses TSTORE (§19.7)
send(                 → Silent failure risk
onERC1155Received(    → Reentrancy hook (like ERC-777)
IERC7702Delegation(   → EOA-as-contract risks (Pectra)
tstore(               → TSTORE Poison: solc 0.8.28–0.8.33 + --via-ir corrupts slot (§19.6)
EXTDELEGATECALL(      → EOF only — legacy contracts blocked; check deployment target (§22)
```

---

## Top 10 Critical Checks

| Priority | Check | What to Look For |
|----------|-------|------------------|
| 1 | **Reentrancy** | External calls before state updates |
| 2 | **Access Control** | Missing modifiers, unprotected functions |
| 3 | **Oracle Manipulation** | Spot prices, single oracle, no staleness check |
| 4 | **Uninitialized Proxy** | Implementation without `_disableInitializers()` |
| 5 | **Unchecked Returns** | `.call()` without checking `success` |
| 6 | **Integer Issues** | Unchecked blocks, division before multiplication |
| 7 | **Flash Loan Vectors** | Live balances for pricing/voting |
| 8 | **Missing Slippage** | Swaps without `minAmountOut` |
| 9 | **Centralization** | Single owner, no timelock, instant admin actions |
| 10 | **Input Validation** | Missing zero-address, bounds, array length checks |

---

## Pattern Recognition

### Vulnerable
```solidity
// Reentrancy
(bool s,) = to.call{value: amt}("");
balances[msg.sender] -= amt;  // State AFTER call

// Spot price oracle
uint256 price = reserveB / reserveA;

// Missing access control
function mint(address to, uint256 amt) external {

// Unchecked return
token.transfer(to, amount);  // No bool check

// Flash loan governance
uint256 votes = token.balanceOf(voter);  // Live balance
```

### Secure
```solidity
// CEI Pattern
balances[msg.sender] -= amt;  // State BEFORE call
(bool s,) = to.call{value: amt}("");

// Chainlink oracle
(,int256 price,,,) = feed.latestRoundData();

// Access control
function mint(address to, uint256 amt) external onlyRole(MINTER) {

// SafeERC20
token.safeTransfer(to, amount);

// Snapshot voting
uint256 votes = token.getPastVotes(voter, snapshot);
```

---

## Quick Tool Commands

```bash
# Static analysis (run first)
slither . --json report.json
aderyn .

# Compile and test
forge build
forge test -vvv

# Check specific vulnerability
slither . --detect reentrancy-eth,reentrancy-no-eth

# Gas report
forge test --gas-report

# Fork mainnet test
forge test --fork-url $ETH_RPC_URL
```

---

## Severity Quick Guide

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | Direct fund loss, no conditions | Unprotected withdraw, reentrancy drain |
| **High** | Fund loss with conditions | Oracle manipulation, access control bypass |
| **Medium** | Limited impact, specific conditions | Griefing, temporary DoS, front-running |
| **Low** | Theoretical, best practice | Missing events, floating pragma |
| **Informational** | Code quality | Naming, unused variables, gas |

---

## Protocol-Specific Priority

### Lending Protocol
1. Liquidation logic manipulation
2. Collateral factor changes
3. Interest rate calculation
4. Bad debt scenarios
5. Oracle dependencies

### AMM / DEX
1. Price manipulation resistance
2. Slippage protection
3. LP token accounting
4. Fee calculation accuracy
5. Reentrancy in swaps

### Vault / ERC-4626
1. First depositor inflation attack
2. Share price manipulation
3. Withdrawal queue logic
4. Rounding direction
5. Asset/share conversion

### Governance
1. Flash loan voting
2. Proposal validation
3. Timelock bypass
4. Quorum manipulation
5. Vote delegation

### Bridge
1. Message validation
2. Replay protection
3. Validator trust
4. Finality assumptions
5. Rate limiting

---

## DeFi Integration Checks

When contract integrates with external protocols:

| Integration | Key Checks |
|-------------|------------|
| **Uniswap** | Slippage, deadline, callback validation |
| **Chainlink** | Staleness, decimals, L2 sequencer |
| **Aave/Compound** | Health factor, liquidation, interest |
| **Curve** | Read-only reentrancy, virtual price |
| **Balancer** | Flash loan callbacks, pool manipulation |

---

## Invariants to Verify

```solidity
// Universal
totalSupply == sum(balances)
contract.balance >= trackedDeposits

// ERC-4626
convertToAssets(totalSupply()) <= totalAssets()  // solvency
sharePrice only increases (no loss)

// Lending
totalBorrows <= totalDeposits
healthFactor >= 1 for non-liquidatable

// AMM
k_after >= k_before (constant product)
```

---

## Compiler & Toolchain Checks (v3.2.0)

Always check before reviewing transient storage or via-ir builds:

| Check | Risk | Action |
|-------|------|--------|
| `solc 0.8.28–0.8.33` + `--via-ir` + `tstore` | TSTORE Poison — slot corruption | Upgrade to 0.8.34+; see `vulnerability-taxonomy.md §19.6` |
| `transfer()`/`send()` as reentrancy guard | 2300-gas no longer blocks TSTORE callee | Replace with `nonReentrant`; see §19.7 |
| `payable(addr).transfer()` or `.send()` in codebase | Won't compile under Solidity 0.9.0; migration to `.call()` opens reentrancy | Migrate with CEI + `nonReentrant`; see §23 |
| Solidity 0.8.20+ without explicit `evmVersion` | Emits PUSH0 (EIP-3855) — fails on non-Shanghai chains | Set `evm_version = "paris"` for cross-chain; see §24 |
| `upgradeTo(newImpl)` without `proxiableUUID()` check | UUPS brick attack — proxy permanently stuck | Use OZ `_upgradeToAndCallUUPS`; see §25.3 |
| Raw `sstore` near ERC-1967 slot values in implementation | Overwrites proxy implementation pointer | Audit all assembly slots vs §25.1 constants |
| EOF-targeted deploy (EIP-7692/Fusaka) | `EXTDELEGATECALL` breaks legacy contracts | Full EOF checklist at §22 |
| OZ v4→v5 upgrade without migration | Storage slot collision | Run `@openzeppelin/upgrade-safe-checker`; see §6.6 |
| Custom math with bit-shift overflow guard | Sentinel value off-by-one (Cetus $223M) | Verify boundary: see §3.4 |

---

## Common False Positives

Don't report these without deeper analysis:

| Pattern | Why It May Be OK |
|---------|------------------|
| `unchecked` block | Safe if overflow impossible (e.g., loop counter) |
| No zero-address check | May be intentional (burn address) |
| `transfer` instead of `call` | Legacy but works for EOAs |
| Centralization | May be intended for admin (check timelock) |
| Floating pragma | OK in libraries, bad in deployable contracts |

---

## Audit Output Template

```markdown
## [SEV-ID] Title

**Severity**: Critical/High/Medium/Low/Informational
**File**: `Contract.sol#L42`

### Description
[What's wrong]

### Impact
[What damage can occur]

### PoC
[Steps or code to reproduce]

### Recommendation
[How to fix with code example]
```

---

### AI-Generated Code Red Flags

| Signal | What to Check | Reference |
|--------|--------------|-----------|
| Mass commits / "generated by" comments | Every external call: CEI order | `ai-code-patterns.md §2.1` |
| `nonReentrant` missing on external fns | Reentrancy guard placement | `ai-code-patterns.md §2.4` |
| `require()` without message string | Completeness of access control | `ai-code-patterns.md §3` |
| Mixed OZ v4/v5 imports | Storage slot migration risks | `vulnerability-taxonomy.md §6.6` |
| Permit / EIP-712 without nonce | Signature replay vulnerability | `ai-code-patterns.md §2.5` |
| `pure` oracle adapter returning constant | Economic correctness failure | `ai-code-patterns.md §2.3` |

### Glamsterdam Readiness (EIP-7732 / EIP-7928)

- Single-slot timing windows → use ≥ 2–3 slot buffer for withholding tolerance (`glamsterdam.md §1.2`)
- Preconf-based settlement → require post-inclusion finalization delay, not just preconf commitment
- BAL parallelization → pack price + timestamp in same storage slot for atomic reads (`glamsterdam.md §2.2`)
- Proprietary oracle lag → circuit breaker if oracle diverges >X% from external reference
