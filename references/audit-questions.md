# Audit Questions Checklist

Systematic questions to ask when reviewing each type of function or pattern.

---

## General Function Review

For EVERY function, ask:

### Access Control
- [ ] Who can call this function?
- [ ] Is the access modifier correct (public/external/internal/private)?
- [ ] Are there missing access control checks?
- [ ] Can a non-owner call admin functions?

### Input Validation
- [ ] Are all parameters validated?
- [ ] Can zero address be passed where it shouldn't?
- [ ] Can zero amounts cause issues?
- [ ] Are array lengths checked?
- [ ] Can overflow occur in arithmetic?

### State Changes
- [ ] What state does this function modify?
- [ ] Is the state updated before external calls (CEI)?
- [ ] Can this function be called multiple times unexpectedly?
- [ ] Does it emit events for important changes?

### External Interactions
- [ ] Does it make external calls?
- [ ] Are return values checked?
- [ ] Can external calls revert and cause issues?
- [ ] Is reentrancy possible?

---

## Deposit / Stake Functions

```solidity
function deposit(uint256 amount) external { ... }
```

### Questions
- [ ] Can user deposit zero?
- [ ] Is the token transfer done safely (SafeERC20)?
- [ ] Does it handle fee-on-transfer tokens?
- [ ] Does it handle rebasing tokens?
- [ ] Can first depositor manipulate share price (inflation attack)?
- [ ] Are shares minted proportionally to deposit?
- [ ] Is there a minimum deposit requirement?
- [ ] What happens if contract is paused during deposit?
- [ ] Can deposit be front-run?
- [ ] Is reentrancy possible via token callbacks (ERC777)?

---

## Withdraw / Unstake Functions

```solidity
function withdraw(uint256 amount) external { ... }
```

### Questions
- [ ] Can user withdraw more than their balance?
- [ ] Is withdrawal possible when paused? (Often should be allowed)
- [ ] Are shares burned before or after transfer (CEI)?
- [ ] Can withdrawal be blocked by attacker (DoS)?
- [ ] Is there a cooldown/timelock?
- [ ] Are pending rewards handled correctly?
- [ ] What happens if token transfer fails?
- [ ] Can user withdraw to a different address?
- [ ] Is the entire balance withdrawable, or is dust left?

---

## Swap / Exchange Functions

```solidity
function swap(address tokenIn, address tokenOut, uint256 amountIn) external { ... }
```

### Questions
- [ ] Is slippage protection implemented (minAmountOut)?
- [ ] Is there a deadline parameter?
- [ ] Can the swap be sandwiched?
- [ ] Is the price calculation correct?
- [ ] Is the price from a manipulation-resistant source?
- [ ] Are fees calculated correctly?
- [ ] Can the swap be front-run?
- [ ] What if tokenIn == tokenOut?
- [ ] Are both tokens validated (not zero address)?
- [ ] Can swap drain the pool completely?

---

## Borrow Functions

```solidity
function borrow(uint256 amount) external { ... }
```

### Questions
- [ ] Is collateral requirement enforced?
- [ ] Is health factor checked before allowing borrow?
- [ ] Can user borrow and immediately be liquidatable (rounding)?
- [ ] Is there a borrow cap (per user or global)?
- [ ] Is interest rate calculated correctly?
- [ ] Can user borrow with flash-loaned collateral?
- [ ] Is the oracle price fresh and validated?
- [ ] Can borrow be used to manipulate pool rates?

---

## Liquidation Functions

```solidity
function liquidate(address user, uint256 amount) external { ... }
```

### Questions
- [ ] Is health factor threshold correct?
- [ ] Can healthy positions be liquidated (false positive)?
- [ ] Can unhealthy positions escape liquidation (false negative)?
- [ ] Is liquidation bonus reasonable?
- [ ] Can liquidator receive more than user's collateral?
- [ ] Is there bad debt handling?
- [ ] Can liquidation be front-run?
- [ ] Can self-liquidation be exploited?
- [ ] Can partial liquidation leave dust?
- [ ] Is oracle price fresh at liquidation time?

---

## Mint Functions

```solidity
function mint(address to, uint256 amount) external { ... }
```

### Questions
- [ ] Who can call mint?
- [ ] Is there a max supply cap?
- [ ] Is max supply enforced correctly (off-by-one)?
- [ ] Can zero address receive minted tokens?
- [ ] For NFTs: is _safeMint used? (reentrancy via callback)
- [ ] Is token ID generation predictable? (frontrunning)
- [ ] Are whitelist/allowlist checks correct?
- [ ] Is Merkle proof verification correct?

---

## Burn Functions

```solidity
function burn(uint256 amount) external { ... }
```

### Questions
- [ ] Can user burn more than balance?
- [ ] Who can burn whose tokens?
- [ ] Is allowance checked for burning on behalf?
- [ ] Are locked tokens protected from burning?
- [ ] Is total supply updated correctly?
- [ ] For NFTs: is token ownership verified?

---

## Transfer Functions

```solidity
function transfer(address to, uint256 amount) external { ... }
```

### Questions
- [ ] Can transfer to zero address?
- [ ] Can transfer to self cause issues?
- [ ] Can transfer to contract addresses cause issues?
- [ ] Are paused/frozen accounts respected?
- [ ] Is blacklist/whitelist checked?
- [ ] For ERC777: are hooks called? (reentrancy)
- [ ] Is balance updated correctly (no underflow)?

---

## Approval Functions

```solidity
function approve(address spender, uint256 amount) external { ... }
```

### Questions
- [ ] Is there approve race condition?
- [ ] Should increaseAllowance/decreaseAllowance be used instead?
- [ ] Can infinite approval (type(uint256).max) cause issues?
- [ ] Can approving zero address cause issues?

---

## Claim / Reward Functions

```solidity
function claimRewards() external { ... }
```

### Questions
- [ ] Are rewards calculated correctly?
- [ ] Is reward-per-share accumulator pattern correct?
- [ ] Can user claim more than entitled?
- [ ] Can user claim multiple times (replay)?
- [ ] Are pending rewards updated before claiming?
- [ ] Is there enough reward token to pay out?
- [ ] Can reward calculation overflow/underflow?
- [ ] Is precision loss acceptable?
- [ ] Can flash-stake and claim disproportionate rewards?

---

## Governance Functions

### Propose

```solidity
function propose(address[] targets, bytes[] calldatas) external { ... }
```

- [ ] Is there proposal threshold (minimum tokens)?
- [ ] Can proposal contain arbitrary code?
- [ ] Is proposer's voting power snapshot-based?
- [ ] Can malicious proposal be submitted?
- [ ] Is there proposal spam protection?

### Vote

```solidity
function castVote(uint256 proposalId, uint8 support) external { ... }
```

- [ ] Is voting power snapshot-based (not live balance)?
- [ ] Is there voting delay after proposal?
- [ ] Can user vote multiple times?
- [ ] Can user vote after transferring tokens?
- [ ] Is quorum flash-loan resistant?

### Execute

```solidity
function execute(uint256 proposalId) external { ... }
```

- [ ] Is timelock enforced?
- [ ] Can proposal be executed multiple times?
- [ ] Is proposal state checked before execution?
- [ ] Can execution be front-run with harmful effect?
- [ ] Can governance execute self-destructive actions?

---

## Oracle Functions

```solidity
function getPrice(address token) external view returns (uint256) { ... }
```

### Questions
- [ ] Is price validated (> 0)?
- [ ] Is staleness checked (updatedAt)?
- [ ] Is round completeness checked (answeredInRound)?
- [ ] For L2: is sequencer uptime checked?
- [ ] Can price be manipulated (spot vs TWAP)?
- [ ] Is there fallback if oracle fails?
- [ ] Are decimals handled correctly?
- [ ] Is the oracle decentralized enough?

---

## Upgrade Functions

```solidity
function upgradeToAndCall(address newImpl, bytes data) external { ... }
```

### Questions
- [ ] Who can call upgrade?
- [ ] Is there a timelock?
- [ ] Is new implementation validated?
- [ ] Is storage layout compatible?
- [ ] Is initializer called/protected on new impl?
- [ ] Can upgrade brick the contract?
- [ ] Is _authorizeUpgrade protected (UUPS)?

---

## Emergency Functions

```solidity
function pause() external { ... }
function emergencyWithdraw() external { ... }
```

### Questions
- [ ] Who can pause?
- [ ] Can attacker pause maliciously?
- [ ] Are critical functions (withdraw) still usable when paused?
- [ ] Can pause be bypassed?
- [ ] Is emergency withdraw safe from reentrancy?
- [ ] Does emergency withdraw respect user balances?

---

## Quick Reference: Red Flags

When you see these patterns, investigate immediately:

| Pattern | Concern |
|---------|---------|
| External call before state update | Reentrancy |
| `balanceOf(address(this))` for accounting | Donation attack |
| `tx.origin` for auth | Phishing |
| `block.timestamp` for randomness | Manipulation |
| Unbounded loop over array | DoS via gas |
| `transfer()` or `send()` | May fail with 2300 gas |
| `delegatecall` with user input | Code injection |
| Missing `nonReentrant` on payable | Reentrancy |
| `getReserves()` for pricing | Flash loan manipulation |
| Voting with live balances | Flash loan governance |
