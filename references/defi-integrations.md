# DeFi Protocol Integration Security

Integrating with external DeFi protocols introduces trust assumptions, interface
constraints, and attack surface that are frequently underaudited. This reference
covers secure integration patterns for the most commonly used protocols.

---

## Universal Integration Principles

Before diving into protocol-specific patterns:

1. **Assume the external protocol can fail** — price feeds go stale, AMMs can be drained,
   governance can be compromised.
2. **Never hold user funds in an intermediary state** — if an external call fails,
   the user's funds must be recoverable.
3. **Slippage and deadlines are not optional** — every swap/add-liquidity call must
   enforce them.
4. **Validate all return values** — especially from ERC-20 `transfer`/`approve` calls.
5. **Reentrancy risk is inherited** — if the external protocol has a reentrancy hook
   (ERC-777, callback on receive), your contract inherits that risk.

---

## Uniswap V3 Integration

### Core Interfaces

```solidity
interface IUniswapV3Pool {
    function slot0() external view returns (
        uint160 sqrtPriceX96, int24 tick, uint16 observationIndex,
        uint16 observationCardinality, uint16 observationCardinalityNext,
        uint8 feeProtocol, bool unlocked
    );
    function observe(uint32[] calldata secondsAgos) external view returns (
        int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s
    );
}

interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn; address tokenOut; uint24 fee;
        address recipient; uint256 deadline;
        uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata params)
        external payable returns (uint256 amountOut);
}
```

### Critical: Do Not Use `slot0` as Price Oracle

```solidity
// VULNERABLE: spot price from slot0 is manipulable in a single transaction
function getPrice() external view returns (uint256) {
    (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();
    return uint256(sqrtPriceX96) ** 2 / (2 ** 192); // spot price — manipulable
}

// SECURE: use TWAP via observe()
function getTWAP(address pool, uint32 twapInterval) public view returns (uint256) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval; // e.g., 1800 (30 minutes)
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives, ) = IUniswapV3Pool(pool).observe(secondsAgos);

    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(twapInterval)));

    // Round towards negative infinity for consistency
    if (tickCumulativesDelta < 0 && (tickCumulativesDelta % int56(uint56(twapInterval)) != 0)) {
        arithmeticMeanTick--;
    }

    uint160 sqrtRatioX96 = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);
    return FullMath.mulDiv(uint256(sqrtRatioX96) * uint256(sqrtRatioX96), 1e18, 2 ** 192);
}
```

### Secure Swap Pattern

```solidity
// VULNERABLE: no slippage, no deadline
function swapUnsafe(uint256 amountIn) external {
    router.exactInputSingle(ISwapRouter.ExactInputSingleParams({
        tokenIn: tokenA, tokenOut: tokenB, fee: 3000,
        recipient: address(this), deadline: block.timestamp + 1000,
        amountIn: amountIn, amountOutMinimum: 0,  // no slippage protection
        sqrtPriceLimitX96: 0
    }));
}

// SECURE: enforce slippage + deadline from caller
function swapSafe(uint256 amountIn, uint256 minAmountOut, uint256 deadline) external {
    require(deadline >= block.timestamp, "deadline passed");
    IERC20(tokenA).safeTransferFrom(msg.sender, address(this), amountIn);
    // safeApprove is deprecated in OZ 5.x (has same race condition as approve).
    // Use forceApprove (sets to 0 then to amount atomically) or safeIncreaseAllowance.
    IERC20(tokenA).forceApprove(address(router), amountIn);

    uint256 amountOut = router.exactInputSingle(ISwapRouter.ExactInputSingleParams({
        tokenIn: tokenA, tokenOut: tokenB, fee: 3000,
        recipient: msg.sender, deadline: deadline,
        amountIn: amountIn, amountOutMinimum: minAmountOut,
        sqrtPriceLimitX96: 0
    }));

    require(amountOut >= minAmountOut, "insufficient output");
}
```

### Uniswap V3 Integration Checklist

```
[ ] TWAP used for any price-sensitive calculations (not slot0)
[ ] TWAP interval is appropriate for the token's liquidity depth (>= 30 min for most)
[ ] amountOutMinimum is set and validated in all swap calls
[ ] deadline is set and validated (not block.timestamp for user-facing)
[ ] sqrtPriceLimitX96 used when needed to bound price impact
[ ] Token approval reset to 0 after use (OZ 5.x: use forceApprove — safeApprove was removed)
[ ] reentrancy guard on any callback function (uniswapV3Callback)
[ ] Callback validates msg.sender is the expected pool address
[ ] Pool key (token0, token1, fee) validated — not user-supplied without check
```

---

## Uniswap V4 Hooks

V4 introduces hooks: contracts that execute before/after pool operations. This is a
new and significant attack surface.

### Hook Attack Vectors

#### 1. Malicious Hook Fee Drain
```solidity
// VULNERABLE hook: steals tokens from swap callers
contract MaliciousHook is BaseHook {
    function afterSwap(address sender, ...) external override returns (bytes4, int128) {
        // Drain tokens from the PoolManager or from the swap caller
        poolManager.take(currency, address(this), stolenAmount);
        return (BaseHook.afterSwap.selector, 0);
    }
}
```
**Mitigation**: Only integrate with audited, immutable hooks. Validate hook addresses
against an allowlist before using a pool.

#### 2. Hook Reentrancy
```solidity
// VULNERABLE: hook calls back into your contract during a swap
function afterSwap(...) external override returns (bytes4, int128) {
    IVulnerableVault(caller).deposit(...); // reenters caller's contract
    return (BaseHook.afterSwap.selector, 0);
}
```
**Mitigation**: Apply `nonReentrant` to all functions that interact with V4 pools.

#### 3. Hook-Based Price Manipulation
A hook can modify effective swap prices or execute additional swaps within the same
transaction, manipulating TWAP observations.

#### 4. Untrusted Pool Key
```solidity
// VULNERABLE: user-supplied pool key with malicious hook
function swap(PoolKey calldata key, ...) external {
    poolManager.swap(key, params, hookData); // key.hooks is attacker-controlled
}

// SECURE: validate hook address against allowlist
mapping(address => bool) public allowedHooks;

function swap(PoolKey calldata key, ...) external {
    require(allowedHooks[address(key.hooks)], "hook not allowed");
    poolManager.swap(key, params, hookData);
}
```

### Uniswap V4 Hook Checklist

```
[ ] Hook addresses are validated against an allowlist
[ ] Hook contract is immutable (no upgradeable hooks from untrusted parties)
[ ] beforeSwap/afterSwap do not introduce reentrancy paths
[ ] Hook does not modify pool state in ways that break invariants
[ ] PoolKey validation includes fee tier, tick spacing, and hooks address
[ ] hookData is validated if it carries user-influenced values
[ ] Flash accounting (delta-based) is correctly settled in all hooks
[ ] Hook permissions (flags) are minimal for the hook's actual needs
```

### V4 Math Layer Pitfalls

Hooks that interact with V4's internal math libraries (`TickMath`, `SqrtPriceMath`,
`FullMath`) must understand their precision boundaries and failure modes.

#### TickMath Boundaries

`TickMath.getSqrtPriceAtTick(tick)` reverts if `tick` is outside `[MIN_TICK, MAX_TICK]`
(`[-887272, 887272]`). A hook that computes a target tick without clamping can brick
a pool or create a griefable revert path.

```solidity
// VULNERABLE: unclamped tick computation in beforeSwap hook
function beforeSwap(...) external override {
    int24 targetTick = currentTick + tickOffset; // can overflow MIN/MAX_TICK
    uint160 sqrtPrice = TickMath.getSqrtPriceAtTick(targetTick); // reverts if out of range
}

// SECURE: clamp before calling TickMath
int256 t = int256(currentTick) + tickOffset;
if (t < int256(TickMath.MIN_TICK)) t = int256(TickMath.MIN_TICK);
if (t > int256(TickMath.MAX_TICK)) t = int256(TickMath.MAX_TICK);
int24 targetTick = int24(t);
uint160 sqrtPrice = TickMath.getSqrtPriceAtTick(targetTick);
```

**Checklist:**
- [ ] All tick values passed to `TickMath.getSqrtPriceAtTick` are clamped to `[MIN_TICK, MAX_TICK]`
- [ ] Tick spacing is validated: `tick % tickSpacing == 0` before use
- [ ] Integer overflow in tick arithmetic is impossible (use `int256` intermediate)

#### SqrtPriceMath Precision Loss

`SqrtPriceMath.getAmount0Delta` and `getAmount1Delta` operate in Q64.96 fixed-point.
Precision loss occurs when the price range is narrow or liquidity is very large.

```solidity
// VULNERABLE: assuming getAmount0Delta is always exact
uint256 amount0 = SqrtPriceMath.getAmount0Delta(sqrtRatioLower, sqrtRatioUpper, liquidity, true);
// amount0 can be off by 1 wei due to rounding — critical for accounting invariants

// SECURE: account for rounding direction explicitly
// roundUp = true when computing how much to take FROM the user (conservative)
// roundUp = false when computing how much to give TO the user (conservative)
uint256 amount0ToTake = SqrtPriceMath.getAmount0Delta(lower, upper, liq, true);  // ceiling
uint256 amount0ToGive = SqrtPriceMath.getAmount0Delta(lower, upper, liq, false); // floor
```

**Checklist:**
- [ ] Rounding direction (`roundUp` parameter) matches economic intent (ceiling for debit, floor for credit)
- [ ] No accounting invariant assumes exact equality when `SqrtPriceMath` is involved
- [ ] Tests verify ±1 wei rounding edge cases

#### FullMath.mulDiv Overflow Conditions

`FullMath.mulDiv(a, b, denominator)` computes `a * b / denominator` with 512-bit
intermediate precision. It reverts if `denominator == 0` or if the result overflows uint256.

```solidity
// DANGEROUS pattern: user-controlled denominator
function priceRatio(uint160 sqrtA, uint160 sqrtB) internal pure returns (uint256) {
    return FullMath.mulDiv(sqrtA, sqrtA, sqrtB * sqrtB);
    // If sqrtB == 0 → denominator == 0 → revert (griefable if sqrtB is user-controlled)
}

// SECURE: validate denominator before calling
function priceRatio(uint160 sqrtA, uint160 sqrtB) internal pure returns (uint256) {
    require(sqrtB > 0, "Zero sqrtPrice");
    return FullMath.mulDiv(sqrtA, sqrtA, uint256(sqrtB) * sqrtB);
}
```

**Checklist:**
- [ ] `FullMath.mulDiv` denominator is never zero under any input conditions
- [ ] If denominator depends on user input, validate `> 0` before calling
- [ ] `FullMath.mulDivRoundingUp` is used when ceiling is required (e.g., fee computation)

#### sqrtPriceLimitX96 in Hook-Initiated Swaps

When a hook initiates a swap (e.g., in `afterSwap` for rebalancing), using `sqrtPriceLimitX96 = 0`
tells the pool to use the maximum/minimum price — sandwichable.

```solidity
// VULNERABLE: no price limit in hook-initiated swap
IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
    zeroForOne: true,
    amountSpecified: -int256(rebalanceAmount),
    sqrtPriceLimitX96: 0  // no limit — sandwichable
});

// SECURE: set price limit based on current price + tolerance
(uint160 currentSqrtPrice, , , ) = poolManager.getSlot0(poolId);
uint160 priceLimit = uint160(uint256(currentSqrtPrice) * 99 / 100); // ~2% price slippage (1% on sqrt price)
IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
    zeroForOne: true,
    amountSpecified: -int256(rebalanceAmount),
    sqrtPriceLimitX96: priceLimit
});
```

**Checklist:**
- [ ] Hook-initiated swaps never use `sqrtPriceLimitX96 = 0`
- [ ] Price limit is computed from a manipulation-resistant price source (TWAP, not slot0)
- [ ] Hook-initiated swap amounts are bounded to prevent runaway loops

---

## Chainlink Price Feeds

### Full Validation Pattern

```solidity
// VULNERABLE: no staleness, no round completeness check
function getPriceUnsafe() external view returns (uint256) {
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return uint256(price);
}

// SECURE: full validation
uint256 public constant MAX_PRICE_STALENESS = 3600; // 1 hour

function getPriceSafe() external view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();

    require(price > 0, "invalid price");
    require(updatedAt != 0, "round not complete");
    require(block.timestamp - updatedAt <= MAX_PRICE_STALENESS, "stale price");
    require(answeredInRound >= roundId, "stale round");

    return uint256(price);
}
```

### L2 Sequencer Check

Required on Arbitrum, Optimism, Base, and other L2s where the sequencer can go down,
causing Chainlink to appear fresh while actually being stale.

```solidity
address public constant SEQUENCER_FEED = 0xFdB631F5EE196F0ed6FAa767959853A9F217697D; // Arbitrum
uint256 public constant GRACE_PERIOD = 3600; // 1 hour after sequencer comes back online

function isSequencerUp() public view returns (bool) {
    (, int256 answer, uint256 startedAt, , ) = AggregatorV3Interface(SEQUENCER_FEED).latestRoundData();
    // answer = 0: sequencer up, 1: sequencer down
    if (answer != 0) return false;
    // Grace period after sequencer comes back online
    if (block.timestamp - startedAt < GRACE_PERIOD) return false;
    return true;
}

function getPriceWithL2Check() external view returns (uint256) {
    require(isSequencerUp(), "sequencer down");
    return getPriceSafe();
}
```

### Multi-Oracle Fallback

```solidity
contract MultiOraclePrice {
    AggregatorV3Interface public primaryFeed;
    AggregatorV3Interface public fallbackFeed;
    uint256 public maxDeviation = 500; // 5% in basis points

    function getPrice() external view returns (uint256) {
        try this.getPrimaryPrice() returns (uint256 price) {
            return price;
        } catch {
            return getFallbackPrice();
        }
    }

    function getPrimaryPrice() external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = primaryFeed.latestRoundData();
        require(price > 0 && block.timestamp - updatedAt <= 3600, "primary stale");
        return uint256(price);
    }
}
```

### Chainlink Integration Checklist

```
[ ] latestRoundData() used (not latestAnswer() — deprecated)
[ ] price > 0 validated
[ ] updatedAt != 0 validated (incomplete round)
[ ] block.timestamp - updatedAt <= maxStaleness validated
[ ] answeredInRound >= roundId validated
[ ] Correct decimal handling (priceFeed.decimals())
[ ] L2 sequencer check implemented for Arbitrum/Optimism/Base deployments
[ ] Sequencer grace period enforced (typically 1 hour)
[ ] Circuit breaker if price deviates > X% from TWAP
[ ] Feed address is immutable or protected by timelock if changeable
[ ] Correct feed used (ETH/USD vs ETH/BTC — unit mismatch is a common bug)
```

---

## Aave V3 Flash Loans

### Secure Flash Loan Pattern

```solidity
// Implementing IFlashLoanSimpleReceiver
contract FlashLoanReceiver is IFlashLoanSimpleReceiver {
    IPoolAddressesProvider public immutable ADDRESSES_PROVIDER;
    IPool public immutable POOL;

    constructor(address provider) {
        ADDRESSES_PROVIDER = IPoolAddressesProvider(provider);
        POOL = IPool(ADDRESSES_PROVIDER.getPool());
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override returns (bool) {
        // CRITICAL: validate caller is the Aave pool
        require(msg.sender == address(POOL), "caller not pool");
        // CRITICAL: validate initiator is trusted
        require(initiator == address(this), "untrusted initiator");

        // --- Your logic here ---
        uint256 amountOwed = amount + premium;
        IERC20(asset).approve(address(POOL), amountOwed);

        return true;
    }
}
```

### Flash Loan Attack Surface

When your protocol is the TARGET (not the user) of a flash loan:

```
[ ] No function uses token.balanceOf(address(this)) as a trust signal
[ ] No state changes in single-block that affect collateral ratios used elsewhere
[ ] Price feeds are time-weighted (not spot), preventing single-block manipulation
[ ] Governance snapshot is taken at block N-1 or earlier, not block.number
[ ] Flash loan fees are correctly accounted in debt tracking
[ ] Re-entrancy guard on all functions reachable via flash loan callback
```

### Aave V3 Borrowing Integration

```solidity
// VULNERABLE: hardcoded interest rate mode, no validation
function borrowFromAave(address asset, uint256 amount) external {
    pool.borrow(asset, amount, 2, 0, msg.sender); // variable rate
}

// SECURE: validate health factor won't breach, use correct referral
function borrowSafe(address asset, uint256 amount, uint256 interestRateMode) external {
    // Check health factor before borrow
    (,,,,,uint256 healthFactor) = pool.getUserAccountData(msg.sender);
    require(healthFactor > 1.05e18, "too close to liquidation");

    pool.borrow(asset, amount, interestRateMode, 0, msg.sender);
}
```

---

## Curve Finance Integration

### Read-Only Reentrancy (Critical)

Curve pools modify ETH balances during `remove_liquidity`. If you call
`get_virtual_price()` or `get_dy()` from an external contract **during** a Curve
callback, you may read stale/manipulated prices. This is the root cause of the
Curve 2023 exploit ($70M+).

```solidity
// VULNERABLE: reads Curve price in a context reachable from Curve callback
function getCollateralValue() external view returns (uint256) {
    uint256 lpPrice = curvePool.get_virtual_price(); // can be stale during reentrancy
    return lpBalance * lpPrice / 1e18;
}

// SECURE: use the Curve reentrancy lock check
interface ICurvePool {
    function withdraw_admin_fees() external; // triggers reentrancy lock check
}

// Method 1: Check the reentrancy lock directly (for supported pools)
// Method 2: Use a mutex in your own contract
modifier notInCurveCallback() {
    // For ETH pools: check if the Curve pool is mid-execution
    // Use a Curve wrapper that exposes the lock state
    _;
}

// Method 3: Only read virtual_price with nonReentrant + CEI in your own code
// Ensure your function can't be called during a Curve ETH transfer
```

### LP Token Price Calculation

```solidity
// VULNERABLE: using virtual_price directly (manipulable via donation)
function getLpPrice() external view returns (uint256) {
    return curvePool.get_virtual_price(); // can be inflated

}

// SECURE: use the fair-price calculation (resistant to single-block manipulation)
// virtual_price * min(current_price, fair_price) / 1e18
// Reference: Chainlink LP token price feeds for Curve pools
```

### Curve Integration Checklist

```
[ ] get_virtual_price() not called from a context reachable during Curve reentrancy
[ ] LP token price uses fair-price method, not raw virtual_price
[ ] Pool type identified (plain, lending, meta, tricrypto) — each has different interface
[ ] Slippage enforced on all add/remove liquidity and exchange calls
[ ] Pool admin fee changes are monitored (can affect returns)
[ ] Gauge rewards claimed correctly (separate transaction, no atomicity assumption)
[ ] Correct pool address used (Curve has many pools for same tokens with different fees)
```

---

## Balancer Integration

### Vault-Based Architecture

Balancer V2+ uses a central Vault. All tokens flow through it.

```solidity
interface IBalancerVault {
    struct SingleSwap {
        bytes32 poolId; IVault.SwapKind kind;
        address assetIn; address assetOut; uint256 amount; bytes userData;
    }
    struct FundManagement {
        address sender; bool fromInternalBalance;
        address payable recipient; bool toInternalBalance;
    }
    function swap(
        SingleSwap memory singleSwap,
        FundManagement memory funds,
        uint256 limit,
        uint256 deadline
    ) external payable returns (uint256);
}
```

### Flash Loan Reentrancy (Balancer)

Balancer flash loans call back into arbitrary contracts. Any function callable
during a Balancer flash loan is reachable by an attacker with zero capital.

```solidity
// VULNERABLE: state read during Balancer flash loan callback
// An attacker can call flashLoan(), then within receiveFlashLoan(),
// call your getPrice() which reads from a Balancer pool — getting manipulated price

// SECURE: use nonReentrant on ALL price-reading functions
function getPoolPrice() external view nonReentrant returns (uint256) { ... }
```

### Balancer Composable Stable Pools

These pools include their own BPT (pool token) in the pool. Price calculations differ
from regular stable pools. `getRate()` is the correct function to use for pricing.

### Balancer Integration Checklist

```
[ ] poolId validated — not user-supplied without verification
[ ] limit (slippage) set on all swap calls
[ ] deadline set and enforced
[ ] Flash loan callback validates caller is Balancer Vault
[ ] Flash loan callback validates initiator is trusted
[ ] No price reads from Balancer pools without reentrancy protection
[ ] Composable Stable Pools use getRate(), not simple reserve math
[ ] Internal balance (Vault accounting) correctly handled if used
```

---

## Compound V3 (Comet) Integration

```solidity
interface IComet {
    function supply(address asset, uint256 amount) external;
    function withdraw(address asset, uint256 amount) external;
    function borrowBalanceOf(address account) external view returns (uint256);
    function collateralBalanceOf(address account, address asset) external view returns (uint128);
}

// Critical: Compound uses its own asset whitelist and collateral factors
// Supplying an unsupported asset silently does nothing
// Always verify the asset is supported before integration
function supplyCollateral(address comet, address asset, uint256 amount) external {
    IComet.AssetInfo memory info = IComet(comet).getAssetInfoByAddress(asset);
    require(info.asset == asset, "asset not supported");

    IERC20(asset).forceApprove(comet, amount); // safeApprove deprecated in OZ 5.x — use forceApprove
    IComet(comet).supply(asset, amount);
}
```

### Compound Integration Checklist

```
[ ] Asset is on Comet's supported collateral list before supply
[ ] Borrow capacity checked before borrowing (avoid instant liquidation)
[ ] Interest accrual understood — borrowBalanceOf increases over time
[ ] Liquidation threshold different from borrow factor — both checked
[ ] Supply and borrow caps validated (Comet enforces them, will revert if exceeded)
[ ] Governor/admin keys for Comet tracked (parameter changes affect your integration)
```

---

## ERC-4626 Vault Integration

### Inflation Attack on First Deposit

Any ERC-4626 vault is vulnerable to the first-depositor inflation attack if not
protected:

```solidity
// VULNERABLE: attacker donates to inflate share price before first deposit
function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
    shares = convertToShares(assets); // rounds down — shares = 0 for small deposit
    _mint(receiver, shares);
    asset.transferFrom(msg.sender, address(this), assets);
}

// SECURE: use virtual offset (OZ v5 implementation)
// _decimalsOffset() returns 3 → internal shares use 1000x precision
// This makes the attack require 10^(decimalsOffset * 10) capital, which is infeasible
contract SecureVault is ERC4626 {
    function _decimalsOffset() internal pure override returns (uint8) {
        return 3; // 1000x offset — audit parameter based on token decimals
    }
}
```

### ERC-4626 Consumer Checklist

When integrating with an external ERC-4626 vault:

```
[ ] previewDeposit/previewWithdraw used for display only — not for accounting
[ ] convertToAssets/convertToShares used for actual calculations
[ ] Share price can decrease (loss events) — design handles this
[ ] maxDeposit/maxWithdraw limits checked before deposit/withdraw
[ ] Vault's underlying asset matches expected token
[ ] Vault is not paused before attempting operations
[ ] Reentrancy guard on your callbacks (vault can call ERC-777 tokens)
[ ] Decimals mismatch between vault shares and underlying handled
```

---

## Common Multi-Protocol Integration Bugs

### Composability Reentrancy
```
Protocol A calls Protocol B which calls back into Protocol A.
If Protocol A has CEI violations, the callback can exploit inconsistent state.

Pattern: Flash loan (Aave) → Swap (Uniswap) → Receive callback → Call your Vault
```
**Defense**: `nonReentrant` on all public/external state-changing functions.

### Stale Price Across Integrations
```
You read Chainlink price at block N.
You use Uniswap spot price at block N (in same tx).
Attacker sandwiches: manipulate Uniswap spot price BEFORE your tx.
Chainlink and Uniswap now disagree — your logic uses wrong price.
```
**Defense**: Use TWAP for Uniswap; validate both prices agree within a tolerance.

### Fee Token (Fee-on-Transfer) in Protocol Integration
```
token.transferFrom(user, address(this), 100); // 2% fee → only 98 received
pool.deposit(token, 100, ...);                // tries to deposit 100 → will fail
                                              // or deposits wrong amount
```
**Defense**: Measure balance before/after transfer; use actual received amount.

### Decimal Mismatch
```
Chainlink ETH/USD returns 8 decimals.
Your contract assumes 18 decimals.
Price is off by 1e10 → all calculations wrong.
```
**Defense**: Always call `priceFeed.decimals()` and normalize explicitly.

---

## Intent-Based Protocols (Permit2, UniswapX, 1inch Fusion)

Intent protocols separate order signing (off-chain) from order execution (on-chain).
Users sign typed EIP-712 messages; fillers/solvers execute them. Security model shifts
from AMM state to signature validation + callback logic.

See `intent-protocols.md` for deep reference and attack vectors.

### Permit2

Universal token approval contract enabling signature-based transfers. Used by UniswapX,
many aggregators, and third-party protocols.

**Key checks:**
- [ ] Is `deadline` enforced strictly? Expired permits must not be replayable
- [ ] Is `nonce` invalidated after use? Bitmap nonces (word + bit) must be atomically consumed
- [ ] Is `spender` restricted to the expected contract address?
- [ ] `SignatureTransfer` (one-time, nonce-based) vs `AllowanceTransfer` (expiry-based) — correct mode chosen?
- [ ] Is the Permit2 contract address the canonical Uniswap deployment?

**Common vulnerability:**
```solidity
// VULN: signer is msg.sender — attacker can use their own permit to drain others
permit2.permitTransferFrom(permit, transferDetails, msg.sender, sig);

// SECURE: signer must be the original order creator, passed explicitly
permit2.permitTransferFrom(permit, transferDetails, orderOwner, sig);
```

### UniswapX Reactor Integration

Users sign `DutchOrder`/`LimitOrder` structs; fillers call `reactor.execute()`.

**Key checks:**
- [ ] Is the `exclusiveFiller` window honored? Non-exclusive fills during the window must revert
- [ ] Is Dutch auction decay linear? Can `endAmount` be hit instantly on the same block?
- [ ] Is nonce bitmap invalidation correct? Replay must revert even across different nonce words
- [ ] Are output tokens validated against what was signed? Filler cannot substitute tokens

**Callback security:**
```solidity
contract Filler is IReactorCallback {
    IReactor public immutable reactor;

    function reactorCallback(ResolvedOrder[] calldata, bytes calldata) external {
        require(msg.sender == address(reactor), "Only reactor"); // Critical auth check
        // Execute fill logic — input tokens already transferred by reactor
        // Must approve output tokens to reactor before returning
    }
}
```

### 1inch Fusion / Limit Order Protocol v4

Dutch auction with resolvers. Orders are gasless; resolvers pay gas and compete to fill.

**Key checks:**
- [ ] Are `PreInteraction` and `PostInteraction` hooks reentrant-safe?
- [ ] Can `Extension` data inject arbitrary calldata into resolver callbacks?
- [ ] Is `takerAsset`/`makerAsset` validation sufficient to prevent token substitution?
- [ ] Are order expirations enforced? Cannot fill expired orders even in same block?
- [ ] Is `series` nonce (epoch-based mass cancellation) handled without cross-user interference?

### Cross-Protocol Intent Risks

- **Order front-running**: Signed intents in mempool before reaching filler network
- **Filler collusion**: Permissioned fillers delay execution until Dutch price hits floor
- **Griefing via cancellation**: Spam cancellations invalidate in-progress honest fills
- **Solver insolvency**: Flash-loan-based fills must guarantee atomic repayment
- **Token rescue abuse**: Functions to recover sent tokens could drain in-transit funds

---

## Cross-References

- `intent-protocols.md` — Deep reference: witness hashes, decay math, callback auth
- `vulnerability-taxonomy.md` — Flash loan vectors, oracle manipulation, reentrancy
- `defi-checklist.md` — Protocol-specific security checklists
- `l2-crosschain.md` — Sequencer feeds, L2-specific oracle considerations
- `secure-patterns.md` — Oracle integration secure pattern reference
- `exploit-case-studies.md` — Curve read-only reentrancy, Beanstalk flash loan governance
