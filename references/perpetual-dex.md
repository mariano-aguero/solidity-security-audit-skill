# Perpetual DEX Security Reference

Security framework for on-chain perpetual futures and derivatives protocols.
Covers GMX v2, Synthetix Perps v3, and general perp protocol patterns.

See `defi-integrations.md` for oracle/Chainlink integration checklists.
See `defi-checklist.md` for general DeFi security checks.

---

## Architecture Patterns

| Pattern | Examples | Key Risk |
|---------|----------|----------|
| Real AMM with LPs | GMX v1/v2, Gains Network | Oracle manipulation, LP solvency |
| vAMM / virtual liquidity | Perp Protocol v1 | Funding rate manipulation |
| Synthetix debt pool | Synthetix Perps v3 | Global debt skew, liquidation cascade |
| On-chain order book | dYdX v4 (Cosmos app-chain) | Sequencer manipulation, MEV |

---

## 1. Oracle & Mark Price Security

### 1.1 Mark Price Calculation

Perpetuals use a mark price (not spot) for unrealized PnL and funding.
Divergence between mark and index price is exploitable.

**Vulnerable — single oracle, no circuit breaker:**
```solidity
function getMarkPrice(bytes32 marketId) external view returns (uint256) {
    return chainlinkFeed.latestAnswer(); // Single source, no staleness check
}
```

**Secure — multi-source with deviation circuit breaker:**
```solidity
function getMarkPrice(bytes32 marketId) external view returns (uint256) {
    uint256 indexPrice = _getValidatedIndexPrice(marketId);
    uint256 premium = _calculateFundingPremium(marketId);
    uint256 markPrice = indexPrice + premium;

    // Mark cannot deviate more than MAX_MARK_DEVIATION_BPS from index
    uint256 maxDev = indexPrice * MAX_MARK_DEVIATION_BPS / 10_000;
    require(
        markPrice <= indexPrice + maxDev && markPrice >= indexPrice - maxDev,
        "Mark price circuit breaker"
    );
    return markPrice;
}
```

### 1.2 Liquidation Oracle Attack Surface

**Audit checks:**
- [ ] Is the liquidation oracle the same as the PnL oracle? (Use TWAP for liquidations, spot for PnL)
- [ ] Is there a minimum liquidation health factor buffer above maintenance margin?
- [ ] Are liquidations paused if oracle deviation exceeds a threshold?
- [ ] Can the same oracle update both trigger a liquidation AND mark a position's PnL?
- [ ] Is the oracle heartbeat checked before processing liquidations?

---

## 2. Funding Rate Mechanics

### 2.1 Funding Rate Manipulation

Funding rate is a function of open interest imbalance. A dominant position can
drive funding to extract value from counterparties.

**Vulnerable — instantaneous OI snapshot:**
```solidity
function getFundingRate() public view returns (int256) {
    int256 skew = int256(longOI) - int256(shortOI);
    return skew * FUNDING_VELOCITY / int256(totalOI); // Manipulable via flash loan
}
```

**Secure — time-weighted average with velocity cap:**
```solidity
function getFundingRate() public view returns (int256) {
    int256 skew = _getEWMASkew(); // Exponentially weighted moving average
    int256 rate = skew * FUNDING_VELOCITY / int256(totalOI);
    return _clamp(rate, -MAX_FUNDING_RATE, MAX_FUNDING_RATE);
}
```

**Audit checks:**
- [ ] Is there a max funding rate cap? Can funding be driven to extreme values?
- [ ] Are funding payments settled frequently enough to prevent large liability accumulation?
- [ ] Can funding rate manipulators profit more than the funding cost they pay?
- [ ] Is the funding calculation resistant to flash loan OI inflation?

### 2.2 Funding Accrual Accounting

- [ ] Are funding payments correctly pro-rated for partial periods?
- [ ] Is there overflow risk in `cumFundingPerUnit` for long-running markets?
- [ ] Are negative funding payments (protocol owes traders) bounded?

---

## 3. Liquidation Logic

### 3.1 Cascade Prevention

```solidity
// SECURE: Limit max liquidation volume per block to prevent cascades
function liquidate(bytes32 positionId) external {
    Position memory pos = positions[positionId];
    require(_isLiquidatable(pos), "Not liquidatable");

    require(
        block.number > lastLiquidationBlock ||
        blockLiquidationVolume + pos.size <= MAX_BLOCK_LIQUIDATION_VOLUME,
        "Block liquidation limit"
    );
    blockLiquidationVolume += pos.size;
    lastLiquidationBlock = block.number;
    _executeLiquidation(positionId);
}
```

**Audit checks:**
- [ ] Is there a maximum liquidation size per block?
- [ ] Are partial liquidations supported for positions too large to liquidate profitably at once?
- [ ] Is the liquidation keeper incentive (bonus) sufficient at all market conditions?
- [ ] Can a position grow too large to liquidate (above available liquidity)?

### 3.2 Bad Debt Handling

- [ ] What happens when a liquidated position has negative equity (underwater)?
- [ ] Is there an insurance fund? What are the conditions for depletion?
- [ ] Can bad debt be socialized to LPs? Is the mechanism fair and bounded?
- [ ] Are undercollateralized positions auto-deleveraged (ADL)? Is ADL selection fair?

---

## 4. LP Pool & Solvency

### 4.1 LP Exposure to Trader PnL

In GMX-style protocols, LPs are the counterparty to all trades.

```solidity
// AUDIT: LP token price must account for all unrealized trader profits
function getLPTokenPrice() external view returns (uint256) {
    uint256 totalAssets = _getTotalPoolValue();
    // Must include:
    // 1. Unrealized trader PnL (protocol owes this — deduct from assets)
    // 2. Pending funding payments owed
    // 3. Borrow fees owed to LPs (add to assets)
    uint256 totalShares = lpToken.totalSupply();
    return totalAssets * PRICE_PRECISION / totalShares;
}
```

**Audit checks:**
- [ ] Are unrealized trader profits subtracted from LP pool value?
- [ ] Is there a maximum open interest cap relative to LP pool size?
- [ ] Can a single large winning position drain the entire LP pool?
- [ ] Are deposits/withdrawals paused during high-volatility events?

### 4.2 LP Withdrawal Timing

- [ ] Are LPs required to lock funds for a minimum period? (Prevents LP flash entering/exiting)
- [ ] Is there a withdrawal delay to prevent front-running known price impact events?
- [ ] During market stress, can LPs withdraw while the pool is underwater?

---

## 5. Position Management

### 5.1 Precision in PnL Calculation

```solidity
// VULN: Division before multiplication loses precision
function getPnL(Position memory pos) internal view returns (int256) {
    uint256 markPrice = getMarkPrice(pos.marketId);
    int256 priceDelta = int256(markPrice) - int256(pos.entryPrice);
    return priceDelta * int256(pos.size) / int256(PRICE_PRECISION);
    // Better: multiply first, then divide
}

// SECURE: Multiply before dividing
function getPnL(Position memory pos) internal view returns (int256) {
    uint256 markPrice = getMarkPrice(pos.marketId);
    int256 priceDelta = int256(markPrice) - int256(pos.entryPrice);
    return int256(pos.size) * priceDelta / int256(PRICE_PRECISION);
}
```

### 5.2 Leverage Calculation with Fees

```solidity
// VULN: Effective margin not adjusted for pending fees
function _verifyMarginRequirement(Position memory pos) internal view {
    uint256 notional = pos.size * getMarkPrice(pos.marketId) / PRICE_PRECISION;
    uint256 minMargin = notional * MAINTENANCE_MARGIN_BPS / 10_000;
    uint256 effectiveMargin = pos.collateral; // BUG: ignores pending fee deduction
    require(effectiveMargin >= minMargin, "Insufficient margin");
}

// SECURE: Deduct accrued fees from effective margin
function _verifyMarginRequirement(Position memory pos) internal view {
    uint256 notional = pos.size * getMarkPrice(pos.marketId) / PRICE_PRECISION;
    uint256 minMargin = notional * MAINTENANCE_MARGIN_BPS / 10_000;
    uint256 accruedFees = _getAccruedFees(pos);
    require(pos.collateral >= accruedFees, "Fees exceed collateral");
    uint256 effectiveMargin = pos.collateral - accruedFees;
    require(effectiveMargin >= minMargin, "Insufficient margin");
}
```

---

## 6. GMX V2 Specific Checks

GMX v2 uses Synthetics (GM pools) with market-specific liquidity.

- [ ] Are GM pool deposits/withdrawals subject to price impact? (Prevents sandwich attacks)
- [ ] Is `maxPnlFactor` (max % of pool traders can win) enforced correctly?
- [ ] Are limit order callbacks validated against market conditions at execution time?
- [ ] Is the keeper network properly incentivized and permissioned? Can keepers front-run orders?
- [ ] Are ADL (auto-deleveraging) selections fair and manipulation-resistant?
- [ ] Is the `referral` reward system resistant to self-referral extraction?

---

## 7. Synthetix Perps V3 Specific Checks

- [ ] Is the global debt pool accounting correct? Can one market's loss skew another?
- [ ] Are margin requirements consistent across collateral types (sUSD vs USDC vs WETH)?
- [ ] Is the oracle staleness window appropriate for each supported market?
- [ ] Can the settlement keeper be manipulated via order timing?

---

## 8. Testing Perpetual Protocols

```solidity
// Test: liquidation at exact maintenance margin boundary
function test_liquidationAtExactMargin() public {
    oracle.setPrice(2000e8);
    vm.prank(trader);
    perp.openPosition(ETH_MARKET, 10e18, 5); // 5x leverage

    uint256 liqPrice = perp.getLiquidationPrice(trader, ETH_MARKET);
    oracle.setPrice(liqPrice);

    assertTrue(perp.isLiquidatable(trader, ETH_MARKET));
    perp.liquidate(trader, ETH_MARKET);
    assertEq(perp.getPositionSize(trader, ETH_MARKET), 0);
}

// Test: funding rate cap enforcement
function test_fundingRateCapEnforced() public {
    _openLargePosition(LONG, type(uint128).max);
    int256 fundingRate = perp.getFundingRate(ETH_MARKET);
    assertLe(fundingRate, int256(MAX_FUNDING_RATE));
    assertGe(fundingRate, -int256(MAX_FUNDING_RATE));
}

// Test: LP pool correctly reflects unrealized trader PnL
function test_lpPriceDecreasesOnTraderProfit() public {
    uint256 lpPriceBefore = perp.getLPTokenPrice();
    _openProfitablePosition(); // Trader in profit = LP pool decreases
    uint256 lpPriceAfter = perp.getLPTokenPrice();
    assertLt(lpPriceAfter, lpPriceBefore);
}
```

---

## References

- [GMX v2 Contracts (gmx-synthetics)](https://github.com/gmx-io/gmx-synthetics)
- [Synthetix Perps v3](https://github.com/Synthetixio/synthetix-v3)
- [Perpetual Protocol v2 (Curie)](https://github.com/perpetual-protocol/perp-curie-contract)
- [defi-integrations.md](defi-integrations.md) — Chainlink, Uniswap integration patterns
- [defi-checklist.md](defi-checklist.md) — General DeFi security checks
- [exploit-case-studies.md](exploit-case-studies.md) — Real perp protocol exploits
