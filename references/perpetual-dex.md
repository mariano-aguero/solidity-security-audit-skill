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
    // Premium is signed: positive when longs dominate, negative when shorts dominate
    int256 premium = _calculateFundingPremium(marketId);

    uint256 markPrice = premium >= 0
        ? indexPrice + uint256(premium)
        : indexPrice - uint256(-premium);

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

The classic precision loss pattern: dividing before multiplying.
For PnL this typically happens when an intermediate ratio or rate is computed first.

```solidity
// VULN: Intermediate division truncates before multiplying by size
function getPnL(Position memory pos) internal view returns (int256) {
    uint256 markPrice = getMarkPrice(pos.marketId);
    int256 priceDelta = int256(markPrice) - int256(pos.entryPrice);
    // BAD: divides priceDelta by PRICE_PRECISION first, then multiplies by size
    // priceDelta might truncate to 0 if priceDelta < PRICE_PRECISION
    int256 priceRatio = priceDelta / int256(PRICE_PRECISION);
    return priceRatio * int256(pos.size);
}

// SECURE: Multiply by size first, then divide — preserves all significant bits
function getPnL(Position memory pos) internal view returns (int256) {
    uint256 markPrice = getMarkPrice(pos.marketId);
    int256 priceDelta = int256(markPrice) - int256(pos.entryPrice);
    return priceDelta * int256(pos.size) / int256(PRICE_PRECISION);
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

## 9. Liquidity Vault as Liquidation Absorber — Structural Manipulation

### The Pattern

Some perpetual DEX protocols use a community liquidity vault (e.g., Hyperliquid's HLP vault)
as the **counterparty of last resort** for liquidations. When a position cannot be liquidated
at market price, the vault absorbs the loss. This creates a structural attack target:
an attacker can intentionally create large positions designed to be liquidated into the vault
at unfavorable prices.

### The Hyperliquid HLP Pattern (Three Incidents, 2025)

**Incident 1 (March 2025)**: Attacker opened a 50x long ETH position ($300M notional),
moved price via off-exchange activity, then allowed the position to be liquidated.
The HLP vault was forced to absorb the liquidation at a price far below market.

**Root Cause Analysis:**
1. **Oracle controlled by single EOA**: price oracle updateable by a single address
2. **No position size caps relative to vault TVL**: attacker's position exceeded HLP's capacity
3. **Liquidation price ≠ oracle price**: different pricing for liquidation vs risk calculations
4. **No circuit breaker**: no pause mechanism for extreme position concentrations

```solidity
// VULNERABLE: vault as unconditional liquidation absorber
contract HLPVault {
    function absorbLiquidation(
        address trader,
        int256 pnl,
        uint256 positionSize
    ) external onlyLiquidationEngine {
        // Vault MUST absorb regardless of size — no check against vault TVL
        if (pnl < 0) {
            _deductFromVault(uint256(-pnl));  // Unconditional deduction
        }
    }
}

// SECURE: position size caps + circuit breakers
contract SecureVault {
    uint256 public constant MAX_POSITION_TVL_RATIO = 10;  // Max 10% of TVL
    uint256 public lastLargeAbsorption;
    uint256 public constant CIRCUIT_BREAKER_COOLDOWN = 1 hours;

    function absorbLiquidation(address trader, int256 pnl, uint256 positionSize) external {
        require(
            positionSize <= totalValueLocked() / MAX_POSITION_TVL_RATIO,
            "Position exceeds vault capacity"
        );
        require(
            block.timestamp >= lastLargeAbsorption + CIRCUIT_BREAKER_COOLDOWN,
            "Circuit breaker active"
        );
        if (uint256(positionSize) > totalValueLocked() / 20) {
            lastLargeAbsorption = block.timestamp;
        }
        if (pnl < 0) {
            _deductFromVault(uint256(-pnl));
        }
    }
}
```

### Oracle Centralization Risk

When a single EOA controls price oracle updates, an attacker who compromises that key
can move prices to trigger favorable liquidations.

```solidity
// VULNERABLE: single EOA oracle
contract CentralizedOracle {
    address public oracleUpdater;  // Single key = single point of failure

    function updatePrice(address asset, uint256 price) external {
        require(msg.sender == oracleUpdater, "Not oracle");
        prices[asset] = price;  // No TWAP, no deviation check, no delay
    }
}

// SECURE: multi-sig oracle with deviation bounds
contract DecentralizedOracle {
    uint256 public constant MAX_DEVIATION = 500;  // 5% max per-update

    function updatePrice(address asset, uint256 newPrice, bytes[] calldata sigs) external {
        require(_verifyMultisig(sigs, keccak256(abi.encode(asset, newPrice))), "Invalid sigs");
        uint256 current = prices[asset];
        uint256 deviation = newPrice > current
            ? (newPrice - current) * 10000 / current
            : (current - newPrice) * 10000 / current;
        require(deviation <= MAX_DEVIATION, "Price deviation too large");
        prices[asset] = newPrice;
    }
}
```

### Audit Checklist

- [ ] **Vault as liquidation absorber**: Is there a cap on how much a single liquidation can drain from the vault (e.g., max 10% TVL)?
- [ ] **Oracle control**: How many keys control oracle price updates? Is it a multisig? Is there an on-chain dispute mechanism?
- [ ] **Position concentration**: Can a single trader's position exceed the vault's absorption capacity?
- [ ] **Liquidation pricing**: Is the price used for liquidations the same as the oracle price used for risk calculations?
- [ ] **Circuit breakers**: Is there a mechanism to pause trading/liquidations if vault TVL drops rapidly?
- [ ] **Insurance fund sequencing**: What is the order of loss absorption (position margin → insurance fund → vault → socialized loss)?
- [ ] **Front-running liquidations**: Can liquidators extract MEV by seeing pending liquidations before executing?
- [ ] **Funding rate manipulation**: Can an attacker hold a large position to skew funding rates against LPs?

---

## References

- [GMX v2 Contracts (gmx-synthetics)](https://github.com/gmx-io/gmx-synthetics)
- [Synthetix Perps v3](https://github.com/Synthetixio/synthetix-v3)
- [Perpetual Protocol v2 (Curie)](https://github.com/perpetual-protocol/perp-curie-contract)
- [defi-integrations.md](defi-integrations.md) — Chainlink, Uniswap integration patterns
- [defi-checklist.md](defi-checklist.md) — General DeFi security checks
- [exploit-case-studies.md](exploit-case-studies.md) — Real perp protocol exploits

---

## 10. dYdX v4 — Cosmos App-Chain Risks

dYdX v4 runs on its own Cosmos SDK chain with an off-chain clob (Central Limit
Order Book) and on-chain settlement. This introduces risks absent from EVM-native perp DEXes.

### 10.1 Off-Chain Order Book Trust Assumptions

Validators maintain the CLOB off-chain via consensus. A malicious validator set can:
- Reorder fills to frontrun large orders before the oracle settles the price
- Selectively delay order inclusion (MEV without on-chain evidence)
- Collude to execute orders at stale prices just before an oracle update

**Audit checks:**
- [ ] Are fills price-validated on-chain against the oracle at time of settlement?
- [ ] Is there a maximum acceptable spread between fill price and oracle price at settlement?
- [ ] Are order timestamps validated to prevent stale order execution?

### 10.2 Cosmos Validator Set Compromise

Unlike Ethereum, dYdX v4 security depends entirely on dYdX's own validator set.
A 33%+ Byzantine fault halts the chain; a 67%+ fault allows equivocation and double-spending.

**Bridge and custody implications:**
- Funds bridged from Ethereum to dYdX v4 depend on IBC bridge validators
- A chain halt freezes all user funds until validator coordination recovers
- No equivalent of Ethereum social consensus for contentious fork resolution
- Insurance funds held on-chain become inaccessible during a halt

**Audit checks:**
- [ ] Is the L1 bridge IBC light-client-based or multisig-based?
- [ ] What is the validator set decentralization? (count, stake distribution, geographic spread)
- [ ] Are there emergency withdrawal mechanisms that bypass chain liveness requirements?

### 10.3 CometBFT Block Proposer MEV

dYdX v4 uses CometBFT (formerly Tendermint) consensus. Block proposers can reorder
transactions within their proposal window, analogous to Ethereum block proposers.

**Attack pattern:**
```
// Validator acts as block proposer:
// Step 1: Validator's own buy order → included first → price moves up
// Step 2: User's large buy order → included second → fills at worse price
// Step 3: Validator sells → profit without on-chain evidence
```

**Audit checks:**
- [ ] Does the protocol use TWAP-based fills to mitigate single-block price manipulation?
- [ ] Are large orders time-weighted or split to reduce sandwiching profitability?
- [ ] Are there commitments to order sequencing before the block is proposed?

---

## 11. Gains Network (gTrade) — Synthetic Asset Risks

gTrade uses a single DAI vault as the sole counterparty for all synthetic perpetuals.
No real underlying assets are held — only DAI collateral for both traders and the vault.

### 11.1 Vault Solvency (DAI Vault as Counterparty)

The DAI vault pays out winning traders and absorbs losses from losers.
If the vault is underfunded relative to outstanding profitable exposure, it cannot pay.

**Vulnerability scenario:**
```
Vault balance: 10M DAI
All open longs are profitable at current price:
  → Aggregate unrealized PnL owed to traders: 12M DAI
  → Vault cannot cover → forced position closures or haircuts
```

**Audit checks:**
- [ ] Is there a maximum open interest cap relative to total vault TVL?
- [ ] Is vault utilization enforced at position open, at PnL accumulation, or both?
- [ ] What is the mechanism when vault drops below minimum solvency? (pause, forced deleveraging, haircut?)
- [ ] Are there circuit breakers that halt new position opens when utilization exceeds a threshold?

### 11.2 Single-Oracle Dependency Across All Markets

gTrade uses Chainlink + custom price aggregation. A single feed failure
or manipulation simultaneously affects all synthetic markets.

**Audit checks:**
- [ ] Is there a price deviation circuit breaker comparing feeds across sources?
- [ ] Can a single Chainlink feed being stale halt the entire protocol?
- [ ] Is there a per-market fallback oracle?
- [ ] Are all markets paused when any single feed fails, or only the affected market?

### 11.3 Governance Collateral Factor Manipulation

Since gTrade has no real underlying assets, all risk parameters are governance-controlled.
A malicious governance action can inflate collateral factors to allow undercollateralized positions.

**Audit checks:**
- [ ] Are collateral factor changes timelocked (minimum 24–72 hours)?
- [ ] Is there a maximum single-action change limit on collateral factors?
- [ ] Who can execute parameter changes — multisig, DAO vote, or single EOA?

---

## 12. Advanced Funding Rate Manipulation

### 12.1 Skew-Based Funding Manipulation

Protocols that set funding rates proportional to long/short skew can be manipulated
by a whale that dominates one side to extract funding from the other.

**Attack flow:**
1. Attacker opens a massive long position (dominates the long side → funding rate at max positive)
2. Short holders pay maximum funding to attacker each funding epoch
3. Attacker's funding income exceeds position cost if oracle price is stable

**Vulnerable pattern:**
```solidity
function getFundingRate(bytes32 marketId) public view returns (int256) {
    int256 skew = int256(longOI[marketId]) - int256(shortOI[marketId]);
    // Linear: unbounded funding rate if skew is extreme
    return (skew * FUNDING_RATE_MULTIPLIER) / int256(totalOI[marketId]);
    // A whale with 99% of OI on one side → near-max funding drain
}
```

**Mitigations to check:**
- [ ] Is there a maximum funding rate cap regardless of skew level?
- [ ] Is there a minimum delay between a skew change and the resulting funding rate update?
- [ ] Is there a maximum position size per address or per block for a single market?

### 12.2 Time-Weighted Funding Rate Gaming

If funding snapshots occur at predictable intervals, attackers can:
1. Open a large skew-dominating position just before the snapshot
2. Close immediately after the snapshot
3. Net receive one epoch of funding at minimal holding cost

**Audit checks:**
- [ ] Is the funding rate computed on a TWAP basis (minutes or hours, not 1 block)?
- [ ] Are funding snapshots at randomized or unpredictable intervals?
- [ ] Are there minimum holding periods before a position accumulates funding?

### 12.3 Funding Rate Oracle Manipulation

Some protocols use an external index rate (e.g., from a CEX) to anchor their funding rate.
Manipulation of that index affects on-chain funding across all positions.

**Audit checks:**
- [ ] Is the funding rate index sourced from a single CEX or multiple sources?
- [ ] Is there a maximum single-epoch change cap on the funding rate?
- [ ] Can the funding rate index be manipulated via Chainlink or a TWAP oracle?

---

## 13. Insurance Fund Attacks

### 13.1 Cascading Liquidations to Drain Insurance Fund

The insurance fund absorbs bad debt when liquidations cannot fully close an underwater
position. A coordinated attack exhausts it:

1. Attacker opens a max-leverage long in an illiquid market
2. Attacker (with a second wallet) rapidly dumps the asset
3. Liquidators cannot act fast enough → position goes deeply negative
4. Insurance fund absorbs bad debt

**Vulnerable pattern:**
```solidity
function absorbBadDebt(bytes32 marketId, address trader) internal {
    int256 badDebt = getUnrealizedLoss(marketId, trader);
    if (badDebt < 0 && insuranceFund >= uint256(-badDebt)) {
        insuranceFund -= uint256(-badDebt); // No cap — fund can be drained to zero
        _closePosition(marketId, trader);
    }
}
```

**Audit checks:**
- [ ] Is there an open interest cap for illiquid markets scaled to insurance fund size?
- [ ] Is maximum leverage reduced for markets with thin order books?
- [ ] What is the maximum single-position bad debt vs. insurance fund balance?
- [ ] Is there a per-epoch cap on total bad debt absorption?

### 13.2 Insurance Fund → Socialized Loss Griefing

When the insurance fund is exhausted, some protocols socialize losses across all
open profitable positions. An attacker can use this to target specific winners:

1. Drain insurance fund via cascading liquidations (see §13.1)
2. Wait until a target trader has a large profitable position
3. Trigger socialized loss → the target's realized PnL is clawed back

**Audit checks:**
- [ ] Is the socialization mechanism capped per epoch (not unlimited clawback)?
- [ ] Can socialized loss be triggered permissionlessly or is it gated?
- [ ] Are users notified before their PnL is socialized?

---

## 14. Cross-Margin vs. Isolated Margin Security

### 14.1 Cross-Margin Contagion

In cross-margin mode, a loss in one market reduces margin available for all others,
potentially triggering cascading liquidations across multiple positions.

**Vulnerable pattern:**
```solidity
function getAccountHealth(address trader) public view returns (int256) {
    int256 totalPnL = 0;
    for (uint256 i = 0; i < openMarkets[trader].length; i++) {
        totalPnL += getUnrealizedPnL(trader, openMarkets[i]); // All markets share margin
    }
    return int256(collateral[trader]) + totalPnL;
    // A loss in market A drains margin for markets B, C, D simultaneously
}
```

**Attack vector:**
- Open a profitable position in market A (long) using cross-margin
- Open a large leveraged position in market B (cross-margin subsidizes the margin)
- Manipulate market B's oracle → market B position triggers liquidation
- Market A profits are seized to cover market B's shortfall

**Audit checks:**
- [ ] Is there a maximum cross-margin exposure ratio per market?
- [ ] Can cross-margin be disabled per market to contain contagion?
- [ ] Is there a minimum cross-margin health factor enforced separately per market?

### 14.2 Isolated to Cross-Margin Switch Timing Attack

An attacker whose isolated margin position is about to be liquidated can switch
to cross-margin to socialize the forthcoming bad debt:

```solidity
// No timelock: attacker switches from isolated to cross just before liquidation
function switchToCross(uint256 positionId) external {
    require(msg.sender == positions[positionId].trader, "Not owner");
    // Missing: check that position is above maintenance margin before allowing switch
    // Missing: timelock between mode switches
    positions[positionId].marginMode = MarginMode.Cross;
    // Now the upcoming bad debt becomes cross-margin bad debt — socialized to all cross users
}
```

**Audit checks:**
- [ ] Is there a timelock (≥ 1 epoch) between switching margin modes?
- [ ] Is the mode switch blocked if the position is below maintenance margin?
- [ ] Are cross-margin losses capped to prevent socialization of unlimited bad debt?
