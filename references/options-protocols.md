# Options Protocol Security Reference

Security framework for on-chain options protocols. Covers Dopex (SSOV),
Lyra (AMM-based), Opyn/Gamma (oToken/Controller), Ribbon Finance (Theta Vaults),
Premia (concentrated liquidity options), Thetanuts, Hegic, and Aevo.

See `defi-checklist.md §Options` for the high-level checklist.
See `vulnerability-taxonomy.md §4` for oracle manipulation patterns.
See `defi-integrations.md` for Chainlink integration patterns.
See `perpetual-dex.md` for related liquidation and margin logic.

---

## Architecture Patterns

| Pattern | Examples | Key Risk |
|---------|----------|----------|
| AMM-based pricing (IV from pool) | Lyra v2, Premia v3 | Stale IV drainage, LP insolvency |
| Orderbook / RFQ | Aevo, Opyn Gamma v2 | Maker trust, off-chain matching |
| Vault-based (covered call/put) | Ribbon, Thetanuts, Dopex SSOV | Strike manipulation, epoch timing |
| Peer-to-pool (pooled writers) | Hegic, Premia v2 | Counterparty pool insolvency |
| Hybrid (AMM + vault) | Lyra v1 + Synthetix | Cross-protocol dependency chain |

**Core invariant**: At any point, the total collateral held by writers must be
sufficient to cover the maximum payout of all outstanding options. An option
protocol is insolvent if `sum(maxPayout_i) > totalCollateral`.

---

## 1. Trust Model & Architecture

### 1.1 Oracle Dependency Chain

Options protocols depend on two distinct oracle types that each carry unique
trust assumptions:

- **Spot oracle** — determines settlement price and triggers liquidations
- **IV oracle** — determines option premium pricing; often admin-controlled

The spot oracle is shared with the broader DeFi ecosystem (Chainlink, Uniswap
TWAP). The IV oracle is protocol-specific and frequently the weakest link.

**Vulnerable — single-source settlement with no validation:**
```solidity
pragma solidity ^0.8.20;

contract OptionsSettlement {
    address public spotOracle;

    function settle(uint256 optionId) external {
        // Single oracle, no staleness check, no TWAP comparison
        uint256 price = IOracle(spotOracle).getPrice();
        uint256 payout = _calculatePayout(optionId, price);
        IERC20(collateral).transfer(options[optionId].holder, payout);
    }

    // Admin can change oracle to a malicious contract at any time — no timelock
    function setOracle(address o) external { require(msg.sender == admin); spotOracle = o; }
}
```

**Secure — dual-source settlement with circuit breaker:**
```solidity
pragma solidity ^0.8.20;

contract OptionsSettlement {
    uint256 public constant MAX_DEVIATION_BPS = 500; // 5%
    uint256 public constant MAX_ORACLE_AGE = 30 minutes;

    function settle(uint256 optionId) external nonReentrant {
        (uint256 clPrice, uint256 clAge) = _getChainlinkPrice();
        require(block.timestamp - clAge <= MAX_ORACLE_AGE, "Stale oracle");

        uint256 twap = _getTWAP(30 minutes);
        require(
            _absDiff(clPrice, twap) * 10_000 / clPrice <= MAX_DEVIATION_BPS,
            "Oracle deviation circuit breaker"
        );

        options[optionId].settled = true;
        IERC20(collateral).transfer(
            options[optionId].holder, _calculatePayout(optionId, clPrice)
        );
    }
}
```

### 1.2 Keeper / Settler Trust

Most protocols rely on keepers to trigger settlement, epoch transitions, or
liquidations. A malicious or absent keeper can delay settlement to manipulate
outcomes.

**Audit checks:**
- [ ] Who can trigger settlement — is it permissionless or restricted to a keeper?
- [ ] If keeper-only: what happens if the keeper is offline at expiry?
- [ ] Can anyone call settlement after a grace period (fallback mechanism)?
- [ ] Is the settlement price locked at expiry time, or at the block when `settle()` is called?
- [ ] Can the keeper selectively settle some options and not others?
- [ ] Is the IV oracle updatable by admin without timelock?
- [ ] Can the admin change the spot oracle address? Is there a timelock?
- [ ] For vault-based protocols: who triggers epoch transitions and can they delay them?

---

## 2. Settlement Oracle Manipulation

### 2.1 Flash-Loan Price Manipulation at Expiry

The most critical attack: manipulate the spot price at the exact block where
options settle. If the settlement oracle reads a spot price (DEX reserve ratio,
single-block observation), an attacker can use a flash loan to move the price,
trigger settlement, and collect inflated payouts.

**Real exploit pattern — Deus DAO (September 2023, ~$6M):** The protocol used a
single DEX spot price for settlement. The attacker flash-loaned assets, moved
the DEX price, triggered settlement in the same transaction, and collected
payouts based on the manipulated price.

**Vulnerable — spot price settlement in single block:**
```solidity
pragma solidity ^0.8.20;

contract VulnerableSettlement {
    IUniswapV2Pair public pair;

    function getSettlementPrice() public view returns (uint256) {
        // Reads current reserves — trivially manipulable via flash loan
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return uint256(reserve1) * 1e18 / uint256(reserve0);
    }

    function settle(uint256 optionId) external {
        uint256 price = getSettlementPrice();
        // Attacker: flash loan → swap to move price → settle → swap back
        _executePayout(optionId, price);
    }
}
```

**Secure — TWAP settlement with observation window:**
```solidity
pragma solidity ^0.8.20;

contract SecureSettlement {
    uint256 public constant TWAP_WINDOW = 30 minutes;
    uint256 public constant SETTLEMENT_DELAY = 15 minutes;

    mapping(uint256 => uint256) public expiryTimestamps;
    mapping(uint256 => uint256) public settlementPrices;

    // Price is snapshotted at expiry, settlement happens after delay
    function snapshotExpiryPrice(uint256 optionId) external {
        require(block.timestamp >= expiryTimestamps[optionId], "Not expired");
        require(settlementPrices[optionId] == 0, "Already snapshotted");

        // Use Chainlink as primary, TWAP as sanity check
        uint256 chainlinkPrice = _getChainlinkPrice();
        uint256 twapPrice = _getUniswapV3TWAP(TWAP_WINDOW);
        require(
            _withinBounds(chainlinkPrice, twapPrice, 500),
            "Price deviation"
        );
        settlementPrices[optionId] = chainlinkPrice;
    }

    function settle(uint256 optionId) external nonReentrant {
        require(settlementPrices[optionId] != 0, "Not snapshotted");
        require(
            block.timestamp >= expiryTimestamps[optionId] + SETTLEMENT_DELAY,
            "Settlement delay"
        );
        _executePayout(optionId, settlementPrices[optionId]);
    }
}
```

### 2.2 Settlement-Block Griefing

If settlement must happen at a specific block and anyone can call it, an
attacker can front-run legitimate settlement with a manipulated price. If only
a keeper can settle, DoS-ing the keeper at the expiry block delays settlement.

**Audit checks:**
- [ ] Is the settlement price a spot price, TWAP, or Chainlink feed?
- [ ] If spot: can a flash loan manipulate the price in the settlement block?
- [ ] Is the settlement price snapshotted at expiry or read when `settle()` is called?
- [ ] Is there a delay between price snapshot and payout execution?
- [ ] Can settlement be triggered by anyone (permissionless griefing)?
- [ ] Is there a circuit breaker if the oracle price deviates >X% from a reference?
- [ ] What happens if the Chainlink feed goes stale at exactly the expiry block?
- [ ] For Inverse Finance-style protocols: can the governance token itself be the settlement oracle? (INV oracle manipulation, April 2022)

---

## 3. Implied Volatility (IV) Attacks

### 3.1 Admin IV Manipulation

If the IV feed is admin-controlled, the admin (or a compromised key) can set IV
to extreme values to misprice options. Near-zero IV makes options nearly free to
buy; extremely high IV makes premiums extractable from the liquidity pool.

**Vulnerable — unbounded admin IV:**
```solidity
pragma solidity ^0.8.20;

contract OptionsAMM {
    uint256 public impliedVolatility; // in basis points (e.g., 8000 = 80%)
    address public admin;

    function setIV(uint256 newIV) external {
        require(msg.sender == admin, "Not admin");
        // No bounds — admin can set IV to 1 (near-zero) or 100_000 (1000%)
        impliedVolatility = newIV;
    }

    function getOptionPremium(uint256 strike, uint256 expiry)
        public view returns (uint256)
    {
        // Black-Scholes approximation using impliedVolatility
        // If IV = 1, premium ~ 0 → attacker buys options for free
        return _blackScholes(strike, expiry, impliedVolatility);
    }
}
```

**Secure — bounded IV with rate limiting:**
```solidity
pragma solidity ^0.8.20;

contract OptionsAMM {
    uint256 public impliedVolatility;
    uint256 public lastIVUpdate;
    uint256 public constant MIN_IV = 500;    // 5% floor
    uint256 public constant MAX_IV = 30_000; // 300% ceiling
    uint256 public constant MAX_IV_CHANGE_PER_HOUR = 1_000; // 10%
    uint256 public constant IV_COOLDOWN = 1 hours;

    function setIV(uint256 newIV) external onlyGovernance {
        require(newIV >= MIN_IV && newIV <= MAX_IV, "IV out of bounds");
        require(
            block.timestamp >= lastIVUpdate + IV_COOLDOWN,
            "IV cooldown"
        );
        uint256 delta = newIV > impliedVolatility
            ? newIV - impliedVolatility
            : impliedVolatility - newIV;
        require(delta <= MAX_IV_CHANGE_PER_HOUR, "IV change too large");

        impliedVolatility = newIV;
        lastIVUpdate = block.timestamp;
        emit IVUpdated(newIV, block.timestamp);
    }
}
```

### 3.2 AMM-Based IV Drainage (Lyra / CLAMM Pattern)

Protocols like Lyra derive IV from pool utilization. When IV becomes stale
(market moves but no trades update the AMM), a sophisticated trader can buy
underpriced options, draining LP funds.

**Lyra AVAX exploit pattern (November 2022):** LPs on Lyra's AVAX market
suffered losses when IV lagged behind actual realized volatility during a
sharp price move. Traders bought cheap options using stale IV, then profited
when the underlying moved as expected.

**Audit checks:**
- [ ] Who sets IV — admin, on-chain model, or external feed?
- [ ] Are there min/max IV bounds to prevent extreme mispricing?
- [ ] Is there a rate limit on IV changes (max delta per update)?
- [ ] If AMM-derived IV: does the AMM update IV on every trade?
- [ ] Can IV become stale during periods of low trading activity?
- [ ] Is there a mechanism to pause trading if IV diverges significantly from realized volatility?
- [ ] Can a single large trade manipulate the AMM IV for subsequent trades?
- [ ] Are there vega exposure limits per LP to prevent pool insolvency from IV mispricing?

---

## 4. Collateral & Margin

### 4.1 Undercollateralized Writing

An options writer must post sufficient collateral to cover the maximum possible
payout. Undercollateralized writing means the protocol cannot honor all payouts
if options expire deep in-the-money (ITM).

**Vulnerable — collateral based on current price, not max payout:**
```solidity
pragma solidity ^0.8.20;

contract OptionsVault {
    function writeOption(uint256 strike, uint256 amount, bool isCall) external {
        // Only requires collateral = current spot price, not max payout
        uint256 required = oracle.getPrice() * amount / 1e18;
        require(collateral[msg.sender] >= required, "Insufficient");
        _mint(msg.sender, strike, amount, isCall);
    }
}
```

**Secure — full collateralization for naked options:**
```solidity
pragma solidity ^0.8.20;

contract OptionsVault {
    function writeOption(uint256 strike, uint256 amount, bool isCall) external nonReentrant {
        // Covered call: 1:1 underlying. Put: strike * amount (max payout)
        uint256 required = isCall ? amount : strike * amount / 1e18;
        require(collateral[msg.sender] >= required, "Insufficient");
        lockedCollateral[msg.sender] += required;
        _mint(msg.sender, strike, amount, isCall);
    }

    function withdrawCollateral(uint256 amount) external {
        uint256 free = collateral[msg.sender] - lockedCollateral[msg.sender];
        require(amount <= free, "Collateral locked");
        collateral[msg.sender] -= amount;
        IERC20(collateralToken).transfer(msg.sender, amount);
    }
}
```

### 4.2 Margin Maintenance and Liquidation

For partially collateralized (margin) models, the protocol must continuously
check that writers maintain sufficient margin as the underlying price moves.
Missing or delayed margin calls create insolvency risk.

**Vulnerable — no margin maintenance check:**
```solidity
pragma solidity ^0.8.20;

contract MarginOptions {
    function writeOption(uint256 strike, uint256 amount) external {
        uint256 required = strike * amount * 2_000 / 10_000 / 1e18; // 20% initial
        require(collateral[msg.sender] >= required, "Margin");
        _mint(msg.sender, strike, amount, true);
        // No maintenance check — writer becomes undercollateralized as option goes ITM
        // No liquidation function exists
    }
}
```

**Secure — continuous margin with liquidation:**
```solidity
pragma solidity ^0.8.20;

contract MarginOptions {
    uint256 public constant MAINTENANCE_MARGIN_BPS = 1_200; // 12%
    uint256 public constant LIQUIDATION_BONUS_BPS = 500;    // 5%

    function isLiquidatable(address writer) public view returns (bool) {
        return collateral[writer] < _maintenanceMarginRequired(writer);
    }

    function liquidate(address writer, uint256 optionId) external nonReentrant {
        require(isLiquidatable(writer), "Not liquidatable");
        uint256 seized = _seizeCollateral(writer, optionId);
        _transferObligation(writer, address(this), optionId);
        IERC20(collateralToken).transfer(msg.sender, seized * LIQUIDATION_BONUS_BPS / 10_000);
        emit WriterLiquidated(writer, optionId, seized);
    }
}
```

**Audit checks:**
- [ ] Are options fully collateralized or using a margin model?
- [ ] If margin: is there a maintenance margin check?
- [ ] Can a writer withdraw collateral while options are ITM?
- [ ] Is there a liquidation mechanism for undercollateralized writers?
- [ ] Can liquidation be front-run (MEV) to extract the liquidation bonus unfairly?
- [ ] For cash-settled options: is the payout capped at collateral posted?
- [ ] For physically settled options: is delivery atomic with payment?
- [ ] Can a writer's position become insolvent between margin checks (price gap risk)?

---

## 5. Vault Strategy Risks (Ribbon / Thetanuts / Theta Vaults)

### 5.1 Adversarial Strike Selection

Theta vault strategies (covered calls, cash-secured puts) depend on strike
selection each epoch. If the strike selector (manager/keeper) can choose strikes
adversarially, depositors lose funds.

**Vulnerable — manager selects strike after seeing order flow:**
```solidity
pragma solidity ^0.8.20;

contract ThetaVault {
    function setStrikePrice(uint256 newStrike) external {
        require(msg.sender == manager, "Not manager");
        // No bounds — manager sets ATM strike to maximize premium but increase exercise risk
        currentStrike = newStrike;
    }

    function startAuction() external {
        require(msg.sender == manager, "Not manager");
        // Manager sets strike THEN starts auction — can adjust after seeing bids
        _startGnosisAuction(currentStrike);
    }
}
```

**Secure — algorithmic strike with bounds and commit-reveal:**
```solidity
pragma solidity ^0.8.20;

contract ThetaVault {
    uint256 public constant MIN_OTM_BPS = 500;  // min 5% out-of-money
    uint256 public constant MAX_OTM_BPS = 3_000; // max 30% out-of-money
    uint256 public constant STRIKE_LOCK_BEFORE_AUCTION = 2 hours;

    function setStrikePrice(uint256 newStrike) external onlyKeeper {
        uint256 spot = oracle.getPrice();

        // For covered calls: strike must be above spot by MIN_OTM_BPS
        uint256 minStrike = spot * (10_000 + MIN_OTM_BPS) / 10_000;
        uint256 maxStrike = spot * (10_000 + MAX_OTM_BPS) / 10_000;
        require(
            newStrike >= minStrike && newStrike <= maxStrike,
            "Strike out of bounds"
        );
        require(
            block.timestamp + STRIKE_LOCK_BEFORE_AUCTION <= auctionStart,
            "Too close to auction"
        );

        currentStrike = newStrike;
        strikeLockTime = block.timestamp;
        emit StrikeSet(newStrike, spot, block.timestamp);
    }
}
```

### 5.2 Epoch Deposit/Withdrawal Timing

Vault depositors can game epoch boundaries: deposit just before a profitable
epoch (front-running known premium income) or withdraw just before an expected
exercise event (avoiding losses).

**Vulnerable — instant deposit with immediate epoch participation:**
```solidity
pragma solidity ^0.8.20;

contract ThetaVault {
    function deposit(uint256 amount) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        // Deposit immediately participates in current epoch — front-runnable
        shares[msg.sender] += _convertToShares(amount);
    }
}
```

**Secure — queued deposits with epoch delay:**
```solidity
pragma solidity ^0.8.20;

contract ThetaVault {
    mapping(address => PendingDeposit) public pendingDeposits;

    function deposit(uint256 amount) external nonReentrant {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        pendingDeposits[msg.sender].amount += amount;
        pendingDeposits[msg.sender].epoch = currentEpoch + 1; // next epoch
        emit DepositQueued(msg.sender, amount, currentEpoch + 1);
    }

    function claimShares() external {
        PendingDeposit storage pd = pendingDeposits[msg.sender];
        require(currentEpoch >= pd.epoch, "Not yet eligible");
        shares[msg.sender] += _convertToShares(pd.amount, pd.epoch);
        delete pendingDeposits[msg.sender];
    }
}
```

### 5.3 Auction Manipulation (Gnosis Auction Abuse)

Ribbon Finance uses Gnosis Auction to sell options. Auction manipulation vectors
include: last-block sniping, wash trading to set a floor price, and
colluding bidders who split a large order to avoid detection.

**Audit checks:**
- [ ] Who selects the strike price — admin, keeper, or algorithm?
- [ ] Is the strike set before or after the premium auction starts?
- [ ] Is there a minimum OTM distance enforced on-chain?
- [ ] Can the manager time strike selection to maximize personal premium at depositor expense?
- [ ] Are deposits queued for the next epoch (no same-epoch participation)?
- [ ] Can depositors withdraw mid-epoch to avoid exercise losses?
- [ ] Is the auction mechanism (Gnosis Auction) resistant to last-block sniping?
- [ ] Is there a minimum premium threshold below which the vault rejects the auction result?
- [ ] Are performance fees calculated on gross or net returns? Can the fee structure be gamed?
- [ ] Can the vault manager roll options instead of settling (indefinite extension)?

---

## 6. Multi-Leg Strategies & Complex Payoffs

### 6.1 Payoff Correctness for Spreads

Multi-leg strategies (bull call spreads, iron condors, straddles) require
precise payoff calculations with signed arithmetic. Incorrect payoff formulas
can result in overpayment or underpayment at settlement.

**Vulnerable — unsigned math for payoffs that can be negative:**
```solidity
pragma solidity ^0.8.20;

contract SpreadSettlement {
    function settleCallSpread(
        uint256 longStrike, uint256 shortStrike,
        uint256 settlementPrice, uint256 amount
    ) external returns (uint256) {
        // BUG: underflows if OTM — unsigned subtraction reverts or wraps
        uint256 longPayout = settlementPrice - longStrike;
        uint256 shortPayout = settlementPrice - shortStrike;
        return (longPayout - shortPayout) * amount / 1e18;
    }
}
```

**Secure — safe payoff with explicit max(0, x) handling:**
```solidity
pragma solidity ^0.8.20;

contract SpreadSettlement {
    function settleCallSpread(
        uint256 longStrike, uint256 shortStrike,
        uint256 settlementPrice, uint256 amount
    ) external returns (uint256) {
        require(longStrike < shortStrike, "Invalid spread");
        uint256 longPay = settlementPrice > longStrike ? settlementPrice - longStrike : 0;
        uint256 shortPay = settlementPrice > shortStrike ? settlementPrice - shortStrike : 0;
        // Capped at max profit = shortStrike - longStrike
        uint256 net = longPay - shortPay;
        uint256 maxProfit = shortStrike - longStrike;
        return (net > maxProfit ? maxProfit : net) * amount / 1e18;
    }
}
```

### 6.2 Calendar Spread Leg Independence

Calendar spreads have different expiry dates per leg. If the near-leg settlement
affects far-leg valuation, attackers can manipulate near-leg to influence far-leg.
Partial settlement of multi-leg positions must not release collateral prematurely.

**Audit checks:**
- [ ] Are payoff calculations correct for all settlement scenarios (ITM, ATM, OTM)?
- [ ] Does the code use signed integers or explicit `max(0, x)` for payoffs that can be negative?
- [ ] Is the net payout of a spread capped at the maximum theoretical profit?
- [ ] For calendar spreads: is the near-leg settlement independent of the far-leg?
- [ ] Can partial settlement of a multi-leg position release collateral prematurely?
- [ ] Is the collateral requirement for a spread the max loss, not the sum of individual legs?
- [ ] Are basket options (multi-underlying) indexing the correct assets at settlement?
- [ ] Can an attacker create a position where individual legs net to a riskless extraction?

---

## 7. Protocol-Specific Patterns

### 7.1 Lyra v2 (AMM + Synthetix Integration)

Lyra v2 prices options via AMM with delta/vega hedging through Synthetix perps.

**Key risks:** IV-spot divergence makes hedge ineffective; hedging lag during fast
moves exposes LPs; Synthetix market suspension leaves Lyra unhedged.

**Audit checks (Lyra-specific):**
- [ ] Does the AMM pause trading when the Synthetix hedging market is suspended?
- [ ] Is the delta hedge updated atomically with each trade, or asynchronously?
- [ ] Can an attacker trade on Lyra while the Synthetix hedge is stale?
- [ ] Is the GWAV (geometric weighted average volatility) manipulation-resistant?

### 7.2 Opyn Gamma (oToken / Controller / Margin Pool)

Opyn uses oTokens (ERC-20) with a Controller managing collateral in a MarginPool.

**Key risks:** oToken mint/burn parity violations cause undercollateralization;
vault operator trust (compromised operator extracts collateral); Chainlink pricer
dispute period can be gamed to manipulate settlement price.

**Audit checks (Opyn-specific):**
- [ ] Is every oToken mint matched by a collateral deposit in the MarginPool?
- [ ] Can a vault operator withdraw excess collateral from a spread margin vault?
- [ ] Is the Chainlink pricer dispute period long enough to catch manipulation?
- [ ] Can oTokens be transferred after expiry but before settlement?

### 7.3 Ribbon Finance (Theta Vault + Gnosis Auction)

Ribbon sells covered calls/puts weekly via Gnosis Auction. See section 5.1 for
strike manipulation risks.

**Audit checks (Ribbon-specific):**
- [ ] Is there a minimum clearing price or bidder count enforced?
- [ ] Can the manager delay epoch closure to allow strategic withdrawals?
- [ ] Are depositors locked during the option lifecycle?
- [ ] Is the vault's premium distributed pro-rata to all depositors?

### 7.4 Dopex (SSOV — Single Staking Option Vault)

Epoch-based vaults with fixed strikes and expiry per epoch.

**Key risks:** Strike array manipulation via governance; epoch boundary
front-running (depositors withdraw before low-demand epochs); reward token
inflation (DPX/rDPX) masking vault underperformance.

**Audit checks (Dopex-specific):**
- [ ] Are epoch strikes set via governance with a timelock?
- [ ] Can depositors withdraw after seeing the epoch's option demand?
- [ ] Is reward distribution separate from core vault accounting?

### 7.5 Premia v3 (Concentrated Liquidity Options)

Uses concentrated liquidity (Uniswap V3-style) for options market-making.

**Key risks:** Range order sniping (adverse selection of narrow-range LPs);
tick crossing rounding errors (see `defi-integrations.md §V4 Math Layer Pitfalls`);
incorrect LP tick attribution during exercise.

**Audit checks (Premia-specific):**
- [ ] Is tick math consistent with Uniswap V3 precision?
- [ ] Can LPs be adversely selected via narrow-range sniping?
- [ ] Is option exercise correctly attributed to the underwriting LP tick range?

---

## 8. Comprehensive Options Audit Checklist

Comprehensive checklist for auditing on-chain options protocols. Items are
grouped by audit category.

### Settlement Oracle (6 items)

- [ ] Identify the settlement oracle type (Chainlink, TWAP, spot, admin)
- [ ] Verify flash-loan resistance: settlement uses TWAP or Chainlink, not single-block spot
- [ ] Check for settlement delay between price snapshot and payout execution
- [ ] Verify circuit breaker exists if oracle price deviates >X% from reference
- [ ] Confirm oracle staleness check (max age) is enforced before settlement
- [ ] Verify keeper liveness fallback — anyone can settle after a grace period

### IV / Pricing (6 items)

- [ ] Identify IV source: admin-controlled, AMM-derived, or external feed
- [ ] Verify IV bounds (min/max) prevent extreme mispricing
- [ ] Check IV rate-limiting (max change per period)
- [ ] For AMM IV: verify IV updates on every trade (no stale IV between trades)
- [ ] Verify Black-Scholes or pricing model implementation against reference
- [ ] Check that low-liquidity underlyings cannot be mispriced via IV manipulation

### Collateral (6 items)

- [ ] Verify full collateralization for naked options (underlying for calls, strike for puts)
- [ ] If margin model: verify maintenance margin and liquidation mechanism exist
- [ ] Check that collateral cannot be withdrawn while options are ITM
- [ ] Verify collateral token is not rebasing/fee-on-transfer (or handled correctly)
- [ ] Check that insolvency is prevented: total collateral >= sum of max payouts
- [ ] Verify liquidation incentive is sufficient but not excessive (MEV extraction)

### Vault Strategy (6 items)

- [ ] Verify strike selection has on-chain bounds (min OTM distance)
- [ ] Check that strike is set before premium auction (no information advantage)
- [ ] Verify deposits are queued for next epoch (no same-epoch front-running)
- [ ] Check for mid-epoch withdrawal prevention during option lifecycle
- [ ] Verify auction mechanism has minimum clearing price and bidder requirements
- [ ] Check performance fee calculation (gross vs net, watermark)

### Multi-Leg (6 items)

- [ ] Verify payoff arithmetic handles all ITM/ATM/OTM combinations correctly
- [ ] Check for underflow in unsigned payoff subtraction (use explicit max(0, x))
- [ ] Verify spread payout is capped at maximum theoretical profit
- [ ] Check calendar spread leg independence (near-leg settlement does not affect far-leg)
- [ ] Verify partial settlement does not release collateral prematurely
- [ ] Check that collateral for spreads = max loss, not sum of individual legs

### Protocol-Specific (6 items)

- [ ] For Lyra: verify trading pauses when Synthetix hedge market is suspended
- [ ] For Opyn: verify oToken mint/burn parity with MarginPool collateral
- [ ] For Ribbon: verify auction has minimum clearing price and bidder threshold
- [ ] For Dopex: verify epoch strikes have governance timelock
- [ ] For Premia: verify tick math precision matches Uniswap V3 standards
- [ ] For all: verify expired options cannot be transferred or used as collateral

### Integration (6 items)

- [ ] Check that oTokens used as DeFi collateral handle expiry correctly
- [ ] Verify that option exercise does not create reentrancy vectors
- [ ] Check cross-protocol dependency chains (Lyra → Synthetix, vaults → Gnosis Auction)
- [ ] Verify ERC-20 compliance of option tokens (approve/transfer edge cases)
- [ ] Check that protocol pausing does not brick user positions permanently
- [ ] Verify upgrade path for option contracts with outstanding positions
