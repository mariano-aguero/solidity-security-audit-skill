# Prediction Market Security Reference

Security framework for on-chain prediction market protocols. Covers
Polymarket (UMA + Gnosis CTF), Augur v1/v2, Azuro, Overtime Markets,
SX Network, PancakeSwap Prediction, and general binary/multi-outcome
market patterns.

See `defi-checklist.md §Prediction` for the high-level checklist.
See `vulnerability-taxonomy.md §4` for oracle manipulation patterns.
See `defi-integrations.md` for Chainlink integration patterns.
See `intent-protocols.md` for cross-chain settlement patterns relevant to
multi-chain prediction markets.

---

## Architecture Patterns

| Pattern | Examples | Key Risk |
|---------|----------|----------|
| UMA Optimistic Oracle + CTF | Polymarket | Dispute bond economics, resolver bribery |
| Chainlink price feed resolution | PancakeSwap Prediction | Oracle staleness, round timing manipulation |
| Centralized resolver | Early Azuro, SX Network | Single-point-of-failure, insider trading |
| DAO / token-weighted vote | Augur v2 (REP fork) | Fork economics, low participation capture |
| Oracle relayer network | Azuro v2 | Relayer collusion, delayed resolution |
| Hybrid (Chainlink + manual fallback) | Overtime Markets (Thales) | Fallback trust, mode-switch timing |

**Core invariant**: For a binary market with outcomes YES/NO, at all times:
`totalYesShares * payoutPerYes + totalNoShares * payoutPerNo <= totalCollateral`.
A prediction market is insolvent if the sum of all potential payouts exceeds
the collateral pool.

---

## 1. Trust Model & Architecture

### 1.1 Resolution Oracle Dependency

Prediction markets depend on a resolution oracle to determine the outcome of
real-world events. Unlike price oracles used in DeFi lending, resolution oracles
produce a one-time, irreversible determination. The trust assumptions differ
significantly by oracle type:

- **UMA Optimistic Oracle** — anyone can propose, disputed via bonded escalation
- **Chainlink** — decentralized price feed, but only for quantitative outcomes
- **Centralized resolver** — single admin or committee decides outcomes
- **DAO vote** — token-weighted governance, subject to plutocratic capture

**Vulnerable — single admin resolver with no dispute path:**
```solidity
pragma solidity ^0.8.20;

contract PredictionMarket {
    address public resolver;
    mapping(bytes32 => uint256) public outcomes; // 0=unresolved, 1=YES, 2=NO

    function resolve(bytes32 marketId, uint256 outcome) external {
        require(msg.sender == resolver, "Not resolver");
        // No dispute mechanism — resolver decision is final and immediate
        // No timelock — insider can resolve and redeem in same block
        outcomes[marketId] = outcome;
    }

    // Resolver can also create markets — creator-as-resolver collusion
    function createMarket(bytes32 marketId) external {
        require(msg.sender == resolver, "Not resolver");
        // ...
    }
}
```

**Secure — optimistic resolution with bonded dispute escalation:**
```solidity
pragma solidity ^0.8.20;

contract PredictionMarket {
    uint256 public constant DISPUTE_WINDOW = 2 hours;
    uint256 public constant DISPUTE_BOND = 1_000e6; // 1000 USDC

    struct Resolution {
        uint256 outcome;
        uint256 proposedAt;
        address proposer;
        bool disputed;
    }

    mapping(bytes32 => Resolution) public resolutions;

    function proposeOutcome(bytes32 marketId, uint256 outcome) external {
        require(resolutions[marketId].proposedAt == 0, "Already proposed");
        IERC20(bondToken).transferFrom(msg.sender, address(this), DISPUTE_BOND);
        resolutions[marketId] = Resolution(outcome, block.timestamp, msg.sender, false);
        emit OutcomeProposed(marketId, outcome, msg.sender);
    }

    function dispute(bytes32 marketId) external {
        Resolution storage r = resolutions[marketId];
        require(block.timestamp <= r.proposedAt + DISPUTE_WINDOW, "Window closed");
        IERC20(bondToken).transferFrom(msg.sender, address(this), DISPUTE_BOND * 2);
        r.disputed = true;
        emit Disputed(marketId, msg.sender);
    }

    function finalizeOutcome(bytes32 marketId) external {
        Resolution storage r = resolutions[marketId];
        require(!r.disputed && block.timestamp > r.proposedAt + DISPUTE_WINDOW);
        _setOutcome(marketId, r.outcome);
    }
}
```

### 1.2 Market Lifecycle Phases

Market lifecycle: **Creation** (parameters set) → **Trading** (buy/sell outcome
tokens) → **Resolution** (oracle determines winner) → **Redemption** (winners
claim collateral). Each transition carries distinct trust requirements.

**Audit checks:**
- [ ] Who can resolve the market — permissionless proposal, admin, DAO, or oracle?
- [ ] Is there a dispute/escalation path if the initial resolution is wrong?
- [ ] Is the dispute bond large enough to deter manipulation but not so large it prevents legitimate disputes?
- [ ] What happens if no one proposes a resolution (market stuck, funds locked)?
- [ ] Can the resolver also hold positions in the market they resolve?
- [ ] Is there a separation between market creator and market resolver?
- [ ] Can resolution be triggered before the event has actually occurred?
- [ ] Is there a grace period between resolution and redemption to allow disputes?

---

## 2. Market Resolution & Oracle Manipulation

### 2.1 UMA Optimistic Oracle Dispute Economics

Polymarket uses UMA's Optimistic Oracle for resolution. The security model relies
on economic incentives: proposing a wrong outcome is unprofitable because the
dispute bond is slashed. However, the cost-of-corruption analysis is subtle.

**Real incident — Polymarket Ukraine election controversy (Feb 2024):**
A market on Ukraine's presidential election saw disputed resolution when the
proposer submitted an outcome that a portion of participants considered premature.
The dispute escalated to UMA's DVM (Data Verification Mechanism), highlighting
that optimistic oracle security depends on DVM voter participation and the
relative size of dispute bonds vs outstanding market value.

**Real incident — Polymarket Maduro election dispute (Jul 2024):**
Venezuela's presidential election market faced prolonged resolution disputes.
Multiple proposals were submitted and disputed, demonstrating that ambiguous
real-world events can lead to extended fund-locking when the oracle dispute
mechanism cycles repeatedly.

**Vulnerable — dispute bond too small relative to market size:**
```solidity
pragma solidity ^0.8.20;

contract MarketWithUMA {
    uint256 public constant DISPUTE_BOND = 100e6; // 100 USDC
    // Market has $10M in positions — cost to corrupt = 100 USDC
    // Attacker profits $10M by posting wrong resolution and waiting for finalization

    function requestResolution(bytes32 marketId) external {
        // Bond is static regardless of market size
        optimisticOracle.requestPrice(
            identifier, block.timestamp, ancillaryData, bondToken, DISPUTE_BOND
        );
    }
}
```

**Secure — dynamic bond scaled to market value:**
```solidity
pragma solidity ^0.8.20;

contract MarketWithUMA {
    uint256 public constant MIN_BOND = 500e6;       // 500 USDC floor
    uint256 public constant BOND_RATIO_BPS = 100;   // 1% of market value
    uint256 public constant MAX_BOND = 100_000e6;    // 100K USDC ceiling

    function requestResolution(bytes32 marketId) external {
        uint256 marketValue = _totalCollateral(marketId);
        uint256 bond = marketValue * BOND_RATIO_BPS / 10_000;
        bond = bond < MIN_BOND ? MIN_BOND : (bond > MAX_BOND ? MAX_BOND : bond);

        optimisticOracle.requestPrice(
            identifier, block.timestamp, ancillaryData, bondToken, bond
        );
    }
}
```

### 2.2 Resolver Bribery and Insider Front-Running

If the resolver (admin, oracle operator, or DAO voter) can take positions before
resolving, the market becomes a guaranteed-profit mechanism for insiders.

**Audit checks:**
- [ ] Can the resolver (or oracle operator) hold positions in markets they resolve?
- [ ] Is the dispute bond dynamically scaled to market size (cost-of-corruption > profit)?
- [ ] For UMA: is the DVM voter participation sufficient to resist plutocratic attacks?
- [ ] Can a proposer submit a resolution and redeem in the same transaction?
- [ ] Is there a minimum dispute window that cannot be shortened by admin?
- [ ] Can disputes be griefed by repeatedly proposing and disputing to lock funds?
- [ ] For centralized resolvers: is there a bond or stake at risk for incorrect resolution?
- [ ] Can the resolver delay resolution indefinitely to force time-decay on positions?

---

## 3. Conditional Token (ERC-1155 CTF) Logic

### 3.1 Split / Merge Position Attacks

Gnosis CTF (Conditional Token Framework) represents outcome positions as
ERC-1155 tokens. The `splitPosition` and `mergePositions` functions convert
collateral into outcome tokens and vice versa. Bugs in split/merge logic can
create or destroy value.

**Vulnerable — merge without full position ownership check:**
```solidity
pragma solidity ^0.8.20;

contract VulnerableCTF {
    function mergePositions(
        IERC20 collateral,
        bytes32 parentCollectionId,
        bytes32 conditionId,
        uint256[] calldata partition,
        uint256 amount
    ) external {
        // Burns outcome tokens and returns collateral
        for (uint256 i = 0; i < partition.length; i++) {
            uint256 positionId = _getPositionId(collateral, parentCollectionId, conditionId, partition[i]);
            // BUG: only checks balance, not that partition covers ALL outcomes
            // Attacker can merge a subset of outcomes, extracting collateral
            // while retaining positions in uncovered outcomes
            _burn(msg.sender, positionId, amount);
        }
        collateral.transfer(msg.sender, amount);
    }
}
```

**Secure — validate partition completeness before merge:**
```solidity
pragma solidity ^0.8.20;

contract SecureCTF {
    function mergePositions(
        IERC20 collateral,
        bytes32 parentCollectionId,
        bytes32 conditionId,
        uint256[] calldata partition,
        uint256 amount
    ) external nonReentrant {
        // Verify partition is a full set of mutually exclusive outcomes
        uint256 fullIndexSet = (1 << outcomeSlotCount[conditionId]) - 1;
        uint256 combinedPartition;
        for (uint256 i = 0; i < partition.length; i++) {
            require(partition[i] != 0, "Empty partition");
            require(partition[i] & combinedPartition == 0, "Overlapping");
            combinedPartition |= partition[i];

            uint256 positionId = _getPositionId(
                collateral, parentCollectionId, conditionId, partition[i]
            );
            _burn(msg.sender, positionId, amount);
        }
        require(combinedPartition == fullIndexSet, "Incomplete partition");
        collateral.transfer(msg.sender, amount);
    }
}
```

### 3.2 Redemption Math and reportPayouts Access

The `reportPayouts` function sets the winning outcome distribution. If access
control is missing, anyone can report arbitrary payouts.

**Audit checks:**
- [ ] Does `mergePositions` verify the partition covers all outcomes (complete set)?
- [ ] Can overlapping partitions in `splitPosition` create duplicate outcome tokens?
- [ ] Is `reportPayouts()` restricted to the designated oracle/resolver?
- [ ] Can `reportPayouts()` be called multiple times (re-resolution attack)?
- [ ] Are position IDs collision-resistant under user-controlled condition parameters?
- [ ] For multi-outcome markets: does redemption math correctly handle fractional payouts?
- [ ] Can an attacker split, partially merge, and extract collateral without full position coverage?
- [ ] Are ERC-1155 callback hooks (onERC1155Received) checked for reentrancy vectors?

---

## 4. AMM-Based Pricing Attacks

### 4.1 LMSR Bounds Violation

The Logarithmic Market Scoring Rule (LMSR) is used by Augur and other protocols
to price outcome shares. LMSR guarantees prices sum to 1.0 for all outcomes,
but implementation bugs can violate this invariant.

**Vulnerable — LMSR with precision loss breaking price bounds:**
```solidity
pragma solidity ^0.8.20;

contract LMSR_AMM {
    uint256 public constant PRECISION = 1e18;
    uint256 public liquidity; // b parameter

    function getPrice(uint256 outcomeShares, uint256 totalShares)
        public view returns (uint256)
    {
        // exp(q_i / b) / sum(exp(q_j / b))
        // BUG: integer division in exp approximation can produce
        // prices that sum to > 1.0 or < 1.0
        uint256 expQ = _integerExp(outcomeShares * PRECISION / liquidity);
        uint256 sumExp = _integerExp(totalShares * PRECISION / liquidity);
        return expQ * PRECISION / sumExp;
        // No check that sum of all outcome prices == PRECISION
    }
}
```

**Secure — CPMM with explicit [0,1] bounds enforcement:**
```solidity
pragma solidity ^0.8.20;

contract BoundedAMM {
    uint256 public constant PRECISION = 1e18;
    uint256 public constant MIN_PRICE = 1e14;      // 0.01% floor
    uint256 public constant MAX_PRICE = 9999e14;    // 99.99% ceiling

    function getPrice(uint256 yesReserve, uint256 noReserve)
        public pure returns (uint256 yesPrice)
    {
        // CPMM: price = opposite_reserve / (yes_reserve + no_reserve)
        uint256 total = yesReserve + noReserve;
        require(total > 0, "Empty pool");
        yesPrice = noReserve * PRECISION / total;

        // Enforce bounds — prevent 0% or 100% prices
        if (yesPrice < MIN_PRICE) yesPrice = MIN_PRICE;
        if (yesPrice > MAX_PRICE) yesPrice = MAX_PRICE;
    }

    function swap(
        uint256 outcomeIndex, uint256 amount, uint256 minOut
    ) external nonReentrant returns (uint256 out) {
        out = _calculateSwapOutput(outcomeIndex, amount);
        require(out >= minOut, "Slippage");

        // Verify invariant after swap
        uint256 yesPrice = getPrice(reserves[0], reserves[1]);
        uint256 noPrice = PRECISION - yesPrice;
        require(
            yesPrice + noPrice == PRECISION,
            "Price invariant violated"
        );
        // ...
    }
}
```

### 4.2 Sandwich Attack at Resolution

A sophisticated MEV attack: the attacker observes the resolution transaction in
the mempool, front-runs it with a large buy on the winning outcome, and
back-runs with a redemption. This is especially profitable if the AMM allows
trading after the resolution transaction is submitted but before it is finalized.

**Audit checks:**
- [ ] Does the AMM enforce prices within [0, 1] for all outcomes at all times?
- [ ] Can a sufficiently large trade push a price to 0 or beyond 1?
- [ ] Is there slippage protection (minOut) on all swap functions?
- [ ] Can liquidity be added/removed asymmetrically to manipulate implied probabilities?
- [ ] Is trading halted atomically when resolution is proposed (no sandwich window)?
- [ ] For LMSR: does the integer exp/log approximation maintain the sum-to-one invariant?
- [ ] Can a flash loan be used to manipulate AMM reserves and extract value?
- [ ] Is there a minimum liquidity requirement to prevent extreme price impact?

---

## 5. Market Creation & Lifecycle Attacks

### 5.1 Malicious Market Creation

If market creation is permissionless, attackers can create markets designed to
extract value from unsuspecting participants.

**Vulnerable — permissionless creation with creator-as-resolver:**
```solidity
pragma solidity ^0.8.20;

contract MarketFactory {
    function createMarket(
        string calldata question,
        address resolver,
        address collateralToken,
        uint256 resolutionTime
    ) external returns (bytes32 marketId) {
        // No validation — creator sets themselves as resolver
        // No collateral whitelist — can use worthless scam token
        // No question validation — ambiguous wording traps users
        markets[marketId] = Market({
            question: question,
            resolver: resolver, // msg.sender can be resolver
            collateral: collateralToken, // any ERC-20 accepted
            resolutionTime: resolutionTime,
            resolved: false
        });
    }
}
```

**Secure — curated creation with collateral whitelist and resolver registry:**
```solidity
pragma solidity ^0.8.20;

contract MarketFactory {
    mapping(address => bool) public approvedCollateral;
    mapping(address => bool) public approvedResolvers;
    uint256 public constant MIN_RESOLUTION_DELAY = 1 hours;
    uint256 public constant CREATION_BOND = 500e6; // 500 USDC

    function createMarket(
        string calldata question, address resolver,
        address collateralToken, uint256 resolutionTime
    ) external returns (bytes32 marketId) {
        require(approvedCollateral[collateralToken], "Unapproved collateral");
        require(approvedResolvers[resolver], "Unapproved resolver");
        require(resolver != msg.sender, "Creator cannot be resolver");
        require(resolutionTime >= block.timestamp + MIN_RESOLUTION_DELAY, "Too soon");
        IERC20(bondToken).transferFrom(msg.sender, address(this), CREATION_BOND);
        markets[marketId] = Market(question, resolver, collateralToken, resolutionTime, false, msg.sender);
    }
}
```

### 5.2 Invalid Market Resolution (1:1 Redemption)

When a market resolves as "Invalid" (the question was ambiguous or the event
did not occur), all positions should be redeemable at equal value. Bugs in
invalid-market handling can create arbitrage or lock funds.

**Audit checks:**
- [ ] Can anyone create a market, or is creation gated/bonded?
- [ ] Can the market creator set themselves as the resolver (collusion vector)?
- [ ] Is there a collateral token whitelist to prevent scam-token markets?
- [ ] When a market resolves "invalid," are all outcomes redeemable 1:1 for collateral?
- [ ] Is there a creation bond that disincentivizes spam markets?
- [ ] Can a market be halted (trading paused) before resolution? By whom?
- [ ] Is there a minimum resolution delay to prevent flash-creation-and-resolve?
- [ ] Can market parameters (question, resolver, resolution time) be changed after creation?

---

## 6. Timing & MEV Attacks

### 6.1 Insider MEV at Resolution

The most profitable MEV in prediction markets occurs at resolution time.
If the resolution transaction is visible in the mempool, searchers can
front-run it with trades on the winning outcome.

**Vulnerable — resolution without trading halt:**
```solidity
pragma solidity ^0.8.20;

contract PredictionAMM {
    function resolve(bytes32 marketId, uint256 outcome) external onlyResolver {
        // Trading is still open when this tx is in the mempool
        // MEV bot: sees resolve(YES) → buys YES tokens → resolve executes → redeem
        markets[marketId].outcome = outcome;
        markets[marketId].resolved = true;
    }

    function swap(bytes32 marketId, uint256 outcomeIdx, uint256 amount)
        external returns (uint256)
    {
        // No check for pending resolution — trades execute during resolution block
        require(!markets[marketId].resolved, "Resolved");
        return _executeSwap(marketId, outcomeIdx, amount);
    }
}
```

**Secure — blackout period with commit-reveal resolution:**
```solidity
pragma solidity ^0.8.20;

contract PredictionAMM {
    uint256 public constant BLACKOUT_PERIOD = 1 hours;

    function commitResolution(bytes32 marketId, bytes32 commitHash) external onlyResolver {
        markets[marketId].commitHash = commitHash;
        markets[marketId].commitTime = block.timestamp;
        markets[marketId].tradingHalted = true; // Halt trading immediately
    }

    function revealResolution(
        bytes32 marketId, uint256 outcome, bytes32 salt
    ) external onlyResolver {
        Market storage m = markets[marketId];
        require(block.timestamp >= m.commitTime + BLACKOUT_PERIOD, "Blackout");
        require(keccak256(abi.encodePacked(outcome, salt)) == m.commitHash, "Bad reveal");
        m.outcome = outcome;
        m.resolved = true;
    }

    function swap(bytes32 marketId, uint256 outcomeIdx, uint256 amount)
        external nonReentrant returns (uint256)
    {
        require(!markets[marketId].tradingHalted, "Trading halted");
        return _executeSwap(marketId, outcomeIdx, amount);
    }
}
```

### 6.2 Dispute Window Timing Exploits

Short dispute windows prevent legitimate disputes; long ones lock funds. Attackers can grief by disputing at the last second to reset windows.

**Audit checks:**
- [ ] Is there a blackout period before resolution where trading is halted?
- [ ] Can trading occur in the same block as the resolution transaction?
- [ ] Is resolution done via commit-reveal to prevent mempool front-running?
- [ ] Can the resolver see and act on position data before submitting resolution?
- [ ] Is the dispute window long enough for legitimate disputes (>= 2 hours)?
- [ ] Can disputes be submitted at the last second to grief and reset the window?
- [ ] For Chainlink-based markets: can round timing be predicted to enable MEV?
- [ ] Is there a position-taking lockout period before the event occurs?

---

## 7. Protocol-Specific Patterns

### 7.1 Polymarket (UMA + CTF on Polygon)

Polymarket uses Gnosis CTF for position tokens and UMA's Optimistic Oracle for
resolution. Collateral is USDC.e on Polygon PoS.

**Key risks:**
- **UMA DVM voter centralization**: if UMA token distribution is concentrated,
  DVM dispute resolution can be captured
- **Polygon reorg risk**: short reorgs on Polygon PoS can reorder resolution
  transactions, enabling MEV
- **USDC.e bridge risk**: Circle's native USDC vs bridged USDC.e divergence

**Audit checks (Polymarket-specific):**
- [ ] Is the UMA dispute bond proportional to market size?
- [ ] Can UMA DVM voters be bribed for less than the value of outstanding positions?
- [ ] Does the CTF implementation handle Polygon reorgs gracefully?
- [ ] Is the market binary-only, or can multi-outcome markets have resolution ambiguity?

### 7.2 Azuro (LP Pool + Oracle Relayer)

Azuro uses a pooled liquidity model where LPs provide liquidity across all
markets. An oracle relayer network resolves outcomes.

**Key risks:**
- **LP pool shared risk**: a single incorrectly resolved high-value market can
  drain the entire LP pool, affecting all markets
- **Oracle relayer trust**: relayers are semi-centralized; collusion among
  relayers can resolve markets incorrectly
- **Liquidity concentration**: if one market attracts disproportionate volume,
  the LP pool becomes exposed to that single outcome

**Audit checks (Azuro-specific):**
- [ ] Is LP exposure per-market capped to prevent pool drainage from a single market?
- [ ] Can oracle relayers be rotated or slashed for incorrect resolution?
- [ ] Is there an escalation path beyond the relayer network (DAO fallback)?
- [ ] Are LP withdrawals gated during pending resolutions?

### 7.3 Augur v2 (REP Staking + Fork Mechanism)

Augur uses REP token staking for dispute resolution with a nuclear option:
forking the entire protocol when disputes cannot be resolved.

**Real issue — Augur v1 REP value collapse:** Low trading volume made REP
staking rewards negligible, reducing economic security. The cost to acquire
enough REP to manipulate outcomes dropped below potential profit. The fork
mechanism was never triggered on mainnet, leaving its game theory untested.

**Audit checks (Augur-specific):**
- [ ] Is the REP staking requirement proportional to market size?
- [ ] Can the fork mechanism be triggered maliciously to disrupt all markets?
- [ ] Is the fork child universe accounting correct (no double-counting REP)?
- [ ] Does low REP market cap make dispute manipulation economically viable?

### 7.4 PancakeSwap Prediction (Chainlink Price Feed)

PancakeSwap Prediction is a simpler model: users bet whether BNB/USD price
will be higher or lower after a fixed round duration (5 minutes). Resolution
uses Chainlink price feeds.

**Known issue — Chainlink staleness on BSC:** PancakeSwap Prediction rounds
can lock user funds when the Chainlink oracle on BSC fails to update within
the round window. If no valid price is available at round close, the round
becomes unresolvable and user positions are stuck until an admin intervenes.
This has occurred multiple times during BSC congestion events.

**Key risks:**
- **Round timing manipulation**: keeper controls when rounds start/end; a
  malicious or delayed keeper can shift round boundaries to favorable prices
- **Chainlink heartbeat mismatch**: if the oracle heartbeat (e.g., 60s) is
  longer than round duration (e.g., 5 min), stale prices can resolve rounds
- **Claim window expiry**: unclaimed winnings expire and go to treasury

**Audit checks (PancakeSwap-specific):**
- [ ] Is the round start/end time enforced on-chain or keeper-controlled?
- [ ] What happens if Chainlink does not update during a round (round stuck)?
- [ ] Is there a maximum round duration to prevent keeper-delayed resolution?
- [ ] Can the keeper selectively skip rounds to avoid unfavorable outcomes?

### 7.5 SX Network (Sportsbook AMM, Layer-2)

SX Network runs a sports-focused prediction market on its own L2 with a custom
sportsbook AMM. Key risks: L2 sequencer can reorder bets before results,
off-chain odds feed lacks on-chain verification, single-chain bridge exit.

**Audit checks (SX Network-specific):**
- [ ] Can the sequencer reorder bet transactions to front-run known results?
- [ ] Are off-chain odds feeds signed and verifiable on-chain?
- [ ] Is there a forced-exit mechanism if the sequencer goes offline?

### 7.6 Overtime Markets (Optimism, Thales Fork)

Overtime runs on Optimism using Chainlink for sports data with a Thales AMM.
Key risks: not all events have Chainlink feeds (centralized fallback), AMM LPs
are counterparty to all traders (drain risk), Optimism sequencer downtime
creates stale-odds windows.

**Audit checks (Overtime-specific):**
- [ ] Is there a fallback resolver for events not covered by Chainlink?
- [ ] Are LP exposure limits enforced per market and per sport?
- [ ] Is the Optimism sequencer uptime feed checked before accepting bets?

---

## 8. Comprehensive Prediction Markets Audit Checklist

Comprehensive checklist for auditing on-chain prediction market protocols.
Items are grouped by audit category.

### Resolution & Oracle (6 items)

- [ ] Identify the resolution oracle type (UMA, Chainlink, centralized, DAO, relayer)
- [ ] Verify dispute bond is dynamically scaled to market size (cost-of-corruption > profit)
- [ ] Check for dispute escalation path with increasing bonds and independent arbitration
- [ ] Verify resolution cannot occur before the real-world event (premature resolution)
- [ ] Confirm resolver cannot hold positions in markets they resolve (insider prevention)
- [ ] Check for unresolved market timeout with fund recovery mechanism

### CTF Logic (6 items)

- [ ] Verify `splitPosition` creates tokens for all outcomes in the condition
- [ ] Verify `mergePositions` requires a complete partition covering all outcomes
- [ ] Check `reportPayouts()` access control — only designated oracle can call
- [ ] Verify `reportPayouts()` cannot be called twice (re-resolution prevention)
- [ ] Check position ID derivation for collision resistance under user-controlled inputs
- [ ] Verify redemption math handles fractional payouts without rounding exploitation

### AMM Pricing (6 items)

- [ ] Verify AMM prices for all outcomes sum to 1.0 (invariant check)
- [ ] Check that no single trade can push a price to 0 or above 1.0
- [ ] Verify slippage protection (minOut) is enforced on all swap paths
- [ ] Check for flash-loan AMM reserve manipulation vectors
- [ ] Verify liquidity add/remove cannot asymmetrically skew implied probabilities
- [ ] For LMSR: verify integer math approximation maintains sum-to-one property

### Market Lifecycle (6 items)

- [ ] Verify market creation has collateral whitelist and resolver registry
- [ ] Check that creator-as-resolver collusion is prevented
- [ ] Verify "invalid" market resolution returns collateral 1:1 to all positions
- [ ] Check for market creation spam prevention (bond or fee)
- [ ] Verify market parameters cannot be changed after creation
- [ ] Check minimum resolution delay prevents flash-create-and-resolve

### Timing / MEV (6 items)

- [ ] Verify trading halts when resolution is proposed (no sandwich window)
- [ ] Check for commit-reveal resolution to prevent mempool front-running
- [ ] Verify blackout period before event prevents last-minute insider trading
- [ ] Check dispute window is sufficient (>= 2 hours) and cannot be shortened
- [ ] Verify dispute-at-deadline griefing is mitigated (window extension or bond increase)
- [ ] For Chainlink-based: verify round timing cannot be predicted for MEV extraction

### Protocol-Specific (6 items)

- [ ] For Polymarket: verify UMA dispute bond proportional to market value
- [ ] For Azuro: verify LP pool exposure is capped per individual market
- [ ] For Augur: verify REP staking economics make manipulation unprofitable
- [ ] For PancakeSwap: verify Chainlink staleness handling for stuck rounds
- [ ] For SX Network: verify sequencer cannot reorder bets after results known
- [ ] For all: verify expired unclaimed positions have a recovery mechanism

### Integration (6 items)

- [ ] Check that outcome tokens (ERC-1155) handle reentrancy via callbacks
- [ ] Verify cross-chain settlement (if applicable) handles finality correctly
- [ ] Check that protocol pausing does not permanently lock user positions
- [ ] Verify collateral token compatibility (USDC.e vs native USDC, fee-on-transfer)
- [ ] Check that outcome tokens used as DeFi collateral handle resolution correctly
- [ ] Verify upgrade path for markets with outstanding positions
