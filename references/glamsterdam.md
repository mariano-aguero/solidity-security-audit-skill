# Glamsterdam Upgrade Security Reference

Security considerations for Ethereum's Glamsterdam upgrade (~2026).
Covers: EIP-7732 (ePBS — Enshrined Proposer-Builder Separation) and EIP-7928 (Block Access Lists / BALs).

See `l2-crosschain.md` for general L2 and sequencer risks.
See `industry-standards.md` for full EIP timeline.
See `vulnerability-taxonomy.md §9` for front-running and MEV patterns.

---

## Overview

| EIP | Change | Primary Security Impact |
|-----|--------|------------------------|
| EIP-7732 | Proposer-Builder Separation enshrined at consensus protocol level | Payload withholding attack, preconf timing risk |
| EIP-7928 | Block Access Lists: per-TX declared read/write sets at block level | MEV transparency, parallelization race conditions |

---

## 1. EIP-7732 — Enshrined Proposer-Builder Separation (ePBS)

### 1.1 Architecture Change

**Before ePBS (current):** PBS is off-protocol via MEV-Boost relays.
Proposers outsource block building to builders through a trusted relay (Flashbots, etc.).
The relay is the single point of trust — no on-chain accountability.

```
Proposer ← relay (trusted, off-chain) ← Builder
              ↑
         MEV-Boost PBS (current model)
```

**After ePBS (EIP-7732):** PBS is enshrined at consensus level with on-chain commitments.
Two distinct roles:
1. **Proposer** — commits to a `SignedExecutionPayloadHeader` (block body hash + bid value)
2. **Payload Provider (Builder)** — reveals the actual `ExecutionPayload` in the next slot

```
Slot N:   Proposer commits to header  ─── on-chain, verifiable
Slot N+1: Builder reveals payload    ─── on-chain, or withheld → empty slot
```

### 1.2 New Attacker Models

#### 1.2.1 Payload Withholding Attack

A builder commits to a bid value but withholds the actual payload, causing an empty slot.
Motivations: griefing a specific protocol's time-sensitive operation (liquidations,
oracle updates, keeper calls, auction settlements).

**Smart contract implications:**

```solidity
// Vulnerable: assumes every slot produces a block with >0 transactions
contract LiquidationKeeper {
    uint256 public constant MAX_LIQUIDATION_DELAY_SLOTS = 1;

    function liquidate(address borrower) external {
        // If slot N is withheld, this can only be called in slot N+1
        // A 1-slot withholding delays liquidation → accumulates bad debt
        require(
            block.number <= lastUnhealthyBlock[borrower] + MAX_LIQUIDATION_DELAY_SLOTS,
            "Liquidation window expired"
        );
        _liquidate(borrower);
    }
}
```

**Safer pattern — tolerance for missed slots:**
```solidity
contract LiquidationKeeper {
    // Buffer for withholding: allow 3 slots instead of 1
    uint256 public constant LIQUIDATION_GRACE_SLOTS = 3;

    function liquidate(address borrower) external {
        require(
            block.number <= lastUnhealthyBlock[borrower] + LIQUIDATION_GRACE_SLOTS,
            "Liquidation window expired"
        );
        _liquidate(borrower);
    }
}
```

**Audit checks:**
- [ ] Does the protocol use any single-slot windows for liquidations, keepers, or settlements?
- [ ] Are deadline checks using `block.number` with a buffer ≥ 2–3 slots for withholding tolerance?
- [ ] Do keeper reward calculations account for missed slots?

#### 1.2.2 Formalized Builder MEV (Reduced Relay Accountability)

With ePBS, builders have a formal on-chain role but no social reputation requirement.
A malicious builder can sandwich, exclude transactions, and reorder freely
with no relay acting as a social accountability layer.

**Audit checks:**
- [ ] Are slippage protections enforced on-chain (not just at the frontend)?
- [ ] Do AMM swaps specify `amountOutMinimum` / `sqrtPriceLimitX96`?
- [ ] Does the protocol assume any intra-block ordering guarantees?

#### 1.2.3 Preconfirmation Timing Attacks

ePBS enables "preconfirmations": a slot-N proposer can commit to including a TX in slot N
before the slot begins. Contracts that treat a preconfirmation as equivalent to finality
are vulnerable — the payload can still be withheld.

**Vulnerable pattern:**
```solidity
// Settles based on preconfirmation before payload is revealed
contract SettlementBridge {
    IPreconfBridge public immutable preconfBridge;

    function settleOnPreconf(bytes32 txHash) external {
        // VULNERABLE: preconf commitment != payload finality
        // Builder can still withhold the payload after committing
        require(preconfBridge.isPreconfirmed(txHash), "Not preconfirmed");
        _settle(txHash); // Premature: settlement before actual inclusion
    }
}
```

**Secure — wait for on-chain finalization:**
```solidity
contract SettlementBridge {
    uint256 public constant FINALIZATION_SLOTS = 2; // Slots after payload reveal

    mapping(bytes32 => uint256) public inclusionBlock;

    function recordInclusion(bytes32 txHash) external {
        require(inclusionBlock[txHash] == 0, "Already recorded");
        inclusionBlock[txHash] = block.number;
    }

    function settle(bytes32 txHash) external {
        uint256 included = inclusionBlock[txHash];
        require(included != 0, "Not yet included");
        require(
            block.number >= included + FINALIZATION_SLOTS,
            "Not finalized yet"
        );
        _settle(txHash);
    }
}
```

**Audit check:**
- [ ] Does the protocol interact with any preconfirmation bridge or service?
- [ ] Is there a mandatory delay between "preconfirmed" and "settled"?

### 1.3 Detection Patterns

```bash
# Tight block.number windows (single-slot tolerance)
grep -rn "block\.number.*+\s*1\b" src/ --include="*.sol"

# Preconfirmation-related patterns
grep -rn "preconf\|preConfirm\|isPreconfirmed" src/ --include="*.sol" -i

# Keeper/liquidation deadline patterns
grep -rn "MAX.*DELAY\|GRACE.*SLOT\|liquidat.*window\|deadline.*block" src/ --include="*.sol" -i
```

---

## 2. EIP-7928 — Block Access Lists (BALs)

### 2.1 What Are BALs

Block Access Lists allow each transaction to declare upfront which accounts and
storage slots it will read and write. Builders include this parallel array in the block.

```
BlockBody {
    transactions: [TX1, TX2, TX3, ...],
    accessLists: [             ← new: parallel per-TX declaration
        BAL_for_TX1,           // { accounts: [...], storageKeys: [...] }
        BAL_for_TX2,
        BAL_for_TX3,
        ...
    ]
}
```

Primary motivation: allow parallel execution of non-conflicting transactions.
Security side effect: MEV access patterns become fully transparent.

### 2.2 Security Implications

#### 2.2.1 MEV Access Pattern Transparency

BALs expose every transaction's state access pattern to builders and observers.
MEV bots that previously relied on opaque access patterns for their edge lose that advantage.

**New attack surface for protocols:**
- A frontrunner can see exactly which storage slots a pending DEX swap touches and
  construct a perfect sandwich without any simulation overhead
- Liquidation bots competing for the same position have full visibility into each
  other's target slots — first-mover advantage becomes entirely about gas priority

**Audit check:**
- [ ] Does the protocol rely on access-pattern opacity for any security property?
- [ ] Are MEV-sensitive operations (liquidations, arbitrage) using private mempools
  or commit-reveal to maintain ordering fairness?

#### 2.2.2 Underdeclared Access Sets

If a transaction touches slots not declared in its BAL, client behavior may vary:
- Builder-level rejection (transaction excluded from block)
- Execution proceeds but transaction is flagged invalid post-execution

Protocols that submit transactions programmatically must generate correct BALs:

```solidity
// On-chain contract is fine — BAL is generated by the transaction sender.
// Off-chain: keeper bots, relayers, and smart wallets that auto-generate transactions
// must correctly enumerate all storage slots they will touch, including:
//   - The contract's own storage
//   - ERC20 token balances for any token being moved
//   - Any oracle slot read during execution
```

**Audit check:**
- [ ] Do off-chain keepers, relayers, or bots correctly declare all accessed slots?
- [ ] Is there a fallback if BAL generation underestimates the access set?

#### 2.2.3 Parallelization Safety

BALs enable clients to execute non-conflicting transactions in parallel.
Contracts that make implicit assumptions about strict sequential ordering within a block
may break when TXes touching different slots execute concurrently.

**Vulnerable — non-atomic price + timestamp in separate slots:**
```solidity
contract SpotOracle {
    uint256 public price;      // Slot 0
    uint256 public lastUpdate; // Slot 1

    function update(uint256 newPrice) external onlyKeeper {
        price = newPrice;       // Write slot 0
        lastUpdate = block.timestamp; // Write slot 1
    }

    function getPrice() external view returns (uint256) {
        // If TX reading this executes concurrently with update():
        // it might read the new price but the old lastUpdate (or vice versa)
        require(block.timestamp - lastUpdate < MAX_STALENESS, "Stale");
        return price;
    }
}
```

**Secure — atomic packed storage:**
```solidity
contract SpotOracle {
    // Pack price + timestamp in one slot — single atomic read/write
    struct PriceData {
        uint128 price;
        uint32 timestamp;
        uint96 _reserved;
    }
    PriceData public priceData; // Slot 0 only — atomic update

    function update(uint128 newPrice) external onlyKeeper {
        priceData = PriceData({
            price: newPrice,
            timestamp: uint32(block.timestamp),
            _reserved: 0
        });
    }

    function getPrice() external view returns (uint128) {
        PriceData memory d = priceData; // Single slot read — atomic
        require(block.timestamp - d.timestamp < MAX_STALENESS, "Stale");
        return d.price;
    }
}
```

**Audit check:**
- [ ] Are price and timestamp/block values packed into a single storage slot?
- [ ] Does the contract assume atomic reads of multi-slot state?
- [ ] Are there multi-step state transitions that must be atomic across slots?

### 2.3 Detection Patterns

```bash
# Separate price and timestamp variables (parallelization atomicity risk)
grep -rn "lastUpdate\|lastPrice\|priceTimestamp\|updateTime" src/ --include="*.sol"

# tx.gasprice or block.basefee in business logic (may interact with BAL-based parallelism)
grep -rn "tx\.gasprice\|block\.basefee" src/ --include="*.sol"

# Manual access list construction (BAL generation in off-chain scripts)
grep -rn "accessList\|access_list\|storageKeys" . --include="*.ts" --include="*.js" -r
```

---

## 3. Audit Checklist Summary

### EIP-7732 (ePBS)
- [ ] Single-slot timing windows → add ≥ 2–3 slot buffer for withholding tolerance
- [ ] Preconfirmation settlement → require post-inclusion finalization delay
- [ ] On-chain slippage enforcement → `amountOutMinimum`, `sqrtPriceLimitX96`
- [ ] Keeper reward structure → accounts for missed slots

### EIP-7928 (BALs)
- [ ] Price + timestamp → packed into single storage slot (atomic)
- [ ] Multi-slot state transitions → reviewed for parallelization safety
- [ ] Off-chain TX generators → correctly enumerate accessed storage slots
- [ ] MEV-sensitive operations → private mempool or commit-reveal if ordering matters

---

## References

- `l2-crosschain.md` — L2 sequencer risks, cross-chain messaging patterns
- `industry-standards.md` — Full EIP timeline and Ethereum upgrade schedule
- `vulnerability-taxonomy.md §9` — Front-running, sandwich attacks, MEV patterns
- `defi-integrations.md` — Oracle and AMM integration security checklists
