# RWA Protocol Security Reference

Security framework for Real World Asset (RWA) tokenization protocols.
Covers Centrifuge, Maple Finance, Goldfinch, TrueFi, OpenTrade, tokenized T-bill
vaults (Ondo, Backed, Matrixdock), and general RWA protocol patterns.

See `defi-checklist.md §RWA` for the high-level checklist.
See `defi-integrations.md` for oracle/Chainlink integration patterns.
See `vulnerability-taxonomy.md §4` for oracle manipulation patterns.

---

## Architecture Patterns

| Pattern | Examples | Key Risk |
|---------|----------|----------|
| Pool-based lending to real borrowers | Centrifuge, Goldfinch, TrueFi | Off-chain default, NAV manipulation |
| Institutional credit vaults | Maple Finance, Clearpool | Pool delegate trust, credit assessment |
| Tokenized government securities | Ondo OUSG, Backed bIBTA, Matrixdock STBT | Redemption gating, oracle lag |
| Real estate tokenization | RealT, Lofty | Illiquid collateral, jurisdiction risk |
| Invoice/receivables financing | Centrifuge Tinlake | Borrower fraud, double-pledge |
| Tokenized fund shares | Franklin Templeton BENJI, BlackRock BUIDL | Transfer restrictions, NAV staleness |

**Core invariant**: The total value of on-chain tokens must never exceed the
verifiable value of the off-chain backing assets. This is unenforceable purely
on-chain — RWA protocols fundamentally depend on trusted intermediaries.

---

## 1. Trust Model & Architecture

### 1.1 Off-Chain Asset Custodian Trust

RWA protocols bridge on-chain code and off-chain legal reality. The smart contract
cannot seize physical collateral or enforce repayment. Security depends on:

- **Legal structure**: SPV (Special Purpose Vehicle) isolation, bankruptcy remoteness
- **Custody chain**: Who holds the underlying asset, and who can attest its value?
- **Admin privilege surface**: What can the pool manager do unilaterally?

**Vulnerable — pool manager with unrestricted powers:**
```solidity
contract RWAPool {
    address public poolManager;

    function updateNAV(uint256 newNAV) external {
        require(msg.sender == poolManager, "Not manager");
        // No timelock, no bounds check, no multi-sig
        totalNAV = newNAV;
    }

    function drawdown(uint256 amount) external {
        require(msg.sender == poolManager, "Not manager");
        // Manager can drain pool into any borrower address they control
        asset.transfer(msg.sender, amount);
    }
}
```

**Secure — bounded NAV with timelock and multi-sig:**
```solidity
contract RWAPool {
    uint256 public constant MAX_NAV_CHANGE_BPS = 500; // 5% max per update
    uint256 public constant NAV_TIMELOCK = 24 hours;
    uint256 public pendingNAV;
    uint256 public navUpdateTimestamp;

    function proposeNAV(uint256 newNAV) external onlyMultisig {
        uint256 maxDelta = totalNAV * MAX_NAV_CHANGE_BPS / 10_000;
        require(
            newNAV <= totalNAV + maxDelta && newNAV >= totalNAV - maxDelta,
            "NAV change exceeds bounds"
        );
        pendingNAV = newNAV;
        navUpdateTimestamp = block.timestamp;
        emit NAVProposed(newNAV, block.timestamp);
    }

    function executeNAV() external {
        require(block.timestamp >= navUpdateTimestamp + NAV_TIMELOCK, "Timelock");
        totalNAV = pendingNAV;
        emit NAVUpdated(pendingNAV);
    }
}
```

### 1.2 Pool Manager Privilege Escalation

**Audit checks:**
- [ ] What actions can the pool manager take without timelock?
- [ ] Can the pool manager add themselves as a borrower?
- [ ] Can the pool manager pause redemptions indefinitely?
- [ ] Is pool manager fee taken before or after investor returns?
- [ ] Is there a maximum drawdown per epoch to limit admin abuse?
- [ ] Can the pool manager whitelist/blacklist token holders unilaterally?
- [ ] Is there a governance mechanism to replace a malicious pool manager?
- [ ] Are critical admin functions behind a multi-sig or DAO vote?

---

## 2. NAV Oracle Manipulation

### 2.1 Stale NAV and Off-Chain Valuation

NAV (Net Asset Value) is the core pricing mechanism for RWA pools. Unlike on-chain
DeFi where prices come from AMMs or Chainlink, RWA NAV often depends on an admin
reporting off-chain asset values. This creates unique manipulation vectors.

**Vulnerable — NAV from single admin with no staleness check:**
```solidity
function getSharePrice() public view returns (uint256) {
    // NAV could be days old — admin hasn't updated after a default event
    return totalNAV * 1e18 / totalShares;
}
```

**Secure — NAV with staleness enforcement and circuit breaker:**
```solidity
uint256 public constant MAX_NAV_AGE = 24 hours;
uint256 public lastNAVUpdate;

function getSharePrice() public view returns (uint256) {
    require(block.timestamp - lastNAVUpdate <= MAX_NAV_AGE, "NAV stale");
    return totalNAV * 1e18 / totalShares;
}

// Emergency: if NAV is stale, block deposits and redemptions
modifier navFresh() {
    require(block.timestamp - lastNAVUpdate <= MAX_NAV_AGE, "NAV stale");
    _;
}

function deposit(uint256 assets) external navFresh returns (uint256 shares) {
    // ...
}
```

### 2.2 NAV Manipulation for Over-Borrowing

An attacker with pool manager access (or a compromised manager) can inflate NAV
to allow excessive borrowing against the pool:

1. Inflate NAV by reporting fake asset appreciation
2. Borrow against the inflated collateral value
3. Default on the loan — actual assets are worth less than borrowed amount

**Audit checks:**
- [ ] Is NAV update bounded (max % change per period)?
- [ ] Is there a cooldown between NAV update and borrowing/redemption?
- [ ] Can the NAV reporter manipulate NAV to enable over-borrowing?
- [ ] Is there an independent NAV verification mechanism (oracle, auditor attestation)?
- [ ] For liquid RWA (T-bills), is a Chainlink-style price feed used instead of admin pricing?
- [ ] Is the NAV heartbeat checked before processing deposits or redemptions?
- [ ] Can a stale NAV be used to redeem at a favorable price after a default?

### 2.3 T-Bill Vault Oracle Risks

Tokenized government securities (Ondo OUSG, Backed bIBTA) use hybrid pricing:
on-chain Chainlink feeds for liquid instruments, with admin fallback for illiquid ones.

**Audit checks:**
- [ ] If the Chainlink feed for the underlying T-bill goes stale, does the vault freeze or fall back to admin price?
- [ ] Can the admin fallback price diverge significantly from the Chainlink price?
- [ ] Is the conversion rate between the tokenized asset and the underlying updated atomically?
- [ ] Are there arbitrage windows between the on-chain price and the off-chain redemption price?

---

## 3. Epoch Redemption Race Conditions

### 3.1 Epoch-Based Redemption Architecture

Most RWA protocols use epoch-based redemptions because the underlying assets are
illiquid. Investors request redemptions during an epoch, and the pool manager
fulfills them at epoch close using available liquidity.

**Vulnerable — no lock-up, instant redemption request cancellation:**
```solidity
function requestRedeem(uint256 shares) external {
    redemptionRequests[msg.sender] += shares;
}

function cancelRedeem() external {
    // Attacker can front-run epoch close: request large redemption to
    // consume liquidity, then cancel just before execution
    redemptionRequests[msg.sender] = 0;
}
```

**Secure — minimum lock-up with cancellation deadline:**
```solidity
uint256 public constant MIN_LOCKUP = 1 days;
uint256 public constant CANCEL_DEADLINE_BEFORE_EPOCH = 4 hours;

function requestRedeem(uint256 shares) external {
    require(
        block.timestamp >= depositTimestamp[msg.sender] + MIN_LOCKUP,
        "Lock-up period"
    );
    redemptionRequests[msg.sender] = RedemptionRequest({
        shares: shares,
        requestedAt: block.timestamp
    });
}

function cancelRedeem() external {
    require(
        block.timestamp < epochEnd - CANCEL_DEADLINE_BEFORE_EPOCH,
        "Past cancellation deadline"
    );
    delete redemptionRequests[msg.sender];
}
```

### 3.2 Redemption Queue Manipulation

**Attack vectors:**
- **Priority queue gaming**: Whitelisted addresses (pool manager, early investors) get
  priority redemption, draining liquidity before retail investors.
- **Epoch timing manipulation**: If epoch length is admin-controlled, shortening an epoch
  can catch investors off-guard before they can submit redemption requests.
- **Rollover exploitation**: If unfulfilled redemptions roll over to the next epoch,
  an attacker can accumulate priority across epochs.

**Audit checks:**
- [ ] Are redemption requests accumulated per epoch and executed at epoch end?
- [ ] Can an attacker submit and cancel large redemptions to manipulate queue ordering?
- [ ] Is there a minimum lock-up period preventing same-block deposit-and-redeem?
- [ ] What happens to unfulfilled redemption requests — rollover or expiry?
- [ ] Can a whitelisted address drain the liquidity reserve before other redemptions?
- [ ] Can the pool manager change epoch length with pending redemption requests?
- [ ] Is there a pro-rata mechanism when liquidity is insufficient for all redemptions?
- [ ] Can redemption be front-run by observing the pool manager's liquidity provision tx?

---

## 4. Tranche Accounting Attacks

### 4.1 Senior/Junior Tranche Architecture

Many RWA protocols (Centrifuge Tinlake, Goldfinch) split capital into tranches:
junior absorbs losses first, senior gets priority returns. Miscounting tranche
sizes or loss absorption order is a critical vulnerability.

**Vulnerable — rounding error in tranche share calculation:**
```solidity
function calculateSeniorReturn(uint256 totalReturn) public view returns (uint256) {
    // Integer division truncation: if totalReturn = 99, seniorRatio = 80%,
    // seniorReturn = 79 (truncated), juniorReturn could be assigned 20
    // Total = 99 but assigned = 99 — but in edge cases, rounding error
    // compounds across epochs and creates phantom value
    uint256 seniorReturn = totalReturn * seniorRatio / 100;
    return seniorReturn;
}
```

**Secure — explicit rounding with remainder tracking:**
```solidity
function calculateSeniorReturn(uint256 totalReturn) public view returns (uint256) {
    uint256 seniorReturn = totalReturn * seniorRatio / PRECISION;
    // Junior gets the remainder — prevents phantom value creation
    uint256 juniorReturn = totalReturn - seniorReturn;
    // Track cumulative rounding errors
    cumulativeRoundingDelta += (totalReturn * seniorRatio) % PRECISION;
    return seniorReturn;
}
```

### 4.2 Bad Debt Allocation Manipulation

When a borrower defaults, losses must be allocated to tranches in the correct order.
A malicious pool manager can manipulate the timing and reporting of defaults to
shift losses between tranches.

**Attack scenario:**
1. Pool manager knows a default is imminent
2. Before reporting the default, they deposit into the junior tranche (buying cheap)
3. Report a partial default (smaller than actual)
4. Allow junior tranche to "recover" with new deposits
5. Report the remaining default later, socializing losses across more junior holders

**Audit checks:**
- [ ] Is the loss absorption order (junior → senior) enforced on-chain?
- [ ] Can the pool manager redirect losses away from junior tranche?
- [ ] Is there a minimum junior tranche ratio enforced to protect senior LPs?
- [ ] Can junior tranche be drained via strategic deposit/withdraw timing around defaults?
- [ ] If multiple tranches share a single ERC-4626 vault, is conversion rate per-tranche?
- [ ] Are write-downs applied atomically or can they be split to game timing?
- [ ] Is there a cooldown on junior tranche deposits after a default event?

---

## 5. KYC/Transfer Restriction Bypass

### 5.1 ERC-1400 / ERC-3643 Transfer Hook Bypass

RWA tokens must enforce transfer restrictions for regulatory compliance (KYC/AML).
The main token standards are ERC-1400 (Security Token Standard) and ERC-3643
(T-REX for regulated exchanges). Both rely on transfer hooks that can be bypassed.

**Vulnerable — transfer restriction only on `transfer()`, not `transferFrom()`:**
```solidity
function transfer(address to, uint256 amount) public override returns (bool) {
    require(whitelist[to], "Recipient not KYC'd");
    return super.transfer(to, amount);
}

// transferFrom() inherits from ERC20 — NO whitelist check!
// Attacker can approve a non-KYC'd address and use transferFrom() to bypass
```

**Secure — restriction on all transfer paths:**
```solidity
function _beforeTokenTransfer(
    address from,
    address to,
    uint256 amount
) internal override {
    // Skip check for minting (from == address(0)) and burning (to == address(0))
    if (from != address(0) && to != address(0)) {
        require(whitelist[to], "Recipient not KYC'd");
        require(!blocklist[from], "Sender blocked");
        require(!blocklist[to], "Recipient blocked");
    }
    super._beforeTokenTransfer(from, to, amount);
}
```

### 5.2 Whitelist Staleness and Off-Chain Sync

**Attack vectors:**
- **Stale whitelist**: User's KYC expires off-chain but on-chain whitelist isn't updated
- **DEX bypass**: RWA tokens listed on a DEX allow non-KYC'd addresses to buy via swap
- **Wrapper bypass**: Wrapping RWA tokens in an ERC-20 wrapper removes transfer restrictions
- **Approval drain**: Approved spender transfers to non-KYC'd address before whitelist revocation

**Audit checks:**
- [ ] Does the whitelist check apply to all transfer paths (`transfer`, `transferFrom`, hooks)?
- [ ] Can a non-KYC'd address receive tokens via a DEX swap or secondary market?
- [ ] Does the whitelist have an expiry mechanism synced with off-chain KYC status?
- [ ] If whitelist is managed off-chain, can a user remain whitelisted after KYC revocation?
- [ ] Are there jurisdiction-specific blocklists that could freeze any investor?
- [ ] Can tokens be wrapped in a standard ERC-20 to bypass transfer restrictions?
- [ ] Is there a forced transfer mechanism for regulatory seizure (ERC-3643 `forcedTransfer`)?
- [ ] Can the compliance agent freeze/unfreeze accounts, and is this behind a timelock?

---

## 6. Default Handling

### 6.1 Late Repayment and Grace Period Abuse

RWA loans have grace periods before a default is declared. Sophisticated borrowers
can exploit timing windows around grace periods and NAV update cycles.

**Vulnerable — grace period allows strategic withdrawal timing:**
```solidity
uint256 public constant GRACE_PERIOD = 7 days;

function isDefaulted(uint256 loanId) public view returns (bool) {
    Loan storage loan = loans[loanId];
    // Attacker (borrower) can time their actions:
    // 1. Miss payment deadline
    // 2. During grace period, NAV still reflects full loan value
    // 3. Accomplice redeems at full NAV before default declaration
    return block.timestamp > loan.dueDate + GRACE_PERIOD && !loan.repaid;
}
```

**Secure — NAV adjustment on payment miss, not just on default declaration:**
```solidity
function isOverdue(uint256 loanId) public view returns (bool) {
    return block.timestamp > loans[loanId].dueDate && !loans[loanId].repaid;
}

function getNAVAdjustedForOverdue() public view returns (uint256) {
    uint256 nav = baseNAV;
    for (uint256 i = 0; i < activeLoans.length; i++) {
        if (isOverdue(activeLoans[i])) {
            // Haircut overdue loans immediately — don't wait for default declaration
            uint256 daysOverdue = (block.timestamp - loans[activeLoans[i]].dueDate) / 1 days;
            uint256 haircut = Math.min(daysOverdue * DAILY_HAIRCUT_BPS, 10_000);
            nav -= loans[activeLoans[i]].principal * haircut / 10_000;
        }
    }
    return nav;
}
```

### 6.2 Write-Down Timing Manipulation

**Attack vectors:**
- **Delayed write-down**: Pool manager delays reporting a default to allow insiders to redeem
- **Premature recovery**: Marking a defaulted loan as "recovered" without actual repayment
- **Partial default gaming**: Splitting a full default into multiple partial write-downs
  to avoid triggering circuit breakers

**Audit checks:**
- [ ] What on-chain mechanism exists to handle borrower default?
- [ ] Can a defaulted loan be marked as recovered without actual repayment?
- [ ] Is there a grace period that a borrower can exploit to time withdrawals before default?
- [ ] Are write-downs applied automatically based on overdue status or manually by admin?
- [ ] Is there a minimum write-down per overdue day to prevent delayed recognition?
- [ ] Can the pool manager selectively write down some loans while hiding others?
- [ ] Is there a third-party auditor or oracle that can independently trigger write-downs?

---

## 7. Protocol-Specific Patterns

### 7.1 Centrifuge / Tinlake Architecture

Centrifuge uses an epoch-based system with senior/junior tranches (DROP/TIN tokens).
The NAV is computed off-chain and submitted by an oracle.

**Key risks:**
- **Coordinator manipulation**: The epoch coordinator determines redemption execution order
- **NAV oracle trust**: A single oracle submits the NAV; no on-chain verification
- **Epoch execution front-running**: MEV bots can observe the oracle submission and
  trade just before epoch execution

**Audit checks (Centrifuge-specific):**
- [ ] Is the NAV oracle submission permissioned and behind a timelock?
- [ ] Can the coordinator manipulate execution order within an epoch?
- [ ] Is there a maximum NAV change between consecutive epochs?
- [ ] Are DROP/TIN conversion rates correctly adjusted after write-downs?

### 7.2 Maple Finance Architecture

Maple uses pool delegates who assess borrower credit and manage pools. Lenders
deposit into pools and earn yield from borrower interest payments.

**Key risks:**
- **Pool delegate collusion**: Delegate approves a loan to an entity they control
- **Cover asset manipulation**: The first-loss cover (pool delegate's stake) may be
  insufficient to absorb actual defaults
- **Withdrawal manager gaming**: Maple V2 uses a withdrawal manager with configurable
  windows that can be manipulated

**Audit checks (Maple-specific):**
- [ ] Is the pool delegate's cover stake sufficient relative to total pool assets?
- [ ] Can the pool delegate approve loans to addresses they control?
- [ ] Is there a minimum cover ratio enforced on-chain?
- [ ] Can withdrawal windows be changed by the pool delegate with pending requests?

### 7.3 Tokenized T-Bill Vaults (Ondo, Backed, Matrixdock)

These protocols tokenize short-term government securities. They typically have
a minting/redeeming mechanism through a centralized intermediary.

**Key risks:**
- **Redemption gating**: The issuer can pause redemptions, trapping user funds
- **Rebasing vs non-rebasing**: Rebasing tokens (OUSG) have different composability
  risks than non-rebasing (USDY uses exchange rate)
- **Instant mint arbitrage**: If the mint price uses a stale NAV, arbitrageurs can
  mint cheap after a rate hike announcement

**Audit checks (T-bill vault-specific):**
- [ ] Can the issuer pause minting/redeeming unilaterally?
- [ ] Is there an arbitrage window between announced yield changes and NAV updates?
- [ ] For rebasing tokens, is the rebase correctly handled by all integrated DeFi protocols?
- [ ] Is the minimum investment/redemption amount used to prevent dust attacks?
- [ ] Are accrued yields correctly distributed during transfer (no yield loss on transfer)?

---

## 8. RWA Audit Checklist

Comprehensive checklist for auditing RWA protocols. Items are grouped by audit phase.

### Trust Model Assessment

- [ ] Identify all privileged roles and their on-chain powers
- [ ] Map the trust chain: code → admin → custodian → legal entity → physical asset
- [ ] Review SPV/legal structure for bankruptcy remoteness
- [ ] Verify multi-sig or DAO governance for critical admin functions
- [ ] Check for emergency pause mechanisms and their scope
- [ ] Assess pool manager replacement/removal process

### NAV and Pricing

- [ ] Verify NAV update mechanism (admin, oracle, hybrid)
- [ ] Check NAV staleness protections (maximum age, circuit breakers)
- [ ] Verify NAV change bounds (max % per update)
- [ ] Check for cooldown between NAV update and deposit/redeem execution
- [ ] Verify share price calculation (totalNAV / totalShares) for precision
- [ ] For liquid RWA: verify Chainlink feed integration with staleness/deviation checks
- [ ] For illiquid RWA: verify admin price has timelock and multi-sig

### Tranche Mechanics

- [ ] Verify loss absorption order is enforced on-chain (junior first)
- [ ] Check rounding behavior in tranche return calculations
- [ ] Verify minimum junior tranche ratio enforcement
- [ ] Check for write-down timing manipulation vectors
- [ ] Verify tranche token conversion rates update correctly after defaults
- [ ] Check deposit/withdraw restrictions around default events

### Redemption Flow

- [ ] Verify epoch-based redemption with proper queue mechanics
- [ ] Check for same-block deposit-and-redeem prevention (minimum lock-up)
- [ ] Verify pro-rata redemption when liquidity is insufficient
- [ ] Check cancellation deadline enforcement
- [ ] Verify unfulfilled request handling (rollover vs expiry)
- [ ] Check for front-running vectors around epoch transitions

### Transfer Restrictions and Compliance

- [ ] Verify whitelist/blacklist checks on all transfer paths
- [ ] Check for DEX bypass or wrapper bypass vectors
- [ ] Verify KYC expiry synchronization mechanism
- [ ] Check forced transfer mechanism for regulatory compliance
- [ ] Verify ERC-1400 or ERC-3643 implementation correctness
- [ ] Check that approve + transferFrom path is also restricted

### Default and Recovery

- [ ] Verify on-chain default detection mechanism
- [ ] Check NAV adjustment on payment overdue (not just on default declaration)
- [ ] Verify write-down is automatic or has admin timelock
- [ ] Check for delayed write-down or premature recovery vectors
- [ ] Verify grace period cannot be exploited for strategic redemptions
- [ ] Check insurance/cover fund adequacy and disbursement logic

### Integration and Composability

- [ ] If tokens are used as DeFi collateral, verify liquidation handles transfer restrictions
- [ ] Check rebasing token behavior in AMMs, lending protocols, and vaults
- [ ] Verify that pausing the RWA token doesn't brick integrated DeFi positions
- [ ] Check that yield accrual works correctly across token transfers
- [ ] Verify cross-chain bridge compatibility with transfer restrictions
