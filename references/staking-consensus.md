# Staking & Consensus Layer Security

Security reference for protocols interacting with Ethereum's consensus layer:
liquid staking (Lido, Rocket Pool), restaking (EigenLayer, Karak, Symbiotic),
and any contract that manages validators, withdrawal credentials, or beacon deposits.

Focuses on the **Pectra upgrade** (May 2025) EIPs that introduce new attack surfaces:
EIP-7002 (triggerable exits), EIP-7251 (MaxEB), EIP-6110 (on-chain deposits).

See `defi-checklist.md §Restaking & LRT` for EigenLayer/AVS checklists.
See `account-abstraction.md` for EIP-7702 staking wallet interactions.

---

## Pectra Upgrade Overview (May 2025)

| EIP | Change | Primary Security Impact |
|-----|--------|------------------------|
| EIP-7002 | Withdrawal credentials can trigger validator exits from EL | New forced-exit attack surface |
| EIP-7251 | MAX_EFFECTIVE_BALANCE raised 32→2048 ETH | Slashing amplified up to 64x |
| EIP-6110 | Validator deposits supplied on-chain (no ETH1 log delay) | Deposit front-running, flow changes |
| EIP-7702 | EOA code delegation | Staking wallets can be compromised via malicious delegation |

---

## 1. EIP-7002 — Execution Layer Triggerable Exits

**Before Pectra**: Only the validator's signing key (BLS key) could initiate an exit.
Withdrawal credentials (smart contracts) could NOT trigger exits.

**After Pectra**: A new precompile at `0x00000961` (`WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS`)
allows the contract at the withdrawal credential address to submit an exit request.

### 1.1 Architecture

```
Withdrawal Credential (smart contract)
      │
      │ calls WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS
      │ with (validator_pubkey, amount)
      │
      ▼
Beacon chain processes exit after sweep delay (~27 hours)
```

```solidity
// The withdrawal request predeploy interface (EIP-7002)
address constant WITHDRAWAL_REQUEST_CONTRACT = 0x00000961Cf7Be79e855cc5E0cD2d36B7a5751E2B;

function triggerValidatorExit(bytes calldata validatorPubkey) external payable {
    // Fee required: dynamic, starts at 1 wei and increases with demand
    uint256 fee = WITHDRAWAL_REQUEST_CONTRACT.call{value: msg.value}(
        abi.encodePacked(validatorPubkey, uint64(0)) // amount=0 means full exit
    );
}
```

### 1.2 Attack Vectors

#### 1.2.1 Withdrawal Credential Key Compromise → Mass Forced Exit

If the withdrawal credential private key (for EOA credentials) or a bug in the
withdrawal contract is exploited, an attacker can force-exit all validators at once.

**Impact:**
- For Lido/Rocket Pool scale: could force-exit thousands of validators simultaneously
- Mass exits cause queue congestion — validators wait days to exit during high demand
- Protocol loses staking yield during the exit queue period
- If attacker times with slashing, amplified losses

**Audit check for liquid staking protocols:**
```solidity
// Who can call triggerExit?
function requestValidatorExit(bytes calldata pubkey) external {
    // VULN: Missing access control — any caller can trigger exit
    _submitExitRequest(pubkey);

    // SECURE: Only protocol multisig/guardian with timelock
    require(hasRole(EXIT_MANAGER_ROLE, msg.sender), "Not exit manager");
    require(!emergencyPaused, "Paused");
    _submitExitRequest(pubkey);
}
```

#### 1.2.2 Partial Withdrawal Griefing (amount != 0)

EIP-7002 also supports partial withdrawals (setting amount to a specific value).
An attacker with withdrawal credential control can drain validators to exactly
32 ETH (keeping them active but extracting all excess balance).

```solidity
// VULN: No minimum balance protection
function partialWithdraw(bytes calldata pubkey, uint64 amount) external onlyOperator {
    _submitWithdrawalRequest(pubkey, amount);
    // Missing: Check that remaining balance stays above operational minimum
}

// SECURE: Enforce minimum post-withdrawal balance
function partialWithdraw(bytes calldata pubkey, uint64 amount) external onlyOperator {
    uint64 currentBalance = _getValidatorBalance(pubkey);
    require(currentBalance - amount >= MIN_VALIDATOR_BALANCE, "Below minimum");
    _submitWithdrawalRequest(pubkey, amount);
}
```

#### 1.2.3 Exit Queue Manipulation / DoS

An attacker can flood the exit queue with cheap requests to delay legitimate exits.
The fee mechanism (EIP-7002) starts at 1 wei and doubles per additional request per block.

```solidity
// AUDIT: Check that exit requests are rate-limited
// An unbounded loop of exit triggers can drain protocol ETH on fees
function massExit(bytes[] calldata pubkeys) external onlyOwner {
    for (uint256 i = 0; i < pubkeys.length; i++) {
        // Fee grows exponentially — 10 exits in one block costs ~1023 wei
        // But 1000 exits across blocks still creates exit queue backlog
        _submitExitRequest(pubkeys[i]);
    }
    // Missing: daily exit limit to prevent queue congestion
}
```

### 1.3 EIP-7002 Checklist

- [ ] Is `triggerValidatorExit()` behind strict role-based access control?
- [ ] Is there a timelock or multi-sig requirement before triggering exits?
- [ ] Is there a daily/per-epoch exit rate limit to prevent mass exits?
- [ ] Are partial withdrawal amounts validated against minimum balance thresholds?
- [ ] Does the protocol handle the ~27-hour exit delay in its accounting?
- [ ] Can an attacker drain protocol ETH via repeated fee-paying exit requests?
- [ ] Is there emergency pause functionality that blocks exit requests?
- [ ] Does the protocol detect and handle situations where the exit queue is congested?

---

## 2. EIP-7251 — Increase MAX_EFFECTIVE_BALANCE

**Before Pectra**: Every validator's MAX_EFFECTIVE_BALANCE = 32 ETH. Excess balance
auto-withdrawn. Consolidation required multiple 32 ETH validators.

**After Pectra**: MAX_EFFECTIVE_BALANCE up to 2048 ETH. A single validator can hold
64× more stake. Consolidation mechanism merges multiple validators into one.

### 2.1 Slashing Amplification

Slashing penalties scale with effective balance. Under EIP-7251, slashing a single
consolidated validator holding 2048 ETH incurs 64× the penalties vs pre-Pectra.

| Scenario | Pre-Pectra | Post-Pectra (MaxEB) |
|----------|-----------|---------------------|
| Single validator slashed | Max 1 ETH initial + corr. | Up to 64 ETH initial + corr. |
| Correlation penalty (1% slashed) | ~0.32 ETH | ~20.48 ETH |
| Inactivity leak (worst case) | ~32 ETH per validator | ~2048 ETH per consolidated |

**Audit check for restaking/LST protocols:**
```solidity
// Does the protocol account for amplified slashing in its insurance fund sizing?
function getSlashingCoverage() external view returns (uint256) {
    uint256 maxValidatorBalance = _getMaxEffectiveBalance(); // Could be 2048 ETH now
    // Pre-Pectra: coverage might be sized for 32 ETH max loss
    // Post-Pectra: must cover 2048 ETH max loss per validator
    return insuranceFund / maxValidatorBalance; // Coverage ratio must be rechecked
}
```

### 2.2 Consolidation Race Conditions

The consolidation mechanism allows a `source` validator to merge into a `target` validator.
Both must share the same withdrawal credentials. The request is submitted via a new precompile.

```
source_validator (32 ETH) → merge into → target_validator (accumulates up to 2048 ETH)
```

**Attack: Consolidation front-running**

```solidity
// Consolidation is a two-signature operation (source + target BLS keys)
// If an attacker observes a pending consolidation in the mempool/beacon pool,
// they can front-run by submitting their own consolidation request for the target validator

// SECURE: Use off-chain coordination or commit-reveal for consolidation
function requestConsolidation(
    bytes calldata sourcePubkey,
    bytes calldata targetPubkey,
    bytes calldata sourceSignature,
    bytes calldata targetSignature
) external onlyOperator {
    // Verify both signatures before submitting
    _verifyBLSSignature(sourcePubkey, sourceSignature);
    _verifyBLSSignature(targetPubkey, targetSignature);
    // Submit to precompile atomically with signature proof
    _submitConsolidation(sourcePubkey, targetPubkey);
}
```

**Attack: Consolidation griefing**

A validator operator who loses their source BLS key after initiating consolidation
cannot cancel — the consolidation proceeds or the source balance is stuck.

### 2.3 Governance Centralization

Fewer validators with higher stakes reduces the validator set size, potentially:
- Increasing MEV capture concentration
- Making censorship easier (fewer nodes to bribe/compromise)
- Increasing slashing correlation risk (if consolidated validators share infrastructure)

**Audit check:**
- Does the protocol set a maximum effective balance limit below 2048 ETH?
- Is there a cap on how many validators a single operator can consolidate?

### 2.4 EIP-7251 Checklist

- [ ] Has the protocol recalculated slashing insurance/coverage for 2048 ETH max loss?
- [ ] Is consolidation restricted to authorized operators with rate limiting?
- [ ] Are BLS signatures verified on-chain before submitting consolidation requests?
- [ ] Does the protocol track which validators have been consolidated?
- [ ] Is there a maximum balance cap to limit consolidation (risk management)?
- [ ] Does the accounting system handle auto-compounding rewards for MaxEB validators?
- [ ] Are withdrawal amounts recalculated for validators with >32 ETH effective balance?
- [ ] Does the protocol detect and handle the sweep delay for large balance withdrawals?

---

## 3. EIP-6110 — Supply Validator Deposits On-Chain

**Before Pectra**: Deposits processed by Eth1 deposit contract, with ~13 hour delay
before the beacon chain recognized them (ETH1 follow distance).

**After Pectra**: Deposits are included in the beacon block directly from the execution
layer. The delay shrinks from ~13 hours to ~10 minutes (single epoch).

### 3.1 Deposit Front-Running

With near-instant deposit recognition, the window between deposit submission and validator
activation shrinks. However, the deposit pubkey and withdrawal credentials are still
visible in the mempool before inclusion.

**Attack: Credential hijacking on deposit**

```solidity
// Attacker sees pending deposit tx in mempool with validator pubkey
// If the protocol's contract doesn't bind pubkey → withdrawal_credential atomically,
// attacker front-runs with same pubkey but their withdrawal credentials

// VULN: Two-step deposit where pubkey and credentials are submitted separately
function registerPubkey(bytes calldata pubkey) external {
    pendingPubkeys[msg.sender] = pubkey; // Step 1
}

function submitDeposit(bytes calldata pubkey) external payable {
    // Step 2: attacker frontruns here with their own withdrawal_credential
    _submitBeaconDeposit(pubkey, withdrawalCredentials[msg.sender]); // Checks msg.sender
}

// SECURE: Atomic single-tx deposit with pre-committed credentials
function deposit(
    bytes calldata pubkey,
    bytes calldata withdrawalCredential,
    bytes calldata signature,
    bytes32 depositDataRoot
) external payable {
    require(msg.value == 32 ether, "Wrong deposit amount");
    // BLS signature covers (pubkey, withdrawalCredential, amount) — atomic
    BEACON_DEPOSIT_CONTRACT.deposit{value: msg.value}(
        pubkey, withdrawalCredential, signature, depositDataRoot
    );
}
```

### 3.2 Deposit Queue Ordering

Post-EIP-6110, multiple deposits in the same block are included in block order.
Protocols that rely on sequential deposit processing must handle same-block deposits
being activated in potentially different validator index order.

```solidity
// AUDIT: Does the protocol assume a specific validator index after deposit?
// Validator indices are assigned by the beacon chain, not the protocol
mapping(bytes => uint64) public validatorIndices; // pubkey => index

function onValidatorActivated(bytes calldata pubkey, uint64 index) external onlyOracle {
    // VULN: Race between multiple same-block deposits
    // The index assigned may differ from the protocol's expected order
    require(pendingDeposits[pubkey], "Not registered");
    validatorIndices[pubkey] = index;
}
```

### 3.3 EIP-6110 Checklist

- [ ] Are deposits atomic (pubkey + withdrawal_credential in single tx)?
- [ ] Does the protocol avoid assuming specific validator index ordering?
- [ ] Are same-block multiple deposits handled correctly?
- [ ] Does the accounting system reflect the shortened activation delay (~10 min)?
- [ ] Is the deposit data root verified before submission to prevent malformed deposits?
- [ ] Does the protocol handle failed deposits (e.g., duplicate pubkey) with refund logic?

---

## 4. Combined Pectra Attack Scenarios

### 4.1 Exit + Slash Coordination Attack

1. Attacker stakes large amount via target LST protocol
2. Waits for validators to consolidate under EIP-7251 to 2048 ETH each
3. Compromises withdrawal credential (EIP-7002 surface) OR triggers voluntary exit
4. During exit queue congestion, initiates slashable offense (equivocation)
5. Slashing penalty is amplified (64× vs pre-Pectra)
6. LST token price crashes during exit delay + slashing period

**Mitigation for protocols:**
- Cap individual validator effective balance below protocol-defined threshold
- Implement exit rate limiting (EIP-7002 guard)
- Maintain overcollateralized insurance fund sized for MaxEB slashing

### 4.2 LST Share Price Manipulation via Forced Exit

```
Attacker holds large LST position (short via derivatives)
      │
      ├─ Triggers mass forced exits on validators (EIP-7002)
      ├─ Exit queue congestion → protocol yield drops
      ├─ LST share price temporarily drops below peg
      └─ Attacker profits on short position, buys back LST cheaply
```

**Mitigation:** Emergency pause on exit triggers, exit rate limiting, circuit breaker.

---

## 5. Post-Pectra Observations (May 2025 – present)

This section documents real-world outcomes from the first ~12 months after Pectra
activation (May 2025). It refines the theoretical attack scenarios in sections 1–4
with observed protocol behavior, incidents, and validator data.

> **Epistemic note**: Information below reflects publicly disclosed protocol decisions
> and on-chain data as of mid-2026. Where specifics are uncertain, this is flagged
> explicitly. Auditors should verify current state against protocol governance forums
> and on-chain data before relying on any claim.

### 5.1 LST/LRT Protocol Adaptation

#### Lido

Lido was the most publicly transparent about its Pectra response. Key observations:

- **EIP-7251 consolidation**: Lido governance discussed enabling MaxEB validators
  in a phased rollout. The Community Staking Module (CSM) and simple-DVT subsets
  were candidates for early consolidation pilots. As of mid-2026, Lido had not
  consolidated all validators to maximum effective balance — the approach was
  conservative, with governance votes gating each phase.
- **EIP-7002 integration**: Lido's withdrawal credential architecture required
  updates to support execution-layer triggerable exits. The V2 staking router
  added access-controlled exit request functions gated by the protocol's
  existing guardian multisig.
- **Audit takeaway**: Protocols with large validator sets adopted phased
  consolidation rather than immediate MaxEB migration. Auditors should check
  whether a protocol's consolidation governance path includes rollback
  mechanisms if slashing amplification risk exceeds insurance coverage.

#### Rocket Pool

- Rocket Pool's minipool architecture (node operators staking alongside protocol
  ETH) created unique challenges for EIP-7251 consolidation, since minipools
  are designed around 8/16 ETH operator bonds paired with protocol ETH to
  reach 32 ETH.
- As of mid-2026, no public disclosure confirmed that Rocket Pool had enabled
  consolidation beyond 32 ETH per minipool. The minipool bond structure may
  require significant redesign to support MaxEB validators.
- **Audit takeaway**: Protocols with per-validator bond/collateral splits
  (operator + protocol ETH) face structural barriers to consolidation. Auditors
  should verify whether consolidation accounting correctly attributes excess
  balance above 32 ETH between operator and protocol shares.

#### LRT Protocols (EtherFi, Renzo, Kelp, Puffer)

- LRT protocols (liquid restaking tokens) generally deferred EIP-7251
  consolidation decisions to their underlying LST providers or node operators.
- No public evidence as of mid-2026 indicates that LRT protocols independently
  consolidated validators to >32 ETH effective balance.
- EIP-7002 (triggerable exits) was more immediately relevant to LRT protocols,
  as it provides an execution-layer mechanism for honoring withdrawal requests
  without relying solely on operator cooperation.
- **Audit takeaway**: LRT protocols wrapping LSTs inherit the consolidation
  posture of their underlying LST. Auditors should trace the consolidation
  path through the full stack (LRT → LST → node operator → beacon chain).

#### EigenLayer

- EigenLayer's slashing mechanism (AVS-level slashing) operates independently
  from beacon chain slashing. The interaction between EIP-7002 triggerable
  exits and EigenLayer's withdrawal flow was an area of active development.
- As of mid-2026, no publicly confirmed incident demonstrated a conflict between
  Pectra-level slashing and AVS-level slashing on the same validator.
- **Audit takeaway**: The dual-slashing surface (beacon chain + AVS) on a
  consolidated MaxEB validator remains the highest-risk untested scenario in
  the restaking stack. Auditors should verify that protocols account for the
  possibility of simultaneous beacon slashing and AVS slashing on a single
  validator with >32 ETH effective balance (see §4.1 for theoretical model).

### 5.2 Observed Incidents & Near-Misses

**No large public exploit leveraged Pectra primitives (EIP-7002, EIP-7251,
EIP-6110) in the first 12 months post-activation as of mid-2026.**

This is itself a useful audit data point — it suggests that:

1. The theoretical attack vectors in sections 1–4 remain theoretical, not
   because they are impossible, but because the prerequisites (withdrawal
   credential compromise at scale, coordinated consolidation + slashing)
   have high execution barriers.
2. Protocols adopted conservative rollout strategies (phased consolidation,
   access-controlled exit triggers) that reduced the immediate attack surface.
3. The exit queue fee mechanism (EIP-7002) and exponential fee scaling
   provided effective economic deterrence against exit queue flooding.

**Known near-misses and disclosures:**

- **Withdrawal credential migration**: Multiple protocols underwent
  0x01 → 0x02 credential prefix migrations. No public exploit was reported,
  but audit reports from multiple firms flagged hardcoded `0x01` prefix
  checks that would reject valid 0x02 credentials post-Pectra. This was
  a configuration-level issue rather than a smart contract vulnerability.
- **EIP-7702 delegation attacks**: While not directly a staking primitive,
  EIP-7702 (activated alongside Pectra) enabled sweeper campaigns targeting
  EOAs that had signed malicious delegation tuples. Significant losses were
  reported in the weeks following Pectra activation (see
  `vulnerability-taxonomy.md §17.6` for the attack pattern; specific loss
  figures are still being totaled across the various sweeper campaigns).
  This is relevant to staking because validator withdrawal credentials set
  to EOAs could be compromised via EIP-7702 delegation.
- **Bug bounty disclosures**: No Immunefi, Cantina, or Sherlock disclosure
  as of mid-2026 specifically cited EIP-7002 or EIP-7251 as the root cause
  of a critical finding. Several medium-severity findings related to
  hardcoded 32 ETH constants were disclosed across multiple protocols
  (see §5.4 for the resulting audit heuristics).

### 5.3 Exit Queue & Validator Behavior Data

#### Exit Queue Dynamics

- The exit queue did not experience sustained congestion in the first 12 months
  post-Pectra. The feared mass-exit scenario (§4.2) did not materialize.
- Exit queue depths remained manageable, with no publicly reported period where
  exit wait times exceeded several days. The exponential fee mechanism in
  EIP-7002 appears to have discouraged frivolous exit requests.
- **Audit takeaway**: While exit queue flooding remains a theoretical vector,
  auditors can reduce the severity classification for exit-queue-only attacks
  (without accompanying slashing) from High to Medium, given observed
  resilience. The economic cost of flooding via EIP-7002 fees is non-trivial.

#### Validator Consolidation Rate

- Consolidation adoption was gradual. As of mid-2026, the majority of
  validators on the beacon chain still operated at 32 ETH effective balance.
  Large operators (institutional staking providers) were the earliest
  consolidation adopters, reducing operational overhead by managing fewer
  validators with higher individual stakes.
- Solo stakers had minimal incentive to consolidate (most operate single
  validators). The validator set size reduction predicted by MaxEB critics
  was slower than expected.
- **Audit takeaway**: Protocols should not assume that all validators in
  their set have consolidated. Accounting logic must handle mixed validator
  sets (some at 32 ETH, some at 64–2048 ETH) simultaneously.

#### Deposit Activation Time (EIP-6110)

- EIP-6110 reduced deposit-to-activation from ~12-13 hours to approximately
  one epoch (~6.4 minutes) for deposits included in beacon blocks.
- No public reports confirmed deposit front-running exploits leveraging the
  shortened window. The atomic deposit mechanism (pubkey + credentials in
  a single transaction) adopted by major protocols eliminated the primary
  front-running vector described in §3.1.
- **Audit takeaway**: The reduced activation window is a UX improvement
  but does not introduce new attack surface when deposits are atomic.
  Protocols still using two-step deposit flows should be flagged as
  critical — the compressed window makes front-running even more feasible.

### 5.4 Protocol Audit Heuristics Refined Post-Pectra

The following checklist items emerged from real audit findings and protocol
migrations in the 12 months after Pectra activation. These supplement the
theoretical checklist in §6.

- [ ] **Hardcoded `MAX_EFFECTIVE_BALANCE = 32 ether`**: Multiple protocols had
  constants or require statements assuming 32 ETH maximum. Post-Pectra, these
  silently reject valid consolidated validators or miscompute shares. Search
  for `32 ether`, `32e18`, `32_000_000_000` (Gwei) in all staking-related contracts.
- [ ] **Withdrawal credential prefix**: Protocol must accept both `0x01` (BLS)
  and `0x02` (execution address) prefixes. Hardcoded `bytes1(0x01)` checks
  will reject post-Pectra credentials.
- [ ] **Validator index cache invalidation**: When two validators consolidate,
  the source validator is exited and its index becomes inactive. Any
  `pubkey → validatorIndex` mapping must handle index invalidation.
- [ ] **Slashing penalty constants**: Pre-Pectra `MIN_SLASHING_PENALTY_QUOTIENT`
  (4096 on mainnet) still applies, but the base penalty scales with effective
  balance. Insurance calculations using `32 ETH / 4096` underestimate risk
  for consolidated validators.
- [ ] **Off-chain tooling balance ceiling**: Operator dashboards, accounting
  systems, and oracle reporters that cap balance at 32 ETH will misreport
  for consolidated validators. Verify that all off-chain components accept
  balances up to 2048 ETH.
- [ ] **Partial vs full exit accounting**: EIP-7002 enables partial withdrawals
  (specific amount) and full exits (amount = 0). Protocol withdrawal queues
  must distinguish between these and update internal accounting accordingly.
- [ ] **Insurance fund sizing**: Coverage calculations must use the actual
  maximum effective balance in the protocol's validator set, not the legacy
  32 ETH assumption. A single consolidated 2048 ETH validator slashing event
  can exhaust funds sized for 32 ETH max.
- [ ] **Governance coordination**: MaxEB consolidation is an irreversible
  operation at the beacon chain level. Governance multisigs authorizing
  consolidation should require timelock + documentation of insurance
  coverage adjustment.
- [ ] **EIP-7002 operator tooling**: Node operators need execution-layer
  tooling to submit exit requests. Verify that operator dashboards and
  key management systems support the EIP-7002 precompile interface.
- [ ] **Dual-slashing surface for restaked validators**: If the protocol
  wraps restaked ETH (EigenLayer/Symbiotic), verify that the insurance
  model accounts for simultaneous beacon chain slashing + AVS slashing
  on a consolidated validator.

### 5.5 Open Questions / Active Risk Areas

The following areas remain actively uncertain as of mid-2026. Audit attention
should remain elevated on these topics.

1. **Asymmetric consolidation centralization**: Large operators consolidate
   faster than solo stakers, creating an economic centralization gradient.
   The long-tail effects on validator set diversity, MEV capture distribution,
   and censorship resistance are still developing. No equilibrium has been
   reached.

2. **Dual-slashing coordination (EigenLayer + Pectra)**: AVS slashing and
   beacon chain slashing on the same consolidated validator have not been
   stress-tested at scale. The interaction between EigenLayer's slashing
   veto committee and beacon chain's automatic correlation penalties on
   MaxEB validators remains an open design space.

3. **Exit queue under extreme market stress**: The exit queue has not been
   tested under a severe market downturn combined with a large LST de-peg
   event. The theoretical attack in §4.2 (forced exit + short position)
   remains viable but unobserved.

4. **Withdrawal credential upgrade path**: The 0x01 → 0x02 migration is
   one-way. Validators that have not migrated may face future protocol
   compatibility issues. The timeline for deprecating 0x01 credentials
   is not yet defined by the Ethereum protocol.

5. **Consolidation reversibility**: Once validators consolidate, splitting
   back to multiple 32 ETH validators requires a full exit and re-deposit
   cycle. Protocols that consolidate aggressively may face liquidity
   constraints if they need to un-consolidate during high exit queue periods.

6. **MaxEB validator liveness penalties**: Inactivity leak penalties on a
   2048 ETH validator are 64x more severe than on a 32 ETH validator.
   Extended downtime (>4 epochs of missed attestations) on consolidated
   validators has not been widely observed, and the economic impact on
   LST share prices is untested.

7. **Cross-protocol consolidation coordination**: Multiple LST/LRT protocols
   may share the same node operators. Consolidation decisions by one protocol
   can affect exit queue dynamics for others sharing the same operator
   infrastructure.

---

## 6. Staking Protocol Audit Checklist (Post-Pectra)

### Access Control
- [ ] Is `triggerValidatorExit()` (EIP-7002) gated by multisig + timelock?
- [ ] Is consolidation (EIP-7251) restricted to authorized operators?
- [ ] Are deposit submission functions protected against pubkey hijacking?

### Economic Security
- [ ] Is the insurance/slashing coverage fund recalculated for 2048 ETH max effective balance?
- [ ] Is there a daily exit rate limit to prevent exit queue congestion attacks?
- [ ] Is there a maximum per-operator validator consolidation cap?

### Accounting
- [ ] Does the protocol handle auto-compounding for MaxEB validators (> 32 ETH balance)?
- [ ] Does the share price calculation account for the shorter deposit activation delay?
- [ ] Is withdrawal accounting correct for partial withdrawals via EIP-7002?

### Oracle & Reporting
- [ ] Is the validator balance oracle updated to report MaxEB values (not capped at 32)?
- [ ] Does the oracle handle the shortened deposit-to-activation window?
- [ ] Is exit queue length factored into withdrawal time estimates shown to users?

---

## References

- [EIP-7002: Execution Layer Triggerable Exits](https://eips.ethereum.org/EIPS/eip-7002)
- [EIP-7251: Increase MAX_EFFECTIVE_BALANCE](https://eips.ethereum.org/EIPS/eip-7251)
- [EIP-6110: Supply Validator Deposits On-Chain](https://eips.ethereum.org/EIPS/eip-6110)
- [Lido's Pectra Roadmap Analysis](https://blog.lido.fi/lidos-roadmap-to-pectra-navigating-complexity/)
- [EIP-7251 Effects on Rewards & Risks (Lido Research)](https://research.lido.fi/t/eip-7251-effects-on-rewards-risks/7718)
- Lido governance forum — EIP-7251 MaxEB enablement discussion and phased rollout decisions (research.lido.fi)
- Galaxy Research — Ethereum validator set analysis post-Pectra: consolidation rates and exit queue data (galaxy.com/insights)
- [defi-checklist.md §Restaking & LRT](defi-checklist.md)
- [account-abstraction.md](account-abstraction.md)
- [vulnerability-taxonomy.md §17 — EIP-7702](vulnerability-taxonomy.md)
