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

## 5. Staking Protocol Audit Checklist (Post-Pectra)

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
- [defi-checklist.md §Restaking & LRT](defi-checklist.md)
- [account-abstraction.md](account-abstraction.md)
- [vulnerability-taxonomy.md §17 — EIP-7702](vulnerability-taxonomy.md)
