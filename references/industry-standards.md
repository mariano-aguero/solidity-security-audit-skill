# Security Standards Reference

Quick reference for vulnerability classification and severity standards used in audit reports.

---

## OWASP Smart Contract Top 10 (2025)

**Source:** OWASP Foundation SC Top 10 — ranked by financial impact and incident frequency
from SolidityScan Web3HackHub 2025 data. Access control overtook reentrancy as #1 ($953M in 2024).

| Rank | ID | Category | Financial Impact 2024 | Key Patterns |
|------|-----|----------|-----------------------|--------------|
| 1 | SC01 | **Access Control Vulnerabilities** | $953M | Missing modifiers, tx.origin, unprotected initializers, role hierarchy errors |
| 2 | SC02 | **Price Oracle Manipulation** | $850M+ | Spot price usage, stale feeds, single oracle, TWAP bypass |
| 3 | SC03 | **Logic Errors / Business Rule Violations** | High | Off-by-one, incorrect fee math, wrong state machine transitions |
| 4 | SC04 | **Lack of Input Validation** | High | Missing zero-address checks, unchecked array bounds, unvalidated amounts |
| 5 | SC05 | **Reentrancy Vulnerabilities** | High (classic) | Single-fn, cross-fn, cross-contract, read-only, ERC-1155 hook |
| 6 | SC06 | **Unchecked External Calls** | Medium | Ignored return values, failed calls silently passing, unsafe delegatecall |
| 7 | SC07 | **Flash Loan Attacks** | High (catalyst) | Oracle + flash loan combos, governance flash attacks, collateral manipulation |
| 8 | SC08 | **Integer Overflow / Underflow** | Medium | unchecked blocks, pre-0.8.x code, precision loss in division |
| 9 | SC09 | **Insecure Randomness** | Medium | blockhash, block.timestamp, commit-reveal without entropy |
| 10 | SC10 | **Denial of Service** | Medium | Unbounded loops, force-send ETH, block gas limit, pull-not-push violations |

**Cross-reference:** SC01 → taxonomy §2, SC02 → taxonomy §4, SC05 → taxonomy §1, SC08 → taxonomy §3

---

## SWC Registry (Smart Contract Weakness Classification)

**EIP-1470** — Classification scheme for smart contract weaknesses.

| SWC | Title | Severity |
|-----|-------|----------|
| SWC-100 | Function Default Visibility | High |
| SWC-101 | Integer Overflow and Underflow | High |
| SWC-103 | Floating Pragma | Low |
| SWC-104 | Unchecked Call Return Value | Medium |
| SWC-105 | Unprotected Ether Withdrawal | Critical |
| SWC-106 | Unprotected SELFDESTRUCT | Critical |
| SWC-107 | Reentrancy | Critical |
| SWC-109 | Uninitialized Storage Pointer | High |
| SWC-110 | Assert Violation | Medium |
| SWC-112 | Delegatecall to Untrusted Callee | Critical |
| SWC-113 | DoS with Failed Call | Medium |
| SWC-114 | Transaction Order Dependence | Medium |
| SWC-115 | Authorization through tx.origin | High |
| SWC-116 | Block Timestamp Dependence | Low |
| SWC-117 | Signature Malleability | Medium |
| SWC-119 | Shadowing State Variables | Medium |
| SWC-120 | Weak Sources of Randomness | Medium |
| SWC-121 | Missing Protection against Signature Replay | High |
| SWC-122 | Lack of Proper Signature Verification | High |
| SWC-124 | Write to Arbitrary Storage | Critical |
| SWC-128 | DoS With Block Gas Limit | Medium |
| SWC-131 | Presence of Unused Variables | Informational |
| SWC-133 | Hash Collision with Multiple Variable Length Arguments | Medium |
| SWC-134 | Hardcoded Gas Amount | Low |
| SWC-135 | Code With No Effects | Informational |
| SWC-136 | Unencrypted Private Data On-Chain | Informational |

---

## Severity Classification

Standard used by Immunefi, Sherlock, and Code4rena for classifying findings.

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct theft/freezing of funds, permanent protocol corruption, bypass of all access controls |
| **High** | Conditional theft/freezing of funds, significant protocol disruption, privilege escalation |
| **Medium** | Indirect loss, griefing with cost, issues requiring specific/unlikely conditions |
| **Low** | Minor issues, best practice violations, theoretical edge cases |
| **Informational** | Code quality, gas optimizations, documentation gaps |

---

## Key EIPs for Security

| EIP | Title | Security Relevance |
|-----|-------|--------------------|
| EIP-712 | Typed Structured Data Hashing | Prevents signature replay across dApps |
| EIP-1153 | Transient Storage Opcodes | tload/tstore — new reentrancy guard pattern, new collision risks |
| EIP-1967 | Standard Proxy Storage Slots | Prevents storage collision in proxies |
| EIP-2098 | Compact Signature Representation | Prevents signature malleability |
| EIP-2612 | Permit (Gasless Approvals) | New approval attack surface |
| EIP-4337 | Account Abstraction via EntryPoint | New MEV, bundler trust, paymaster drain vectors |
| EIP-4626 | Tokenized Vault Standard | Share inflation attacks |
| EIP-4844 | Shard Blob Transactions | Blob availability window, L2 data cost changes |
| EIP-5792 | Wallet Call API | Batch transactions — new AA interaction surface |
| EIP-6093 | Custom Errors for ERC Tokens | Standardized revert reasons — spoofing risk if checked naively |
| EIP-6551 | Token-Bound Accounts (TBA) | NFTs owning assets — new ownership/reentrancy attack surface |
| EIP-6780 | SELFDESTRUCT Restriction | Changed selfdestruct behavior post-Cancun |
| EIP-7201 | Namespaced Storage Layout | Prevents storage collision in upgradeable contracts |
| EIP-7702 | Set Code for EOAs | EOAs can become smart accounts — delegation and replay risks |
| EIP-7002 | Execution Layer Triggerable Exits | Withdrawal credentials can force validator exits — new staking attack surface |
| EIP-7251 | Increase MAX_EFFECTIVE_BALANCE | Up to 2048 ETH per validator — amplified slashing, consolidation race conditions |
| EIP-6110 | Supply Validator Deposits On-Chain | Deposits visible in EL immediately — deposit front-running, flow changes |
| ERC-7683 | Cross-Chain Intents Standard | Filler trust model, msg.sender bypass via DestinationSettler, parameter substitution |

---

## Leading Audit Firms & Methodologies

Reference for understanding how severity classifications map across firms:

| Firm | Known For | Severity Scale |
|------|-----------|---------------|
| **Trail of Bits** | Deep research, custom tools (Slither, Echidna, Medusa) | Critical / High / Medium / Low / Informational |
| **OpenZeppelin** | Secure contract libraries, formal reviews | Critical / High / Medium / Low / Informational |
| **Consensys Diligence** | MythX, Scribble formal specs | Critical / High / Medium / Low |
| **Cyfrin** | Foundry-native, CodeHawks competitive audits | Critical / High / Medium / Low / Gas / Informational |
| **Sherlock** | Contest platform, on-chain insurance model | High / Medium (no Critical/Low — mapped to these two) |
| **Code4rena** | Contest platform, warden community | Critical / High / Medium / Low / QA / Gas |
| **Spearbit / Cantina** | Elite researcher network, Cantina competitions | Critical / High / Medium / Low / Informational |
| **Halborn** | Security operations, blockchain-specific | Critical / High / Medium / Low / Informational |
| **Pashov Audit Group** | Boutique, complex DeFi protocols | Critical / High / Medium / Low / Informational |
| **Guardian Audits** | Competitive audits, DeFi / GameFi focus | Critical / High / Medium / Low |
| **Immunefi** | Bug bounty platform, largest payouts | Critical / High / Medium / Low (bounty-aligned) |

### Sherlock vs Code4rena Severity Mapping

Sherlock only uses **High** and **Medium** in contest reports. When porting:
- Critical → High (Sherlock)
- High → High (Sherlock)
- Medium → Medium (Sherlock)
- Low / QA → Not rewarded in Sherlock contests (typically)

### Immunefi Critical Payout Criteria

Immunefi Critical pays for:
- Direct theft of funds (any amount)
- Permanent freezing of funds
- Protocol insolvency
- Governance takeover

---

## Contest & Bounty Platform Rules (2025)

### Code4rena — Current Format

Code4rena uses **QA Reports** to consolidate Low and Informational findings:

| Submission Type | Severity | Notes |
|-----------------|----------|-------|
| Individual finding | Critical / High / Medium | Scored per finding, per warden |
| QA Report | Low + Informational combined | Single report, graded A/B/C; max score replaces per-finding count |
| Gas Report | Gas optimization | Optional, separate scoring pool |

**Practical impact for auditors:**
- Do **not** submit Low findings individually — they must go into the QA report
- A single QA report covers all Low and Info findings for the contest
- QA report grade (A = full score, B = partial, C = minimal) determines payout
- Critical and High findings are still submitted individually with PoC required

### Sherlock v2 — Severity Rules (2025)

Sherlock's severity model was rewritten in 2025. Key changes from v1:

| Rule | v1 | v2 |
|------|----|----|
| Severity tiers | High / Medium | High / Medium (unchanged) |
| Duplication | Highest-severity unique finding wins | Lead watson can escalate; dupes grouped by root cause |
| Low findings | Not rewarded | Still not rewarded in contests |
| Admin/owner trust | Fully trusted | **Trusted** by default — admin-as-attack-vector is out of scope unless README marks admin as restricted |
| External integrations | Auditor's discretion | Must be in scope or explicitly broken to count |
| Watson escalation | None | Lead Watson can escalate Medium → High with judge approval |

**Restricted vs. Trusted admin (Sherlock v2):**

```solidity
// This is NOT a valid finding under Sherlock v2 default rules:
// "Admin can call setFeeRate(10000) and drain protocol"
// Reason: admin is trusted by default

// This IS valid if scope says "admin is restricted":
// "Any user can call setFeeRate due to missing onlyOwner modifier"
```

**Practical impact:**
- Before filing a finding that depends on admin behavior, check the contest README for trust assumptions
- "Admin can rugpull" is never a finding unless protocol explicitly marks admin as restricted
- External protocol failure (e.g., Chainlink goes down) is only valid if the contest README lists it as in scope

### Immunefi — Boost & Attackathon Format

Immunefi runs two distinct programs beyond classic bug bounty:

| Format | How it works | Payout model |
|--------|-------------|--------------|
| **Classic Bug Bounty** | Continuous, private submission | Fixed table by severity (Critical up to $X) |
| **Boost** | Time-boxed (1–4 weeks), semi-public | Fixed pool split among valid findings by severity weight |
| **Attackathon** | Fully public competitive audit | Fixed pool, all wardens compete, graded like Code4rena |

**Boost / Attackathon severity weights (typical):**

| Severity | Weight |
|----------|--------|
| Critical | 9 |
| High | 3 |
| Medium | 1 |
| Low | 0 (informational only, no payout) |

**Immunefi v2.3 out-of-scope rules:**
The following are **never** valid Immunefi findings regardless of program:
- Issues requiring compromised private keys / admin keys (unless explicitly in scope)
- Theoretical attacks with no demonstrated economic profitability
- UI/UX bugs without on-chain impact
- Duplicate reports (first-submission wins)
- Issues already acknowledged in previous audits (unless fixed and reintroduced)

### Severity Escalation Across Platforms

| Scenario | Immunefi | Sherlock | Code4rena |
|----------|----------|----------|-----------|
| Requires specific block timing | Medium | Medium | Medium |
| Requires admin cooperation | Out of scope | Out of scope (default) | Depends on README |
| DoS without fund loss | Medium max | Medium max | Medium max |
| Loss of yield (not principal) | Medium | Medium | Medium |
| Complete loss of user funds | Critical | High | Critical |
| Governance takeover | Critical | High | Critical |
