# Security Standards Reference

Quick reference for vulnerability classification and severity standards used in audit reports.

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
| EIP-1967 | Standard Proxy Storage Slots | Prevents storage collision in proxies |
| EIP-2098 | Compact Signature Representation | Prevents signature malleability |
| EIP-2612 | Permit (Gasless Approvals) | New approval attack surface |
| EIP-4337 | Account Abstraction | New MEV and bundler trust vectors |
| EIP-4626 | Tokenized Vault Standard | Share inflation attacks |
| EIP-6780 | SELFDESTRUCT Restriction | Changed selfdestruct behavior |
| EIP-7201 | Namespaced Storage Layout | Prevents storage collision |
