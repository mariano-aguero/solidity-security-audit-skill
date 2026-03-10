---
name: solidity-security-audit
description: >
  Comprehensive Solidity smart contract security auditing and vulnerability analysis skill.
  Based on methodologies from Trail of Bits, OpenZeppelin, Consensys Diligence, Sherlock,
  CertiK, Cyfrin, Spearbit, Halborn, and other leading Web3 security firms.
  This skill should be used whenever the user asks to "audit a smart contract",
  "review Solidity code for security", "find vulnerabilities", "check for reentrancy",
  "analyze gas optimization", "review access control", "check proxy patterns",
  "analyze DeFi protocol security", "review ERC20/ERC721 implementation",
  "check oracle manipulation risks", "review upgrade patterns", or mentions any
  security review of EVM-compatible smart contracts. Also triggers for keywords like
  "slither", "echidna", "foundry fuzz", "formal verification", "invariant testing",
  "flash loan attack", "MEV", "sandwich attack", "front-running", "delegatecall",
  "selfdestruct", "reentrancy guard", "access control vulnerability",
  "storage collision", "proxy upgrade security", "smart contract exploit",
  "L2 security", "cross-chain", "bridge security", "sequencer", "LayerZero", "CCIP",
  "account abstraction", "ERC-4337", "smart account", "paymaster", "bundler", "UserOperation",
  "re-audit", "diff audit", "remediation review", "fix verification", "Uniswap v4 hooks",
  "Chainlink integration", "Aave integration", "flash loan receiver", "ERC-4626 vault",
  "restaking", "EigenLayer", "AVS", "severity classification", "severity decision",
  "perpetual", "perp dex", "GMX", "Synthetix", "funding rate", "liquidation cascade",
  "intent protocol", "UniswapX", "Permit2", "1inch Fusion", "Dutch auction order",
  "ZK-VM", "zkSync", "Polygon zkEVM", "ZK proof", "Risc0", "SP1", "Circom", "under-constrained",
  "ERC-7683", "cross-chain intents", "IOriginSettler", "IDestinationSettler", "CrossChainOrder",
  "filler protocol", "origin settler", "destination settler", "orderId", "fillDeadline",
  "EIP-7002", "triggerable exit", "execution layer withdrawal", "validator exit",
  "EIP-7251", "MaxEB", "max effective balance", "validator consolidation", "consolidation",
  "EIP-6110", "beacon deposit", "validator deposit", "liquid staking security",
  "OWASP SC", "OWASP smart contract", "SC01", "SC02",
  "ERC-6909", "multi-token", "PoolManager claims", "claim token", "isOperator",
  "MEV bot", "MEV contract", "arbitrage bot", "sandwich bot", "sweep function",
  "AI-generated code", "Copilot", "vibe coding", "LLM-generated Solidity",
  "Wake", "eth-wake", "Ackee Blockchain",
  "TSTORE", "TLOAD", "transient storage", "tstore compiler bug", "tstore poison",
  "solc 0.8.28", "solc via-ir", "via-ir optimizer", "reentrancy guard bypass tstore",
  "EOF", "EIP-7692", "Fusaka upgrade", "EXTDELEGATECALL", "EVM object format",
  "gas observability", "code observability", "CODESIZE EXTCODESIZE EOF",
  "ERC-7726", "price adapter", "price oracle adapter", "false validity assumption",
  "IQuote", "getQuote oracle",
  "phantom collateral", "orphaned state", "Abracadabra exploit", "cook batch router",
  "failed external call state", "liquidation ghost debt",
  "overflow sentinel", "Cetus exploit", "bit-shift guard", "FullMath overflow",
  "PRBMath overflow", "custom math library overflow",
  "OpenZeppelin v5 migration", "OZ v4 to v5", "ERC-7201 namespaced storage",
  "sequential storage layout", "namespaced storage layout", "storage slot migration",
  "LDF rounding", "Bunni exploit", "liquidity distribution function",
  "asymmetric rounding liquidity", "flash tick shift",
  "JIT liquidity attack", "just-in-time liquidity", "V4 JIT",
  "Morpho Blue", "Euler V2", "EVC", "modular lending", "permissionless market",
  "EigenVault", "cross-vault health", "ERC-4337 executor vault",
  "EIP-7701", "native account abstraction", "ACCEPT_ROLE opcode",
  "per-transaction validation", "legacy contract validation".
  Even if the user simply pastes Solidity code and asks "is this safe?" or
  "any issues here?", use this skill.
---

# Solidity Security Audit Skill

## Purpose

Perform professional-grade smart contract security audits following methodologies
established by the world's leading Web3 security firms. Produce actionable,
severity-classified findings with remediation guidance.

## Audit Mode Selection

Before starting, identify the audit mode:

| Mode | When to Use | Entry Point |
|------|-------------|-------------|
| **Full Audit** | First-time review of a codebase | Phases 1–5 below |
| **Re-audit / Diff** | Previous audit exists; team applied fixes or added features | `references/diff-audit.md` |
| **Integration Review** | Contract integrates Uniswap, Chainlink, Aave, Curve, etc. | `references/defi-integrations.md` + Phase 3 |
| **Quick Scan** | Rapid assessment, limited time | `references/quick-reference.md` — abbreviated Phase 0 (5 min max), run Phases 1–2 only, focus Phase 3 on Critical/High patterns from `quick-reference.md` |

For severity classification guidance at any point, consult `references/severity-decision-tree.md`.

---

## Full Audit Workflow

Execute audits in this order. Each phase builds on the previous one.

### Phase 0 — Threat Modeling

Before touching code, build a mental model of what the protocol does and what
can go wrong economically. This shapes where you spend time in Phase 3.

1. **Map the actors**: who interacts with this protocol?
   - Unprivileged users, liquidity providers, borrowers
   - Privileged roles: admin, guardian, keeper, fee recipient
   - External actors: MEV bots, flash loan attackers, liquidators, governance participants

2. **Identify the crown jewels**: what assets or rights are at risk?
   - User funds locked in the protocol
   - Protocol-owned reserves or insurance funds
   - Governance control (ability to upgrade, change parameters, drain)

3. **Define critical invariants**: what must NEVER be false?
   - Solvency: total liabilities ≤ total assets
   - Accounting: sum of individual balances = tracked total
   - Access: only authorized callers can execute privileged operations

4. **Trace trust boundaries**: what external systems does this protocol trust?
   - Oracles (Chainlink, TWAP, custom)
   - External protocol integrations (Uniswap, Aave, Curve)
   - Bridging / messaging layers (LayerZero, CCIP, Wormhole)
   - Multisig signers or governance

5. **Estimate MEV surface**: what operations create profitable ordering opportunities?
   - Liquidations, arbitrage, sandwich-able swaps
   - Front-runnable reveals, claims, or settlements

6. **Note upgrade/admin blast radius**: if the admin key or a multisig is compromised,
   what is the maximum damage? Is there a timelock? A pause mechanism?

Output: a 5–10 line threat summary that focuses the manual review in Phase 3 on
the highest-value attack paths. Skip this only for Quick Scan mode.

---

### Phase 1 — Reconnaissance

1. Identify the Solidity version, compiler settings, and framework (Hardhat/Foundry)
2. Map the contract architecture: inheritance tree, library usage, external dependencies
3. Identify the protocol type (DeFi lending, AMM, NFT, governance, bridge, vault, etc.)
4. Determine the trust model: who are the privileged roles? What can they do?
5. List all external integrations (oracles, other protocols, token standards)

### Phase 2 — Automated Analysis

If tools are available in the environment, run them in this order:

```
# Static analysis
slither . --json slither-report.json

# Compile and test
forge build
forge test --gas-report

# Custom detectors (if Aderyn is available)
aderyn .
```

If tools are NOT available, perform manual static analysis covering the same
categories these tools check. Read `references/tool-integration.md` for details.

### Phase 3 — Manual Review (Core)

This is where the highest-value findings come from. Follow the vulnerability
taxonomy in `references/vulnerability-taxonomy.md` systematically:

**CRITICAL PRIORITY — Check these first:**
- Reentrancy (all variants: cross-function, cross-contract, read-only)
- Access control flaws (missing modifiers, incorrect role checks, unprotected initializers)
- Price oracle manipulation (spot price usage, single oracle dependency, TWAP bypass)
- Flash loan attack vectors
- Proxy/upgrade vulnerabilities (storage collision, uninitialized implementation, UUPS gaps)
- Unchecked external calls and return values
- ERC-7702 delegation risks (if EOAs or authorization tuples are present: malicious delegation target, stale authorization replay, nonce race, re-initialization of delegated code) — see `references/vulnerability-taxonomy.md §17`

**HIGH PRIORITY:**
- Integer overflow/underflow (pre-0.8.x or unchecked blocks)
- Logic errors in business rules (token minting, reward calculations, fee distribution)
- Front-running and MEV exposure (sandwich attacks, transaction ordering dependence)
- Denial of Service vectors (gas griefing, unbounded loops, block gas limit)
- Signature replay and malleability
- Delegatecall to untrusted contracts

**MEDIUM PRIORITY:**
- Gas optimization issues that affect usability
- Missing event emissions for state changes
- Centralization risks and single points of failure
- Timestamp dependence
- Floating pragma versions
- Missing zero-address checks

**LOW / INFORMATIONAL:**
- Code style and readability
- Unused variables and imports
- Missing NatSpec documentation
- Redundant code patterns

### Phase 4 — DeFi-Specific Analysis

When auditing DeFi protocols, apply the specialized checklist from
`references/defi-checklist.md`. Key areas:

- **Lending protocols**: Liquidation logic, collateral factor manipulation, bad debt scenarios
- **AMMs/DEXs**: Slippage protection, price impact calculations, LP token accounting
- **Vaults/Yield**: Share price manipulation (inflation attack), withdrawal queue logic
- **Bridges**: Message verification, replay protection, validator trust assumptions
- **Governance**: Vote manipulation, flash loan governance attacks, timelock bypass
- **Staking**: Reward calculation precision, stake/unstake timing attacks

### Phase 5 — Report Generation

Structure every finding using this format:

```
## [SEVERITY-ID] Title

**Severity**: Critical | High | Medium | Low | Informational
**Category**: (from vulnerability taxonomy)
**Location**: `ContractName.sol#L42-L58`

### Description
Clear explanation of the vulnerability, why it exists, and what an attacker could do.

### Impact
Concrete description of damage: funds at risk, protocol disruption, data corruption.

### Proof of Concept
Step-by-step exploit scenario or code demonstrating the issue.

### Recommendation
Specific code changes to fix the vulnerability. Include example code when possible.
```

Classify severity following the standard used by Immunefi, Code4rena, and Sherlock:

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct loss of funds, permanent protocol corruption, bypass of all access controls |
| **High** | Conditional loss of funds, significant protocol disruption, privilege escalation |
| **Medium** | Indirect loss, limited impact requiring specific conditions, griefing with cost |
| **Low** | Minor issues, best practice violations, theoretical edge cases |
| **Informational** | Code quality, gas optimizations, documentation gaps |

## Key Patterns to Enforce

### Checks-Effects-Interactions (CEI)
Every function that modifies state and makes external calls must follow CEI.
Verify state changes happen BEFORE any external call.

### Pull Over Push
Favor withdrawal patterns over direct transfers. Let users claim rather than
pushing funds to them automatically.

### Least Privilege
Every function should have the minimum required access level. Prefer role-based
access control (OpenZeppelin AccessControl) over single-owner patterns.

### Defense in Depth
No single security mechanism should be the only protection. Layer reentrancy
guards, access controls, input validation, and invariant checks.

## Reference Materials

For detailed vulnerability descriptions, exploit examples, and remediation
patterns, consult these reference files:

### Core References
- `references/vulnerability-taxonomy.md` — 50+ vulnerability types with code examples
- `references/defi-checklist.md` — Protocol-specific checklists (lending, AMM, vaults, bridges, tokens)
- `references/industry-standards.md` — SWC Registry, severity classification, security EIPs
- `references/quick-reference.md` — One-page cheat sheet for rapid security assessment

### Audit Guides
- `references/audit-questions.md` — Systematic questions for each function type
- `references/secure-patterns.md` — Secure code patterns to compare against
- `references/report-template.md` — Professional audit report format

### Testing & Tools
- `references/tool-integration.md` — Slither, Echidna, Foundry, Halmos, custom detectors
- `references/automated-detection.md` — Regex patterns for automated scanning
- `references/poc-templates.md` — Foundry templates for proving exploits
- `references/invariants.md` — Protocol invariants for testing

### Specialized
- `references/l2-crosschain.md` — L2 sequencer risks, bridge security, cross-chain patterns
- `references/account-abstraction.md` — ERC-4337 security: accounts, paymasters, bundlers
- `references/exploit-case-studies.md` — Real-world exploits analyzed (DAO, Euler, Curve, etc.)

### New in v2
- `references/diff-audit.md` — Re-audit and change review methodology
- `references/severity-decision-tree.md` — Structured severity classification decision trees
- `references/defi-integrations.md` — Secure integration patterns: Uniswap v3/v4, Chainlink, Aave, Curve, Balancer

### New in v3
- `references/intent-protocols.md §8` — ERC-7683 Cross-Chain Intents (live on Base/Arbitrum): filler trust model, parameter substitution, double-fill, settlement finality race
- `references/staking-consensus.md` — Pectra upgrade security: EIP-7002 (triggerable exits), EIP-7251 (MaxEB + slashing amplification), EIP-6110 (on-chain deposits)
- `references/industry-standards.md` — OWASP Smart Contract Top 10 2025 table added

### New in v3.2.0
- `references/vulnerability-taxonomy.md §19.6` — TSTORE Poison compiler bug (solc 0.8.28–0.8.33 + --via-ir): ownership theft, reentrancy guard bypass, ~500K affected contracts
- `references/vulnerability-taxonomy.md §19.7` — 2300-gas stipend bypass via TSTORE: transfer()/send() no longer block reentrancy when callee uses TSTORE
- `references/vulnerability-taxonomy.md §22` — EVM EOF (EIP-7692/Fusaka): gas/code observability removal, EXTDELEGATECALL legacy restriction, deploy-time validation
- `references/vulnerability-taxonomy.md §3.4` — Math overflow sentinel errors: Cetus $223M pattern, wrong bit-shift boundaries in FullMath/PRBMath
- `references/vulnerability-taxonomy.md §6.6` — OZ v4→v5 storage slot migration break: sequential vs ERC-7201 namespaced layout
- `references/vulnerability-taxonomy.md §12.6` — Phantom collateral via failed external call: Abracadabra pattern, cook() batch-router shared-state
- `references/vulnerability-taxonomy.md §4.5` — ERC-7726 false validity assumption: oracle adapters that silently pass invalid data
- `references/vulnerability-taxonomy.md §18.6` — V4 hook LDF rounding attack: Bunni $8.4M, asymmetric rounding in add/remove liquidity
- `references/defi-checklist.md` — JIT liquidity attack checklist, LDF rounding checklist, Modular Lending (Morpho Blue + Euler V2 EVC) checklist
- `references/account-abstraction.md` — EIP-7701 Native AA section: ACCEPT_ROLE opcode risk, legacy contract unintentional validation
- `references/automated-detection.md` — TSTORE Poison version detector + co-usage regex patterns

### Navigation
- `references/INDEX.md` — Topic → file:section map; use when you know the topic but not which file covers it

Load these files as needed based on the specific audit context.

## Important Notes

- Always state clearly if the review is a limited automated scan vs. a full manual audit
- Never guarantee that code is "100% secure" — audits reduce risk, they don't eliminate it
- Flag centralization risks even if they aren't traditional "vulnerabilities"
- Consider the economic incentives: would the exploit be profitable given gas costs?
- Check interactions with common DeFi primitives (flash loans, MEV, composability)
- When in doubt about severity, read how Sherlock, Code4rena, and Immunefi classify similar findings
