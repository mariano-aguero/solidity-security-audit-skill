<p align="center">
  <a href="https://claude.ai/code"><img src="https://img.shields.io/badge/Claude_Code-Compatible-D97706?style=for-the-badge" alt="Claude Code Compatible"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"></a>
  <a href="https://github.com/mariano-aguero/solidity-security-audit-skill/releases/tag/v1.0.0"><img src="https://img.shields.io/badge/v2.0-improvements-blue?style=for-the-badge" alt="v2 improvements"></a>
</p>

# Solidity Security Audit Skill

An open-source **Agent Skill** for performing professional-grade smart contract security audits. Compatible with Claude Code, Cursor, Windsurf, and other AI coding assistants.

## Overview

This skill transforms your AI agent into a comprehensive smart contract security auditor. It provides structured methodologies, vulnerability patterns, and tools integration based on industry best practices from Trail of Bits, OpenZeppelin, Sherlock, Cyfrin, Cantina, and other leading Web3 security firms.

### What's Included

| Category | Content |
|----------|---------|
| **Vulnerability Patterns** | 25 sections, 100+ vulnerability types with code examples (incl. ERC-7702, V4 hooks, transient storage, PUSH0, ERC-1967) |
| **Protocol Checklists** | Lending, AMM, Vaults, Bridges, Governance, Staking, NFT, Restaking/LRT, V4 Hooks, Airdrop, RWA, Options, Prediction Markets, Safe Modules |
| **Token Standards** | ERC-20, ERC-721, ERC-1155, ERC-4626 security checks |
| **Tool Integration** | Slither (SARIF + 7-step triage cheat sheet), Foundry (coverage), Echidna, Aderyn, Halmos, Certora, Slang AST |
| **PoC Templates** | Foundry templates incl. V4 hook drain, transient storage bypass, ERC-7702 abuse |
| **Real Exploits** | 20 case studies: The DAO → Bybit ($1.5B), Ronin ($625M), Mango, BNB Chain, Multichain |
| **L2 Security** | Sequencer, bridges, Blast rebasing, zkEVM specifics, EIP-4844, precompiles |
| **Account Abstraction** | ERC-4337 accounts, paymasters, bundlers, ERC-7702, ERC-7579 modules |
| **DeFi Integrations** | Uniswap v3/v4, Chainlink, Aave, Curve, Balancer, intent protocols (Permit2, ERC-7683) |
| **Severity Decision Trees** | Impact×Likelihood matrix, per-vuln decision trees, escalation factors |
| **Diff/Re-audit** | Change review workflow, remediation verification, storage layout diff |
| **Contest Mode** | Platform routing for Code4rena, Sherlock, Immunefi, Cantina, CodeHawks; ROI strategy, validity rules |

## Installation

```bash
npx skills add mariano-aguero/solidity-security-audit-skill
```

## Features

### Audit Mode Selection

The skill supports multiple audit modes depending on context:

| Mode | When to Use |
|------|-------------|
| **Full Audit** | First-time review of a codebase |
| **Re-audit / Diff** | Previous audit exists; team applied fixes or added features |
| **Integration Review** | Contract integrates Uniswap, Chainlink, Aave, Curve, etc. |
| **Quick Scan** | Rapid assessment from the one-page cheat sheet |
| **Contest Mode** | Submitting to Code4rena, Sherlock, Immunefi, Cantina, or CodeHawks |

### 5-Phase Audit Workflow

1. **Reconnaissance** — Architecture mapping, trust model, external dependencies
2. **Automated Analysis** — Slither (with SARIF), Aderyn, Foundry coverage
3. **Manual Review** — Systematic vulnerability taxonomy (100+ types, 25 sections)
4. **Protocol-Specific** — DeFi checklists by protocol type
5. **Report Generation** — Severity-classified findings with PoC

### Vulnerability Coverage

**Critical & High Priority**
- Reentrancy (classic, cross-function, cross-contract, read-only)
- Access control bypass and unprotected initializers
- Oracle manipulation and flash loan attacks
- Proxy storage collisions and upgrade vulnerabilities
- **ERC-7702**: malicious delegation, cross-chain replay, re-initialization
- **Uniswap V4 hooks**: delta drain, unlock() reentrancy, permission misconfiguration
- **Transient storage**: guard bypass via delegatecall, cross-function state leak

**DeFi-Specific**
- Lending: liquidation logic, bad debt, interest calculation
- AMM: slippage protection, LP accounting, price impact
- Vaults: first depositor inflation, share manipulation
- Bridges: message validation, replay protection
- Governance: flash loan voting, timelock bypass
- **Restaking/LRT**: slashing propagation, operator concentration, withdrawal queues
- **Points/Airdrop**: double-claim, Merkle root rug, vesting bypass
- **RWA**: NAV manipulation, tranche accounting, epoch redemptions, KYC bypass
- **Options**: settlement oracle, IV manipulation, undercollateralized writing
- **Prediction Markets**: resolver bribe, CTF merge attack, AMM price bounds
- **Safe Modules**: delegatecall storage collision, enableModule, guard bypass

**Compiler & Upgrade**
- **Solidity 0.9.0**: `transfer()`/`send()` removal, new reentrancy surface on migration
- **PUSH0 cross-chain**: EIP-3855 incompatibility on non-Shanghai chains (evmVersion)
- **ERC-1967 slot corruption**: UUPS brick attack, delegatecall overwrite, layout migration
- **Supply chain**: compromised npm/CI, blind signing (Bybit $1.5B pattern)
- **ERC-6909**: dual approval confusion, inflation attack (Uniswap V4 claim tokens)
- **EOF (EIP-7692)**: gas/code observability removed, EXTDELEGATECALL restrictions

**Emerging Areas**
- L2/Cross-chain: sequencer risks, message passing, finality
- **Blast L2**: rebasing ETH/USDB yield modes, accounting invariants
- **zkEVM**: opcode differences (PUSH0, SELFDESTRUCT, blockhash), zkSync AA
- **EIP-4844**: blob availability window, L2 gas pricing post-Dencun
- Account Abstraction: paymaster drain, session keys, bundler griefing

### Tool Integration

```bash
# Static analysis
slither . --sarif slither.sarif        # SARIF for GitHub Security tab
aderyn .                               # Complementary fast AST-based analysis

# Symbolic execution
halmos                                 # Requires check_* test functions

# Property fuzzing
echidna . --contract MyContract        # Requires echidna_* test functions

# Coverage analysis
forge coverage --report summary        # Identify untested functions
forge coverage --report lcov           # HTML visualization

# Fuzz and invariant testing
forge test --fuzz-runs 10000
forge test --match-test invariant_

# Fork testing
forge test --fork-url $ETH_RPC_URL

# AST-based custom analysis
npx ts-node scan-project.ts            # Slang-powered custom detectors
```

### Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct loss of funds, permanent protocol corruption |
| **High** | Conditional loss of funds, significant disruption |
| **Medium** | Limited impact, specific conditions required |
| **Low** | Best practice violations, theoretical issues |
| **Informational** | Code quality, gas optimizations |

Uses the structured decision tree from `references/severity-decision-tree.md` to
minimize classification subjectivity.

## Project Structure

```
solidity-security-audit-skill/
├── SKILL.md                         # Entry point: audit modes + 5-phase workflow
└── references/
    ├── vulnerability-taxonomy.md    # 100+ vulnerabilities, 25 sections (incl. ERC-7702, V4 hooks, §20-§25)
    ├── defi-checklist.md            # Protocol checklists (incl. restaking, V4 hooks, airdrop)
    ├── tool-integration.md          # Slither/SARIF, Foundry/coverage, Slang AST, Echidna
    ├── industry-standards.md        # SWC, severity, EIPs (incl. EIP-1153, EIP-7702), firms
    ├── automated-detection.md       # Regex patterns for scanning
    ├── audit-questions.md           # Questions per function type
    ├── secure-patterns.md           # Secure code reference
    ├── report-template.md           # Professional audit report format
    ├── poc-templates.md             # Foundry PoC (incl. V4 hook drain, transient bypass)
    ├── invariants.md                # Protocol invariants for testing
    ├── exploit-case-studies.md      # Real exploit analysis
    ├── quick-reference.md           # One-page cheat sheet
    ├── l2-crosschain.md             # L2 security (incl. Blast, zkEVM, EIP-4844)
    ├── account-abstraction.md       # ERC-4337 security
    ├── diff-audit.md                # Re-audit and change review methodology  [v2]
    ├── severity-decision-tree.md    # Structured severity classification       [v2]
    ├── defi-integrations.md         # Uniswap v3/v4, Chainlink, Aave, Curve   [v2]
    ├── intent-protocols.md          # Permit2, UniswapX, 1inch Fusion, ERC-7683 [v3]
    ├── perpetual-dex.md             # GMX v2, Synthetix, liquidation, LP solvency [v3]
    ├── zkvm-specific.md             # ZK proof bugs, Noir, SP1, Polygon CDK    [v3]
    ├── staking-consensus.md         # Pectra: EIP-7002/7251/6110, LST/restaking [v3.1]
    ├── ai-code-patterns.md          # LLM anti-patterns, vibe-coding checklist  [v3.4]
    ├── glamsterdam.md               # EIP-7732 ePBS + EIP-7928 BALs            [v3.4]
    └── INDEX.md                     # Topic → file:section navigation map
```

## Usage

The skill activates automatically for security-related queries:

```
"Audit this Solidity contract for vulnerabilities"
"Check this lending protocol for flash loan attacks"
"Review my ERC-4626 vault for inflation attacks"
"Is this proxy upgrade pattern safe?"
"Check for reentrancy in this withdraw function"
"Audit this L2 bridge for message replay"
"Review this ERC-4337 paymaster for drain attacks"
"Re-audit these changes from the previous report"
"Is this Uniswap V4 hook safe?"
"Review my Chainlink integration"
"How severe is this finding?"
```

## Example Output

```markdown
## [H-01] Reentrancy in withdraw() allows draining funds

**Severity**: High
**File**: `Vault.sol#L45-L52`

### Description
The withdraw function sends ETH before updating state...

### Impact
Attacker can drain all funds from the vault...

### Proof of Concept
1. Attacker deposits 1 ETH
2. Attacker calls withdraw()
3. In receive(), attacker calls withdraw() again
4. Balance not yet updated, withdraw succeeds again
5. Repeat until drained

### Recommendation
Apply CEI pattern and add ReentrancyGuard...
```

## Changelog

### v3.10.0 (2026-03)
- **New**: Context Gathering pre-phase — structured questions (scope, version, chain, prior audits, protocol type) before auditing; safe defaults table; fast path for single-function pastes

### v3.9.0 (2026-03)
- **Updated** `tool-integration.md` — Slither Triage Cheat Sheet: 7-step framework for 100–300 findings; P0→P3 priority table; per-detector false positive guide (9 detectors); `.slither.config.json` template; `slither-check-upgradeability` workflow; triage decision card

### v3.8.0 (2026-03)
- **New** `defi-checklist.md` — RWA Protocols section (NAV manipulation, tranche accounting, epoch redemptions, KYC bypass)
- **New** `defi-checklist.md` — Options & Structured Products section (settlement oracle, IV manipulation, undercollateralized writing, automated vaults)
- **New** `defi-checklist.md` — Prediction Markets section (resolver bribe, CTF merge, AMM price bounds, insider MEV)
- **New** `defi-checklist.md` — Gnosis Safe Modules & Guards section (delegatecall collision, enableModule time-lock, guard bypass, Zodiac escalation)
- **Updated** `SKILL.md` — Phase 0 routing table: 13 → 17 protocol types

### v3.7.0 (2026-03)
- **New** `exploit-case-studies.md #19` — BNB Chain Bridge $570M (Merkle proof forgery via iavl library bug)
- **New** `exploit-case-studies.md #20` — Multichain $130M (MPC key centralization; jurisdiction risk)

### v3.6.0 (2026-03)
- **New** `vulnerability-taxonomy.md §23` — Solidity 0.9.0: `transfer()`/`send()` removal, new reentrancy surface
- **New** `vulnerability-taxonomy.md §24` — PUSH0 cross-chain compatibility (EIP-3855, non-Shanghai chains)
- **New** `vulnerability-taxonomy.md §25` — ERC-1967 proxy storage slot corruption, UUPS brick attack

### v3.5.0 (2026-03)
- **New**: Contest Mode — platform routing (C4, Sherlock, Immunefi, Cantina, CodeHawks), ROI strategy, validity pre-check, per-platform rules
- **New** `exploit-case-studies.md #17` — Ronin Bridge $625M (validator threshold + stale permissions)
- **New** `exploit-case-studies.md #18` — Mango Markets $117M (oracle manipulation via self-trading)
- **Updated** `report-template.md` — Immunefi bug bounty submission format

### v2.0.3 (2026-02)
- **Updated** `README.md` — Echidna and Halmos added to Tool Integration section with usage examples (`echidna_*` and `check_*` function conventions); explicit install commands for both tools

### v2.0.2 (2026-02)
- **New**: `package.json` — project metadata for Socket and Snyk security audit compatibility

### v2.0.1 (2026-02)
- **Updated** `CLAUDE.md` — architecture updated with 17 files, new maintenance guidelines for diff-audit, severity-decision-tree, and defi-integrations; added Cantina, Halborn, Pashov to firm list

### v2.0.0 (2026-02)
- **New**: `diff-audit.md` — re-audit workflow, remediation verification, storage layout diff
- **New**: `severity-decision-tree.md` — Impact×Likelihood matrix, per-vuln decision trees
- **New**: `defi-integrations.md` — Uniswap v3/v4 hooks, Chainlink, Aave, Curve, Balancer
- **Updated** `vulnerability-taxonomy.md` — ERC-7702, Uniswap V4 hooks, transient storage sections
- **Updated** `defi-checklist.md` — Restaking/LRT, V4 hooks protocol, Points/Airdrop checklists
- **Updated** `l2-crosschain.md` — Blast L2, zkEVM specifics, EIP-4844, L2 precompiles
- **Updated** `tool-integration.md` — Slang AST analysis, SARIF output, forge coverage
- **Updated** `industry-standards.md` — EIP-7702, EIP-1153, EIP-4844, ERC-6551, ERC-6093; audit firms table
- **Updated** `poc-templates.md` — V4 hook drain, transient storage bypass, ERC-7702 abuse PoCs

### v1.0.0 (2026-02)
- Initial release: 5-phase audit workflow, 14 reference files, 280KB documentation

## Contributing

Contributions welcome:

- New vulnerability patterns from recent exploits
- Additional protocol checklists
- Tool integration updates
- Exploit case studies

## License

MIT License — See [LICENSE](LICENSE) for details.

---

**Disclaimer**: This skill assists with security reviews but does not replace professional audits. No tool guarantees 100% security. Engage professional auditors for production deployments.
