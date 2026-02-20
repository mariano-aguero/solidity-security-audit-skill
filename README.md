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
| **Vulnerability Patterns** | 50+ vulnerability types with code examples (incl. ERC-7702, V4 hooks, transient storage) |
| **Protocol Checklists** | Lending, AMM, Vaults, Bridges, Governance, Staking, NFT, **Restaking/LRT**, **V4 Hooks**, **Airdrop** |
| **Token Standards** | ERC-20, ERC-721, ERC-1155, ERC-4626 security checks |
| **Tool Integration** | Slither (SARIF), Foundry (coverage), Echidna, Aderyn, Halmos, Certora, **Slang AST** |
| **PoC Templates** | Foundry templates incl. **V4 hook drain**, **transient storage bypass**, **ERC-7702 abuse** |
| **Real Exploits** | The DAO, Beanstalk, Euler, Curve, Nomad, Wormhole |
| **L2 Security** | Sequencer, bridges, **Blast rebasing**, **zkEVM specifics**, **EIP-4844**, **precompiles** |
| **Account Abstraction** | ERC-4337 accounts, paymasters, bundlers |
| **DeFi Integrations** | Uniswap v3/v4, Chainlink, Aave, Curve, Balancer secure integration patterns |
| **Severity Decision Trees** | Impact×Likelihood matrix, per-vuln decision trees, escalation factors |
| **Diff/Re-audit** | Change review workflow, remediation verification, storage layout diff |

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

### 5-Phase Audit Workflow

1. **Reconnaissance** — Architecture mapping, trust model, external dependencies
2. **Automated Analysis** — Slither (with SARIF), Aderyn, Foundry coverage
3. **Manual Review** — Systematic vulnerability taxonomy (50+ types)
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
aderyn .                                # Complementary analysis

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
    ├── vulnerability-taxonomy.md    # 50+ vulnerabilities with code (incl. ERC-7702, V4 hooks)
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
    └── defi-integrations.md         # Uniswap v3/v4, Chainlink, Aave, Curve   [v2]
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
