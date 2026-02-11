# Solidity Security Audit Skill

An open-source **Agent Skill** for performing professional-grade smart contract security audits. Compatible with Claude Code, Cursor, Windsurf, and other AI coding assistants.

## Overview

This skill transforms your AI agent into a comprehensive smart contract security auditor. It provides structured methodologies, vulnerability patterns, and tools integration based on industry best practices.

### What's Included

| Category | Content |
|----------|---------|
| **Vulnerability Patterns** | 40+ vulnerability types with code examples |
| **Protocol Checklists** | Lending, AMM, Vaults, Bridges, Governance, Staking, NFT |
| **Token Standards** | ERC-20, ERC-721, ERC-1155, ERC-4626 security checks |
| **Tool Integration** | Slither, Foundry, Echidna, Aderyn, Halmos, Certora |
| **PoC Templates** | Foundry templates for proving exploits |
| **Real Exploits** | The DAO, Beanstalk, Euler, Curve, Nomad, Wormhole |
| **L2 Security** | Sequencer risks, bridges, cross-chain patterns |
| **Account Abstraction** | ERC-4337 accounts, paymasters, bundlers |

## Installation

```bash
npx skills add mariano-aguero/solidity-security-audit-skill
```

## Features

### 5-Phase Audit Workflow

1. **Reconnaissance** — Architecture mapping, trust model, external dependencies
2. **Automated Analysis** — Slither, Aderyn, Foundry integration
3. **Manual Review** — Systematic vulnerability taxonomy
4. **Protocol-Specific** — DeFi checklists by protocol type
5. **Report Generation** — Severity-classified findings with PoC

### Vulnerability Coverage

**Critical & High Priority**
- Reentrancy (classic, cross-function, cross-contract, read-only)
- Access control bypass and unprotected initializers
- Oracle manipulation and flash loan attacks
- Proxy storage collisions and upgrade vulnerabilities

**DeFi-Specific**
- Lending: liquidation logic, bad debt, interest calculation
- AMM: slippage protection, LP accounting, price impact
- Vaults: first depositor inflation, share manipulation
- Bridges: message validation, replay protection
- Governance: flash loan voting, timelock bypass

**Emerging Areas**
- L2/Cross-chain: sequencer risks, message passing, finality
- Account Abstraction: paymaster drain, session keys, bundler griefing

### Tool Integration

```bash
# Static analysis
slither . --json report.json
aderyn .

# Fuzz testing
forge test --fuzz-runs 10000

# Invariant testing
forge test --match-test invariant

# Fork testing
forge test --fork-url $ETH_RPC_URL
```

### Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct loss of funds, permanent protocol corruption |
| **High** | Conditional loss of funds, significant disruption |
| **Medium** | Limited impact, specific conditions required |
| **Low** | Best practice violations, theoretical issues |
| **Informational** | Code quality, gas optimizations |

## Project Structure

```
solidity-security-audit-skill/
├── SKILL.md                    # Entry point with 5-phase workflow
└── references/
    ├── vulnerability-taxonomy.md    # 40+ vulnerabilities with code
    ├── defi-checklist.md            # Protocol + token checklists
    ├── tool-integration.md          # Slither, Echidna, Foundry, Halmos
    ├── industry-standards.md        # SWC Registry, severity, EIPs
    ├── automated-detection.md       # Regex patterns for scanning
    ├── audit-questions.md           # Questions per function type
    ├── secure-patterns.md           # Secure code reference
    ├── report-template.md           # Professional report format
    ├── poc-templates.md             # Foundry PoC templates
    ├── invariants.md                # Protocol invariants
    ├── exploit-case-studies.md      # Real exploit analysis
    ├── quick-reference.md           # One-page cheat sheet
    ├── l2-crosschain.md             # L2 and bridge security
    └── account-abstraction.md       # ERC-4337 security
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
