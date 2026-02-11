# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an **Agent Skill** for smart contract security auditing. It's a documentation-only project (no code to build/test) designed to be installed via `npx skills add mariano-aguero/solidity-security-audit-skill`.

The skill transforms AI agents into Solidity security auditors following methodologies from Trail of Bits, OpenZeppelin, Sherlock, Cyfrin, and other leading Web3 security firms.

## Architecture

```
SKILL.md                        # Entry point - 5-phase audit workflow
references/
├── vulnerability-taxonomy.md   # 40+ vulnerability types with code
├── defi-checklist.md           # Protocol + token checklists
├── tool-integration.md         # Slither, Echidna, Foundry, custom detectors
├── industry-standards.md       # SWC table, severity classification, EIPs
├── automated-detection.md      # Regex patterns for scanning
├── audit-questions.md          # Questions per function type
├── secure-patterns.md          # Secure code reference
├── report-template.md          # Audit report format
├── poc-templates.md            # Foundry PoC templates
├── invariants.md               # Protocol invariants
├── exploit-case-studies.md     # Real exploit analysis
├── quick-reference.md          # One-page cheat sheet
├── l2-crosschain.md            # L2 and cross-chain security
└── account-abstraction.md      # ERC-4337 smart accounts
```

**References** are loaded on-demand based on audit context. Files cross-reference each other to avoid duplication.

## Maintenance Guidelines

When updating this skill:

- **Vulnerability patterns**: Add to `vulnerability-taxonomy.md` with SWC ID, code examples (vulnerable + secure), and remediation
- **DeFi checklists**: Add to `defi-checklist.md` organized by protocol type with checkbox format
- **Tool updates**: Update `tool-integration.md` with new commands, detectors, or configuration
- **Detection patterns**: Add regex patterns to `automated-detection.md` with severity and recommendation
- **New standards**: Update `industry-standards.md` with EIPs, firm methodologies, or severity classifications
- **L2/Cross-chain**: Add new L2 networks, bridge patterns, or sequencer feeds to `l2-crosschain.md`
- **Quick reference**: Keep `quick-reference.md` as a condensed 1-page cheat sheet (avoid bloating)
- **Account Abstraction**: Add new ERC-4337 patterns, Entry Point versions, or AA wallet vulnerabilities to `account-abstraction.md`

## Severity Classification

Follow Immunefi/Sherlock/Code4rena standard:
- **Critical**: Direct loss of funds, permanent protocol corruption
- **High**: Conditional loss of funds, significant disruption
- **Medium**: Indirect loss, limited impact with specific conditions
- **Low**: Best practice violations, theoretical edge cases
- **Informational**: Code quality, gas optimizations
