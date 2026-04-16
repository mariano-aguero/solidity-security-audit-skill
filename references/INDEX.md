# Reference Index

Topic-to-file:section map for fast lookup during audits.
Use this when you know what you're looking for but not which file covers it.

**This is a master index — load the relevant sub-index for your audit phase:**

| Category | Sub-Index | When to Load |
|----------|-----------|--------------|
| Vulnerability types, secure patterns | [INDEX-vulns.md](INDEX-vulns.md) | Phase 3 — Manual Review |
| DeFi protocols, tokens, invariants | [INDEX-defi.md](INDEX-defi.md) | Phase 4 — Protocol-Specific Review |
| Tools, detection patterns, PoC templates | [INDEX-tools.md](INDEX-tools.md) | Phase 2 — Automated Analysis / PoC writing |
| L2/AA/ZK/staking, quick lookup table | [INDEX-advanced.md](INDEX-advanced.md) | Phase 3–5 — Specialized contexts |

---

## Quick Category Guide

**Vulnerability Types** → [INDEX-vulns.md](INDEX-vulns.md)
Reentrancy, access control, integer math, oracle, flash loan, proxy, external calls, DoS, front-running, MEV, signatures, token standards, logic, gas, Solidity quirks, governance, cross-chain, ERC-7702, V4 hooks, transient storage, supply chain, ERC-6909, EOF, Solidity 0.9.0, PUSH0, ERC-1967, AI-generated code, secure patterns.

**DeFi Protocols & Invariants** → [INDEX-defi.md](INDEX-defi.md)
Lending, AMM/DEX, Uniswap V3/V4, modular lending, CeDeFi, RWA, options, prediction markets, Safe modules, ERC-4626 vaults, bridges, governance, staking, NFTs, restaking/LRT, EigenLayer AVS, intent protocols, perpetual DEX, tokens/airdrops, Chainlink, Aave, Curve, Balancer, invariant tests.

**Tools & Detection** → [INDEX-tools.md](INDEX-tools.md)
Slither (triage, FP guide, upgradeability), Aderyn v0.6, Foundry, Echidna, Medusa, Halmos, Certora, Slang, Mythril, Manticore, Semgrep, Wake, Kontrol. Automated detection patterns. PoC templates (reentrancy, flash loan, oracle, access control, vault inflation, signature replay, governance, V4 hook, ERC-7702, Safe).

**Infrastructure & Advanced Topics** → [INDEX-advanced.md](INDEX-advanced.md)
L2/cross-chain (Blast, zkEVM, EIP-4844, bridges, sequencers), ZK-VM (zkSync, Polygon CDK, Circom, Halo2, Risc0, SP1, Noir, folding schemes), Account Abstraction (ERC-4337, ERC-7579, EIP-7701), staking/Pectra (EIP-7002/7251/6110), Glamsterdam (EIP-7732/7928), re-audit methodology, severity trees, report formats, exploit case studies, industry standards, OWASP SC Top 10. **Includes "I found X, what do I do?" quick lookup table.**
