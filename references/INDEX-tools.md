# Index: Tools, Detection Patterns & PoC Templates

Sub-index for tooling, automated detection, and proof-of-concept templates.
→ For vulnerability types see [INDEX-vulns.md](INDEX-vulns.md)
→ For DeFi protocols/invariants see [INDEX-defi.md](INDEX-defi.md)
→ For infrastructure/advanced topics see [INDEX-advanced.md](INDEX-advanced.md)

---

## By Tool

| Tool | File | Section |
|------|------|---------|
| Slither — static analysis | tool-integration.md | §1 Slither |
| Slither triage — 200 findings, priority order, FP identification guide | tool-integration.md | §1 Slither Triage Cheat Sheet |
| Slither triage — false positive patterns per detector | tool-integration.md | §1 Triage → FP Guide |
| Slither triage — `.slither.config.json` suppression | tool-integration.md | §1 Triage → Config |
| Slither triage — `slither-check-upgradeability` workflow | tool-integration.md | §1 Triage → Upgradeability |
| Slither reports 200+ findings — how to triage efficiently | tool-integration.md | §1 Slither Triage Cheat Sheet |
| Aderyn v0.6 — LSP server, VS Code extension, CI integration | tool-integration.md | §2 Aderyn |
| Foundry Forge — testing & fuzzing | tool-integration.md | §3 Foundry |
| Echidna 2025 — verification mode, multi-solver, Foundry reproducer | tool-integration.md | §4 Echidna |
| Medusa — parallel fuzzing | tool-integration.md | §5 Medusa |
| Halmos + Recon — auto-reproducer generation (2025) | tool-integration.md | §6 Halmos |
| Certora Prover — formal verification | tool-integration.md | §7 Certora |
| Gas benchmarking (Foundry) | tool-integration.md | §8 Gas Benchmarking |
| Slang — AST-based analysis | tool-integration.md | §9 Slang |
| Custom Slither detectors | tool-integration.md | §10 Custom Detectors |
| Mythril — symbolic execution | tool-integration.md | §11 Mythril |
| Manticore — EVM simulation | tool-integration.md | §12 Manticore |
| Semgrep — pattern matching | tool-integration.md | §13 Semgrep |
| Wake — data flow analysis + fuzzing | tool-integration.md | §14 Wake |
| Kontrol — K Framework EVM-precise formal proofs | tool-integration.md | §15 Kontrol |
| Tool selection matrix (when to use which) | tool-integration.md | Tool Selection Matrix |
| Recommended audit pipeline | tool-integration.md | Recommended Audit Pipeline |
| Automated scan workflow | automated-detection.md | Automated Scan Workflow |

---

## By Automated Detection Pattern

| Pattern | File | Section |
|---------|------|---------|
| Oracle manipulation (spot price) | automated-detection.md | DeFi-Specific → Oracle Manipulation |
| Flash loan attack vector | automated-detection.md | DeFi-Specific → Flash Loan |
| Missing slippage protection | automated-detection.md | DeFi-Specific → Missing Slippage |
| ERC-777 reentrancy | automated-detection.md | DeFi-Specific → ERC777 |
| Donation attack (balanceOf shares) | automated-detection.md | DeFi-Specific → Donation Attack |
| Precision loss in division | automated-detection.md | DeFi-Specific → Precision Loss |
| Missing Chainlink staleness check | automated-detection.md | DeFi-Specific → Oracle Staleness |
| Unchecked ERC-20 transfer | automated-detection.md | DeFi-Specific → Unchecked Transfer |
| Front-running (reveal/claim functions) | automated-detection.md | DeFi-Specific → Front-Running |
| ERC-7702 delegatecall in receive() | automated-detection.md | ERC-7702 → Delegatecall |
| ERC-7702 nonce replay | automated-detection.md | ERC-7702 → Nonce Replay |
| ERC-7702 delegation phishing | automated-detection.md | ERC-7702 → Phishing |
| Transient storage without cleanup | automated-detection.md | Transient Storage → No Cleanup |
| Permit frontrunning | automated-detection.md | ERC-20 / Permit Patterns → Permit Frontrunning |
| Hardcoded addresses | automated-detection.md | Web3 General → Hardcoded Addresses |
| Console.log in production | automated-detection.md | Web3 General → Console.log |
| Floating pragma | automated-detection.md | Web3 General → Floating Pragma |
| Unlimited token approval | automated-detection.md | Web3 General → Unlimited Approval |

---

## By PoC Template

| Attack Type | File | Section |
|-------------|------|---------|
| Reentrancy | poc-templates.md | Reentrancy PoC |
| Flash loan + oracle manipulation | poc-templates.md | Flash Loan Attack PoC |
| Oracle manipulation | poc-templates.md | Oracle Manipulation PoC |
| Access control bypass | poc-templates.md | Access Control Bypass PoC |
| Vault inflation (first depositor) | poc-templates.md | First Depositor / Inflation Attack PoC |
| Signature replay | poc-templates.md | Signature Replay PoC |
| Governance attack | poc-templates.md | Governance Attack PoC |
| Uniswap V4 hook drain | poc-templates.md | Uniswap V4 Hook Drain PoC |
| Transient storage guard bypass | poc-templates.md | Transient Storage Reentrancy Guard Bypass PoC |
| ERC-7702 malicious delegation | poc-templates.md | ERC-7702 Malicious Delegation PoC |
| Simulation guard bypass (Safe/multisig) | poc-templates.md | Simulation Guard Bypass PoC |
| Supply chain / bytecode verification | poc-templates.md | Supply Chain Verification PoC |
