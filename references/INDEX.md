# Reference Index

Topic-to-file:section map for fast lookup during audits.
Use this when you know what you're looking for but not which file covers it.

---

## By Vulnerability Type

| Topic | File | Section |
|-------|------|---------|
| Reentrancy — classic (single-function) | vulnerability-taxonomy.md | §1.1 |
| Reentrancy — cross-function | vulnerability-taxonomy.md | §1.2 |
| Reentrancy — cross-contract | vulnerability-taxonomy.md | §1.3 |
| Reentrancy — read-only | vulnerability-taxonomy.md | §1.4 |
| Reentrancy — transient storage guard (EIP-1153) | vulnerability-taxonomy.md | §1.5 |
| Reentrancy — ERC-1155 hook | vulnerability-taxonomy.md | §1.6 |
| Access control — missing modifiers | vulnerability-taxonomy.md | §2.1 |
| Access control — unprotected initializer | vulnerability-taxonomy.md | §2.2 |
| Access control — tx.origin auth | vulnerability-taxonomy.md | §2.3 |
| Access control — incorrect role hierarchy | vulnerability-taxonomy.md | §2.4 |
| Access control — single-step ownership transfer | vulnerability-taxonomy.md | §2.5 |
| Access control — AccessManager (OZ 5.x) | vulnerability-taxonomy.md | §2.6 |
| Integer overflow/underflow (unchecked blocks) | vulnerability-taxonomy.md | §3.1 |
| Division precision loss | vulnerability-taxonomy.md | §3.2 |
| Rounding direction attacks | vulnerability-taxonomy.md | §3.3 |
| Oracle — spot price dependency | vulnerability-taxonomy.md | §4.1 |
| Oracle — stale price / no staleness check | vulnerability-taxonomy.md | §4.2 |
| Oracle — centralization risk | vulnerability-taxonomy.md | §4.3 |
| Oracle — L2 sequencer dependency | vulnerability-taxonomy.md | §4.4 |
| Flash loan — governance attack | vulnerability-taxonomy.md | §5.1 |
| Flash loan — price manipulation | vulnerability-taxonomy.md | §5.2 |
| Flash loan — collateral ratio manipulation | vulnerability-taxonomy.md | §5.3 |
| Proxy — storage collision | vulnerability-taxonomy.md | §6.1 |
| Proxy — uninitialized implementation | vulnerability-taxonomy.md | §6.2 |
| Proxy — function selector clash | vulnerability-taxonomy.md | §6.3 |
| Proxy — UUPS missing authorization | vulnerability-taxonomy.md | §6.4 |
| Proxy — storage layout changes on upgrade | vulnerability-taxonomy.md | §6.5 |
| External call — unchecked return values | vulnerability-taxonomy.md | §7.1 |
| External call — delegatecall to untrusted contract | vulnerability-taxonomy.md | §7.2 |
| External call — unsafe external interaction | vulnerability-taxonomy.md | §7.3 |
| External call — gas griefing | vulnerability-taxonomy.md | §7.4 |
| DoS — unbounded loops | vulnerability-taxonomy.md | §8.1 |
| DoS — unexpected revert in loops | vulnerability-taxonomy.md | §8.2 |
| DoS — block gas limit manipulation | vulnerability-taxonomy.md | §8.3 |
| DoS — selfdestruct force-send ETH | vulnerability-taxonomy.md | §8.4 |
| Front-running — transaction ordering | vulnerability-taxonomy.md | §9.1 |
| Front-running — sandwich attack | vulnerability-taxonomy.md | §9.2 |
| Front-running — commit-reveal weakness | vulnerability-taxonomy.md | §9.3 |
| MEV — ERC-4337 / Account Abstraction | vulnerability-taxonomy.md | §9.4 |
| Signature — replay attack | vulnerability-taxonomy.md | §10.1 |
| Signature — malleability | vulnerability-taxonomy.md | §10.2 |
| Signature — missing signer validation | vulnerability-taxonomy.md | §10.3 |
| Signature — EIP-712 implementation errors | vulnerability-taxonomy.md | §10.4 |
| ERC-20 — fee-on-transfer / rebasing tokens | vulnerability-taxonomy.md | §11.1 |
| ERC-20 — missing return values | vulnerability-taxonomy.md | §11.2 |
| ERC-20 — approve race condition (permit frontrunning) | vulnerability-taxonomy.md | §11.3 |
| ERC-721 — safe mint reentrancy | vulnerability-taxonomy.md | §11.4 |
| ERC-4626 — vault inflation attack (first depositor) | vulnerability-taxonomy.md | §11.5 |
| Logic — incorrect state machine transitions | vulnerability-taxonomy.md | §12.1 |
| Logic — off-by-one errors | vulnerability-taxonomy.md | §12.2 |
| Logic — incorrect fee/reward calculations | vulnerability-taxonomy.md | §12.3 |
| Logic — missing slippage protection | vulnerability-taxonomy.md | §12.4 |
| Logic — inconsistent state after partial execution | vulnerability-taxonomy.md | §12.5 |
| Gas — storage vs memory vs calldata | vulnerability-taxonomy.md | §13.1 |
| Gas — redundant storage reads | vulnerability-taxonomy.md | §13.2 |
| Gas — packed storage | vulnerability-taxonomy.md | §13.3 |
| Gas — immutable and constant | vulnerability-taxonomy.md | §13.4 |
| Gas — unchecked arithmetic for safe ops | vulnerability-taxonomy.md | §13.5 |
| Gas — custom errors | vulnerability-taxonomy.md | §13.6 |
| Arithmetic — overflow sentinel value in custom math libs (Cetus pattern) | vulnerability-taxonomy.md | §3.4 |
| Oracle — ERC-7726 false validity assumption (standard provides no data guarantees) | vulnerability-taxonomy.md | §4.5 |
| Oracle — chain complexity for restaking assets (Moonwell pattern) | vulnerability-taxonomy.md | §4.6 |
| Oracle — price hardcoding as contagion amplifier (xUSD/Stream Finance $285M) | vulnerability-taxonomy.md | §4.7 |
| Proxy — OZ v4→v5 storage slot migration break (ERC-7201 namespace change) | vulnerability-taxonomy.md | §6.6 |
| Proxy / Storage — custom layout collisions (solc 0.8.29, --via-ir, multiple inheritance) | vulnerability-taxonomy.md | §6.7 |
| Front-running — cross-chain sandwich via source-chain event leakage (21.4% profit rate) | vulnerability-taxonomy.md | §9.5 |
| Logic — phantom collateral via failed external call (Abracadabra pattern) | vulnerability-taxonomy.md | §12.6 |
| Logic — multi-action router security flag reset (cook() bypass pattern) | vulnerability-taxonomy.md | §12.7 |
| Uniswap V4 — LDF rounding attack (Bunni $8.4M pattern) | vulnerability-taxonomy.md | §18.6 |
| ERC-7702 — sweeper campaigns and tx.origin guard bypass (post-Pectra, $2.5M+) | vulnerability-taxonomy.md | §17.6 |
| Transient storage — `delete` emits wrong opcode (TransientStorageClearingHelperCollision, 0.8.28–0.8.33) | vulnerability-taxonomy.md | §19.8 |
| Solidity — floating pragma | vulnerability-taxonomy.md | §14.1 |
| Solidity — shadowed variables | vulnerability-taxonomy.md | §14.2 |
| Solidity — incorrect inheritance order | vulnerability-taxonomy.md | §14.3 |
| Solidity — uninitialized storage pointers | vulnerability-taxonomy.md | §14.4 |
| Solidity — selfdestruct risks | vulnerability-taxonomy.md | §14.5 |
| Solidity — block properties as randomness | vulnerability-taxonomy.md | §14.6 |
| Solidity — MCOPY opcode misuse (EIP-5656, 0.8.25+) | vulnerability-taxonomy.md | §14.7 |
| EVM EOF — gas observability removed (GAS opcode) | vulnerability-taxonomy.md | §22.1 |
| EVM EOF — code observability removed (EXTCODESIZE breaks EOA check) | vulnerability-taxonomy.md | §22.2 |
| EVM EOF — EXTDELEGATECALL cannot target legacy contracts | vulnerability-taxonomy.md | §22.3 |
| EVM EOF — deploy-time validation breaks metaprogramming | vulnerability-taxonomy.md | §22.4 |
| Governance — flash loan attack | vulnerability-taxonomy.md | §15.1 |
| Governance — low quorum exploitation | vulnerability-taxonomy.md | §15.2 |
| Governance — timelock bypass | vulnerability-taxonomy.md | §15.3 |
| Governance — proposal griefing | vulnerability-taxonomy.md | §15.4 |
| Cross-chain — message verification | vulnerability-taxonomy.md | §16.1 |
| Cross-chain — replay across chains | vulnerability-taxonomy.md | §16.2 |
| Cross-chain — validator trust | vulnerability-taxonomy.md | §16.3 |
| Cross-chain — token wrapping accounting | vulnerability-taxonomy.md | §16.4 |
| ERC-7702 — malicious delegation target | vulnerability-taxonomy.md | §17.1 |
| ERC-7702 — signature replay / stale authorization | vulnerability-taxonomy.md | §17.2 |
| ERC-7702 — EOA nonce race condition | vulnerability-taxonomy.md | §17.3 |
| ERC-7702 — re-initialization of delegated code | vulnerability-taxonomy.md | §17.4 |
| Uniswap V4 — hook vulnerabilities | vulnerability-taxonomy.md | §18 |
| Transient storage — specific issues | vulnerability-taxonomy.md | §19 |
| Transient storage — TSTORE Poison compiler bug (solc 0.8.28–0.8.33, via-ir) | vulnerability-taxonomy.md | §19.6 |
| Transient storage — 2300-gas stipend bypass via TSTORE (transfer/send broken) | vulnerability-taxonomy.md | §19.7 |
| Supply chain & build system attacks | vulnerability-taxonomy.md | §20 |
| ERC-6909 — dual approval model confusion | vulnerability-taxonomy.md | §21.1 |
| ERC-6909 — donation / inflation attack (no totalSupply) | vulnerability-taxonomy.md | §21.2 |
| ERC-6909 — Uniswap V4 claim token misuse | vulnerability-taxonomy.md | §21.3 |
| AI-generated code — CEI violation | ai-code-patterns.md | §2.1 |
| AI-generated code — incomplete access control | ai-code-patterns.md | §2.2 |
| AI-generated code — hallucinated interfaces | ai-code-patterns.md | §2.3 |
| AI-generated code — broken reentrancy guard | ai-code-patterns.md | §2.4 |
| AI-generated code — EIP-712 missing nonce | ai-code-patterns.md | §2.5 |
| AI-generated code — detection red flags | ai-code-patterns.md | §1 |

---

## By Secure Pattern / Fix

| Topic | File | Section |
|-------|------|---------|
| Checks-Effects-Interactions (CEI) | secure-patterns.md | Reentrancy Protection → CEI |
| ReentrancyGuard (OZ) | secure-patterns.md | Reentrancy Protection → ReentrancyGuard |
| Transient storage reentrancy lock | secure-patterns.md | Reentrancy Protection → Transient Storage Lock |
| Ownable2Step | secure-patterns.md | Access Control → Ownable2Step |
| Role-based access (AccessControl) | secure-patterns.md | Access Control → Role-Based |
| Initializer protection (_disableInitializers) | secure-patterns.md | Access Control → Initializer |
| SafeERC20 | secure-patterns.md | Safe External Calls → SafeERC20 |
| Checking call return values | secure-patterns.md | Safe External Calls → Return Values |
| Safe delegatecall (immutable implementation) | secure-patterns.md | Safe External Calls → Safe Delegatecall |
| Chainlink with full validation | secure-patterns.md | Oracle Integration → Chainlink |
| L2 sequencer check | secure-patterns.md | Oracle Integration → L2 Sequencer |
| EIP-712 typed data signature | secure-patterns.md | Signature Handling → EIP-712 |
| SignatureChecker (ERC-1271, smart wallets) | secure-patterns.md | Signature Handling → SignatureChecker |
| UUPS proxy | secure-patterns.md | Proxy Patterns → UUPS |
| ERC-7201 namespaced storage | secure-patterns.md | Proxy Patterns → ERC-7201 |
| ERC-4626 with inflation protection | secure-patterns.md | Token Patterns → ERC-4626 |
| Fee-on-transfer token handling | secure-patterns.md | Token Patterns → Fee-on-Transfer |
| Snapshot voting (flash loan resistance) | secure-patterns.md | Governance Patterns → Snapshot |
| Pausable + guardian | secure-patterns.md | Emergency Patterns → Pausable |
| Circuit breaker (daily outflow limit) | secure-patterns.md | Emergency Patterns → Circuit Breaker |
| Pull payment pattern | secure-patterns.md | Pull Payment Pattern |
| Commit-reveal scheme | secure-patterns.md | Commit-Reveal Pattern |
| Timelock for admin operations | secure-patterns.md | Timelock Pattern |
| Merkle airdrop + duplicate-claim prevention | secure-patterns.md | Merkle Airdrop |
| EIP-1167 minimal proxy (clone factory) | secure-patterns.md | EIP-1167 Minimal Proxy |

---

## By Protocol / DeFi Context

| Context | File | Section |
|---------|------|---------|
| Lending (Aave/Compound/Morpho) — checklist | defi-checklist.md | Lending Protocols |
| Lending — integration pitfalls | defi-integrations.md | Compound V3 (Comet) |
| AMM / DEX — checklist | defi-checklist.md | AMMs & DEXs |
| Uniswap V3 integration | defi-integrations.md | Uniswap V3 |
| Uniswap V4 hooks — checklist | defi-checklist.md | Uniswap V4 Hooks Protocol |
| Uniswap V4 — JIT liquidity attack via hooks | defi-checklist.md | Uniswap V4 Hooks Protocol → JIT |
| Uniswap V4 — LDF rounding checklist | defi-checklist.md | Uniswap V4 Hooks Protocol → LDF |
| Uniswap V4 hooks — integration | defi-integrations.md | Uniswap V4 Hooks |
| Uniswap V4 math layer (TickMath, SqrtPriceMath, FullMath) | defi-integrations.md | V4 Math Layer Pitfalls |
| Modular lending — Morpho Blue permissionless markets | defi-checklist.md | Modular Lending Protocols |
| Modular lending — Euler V2 EVC cross-vault health | defi-checklist.md | Modular Lending Protocols → EVC |
| CeDeFi & Recursive Leverage — checklist | defi-checklist.md | CeDeFi & Recursive Leverage |
| V4 hook `onlyPoolManager` requirement (Cork Protocol $11M) | defi-checklist.md | Uniswap V4 Hooks → Callback Security |
| Airdrop — `sweepUnclaimed()` access control | defi-checklist.md | Points & Airdrop Protocols → Merkle-Based |
| Perpetual DEX — vault as liquidation absorber (Hyperliquid pattern) | perpetual-dex.md | §9 |
| Vault / ERC-4626 — checklist | defi-checklist.md | Vaults & Yield Aggregators |
| ERC-4626 vault integration | defi-integrations.md | ERC-4626 Vault Integration |
| Bridge / cross-chain — checklist | defi-checklist.md | Bridges & Cross-Chain |
| Governance DAO — checklist | defi-checklist.md | Governance |
| Staking — checklist | defi-checklist.md | Staking Protocols |
| NFT marketplace — checklist | defi-checklist.md | NFT Protocols |
| Restaking / LRT (EigenLayer) — checklist | defi-checklist.md | Restaking & LRT |
| Restaking — Karak DSS & Symbiotic resolvers | defi-checklist.md | Restaking & LRT → Karak & Symbiotic |
| EigenLayer AVS contracts — checklist | defi-checklist.md | EigenLayer AVS Contracts |
| Intent protocols (Permit2, UniswapX) — checklist | defi-integrations.md | Intent-Based Protocols |
| Intent protocols — deep reference | intent-protocols.md | (all sections) |
| Permit2 — nonce bitmap, witness hash | intent-protocols.md | §1 Signature & Nonce Security |
| UniswapX — Dutch auction, callback auth | intent-protocols.md | §2–3 |
| ERC-7683 — cross-chain intents (live on Base/Arbitrum) | intent-protocols.md | §8 ERC-7683 |
| ERC-7683 — filler trust model | intent-protocols.md | §8.2 Filler Trust Model |
| ERC-7683 — parameter substitution cross-chain | intent-protocols.md | §8.3 Parameter Substitution |
| ERC-7683 — double-fill / orderId collision | intent-protocols.md | §8.4 Double-Fill |
| ERC-7683 — settlement finality race | intent-protocols.md | §8.5 Settlement Finality Race |
| ERC-7683 — security checklist | intent-protocols.md | §8.9 ERC-7683 Checklist |
| Perpetual DEX — GMX v2, Synthetix Perps | perpetual-dex.md | (all sections) |
| Perpetual DEX — oracle, liquidation, LP | perpetual-dex.md | §1–4 |
| Perpetual DEX — PnL precision, leverage | perpetual-dex.md | §5 |
| ZK-VM — ZK proof verification | zkvm-specific.md | §1 ZK Proof Verification |
| ZK-VM — EVM equivalence gaps (zkSync/zkEVM) | zkvm-specific.md | §2 EVM Equivalence Gaps |
| ZK circuit vulnerabilities (Circom/Halo2) | zkvm-specific.md | §3 ZK Circuit Vulnerabilities |
| ZK-coprocessor (Risc0, SP1) | zkvm-specific.md | §4 ZK-Coprocessor |
| Points & airdrop — checklist | defi-checklist.md | Points & Airdrop Protocols |
| Token-specific (rebasing, FoT, USDT) | defi-checklist.md | Token-Specific Checklists |
| Chainlink integration | defi-integrations.md | Chainlink Price Feeds |
| Aave V3 flash loans | defi-integrations.md | Aave V3 Flash Loans |
| Curve integration | defi-integrations.md | Curve Finance |
| Balancer integration | defi-integrations.md | Balancer Integration |
| Multi-protocol integration bugs | defi-integrations.md | Common Multi-Protocol Integration Bugs |

---

## By Invariant Type

| Context | File | Section |
|---------|------|---------|
| Universal invariants (all protocols) | invariants.md | Universal Invariants |
| ERC-20 token invariants | invariants.md | ERC20 Token Invariants |
| ERC-4626 vault invariants | invariants.md | ERC4626 Vault Invariants |
| Lending protocol invariants | invariants.md | Lending Protocol Invariants |
| AMM / DEX invariants | invariants.md | AMM / DEX Invariants |
| Staking invariants | invariants.md | Staking Protocol Invariants |
| Governance invariants | invariants.md | Governance Invariants |
| Bridge invariants | invariants.md | Bridge Invariants |
| Uniswap V3 / concentrated liquidity | invariants.md | Uniswap V3 Invariants |
| Writing invariant tests (Foundry) | invariants.md | Writing Invariant Tests |
| Echidna invariant format | invariants.md | Echidna Invariant Format |

---

## By Tool

| Tool | File | Section |
|------|------|---------|
| Slither — static analysis | tool-integration.md | §1 Slither |
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

---

## By Infrastructure / Specialized Context

| Context | File | Section |
|---------|------|---------|
| L2 architecture overview | l2-crosschain.md | L2 Architecture |
| Sequencer risks | l2-crosschain.md | Sequencer Risks |
| L1 ↔ L2 message passing | l2-crosschain.md | L1 ↔ L2 Message Passing |
| Bridge security patterns | l2-crosschain.md | Bridge Security Patterns |
| Cross-chain reentrancy | l2-crosschain.md | Cross-Chain Reentrancy |
| Optimistic rollup specific | l2-crosschain.md | Optimistic Rollup |
| ZK rollup specific | l2-crosschain.md | ZK Rollup |
| ZK-VM (zkSync Era, Polygon zkEVM) — deep reference | zkvm-specific.md | §2 EVM Equivalence Gaps |
| ZK proof verification vulnerabilities | zkvm-specific.md | §1 ZK Proof Verification |
| ZK circuit under-constraining (Circom, Halo2) | zkvm-specific.md | §3 ZK Circuit Vulnerabilities |
| ZK-coprocessor (Risc0, SP1) on-chain verification | zkvm-specific.md | §4 ZK-Coprocessor |
| Cross-chain messaging (CCIP, Wormhole, LayerZero) | l2-crosschain.md | Cross-Chain Messaging Protocols |
| Blast L2 yield-bearing assets | l2-crosschain.md | Blast L2 |
| zkEVM-specific | l2-crosschain.md | zkEVM-Specific |
| EIP-4844 (blobs) security | l2-crosschain.md | EIP-4844 |
| L2 precompile security | l2-crosschain.md | L2 Precompile Security |
| L2 sequencer feeds (Chainlink) | l2-crosschain.md | L2 Sequencer Feeds |
| Cross-chain sandwich attack via source-chain event leakage (21.4% profit) | l2-crosschain.md | Cross-Chain Sandwich Attacks |
| Fusaka upgrade security — EIP-7825 per-tx gas cap (16.78M) | l2-crosschain.md | Fusaka Upgrade Security Implications |
| App-chain fork risk — inherited bugs (Berachain pattern) | l2-crosschain.md | App-Chain Fork Risk |
| ERC-4337 account architecture | account-abstraction.md | Architecture Overview |
| UserOperation structure | account-abstraction.md | UserOperation Structure |
| PackedUserOperation (v0.7 migration) | account-abstraction.md | UserOperation v0.7 |
| Smart account (wallet) vulnerabilities | account-abstraction.md | Account Vulnerabilities |
| Paymaster vulnerabilities | account-abstraction.md | Paymaster Vulnerabilities |
| Factory vulnerabilities (AA) | account-abstraction.md | Factory Vulnerabilities |
| Nonce management (AA) | account-abstraction.md | Nonce Management |
| Bundler considerations | account-abstraction.md | Bundler Considerations |
| Session keys | account-abstraction.md | Session Keys |
| EIP-7579 modular smart accounts | account-abstraction.md | EIP-7579 |
| ERC-7579 — module poisoning via `onUninstall` revert | account-abstraction.md | EIP-7579 → Module Poisoning via onUninstall Revert |
| ERC-7579 — stale state after module reinstallation | account-abstraction.md | EIP-7579 → Stale State After Module Reinstallation |
| ERC-7579 — executor module `delegatecall` abuse | account-abstraction.md | EIP-7579 → Executor Module delegatecall Abuse |
| ERC-7484 — module registry attestation | account-abstraction.md | EIP-7579 → ERC-7484 Module Registry |
| ERC-7821 — minimal batch executor for EIP-7702 delegation | account-abstraction.md | ERC-7821 |
| EIP-7701 native AA — ACCEPT_ROLE opcode risk | account-abstraction.md | EIP-7701 Native AA |
| AA checklist | account-abstraction.md | Checklist: Account Abstraction |
| Re-audit / diff audit methodology | diff-audit.md | (full file) |
| Severity classification decision trees | severity-decision-tree.md | (full file) |
| Audit report format (private) | report-template.md | Report Structure |
| Contest submission format (Code4rena, Sherlock) | report-template.md | Contest Submission Format |
| Real exploit case studies | exploit-case-studies.md | (full file) |
| Audit questions by function type | audit-questions.md | (full file) |
| One-page cheat sheet | quick-reference.md | (full file) |
| Industry standards (SWC, EIPs, firms) | industry-standards.md | (full file) |
| OWASP Smart Contract Top 10 (2025) | industry-standards.md | OWASP SC Top 10 |
| Staking/consensus layer security (Pectra) | staking-consensus.md | (full file) |
| EIP-7002 — triggerable validator exits | staking-consensus.md | §1 EIP-7002 |
| EIP-7002 — mass forced exit attack | staking-consensus.md | §1.2.1 |
| EIP-7002 — partial withdrawal griefing | staking-consensus.md | §1.2.2 |
| EIP-7251 — MaxEB slashing amplification | staking-consensus.md | §2 EIP-7251 |
| EIP-7251 — consolidation race conditions | staking-consensus.md | §2.2 |
| EIP-6110 — validator deposit front-running | staking-consensus.md | §3 EIP-6110 |
| Pectra combined attack scenarios | staking-consensus.md | §4 Combined Attacks |
| Post-Pectra staking audit checklist | staking-consensus.md | §5 Checklist |

---

## Quick Lookup: "I found X, what do I do?"

| What you found | Start here |
|----------------|------------|
| Uses `balanceOf(address(this))` for share math | taxonomy §11.5, checklist Vaults, detection Donation Attack |
| Uses `getReserves()` or spot price | taxonomy §4.1, detection Oracle Manipulation |
| `latestRoundData()` without staleness | taxonomy §4.2, detection Missing Oracle Staleness |
| `transfer()` without checking return | taxonomy §11.2, detection Unchecked ERC-20 Transfer |
| `delegatecall` to user-controlled address | taxonomy §7.2, secure-patterns Safe Delegatecall |
| `initialize()` without `initializer` modifier | taxonomy §2.2, secure-patterns Initializer |
| Flash loan in same tx as governance vote | taxonomy §5.1 + §15.1, invariants Governance |
| Swap with `amountOutMin = 0` | taxonomy §12.4, detection Missing Slippage |
| `tstore` without cleanup | automated-detection Transient Storage, taxonomy §19 |
| ERC-7702 authorization tuple | taxonomy §17, automated-detection ERC-7702, PoC ERC-7702 |
| Safe/multisig module approval | poc-templates Simulation Guard Bypass, case-studies Bybit |
| Merkle claim without bitmap | secure-patterns Merkle Airdrop |
| Clone/minimal proxy factory | secure-patterns EIP-1167, taxonomy §6.2 |
| `permit()` call that can be front-run | automated-detection Permit Frontrunning, taxonomy §11.3 |
| ERC-7683 `fill()` without orderId tracking | intent-protocols §8.4 Double-Fill |
| ERC-7683 `originData` not verified against orderId | intent-protocols §8.3 Parameter Substitution |
| ERC-7683 contract uses `msg.sender == user` auth | intent-protocols §8.2 Filler Trust Model |
| Liquid staking with `triggerValidatorExit()` | staking-consensus §1 EIP-7002 |
| Staking insurance fund sized for 32 ETH max | staking-consensus §2.1 Slashing Amplification |
| Validator consolidation with BLS not verified | staking-consensus §2.2 Consolidation Race |
| Two-step deposit (pubkey then credentials separate) | staking-consensus §3.1 Deposit Front-Running |
| ERC-6909 dual approval — `isOperator` bypasses allowance | taxonomy §21.1 |
| ERC-6909 with V4 PoolManager claim tokens | taxonomy §21.3 |
| MEV bot without `onlyOwner` on sweep | defi-checklist MEV Bot Contracts |
| AI-generated code — missing `nonReentrant`, CEI violations | audit-questions AI-Generated Code |
| V4 hook with no `msg.sender == poolManager` check | defi-checklist V4 Hooks, taxonomy §18, case-studies Cork Protocol |
| Batch router boolean flag that can be reset to `false` | taxonomy §12.7 (Abracadabra cook() pattern) |
| Collateral price hardcoded at `$1.00` | taxonomy §4.7 (xUSD/Stream Finance), defi-checklist CeDeFi |
| ERC-7579 module installation — `onUninstall` revert risk | account-abstraction EIP-7579 → Module Poisoning |
| Community vault absorbing liquidations | perpetual-dex §9 (Hyperliquid HLP pattern) |
| `delete` on transient variable (compiler 0.8.28–0.8.33 + via-ir) | taxonomy §19.8 (TransientStorageClearingHelperCollision) |
| EIP-7702 sweeper delegation / `tx.origin == msg.sender` bypass | taxonomy §17.6, automated-detection ERC-7702 |
| `sweepUnclaimed()` without timelock or access control | defi-checklist Points & Airdrop → Merkle-Based |
| Cross-chain swap with minAmountOut in source-chain event | taxonomy §9.5, l2-crosschain Cross-Chain Sandwich |
| Oracle chain with multiple adapters (restaking assets) | taxonomy §4.6 (Moonwell pattern) |
| dYdX v4 — off-chain CLOB trust model | perpetual-dex.md | §10 |
| Gains Network — DAI vault counterparty | perpetual-dex.md | §11 |
| Funding rate — skew manipulation | perpetual-dex.md | §12 |
| Insurance fund drain attacks | perpetual-dex.md | §13 |
| Cross-margin contagion / isolated-to-cross | perpetual-dex.md | §14 |
| Noir — unconstrained function risks | zkvm-specific.md | §7 |
| SP1 — cycle limit DoS + output integrity | zkvm-specific.md | §8 |
| Polygon CDK — sequencer + LxLy bridge | zkvm-specific.md | §9 |
| Folding schemes (Nova, SuperNova, HyperNova) | zkvm-specific.md | §10 |
| EIP-7732 ePBS — payload withholding | glamsterdam.md | §1 |
| EIP-7928 BALs — MEV transparency | glamsterdam.md | §2 |
| xUSD / Stream Finance exploit analysis | exploit-case-studies.md | #15 |
| Hyperliquid HLP exploit analysis | exploit-case-studies.md | #16 |
