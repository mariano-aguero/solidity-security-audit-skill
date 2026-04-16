# Index: Infrastructure, Specialized Contexts & Quick Lookup

Sub-index for L2/cross-chain, account abstraction, staking, ZK, and the fast-pattern lookup table.
→ For vulnerability types see [INDEX-vulns.md](INDEX-vulns.md)
→ For DeFi protocols/invariants see [INDEX-defi.md](INDEX-defi.md)
→ For tools/detection/PoCs see [INDEX-tools.md](INDEX-tools.md)

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
| ZK-VM — ZK proof verification | zkvm-specific.md | §1 ZK Proof Verification |
| ZK-VM — EVM equivalence gaps (zkSync/zkEVM) | zkvm-specific.md | §2 EVM Equivalence Gaps |
| ZK circuit vulnerabilities (Circom/Halo2) | zkvm-specific.md | §3 ZK Circuit Vulnerabilities |
| ZK-coprocessor (Risc0, SP1) | zkvm-specific.md | §4 ZK-Coprocessor |
| Noir — unconstrained function risks | zkvm-specific.md | §7 |
| SP1 — cycle limit DoS + output integrity | zkvm-specific.md | §8 |
| Polygon CDK — sequencer + LxLy bridge | zkvm-specific.md | §9 |
| Folding schemes (Nova, SuperNova, HyperNova) | zkvm-specific.md | §10 |
| Cross-chain messaging (CCIP, Wormhole, LayerZero) | l2-crosschain.md | Cross-Chain Messaging Protocols |
| Blast L2 yield-bearing assets | l2-crosschain.md | Blast L2 |
| zkEVM-specific | l2-crosschain.md | zkEVM-Specific |
| EIP-4844 (blobs) security | l2-crosschain.md | EIP-4844 |
| L2 precompile security | l2-crosschain.md | L2 Precompile Security |
| L2 sequencer feeds (Chainlink) | l2-crosschain.md | L2 Sequencer Feeds |
| Cross-chain sandwich attack via source-chain event leakage | l2-crosschain.md | Cross-Chain Sandwich Attacks |
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
| Staking/consensus layer security (Pectra) | staking-consensus.md | (full file) |
| EIP-7002 — triggerable validator exits | staking-consensus.md | §1 EIP-7002 |
| EIP-7002 — mass forced exit attack | staking-consensus.md | §1.2.1 |
| EIP-7002 — partial withdrawal griefing | staking-consensus.md | §1.2.2 |
| EIP-7251 — MaxEB slashing amplification | staking-consensus.md | §2 EIP-7251 |
| EIP-7251 — consolidation race conditions | staking-consensus.md | §2.2 |
| EIP-6110 — validator deposit front-running | staking-consensus.md | §3 EIP-6110 |
| Pectra combined attack scenarios | staking-consensus.md | §4 Combined Attacks |
| Post-Pectra staking audit checklist | staking-consensus.md | §5 Checklist |
| EIP-7732 ePBS — payload withholding | glamsterdam.md | §1 |
| EIP-7928 BALs — MEV transparency | glamsterdam.md | §2 |
| Re-audit / diff audit methodology | diff-audit.md | (full file) |
| Severity classification decision trees | severity-decision-tree.md | (full file) |
| Audit report format (private) | report-template.md | Report Structure |
| Contest submission format (Code4rena, Sherlock) | report-template.md | Contest Submission Format |
| Real exploit case studies | exploit-case-studies.md | (full file) |
| xUSD / Stream Finance exploit analysis | exploit-case-studies.md | #15 |
| Hyperliquid HLP exploit analysis | exploit-case-studies.md | #16 |
| Ronin Bridge — validator threshold + stale permissions ($625M) | exploit-case-studies.md | #17 |
| Mango Markets — self-trading oracle manipulation ($117M) | exploit-case-studies.md | #18 |
| BNB Chain Bridge — Merkle proof forgery via iavl library bug ($570M) | exploit-case-studies.md | #19 |
| Multichain — MPC key centralization, CEO arrested ($130M) | exploit-case-studies.md | #20 |
| Audit questions by function type | audit-questions.md | (full file) |
| One-page cheat sheet | quick-reference.md | (full file) |
| Industry standards (SWC, EIPs, firms) | industry-standards.md | (full file) |
| OWASP Smart Contract Top 10 (2025) | industry-standards.md | OWASP SC Top 10 |

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
| Bridge validator threshold ≤ 5/9 or stale temporary validator grant | exploit-case-studies #17 (Ronin), l2-crosschain Bridge Security |
| Lending protocol prices collateral from its own internal DEX spot market | exploit-case-studies #18 (Mango), taxonomy §4.1 + §4.3 |
| Bridge verifies Merkle proof using off-chain library (Go/Rust) without independent audit | exploit-case-studies #19 (BNB Chain), taxonomy §16 |
| RWA pool where NAV is set by a single admin with no time-lock | defi-checklist RWA → Off-Chain Trust |
| Options protocol settling at a spot price (not TWAP) | defi-checklist Options → Settlement Oracle |
| Prediction market with a single centralized resolver, no dispute mechanism | defi-checklist Prediction Markets → Resolution |
| Safe with a module that has state variables (potential storage collision) | defi-checklist Safe Modules → Storage Collisions |
| `enableModule()` callable without owner threshold | defi-checklist Safe Modules → Installation |
| Bridge uses MPC / TSS with all key operators in one jurisdiction | exploit-case-studies #20 (Multichain), taxonomy §16 |
| No emergency pause mechanism independent of the compromised key | exploit-case-studies #20 (Multichain) |
| `delete` on transient variable (compiler 0.8.28–0.8.33 + via-ir) | taxonomy §19.8 (TransientStorageClearingHelperCollision) |
| EIP-7702 sweeper delegation / `tx.origin == msg.sender` bypass | taxonomy §17.6, automated-detection ERC-7702 |
| `sweepUnclaimed()` without timelock or access control | defi-checklist Points & Airdrop → Merkle-Based |
| Cross-chain swap with minAmountOut in source-chain event | taxonomy §9.5, l2-crosschain Cross-Chain Sandwich |
| Oracle chain with multiple adapters (restaking assets) | taxonomy §4.6 (Moonwell pattern) |
| `payable(addr).transfer()` or `.send()` found | taxonomy §23 (Solidity 0.9.0 removal + reentrancy surface) |
| Solidity 0.8.20+ deployed on non-Ethereum chain without evmVersion lock | taxonomy §24 (PUSH0 cross-chain) |
| `upgradeTo()` without proxiableUUID check / UUPS proxy | taxonomy §25.3 (brick attack) |
| Raw `sstore` with hardcoded large slot value in implementation | taxonomy §25.2 (ERC-1967 collision) |
| Storage variables reordered between V1 and V2 upgrade | taxonomy §25.5 (layout migration) |
