# Index: DeFi Protocols, Tokens & Invariants

Sub-index for DeFi protocol security and invariant testing.
→ For vulnerability types see [INDEX-vulns.md](INDEX-vulns.md)
→ For tools/detection/PoCs see [INDEX-tools.md](INDEX-tools.md)
→ For infrastructure/advanced topics see [INDEX-advanced.md](INDEX-advanced.md)

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
| V4 hook `onlyPoolManager` requirement (Cork Protocol $11M) | defi-checklist.md | Uniswap V4 Hooks → Callback Security |
| Modular lending — Morpho Blue permissionless markets | defi-checklist.md | Modular Lending Protocols |
| Modular lending — Euler V2 EVC cross-vault health | defi-checklist.md | Modular Lending Protocols → EVC |
| CeDeFi & Recursive Leverage — checklist | defi-checklist.md | CeDeFi & Recursive Leverage |
| RWA — deep reference | rwa-protocols.md | (all sections) |
| RWA — trust model, pool manager privilege | rwa-protocols.md | §1 Trust Model & Architecture |
| RWA — NAV oracle manipulation, stale NAV | rwa-protocols.md | §2 NAV Oracle Manipulation |
| RWA — epoch redemption race conditions | rwa-protocols.md | §3 Epoch Redemption Race Conditions |
| RWA — senior/junior tranche accounting | rwa-protocols.md | §4 Tranche Accounting Attacks |
| RWA — KYC/transfer restriction bypass | rwa-protocols.md | §5 KYC/Transfer Restriction Bypass |
| RWA — default handling, write-down timing | rwa-protocols.md | §6 Default Handling |
| RWA — Centrifuge, Maple, T-bill vaults | rwa-protocols.md | §7 Protocol-Specific Patterns |
| RWA — comprehensive audit checklist | rwa-protocols.md | §8 RWA Audit Checklist |
| RWA — high-level checklist | defi-checklist.md | Real World Assets |
| Options — settlement oracle manipulation at expiry | defi-checklist.md | Options → Settlement Oracle |
| Options — IV manipulation in AMM-based pricing | defi-checklist.md | Options → IV and Pricing |
| Options — undercollateralized option writing | defi-checklist.md | Options → Collateral and Writing |
| Options vault (Ribbon-style) — adversarial strike selection | defi-checklist.md | Options → Automated Vaults |
| Prediction market — resolver/oracle bribe attack | defi-checklist.md | Prediction Markets → Resolution |
| Prediction market — CTF conditional token merge attack | defi-checklist.md | Prediction Markets → CTF Logic |
| Prediction market — AMM price outside [0,1] | defi-checklist.md | Prediction Markets → AMM |
| Safe module — storage collision via delegatecall | defi-checklist.md | Gnosis Safe Modules → Storage Collisions |
| Safe module — `enableModule()` without time-lock | defi-checklist.md | Gnosis Safe Modules → Installation |
| Safe guard — bypassed via `execTransactionFromModule()` | defi-checklist.md | Gnosis Safe Modules → Guards |
| Safe recovery module — guardian grief / time-lock reset | defi-checklist.md | Gnosis Safe Modules → Recovery |
| Airdrop — `sweepUnclaimed()` access control | defi-checklist.md | Points & Airdrop Protocols → Merkle-Based |
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
| Perpetual DEX — vault as liquidation absorber (Hyperliquid pattern) | perpetual-dex.md | §9 |
| dYdX v4 — off-chain CLOB trust model | perpetual-dex.md | §10 |
| Gains Network — DAI vault counterparty | perpetual-dex.md | §11 |
| Funding rate — skew manipulation | perpetual-dex.md | §12 |
| Insurance fund drain attacks | perpetual-dex.md | §13 |
| Cross-margin contagion / isolated-to-cross | perpetual-dex.md | §14 |
| Points & airdrop — checklist | defi-checklist.md | Points & Airdrop Protocols |
| Token-specific (rebasing, FoT, USDT) | defi-checklist.md | Token-Specific Checklists |
| Chainlink integration | defi-integrations.md | Chainlink Price Feeds |
| Aave V3 flash loans | defi-integrations.md | Aave V3 Flash Loans |
| Curve integration | defi-integrations.md | Curve Finance |
| Balancer integration | defi-integrations.md | Balancer Integration |
| Multi-protocol integration bugs | defi-integrations.md | Common Multi-Protocol Integration Bugs |
| Slither fires `reentrancy-eth` but `nonReentrant` is present | tool-integration.md | §1 Triage → FP Guide → reentrancy-eth |
| Slither fires `unchecked-transfer` but SafeERC20 is used | tool-integration.md | §1 Triage → FP Guide → unchecked-transfer |

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
