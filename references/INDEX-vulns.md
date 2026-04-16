# Index: Vulnerability Types & Secure Patterns

Sub-index for vulnerability taxonomy and secure pattern reference.
→ DeFi protocols/invariants: [INDEX-defi.md](INDEX-defi.md) | Tools/PoCs: [INDEX-tools.md](INDEX-tools.md) | Infrastructure: [INDEX-advanced.md](INDEX-advanced.md)

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
| Arithmetic — overflow sentinel value in custom math libs (Cetus pattern) | vulnerability-taxonomy.md | §3.4 |
| Oracle — spot price dependency | vulnerability-taxonomy.md | §4.1 |
| Oracle — stale price / no staleness check | vulnerability-taxonomy.md | §4.2 |
| Oracle — centralization risk | vulnerability-taxonomy.md | §4.3 |
| Oracle — L2 sequencer dependency | vulnerability-taxonomy.md | §4.4 |
| Oracle — ERC-7726 false validity assumption | vulnerability-taxonomy.md | §4.5 |
| Oracle — chain complexity for restaking assets (Moonwell pattern) | vulnerability-taxonomy.md | §4.6 |
| Oracle — price hardcoding as contagion amplifier (xUSD/Stream Finance $285M) | vulnerability-taxonomy.md | §4.7 |
| Flash loan — governance attack | vulnerability-taxonomy.md | §5.1 |
| Flash loan — price manipulation | vulnerability-taxonomy.md | §5.2 |
| Flash loan — collateral ratio manipulation | vulnerability-taxonomy.md | §5.3 |
| Proxy — storage collision | vulnerability-taxonomy.md | §6.1 |
| Proxy — uninitialized implementation | vulnerability-taxonomy.md | §6.2 |
| Proxy — function selector clash | vulnerability-taxonomy.md | §6.3 |
| Proxy — UUPS missing authorization | vulnerability-taxonomy.md | §6.4 |
| Proxy — storage layout changes on upgrade | vulnerability-taxonomy.md | §6.5 |
| Proxy — OZ v4→v5 storage slot migration break (ERC-7201 namespace change) | vulnerability-taxonomy.md | §6.6 |
| Proxy / Storage — custom layout collisions (solc 0.8.29, --via-ir, multiple inheritance) | vulnerability-taxonomy.md | §6.7 |
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
| Front-running — cross-chain sandwich via source-chain event leakage | vulnerability-taxonomy.md | §9.5 |
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
| Logic — phantom collateral via failed external call (Abracadabra pattern) | vulnerability-taxonomy.md | §12.6 |
| Logic — multi-action router security flag reset (cook() bypass pattern) | vulnerability-taxonomy.md | §12.7 |
| Gas — storage vs memory vs calldata | vulnerability-taxonomy.md | §13.1 |
| Gas — redundant storage reads | vulnerability-taxonomy.md | §13.2 |
| Gas — packed storage | vulnerability-taxonomy.md | §13.3 |
| Gas — immutable and constant | vulnerability-taxonomy.md | §13.4 |
| Gas — unchecked arithmetic for safe ops | vulnerability-taxonomy.md | §13.5 |
| Gas — custom errors | vulnerability-taxonomy.md | §13.6 |
| Solidity — floating pragma | vulnerability-taxonomy.md | §14.1 |
| Solidity — shadowed variables | vulnerability-taxonomy.md | §14.2 |
| Solidity — incorrect inheritance order | vulnerability-taxonomy.md | §14.3 |
| Solidity — uninitialized storage pointers | vulnerability-taxonomy.md | §14.4 |
| Solidity — selfdestruct risks | vulnerability-taxonomy.md | §14.5 |
| Solidity — block properties as randomness | vulnerability-taxonomy.md | §14.6 |
| Solidity — MCOPY opcode misuse (EIP-5656, 0.8.25+) | vulnerability-taxonomy.md | §14.7 |
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
| ERC-7702 — sweeper campaigns and tx.origin guard bypass (post-Pectra, $2.5M+) | vulnerability-taxonomy.md | §17.6 |
| Uniswap V4 — hook vulnerabilities (all) | vulnerability-taxonomy.md | §18 |
| Uniswap V4 — LDF rounding attack (Bunni $8.4M pattern) | vulnerability-taxonomy.md | §18.6 |
| Transient storage — all issues | vulnerability-taxonomy.md | §19 |
| Transient storage — TSTORE Poison compiler bug (solc 0.8.28–0.8.33, via-ir) | vulnerability-taxonomy.md | §19.6 |
| Transient storage — 2300-gas stipend bypass via TSTORE | vulnerability-taxonomy.md | §19.7 |
| Transient storage — `delete` emits wrong opcode (0.8.28–0.8.33) | vulnerability-taxonomy.md | §19.8 |
| Supply chain & build system attacks | vulnerability-taxonomy.md | §20 |
| ERC-6909 — dual approval model confusion | vulnerability-taxonomy.md | §21.1 |
| ERC-6909 — donation / inflation attack (no totalSupply) | vulnerability-taxonomy.md | §21.2 |
| ERC-6909 — Uniswap V4 claim token misuse | vulnerability-taxonomy.md | §21.3 |
| EVM EOF — gas observability removed (GAS opcode) | vulnerability-taxonomy.md | §22.1 |
| EVM EOF — code observability removed (EXTCODESIZE breaks EOA check) | vulnerability-taxonomy.md | §22.2 |
| EVM EOF — EXTDELEGATECALL cannot target legacy contracts | vulnerability-taxonomy.md | §22.3 |
| EVM EOF — deploy-time validation breaks metaprogramming | vulnerability-taxonomy.md | §22.4 |
| Solidity 0.9.0 — transfer()/send() removed, reentrancy surface | vulnerability-taxonomy.md | §23 |
| Solidity 0.9.0 — send() silent failure → unchecked call() | vulnerability-taxonomy.md | §23.3 |
| PUSH0 opcode — cross-chain incompatibility (non-Shanghai chains) | vulnerability-taxonomy.md | §24 |
| PUSH0 opcode — evmVersion misconfiguration in foundry.toml / hardhat | vulnerability-taxonomy.md | §24.2 |
| ERC-1967 — proxy slot corruption, UUPS brick, delegatecall overwrite, layout migration | vulnerability-taxonomy.md | §25.2–§25.5 |
| AI-generated code — anti-patterns (CEI, access control, reentrancy guard, EIP-712 nonce) | ai-code-patterns.md | §2.1–§2.5 |
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
