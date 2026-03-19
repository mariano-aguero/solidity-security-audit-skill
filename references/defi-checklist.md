# DeFi-Specific Audit Checklist

Specialized security checklist organized by protocol type.

---

## Universal DeFi Checks (Apply to ALL DeFi protocols)

### Token Interaction
- [ ] Does the protocol handle fee-on-transfer tokens correctly?
- [ ] Does the protocol handle rebasing tokens correctly?
- [ ] Does the protocol handle tokens with non-standard decimals (e.g., USDC=6, WBTC=8)?
- [ ] Does the protocol use SafeERC20 for all token interactions?
- [ ] Is the protocol safe against ERC-777 callback reentrancy?
- [ ] Does the protocol validate token addresses are not zero?
- [ ] Does the protocol handle tokens that return `false` instead of reverting?
- [ ] Does the protocol handle tokens with multiple entry points (e.g., proxy tokens)?
- [ ] Does the protocol handle tokens with blacklist functionality (USDC, USDT)?

### Oracle & Price Feeds
- [ ] Are oracle prices validated for staleness?
- [ ] Is there a fallback mechanism if the primary oracle fails?
- [ ] Are prices resistant to flash loan manipulation?
- [ ] Is the oracle decentralized enough (not single point of failure)?
- [ ] On L2s: is the sequencer uptime checked before using prices?
- [ ] Are TWAP windows long enough to resist manipulation?
- [ ] Are spot prices NEVER used for critical calculations?

### Flash Loan Resistance
- [ ] Can any critical function's behavior be changed by flash-loaned tokens?
- [ ] Are governance actions protected against flash loan voting?
- [ ] Do lending pools account for flash loan manipulation of collateral?
- [ ] Are share-price calculations resistant to single-block manipulation?

### Economic Security
- [ ] Is there slippage protection on all swap/conversion operations?
- [ ] Are deadlines enforced on time-sensitive operations?
- [ ] Does the fee structure prevent extraction of value through rounding?
- [ ] Are withdrawal limits in place to prevent bank-run scenarios?
- [ ] Is there circuit breaker / pause functionality for emergencies?

### Access Control
- [ ] Is there a clear separation of admin roles (deployer, operator, guardian)?
- [ ] Are admin functions behind timelocks for critical operations?
- [ ] Is there multisig requirement for high-impact actions?
- [ ] Can admin keys be rotated without disrupting the protocol?
- [ ] Are emergency functions appropriately restricted?
- [ ] Does any function use `tx.origin == msg.sender` or `tx.origin` as an auth guard? Post-Pectra (ERC-7702), EOAs can delegate execution — this check no longer reliably identifies EOA callers (see `vulnerability-taxonomy.md §17.6`)
- [ ] Does the protocol assume `msg.sender` cannot be a smart contract with EOA privileges? ERC-7702 delegated EOAs break this assumption.

---

## Lending Protocols (Aave, Compound, Morpho-style)

### Core Lending Logic
- [ ] Is the interest rate model correctly implemented?
- [ ] Do utilization rate calculations handle edge cases (0 supply, 100% utilization)?
- [ ] Is accrued interest correctly calculated and distributed?
- [ ] Are exchange rates between underlying and receipt tokens monotonically increasing?

### Collateral Management
- [ ] Are collateral factors set appropriately per asset?
- [ ] Can collateral factors be changed while positions are open?
- [ ] Is there a delay/buffer on collateral factor changes to prevent immediate liquidations?
- [ ] Does the protocol handle multiple collateral types safely?

### Liquidation
- [ ] Is the liquidation threshold set correctly relative to collateral factor?
- [ ] Can liquidations happen atomically (flash loan liquidation)?
- [ ] Is the liquidation bonus/incentive appropriate?
- [ ] Can partial liquidations leave dust positions?
- [ ] Does the protocol handle bad debt correctly?
- [ ] Is there a mechanism to socialize bad debt fairly?
- [ ] Can a liquidation be sandwiched to extract extra value?

### Borrowing
- [ ] Are borrow limits enforced correctly at time of borrowing?
- [ ] Are borrow limits re-checked on any action that could change health factor?
- [ ] Can a user borrow and immediately be liquidatable (rounding issues)?
- [ ] Is there protection against borrowing the same token used as collateral?

---

## AMMs & DEXs (Uniswap, Curve, Balancer-style)

### Pool Logic
- [ ] Are pool invariants (x*y=k, StableSwap, etc.) correctly maintained?
- [ ] Can pool reserves be manipulated via direct token transfers?
- [ ] Are virtual reserves / concentrated liquidity bounds correct?
- [ ] Is the pool's fee calculation correct and resistant to gaming?

### LP Token Accounting
- [ ] Is LP token minting proportional to liquidity provided?
- [ ] Is LP token burning proportional to liquidity removed?
- [ ] Is the first deposit handled correctly (initialization)?
- [ ] Are LP shares resistant to inflation/deflation attacks?
- [ ] Does the protocol lock minimum liquidity to prevent share manipulation?

### Swaps
- [ ] Is slippage protection enforced (amountOutMin)?
- [ ] Is deadline enforced on swap transactions?
- [ ] Are swap calculations correct across all price ranges?
- [ ] Is the router safe against token transfer fee accounting issues?

### Price Impact & MEV
- [ ] Is there maximum price impact protection?
- [ ] Is the pool vulnerable to sandwich attacks?
- [ ] Are there anti-sniping mechanisms for new pool creation?
- [ ] Is TWAP implementation resistant to manipulation?

---

## Vaults & Yield Aggregators (Yearn, ERC-4626 style)

### Share Accounting
- [ ] Is the vault ERC-4626 compliant (if applicable)?
- [ ] Is the share-to-asset ratio calculated correctly?
- [ ] Is the vault resistant to inflation/donation attacks?
  - First depositor deposits 1 wei
  - Attacker donates large amount directly
  - Second depositor receives 0 shares
- [ ] Is there a virtual offset or minimum deposit to prevent this?
- [ ] Do `deposit` and `mint` calculate shares consistently?
- [ ] Do `withdraw` and `redeem` calculate assets consistently?

### Strategy Interactions
- [ ] Are strategy harvest/compound functions access controlled?
- [ ] Can strategy losses be socialized across all depositors fairly?
- [ ] Is there a withdrawal queue or instant liquidity guarantee?
- [ ] Are unrealized profits handled correctly?
- [ ] Can a strategy be emergency-withdrawn?

### Fees
- [ ] Are management/performance fees calculated on the correct base?
- [ ] Can fees be extracted retroactively from existing depositors?
- [ ] Are fee calculations resistant to timing attacks?
- [ ] Is there a maximum fee cap to protect users?

---

## Bridges & Cross-Chain Protocols

### Message Passing
- [ ] Are messages signed by a sufficient number of validators?
- [ ] Is there replay protection (nonce per chain)?
- [ ] Can messages be reordered or skipped?
- [ ] Is there validation of source chain identity?
- [ ] Are message timeouts/expirations enforced?

### Token Bridging
- [ ] Does lock-and-mint accounting balance correctly?
- [ ] Is there overflow risk in token amount conversion between chains?
- [ ] Can a failed message on the destination chain be retried or refunded?
- [ ] Are bridged token supplies capped appropriately?

### Validator Security
- [ ] What is the validator set size and threshold for consensus?
- [ ] Can validators be rotated securely?
- [ ] Is there slashing for malicious validators?
- [ ] Are validator keys managed with appropriate security (MPC, HSM)?

---

## Governance (Governor, DAO-style)

### Voting
- [ ] Is voting power snapshot-based (not current balance)?
- [ ] Is there a voting delay to prevent flash-loan governance?
- [ ] Is quorum set at a reasonable level?
- [ ] Are votes delegatable? If so, is delegation secure?
- [ ] Can a user vote, transfer tokens, and vote again from another address?

### Proposals
- [ ] Is there a minimum proposal threshold?
- [ ] Can proposals include arbitrary calldata?
- [ ] Is there a timelock between proposal approval and execution?
- [ ] Can proposals be cancelled after passing?
- [ ] Is there griefing protection against proposal spam?

### Execution
- [ ] Are executed proposals marked to prevent re-execution?
- [ ] Can governance execute self-destructive actions?
- [ ] Is there an emergency bypass mechanism? If so, who controls it?
- [ ] Are governance actions bounded (e.g., max parameter changes per proposal)?

---

## Staking Protocols

### Reward Distribution
- [ ] Is the reward-per-share accumulator pattern correctly implemented?
- [ ] Are rewards calculated with sufficient precision?
- [ ] Can a user flash-stake to claim disproportionate rewards?
- [ ] Is there a minimum staking duration?
- [ ] Are pending rewards correctly handled during unstake?

### Staking/Unstaking
- [ ] Is there a cooldown period for unstaking?
- [ ] Can the unstaking queue be griefed (DoS)?
- [ ] Is there a cap on total staked amount?
- [ ] Are staking positions transferable? Should they be?

### Slashing
- [ ] Is the slashing mechanism fair and bounded?
- [ ] Can slashing affect users who unstaked before the infraction?
- [ ] Is there a slashing committee or oracle? What's their trust model?

---

## NFT Protocols (Marketplaces, Minting)

### Minting
- [ ] Is the max supply enforced?
- [ ] Is the minting function protected against reentrancy via `_safeMint`?
- [ ] Is there whitelist/allowlist bypass risk?
- [ ] Are Merkle proof verifications correct?
- [ ] Is the randomness source for reveals manipulation-resistant?

### Marketplace
- [ ] Are expired/cancelled listings properly handled?
- [ ] Is the royalty enforcement mechanism correct (ERC-2981)?
- [ ] Can orders be replayed or front-run?
- [ ] Are signed orders bound to specific chain and contract?

### Metadata
- [ ] Is metadata URI access-controlled for updates?
- [ ] Can metadata be frozen permanently?
- [ ] Is the reveal mechanism fair (not pre-determinable)?

---

## Restaking & Liquid Restaking Tokens (EigenLayer, Renzo, Kelp, Mellow style)

Restaking protocols allow staked ETH (or LSTs) to be re-used as economic security
for other services (AVSs). LRT protocols wrap restaked positions into liquid tokens.

### Core Restaking Logic
- [ ] Is the slashing mechanism from the underlying AVS correctly propagated to LRT holders?
- [ ] Can an AVS slash cause the LRT to be temporarily under-collateralized?
- [ ] Is there a circuit breaker if slashing exceeds a threshold percentage?
- [ ] Are withdrawal queues correctly ordered (EigenLayer has a 7-day delay)?
- [ ] Can the restaking strategy be changed by admin while user funds are deposited?

### Operator & AVS Trust
- [ ] Is the operator set permissioned or permissionless?
- [ ] Can a single operator control a majority of restaked capital?
- [ ] Is there delegation concentration risk (too many users delegating to one operator)?
- [ ] What happens if an AVS is decommissioned while funds are still delegated to it?
- [ ] Can AVS conditions be modified post-delegation without user consent?

### Share Price & Accounting
- [ ] Is the LRT share price calculated from total underlying assets including pending rewards?
- [ ] Can queued withdrawals affect the share price calculation?
- [ ] Is there a donation/inflation attack vector on the LRT vault?
- [ ] Are slashing events immediately reflected in the share price?
- [ ] Does reward compounding correctly track per-AVS yield?

### Withdrawal Queue
- [ ] Is the withdrawal queue FIFO or priority-based? Is the ordering exploitable?
- [ ] Can the queue be griefed (spamming small withdrawals to delay large ones)?
- [ ] Is there a maximum queue depth? What happens when it's full?
- [ ] Are withdrawal requests properly validated against available liquidity?
- [ ] Can an operator exit while users have pending withdrawals?

### Oracle & Pricing
- [ ] Is the LRT/ETH price determined on-chain or off-chain?
- [ ] Can the price be manipulated by triggering a slash event?
- [ ] If LSTs (stETH, rETH) are used as inputs, is their de-peg handled?
- [ ] Are there circuit breakers if the LRT/ETH peg deviates by more than X%?

### Karak & Symbiotic (Alternative Restaking Protocols)

Karak uses a DSS (Distributed Secure Services) gateway model with a two-step
slash flow (`requestSlashDSS` → `finalizeSlashDSS`). Symbiotic uses permissionless
vaults with configurable resolvers that can veto slashing within a resolution window.

**Karak-specific:**
- [ ] Is the two-step slash (`requestSlashDSS` / `finalizeSlashDSS`) properly gated? Can finalization be front-run by an operator withdrawing stake?
- [ ] Are DSS registration messages protected against nonce reuse and cross-chain replay?
- [ ] Is the vault's `stakedAssets` mapping correctly updated after slash events? Can it underflow if multiple slashes arrive in one block?
- [ ] Can a DSS be paused or removed by the Karak core while user funds remain staked in it — and is there a safe withdrawal path?
- [ ] Does the vault enforce a minimum stake threshold that prevents dust-amount operators from blocking slash quorum?

**Symbiotic-specific:**
- [ ] Are vault resolvers correctly permissioned? Can an unauthorized address register as a resolver and veto legitimate slashes?
- [ ] Is slash resolution bounded in time? Can an unresolved slash (resolver inaction) freeze vault withdrawals indefinitely?
- [ ] Does the network middleware correctly snapshot operator stake before computing slash amounts? Can stale snapshots be exploited?
- [ ] Are collateral types validated on vault creation? Can an attacker register a vault with a fee-on-transfer or rebasing ERC20 that inflates `totalStake`?
- [ ] Is the slash veto window short enough that an operator cannot withdraw between `requestSlash` and `executeSlash`?

**Both protocols:**
- [ ] If the same ETH/LST stake is simultaneously restaked in both EigenLayer and Karak/Symbiotic, can double-restaking of the same collateral occur?
- [ ] Are operator registration signatures (if used) protected against replay across deployment chains?

---

## EigenLayer AVS Contracts

AVS (Actively Validated Service) contracts define tasks, operator registration,
slashing conditions, and reward distribution for services built on EigenLayer restaked security.
Key references: EigenLayer M2 mainnet contracts, `ServiceManager`, `ECDSAStakeRegistry`, `BLSSignatureChecker`.

### AVS Registration & Operator Management
- [ ] Is operator registration permissioned or open? Can a malicious operator grief the AVS?
- [ ] Is there a minimum stake requirement for operators? Can an undercollateralized operator be slashed beyond their stake?
- [ ] Are operator deregistration delays sufficient to prevent stake-withdrawal-before-slash races?
- [ ] Can the AVS owner add/remove operators unilaterally, enabling censorship of legitimate operators?
- [ ] Is the quorum threshold correctly enforced (e.g., 2/3 BLS signers) before accepting task responses?

### Task Lifecycle & Validation
- [ ] Are tasks correctly mapped to their response window (challenge window expiry)?
- [ ] Can tasks be submitted with invalid calldata that passes validation but triggers unexpected behavior?
- [ ] Is there protection against task ID collisions or replay of previously completed task IDs?
- [ ] Can a single operator submit both a task and its own response (self-dealing)?
- [ ] Are off-chain computation results verified on-chain, or is there trust-only attestation?
- [ ] Is BLS signature aggregation resistant to rogue-key attacks?

### Slashing Conditions
- [ ] Are slashing conditions precisely defined and unambiguous? Can they be triggered accidentally by honest operators?
- [ ] Is there a challenge/dispute period before slashing finalizes? Can it be griefed?
- [ ] Who can trigger slashing — only the AVS contract or any address? Is permissioning correct?
- [ ] Can slashing be front-run (operator withdraws stake right before slash tx lands)?
- [ ] Are slashing events bounded? Can a single bug slash 100% of operator stake?
- [ ] Is the slashing veto period (EigenLayer M2 veto committee) accounted for in protocol timing assumptions?

### Payment & Reward Distribution
- [ ] Are rewards distributed proportionally to stake weight? Is there a rounding attack?
- [ ] Can reward claims be replayed or double-claimed?
- [ ] Is there a lock period for rewards to prevent claim before full task validation?
- [ ] Can an operator claim rewards for tasks they didn't honestly complete?
- [ ] Are unclaimed rewards handled correctly (expiry, protocol treasury, rollover)?

### Integration with EigenLayer Core
- [ ] Does the AVS correctly integrate with `DelegationManager` for stake accounting?
- [ ] Are `StrategyManager` share values correctly interpreted (shares ≠ underlying tokens 1:1)?
- [ ] Does the AVS handle the EigenLayer withdrawal delay (7-day queue) in its trust assumptions?
- [ ] Is the AVS registered in `AVSDirectory`? Are metadata URI updates validated?
- [ ] If using post-M2 EigenLayer contracts (Slashing upgrade): does the AVS correctly call `AllocationManager.slashOperator()` with valid parameters?
- [ ] Is the slashing magnitude bounded per strategy to prevent full stake loss from a single call?
- [ ] Note: In EigenLayer M2 (mainnet), the `Slasher` contract is a stub — active slashing was introduced in the subsequent Slashing upgrade via `AllocationManager` and Operator Sets.

### BLS & Signature Security (if using BLSSignatureChecker)
- [ ] Is the BLS G2 point validation correct? Are zero/invalid G2 points rejected?
- [ ] Is the aggregate BLS signature verified against the correct message hash?
- [ ] Are non-signers correctly accounted for in the quorum weight calculation?
- [ ] Is the sigma freshness validated (maximum age before rejection)?
- [ ] Is the `referenceBlockNumber` within allowed bounds to prevent stale quorum data?

### ECDSA Quorum (if using ECDSAStakeRegistry)
- [ ] Is the operator signing key separate from the operator's Ethereum address?
- [ ] Can an operator change their signing key mid-task, invalidating in-flight signatures?
- [ ] Is there a delay between signing key rotation and effectiveness?
- [ ] Are signature weight thresholds (e.g., 67% of total stake) enforced correctly?

---

## Uniswap V4 Hooks Protocol

V4 hooks are contracts that execute callbacks before/after pool operations.
Protocols built on top of V4 hooks introduce additional security considerations
beyond standard AMM security.

### Hook Registration & Permissions
- [ ] Are hook permission bits correctly set in the hook address?
- [ ] Does the hook only request the minimum permissions it needs?
- [ ] Is the hook address deterministic (CREATE2)? Can it be front-run?
- [ ] Can the hook be replaced or upgraded after pools are initialized with it?

### Callback Security
- [ ] **All hook callbacks (`beforeSwap`, `afterSwap`, `beforeAddLiquidity`, `afterAddLiquidity`, `beforeRemoveLiquidity`, `afterRemoveLiquidity`, `beforeInitialize`, `afterInitialize`, `beforeDonate`, `afterDonate`) restrict `msg.sender == address(poolManager)`** (Cork Protocol $11M: missing `onlyPoolManager`)
- [ ] Hook factory/`createMarket()` functions have appropriate access control or governance — external market creation must be permissioned
- [ ] Are `beforeSwap`/`afterSwap` callbacks nonReentrant?
- [ ] Does the hook validate `msg.sender == address(poolManager)` in all callbacks?
- [ ] Is `hookData` validated — not blindly decoded as user-controlled input?
- [ ] Can a malicious `hookData` cause the hook to drain tokens?
- [ ] Do callbacks correctly handle the case where `delta` is zero?

### Delta Accounting
- [ ] Are returned `int128` delta values from callbacks correctly bounded?
- [ ] Does the hook settle all open deltas before returning from callbacks?
- [ ] Can unsettled deltas leave the PoolManager in an inconsistent state?
- [ ] Are `take()` and `settle()` calls balanced within each callback?

### Pool Initialization
- [ ] Does `beforeInitialize` validate initial price and tick spacing?
- [ ] Can a malicious actor front-run pool initialization with an extreme price?
- [ ] Is the hook's state correctly initialized when a new pool is created with it?

### Flash Accounting
- [ ] Are flash loans via V4's `unlock()` correctly settled within the same call?
- [ ] Can the hook's flash accounting be exploited via nested `unlock()` calls?
- [ ] Are all currency deltas correctly net-settled at the end of the unlock callback?

### JIT (Just-In-Time) Liquidity Attacks

JIT liquidity is when an actor injects concentrated liquidity into a pool immediately
before a large swap (to capture fees) and removes it immediately after. In V4, a hook
can automate this on-chain — bypassing the mempool entirely — turning it into a
systematic fee extraction mechanism against passive LPs.

- [ ] Can the hook inject and remove liquidity within a single `unlock()` callback, capturing swap fees at zero market risk?
- [ ] Is there a minimum liquidity duration (blocks or time) before removal is permitted?
- [ ] Can an actor with hook `BEFORE_SWAP` + `AFTER_SWAP` permissions perform JIT entirely within one swap callback?
- [ ] Are fee tiers designed to make JIT economically unattractive (e.g., fee > JIT opportunity cost)?
- [ ] Does the hook track `addedAt` timestamp for positions? Is it enforced on removal?
- [ ] Can JIT be performed via a flash loan within the same `unlock()` without holding capital?

### Liquidity Distribution Function (LDF) Rounding

For hooks that implement custom liquidity distribution across ticks (Bunni-style):

- [ ] Is the LDF weight function symmetric? (`weight(tick, current+N) == weight(tick, current-N)`)
- [ ] Are rounding directions consistent between add-liquidity and remove-liquidity paths?
- [ ] Can a flash loan move the current tick enough to shift the LDF's active tick range?
- [ ] Is there a minimum position size that prevents dust-amplified rounding discrepancies?
- [ ] Is there a price impact cap on swaps that bounds tick movement within a single tx?

---

## Modular Lending Protocols (Morpho Blue, Euler V2 EVC)

Modular lending architectures allow permissionless creation of isolated lending markets.
Morpho Blue lets anyone create a market with any oracle and any LTV. Euler V2's Ethereum
Vault Connector (EVC) enables cross-vault liquidity combinations. The protocol core can be
audited, but individual market/vault parameters create unbounded new attack surfaces.

### Morpho Blue — Permissionless Market Risks

- [ ] Can anyone register a market with a malicious oracle (spot price, self-reporting)?
- [ ] Is there market-level oracle validation, or only protocol-level audit?
- [ ] Can a market creator set LTV so high (e.g., 99%) that collateral is always undercollateralized after a small price move?
- [ ] Can the IRM (interest rate model) be set to an adversarial contract that manipulates borrow rates?
- [ ] Are MetaMorpho vault curators (who select which markets to allocate to) properly permissioned?
- [ ] Can the MetaMorpho vault curator change oracle or LTV parameters mid-operation for depositors?
- [ ] Is `reallocateTo()` gated against flash-loan-amplified reallocation that drains one market?
- [ ] Are uncurated markets (anyone can supply/borrow) excluded from vault allocation?

### Euler V2 — Ethereum Vault Connector (EVC) Risks

The EVC allows accounts to combine collateral from multiple vaults. A health check in one
vault depends on positions in other vaults — creating cross-vault health invariants.

- [ ] Is the health check computed atomically across ALL vaults in the account's sub-account?
- [ ] Can an EVC callback (during a cross-vault operation) violate health between the start and end of a transaction?
- [ ] Are EVC `permit()` messages (signed EVC operations) protected against replay across chains?
- [ ] Can a user create a circular dependency between vaults (A uses B as collateral, B uses A)?
- [ ] Is vault deactivation (removing a collateral vault) safe when the account still has borrows backed by it?
- [ ] Does the governor/admin have a timelock before changing risk parameters (LTV, oracle, IRM)?

### Shared Risks (Morpho & Euler)

- [ ] Does the integrating protocol inherit the risk of each individual market's oracle, not just the core protocol's audit?
- [ ] Are bad debt socialization mechanisms clearly defined? Who absorbs losses from insolvent positions?
- [ ] Can an attacker create a market/vault specifically to drain integrating protocols that auto-route to it?

---

## Points & Airdrop Protocols

Points protocols (also called "pre-token incentive protocols") record off-chain
or on-chain points for future airdrop allocation. Common in 2024-2025 DeFi.

### Points Accounting
- [ ] Can points be double-counted (same action recorded twice)?
- [ ] Is there a Merkle proof or signature-based claim mechanism?
- [ ] Can points be front-run (e.g., observing a pending large deposit and sandwiching)?
- [ ] Is there a cap per address on total claimable points?
- [ ] Are historical points correctly snapshotted if the accounting formula changes?

### Merkle-Based Airdrop Claims
- [ ] Is the Merkle root set by a trusted admin with no timelock? (rug risk)
- [ ] Is there a deadline for claims? What happens to unclaimed tokens?
- [ ] **`sweepUnclaimed()` / `recoverTokens()` has strict access control** — only owner/multisig with timelock, not arbitrary callers (zkSync airdrop $4M: missing access control on sweep)
- [ ] Sweep function cannot be called while the claim window is still open
- [ ] Sweep destination address is hardcoded or requires governance approval (not a constructor parameter that can be socially-engineered)
- [ ] Can the Merkle root be updated after claims start (retroactive exclusion)?
- [ ] Is there protection against claiming on behalf of another address without consent?
- [ ] Are claimed tokens tracked to prevent double-claiming?

```solidity
// VULNERABLE: no double-claim protection
function claim(uint256 amount, bytes32[] calldata proof) external {
    require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid proof");
    token.transfer(msg.sender, amount); // can be called twice!
}

// SECURE: track claimed addresses
mapping(address => bool) public claimed;
function claim(uint256 amount, bytes32[] calldata proof) external {
    require(!claimed[msg.sender], "already claimed");
    require(MerkleProof.verify(proof, merkleRoot,
        keccak256(abi.encodePacked(msg.sender, amount))), "invalid proof");
    claimed[msg.sender] = true;
    token.transfer(msg.sender, amount);
}
```

### Vesting & Lock-ups
- [ ] Are vesting schedules enforced correctly (cliff + linear)?
- [ ] Can vesting be bypassed by transferring the vesting contract's position?
- [ ] Is early unlock/exit handled correctly with penalty calculations?
- [ ] Are vesting tokens correctly locked (not claimable before vesting starts)?

### Sybil & Manipulation Resistance
- [ ] Is points accrual based on economic activity that can't be cheaply Sybil-attacked?
- [ ] Can a user create multiple addresses to multiply their airdrop allocation?
- [ ] Is there a minimum threshold to claim (to prevent dust griefing)?
- [ ] If based on off-chain activity, is the oracle/admin that submits data trusted and audited?

---

## Token-Specific Checklists

### ERC-20 Token Audit

**Core Functions**
- [ ] `transfer` updates balances correctly
- [ ] `transferFrom` checks and updates allowance
- [ ] `approve` sets allowance correctly
- [ ] `balanceOf` returns correct balance
- [ ] `totalSupply` matches sum of all balances

**Security Checks**
- [ ] No overflow/underflow in balance updates
- [ ] Zero address cannot receive tokens
- [ ] Cannot transfer more than balance
- [ ] Cannot transferFrom more than allowance
- [ ] Events emitted for Transfer and Approval
- [ ] Approve race condition handled (or documented)

**Extensions**
- [ ] If pausable: pause affects correct functions
- [ ] If burnable: burn updates totalSupply
- [ ] If mintable: mint has proper access control
- [ ] If permit: EIP-2612 implemented correctly (nonce, deadline, chainId)

---

### ERC-721 NFT Audit

**Core Functions**
- [ ] `ownerOf` returns correct owner
- [ ] `balanceOf` returns correct count
- [ ] `transferFrom` transfers ownership correctly
- [ ] `safeTransferFrom` calls onERC721Received
- [ ] `approve` and `setApprovalForAll` work correctly

**Security Checks**
- [ ] Cannot transfer token you don't own
- [ ] `_safeMint` reentrancy protected
- [ ] Token IDs are unique and cannot be reused
- [ ] Metadata URI cannot be manipulated
- [ ] Royalties (ERC-2981) calculated correctly

**Common Issues**
- [ ] `_mint` vs `_safeMint` choice is intentional
- [ ] Max supply enforced before minting
- [ ] Whitelist/allowlist cannot be bypassed

---

### ERC-1155 Multi-Token Audit

**Core Functions**
- [ ] `balanceOf` returns correct balance per token ID
- [ ] `balanceOfBatch` handles arrays correctly
- [ ] `safeTransferFrom` updates balances correctly
- [ ] `safeBatchTransferFrom` handles multiple tokens
- [ ] `setApprovalForAll` works correctly

**Security Checks**
- [ ] Array length mismatches handled
- [ ] Callbacks (`onERC1155Received`) checked for reentrancy
- [ ] Cannot transfer more than balance
- [ ] Zero address checks

---

### ERC-4626 Vault Audit

**Core Functions**
- [ ] `deposit` mints correct shares
- [ ] `mint` takes correct assets
- [ ] `withdraw` burns correct shares
- [ ] `redeem` returns correct assets
- [ ] `convertToShares` and `convertToAssets` are consistent

**Security Checks**
- [ ] First depositor inflation attack prevented
- [ ] Share price cannot decrease (except from losses)
- [ ] `previewX` functions match actual `X` execution
- [ ] `maxX` functions return accurate limits
- [ ] Rounding favors the vault (not the user)

**Accounting**
- [ ] `totalAssets` includes all protocol assets
- [ ] Fees calculated correctly
- [ ] Losses distributed fairly

---

## MEV Bot Contracts

**Context:** MEV bots are smart contracts that execute arbitrage, sandwich attacks, or
liquidations. New research (2025) found 1,030/6,554 MEV bot contracts have exploitable
vulnerabilities, with $2.76M already stolen. MEV bots can appear in audit scope directly
(as auditable protocol components) or as adjacent infrastructure.

### Asset Management Vulnerabilities

- [ ] Are withdrawal/sweep functions gated by access control?
  - Many MEV bots expose `withdraw()` or `sweepTokens()` without `onlyOwner`
  - Classic pattern: `function sweep(address token) external { IERC20(token).transfer(owner, ...) }` — anyone can call if `onlyOwner` missing
- [ ] Can any external caller trigger a token transfer out of the bot contract?
- [ ] Is ETH withdrawal restricted? (`receive()` + payable functions without auth)
- [ ] Are profit-taking functions (claiming arbitrage profits) protected?

### Execution Logic

- [ ] Is the callback/execution entry point restricted to expected callers?
  - Bots that accept flash loan callbacks must validate `msg.sender == pool`
- [ ] Can an attacker sandwich the MEV bot itself?
  - On-chain bots with hardcoded slippage can be front-run
- [ ] Are slippage tolerances hardcoded vs dynamically computed?
  - Hardcoded `amountOutMin` values based on past prices can be manipulated
- [ ] Are all external call return values checked? (failed swaps silently lose funds)

### Flash Loan Exposure

- [ ] If the bot uses flash loans: is repayment validated before any state finalization?
- [ ] Can the flash loan callback be triggered directly by an external caller?
- [ ] Is the callback re-entrant? Could a nested callback drain the bot before repayment?

### Access Control

- [ ] Is there an `owner` or `operator` role? Is it set correctly at deployment?
- [ ] Can `owner` be changed? Is the transfer two-step?
- [ ] Are there emergency functions that unauthorized callers could exploit?

### MEV Bot-Specific Red Flags

| Pattern | Risk |
|---------|------|
| `function sweep(address token) external` without `onlyOwner` | Anyone can drain bot |
| `amountOutMin` hardcoded to 0 or old constant | Sandwich-able on all swaps |
| Flash loan callback without `require(msg.sender == pool)` | Callback hijacking |
| `receive()` with non-trivial logic and no auth | ETH theft via `.call{value:0}` |
| Missing return value check on swap calls | Silent losses on failed swaps |

---

## CeDeFi & Recursive Leverage

Protocols that mix centralized stablecoin issuance with on-chain borrowing can create
recursive leverage amplifiers when collateral prices are hardcoded.

**Key risks:**
- Stablecoin collateral priced at hardcoded $1.00 instead of live oracle
- High LTV ratios enable 7–8x recursive leverage in just a few deposit-borrow cycles
- Cascade liquidations when peg breaks, contagion to external protocols

**Audit checklist:**
- [ ] Verify no collateral asset has a hardcoded price (search for `1e18`, `1e8` used as return values in price functions)
- [ ] Calculate maximum achievable recursive leverage: `1 / (1 - LTV)` iterations
- [ ] Check that stablecoin price feeds have depeg circuit breakers (e.g., revert if price < $0.98)
- [ ] Review liquidation cascade: if largest positions liquidate simultaneously, can the protocol absorb bad debt?
- [ ] Check position size caps — single positions should not be large enough to destabilize the protocol
- [ ] Verify that the protocol does not accept its own issued token as collateral (recursive self-collateralization)
- [ ] Test oracle failure path: if feed is stale, does borrowing halt or continue with last price?

**Reference**: xUSD/Stream Finance ($285M contagion, Nov 2025) — 7.6x recursive leverage via `$1.00` hardcoded stablecoin price.
See `vulnerability-taxonomy.md §4.7` for code examples.

---

## Real World Assets (RWA) Protocols (Centrifuge, Maple, Goldfinch, TrueFi-style)

> See also: `vulnerability-taxonomy.md §4` (Oracle & Price Manipulation), `§16` (Cross-Chain & Bridge Risks)

RWA protocols tokenize off-chain assets — loans, invoices, real estate, treasury bills.
Their core security challenge is the **trust bridge between on-chain code and off-chain legal reality**.
The smart contract cannot seize collateral or enforce repayment; it relies on legal structures
and trusted admins to report accurate state. This creates a fundamentally different threat
model from purely on-chain DeFi.

### Off-Chain Trust and NAV Reporting

- [ ] Who sets the Net Asset Value (NAV) of the pool? Is it an admin, an oracle, or computed on-chain?
- [ ] Can the NAV reporter (pool manager / admin) manipulate NAV to enable over-borrowing or prevent redemptions?
- [ ] Is there a time delay or multi-sig requirement before a NAV update takes effect?
- [ ] Are there circuit breakers that halt redemptions if NAV drops more than X% in a single update?
- [ ] Does the protocol use a Chainlink-style price feed for liquid RWA (T-bills, money market funds), or a centralized admin price?

### Senior/Junior Tranche Accounting

Many RWA protocols split capital into tranches: junior absorbs losses first, senior gets
priority redemption. Miscounting tranche sizes or loss absorption order is a critical bug.

- [ ] Is the loss absorption order (junior → senior) enforced on-chain, or off-chain by the pool manager?
- [ ] Can the pool manager redirect losses away from junior tranche unfairly?
- [ ] Is there a minimum junior tranche ratio enforced? (Without it, senior LPs bear unpriced risk)
- [ ] Can the junior tranche be drained via strategic deposit/withdraw timing relative to a default event?
- [ ] If multiple tranches share a single ERC-4626 vault, is the conversion rate correctly calculated per tranche?

### Epoch-Based Redemption Windows

- [ ] Are redemption requests accumulated per epoch and executed at epoch end?
- [ ] Can an attacker submit a large redemption request then front-run the epoch closing to cancel it?
- [ ] Is there a minimum lock-up period preventing same-block deposit-and-redeem?
- [ ] What happens to redemption requests that cannot be filled in an epoch? Do they roll over or expire?
- [ ] Can a whitelisted address drain the liquidity reserve before other redemptions are processed?

### Pool Manager / Admin Trust

- [ ] What can the pool manager do unilaterally without time-lock or multi-sig?
  - Pause redemptions
  - Change NAV
  - Whitelist / blacklist token holders
  - Draw down borrower credit lines
  - Write off defaulted loans
- [ ] Is there a maximum drawdown per epoch or per time window to limit admin abuse?
- [ ] Can the pool manager add themselves as a borrower?
- [ ] Is pool manager compensation (fees) taken from the protocol before investor returns?

### KYC / Transfer Restrictions

- [ ] Do RWA tokens enforce transfer restrictions (ERC-1400, ERC-3643, or custom whitelist)?
- [ ] Can a non-KYC'd address receive tokens via a DEX swap or secondary market?
- [ ] Does the whitelist check apply to `transferFrom()` as well as `transfer()`?
- [ ] If whitelist is managed off-chain, can a user remain whitelisted after KYC status revokes?
- [ ] Are there jurisdiction-specific transfer blocklists that could be used to freeze any investor?

### Default and Liquidation

- [ ] What on-chain mechanism exists to handle borrower default?
- [ ] If collateral is off-chain (real estate, invoices), who controls the legal enforcement process?
- [ ] Can a defaulted loan be marked as "recovered" without actual repayment, inflating NAV?
- [ ] Is there a grace period that an attacker (borrower) can exploit to time withdrawals before default declaration?

---

## Options & Structured Products (Dopex, Lyra, Opyn/Gamma, Ribbon Finance-style)

> See also: `vulnerability-taxonomy.md §4` (Oracle & Price Manipulation), `§9` (Front-Running & MEV)

Options protocols price, underwrite, and settle derivative contracts on-chain.
Their core risk is that pricing correctness depends on **implied volatility (IV)** — which
is nearly impossible to source trustlessly — and **settlement oracle integrity** at expiry,
which is highly susceptible to flash-loan manipulation.

### Settlement Oracle Manipulation

The most critical attack vector: manipulate the spot price at the exact block where options settle.

- [ ] What oracle is used to determine the settlement price? Is it a spot price, TWAP, or Chainlink?
- [ ] If spot price: can a flash loan or large spot trade manipulate the price at the settlement block?
- [ ] Is the settlement price the price at a specific block timestamp, or an average over a window?
- [ ] Can the settlement be triggered by anyone (griefable if block-specific oracle)?
- [ ] Is there a circuit breaker preventing settlement if the oracle price deviates >X% from the 1h TWAP?

### Implied Volatility (IV) and Pricing

- [ ] Who sets the IV used for option pricing? Is it a privileged admin, an on-chain model, or external feed?
- [ ] Can IV be set to an extreme value (near-zero or very high) to misprice options in favor of the protocol or a buyer?
- [ ] Is there a bound on how much IV can change per update?
- [ ] If an AMM prices options dynamically (e.g., CLAMM), can LP positions be drained by trading against stale IV?
- [ ] Are options priced correctly when the underlying asset has very low liquidity?

### Collateral and Writing Options

- [ ] Are options fully collateralized at writing time (no undercollateralized writing)?
- [ ] If partially collateralized (margin model): is the margin updated as the underlying price moves?
- [ ] Can a writer withdraw collateral while the option is in-the-money (ITM)?
- [ ] For cash-settled options: is the payout calculated correctly using the settlement oracle?
- [ ] For physically settled options: is the asset transfer atomic with the premium receipt?

### Automated Vaults (Ribbon/Thetanuts-style covered call/put vaults)

- [ ] Who sets the strike price for each epoch? Can it be set adversarially close to spot?
- [ ] Is the strike set before or after the premium is known? (Setting it after = manipulation)
- [ ] Can the vault operator time the strike selection to maximize their own premium income at depositor expense?
- [ ] Are deposited funds locked in a way that prevents front-running the strike announcement?
- [ ] Is the premium received per option validated against an on-chain minimum?

### Multi-Leg Strategies and Complex Payoffs

- [ ] Is the payoff calculation for spreads, straddles, condors correct under all settlement scenarios?
- [ ] For calendar spreads: is the near-leg settlement price independent of the far-leg strike?
- [ ] Can a combination strategy be settled partially (near-leg) before the far-leg is priced?
- [ ] Are signed integers used where payoffs can be negative? (Net debit spreads)

---

## Prediction Markets (Polymarket/CTF, Augur-style)

> See also: `vulnerability-taxonomy.md §4.1` (Spot Price Dependency), `§9` (Front-Running & MEV)

Prediction markets let users bet on real-world event outcomes. Their contracts are often
simple (binary outcome AMMs), but the critical security surface is the **resolution layer**:
who decides what happened, and can that be manipulated?

### Market Resolution and Oracle Trust

- [ ] Who resolves the market? (UMA Optimistic Oracle, Chainlink, centralized admin, DAO vote)
- [ ] Is the resolver economically incentivized to resolve correctly? What's the cost to manipulate?
- [ ] Can the resolver be bribed for less than the outstanding positions' value?
- [ ] Is there a dispute/escalation mechanism? Can disputes be front-run or griefed?
- [ ] What happens if the resolver fails to respond in time? (Markets stuck, funds locked)
- [ ] For UMA-style optimistic resolution: is the dispute bond large enough to deter manipulation?

### Conditional Token (ERC-1155) Logic (Gnosis CTF-based)

Many prediction markets use Gnosis's Conditional Token Framework (CTF) with ERC-1155 tokens.

- [ ] Are conditional tokens split and merged correctly? (`splitPosition` / `mergePositions`)
- [ ] Can a user merge positions they don't fully own (partial merge attack)?
- [ ] Are redemption conditions exclusive (exactly one outcome wins) or can multiple outcomes be valid simultaneously?
- [ ] Can an attacker create a circular condition dependency that makes redemption impossible?
- [ ] Is `reportPayouts()` callable by anyone, or restricted to the oracle? (If anyone: griefable)

### AMM-Based Prediction Markets (LMSR, CPMM)

- [ ] Does the AMM enforce prices within [0, 1] for all outcomes?
- [ ] Is there an AMM invariant that a sufficiently large trade could break (price outside bounds)?
- [ ] Can liquidity be added/removed in a way that manipulates the implied probability?
- [ ] Is there a sandwich attack vector at market resolution (large buy → resolve → sell)?
- [ ] For order-book-based markets: is there a minimum order size to prevent spam griefing?

### Market Creation and Lifecycle

- [ ] Can anyone create a market? If so, can malicious markets trick users into losing funds?
  (e.g., ambiguous question wording, resolver who is the creator)
- [ ] Is there a collateral token whitelist, or can a scam token be used as collateral?
- [ ] When a market resolves "invalid", are all positions redeemable 1:1 for collateral?
- [ ] Is there a market creation fee that prevents spam but doesn't disproportionately centralize market creation?
- [ ] Can a market be closed (trading halted) before resolution? By whom?

### Timing and Insider Attacks

- [ ] Is market resolution information available on-chain before the resolution transaction settles? (Insider MEV)
- [ ] Can a user who knows the outcome (e.g., an oracle operator) take a large position before resolution?
- [ ] Is there a position-taking blackout period before resolution (e.g., 1h before cutoff)?

---

## Gnosis Safe Modules and Guards

> See also: `vulnerability-taxonomy.md §6` (Proxy & Upgradeability Issues), `§25` (ERC-1967 Proxy Storage Slot Corruption)

Safe modules extend a multisig wallet with programmable functionality via `delegatecall`.
Because modules execute in the **Safe's own storage context**, a malicious or buggy module
is equivalent to a compromised signer — it can drain funds, change owners, or modify
the Safe's configuration.

### Module Installation and Trust

- [ ] Is `enableModule()` gated by Safe threshold? A module that can enable itself bypasses all security.
- [ ] Can a module enable other modules? (Module A enables malicious Module B)
- [ ] Is there a time-lock between module installation proposal and activation?
- [ ] Are module permissions scoped (Zodiac Roles Modifier pattern) rather than full Safe access?
- [ ] Is the list of enabled modules accessible? Can the size grow unboundedly (gas DoS on execTransaction)?

### `delegatecall` Storage Collisions

Modules called via `delegatecall` execute in the Safe's storage layout. If a module declares
state variables, they overwrite the Safe's storage slots.

```solidity
// Gnosis Safe storage layout (simplified):
// slot 0: singleton (implementation address)
// slot 1: modules linked list head
// slot 2: owners mapping
// slot 3: ownerCount
// slot 4: threshold
// slot 5: nonce

// DANGEROUS: Module with state variable at slot 4 overwrites threshold
contract MaliciousModule {
    address public unused0;  // slot 0 — overwrites singleton!
    address public unused1;  // slot 1 — overwrites modules head
    address public unused2;  // slot 2
    address public unused3;  // slot 3
    uint256 public myVar;    // slot 4 — OVERWRITES THRESHOLD to 0 if set to 0
    // Setting myVar = 0 would set threshold = 0, making the Safe trivially bypassable
}
```

- [ ] Does the module use `delegatecall`? If so, does it have any state variables?
- [ ] Are all state variables in the module stored using namespaced storage (keccak256 slots)?
- [ ] Is the module's storage layout audited against the Safe's known slot assignments?

### Fallback Handler Exploitation

The Safe's fallback handler receives calls that don't match any Safe function signature.
A malicious fallback handler can intercept arbitrary calls to the Safe address.

- [ ] What fallback handler is set? Is it audited?
- [ ] Can the fallback handler execute state-changing operations in the Safe's context?
- [ ] Can the fallback handler be used to call `enableModule()` or `changeThreshold()` indirectly?
- [ ] Is the fallback handler changeable without Safe threshold approval?

### Guard Bypass and Circumvention

Guards are called before and after every Safe transaction to validate parameters.
An incorrectly implemented guard can be bypassed.

- [ ] Does the guard check `to`, `value`, `data`, `operation` (CALL vs DELEGATECALL)?
- [ ] Can the guard be bypassed via a module that calls `execTransactionFromModule()`?
  (Module-executed transactions skip the guard's `checkTransaction` in some Safe versions)
- [ ] Can the guard be disabled by a module, removing all protection?
- [ ] Does the guard handle the case where `data.length == 0` (plain ETH transfer)?

### Role-Based Access Modules (Zodiac Roles Modifier)

- [ ] Are role assignments limited to the minimum set of Safe addresses?
- [ ] Can a role grant itself additional permissions (role escalation)?
- [ ] Are function-level allowlists tight enough? (e.g., allowing `transfer(address,uint256)` should not allow `transferFrom()`)
- [ ] Is there a mechanism to revoke a role if a member is compromised?

### Recovery Modules (Social Recovery)

- [ ] Who are the recovery guardians? Are they sufficiently independent from the Safe owners?
- [ ] What is the recovery threshold? Can a single guardian trigger a recovery?
- [ ] Is there a time-lock on recovery execution during which the current owner can cancel?
- [ ] Can recovery guardians be added/removed without the current owner's consent?
- [ ] Can an attacker grief the recovery process by repeatedly triggering it (resets the time-lock)?
