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
