# Protocol Invariants

Invariants that should NEVER be violated. Use these to write invariant tests
and verify protocol correctness.

---

## Universal Invariants (All Protocols)

> **Notation**: The spec blocks below use pseudocode to express invariant intent.
> Scroll to the "Writing Invariant Tests in Foundry" section for compilable
> templates. For Echidna, use `assert()` inside public functions prefixed with
> `echidna_`. For Certora CVL, use `invariant` keyword with similar logic.

### Accounting (Specification)

```text
// Total supply equals sum of all individual balances
// → track via ghost variable in handler (see Foundry template below)
INVARIANT: token.totalSupply() == Σ token.balanceOf(user) for all users

// Protocol is solvent: real holdings cover tracked obligations
INVARIANT: address(protocol).balance >= protocol.totalDeposits()
INVARIANT: token.balanceOf(address(protocol)) >= protocol.totalTokenDeposits()

// No user balance exceeds total supply
INVARIANT: ∀ user: balances[user] <= totalSupply
```

### Accounting (Foundry — compilable)

```solidity
// Ghost variable maintained by handler to track sum of balances
contract ProtocolHandler is Test {
    uint256 public ghost_sumBalances;

    function deposit(uint256 amount) public {
        uint256 balBefore = protocol.balanceOf(actor);
        // ... deposit logic
        ghost_sumBalances += protocol.balanceOf(actor) - balBefore;
    }

    function withdraw(uint256 amount) public {
        uint256 balBefore = protocol.balanceOf(actor);
        // ... withdraw logic
        ghost_sumBalances -= balBefore - protocol.balanceOf(actor);
    }
}

contract InvariantTest is Test {
    function invariant_totalSupply_equals_sumBalances() public view {
        assertEq(token.totalSupply(), handler.ghost_sumBalances());
    }

    function invariant_solvency() public view {
        assertGe(
            token.balanceOf(address(protocol)),
            protocol.totalTokenDeposits()
        );
    }
}
```

### Access Control (Specification)

```text
// Admin role cannot be acquired without explicit grant from current admin
INVARIANT: hasRole(ADMIN_ROLE, user) → granted by admin via grantRole()

// Owner can only change via transferOwnership (Ownable2Step: requires acceptance)
INVARIANT: owner != address(0)
INVARIANT: owner transitions only through acceptOwnership()
```

### State Consistency (Specification)

```text
// Initialized exactly once
INVARIANT: initializedCount == 1 after first valid initialize() call

// Paused state blocks state-changing functions
INVARIANT: paused == true → deposit/borrow/swap revert
INVARIANT: paused == true → withdraw still succeeds (user protection)
```

---

## ERC20 Token Invariants

```solidity
contract ERC20Invariants is Test {
    ERC20 token;

    // Total supply tracked by ghost variable equals on-chain value
    // (requires handler to track ghost_totalSupply via mint/burn calls)
    function invariant_totalSupply_matches_ghost() public view {
        assertEq(token.totalSupply(), handler.ghost_totalSupply());
    }

    // Transfer doesn't create or destroy tokens
    // (verified by ghost sum — if ghost_sumBalances == totalSupply, conservation holds)
    function invariant_transfer_conservation() public view {
        assertEq(token.totalSupply(), handler.ghost_sumBalances());
    }

    // Allowance after transferFrom is reduced by the transferred amount
    // (unless it was type(uint256).max — infinite approval)
    function invariant_allowance_decreases_after_transferFrom() public view {
        uint256 used = handler.ghost_lastTransferFromAmount();
        uint256 prevAllowance = handler.ghost_allowanceBefore();
        if (prevAllowance != type(uint256).max) {
            assertEq(
                token.allowance(handler.ghost_owner(), handler.ghost_spender()),
                prevAllowance - used
            );
        }
    }

    // Zero address has no balance (tokens sent to address(0) are burned)
    function invariant_zero_address_no_balance() public view {
        assertEq(token.balanceOf(address(0)), 0);
    }
}
```

---

## ERC4626 Vault Invariants

```solidity
contract VaultInvariants is Test {
    IERC4626 vault;
    IERC20 asset;

    // Vault solvency: can always pay out all shares
    function invariant_solvency() public view {
        uint256 totalAssets = vault.totalAssets();
        uint256 totalShares = vault.totalSupply();

        // Total redeemable <= total assets
        assert(vault.previewRedeem(totalShares) <= totalAssets);
    }

    // Share price monotonically increases (no loss from deposits)
    function invariant_share_price_monotonic() public view {
        uint256 currentPrice = vault.totalAssets() * 1e18 / vault.totalSupply();
        assert(currentPrice >= previousSharePrice);
    }

    // Deposit/withdraw symmetry
    function invariant_deposit_withdraw_symmetry() public {
        uint256 assets = 1 ether;
        uint256 shares = vault.previewDeposit(assets);
        uint256 assetsBack = vault.previewRedeem(shares);

        // Should get back same or slightly less (fees/rounding)
        assert(assetsBack <= assets);
        assert(assetsBack >= assets * 999 / 1000); // Max 0.1% loss
    }

    // No inflation attack possible
    function invariant_no_inflation() public view {
        if (vault.totalSupply() > 0) {
            // Minimum share value check
            uint256 shareValue = vault.totalAssets() / vault.totalSupply();
            assert(shareValue < 1e30); // Reasonable upper bound
        }
    }
}
```

---

## Lending Protocol Invariants

```solidity
contract LendingInvariants is Test {
    ILendingPool pool;

    // Total borrows (including accrued interest) <= total assets held by protocol
    // NOTE: totalBorrows can exceed original deposit principal as interest accrues —
    // the correct solvency check is against totalAssets(), not totalDeposits().
    function invariant_borrows_lte_assets() public view {
        assertLe(pool.totalBorrows(), pool.totalAssets());
    }

    // Utilization <= 100% (borrows cannot exceed available liquidity)
    function invariant_utilization_bounded() public view {
        if (pool.totalAssets() > 0) {
            uint256 utilization = pool.totalBorrows() * 1e18 / pool.totalAssets();
            assertLe(utilization, 1e18);
        }
    }

    // Interest accrual is monotonically non-decreasing between blocks
    function invariant_interest_non_negative() public view {
        assertGe(pool.totalBorrows(), handler.ghost_previousTotalBorrows());
    }

    // Health factor: liquidatable users must have HF < 1e18 (< 1.0)
    // Uses actors array — Solidity does not support for-each over arbitrary addresses
    function invariant_liquidation_threshold() public view {
        address[] memory actors = handler.actors();
        for (uint256 i = 0; i < actors.length; i++) {
            address user = actors[i];
            if (pool.isLiquidatable(user)) {
                assertLt(pool.healthFactor(user), 1e18);
            }
        }
    }

    // Collateral always covers outstanding debt within LTV bounds
    function invariant_collateralization() public view {
        address[] memory actors = handler.actors();
        for (uint256 i = 0; i < actors.length; i++) {
            address user = actors[i];
            if (pool.getDebtValue(user) > 0) {
                uint256 collateralValue = pool.getCollateralValue(user);
                uint256 debtValue = pool.getDebtValue(user);
                uint256 maxLTV = pool.maxLTV();
                assertLe(debtValue, collateralValue * maxLTV / 1e18);
            }
        }
    }
}
```

---

## AMM / DEX Invariants

```solidity
contract AMMInvariants is Test {
    IUniswapV2Pair pair;

    // Constant product (x * y = k)
    function invariant_constant_product() public view {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 k = uint256(reserve0) * uint256(reserve1);

        // K should only increase (from fees)
        assert(k >= previousK);
    }

    // LP tokens proportional to liquidity
    function invariant_lp_proportional() public view {
        uint256 totalSupply = pair.totalSupply();
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();

        // Each LP token represents proportional share
        // totalSupply * price = reserve0 + reserve1 (simplified)
    }

    // Swap conservation: k increases (or stays equal) after every swap due to fees
    // k = reserve0 * reserve1; fees cause k to strictly increase
    function invariant_swap_conservation() public view {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 currentK = uint256(reserve0) * uint256(reserve1);
        assertGe(currentK, handler.ghost_lastK());
    }

    // Minimum liquidity locked
    function invariant_minimum_liquidity() public view {
        assert(pair.balanceOf(address(0)) >= pair.MINIMUM_LIQUIDITY());
    }
}
```

---

## Staking Protocol Invariants

```solidity
contract StakingInvariants is Test {
    IStaking staking;

    // Total staked == sum of user stakes
    function invariant_total_staked() public view {
        uint256 sum = 0;
        for (address user in stakers) {
            sum += staking.stakedBalance(user);
        }
        assert(staking.totalStaked() == sum);
    }

    // Rewards don't exceed allocation
    function invariant_rewards_bounded() public view {
        assert(staking.totalDistributedRewards() <= staking.totalRewardsAllocated());
    }

    // Reward rate consistent
    function invariant_reward_rate() public view {
        // rewardPerToken only increases
        assert(staking.rewardPerToken() >= previousRewardPerToken);
    }

    // Unstake returns exact amount staked (no slashing in basic staking)
    // ghost_stakedBefore and ghost_unstakedAmount set by handler on withdraw call
    function invariant_unstake_exact_amount() public view {
        uint256 stakedBefore = handler.ghost_stakedBefore();
        uint256 unstakedAmount = handler.ghost_unstakedAmount();
        address lastActor = handler.ghost_lastActor();
        if (unstakedAmount > 0) {
            assertEq(
                staking.stakedBalance(lastActor),
                stakedBefore - unstakedAmount
            );
        }
    }
}
```

---

## Governance Invariants

```solidity
contract GovernanceInvariants is Test {
    IGovernor governor;

    // Proposal states are sequential
    function invariant_proposal_state_machine() public view {
        // Pending -> Active -> Succeeded/Defeated -> Queued -> Executed
        // No skipping states
    }

    // Vote count matches cast votes
    function invariant_vote_count() public view {
        (uint256 forVotes, uint256 againstVotes, uint256 abstainVotes) =
            governor.proposalVotes(proposalId);

        assert(forVotes + againstVotes + abstainVotes == totalVotesCast);
    }

    // Quorum respected
    function invariant_quorum() public view {
        if (governor.state(proposalId) == ProposalState.Succeeded) {
            assert(governor.proposalVotes(proposalId).forVotes >= governor.quorum());
        }
    }

    // Timelock respected
    function invariant_timelock() public view {
        if (governor.state(proposalId) == ProposalState.Executed) {
            assert(block.timestamp >= proposalEta);
        }
    }
}
```

---

## Bridge Invariants

```solidity
contract BridgeInvariants is Test {
    IBridge bridge;

    // Locked on source == minted on destination
    function invariant_lock_mint_balance() public view {
        assert(bridge.totalLocked() == destinationBridge.totalMinted());
    }

    // Message processed only once
    function invariant_no_replay() public view {
        for (bytes32 messageId in processedMessages) {
            assert(processedCount[messageId] == 1);
        }
    }

    // Validator threshold respected
    function invariant_validator_threshold() public view {
        // All processed messages have >= threshold signatures
    }
}
```

---

## Writing Invariant Tests in Foundry

```solidity
// Handler to guide fuzzer
contract ProtocolHandler is Test {
    Protocol protocol;
    address[] actors;

    constructor(Protocol _protocol) {
        protocol = _protocol;
        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
    }

    function deposit(uint256 actorSeed, uint256 amount) public {
        address actor = actors[actorSeed % actors.length];
        amount = bound(amount, 1, 100 ether);

        deal(address(token), actor, amount);

        vm.startPrank(actor);
        token.approve(address(protocol), amount);
        protocol.deposit(amount);
        vm.stopPrank();
    }

    function withdraw(uint256 actorSeed, uint256 amount) public {
        address actor = actors[actorSeed % actors.length];
        uint256 balance = protocol.balanceOf(actor);
        amount = bound(amount, 0, balance);

        vm.prank(actor);
        protocol.withdraw(amount);
    }
}

contract ProtocolInvariantTest is Test {
    Protocol protocol;
    ProtocolHandler handler;

    function setUp() public {
        protocol = new Protocol();
        handler = new ProtocolHandler(protocol);

        targetContract(address(handler));
    }

    function invariant_solvency() public view {
        assert(address(protocol).balance >= protocol.totalDeposits());
    }
}
```

```bash
# Run invariant tests
forge test --match-test invariant -vvv

# With more runs
forge test --match-test invariant --fuzz-runs 10000
```

---

## Echidna Invariant Format

Echidna uses public functions prefixed with `echidna_` that return `bool`.
No assertion library needed — returning `false` is a counterexample.

```solidity
contract ProtocolEchidnaTest {
    Protocol protocol;

    constructor() {
        protocol = new Protocol();
    }

    // Solvency: ETH held >= tracked deposits
    function echidna_solvency() public view returns (bool) {
        return address(protocol).balance >= protocol.totalDeposits();
    }

    // Total supply consistency
    function echidna_totalSupply_non_zero_after_deposit() public returns (bool) {
        try protocol.deposit{value: 1 ether}() {
            return protocol.totalSupply() > 0;
        } catch {
            return true; // revert is acceptable
        }
    }
}
```

```yaml
# echidna.yaml
testMode: "assertion"
testLimit: 50000
deployer: "0x10000"
sender: ["0x10000", "0x20000", "0x30000"]
```

See `references/tool-integration.md` section 4 (Echidna) for full configuration
and corpus management options.

---

## Uniswap V3 / Concentrated Liquidity Invariants

V3 replaces the global `x*y=k` with per-tick liquidity. The invariants differ
significantly from V2.

```solidity
contract UniswapV3Invariants is Test {
    IUniswapV3Pool pool;

    // Active liquidity must be positive when price is in range
    function invariant_active_liquidity_positive() public view {
        uint128 liquidity = pool.liquidity();
        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
        if (sqrtPriceX96 > 0) {
            // If pool has a price, it must have liquidity
            assertGt(liquidity, 0);
        }
    }

    // sqrtPrice must stay within tick bounds of active range
    function invariant_price_within_tick_bounds() public view {
        (, int24 currentTick,,,,,) = pool.slot0();
        int24 tickSpacing = pool.tickSpacing();
        // Current tick must be a valid multiple of tickSpacing
        assertEq(currentTick % tickSpacing, 0);
    }

    // Fee growth global must be monotonically non-decreasing
    function invariant_fee_growth_monotonic() public view {
        uint256 feeGrowth0 = pool.feeGrowthGlobal0X128();
        uint256 feeGrowth1 = pool.feeGrowthGlobal1X128();
        assertGe(feeGrowth0, handler.ghost_lastFeeGrowth0());
        assertGe(feeGrowth1, handler.ghost_lastFeeGrowth1());
    }

    // Protocol cannot owe more fees than it has collected
    function invariant_protocol_fees_bounded() public view {
        (uint128 token0Fees, uint128 token1Fees) = pool.protocolFees();
        assertLe(token0Fees, token.balanceOf(address(pool)));
    }
}
```
