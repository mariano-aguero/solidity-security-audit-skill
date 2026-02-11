# Protocol Invariants

Invariants that should NEVER be violated. Use these to write invariant tests
and verify protocol correctness.

---

## Universal Invariants (All Protocols)

### Accounting

```solidity
// Total supply equals sum of all balances
invariant totalSupply_equals_sumBalances() {
    assert(token.totalSupply() == sum(token.balanceOf(user) for all users));
}

// Contract balance >= tracked balance
invariant solvency() {
    assert(address(contract).balance >= contract.totalDeposits());
    assert(token.balanceOf(address(contract)) >= contract.totalTokenDeposits());
}

// No negative balances (implicit in uint, but check logic)
invariant no_negative_balances() {
    assert(balances[user] >= 0); // Always true for uint
    assert(balances[user] <= totalSupply); // Sanity check
}
```

### Access Control

```solidity
// Only authorized can call admin functions
invariant admin_only() {
    // After any tx, verify admin state unchanged by non-admins
    assert(owner == previousOwner || msg.sender == previousOwner);
}

// Roles cannot escalate without proper authorization
invariant no_privilege_escalation() {
    assert(!hasRole(ADMIN_ROLE, user) || wasGrantedByAdmin(user));
}
```

### State Consistency

```solidity
// Initialized only once
invariant single_initialization() {
    assert(initializedCount <= 1);
}

// Paused state respected
invariant pause_respected() {
    if (paused) {
        assert(no_state_changing_functions_executed());
    }
}
```

---

## ERC20 Token Invariants

```solidity
contract ERC20Invariants is Test {
    ERC20 token;

    // Total supply is constant (unless mint/burn)
    function invariant_totalSupply_constant() public view {
        // If no mint/burn, totalSupply unchanged
    }

    // Transfer doesn't create or destroy tokens
    function invariant_transfer_conservation() public view {
        assert(
            balanceBefore[from] + balanceBefore[to] ==
            token.balanceOf(from) + token.balanceOf(to)
        );
    }

    // Allowance decreases correctly
    function invariant_allowance_decreases() public view {
        // After transferFrom, allowance decreased by amount
        // Unless infinite approval
    }

    // Zero address has no balance
    function invariant_zero_address_no_balance() public view {
        assert(token.balanceOf(address(0)) == 0);
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

    // Total borrows <= total deposits
    function invariant_borrows_lte_deposits() public view {
        assert(pool.totalBorrows() <= pool.totalDeposits());
    }

    // Utilization <= 100%
    function invariant_utilization_bounded() public view {
        uint256 utilization = pool.totalBorrows() * 1e18 / pool.totalDeposits();
        assert(utilization <= 1e18);
    }

    // Interest accrual never negative
    function invariant_interest_non_negative() public view {
        assert(pool.totalBorrows() >= pool.previousTotalBorrows());
    }

    // Health factor: liquidatable users have HF < 1
    function invariant_liquidation_threshold() public view {
        for (address user in borrowers) {
            if (pool.isLiquidatable(user)) {
                assert(pool.healthFactor(user) < 1e18);
            }
        }
    }

    // Collateral always covers debt (with LTV)
    function invariant_collateralization() public view {
        for (address user in borrowers) {
            uint256 collateralValue = pool.getCollateralValue(user);
            uint256 debtValue = pool.getDebtValue(user);
            uint256 maxLTV = pool.maxLTV();

            assert(debtValue <= collateralValue * maxLTV / 1e18);
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

    // No tokens created from swaps
    function invariant_swap_conservation() public view {
        // token0_out + token1_out <= token0_in + token1_in (minus fees)
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

    // Unstake returns exact amount (no slashing in basic staking)
    function invariant_unstake_amount() public view {
        // userBalance after unstake == userBalance before - unstakedAmount
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
