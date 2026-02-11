# Secure Coding Patterns

Reference implementations of secure patterns. Compare audited code against these.

---

## Reentrancy Protection

### Checks-Effects-Interactions (CEI)

```solidity
// SECURE: State updated before external call
function withdraw(uint256 amount) external {
    // 1. CHECKS
    require(balances[msg.sender] >= amount, "Insufficient balance");

    // 2. EFFECTS
    balances[msg.sender] -= amount;

    // 3. INTERACTIONS
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

### ReentrancyGuard

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function withdraw(uint256 amount) external nonReentrant {
        // Safe from reentrancy
    }
}
```

### Transient Storage Lock (Solidity 0.8.24+)

```solidity
contract TransientReentrancyGuard {
    bytes32 constant LOCK_SLOT = keccak256("reentrancy.lock");

    modifier nonReentrant() {
        assembly {
            if tload(LOCK_SLOT) { revert(0, 0) }
            tstore(LOCK_SLOT, 1)
        }
        _;
        assembly {
            tstore(LOCK_SLOT, 0)
        }
    }
}
```

---

## Access Control

### Ownable2Step

```solidity
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract Treasury is Ownable2Step {
    constructor() Ownable(msg.sender) {}

    function emergencyWithdraw() external onlyOwner {
        // Only owner can call
    }
}

// Transfer requires:
// 1. owner.transferOwnership(newOwner)
// 2. newOwner.acceptOwnership()
```

### Role-Based Access Control

```solidity
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract Protocol is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function updateConfig() external onlyRole(OPERATOR_ROLE) {
        // ...
    }
}
```

### Initializer Protection

```solidity
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract VaultV1 is Initializable {
    address public owner;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers(); // Protect implementation
    }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
```

---

## Safe External Calls

### SafeERC20

```solidity
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Vault {
    using SafeERC20 for IERC20;

    function deposit(IERC20 token, uint256 amount) external {
        // Handles tokens that don't return bool
        token.safeTransferFrom(msg.sender, address(this), amount);
    }

    function withdraw(IERC20 token, uint256 amount) external {
        token.safeTransfer(msg.sender, amount);
    }
}
```

### Checking Call Return Values

```solidity
function sendETH(address to, uint256 amount) internal {
    (bool success,) = to.call{value: amount}("");
    require(success, "ETH transfer failed");
}
```

### Safe Delegatecall

```solidity
// Only delegatecall to trusted, immutable addresses
contract Proxy {
    address public immutable implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
```

---

## Oracle Integration

### Chainlink with Full Validation

```solidity
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SecureOracle {
    AggregatorV3Interface public immutable priceFeed;
    uint256 public constant MAX_STALENESS = 1 hours;

    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 price,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();

        // Validate price is positive
        require(price > 0, "Invalid price");

        // Validate not stale
        require(block.timestamp - updatedAt < MAX_STALENESS, "Stale price");

        // Validate round completeness
        require(answeredInRound >= roundId, "Incomplete round");

        return uint256(price);
    }
}
```

### L2 Sequencer Check

```solidity
contract L2Oracle {
    AggregatorV3Interface public immutable sequencerFeed;
    uint256 public constant GRACE_PERIOD = 1 hours;

    function getPrice() public view returns (uint256) {
        // Check sequencer is up
        (, int256 answer, uint256 startedAt,,) = sequencerFeed.latestRoundData();

        bool isSequencerUp = answer == 0;
        require(isSequencerUp, "Sequencer down");

        // Ensure grace period passed since sequencer came up
        require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period");

        // Then get price...
        return _getPrice();
    }
}
```

---

## Signature Handling

### EIP-712 Typed Data

```solidity
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Permit is EIP712 {
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    mapping(address => uint256) public nonces;

    constructor() EIP712("Token", "1") {}

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Expired");

        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            nonces[owner]++,
            deadline
        ));

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(hash, v, r, s);

        require(signer == owner, "Invalid signature");

        _approve(owner, spender, value);
    }
}
```

### SignatureChecker (Supports ERC-1271)

```solidity
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract MultiSigVerifier {
    function verify(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) public view returns (bool) {
        // Works for both EOA and smart contract wallets
        return SignatureChecker.isValidSignatureNow(signer, hash, signature);
    }
}
```

---

## Proxy Patterns

### UUPS Proxy

```solidity
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract VaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner) external initializer {
        __Ownable_init(owner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

### ERC-7201 Namespaced Storage

```solidity
abstract contract VaultStorage {
    /// @custom:storage-location erc7201:vault.storage.main
    struct MainStorage {
        mapping(address => uint256) balances;
        uint256 totalDeposits;
    }

    // keccak256(abi.encode(uint256(keccak256("vault.storage.main")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MAIN_STORAGE_LOCATION =
        0x1234...00;

    function _getMainStorage() internal pure returns (MainStorage storage $) {
        assembly {
            $.slot := MAIN_STORAGE_LOCATION
        }
    }
}
```

---

## Token Patterns

### ERC-4626 with Inflation Protection

```solidity
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract SecureVault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) ERC20("Vault", "vTKN") {
        // OpenZeppelin 5.x includes virtual offset by default
    }

    // Override to add minimum deposit
    function deposit(uint256 assets, address receiver)
        public
        override
        returns (uint256)
    {
        require(assets >= 1e6, "Minimum deposit required");
        return super.deposit(assets, receiver);
    }
}
```

### Fee-on-Transfer Token Handling

```solidity
function depositToken(IERC20 token, uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;

    // Use 'received' not 'amount' for accounting
    balances[msg.sender] += received;
    totalDeposits += received;
}
```

---

## Governance Patterns

### Snapshot Voting

```solidity
import {ERC20Votes} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";

contract GovToken is ERC20Votes {
    constructor() ERC20("Gov", "GOV") EIP712("Gov", "1") {}

    // Voting power based on snapshot, not current balance
    function getVotes(address account) public view override returns (uint256) {
        return super.getVotes(account);
    }
}

contract Governor {
    function propose(...) external returns (uint256) {
        // Snapshot taken at proposal creation
        uint256 snapshot = block.number + votingDelay;
        // ...
    }

    function castVote(uint256 proposalId, uint8 support) external {
        // Uses snapshot balance, immune to flash loans
        uint256 weight = token.getPastVotes(msg.sender, proposalSnapshot[proposalId]);
        // ...
    }
}
```

---

## Emergency Patterns

### Pausable

```solidity
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract Protocol is Pausable {
    address public guardian;

    function pause() external {
        require(msg.sender == guardian, "Not guardian");
        _pause();
    }

    function deposit() external whenNotPaused {
        // Blocked when paused
    }

    function withdraw() external {
        // Allow withdrawals even when paused (user protection)
    }
}
```

### Circuit Breaker

```solidity
contract CircuitBreaker {
    uint256 public constant MAX_DAILY_OUTFLOW = 1000 ether;
    uint256 public dailyOutflow;
    uint256 public lastResetTime;

    modifier checkCircuitBreaker(uint256 amount) {
        if (block.timestamp > lastResetTime + 1 days) {
            dailyOutflow = 0;
            lastResetTime = block.timestamp;
        }

        require(dailyOutflow + amount <= MAX_DAILY_OUTFLOW, "Circuit breaker");
        dailyOutflow += amount;
        _;
    }

    function withdraw(uint256 amount) external checkCircuitBreaker(amount) {
        // Protected by daily limit
    }
}
```
