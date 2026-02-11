# ERC-4337 Account Abstraction Security

Security patterns for Account Abstraction (ERC-4337) implementations including
smart accounts, bundlers, paymasters, and entry point interactions.

---

## Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    User     │────▶│   Bundler   │────▶│ Entry Point │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    │                          │                          │
                    ▼                          ▼                          ▼
             ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
             │   Account   │           │  Paymaster  │           │   Factory   │
             │  (Wallet)   │           │             │           │             │
             └─────────────┘           └─────────────┘           └─────────────┘
```

| Component | Role | Security Focus |
|-----------|------|----------------|
| **UserOperation** | Transaction intent | Signature, nonce, gas limits |
| **Bundler** | Aggregates & submits UserOps | DoS, front-running, censorship |
| **Entry Point** | Singleton executor | Reentrancy, validation |
| **Account** | Smart contract wallet | Access control, upgrade safety |
| **Paymaster** | Sponsors gas | Drain attacks, validation |
| **Factory** | Deploys accounts | Deterministic addresses, init |

---

## UserOperation Structure

```solidity
struct UserOperation {
    address sender;           // Account address
    uint256 nonce;            // Anti-replay
    bytes initCode;           // Factory + init data (if deploying)
    bytes callData;           // Execution payload
    uint256 callGasLimit;     // Gas for execution
    uint256 verificationGasLimit; // Gas for validation
    uint256 preVerificationGas;   // Bundler overhead
    uint256 maxFeePerGas;     // EIP-1559 max fee
    uint256 maxPriorityFeePerGas; // EIP-1559 priority
    bytes paymasterAndData;   // Paymaster address + data
    bytes signature;          // Account signature
}
```

---

## Account (Wallet) Vulnerabilities

### 1. Signature Validation Bypass

```solidity
// VULNERABLE: Missing signature validation
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external returns (uint256 validationData) {
    // No signature check!
    _payPrefund(missingAccountFunds);
    return 0; // Valid
}

// SECURE: Proper signature validation
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external returns (uint256 validationData) {
    // Only Entry Point can call
    require(msg.sender == entryPoint, "Not from EntryPoint");

    // Validate signature
    bytes32 hash = userOpHash.toEthSignedMessageHash();
    address recovered = hash.recover(userOp.signature);

    if (recovered != owner) {
        return SIG_VALIDATION_FAILED; // 1
    }

    _payPrefund(missingAccountFunds);
    return 0; // Valid
}
```

### 2. Missing Entry Point Check

```solidity
// VULNERABLE: Anyone can call validateUserOp
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external returns (uint256) {
    // Missing: require(msg.sender == entryPoint)
    // Attacker can drain prefund
}

// SECURE: Restrict to Entry Point
modifier onlyEntryPoint() {
    require(msg.sender == address(entryPoint), "Not EntryPoint");
    _;
}

function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external onlyEntryPoint returns (uint256) {
    // Safe
}
```

### 3. Execution Without Validation

```solidity
// VULNERABLE: execute() callable by anyone
function execute(
    address dest,
    uint256 value,
    bytes calldata data
) external {
    // No access control!
    (bool success,) = dest.call{value: value}(data);
    require(success);
}

// SECURE: Only Entry Point or self
function execute(
    address dest,
    uint256 value,
    bytes calldata data
) external {
    require(
        msg.sender == address(entryPoint) || msg.sender == address(this),
        "Unauthorized"
    );
    (bool success,) = dest.call{value: value}(data);
    require(success);
}
```

### 4. Upgrade Vulnerabilities

```solidity
// VULNERABLE: Owner can upgrade to malicious implementation
function upgradeTo(address newImpl) external onlyOwner {
    _upgradeTo(newImpl);
}

// SECURE: Timelock for upgrades
uint256 public constant UPGRADE_DELAY = 2 days;
mapping(address => uint256) public pendingUpgrades;

function proposeUpgrade(address newImpl) external onlyOwner {
    pendingUpgrades[newImpl] = block.timestamp + UPGRADE_DELAY;
    emit UpgradeProposed(newImpl);
}

function executeUpgrade(address newImpl) external onlyOwner {
    require(pendingUpgrades[newImpl] != 0, "Not proposed");
    require(block.timestamp >= pendingUpgrades[newImpl], "Too early");

    delete pendingUpgrades[newImpl];
    _upgradeTo(newImpl);
}
```

---

## Paymaster Vulnerabilities

### 1. Unbounded Gas Sponsorship (Drain Attack)

```solidity
// VULNERABLE: No limits on sponsorship
function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 maxCost
) external returns (bytes memory context, uint256 validationData) {
    // Sponsors anyone without limits
    return ("", 0);
}

// SECURE: Rate limiting and allowlists
mapping(address => uint256) public dailySponsored;
mapping(address => uint256) public lastSponsorDay;
uint256 public constant DAILY_LIMIT = 0.1 ether;

function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 maxCost
) external returns (bytes memory context, uint256 validationData) {
    address sender = userOp.sender;

    // Reset daily limit
    uint256 today = block.timestamp / 1 days;
    if (lastSponsorDay[sender] < today) {
        dailySponsored[sender] = 0;
        lastSponsorDay[sender] = today;
    }

    // Check limit
    require(
        dailySponsored[sender] + maxCost <= DAILY_LIMIT,
        "Daily limit exceeded"
    );

    dailySponsored[sender] += maxCost;
    return (abi.encode(sender, maxCost), 0);
}
```

### 2. Missing postOp Validation

```solidity
// VULNERABLE: postOp doesn't verify actual cost
function _postOp(
    PostOpMode mode,
    bytes calldata context,
    uint256 actualGasCost
) internal override {
    // Doesn't check if user paid their share
}

// SECURE: Verify and charge user
function _postOp(
    PostOpMode mode,
    bytes calldata context,
    uint256 actualGasCost
) internal override {
    (address sender, uint256 maxCost) = abi.decode(context, (address, uint256));

    if (mode == PostOpMode.postOpReverted) {
        // Handle revert case
        return;
    }

    // Charge user's deposit or token balance
    uint256 userShare = actualGasCost * userSharePercent / 100;
    require(
        deposits[sender] >= userShare,
        "Insufficient deposit"
    );
    deposits[sender] -= userShare;
}
```

### 3. Token Paymaster Price Manipulation

```solidity
// VULNERABLE: Uses spot price for token payment
function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 maxCost
) external returns (bytes memory, uint256) {
    // Get current price from DEX
    uint256 tokenPrice = getSpotPrice(); // Manipulatable!

    uint256 tokenCost = maxCost * 1e18 / tokenPrice;
    require(token.balanceOf(userOp.sender) >= tokenCost);

    return (abi.encode(tokenCost), 0);
}

// SECURE: Use oracle with staleness check
function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 maxCost
) external returns (bytes memory, uint256) {
    // Use Chainlink oracle
    (, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
    require(price > 0, "Invalid price");
    require(block.timestamp - updatedAt < 1 hours, "Stale price");

    uint256 tokenCost = maxCost * 1e18 / uint256(price);
    // Add buffer for price movement
    tokenCost = tokenCost * 105 / 100; // 5% buffer

    require(token.balanceOf(userOp.sender) >= tokenCost);

    return (abi.encode(tokenCost), 0);
}
```

---

## Factory Vulnerabilities

### 1. Non-Deterministic Addresses

```solidity
// VULNERABLE: Address depends on block data
function createAccount(address owner) external returns (address) {
    bytes32 salt = keccak256(abi.encodePacked(owner, block.timestamp));
    // Address unpredictable - breaks initCode
    return address(new Account{salt: salt}(owner, entryPoint));
}

// SECURE: Deterministic address from owner + salt
function createAccount(
    address owner,
    uint256 salt
) external returns (address) {
    bytes32 actualSalt = keccak256(abi.encodePacked(owner, salt));
    return address(new Account{salt: actualSalt}(owner, entryPoint));
}

function getAddress(
    address owner,
    uint256 salt
) public view returns (address) {
    bytes32 actualSalt = keccak256(abi.encodePacked(owner, salt));
    return Create2.computeAddress(
        actualSalt,
        keccak256(abi.encodePacked(
            type(Account).creationCode,
            abi.encode(owner, entryPoint)
        ))
    );
}
```

### 2. Front-Running Account Creation

```solidity
// VULNERABLE: Attacker can front-run with different owner
function createAccount(bytes32 salt) external returns (address) {
    // Salt doesn't include msg.sender or owner
    return address(new Account{salt: salt}(msg.sender, entryPoint));
}

// SECURE: Salt includes owner
function createAccount(
    address owner,
    uint256 salt
) external returns (address) {
    // Owner is part of salt - can't front-run with different owner
    bytes32 actualSalt = keccak256(abi.encodePacked(owner, salt));
    return address(new Account{salt: actualSalt}(owner, entryPoint));
}
```

---

## Nonce Management

### 1. Nonce Replay Across Keys

```solidity
// ERC-4337 uses 2D nonces: key (192 bits) + sequence (64 bits)
// Each key has its own sequence

// VULNERABLE: Single key for all operations
function validateUserOp(...) external {
    // Uses only the sequence part
    require(userOp.nonce == nonces[sender]++);
}

// SECURE: Support 2D nonces for parallel transactions
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external returns (uint256) {
    uint192 key = uint192(userOp.nonce >> 64);
    uint64 seq = uint64(userOp.nonce);

    require(seq == nonces[key], "Invalid nonce");
    nonces[key]++;

    // Continue validation...
}
```

### 2. Cross-Chain Nonce Replay

```solidity
// VULNERABLE: Same nonce valid on multiple chains
function validateUserOp(...) external {
    bytes32 hash = keccak256(abi.encode(userOp));
    // No chain ID in hash!
}

// SECURE: Include chain ID in hash (Entry Point does this)
// The Entry Point already includes chainId in userOpHash
// But custom validation must also consider it

function _validateSignature(
    UserOperation calldata userOp,
    bytes32 userOpHash // Already includes chainId from EntryPoint
) internal view returns (bool) {
    // userOpHash is safe to use directly
    return owner == userOpHash.toEthSignedMessageHash().recover(userOp.signature);
}
```

---

## Bundler Considerations

### 1. Simulation vs Execution Discrepancy

```solidity
// VULNERABLE: Different behavior in simulation vs execution
function validateUserOp(...) external returns (uint256) {
    // Bundlers simulate with eth_call
    // This check passes in simulation but fails on-chain
    if (block.basefee > maxBaseFee) {
        return SIG_VALIDATION_FAILED;
    }
}

// Storage access rules (ERC-7562):
// - Can only access sender's storage
// - Can only access paymaster's storage (if using paymaster)
// - Cannot access other accounts' storage during validation

// VULNERABLE: Accesses external storage
function validateUserOp(...) external returns (uint256) {
    // Bundler will reject - accesses external contract
    uint256 price = oracle.getPrice();
}
```

### 2. Gas Griefing

```solidity
// VULNERABLE: Validation uses excessive gas
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external returns (uint256) {
    // Expensive operations in validation
    for (uint i = 0; i < 1000; i++) {
        keccak256(abi.encode(i));
    }
}

// Keep validation gas-efficient
// verificationGasLimit should be minimal
```

---

## Signature Schemes

### 1. EIP-1271 Smart Contract Signatures

```solidity
// For accounts that are already smart contracts
function isValidSignature(
    bytes32 hash,
    bytes memory signature
) external view returns (bytes4) {
    // Validate signature
    if (_isValidSignature(hash, signature)) {
        return IERC1271.isValidSignature.selector; // 0x1626ba7e
    }
    return 0xffffffff;
}

// VULNERABLE: No replay protection in isValidSignature
function isValidSignature(
    bytes32 hash,
    bytes memory signature
) external view returns (bytes4) {
    // Same signature valid for any hash!
    if (signature.length == 65) {
        return 0x1626ba7e;
    }
}
```

### 2. Multi-Signature Accounts

```solidity
// SECURE: Threshold signature validation
function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external onlyEntryPoint returns (uint256) {
    bytes32 hash = userOpHash.toEthSignedMessageHash();

    // Decode multiple signatures
    bytes[] memory signatures = abi.decode(userOp.signature, (bytes[]));
    require(signatures.length >= threshold, "Not enough signatures");

    address lastSigner = address(0);
    for (uint i = 0; i < threshold; i++) {
        address signer = hash.recover(signatures[i]);
        require(isOwner[signer], "Invalid signer");
        require(signer > lastSigner, "Duplicate or unordered"); // Prevent duplicates
        lastSigner = signer;
    }

    _payPrefund(missingAccountFunds);
    return 0;
}
```

---

## Session Keys

### 1. Overprivileged Session Keys

```solidity
// VULNERABLE: Session key can do anything
mapping(address => bool) public sessionKeys;

function validateUserOp(...) external returns (uint256) {
    address signer = recoverSigner(userOp);
    if (owner == signer || sessionKeys[signer]) {
        return 0; // Valid - but session key has full access!
    }
}

// SECURE: Scoped session keys
struct SessionKey {
    address key;
    address[] allowedTargets;
    bytes4[] allowedSelectors;
    uint256 validUntil;
    uint256 maxValue;
}

mapping(bytes32 => SessionKey) public sessionKeys;

function validateUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
) external returns (uint256) {
    address signer = recoverSigner(userOp, userOpHash);

    if (signer == owner) {
        _payPrefund(missingAccountFunds);
        return 0;
    }

    // Check session key permissions
    bytes32 keyId = keccak256(abi.encodePacked(signer));
    SessionKey storage session = sessionKeys[keyId];

    require(session.key == signer, "Invalid session key");
    require(block.timestamp <= session.validUntil, "Session expired");

    // Validate target and selector
    (address target, uint256 value, bytes4 selector) = _parseCallData(userOp.callData);
    require(_isAllowed(session, target, selector), "Not allowed");
    require(value <= session.maxValue, "Value too high");

    _payPrefund(missingAccountFunds);
    return 0;
}
```

---

## Checklist: Account Abstraction Audit

### Account (Wallet)
- [ ] `validateUserOp` only callable by Entry Point
- [ ] Signature validation is correct (EIP-712 or EIP-191)
- [ ] Nonce handling prevents replay
- [ ] `execute` only callable by Entry Point or self
- [ ] Upgrade mechanism has timelock or multi-sig
- [ ] Recovery mechanism is secure
- [ ] Session keys are properly scoped

### Paymaster
- [ ] Rate limiting prevents drain attacks
- [ ] Token pricing uses secure oracle
- [ ] `postOp` handles all failure modes
- [ ] Stake/unstake has appropriate delays
- [ ] Validates sender is legitimate account

### Factory
- [ ] Address is deterministic (CREATE2)
- [ ] Salt includes owner to prevent front-running
- [ ] `getAddress` matches actual deployment
- [ ] Initialization is atomic with deployment

### General
- [ ] No storage access violations (ERC-7562)
- [ ] Gas limits are reasonable
- [ ] Chain ID included in signatures
- [ ] Handles Entry Point upgrades gracefully

---

## Common Attack Vectors

| Attack | Description | Prevention |
|--------|-------------|------------|
| **Signature Replay** | Reuse signature on different chain/nonce | Include chainId, use 2D nonces |
| **Paymaster Drain** | Exhaust paymaster funds with spam | Rate limiting, allowlists |
| **Front-Running Deploy** | Attacker deploys with different owner | Include owner in CREATE2 salt |
| **Validation Bypass** | Skip validation checks | Strict Entry Point checks |
| **Session Key Abuse** | Overprivileged session keys | Scope keys to targets/selectors |
| **Gas Griefing** | Waste bundler gas | Efficient validation, reputation |
| **Storage Access** | Access disallowed storage | Follow ERC-7562 rules |

---

## Entry Point Interaction

```solidity
// Entry Point address (same on all EVM chains)
address constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
address constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

// Depositing to Entry Point for gas
interface IEntryPoint {
    function depositTo(address account) external payable;
    function withdrawTo(address payable dest, uint256 amount) external;
    function getDepositInfo(address account) external view returns (DepositInfo memory);
}

// Account must have deposit or paymaster
function ensureFunded() external payable {
    IEntryPoint(entryPoint).depositTo{value: msg.value}(address(this));
}
```

---

## Testing Account Abstraction

```solidity
// Foundry test for AA
contract AccountTest is Test {
    IEntryPoint entryPoint;
    Account account;
    address owner;
    uint256 ownerKey;

    function setUp() public {
        // Fork mainnet for real Entry Point
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        entryPoint = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);

        (owner, ownerKey) = makeAddrAndKey("owner");
        account = new Account(owner, address(entryPoint));

        // Fund account
        vm.deal(address(account), 1 ether);
        entryPoint.depositTo{value: 0.5 ether}(address(account));
    }

    function test_ValidateUserOp() public {
        UserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Sign
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            ownerKey,
            userOpHash.toEthSignedMessageHash()
        );
        userOp.signature = abi.encodePacked(r, s, v);

        // Validate
        vm.prank(address(entryPoint));
        uint256 result = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 0); // Valid
    }

    function test_RejectInvalidSignature() public {
        UserOperation memory userOp = _createUserOp();
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        // Sign with wrong key
        (, uint256 wrongKey) = makeAddrAndKey("attacker");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            wrongKey,
            userOpHash.toEthSignedMessageHash()
        );
        userOp.signature = abi.encodePacked(r, s, v);

        vm.prank(address(entryPoint));
        uint256 result = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(result, 1); // SIG_VALIDATION_FAILED
    }
}
```
