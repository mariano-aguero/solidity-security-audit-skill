# L2 & Cross-Chain Security

Security patterns specific to Layer 2 networks, bridges, and cross-chain protocols.

---

## L2 Architecture Overview

| L2 Type | Examples | Key Security Considerations |
|---------|----------|----------------------------|
| **Optimistic Rollup** | Arbitrum, Optimism, Base | 7-day challenge period, sequencer trust |
| **ZK Rollup** | zkSync, Scroll, Linea | Proof generation, upgrade mechanisms |
| **Validium** | StarkEx, Immutable X | Data availability off-chain |
| **Sidechain** | Polygon PoS | Separate validator set |

---

## Sequencer Risks

### Sequencer Downtime

The sequencer can go offline, affecting time-sensitive operations.

```solidity
// VULNERABLE: No sequencer check
function liquidate(address user) external {
    require(getHealthFactor(user) < 1e18, "Healthy");
    // Liquidation proceeds...
}

// SECURE: Check L2 sequencer status (Chainlink)
AggregatorV2V3Interface constant SEQUENCER_FEED =
    AggregatorV2V3Interface(0x...) // L2 sequencer feed;

function liquidate(address user) external {
    // Check sequencer is up
    (, int256 answer, uint256 startedAt,,) = SEQUENCER_FEED.latestRoundData();

    bool isSequencerUp = answer == 0;
    require(isSequencerUp, "Sequencer down");

    // Grace period after sequencer comes back up
    uint256 timeSinceUp = block.timestamp - startedAt;
    require(timeSinceUp > GRACE_PERIOD, "Grace period");

    require(getHealthFactor(user) < 1e18, "Healthy");
    // Liquidation proceeds...
}
```

### Sequencer Manipulation

Sequencer can reorder transactions within a block.

```solidity
// VULNERABLE: MEV-extractable on L2
function swap(uint256 amountIn) external returns (uint256) {
    // Sequencer can sandwich this
    uint256 amountOut = calculateOutput(amountIn);
    token.transfer(msg.sender, amountOut);
}

// SECURE: Deadline + slippage protection
function swap(
    uint256 amountIn,
    uint256 minAmountOut,
    uint256 deadline
) external returns (uint256) {
    require(block.timestamp <= deadline, "Expired");
    uint256 amountOut = calculateOutput(amountIn);
    require(amountOut >= minAmountOut, "Slippage");
    token.transfer(msg.sender, amountOut);
}
```

---

## L1 ↔ L2 Message Passing

### Message Replay Protection

```solidity
// VULNERABLE: No replay protection
function processMessage(bytes32 messageHash, bytes calldata data) external {
    require(verifyMessage(messageHash), "Invalid");
    // Process...
}

// SECURE: Track processed messages
mapping(bytes32 => bool) public processedMessages;

function processMessage(bytes32 messageHash, bytes calldata data) external {
    require(!processedMessages[messageHash], "Already processed");
    require(verifyMessage(messageHash), "Invalid");

    processedMessages[messageHash] = true;
    // Process...
}
```

### Message Origin Validation

```solidity
// Arbitrum example
import {AddressAliasHelper} from "@arbitrum/nitro-contracts/src/libraries/AddressAliasHelper.sol";

// VULNERABLE: No sender validation
function receiveFromL1(bytes calldata data) external {
    // Anyone can call
}

// SECURE: Validate L1 sender
address public l1Contract;

function receiveFromL1(bytes calldata data) external {
    // On L2, L1 sender address is aliased
    address expectedSender = AddressAliasHelper.applyL1ToL2Alias(l1Contract);
    require(msg.sender == expectedSender, "Invalid sender");
    // Process...
}
```

### Optimism Cross-Domain Messenger

```solidity
import {ICrossDomainMessenger} from "@eth-optimism/contracts/libraries/bridge/ICrossDomainMessenger.sol";

ICrossDomainMessenger constant MESSENGER =
    ICrossDomainMessenger(0x4200000000000000000000000000000000000007);

// SECURE: Validate cross-domain message
function receiveFromL1(bytes calldata data) external {
    require(
        msg.sender == address(MESSENGER) &&
        MESSENGER.xDomainMessageSender() == l1Contract,
        "Invalid sender"
    );
    // Process...
}
```

---

## Bridge Security Patterns

### Canonical Bridge Risks

| Risk | Description | Mitigation |
|------|-------------|------------|
| **Validator Collusion** | Bridge validators collude to steal | Multi-sig, threshold signatures |
| **Message Forgery** | Fake deposit messages | Merkle proofs, hash verification |
| **Replay Attacks** | Same message processed twice | Nonce tracking, message IDs |
| **Finality Issues** | L1 reorg after bridge action | Wait for finality confirmations |

### Token Bridge Invariant

```solidity
// Fundamental bridge invariant
// Locked on L1 == Minted on L2

contract L1Bridge {
    mapping(address => uint256) public locked;

    function deposit(address token, uint256 amount) external {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        locked[token] += amount;

        // Send message to L2
        messenger.sendMessage(
            l2Bridge,
            abi.encodeCall(IL2Bridge.mint, (token, msg.sender, amount)),
            gasLimit
        );
    }
}

contract L2Bridge {
    mapping(address => uint256) public minted;

    function mint(address token, address to, uint256 amount) external {
        require(msg.sender == messenger && xDomainSender == l1Bridge);

        minted[token] += amount;
        IMintable(l2Token[token]).mint(to, amount);
    }

    // Invariant: l1Bridge.locked[token] >= l2Bridge.minted[token]
}
```

### Rate Limiting for Bridges

```solidity
// Protect against rapid drains
contract RateLimitedBridge {
    uint256 public constant PERIOD = 1 hours;
    uint256 public constant MAX_PER_PERIOD = 1000 ether;

    uint256 public currentPeriodStart;
    uint256 public currentPeriodAmount;

    function withdraw(uint256 amount) external {
        // Reset period if needed
        if (block.timestamp >= currentPeriodStart + PERIOD) {
            currentPeriodStart = block.timestamp;
            currentPeriodAmount = 0;
        }

        require(
            currentPeriodAmount + amount <= MAX_PER_PERIOD,
            "Rate limit exceeded"
        );

        currentPeriodAmount += amount;
        // Process withdrawal...
    }
}
```

---

## Cross-Chain Reentrancy

Reentrancy across chains via bridge callbacks.

```solidity
// VULNERABLE: Cross-chain reentrancy
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function withdrawToL2(uint256 amount, uint256 destChainId) external {
        require(balances[msg.sender] >= amount);

        // Bridge call - attacker's L2 contract receives callback
        bridge.sendTokens{value: msg.value}(
            destChainId,
            msg.sender,  // Attacker's contract on L2
            amount
        );

        // State update AFTER cross-chain call
        balances[msg.sender] -= amount;
    }
}

// SECURE: CEI pattern
function withdrawToL2(uint256 amount, uint256 destChainId) external {
    require(balances[msg.sender] >= amount);

    // State update BEFORE cross-chain call
    balances[msg.sender] -= amount;

    bridge.sendTokens{value: msg.value}(
        destChainId,
        msg.sender,
        amount
    );
}
```

---

## L2-Specific Considerations

### Block Properties Differences

| Property | L1 (Ethereum) | Optimism | Arbitrum | zkSync |
|----------|---------------|----------|----------|--------|
| `block.timestamp` | ~12s blocks | L1 timestamp | L1 timestamp | L2 timestamp |
| `block.number` | L1 blocks | L2 blocks | L2 blocks | L2 batches |
| `block.basefee` | EIP-1559 | Different model | Different model | Different model |
| `blockhash` | Available | Limited | Limited | Limited |

```solidity
// VULNERABLE: Assumes L1 block timing
function isExpired() public view returns (bool) {
    // On L2, block.number increases much faster
    return block.number > deadline;
}

// SECURE: Use timestamps
function isExpired() public view returns (bool) {
    return block.timestamp > deadline;
}
```

### Gas Pricing Differences

```solidity
// L1 gas estimation doesn't work on L2
// Arbitrum: L1 calldata cost + L2 execution cost
// Optimism: L1 data fee + L2 execution fee

// Use L2-specific gas oracles if needed
import {GasPriceOracle} from "@eth-optimism/contracts/L2/GasPriceOracle.sol";

GasPriceOracle constant ORACLE = GasPriceOracle(0x420000000000000000000000000000000000000F);

function estimateCost(bytes calldata data) external view returns (uint256) {
    uint256 l1Fee = ORACLE.getL1Fee(data);
    uint256 l2Fee = gasleft() * tx.gasprice; // Simplified
    return l1Fee + l2Fee;
}
```

---

## Optimistic Rollup Specific

### Challenge Period Considerations

```solidity
// Withdrawals from L2 to L1 have ~7 day delay on Optimistic Rollups

// VULNERABLE: Assumes instant finality
function processL2Withdrawal(bytes calldata proof) external {
    // Process immediately - BAD!
}

// SECURE: Verify challenge period passed
function processL2Withdrawal(
    bytes calldata proof,
    uint256 l2Timestamp
) external {
    require(
        block.timestamp >= l2Timestamp + CHALLENGE_PERIOD,
        "Challenge period not passed"
    );
    require(verifyProof(proof), "Invalid proof");
    // Process...
}
```

### Fraud Proof Implications

- State can be reverted during challenge period
- Don't rely on L2 state for L1 decisions until finalized
- Consider "fast bridges" that take finality risk

---

## ZK Rollup Specific

### Proof Verification

```solidity
// ZK rollups require valid proofs for state transitions
interface IZKVerifier {
    function verify(
        uint256[] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

contract ZKBridge {
    IZKVerifier public verifier;

    function processStateUpdate(
        bytes32 newStateRoot,
        uint256[] calldata proof,
        uint256[] calldata publicInputs
    ) external {
        require(verifier.verify(proof, publicInputs), "Invalid proof");
        require(publicInputs[0] == uint256(newStateRoot), "Root mismatch");

        stateRoot = newStateRoot;
    }
}
```

### Upgrade Risks

ZK rollups often have upgradeability for circuit fixes:

- Check upgrade timelock duration
- Verify upgrade process (multi-sig, governance)
- Review circuit versioning

---

## Cross-Chain Messaging Protocols

### LayerZero Security

```solidity
import {ILayerZeroReceiver} from "@layerzerolabs/contracts/interfaces/ILayerZeroReceiver.sol";

contract SecureLayerZeroReceiver is ILayerZeroReceiver {
    mapping(uint16 => bytes) public trustedRemotes;

    function lzReceive(
        uint16 srcChainId,
        bytes calldata srcAddress,
        uint64 nonce,
        bytes calldata payload
    ) external override {
        // Verify source is trusted
        require(
            msg.sender == address(lzEndpoint),
            "Invalid endpoint"
        );
        require(
            keccak256(srcAddress) == keccak256(trustedRemotes[srcChainId]),
            "Invalid source"
        );

        // Process payload...
    }
}
```

### Chainlink CCIP Security

```solidity
import {CCIPReceiver} from "@chainlink/contracts-ccip/src/v0.8/ccip/applications/CCIPReceiver.sol";

contract SecureCCIPReceiver is CCIPReceiver {
    mapping(uint64 => address) public allowedSenders;

    function _ccipReceive(
        Client.Any2EVMMessage memory message
    ) internal override {
        // Verify sender is allowed
        require(
            allowedSenders[message.sourceChainSelector] ==
            abi.decode(message.sender, (address)),
            "Invalid sender"
        );

        // Process message...
    }
}
```

---

## Checklist: L2 & Cross-Chain Audit

### Sequencer
- [ ] Sequencer uptime check for time-sensitive operations
- [ ] Grace period after sequencer recovery
- [ ] MEV protection (slippage, deadlines)

### Message Passing
- [ ] Message replay protection
- [ ] Source chain/sender validation
- [ ] Nonce handling
- [ ] Message expiry

### Bridge
- [ ] Lock/mint invariant maintained
- [ ] Rate limiting on withdrawals
- [ ] Emergency pause mechanism
- [ ] Multi-sig or threshold signatures

### Finality
- [ ] Challenge period respected (Optimistic)
- [ ] Proof verification (ZK)
- [ ] Reorg handling

### L2-Specific
- [ ] Block property differences handled
- [ ] Gas model differences considered
- [ ] Correct oracle addresses for L2

### Cross-Chain Reentrancy
- [ ] CEI pattern for bridge calls
- [ ] State updates before cross-chain messages
- [ ] Reentrancy guards on receivers

---

## L2 Sequencer Feeds (Chainlink)

| Network | Feed Address |
|---------|--------------|
| Arbitrum One | `0xFdB631F5EE196F0ed6FAa767959853A9F217697D` |
| Optimism | `0x371EAD81c9102C9BF4874A9075FFFf170F2Ee389` |
| Base | `0xBCF85224fc0756B9Fa45aA7892530B47e10b6433` |
| Metis | `0x58218ea7422255EBE94e56b504035a7A0Cd0f4b3` |

```solidity
// Standard sequencer check
function checkSequencer() internal view {
    (, int256 answer, uint256 startedAt,,) =
        SEQUENCER_FEED.latestRoundData();

    if (answer != 0) revert SequencerDown();
    if (block.timestamp - startedAt < GRACE_PERIOD) revert GracePeriod();
}
```
