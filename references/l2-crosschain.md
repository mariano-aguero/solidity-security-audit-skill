# L2 & Cross-Chain Security

Security patterns specific to Layer 2 networks, bridges, and cross-chain protocols.

---

## L2 Architecture Overview

| L2 Type | Examples | Key Security Considerations |
|---------|----------|----------------------------|
| **Optimistic Rollup** | Arbitrum, Optimism, Base | 7-day challenge period, sequencer trust |
| **ZK Rollup** | zkSync Era, Scroll, Linea, Polygon zkEVM | Proof generation, circuit upgrades |
| **Validium** | StarkEx, Immutable X | Data availability off-chain |
| **Sidechain** | Polygon PoS | Separate validator set |
| **Yield-Bearing L2** | Blast | Rebasing ETH/USDB native yield, unique accounting |
| **Alt-DA Rollup** | Base (can use AltDA), Optimism with AltDA | Data availability assumptions differ |

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

## Blast L2 — Yield-Bearing Native Assets

Blast is an Optimistic Rollup where ETH and USDB (Blast's native stablecoin) accrue
yield natively. This creates accounting assumptions that do not exist on other L2s.

### Rebasing ETH and USDB

On Blast, ETH held in a smart contract automatically accrues yield (rebases upward).
USDB (the Blast-native USDC equivalent) also rebases.

```solidity
// VULNERABLE: assumes ETH balance is static (works on all other L2s, breaks on Blast)
contract VaultOnBlast {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value; // this value becomes stale as ETH rebases
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        // address(this).balance > totalDeposits due to accrued yield
        // The yield is permanently stuck in the contract
    }
}
```

**Blast yield modes** (set per contract):
- `AUTOMATIC` (default): ETH/USDB balance increases automatically — unexpected for most contracts
- `VOID`: yield accrues but is not distributed (forfeited to Blast)
- `CLAIMABLE`: yield accumulates and must be explicitly claimed

```solidity
// SECURE: explicitly set yield mode and claim yield
interface IBlast {
    enum YieldMode { AUTOMATIC, VOID, CLAIMABLE }
    function configureClaimableYield() external;
    function claimYield(address contractAddress, address recipientOfYield, uint256 amount)
        external returns (uint256);
    function readClaimableYield(address contractAddress) external view returns (uint256);
}

IBlast constant BLAST = IBlast(0x4300000000000000000000000000000000000002);

contract BlastVault {
    constructor() {
        // Explicitly configure yield behavior
        BLAST.configureClaimableYield(); // yield accumulates, must be explicitly claimed
    }

    function claimAccruedYield(address recipient) external onlyOwner {
        uint256 claimable = BLAST.readClaimableYield(address(this));
        BLAST.claimYield(address(this), recipient, claimable);
    }
}
```

### Blast-Specific Checklist

```
[ ] Yield mode explicitly configured in constructor (not left at default AUTOMATIC)
[ ] If AUTOMATIC: accounting logic handles rebasing balance (no fixed-amount assumptions)
[ ] If CLAIMABLE: yield claim function exists and is access-controlled
[ ] USDB treated as rebasing token (same rules as stETH in DeFi integrations)
[ ] Gas fee revenue mode configured (Blast also has claimable gas fees)
[ ] No invariants that depend on address(this).balance == tracked deposits
[ ] Cross-protocol integrations: downstream protocols aware of rebasing inputs
```

### Blast Gas Revenue

Blast also allows contracts to claim the gas fees spent calling them:

```solidity
interface IBlastPoints {
    function configurePointsOperator(address operator) external;
}

// Configure gas revenue claiming
BLAST.configureClaimableGas(); // gas fees accumulate as claimable
// Claim: BLAST.claimMaxGas(address(this), recipient);
```

**Audit**: Check if gas revenue claiming is implemented or if fees are being forfeited.

---

## zkEVM-Specific Considerations

ZK rollups that implement the EVM (zkEVMs) have subtle differences that can
break contracts written for L1 or other L2s.

### EVM Opcode Differences by zkEVM

| Opcode / Feature | L1 / Arbitrum / Optimism | zkSync Era | Polygon zkEVM | Scroll |
|-----------------|--------------------------|------------|---------------|--------|
| `block.number` | L2 block number | L2 batch | L1 block number | L2 block |
| `block.timestamp` | L2 timestamp | L2 batch time | L1 timestamp | L2 timestamp |
| `blockhash(n)` | Recent L2 hash | Restricted | L1 blockhash | Restricted |
| `PUSH0` | Supported (EIP-3855) | Supported | Not supported (older) | Supported |
| `SELFDESTRUCT` | Restricted (EIP-6780) | Not supported | Not supported | Not supported |
| `CREATE` / `CREATE2` | Standard | Gas model differs | Standard | Standard |
| Native ETH transfer | Standard | Standard | Standard | Standard |

```solidity
// VULNERABLE: relies on blockhash for randomness — unreliable on zkEVMs
function random() external view returns (uint256) {
    return uint256(blockhash(block.number - 1)); // returns 0 on many zkEVMs
}

// VULNERABLE on Polygon zkEVM older deployments: PUSH0 opcode
// Solidity >=0.8.20 emits PUSH0 — will not compile/run on pre-Shanghai zkEVMs
pragma solidity ^0.8.20; // PUSH0 is used, may break on older zkEVM deployments
```

### zkSync Era Specific

```solidity
// zkSync Era: msg.sender of system calls may differ
// Native account abstraction — EOAs and contracts both use AA by default
// Gas estimation differs significantly from L1

// VULNERABLE: hardcoded gas assumption
function withdrawWithExactGas() external {
    (bool ok,) = recipient.call{gas: 21000}(""); // 21000 gas is L1 EOA transfer
    // On zkSync, 21000 may be insufficient due to AA overhead
}

// zkSync: ETH transfers to contracts go through the DefaultAccount
// which may consume more gas than expected
```

**zkSync Era key differences**:
- Native account abstraction (all accounts are smart accounts)
- `ecrecover` precompile address differs from L1
- System contracts at special addresses (0x0000...0001 through 0x0000...ffff)
- `type(C).runtimeCode` not supported in production mode
- ETH is treated as an ERC-20 token internally

### Polygon zkEVM Specific

```solidity
// Polygon zkEVM: block.number returns the L1 block number
// This means block.number can jump by large amounts between consecutive L2 blocks

// VULNERABLE: rate limiting based on block count
mapping(uint256 => uint256) withdrawalsPerBlock;
function withdraw(uint256 amount) external {
    require(withdrawalsPerBlock[block.number] + amount <= LIMIT, "rate limited");
    // On Polygon zkEVM, same block.number may repeat for many L2 blocks
    // Rate limiting is effectively per L1 block, not per L2 block
}
```

### zkEVM Audit Checklist

```
[ ] Solidity version compatible with target zkEVM (PUSH0, Shanghai opcodes)
[ ] blockhash not used for randomness or critical logic
[ ] SELFDESTRUCT not used (not supported on most zkEVMs)
[ ] block.number semantics verified for target chain (L1 vs L2 block)
[ ] block.timestamp semantics verified (L1 vs L2 time)
[ ] Gas estimates not hardcoded (AA overhead differs)
[ ] ecrecover precompile address verified for target chain
[ ] Assembly code reviewed for zkEVM-incompatible opcodes
[ ] CREATE/CREATE2 address derivation verified (may differ from L1)
```

---

## EIP-4844 (Blobs) — L2 Security Implications

EIP-4844 (Dencun upgrade, March 2024) introduced blob transactions, primarily used
by L2s to post data to L1 more cheaply. Contracts on L2 are generally unaffected
directly, but there are indirect security implications.

### Data Availability Assumptions

Blobs are available on L1 for only ~18 days (4096 epochs). After that, the blob
data is pruned. L2s that use blobs for data availability must ensure:

```
[ ] Contracts that verify blob contents use the blob hash (not the full data)
[ ] Fraud/validity proofs can be submitted within the blob availability window
[ ] Long-term data availability is not assumed from blobs alone
[ ] If the protocol needs permanent availability, separate DA layer is used
```

### Blob Hash Access in Contracts

EIP-4844 added `BLOBHASH` opcode (accessible as `blobhash(index)` in Solidity 0.8.24+).

```solidity
// Contracts that verify blob data must use blobhash correctly
function verifyBlobData(uint256 blobIndex, bytes32 commitment) external view {
    bytes32 blobHash = blobhash(blobIndex);
    require(blobHash != bytes32(0), "no blob at index");
    require(blobHash == commitment, "blob mismatch");
    // Note: this only proves the blob was submitted, not the contents
}
```

### Impact on L2 Gas Pricing

Blob fees are separate from regular gas fees and fluctuate independently.
Contracts that estimate L1 data costs for L2 operations must account for blob
fee markets:

```solidity
// Optimism: L1 fee calculation changed post-Dencun
// Old: based on calldata gas cost
// New: based on blob gas cost (much cheaper)
// Contracts using GasPriceOracle.getL1Fee() are updated automatically
// Custom gas estimation logic must be updated

import {GasPriceOracle} from "@eth-optimism/contracts/L2/GasPriceOracle.sol";
// After Ecotone upgrade, getL1Fee() uses blob-based pricing internally
```

---

## L2 Precompile Security

Precompiles are built-in EVM contracts at low addresses. Their availability and
behavior differ across L2s.

### Precompile Address Map

| Precompile | Address | L1 | Arbitrum | Optimism | zkSync Era | Polygon zkEVM |
|-----------|---------|----|---------|---------|-----------|-----------|
| ecrecover | 0x01 | ✓ | ✓ | ✓ | Modified | ✓ |
| SHA256 | 0x02 | ✓ | ✓ | ✓ | ✓ | ✓ |
| RIPEMD-160 | 0x03 | ✓ | ✓ | ✓ | Not native | Not native |
| identity | 0x04 | ✓ | ✓ | ✓ | ✓ | ✓ |
| modexp | 0x05 | ✓ | ✓ | ✓ | Not native | Not native |
| bn256Add | 0x06 | ✓ | ✓ | ✓ | ✓ | ✓ |
| bn256Mul | 0x07 | ✓ | ✓ | ✓ | ✓ | ✓ |
| bn256Pairing | 0x08 | ✓ | ✓ | ✓ | ✓ | ✓ |
| blake2f | 0x09 | ✓ | ✓ | ✓ | Not native | Not native |

```solidity
// VULNERABLE: assumes RIPEMD-160 is available (fails on zkSync Era)
function verifyBitcoinAddress(bytes calldata data) external view returns (bytes20) {
    bytes20 result;
    assembly {
        if iszero(staticcall(gas(), 0x03, add(data, 0x20), mload(data), 0, 20)) {
            revert(0, 0)
        }
        result := mload(0)
    }
    // On zkSync: this call returns success=false or empty data
}

// SECURE: test precompile availability at deployment time
// or use a pure Solidity fallback implementation
```

### ecrecover on zkSync Era

zkSync Era handles `ecrecover` through a system contract, not the standard precompile.
The behavior is compatible but gas costs differ.

```solidity
// Standard ecrecover works on zkSync, but:
// 1. Gas cost is higher (~3x) than on L1
// 2. System contract at 0x0000...0001 handles it internally
// 3. Signature validation in tight loops may be significantly more expensive
```

### L2 Precompile Checklist

```
[ ] All precompiles used in the contract are available on the target L2
[ ] Gas estimates for precompile calls are calibrated for target chain
[ ] RIPEMD-160 and modexp are not used if deploying on zkSync/Polygon zkEVM
[ ] ecrecover gas overhead on zkSync is accounted for in gas limits
[ ] No hardcoded precompile addresses that differ on L2 (e.g., zkSync system contracts)
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
- [ ] Block property differences handled (block.number, block.timestamp semantics)
- [ ] Gas model differences considered
- [ ] Correct oracle addresses for L2
- [ ] Precompile availability verified for target chain
- [ ] zkEVM opcode compatibility (PUSH0, SELFDESTRUCT, blockhash)

### Blast L2
- [ ] Yield mode explicitly configured (not left at default AUTOMATIC)
- [ ] Rebasing ETH/USDB accounting handled in all balance-tracking logic
- [ ] Gas revenue configuration and claiming implemented
- [ ] Downstream integrations aware of rebasing token inputs

### zkEVM
- [ ] Solidity version compatible with target zkEVM opcodes
- [ ] block.number semantics verified for L1-vs-L2 block counting
- [ ] Assembly reviewed for unsupported opcodes
- [ ] SELFDESTRUCT not used in critical flows

### EIP-4844
- [ ] Blob availability window considered for fraud/validity proofs
- [ ] L1 fee estimation updated for post-Dencun blob pricing
- [ ] No long-term data availability assumed from blobs alone

### Cross-Chain Reentrancy
- [ ] CEI pattern for bridge calls
- [ ] State updates before cross-chain messages
- [ ] Reentrancy guards on receivers

---

## L2 Sequencer Feeds (Chainlink)

| Network | Feed Address |
|---------|--------------|
| Arbitrum One | `0xFdB631F5EE196F0ed6FAa767959853A9F217697D` |
| Arbitrum Nova | `0x31d96D87C42679c04A8A2D28Dc1FD7B39AE9bA3e` |
| Optimism | `0x371EAD81c9102C9BF4874A9075FFFf170F2Ee389` |
| Base | `0xBCF85224fc0756B9Fa45aA7892530B47e10b6433` |
| Metis | `0x58218ea7422255EBE94e56b504035a7A0Cd0f4b3` |
| Scroll | `0x45c2b8C204568A03Dc7A2E32B71D67Fe97F908A9` |
| Linea | Not available — use alternative checks |
| zkSync Era | Not available — use alternative checks |

> **Note**: Always verify feed addresses against the official Chainlink documentation
> before deployment — addresses can change between testnets and mainnets.

```solidity
// Standard sequencer check
function checkSequencer() internal view {
    (, int256 answer, uint256 startedAt,,) =
        SEQUENCER_FEED.latestRoundData();

    if (answer != 0) revert SequencerDown();
    if (block.timestamp - startedAt < GRACE_PERIOD) revert GracePeriod();
}
```
