# Intent-Based Protocol Security Reference

Security analysis framework for intent-based order execution systems.
Covers Permit2, UniswapX, 1inch Fusion, and general intent protocol patterns.

See `defi-integrations.md` for integration checklists.
See `defi-checklist.md` for protocol-type security checks.

---

## Architecture Overview

```
User signs intent off-chain (EIP-712 typed data)
      │
      ▼
Filler/Solver Network (off-chain matching)
      │
      ▼
On-chain Reactor/Settlement Contract
      │
  validates:
  ├── signature (EIP-712 via Permit2)
  ├── economic terms (price, amounts)
  ├── timing (deadline, Dutch decay)
  └── filler eligibility (exclusive window)
      │
      ▼
Token transfers: user input → filler, filler output → user
```

Key difference from AMMs: **no on-chain state between orders**. Every fill is
a fresh signed intent. Security lives entirely in signature validation + callback logic.

---

## 1. Signature & Nonce Security

### 1.1 Witness Data in Permit2

UniswapX extends `PermitWitnessTransferFrom` to bind order parameters to the permit.
The witness hash must cover ALL order fields to prevent parameter substitution attacks.

**Vulnerable — incomplete witness hash:**
```solidity
// Attacker submits same permit with different order terms
bytes32 witness = keccak256(abi.encode(
    order.deadline,
    order.inputAmount
    // Missing: outputAmount, recipient, exclusiveFiller, nonce, decayParams
));
```

**Secure — full order struct hash:**
```solidity
bytes32 constant ORDER_TYPEHASH = keccak256(
    "DutchOrder("
    "address reactor,"
    "address swapper,"
    "uint256 nonce,"
    "uint256 deadline,"
    "address exclusiveFiller,"
    "uint256 exclusivityOverrideBps,"
    "DutchInput input,"
    "DutchOutput[] outputs"
    ")"
    "DutchInput(address token,uint256 startAmount,uint256 endAmount)"
    "DutchOutput(address token,uint256 startAmount,uint256 endAmount,address recipient)"
);

bytes32 witness = keccak256(abi.encode(ORDER_TYPEHASH, order)); // All fields covered
```

### 1.2 Bitmap Nonce Invalidation

Permit2 uses bitmap nonces (word + bit position) for efficient mass invalidation.

```solidity
// Nonce: upper 248 bits = word position, lower 8 bits = bit position
uint256 wordPos = nonce >> 8;
uint256 bitPos = nonce & 0xff;
uint256 bit = 1 << bitPos;

// Atomically check and set — reverts if already used
uint256 flipped = nonceBitmap[from][wordPos] ^= bit;
require(flipped & bit != 0, "InvalidNonce"); // Was 0 before flip
```

**Risk**: Batch orders with sequential nonces crossing a word boundary may be
partially invalidated by `invalidateUnorderedNonces(wordPos, mask)` calls.

---

## 2. Dutch Auction Price Decay

### 2.1 Decay Calculation

Dutch auctions decay linearly from `startAmount` to `endAmount` over the decay window.

The naive formula assumes `startAmount > endAmount`. For **output** tokens in Dutch orders
the direction is reversed (`endAmount > startAmount` — user receives more over time).
A single direction formula causes an underflow revert in Solidity 0.8+ when used for outputs.

```solidity
// Handles both directions (inputs: start > end, outputs: start < end)
function resolve(
    uint256 startAmount, uint256 endAmount,
    uint256 startTime, uint256 endTime
) internal view returns (uint256) {
    if (block.timestamp <= startTime) return startAmount;
    if (block.timestamp >= endTime) return endAmount;
    uint256 elapsed = block.timestamp - startTime;
    uint256 duration = endTime - startTime; // Must be > 0
    if (startAmount >= endAmount) {
        // Input decay: amount decreases over time
        return startAmount - (startAmount - endAmount) * elapsed / duration;
    } else {
        // Output decay: amount increases over time (user gets more if filler waits)
        return startAmount + (endAmount - startAmount) * elapsed / duration;
    }
}
```

**Audit checks:**
- Is the decay function direction-aware? A single-direction formula underflows on output tokens
- `endTime > startTime` — division by zero if equal
- Can `block.timestamp` be manipulated by L2 sequencer to get better price?
- Is there a minimum decay window to prevent instant-floor fills?

### 2.2 Exclusive Filler Race Condition

The exclusive window gives one filler priority before open competition begins.

```solidity
// VULN: >= allows non-exclusive fill at the exact boundary block
if (block.timestamp >= exclusiveDeadline) return; // Bypassed at boundary

// SECURE: strict > — only open after deadline passes
if (block.timestamp > exclusiveDeadline) return;
require(filler == exclusiveFiller, "Not exclusive filler");
```

---

## 3. Callback Security

### 3.1 Reactor Callback Authentication

```solidity
contract SecureFiller is IReactorCallback {
    IReactor public immutable reactor;

    function reactorCallback(
        ResolvedOrder[] calldata orders,
        bytes calldata callbackData
    ) external override {
        // CRITICAL: only the reactor should call this — otherwise attacker
        // can invoke callback directly with crafted orders and steal tokens
        require(msg.sender == address(reactor), "Only reactor");

        // Input tokens already transferred by reactor — execute fill logic
        // Must transfer/approve output tokens before returning
        for (uint256 i = 0; i < orders.length; i++) {
            for (uint256 j = 0; j < orders[i].outputs.length; j++) {
                OutputToken memory out = orders[i].outputs[j];
                IERC20(out.token).approve(address(reactor), out.amount);
            }
        }
    }
}
```

### 3.2 Flash Loan in Callback

Fillers often flash-loan inside callbacks to avoid capital requirements.

**Risk**: If flash loan repayment fails, the entire tx reverts — safe by design.
However:
- Any external calls inside the callback that emit events or update external state
  before repayment still revert — verify this is acceptable behavior
- Reentrancy via flash loan: confirm the reactor has reentrancy protection

---

## 4. Order Validation Attack Vectors

### 4.1 Recipient Manipulation

If `output.recipient` is set by the filler rather than the signed order:

```solidity
// VULN: filler can redirect output to themselves
struct OrderOutput { address token; uint256 amount; address recipient; }
function fill(Order calldata order, address outputRecipient) external {
    // recipient comes from filler calldata, not from signed order
    _transferOutput(order.outputToken, order.outputAmount, outputRecipient);
}

// SECURE: recipient must come from the signed order struct
function fill(SignedOrder calldata signedOrder) external {
    Order memory order = abi.decode(signedOrder.order, (Order));
    _verifySignature(signedOrder);
    _transferOutput(order.outputToken, order.outputAmount, order.recipient); // From sig
}
```

### 4.2 Token Address Validation

```solidity
// Validate output token is not address(0) and not the same as input
require(output.token != address(0), "Invalid output token");
require(output.token != address(input.token), "Circular fill");
// Validate token contract exists
require(output.token.code.length > 0, "EOA output token");
```

---

## 5. Cross-Chain Intent Risks

### 5.1 Cross-Chain Replay

Intent protocols on multiple chains must domain-separate signatures:
- EIP-712 domain separator MUST include `chainId`
- Orders signed for Arbitrum must not be fillable on Mainnet

### 5.2 Bridge Timing Attacks

If input is on Chain A and output is on Chain B:
- Filler delivers output on B, then claims input on A
- Without atomic settlement, filler can abandon input claim after delivering output
  (loss to filler) OR deliver no output after claiming input (loss to user)
- **Standard solution**: Escrow + HTLC, or trusted cross-chain relayer with slashing

---

## 6. Detection Patterns

```bash
# Find Permit2 usage
grep -r "IPermit2\|PermitTransferFrom\|permitTransferFrom" src/

# Find UniswapX reactor integrations
grep -r "IReactor\|reactorCallback\|DutchOrder\|SignedOrder" src/

# Find Dutch auction decay logic
grep -r "startAmount\|endAmount\|decayStartTime\|decayEndTime" src/

# Find 1inch limit order protocol integration
grep -r "IOrderMixin\|PreInteraction\|PostInteraction\|takerAsset\|makerAsset" src/

# Find exclusive filler window logic
grep -r "exclusiveFiller\|exclusivityEndTime\|exclusiveDeadline" src/
```

---

## 7. Foundry Test Patterns

```solidity
// Test: expired order reverts
function test_revertIfExpired() public {
    DutchOrder memory order = _buildOrder();
    order.info.deadline = block.timestamp - 1;
    vm.expectRevert(DeadlinePassed.selector);
    reactor.execute(SignedOrder(abi.encode(order), _sign(order)));
}

// Test: exclusive filler enforcement
function test_revertIfNotExclusiveFiller(address nonFiller) public {
    vm.assume(nonFiller != exclusiveFiller);
    DutchOrder memory order = _buildOrder();
    order.exclusiveFiller = exclusiveFiller;
    order.exclusivityEndTime = block.timestamp + 100;
    vm.prank(nonFiller);
    vm.expectRevert(NoExclusiveOverride.selector);
    reactor.execute(SignedOrder(abi.encode(order), _sign(order)));
}

// Test: nonce replay prevention
function test_revertOnNonceReplay() public {
    SignedOrder memory so = SignedOrder(abi.encode(order), _sign(order));
    reactor.execute(so);
    vm.expectRevert(InvalidNonce.selector);
    reactor.execute(so); // Same nonce
}

// Test: callback caller authentication
function test_revertIfCallbackCalledDirectly() public {
    ResolvedOrder[] memory orders;
    vm.prank(attacker);
    vm.expectRevert("Only reactor");
    filler.reactorCallback(orders, "");
}
```

---

## References

- [Permit2 Source](https://github.com/Uniswap/permit2)
- [UniswapX Source](https://github.com/Uniswap/UniswapX)
- [1inch Limit Order Protocol v4](https://github.com/1inch/limit-order-protocol)
- [defi-integrations.md](defi-integrations.md) — Integration checklists
- [defi-checklist.md](defi-checklist.md) — Protocol-type security checks
- [account-abstraction.md](account-abstraction.md) — Interacts with intent protocols via ERC-4337
