# Move Language Security — Sui / Aptos / Movement Audit Supplement

> **This is a SUPPLEMENT, not a primary reference.** The core skill targets Solidity/EVM.
> This file equips an EVM auditor to **triage** Move code and ask the right questions,
> not to replace a Move-native auditor. For production Move audits, engage firms with
> dedicated Move expertise: OtterSec, Zellic, MoveBit, Veridise.

> **Cross-references — do not duplicate content from these files:**
> - `vulnerability-taxonomy.md §3.4` — Math overflow sentinel (Cetus pattern, applicable to Move math libs)
> - `exploit-case-studies.md #12` — Cetus DEX on Sui ($223M, May 2025) — full exploit analysis
> - `l2-crosschain.md` — Bridge security patterns (apply to EVM ↔ Move bridges)
> - `defi-integrations.md` — General DeFi integration patterns (oracle, AMM, lending)

---

## 1. Move Language & VM Overview

### What Move Is

Move is a resource-oriented programming language originally developed for the Diem (Libra)
blockchain by Meta. It was designed from the ground up to handle digital assets safely by
encoding ownership and scarcity directly into the type system through **linear types**.

Three major ecosystems use Move today:

| Ecosystem | Move Variant | Account Model | Key Difference |
|-----------|-------------|---------------|----------------|
| **Sui** | Sui Move (Move 2024) | Object-centric | Objects are first-class; no global storage operators |
| **Aptos** | Aptos Move | Account-centric | Global storage via `move_to`/`move_from`; closer to original Diem Move |
| **Movement** | Aptos Move on Ethereum | Account-centric | M2 settles on Ethereum; inherits Aptos Move semantics |

### Core Concepts

**Abilities** are the central type-system mechanism. Every struct must declare which
abilities it possesses:

| Ability | Meaning | Audit Implication |
|---------|---------|-------------------|
| `copy` | Value can be duplicated | Tokens with `copy` = infinite mint bug |
| `drop` | Value can be silently destroyed | Debt obligations with `drop` = silent debt deletion |
| `store` | Value can be saved to persistent storage | Without `store`, value is ephemeral (single-tx lifetime) |
| `key` | Value can be used as a top-level storage key | Required for global storage / Sui object creation |

**Linear types**: A struct without `copy` and `drop` MUST be explicitly consumed
(moved into storage, destructured, or passed to a consuming function). The bytecode
verifier enforces this at deploy time. This is what makes Move fundamentally different
from Solidity, where any value can be overwritten or ignored.

### EVM → Move Concept Map

| EVM / Solidity | Move (Sui) | Move (Aptos) |
|----------------|-----------|--------------|
| `address` | `address` / object ID | `address` / `signer` |
| `msg.sender` | `tx_context::sender(ctx)` | `signer::address_of(&signer)` |
| `mapping(K => V)` | `Table<K, V>` / dynamic fields | `Table<K, V>` / `SimpleMap<K, V>` |
| ERC-20 token | `sui::coin::Coin<T>` (object) | `aptos_framework::coin::Coin<T>` / Fungible Asset |
| ERC-721 NFT | Any struct with `key` + `store` | `aptos_token::Token` / `aptos_token_objects` |
| `require(...)` | `assert!(condition, ERROR_CODE)` | `assert!(condition, ERROR_CODE)` |
| `modifier onlyOwner` | Capability pattern (`AdminCap`) | Capability pattern / `signer` check |
| Proxy / upgradeable | Package upgrades (restricted) | Module upgrades (with policy) |
| `selfdestruct` | No equivalent | No equivalent |
| Reentrancy | Not possible (no dynamic dispatch) | Not possible (no dynamic dispatch) |
| Storage slots | Object fields / dynamic fields | Global storage / resources |

### What EVM Auditors Can Skip in Move

The Move bytecode verifier eliminates several entire bug classes present in EVM:

- **Reentrancy** — Move has no dynamic dispatch (`call`/`delegatecall`). Functions are
  statically resolved. Cross-module calls cannot re-enter the caller mid-execution.
- **Storage slot collisions** — Move uses typed storage, not raw 256-bit slots.
- **Uninitialized storage** — The type system prevents reading uninitialized values.
- **Stack-based type confusion** — The bytecode verifier ensures stack safety.
- **Integer type confusion** — Move distinguishes `u8`, `u16`, `u32`, `u64`, `u128`, `u256`
  at the type level; implicit conversion does not exist.

---

## 2. Resource Model Security

### 2.1 Resource Ownership Invariants

Resources (structs without `copy`) can only exist in one location at a time. They cannot
be duplicated, and they cannot be silently discarded (unless they have `drop`). This is
Move's strongest safety guarantee — and the source of its most subtle bugs when misused.

**Audit angle:** Any function that accepts a resource and does not consume it properly
(store, return, or destructure) will fail at compile time. The risk is not in violating
linearity (the verifier catches that) but in **choosing the wrong abilities** for a type.

### 2.2 Ability Mismatches — The Critical Foot-Gun

Declaring incorrect abilities on a struct is the Move equivalent of a Solidity access
control vulnerability, but potentially worse because the type system bakes the mistake
into every consumer of that type.

**Vulnerable — `copy` on a token:**
```move
// CRITICAL: Anyone can duplicate this token infinitely
struct GameToken has copy, drop, store, key {
    value: u64,
}

// Attacker code:
public fun exploit(token: GameToken): (GameToken, GameToken) {
    let duplicate = copy token; // Legal because `copy` ability exists
    (token, duplicate)          // 2x tokens from 1x input
}
```

**Secure — token without `copy`:**
```move
struct GameToken has store, key {
    value: u64,
}
// copy is impossible; move semantics enforced by bytecode verifier
```

**Vulnerable — `drop` on a debt obligation:**
```move
// CRITICAL: Borrower can silently destroy their debt
struct DebtReceipt has drop, store {
    amount: u64,
    borrower: address,
}

public fun borrow(amount: u64, ctx: &mut TxContext): (Coin<SUI>, DebtReceipt) {
    let coin = /* withdraw from pool */;
    let receipt = DebtReceipt { amount, borrower: tx_context::sender(ctx) };
    (coin, receipt) // Borrower receives coin AND receipt
    // Because DebtReceipt has `drop`, borrower can simply ignore the receipt
    // and never repay — the receipt is silently garbage-collected
}
```

**Secure — hot potato pattern (see 2.3):**
```move
struct DebtReceipt has store {
    // No `drop` — MUST be consumed by repay()
    amount: u64,
    borrower: address,
}
```

### 2.3 Hot Potato Pattern

A "hot potato" is a struct with **no `drop` ability** that must be consumed in the same
transaction. The bytecode verifier rejects any transaction that leaves an unconsumed
hot potato. This is Move's equivalent of Solidity's flash loan callback enforcement.

**Common uses:**
- Flash loan repayment receipts (must call `repay()` before tx ends)
- Atomic swap commitments
- Multi-step protocol interactions (must complete all steps)

**Audit angle — two failure modes:**

1. **Missing `drop` is correct but rewards are stuck:** If a rewards struct lacks `drop`
   but no function exists to consume it, users cannot claim their rewards. The struct
   exists in storage forever, and the underlying value is permanently locked.

2. **Presence of `drop` on flash loan receipt = no repayment enforcement:**
```move
// VULNERABLE: flash loan receipt can be dropped without repayment
struct FlashLoanReceipt has drop {
    pool_id: ID,
    amount: u64,
}
// Borrower takes the loan, drops the receipt, never repays
```

```move
// SECURE: receipt MUST be passed to repay()
struct FlashLoanReceipt {
    // No abilities at all — pure hot potato
    pool_id: ID,
    amount: u64,
}

public fun repay(receipt: FlashLoanReceipt, payment: Coin<SUI>) {
    let FlashLoanReceipt { pool_id, amount } = receipt; // Destructure = consume
    assert!(coin::value(&payment) >= amount, E_INSUFFICIENT_REPAYMENT);
    // ... deposit payment back to pool
}
```

### 2.4 Capability Tokens

Move replaces Solidity's role-based access control (`onlyOwner`, `AccessControl`) with
**capability objects** — special structs whose mere possession grants authority.

```move
/// Only the holder of AdminCap can call admin functions
struct AdminCap has key, store {
    id: UID,
}

/// Only the holder of MintCap can mint tokens
struct MintCap<phantom T> has key, store {
    id: UID,
}

public fun mint<T>(cap: &MintCap<T>, amount: u64, ctx: &mut TxContext): Coin<T> {
    // Possessing a reference to MintCap proves authorization
    coin::mint(/* treasury */, amount, ctx)
}
```

**Audit checklist for capabilities:**
- [ ] Where is the capability created? (Typically in `init` — the module publish function)
- [ ] Who receives it? (Should be the deployer; check `transfer::transfer` target)
- [ ] Can it be transferred? (If `store` ability → yes, it can be sent to anyone)
- [ ] Can it be duplicated? (If `copy` ability → catastrophic; any holder can clone it)
- [ ] Is it stored in a shared object? (If yes → anyone with a reference can use it)
- [ ] Is there a way to revoke it? (Unlike Solidity `renounceRole`, Move caps exist as objects)

---

## 3. Sui Object Model Security

Sui uses an **object-centric** model rather than an account-centric model. Every on-chain
entity is an object with a globally unique ID, a version, and an owner.

### 3.1 Object Ownership Types

| Ownership | How Created | Access Rule | Audit Concern |
|-----------|------------|-------------|---------------|
| **Owned** (by address) | `transfer::transfer(obj, addr)` | Only the owner can use it in a transaction | Frozen if owner loses access |
| **Shared** | `transfer::share_object(obj)` | Anyone can use it; requires consensus | Contention under high load; MEV surface |
| **Immutable** | `transfer::freeze_object(obj)` | Read-only forever | Cannot be updated; check if mutability is needed |
| **Wrapped** | Stored inside another object's field | Accessible only through the parent | Parent destruction may orphan child data |

**`transfer::public_transfer` vs `transfer::transfer`:**
- `transfer::transfer` — can only be called within the module that defines the type
- `transfer::public_transfer` — can be called by anyone, but the type must have `store` ability
- Audit angle: if a capability type has `store`, it can be publicly transferred out of
  the intended holder's control

### 3.2 Object Versioning and Equivocation

Every Sui object has a monotonically increasing version number. To mutate an object,
the transaction must reference the object's latest version. If a user signs two
transactions referencing the same object version, validators detect the equivocation
and the object may become **locked** (temporarily or permanently unusable).

**Audit implications:**
- Protocols that require users to interact with shared objects at high frequency face
  contention and potential locking
- Off-chain systems that construct transactions must track object versions carefully
- An attacker who can cause equivocation on a critical shared object (e.g., a price oracle)
  can create a denial-of-service condition

### 3.3 Dynamic Fields

Sui's dynamic fields (`dynamic_field::add`, `dynamic_field::remove`, `dynamic_field::borrow_mut`)
allow attaching arbitrary key-value pairs to objects at runtime, similar to Solidity's mappings
but attached to specific objects rather than global storage.

**Common bugs:**
- **Stale references:** Borrowing a dynamic field, then removing or replacing it in another
  call within the same PTB (Programmable Transaction Block)
- **Ownership confusion:** A dynamic field's child object is owned by the parent. If the
  parent is transferred, the child goes with it — which may violate protocol invariants
- **Missing cleanup:** Dynamic fields are not automatically removed when a parent is
  destroyed. Orphaned dynamic fields consume storage fees indefinitely

### 3.4 Programmable Transaction Blocks (PTB)

PTBs allow users to compose multiple Move calls into a single atomic transaction,
passing results between calls. This is analogous to Solidity's multicall pattern but
built into the execution layer.

**Audit angle:**
- **Unintended composition:** A protocol may assume its functions are called individually,
  but PTBs allow users to compose calls in arbitrary order. Example: calling `borrow()`
  and `withdraw_collateral()` in a single PTB without a solvency check between them.
- **Reentrancy-like patterns via PTB:** While true reentrancy is impossible in Move,
  PTB composition can achieve similar effects by interleaving calls to different modules
  within one atomic transaction.
- **Result passing:** PTB results from one call can be passed directly to another.
  A function that returns an intermediate value (e.g., a price) may be bypassed if
  the user substitutes a different value via PTB composition.

### 3.5 Sponsored Transactions

Sui supports sponsored transactions where a third party (sponsor) pays the gas fee.
This is analogous to ERC-4337 paymasters.

**Audit checks:**
- [ ] Does the sponsor validate what transaction the user is submitting? (Blind sponsorship = sponsor pays for malicious txs)
- [ ] Is there replay protection? (Sponsor signature should bind to a specific transaction digest)
- [ ] Can the user inflate gas costs to drain the sponsor? (Gas budget caps required)

### 3.6 Cetus Exploit — Move-Specific Lesson

The Cetus Protocol exploit ($223M, May 2025) is analyzed in full in `exploit-case-studies.md #12`.
The key Move-specific takeaway: **Move's type system and bytecode verifier do not protect
against arithmetic logic bugs.** The overflow occurred in `checked_shlw`, a custom
`integer_mate` library function that used a flawed bitmask to detect overflow in u256
shift operations. The verifier confirmed the code was type-safe and linear — but the
math was simply wrong.

This demonstrates that Move auditors must apply the same rigor to math library review
that EVM auditors apply, despite Move's stronger type guarantees in other areas.
See `vulnerability-taxonomy.md §3.4` for the overflow sentinel pattern.

---

## 4. Aptos-Specific Patterns

### 4.1 Account Model and Resource Accounts

Aptos uses an account-based model similar to Ethereum. Resources are stored under accounts,
accessed via `move_to<T>(signer, resource)` and `move_from<T>(addr)`.

**Resource accounts** are module-controlled accounts created via
`account::create_resource_account(source, seed)`. They return a `SignerCapability` that
allows the module to sign transactions on behalf of the resource account — analogous to
Solidity's factory-created contracts.

```move
struct ModuleData has key {
    signer_cap: account::SignerCapability,
    // Whoever controls this struct controls the resource account
}

public entry fun initialize(deployer: &signer) {
    let (resource_signer, signer_cap) = account::create_resource_account(
        deployer,
        b"my_protocol_seed",
    );
    move_to(deployer, ModuleData { signer_cap });
    // Resource account is now controlled by this module
}
```

**Audit checks:**
- [ ] Where is `SignerCapability` stored? (Must be in a struct with restricted access)
- [ ] Can `SignerCapability` be extracted via a public function? (= full account takeover)
- [ ] Is the seed deterministic? (Predictable addresses may enable front-running)

### 4.2 Fungible Asset (FA) Standard

Aptos is migrating from the legacy `coin::Coin<T>` standard to the new Fungible Asset
framework (`fungible_asset::FungibleAsset`). FA provides richer metadata, fungible stores
per account, and dispatch hooks for transfer/withdraw/deposit.

**Audit angle — dual-standard confusion:**
- During migration, some protocols accept both `Coin<T>` and the FA version of the same asset
- Liquidity can fragment between the two standards
- A protocol that only checks `coin::balance<T>(addr)` may miss FA balances held in
  `FungibleStore`, and vice versa
- Conversion functions (`coin::coin_to_fungible_asset`, `coin::fungible_asset_to_coin`)
  must be audited for rounding or supply-tracking mismatches

### 4.3 Object<T> on Aptos

Aptos also has an object model (separate from Sui's), where objects are addressed by
a deterministic `address` derived from their creation parameters. Unlike Sui objects,
Aptos objects are accessed via their address, not passed as transaction arguments.

**Key differences from Sui objects:**

| Feature | Sui Object | Aptos Object |
|---------|-----------|--------------|
| Identification | Object ID (32-byte UID) | Derived address |
| Ownership | Explicit (owned/shared/immutable) | Owner field in `ObjectCore` |
| Transfer | `transfer::transfer` / `transfer::public_transfer` | `object::transfer(obj, new_owner)` |
| Shared access | `transfer::share_object` | No direct equivalent; use `ObjectGroup` or resource accounts |

### 4.4 Aptos Randomness API

Aptos provides on-chain randomness via `aptos_framework::randomness`. This is a VRF-based
system where validators produce randomness per block.

**Test-and-abort (gas manipulation) attack:**
An attacker submits a transaction that uses randomness, checks the result, and aborts
if unfavorable (paying only gas). They retry until the result is favorable.

```move
// VULNERABLE: attacker can test-and-abort
public entry fun roll_dice(player: &signer) {
    let result = randomness::u64_range(1, 7);
    if (result == 6) {
        // Award jackpot
        coin::transfer<AptosCoin>(/* pool */, signer::address_of(player), JACKPOT);
    };
    // If result != 6, attacker aborts tx and retries
}
```

**Mitigation:** Aptos provides `#[randomness]` annotation which forces the entry function
to commit to the transaction before randomness is revealed, preventing test-and-abort.

```move
#[randomness]
entry fun roll_dice(player: &signer) {
    // Randomness is committed before this function sees it
    let result = randomness::u64_range(1, 7);
    // Cannot abort based on result — tx is already committed
    if (result == 6) {
        coin::transfer<AptosCoin>(/* pool */, signer::address_of(player), JACKPOT);
    };
}
```

**Audit check:**
- [ ] Does the randomness-consuming function use the `#[randomness]` annotation?
- [ ] Can a wrapper function call the randomness function and abort based on the result?
- [ ] Is the randomness used in the same transaction it is generated? (Cross-tx randomness is predictable)

---

## 5. Move Bytecode Verifier — What It Catches and What It Does Not

The Move bytecode verifier runs at module publish time. It rejects any module that
violates structural or type-safety rules. This is fundamentally different from the EVM,
which has no deploy-time validation (pre-EOF).

### 5.1 Verifier Guarantees (EVM auditors can skip these)

| Guarantee | EVM Equivalent Bug | Verdict |
|-----------|-------------------|---------|
| Type safety — no type confusion on stack | ABI encoding/decoding mismatch | Eliminated |
| Resource linearity — no duplication or silent destruction | N/A (EVM has no equivalent) | Eliminated |
| No unauthorized capability creation | N/A | Eliminated |
| Stack balance — no underflow/overflow | Stack too deep / underflow | Eliminated |
| No dynamic dispatch | Reentrancy via external calls | Eliminated |
| Module encapsulation — private functions truly private | Internal function called via delegatecall | Eliminated |
| Reference safety — no dangling references | N/A | Eliminated |

### 5.2 Verifier Does NOT Catch (EVM auditors must focus here)

| Bug Class | Why Verifier Misses It | Example |
|-----------|----------------------|---------|
| Arithmetic overflow in logic | Math is type-safe but can still overflow `u64`/`u128`/`u256` | Cetus `checked_shlw` ($223M) |
| Oracle manipulation | Business logic, not type error | Same as EVM — spot price, stale feeds |
| Capability stored in wrong location | Type-valid but semantically wrong | `MintCap` stored in a shared object |
| Incorrect access control logic | `assert!` conditions can be wrong | Checking wrong address for admin |
| Economic exploits | Protocol design, not code safety | Flash loan attacks via PTB composition |
| Rounding / precision errors | Arithmetic correctness ≠ type correctness | Same as EVM — division truncation |
| Incorrect event emission | Events are not constrained by verifier | Missing or misleading events |
| Upgrade-related state corruption | New module version with changed struct layout | Similar to EVM proxy storage collision |
| Generic type confusion | Phantom types not validated at runtime | `Coin<FakeUSDC>` treated as `Coin<USDC>` |

### 5.3 Audit Implication

Move auditors can skip entire categories of EVM bugs (reentrancy, storage collisions,
uninitialized storage, stack manipulation) and instead focus disproportionately on:

1. **Ability declarations** — correct `copy`/`drop`/`store`/`key` for every struct
2. **Capability distribution** — who holds which caps, can they leak or be cloned
3. **Arithmetic correctness** — same rigor as EVM; the verifier does not help here
4. **PTB/transaction composition** — the "new reentrancy" in Move
5. **Generic type parameters** — phantom types and type confusion

---

## 6. Common Move Audit Findings

These patterns recur across public audit reports from OtterSec, Zellic, MoveBit,
and Veridise. They are the Move-specific equivalents of the "Top 10" Solidity bugs.

### 6.1 Capability Leakage

The most common high-severity Move finding. A capability is stored in a publicly
accessible location or returned by a public function, granting unintended authority.

**Vulnerable — cap stored in shared object:**
```move
struct ProtocolState has key {
    id: UID,
    admin_cap: AdminCap, // Stored inside a shared object
}

// Anyone who can borrow ProtocolState can access admin_cap
public fun get_admin_cap(state: &ProtocolState): &AdminCap {
    &state.admin_cap // Returns a reference to the capability
}
```

**Secure — cap stored as owned object:**
```move
// AdminCap is an owned object, transferred to the deployer at init
fun init(ctx: &mut TxContext) {
    transfer::transfer(
        AdminCap { id: object::new(ctx) },
        tx_context::sender(ctx),
    );
}

// Admin functions require AdminCap as an owned object argument
public fun admin_action(_cap: &AdminCap, /* ... */) {
    // Only the owner of AdminCap can call this
}
```

### 6.2 Arithmetic Overflow in Custom Math Libraries

Move 2024 added checked arithmetic (`checked_add`, `checked_mul`, etc.) but legacy
code and custom libraries may use unchecked operations. Move does abort on overflow
for standard arithmetic (`+`, `-`, `*`, `/`) in recent compiler versions, but custom
bit manipulation (shifts, masks) can produce logically incorrect results without aborting.

This is exactly the Cetus pattern — see `exploit-case-studies.md #12` and
`vulnerability-taxonomy.md §3.4`.

**Audit check:** Review ALL custom math utility modules (`math.move`, `fixed_point.move`,
`full_math.move`) with the same scrutiny applied to Solidity's `FullMath` or `PRBMath`.

### 6.3 Friend Function Abuse

Move's `friend` declaration grants another module permission to call `public(friend)`
functions. Over-broad friend lists effectively make private functions public.

```move
module protocol::core {
    // RISKY: granting friend access to an upgradeable module
    friend protocol::router;
    friend protocol::helper;     // If helper is compromised/upgraded, core is exposed

    public(friend) fun mint_internal(amount: u64): Coin<TOKEN> {
        // Only friends can call this, but friend list is too broad
    }
}
```

**Audit checks:**
- [ ] Is the friend list minimal? (Each friend should need access to specific functions)
- [ ] Are any friends upgradeable modules? (Upgrading a friend can escalate privileges)
- [ ] Could the function be refactored to use capability tokens instead of `friend`?

### 6.4 Generic Type Confusion

Move generics with `phantom` type parameters are not instantiated at runtime. An attacker
can create `Coin<FakeToken>` where `FakeToken` has no value, and pass it to a function
that does not verify the type parameter against a registry.

```move
// VULNERABLE: accepts any Coin<T> without verifying T is a legitimate token
public fun deposit<T>(coin: Coin<T>, pool: &mut Pool) {
    let value = coin::value(&coin);
    pool.total_deposits = pool.total_deposits + value;
    // T could be attacker-created worthless token
    coin::put(&mut pool.balance, coin); // Wrong pool.balance type needed
}
```

**Secure:** Constrain `T` to registered types or use type-specific pools:
```move
public fun deposit(coin: Coin<USDC>, pool: &mut Pool<USDC>) {
    // T is fixed to USDC — no confusion possible
}
```

### 6.5 Init Function Replay Protection

In Sui, the `init(ctx: &mut TxContext)` function runs exactly once when the module is
published. However, custom "initialize" entry functions used alongside `init` (or instead
of it on Aptos) need explicit replay protection.

```move
// VULNERABLE: can be called multiple times
public entry fun initialize(admin: &signer) {
    let admin_cap = AdminCap { /* ... */ };
    move_to(admin, admin_cap);
    // Second call: aborts because admin already has AdminCap? Only if move_to checks.
    // On Aptos, move_to DOES abort if resource already exists — but check anyway.
}
```

**Audit check:**
- [ ] Is the `init` function (Sui) or module initialization (Aptos) idempotent or protected?
- [ ] If using a custom `initialize` function, is there a flag or resource existence check?
- [ ] Can a front-runner call `initialize` before the intended admin?

### 6.6 Struct Ability Escalation via Upgrade

When a module is upgraded, struct definitions can be changed. Adding `store` ability
to a struct that previously lacked it makes the struct persistable in contexts the
original design did not anticipate.

**Audit check:**
- [ ] What is the module's upgrade policy? (`compatible`, `immutable`, `additive`)
- [ ] Can struct abilities be added in an upgrade? (Depends on upgrade policy)
- [ ] Would adding `copy` or `store` to any existing struct create a vulnerability?

---

## 7. Cross-VM Bridge Security (EVM ↔ Move)

When a protocol bridges Ethereum and Sui/Aptos, the audit surface includes both VMs
plus the bridge layer. Apply all patterns from `l2-crosschain.md` plus the following
Move-specific considerations.

### 7.1 Bridge Protocols on Sui & Aptos

| Bridge | Sui Support | Aptos Support | Verification Method |
|--------|-----------|---------------|---------------------|
| Wormhole | Yes (wormhole-sui) | Yes (wormhole-aptos) | Guardian multisig (19 validators, 13/19 threshold) |
| LayerZero | Yes (LayerZero V2) | Yes (LayerZero V2) | DVN (Decentralized Verifier Network) |
| Circle CCTP | Yes | Yes | Attestation service (centralized) |

**Audit checks for bridge integrations:**
- [ ] Is the bridge contract on the Move side verified against the official deployment?
- [ ] Are message payloads decoded with strict type checking? (Move's strong typing helps here)
- [ ] Is the source chain validated? (Reject messages from unexpected chains)

### 7.2 Token Wrapping — Decimal and Supply Mismatches

| Issue | EVM Side | Move Side | Risk |
|-------|----------|-----------|------|
| Decimals | ERC-20: typically 18 or 6 | Sui Coin: configurable at creation | Over/under-crediting on bridge |
| Supply tracking | `totalSupply()` on-chain | `coin::total_supply<T>()` or `TreasuryCap` | Inflation if bridge mints without locking |
| Burn mechanism | `burn(amount)` | `coin::burn(treasury_cap, coin)` requires `TreasuryCap` | Bridge must hold `TreasuryCap` for wrapped tokens |

**Critical check:** When bridging ERC-20 (6 decimals, e.g., USDC) to Sui Coin (configured
with 9 decimals), the bridge must scale amounts correctly. A missing decimal conversion
means 1 USDC on Ethereum could become 1000 USDC on Sui or vice versa.

### 7.3 Address Format Mismatches

| Chain | Address Size | Format |
|-------|-------------|--------|
| Ethereum / EVM | 20 bytes | `0x` + 40 hex chars |
| Sui | 32 bytes | `0x` + 64 hex chars |
| Aptos | 32 bytes | `0x` + 64 hex chars (with optional leading zeros trimmed in display) |

**Risks:**
- EVM 20-byte addresses zero-padded to 32 bytes for Move: verify padding is consistent
  (left-pad, not right-pad)
- Move 32-byte addresses truncated to 20 bytes for EVM: information loss, potential
  collision (different Move addresses mapping to the same EVM address)
- Bridge message replay: a message targeting Sui address `0xABC...` should not be
  replayable on Aptos even if the address format matches

### 7.4 Cetus Bridge Exit Pattern

The Cetus exploit ($223M) demonstrated that bridge withdrawal caps are a critical
defense-in-depth mechanism. After exploiting the overflow bug on Sui, the attacker
attempted to bridge stolen funds to Ethereum via Circle CCTP and Wormhole.

**Defensive pattern from `l2-crosschain.md`:**
- Bridge withdrawal caps proportional to pool TVL
- Time-delayed large withdrawals (>X% of TVL triggers delay)
- Cross-chain monitoring with automatic bridge pause
- Sui-specific: validator committee can freeze objects (used in the Cetus incident)

---

## 8. Move Audit Checklist

30 items across 5 categories. Use as a punch list when triaging Move code.

### Resource & Ability (Items 1-6)

- [ ] **1.** No token/coin type has `copy` ability (infinite duplication)
- [ ] **2.** No debt/obligation/receipt type has `drop` ability (silent destruction)
- [ ] **3.** All hot-potato structs (flash loan receipts, atomic commitments) lack both `copy` and `drop`
- [ ] **4.** Capabilities (`AdminCap`, `MintCap`, `TreasuryCap`) are stored as owned objects, not in shared objects
- [ ] **5.** Capabilities cannot be duplicated (`copy` absent) or transferred without authorization
- [ ] **6.** All struct ability declarations are reviewed — `store` is not granted unnecessarily

### Sui Object Model (Items 7-12)

- [ ] **7.** Shared objects are used only when necessary; owned objects preferred for lower contention
- [ ] **8.** Object ownership transitions are correct (`transfer::transfer` vs `transfer::public_transfer`)
- [ ] **9.** Dynamic fields are cleaned up when parent objects are destroyed or transferred
- [ ] **10.** PTB composition cannot bypass intended call ordering or solvency checks
- [ ] **11.** Object version equivocation does not create denial-of-service on critical protocol objects
- [ ] **12.** Sponsored transaction scope is validated — sponsor cannot be drained by malicious user txs

### Aptos Specifics (Items 13-18)

- [ ] **13.** `SignerCapability` for resource accounts is stored securely (not extractable)
- [ ] **14.** Dual-standard handling (Coin ↔ Fungible Asset) accounts for both balance sources
- [ ] **15.** Randomness-consuming functions use `#[randomness]` annotation (prevents test-and-abort)
- [ ] **16.** Module upgrade policy is appropriate (prefer `immutable` for core financial logic)
- [ ] **17.** `init_module` or custom initialization has replay protection
- [ ] **18.** Resource account seed is not predictable by an attacker (prevents front-running)

### Logic & Math (Items 19-24)

- [ ] **19.** Custom math libraries are reviewed for overflow in bit operations (Cetus pattern)
- [ ] **20.** Fixed-point arithmetic uses checked operations (`checked_add`, `checked_mul`)
- [ ] **21.** Oracle integration validates freshness and source (same as EVM — staleness, manipulation)
- [ ] **22.** Generic type parameters `<T>` are constrained — no attacker-controlled phantom types accepted
- [ ] **23.** `friend` declarations are minimal and do not include upgradeable modules
- [ ] **24.** Event emissions are accurate and complete (not verified by bytecode verifier)

### Bridge & Cross-VM (Items 25-30)

- [ ] **25.** Token decimals are correctly converted between EVM and Move standards
- [ ] **26.** Address format conversion is consistent (20-byte ↔ 32-byte padding scheme)
- [ ] **27.** Bridge messages include source chain ID and are not replayable cross-chain
- [ ] **28.** Bridge withdrawal caps exist proportional to pool TVL
- [ ] **29.** Wrapped token supply on Move side matches locked supply on EVM side
- [ ] **30.** Bridge contract capabilities (`TreasuryCap`, `MintCap`) are not transferable

---

## References

- [Sui Move Documentation](https://docs.sui.io/concepts/sui-move-concepts)
- [Aptos Move Documentation](https://aptos.dev/en/build/smart-contracts)
- [Move Language Reference](https://move-language.github.io/move/)
- [OtterSec — Public Audit Reports](https://osec.io/)
- [Zellic — Public Audit Reports](https://www.zellic.io/research)
- [MoveBit — Move Security Tooling](https://movebit.xyz/)
- [Cetus Exploit Analysis](exploit-case-studies.md) — Case Study #12
- [l2-crosschain.md](l2-crosschain.md) — Bridge security patterns
- [vulnerability-taxonomy.md](vulnerability-taxonomy.md) — §3.4 Math overflow sentinel
