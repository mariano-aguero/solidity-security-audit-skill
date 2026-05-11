# Safe Modules & Guards Security Reference

Security framework for auditing Gnosis Safe (now "Safe") modules, guards,
fallback handlers, and the Zodiac framework ecosystem. Covers Safe v1.3–v1.5,
SafeProxyFactory, Zodiac (Reality.eth, Roles Modifier v2, Delay, Bridge,
Connext, Scope Guard), and social recovery patterns.

See `defi-checklist.md §Safe` for the high-level checklist.
See `vulnerability-taxonomy.md §6` for proxy and upgradeability patterns.
See `vulnerability-taxonomy.md §25` for ERC-1967 storage slot corruption.
See `account-abstraction.md` for ERC-4337 + Safe overlap.
See `prediction-markets.md §2` for UMA OO dispute economics (Reality.eth context).

---

## Architecture Patterns

| Pattern | Examples | Key Risk |
|---------|----------|----------|
| Multisig proxy + singleton | Safe v1.4.1, SafeProxyFactory | Storage collision via delegatecall module |
| Role-scoped module | Zodiac Roles Modifier v2 | Role escalation, parameter allowlist bypass |
| Optimistic execution module | Zodiac Reality Module (UMA/Reality.eth) | Bond manipulation, proposal griefing |
| Time-delayed module | Zodiac Delay Module | Timing attack, cooldown reset grief |
| Cross-chain governance | Zodiac Bridge Module, Connext Module | AMB trust, xCall replay |
| Transaction guard | Safe Guard, Zodiac Scope Guard | Bypass via `execTransactionFromModule` |

**Core invariant**: A Safe with threshold T requires T-of-N owner signatures
for any state-changing operation. Any module, guard, or fallback handler that
weakens this invariant without explicit owner consent is a critical vulnerability.

---

## 1. Trust Model & Architecture

### 1.1 Safe Proxy Architecture

Safe uses a minimal proxy (SafeProxy) pointing to a singleton implementation.
The proxy stores all state (owners, threshold, modules, nonce) in its own
storage. The singleton contains only logic. SafeProxyFactory deploys new
proxies via `createProxyWithNonce`.

Modules are addresses stored in a sentinel-linked list at slot 1. Once enabled,
a module can call `execTransactionFromModule` to execute arbitrary transactions
from the Safe without owner signatures. This makes module installation
equivalent to granting full Safe access.

**Vulnerable -- module with unchecked installation:**
```solidity
pragma solidity ^0.8.20;

contract AutoModule {
    function install(address safe) external {
        // No access control -- attacker installs on any Safe
        ISafe(safe).enableModule(address(this));
    }

    function drain(address safe, address token) external {
        ISafe(safe).execTransactionFromModule(
            token, 0,
            abi.encodeCall(IERC20.transfer, (msg.sender, IERC20(token).balanceOf(safe))),
            Enum.Operation.Call
        );
    }
}
```

**Secure -- module requires Safe threshold approval + timelock:**
```solidity
pragma solidity ^0.8.20;

contract TimelockModule {
    uint256 public constant ACTIVATION_DELAY = 48 hours;
    mapping(address => uint256) public proposedAt;

    function proposeActivation() external {
        require(msg.sender == address(this), "Only via Safe execTransaction");
        proposedAt[msg.sender] = block.timestamp;
    }

    function activate(address safe) external {
        require(proposedAt[safe] != 0 && block.timestamp >= proposedAt[safe] + ACTIVATION_DELAY);
        delete proposedAt[safe];
    }
}
```

### 1.2 Zodiac Framework Topology

Zodiac is a composable module standard by Gnosis Guild. Modules implement the
`IAvatar` interface and can be chained: a Roles Modifier wraps a Delay Module
which wraps a Reality Module. Each layer adds constraints but also attack surface.

**Audit checks:**
- [ ] Is `enableModule()` gated by the Safe's threshold (called via `execTransaction`)?
- [ ] Can a module enable other modules without owner approval?
- [ ] Is there a timelock between module proposal and activation?
- [ ] What is the maximum blast radius if a single module is compromised?
- [ ] Are module permissions scoped (Roles Modifier) or full Safe access?
- [ ] For Zodiac chains: can an inner module bypass outer module constraints?
- [ ] Is the module list bounded? Can unbounded growth cause gas DoS?
- [ ] Does the Safe use `checkModules()` or equivalent to audit active modules?

---

## 2. Module Installation & Lifecycle

### 2.1 enableModule Access Control

`enableModule(address)` adds a module to the Safe's linked list. In Safe v1.4.1,
this function can only be called by the Safe itself (via `execTransaction` with
threshold signatures or via an already-enabled module). The critical risk is
module-to-module escalation: Module A (legitimately installed) enables Module B
(malicious).

**Vulnerable -- module enables arbitrary sub-modules:**
```solidity
pragma solidity ^0.8.20;

contract PluginManager {
    address public safe;

    function installPlugin(address plugin) external {
        // Anyone calls this -- Module A enables arbitrary Module B
        ISafe(safe).execTransactionFromModule(
            safe, 0,
            abi.encodeCall(ISafe.enableModule, (plugin)),
            Enum.Operation.Call
        );
    }
}
```

**Secure -- sub-module requires Safe owner pre-approval:**
```solidity
pragma solidity ^0.8.20;

contract PluginManager {
    address public safe;
    mapping(address => bool) public approvedPlugins;

    function approvePlugin(address plugin) external {
        require(msg.sender == safe, "Only Safe");
        approvedPlugins[plugin] = true;
    }

    function installPlugin(address plugin) external {
        require(approvedPlugins[plugin], "Not approved");
        delete approvedPlugins[plugin];
        ISafe(safe).execTransactionFromModule(
            safe, 0, abi.encodeCall(ISafe.enableModule, (plugin)), Enum.Operation.Call
        );
    }
}
```

### 2.2 Linked List Manipulation

Modules are stored in a sentinel-linked list (`address(0x1)` as sentinel).
`disableModule(address prevModule, address module)` requires the correct
`prevModule` pointer. Providing the wrong `prevModule` silently fails to remove
the target module, leaving it active.

**Real incident -- Radiant Capital ($50M, Oct 2024):** Attackers compromised
3-of-11 multisig signers and used the compromised Safe to install a malicious
module. The module drained funds across multiple chains. The root cause was
insufficient signer operational security, but the module architecture enabled
single-transaction drainage once threshold was reached.

**Audit checks:**
- [ ] Can a module call `enableModule` on the Safe to install sub-modules?
- [ ] Is `disableModule` tested with correct `prevModule` pointer?
- [ ] Can the module linked list grow unboundedly (gas DoS on `getModules()`)?
- [ ] Is there an emergency module-removal mechanism (circuit breaker)?
- [ ] Are module installation events (`EnabledModule`) monitored off-chain?
- [ ] Can a removed module retain state that allows re-exploitation if re-enabled?

---

## 3. delegatecall Storage Collisions

### 3.1 Safe Storage Layout

Safe v1.4.1 uses the following storage layout:

```
slot 0: singleton (address) -- implementation address
slot 1: modules mapping head (sentinel linked list)
slot 2: owners mapping
slot 3: ownerCount (uint256)
slot 4: threshold (uint256)
slot 5: nonce (uint256)
slot 6: _deprecatedDomainSeparator
slot 7: signedMessages mapping
slot 8: approvedHashes mapping
```

A module executed via `delegatecall` runs in the Safe's storage context. If the
module declares state variables, they overwrite the Safe's slots.

**Vulnerable -- module with state variables that overwrite threshold:**
```solidity
pragma solidity ^0.8.20;

// When called via delegatecall from Safe, this module's state
// variables map directly onto the Safe's storage slots
contract DangerousModule {
    address public _slot0;    // overwrites singleton
    address public _slot1;    // overwrites modules head
    address public _slot2;    // overwrites owners mapping slot
    uint256 public _slot3;    // overwrites ownerCount
    uint256 public config;    // slot 4 -- OVERWRITES THRESHOLD

    // If config is set to 0, threshold becomes 0
    // Any single signature (or no signature) can execute transactions
    function initialize(uint256 _config) external {
        config = _config; // writes to slot 4 = Safe's threshold
    }
}
```

**Secure -- namespaced storage (ERC-7201 pattern):**
```solidity
pragma solidity ^0.8.20;

contract SafeModule {
    // ERC-7201: storage at keccak256("safe.module.storage") - 1
    bytes32 private constant STORAGE_SLOT =
        0x5f3e8c03e3b8e5c8b3c7d5a1e9f4b2d6a8c0e2f4a6b8d0e2f4a6b8d0e2f4a5;

    struct ModuleStorage {
        uint256 config;
        mapping(address => bool) authorized;
    }

    function _getStorage() private pure returns (ModuleStorage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function initialize(uint256 _config) external {
        ModuleStorage storage s = _getStorage();
        s.config = _config; // writes to keccak256 slot, not slot 4
    }
}
```

### 3.2 Initializer Collision Risks

Safe uses `setup()` as its initializer, which writes to multiple slots.
If a module's `initialize()` is called via `delegatecall` during Safe setup
(e.g., in a bundled multicall), the module's initialization can corrupt the
Safe's post-setup state.

**Research reference:** OpenZeppelin's "Safe Storage Collision" analysis and
Trail of Bits' audit of Safe v1.3 identified that any contract executed via
`delegatecall` from a Safe must use isolated storage slots. The Safe team
addressed this by recommending `CALL` over `DELEGATECALL` for module execution
in v1.4+, but `delegatecall` remains available via `Enum.Operation.DelegateCall`.

**Audit checks:**
- [ ] Does any module execute via `delegatecall` (`Enum.Operation.DelegateCall`)?
- [ ] If delegatecall: does the module declare any state variables in sequential slots?
- [ ] Does the module use ERC-7201 namespaced storage or keccak256-derived slots?
- [ ] Can the module's `initialize()` be called via `delegatecall` during Safe setup?
- [ ] Has the module's storage layout been verified against the Safe's slot map?
- [ ] For upgradeable modules: does the upgrade preserve storage layout compatibility?

---

## 4. Guards & Bypass Vectors

### 4.1 Transaction Guard Lifecycle

Safe v1.4+ supports transaction guards via `setGuard(address)`. The guard's
`checkTransaction` is called before execution and `checkAfterExecution` after.
Guards validate `to`, `value`, `data`, and `operation` parameters.

**Critical bypass -- execTransactionFromModule skips guards:**

In Safe v1.3 and v1.4.0, `execTransactionFromModule` does NOT invoke the
transaction guard. This means any enabled module can bypass all guard
restrictions. Safe v1.4.1+ introduced separate module guards, but many
deployments still run v1.3/v1.4.0.

**Vulnerable -- guard assumes all transactions pass through it:**
```solidity
pragma solidity ^0.8.20;

contract WithdrawalGuard {
    uint256 public constant DAILY_LIMIT = 10 ether;
    mapping(uint256 => uint256) public dailySpent; // day => spent

    function checkTransaction(
        address to, uint256 value, bytes memory,
        Enum.Operation, uint256, uint256, uint256,
        address, address payable, bytes memory, address
    ) external {
        uint256 today = block.timestamp / 1 days;
        require(dailySpent[today] + value <= DAILY_LIMIT, "Daily limit");
        dailySpent[today] += value;
    }

    // BUG: A module calls execTransactionFromModule(to, value, "", Call)
    // This bypasses checkTransaction entirely -- no daily limit enforced
    function checkAfterExecution(bytes32, bool) external {}
}
```

**Secure -- guard + module guard + module allowlist:**
```solidity
pragma solidity ^0.8.20;

contract ComprehensiveGuard {
    uint256 public constant DAILY_LIMIT = 10 ether;
    mapping(uint256 => uint256) public dailySpent;
    mapping(address => bool) public allowedModules;

    // Transaction guard (owner-signed txns)
    function checkTransaction(
        address, uint256 value, bytes memory,
        Enum.Operation, uint256, uint256, uint256,
        address, address payable, bytes memory, address
    ) external {
        _enforceLimit(value);
    }

    // Module guard (Safe v1.4.1+) -- also checks module-executed txns
    function checkModuleTransaction(
        address, uint256 value, bytes memory,
        Enum.Operation, address module
    ) external returns (bytes32) {
        require(allowedModules[module], "Module not allowed");
        _enforceLimit(value);
        return keccak256("module.guard");
    }

    function _enforceLimit(uint256 value) internal {
        uint256 today = block.timestamp / 1 days;
        require(dailySpent[today] + value <= DAILY_LIMIT, "Daily limit");
        dailySpent[today] += value;
    }

    function checkAfterExecution(bytes32, bool) external {}
}
```

### 4.2 Guard Removal via Module

A module can call `setGuard(address(0))` via `execTransactionFromModule` to
remove the guard entirely. If the guard is the only defense against fund
drainage, a compromised module can remove it before draining.

**Audit checks:**
- [ ] Does the guard's `checkTransaction` validate `to`, `value`, `data`, and `operation`?
- [ ] Can modules bypass the guard via `execTransactionFromModule` (Safe version < v1.4.1)?
- [ ] Is a module guard set (Safe v1.4.1+) in addition to the transaction guard?
- [ ] Can a module call `setGuard(address(0))` to remove the guard?
- [ ] Does the guard handle `data.length == 0` (plain ETH transfer)?
- [ ] For Scope Guard: is the target/selector allowlist comprehensive (no wildcards)?
- [ ] Can the guard be re-entrancy attacked via `checkAfterExecution`?
- [ ] Is guard state (daily limits, counters) stored in the guard contract, not the Safe?

---

## 5. Fallback Handler Attacks

### 5.1 Fallback Handler Trust Model

Safe v1.1+ supports a fallback handler: any call to the Safe that does not
match a Safe function signature is forwarded to the fallback handler via
`delegatecall` (v1.1) or `call` (v1.3+). In v1.3+, the fallback handler
receives the call with `msg.sender` appended to calldata (ERC-2771 pattern).

**Safe v1.3 to v1.4 security model change:** In v1.3, the default
`CompatibilityFallbackHandler` handles `isValidSignature` (ERC-1271),
`getMessageHash`, and token callbacks. In v1.4+, the handler was hardened
to prevent signature replay across chains by including `chainId`.

**Vulnerable -- fallback handler enables attacker module:**
```solidity
pragma solidity ^0.8.20;

contract MaliciousFallbackHandler {
    fallback() external payable {
        address sender;
        assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
        // Malicious: enable attacker as module on any call
        if (sender != address(0)) {
            ISafe(msg.sender).enableModule(address(0xdead));
        }
    }
}
```

**Secure -- minimal handler with explicit function routing:**
```solidity
pragma solidity ^0.8.20;

contract SafeFallbackHandler {
    function isValidSignature(bytes32 hash, bytes calldata sig)
        external view returns (bytes4)
    {
        require(_isValidSafeSignature(msg.sender, hash, sig), "Invalid");
        return 0x1626ba7e; // ERC-1271 magic value
    }

    function onERC721Received(address, address, uint256, bytes calldata)
        external pure returns (bytes4) { return this.onERC721Received.selector; }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external pure returns (bytes4) { return this.onERC1155Received.selector; }

    // No generic fallback -- reject unknown calls
}
```

### 5.2 ERC-1271 Signature Replay

The `CompatibilityFallbackHandler.isValidSignature` validates signatures
against Safe owners. If the implementation does not bind signatures to a
specific chain or nonce, signatures from one chain can be replayed on another
where the same Safe address exists (CREATE2 deterministic deployment).

**Audit checks:**
- [ ] What fallback handler is set? Is it the audited `CompatibilityFallbackHandler`?
- [ ] Can the fallback handler execute state-changing operations?
- [ ] Does `isValidSignature` include `chainId` in the signature domain (EIP-712)?
- [ ] Can the fallback handler be changed without Safe threshold approval?
- [ ] Does the handler correctly implement `onERC721Received` and `onERC1155Received`?
- [ ] Is there a generic `fallback()` that could intercept Safe self-calls?
- [ ] For v1.3 Safes: has the handler been upgraded to include chain-bound signatures?
- [ ] Can the fallback handler be used to call `enableModule()` indirectly?

---

## 6. Recovery & Social Recovery Modules

### 6.1 Zodiac Delay Module Timing Attacks

The Delay Module queues transactions for a configurable cooldown period.
After the cooldown, the transaction can be executed within an expiration window.
Timing attacks exploit the gap between queue and execution.

**Vulnerable -- short cooldown, no cancellation:**
```solidity
pragma solidity ^0.8.20;

contract WeakDelayModule {
    uint256 public constant COOLDOWN = 1 hours; // too short for high-value Safe
    mapping(uint256 => QueuedTx) public queue;

    function queueTx(address to, uint256 value, bytes calldata data) external {
        queue[nonce++] = QueuedTx(to, value, data, block.timestamp);
    }

    function execute(uint256 txNonce) external {
        QueuedTx storage q = queue[txNonce];
        require(block.timestamp >= q.queuedAt + COOLDOWN, "Cooldown");
        // No cancellation -- owners cannot veto a queued malicious tx
        ISafe(avatar).execTransactionFromModule(q.to, q.value, q.data, Enum.Operation.Call);
    }
}
```

**Secure -- adequate cooldown with owner veto:**
```solidity
pragma solidity ^0.8.20;

contract SecureDelayModule {
    uint256 public constant COOLDOWN = 48 hours;
    uint256 public constant EXPIRATION = 7 days;
    mapping(uint256 => bool) public vetoed;

    function queueTx(address to, uint256 value, bytes calldata data)
        external onlyAuthorizedModule
    {
        queue[nonce++] = QueuedTx(to, value, data, block.timestamp);
    }

    function veto(uint256 txNonce) external {
        require(msg.sender == avatar, "Only Safe owners");
        vetoed[txNonce] = true;
    }

    function execute(uint256 txNonce) external {
        QueuedTx storage q = queue[txNonce];
        require(!vetoed[txNonce], "Vetoed");
        require(block.timestamp >= q.queuedAt + COOLDOWN, "Cooldown");
        require(block.timestamp <= q.queuedAt + COOLDOWN + EXPIRATION, "Expired");
        ISafe(avatar).execTransactionFromModule(q.to, q.value, q.data, Enum.Operation.Call);
    }
}
```

### 6.2 Social Recovery Guardian Risks

Social recovery modules allow M-of-N guardians to replace Safe owners. The
critical math: if `M` is too low, guardian collusion drains the Safe; if `M`
is too high, recovery becomes impractical.

**Audit checks:**
- [ ] Is the Delay Module cooldown sufficient (>=24h for significant value)?
- [ ] Can Safe owners veto queued transactions during the cooldown period?
- [ ] Is the recovery threshold (M-of-N) appropriate for the Safe's value?
- [ ] Can a single guardian trigger recovery (M=1)?
- [ ] Can an attacker grief recovery by repeatedly triggering it (resetting timelock)?
- [ ] Are guardians independent from Safe owners (no overlap)?
- [ ] Is there a guardian rotation mechanism with its own timelock?
- [ ] Does recovery conflict with ERC-4337 account recovery (if Safe is a smart account)?

---

## 7. Zodiac Framework Specific Patterns

### 7.1 Reality Module (Optimistic Oracle Execution)

The Reality Module uses Reality.eth (or UMA) to allow anyone to propose
transactions. Proposals require a bond; if undisputed for a period, the
transaction executes. The security model is identical to optimistic oracles:
cost-of-corruption must exceed potential gain.

**Real incident context -- Polymarket UMA disputes (2024):** The same UMA
optimistic oracle economics apply. If the bond is too small relative to the
Safe's assets, an attacker can propose a drain transaction and wait for the
dispute window to pass. See `prediction-markets.md §2` for detailed analysis.

**Vulnerable -- static bond regardless of transaction value:**
```solidity
pragma solidity ^0.8.20;

contract WeakRealityModule {
    uint256 public constant BOND = 100e18; // 100 DAI fixed; Safe holds $10M

    function addProposal(bytes32 questionId, bytes32[] calldata txHashes) external {
        realityOracle.askQuestion(questionId, BOND);
        proposals[questionId] = txHashes;
    }
}
```

**Secure -- dynamic bond scaled to transaction value:**
```solidity
pragma solidity ^0.8.20;

contract SecureRealityModule {
    uint256 public constant MIN_BOND = 1_000e18;
    uint256 public constant BOND_RATIO_BPS = 500; // 5% of tx value

    function addProposal(bytes32 questionId, bytes32[] calldata txHashes, uint256 txValue)
        external
    {
        uint256 bond = txValue * BOND_RATIO_BPS / 10_000;
        bond = bond < MIN_BOND ? MIN_BOND : bond;
        realityOracle.askQuestion{value: 0}(questionId, 48 hours, bond);
        proposals[questionId] = Proposal(txHashes, txValue, block.timestamp);
    }
}
```

### 7.2 Roles Modifier v2

Zodiac Roles Modifier v2 allows scoped permissions: each role defines which
targets, function selectors, and even parameter values a member can call.
Parameter scoping uses `CompValue` and `ComparisonType` (EQ, GT, LT, ONE_OF).

**Known audit finding (Cantina/Spearbit pattern):** Roles Modifier v1 had a
vulnerability where a role with `delegatecall` permission to any target could
bypass all scoping by delegatecalling to a contract that calls the Safe directly.
Roles v2 separates `CALL` and `DELEGATECALL` permissions explicitly.

**Vulnerable -- role with wildcard target and delegatecall:**
```solidity
pragma solidity ^0.8.20;

contract RolesConfig {
    function setupRole(IRolesModifier roles, uint16 roleId) external {
        // Allows roleId to call ANY target with ANY selector
        // AND allows delegatecall -- role can do anything the Safe can
        roles.allowTarget(roleId, address(0), ExecutionOptions.Both);
        // This is equivalent to giving the role full Safe access
    }
}
```

**Secure -- tightly scoped role with parameter constraints:**
```solidity
pragma solidity ^0.8.20;

contract RolesConfig {
    function setupTreasuryRole(
        IRolesModifier roles, uint16 roleId, address token
    ) external {
        // Only allow CALL (not delegatecall)
        roles.scopeTarget(roleId, token);

        // Only allow transfer() with amount <= 10_000e6
        roles.scopeFunction(
            roleId,
            token,
            IERC20.transfer.selector,
            new bool[](2),     // both params are scoped
            new bytes32[](2),  // comparison values
            new uint8[](2)     // comparison types
        );
        // Parameter 0 (to): must be treasury address
        roles.scopeParameter(roleId, token, IERC20.transfer.selector, 0,
            ComparisonType.EQ, abi.encode(treasury));
        // Parameter 1 (amount): must be <= 10_000 USDC
        roles.scopeParameter(roleId, token, IERC20.transfer.selector, 1,
            ComparisonType.LTE, abi.encode(10_000e6));
    }
}
```

### 7.3 Bridge Module & Connext Module

Bridge Module receives cross-chain messages (via AMB or Connext) and executes
them on the Safe. The trust assumption shifts from Safe owners to the bridge
validator set.

**Audit checks:**
- [ ] For Reality Module: is the bond dynamically scaled to transaction/Safe value?
- [ ] Is the Reality.eth dispute window sufficient (>=24h)?
- [ ] Can proposal griefing lock the module (repeated invalid proposals)?
- [ ] For Roles v2: does any role have wildcard target or delegatecall permission?
- [ ] Are role parameters scoped with appropriate ComparisonType (not just EQ)?
- [ ] Can a role grant itself additional permissions (subrole escalation)?
- [ ] For Bridge Module: is the AMB source chain and sender verified?
- [ ] For Connext Module: is `xCall` replay protection enforced (nonce or hash)?

---

## 8. Comprehensive Safe Modules Audit Checklist

Comprehensive checklist for auditing Safe modules, guards, and Zodiac
framework integrations. Items are grouped by audit category.

### Trust & Architecture (6 items)

- [ ] Map all enabled modules and verify each was installed via Safe threshold vote
- [ ] Verify module permissions are scoped (Roles Modifier) not full Safe access
- [ ] Check if any module can enable other modules without owner approval
- [ ] Verify the Safe version (v1.3/v1.4.0/v1.4.1/v1.5) and its guard capabilities
- [ ] Identify all trust assumptions shifted by modules (oracle, bridge, guardians)
- [ ] Verify module installation events are monitored off-chain for unexpected changes

### Module Lifecycle (6 items)

- [ ] Verify `enableModule()` requires Safe threshold signatures (not module self-install)
- [ ] Check for module-to-module privilege escalation (Module A enables Module B)
- [ ] Verify timelock exists between module proposal and activation
- [ ] Test `disableModule()` with correct `prevModule` pointer (sentinel linked list)
- [ ] Check module linked list for unbounded growth potential (gas DoS)
- [ ] Verify removed modules cannot retain exploitable state if re-enabled

### Storage & delegatecall (6 items)

- [ ] Identify all modules that execute via `Enum.Operation.DelegateCall`
- [ ] Verify delegatecall modules use ERC-7201 namespaced storage (not sequential slots)
- [ ] Map module storage slots against Safe layout (slots 0-8) for collisions
- [ ] Check that module `initialize()` cannot be called via delegatecall during Safe setup
- [ ] Verify upgradeable module storage layout compatibility across versions
- [ ] Test that no module operation can set Safe threshold to 0 via slot overwrite

### Guards (6 items)

- [ ] Verify transaction guard checks `to`, `value`, `data`, and `operation` parameters
- [ ] Check if modules bypass the guard via `execTransactionFromModule` (pre-v1.4.1)
- [ ] Verify module guard is set (Safe v1.4.1+) in addition to transaction guard
- [ ] Check if any module can call `setGuard(address(0))` to remove the guard
- [ ] Verify guard handles `data.length == 0` (plain ETH transfers)
- [ ] For Scope Guard: verify target/selector allowlist has no wildcards or gaps

### Fallback Handler (6 items)

- [ ] Identify the active fallback handler and verify it is audited code
- [ ] Verify fallback handler cannot execute state-changing operations
- [ ] Check `isValidSignature` includes `chainId` in EIP-712 domain (no cross-chain replay)
- [ ] Verify fallback handler change requires Safe threshold approval
- [ ] Check handler implements `onERC721Received`/`onERC1155Received` correctly
- [ ] Verify no generic `fallback()` that could intercept Safe self-calls

### Recovery (6 items)

- [ ] Verify recovery guardian threshold (M-of-N) is appropriate for Safe value
- [ ] Check that a single guardian cannot trigger recovery (M >= 2)
- [ ] Verify timelock on recovery execution with owner cancellation window
- [ ] Check for recovery griefing (repeated triggers resetting the timelock)
- [ ] Verify guardians are independent from Safe owners (no overlap)
- [ ] Check for conflicts between social recovery and ERC-4337 account recovery

### Zodiac (6 items)

- [ ] For Reality Module: verify bond is dynamically scaled to Safe/transaction value
- [ ] For Roles Modifier: verify no role has wildcard target + delegatecall permission
- [ ] For Roles Modifier: verify roles cannot grant themselves additional permissions
- [ ] For Delay Module: verify cooldown >= 24h with owner veto capability
- [ ] For Bridge Module: verify AMB source chain and sender address validation
- [ ] For Connext Module: verify xCall replay protection (nonce-based or hash-based)
