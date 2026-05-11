# EOF (EIP-7692) / Fusaka — Migration & Deployment Audit Playbook

> **Cross-references — do not duplicate content from these files:**
> - `vulnerability-taxonomy.md §22` — 5 EOF vulnerability patterns (GAS removal, EXTCODESIZE, EXTDELEGATECALL, deploy-time validation, audit checklist)
> - `severity-decision-tree.md` — EOF severity classification tree (SELFDESTRUCT, legacy proxy, EXTDELEGATECALL, inline assembly JUMP)
> - `poc-templates.md` — EOF Container Compatibility PoC (legacy-to-EOF DELEGATECALL breakage, SELFDESTRUCT removal, invalid container validation)
> - `l2-crosschain.md` — Fusaka EIP-7825 per-tx gas cap, L2 architecture overview
> - `vulnerability-taxonomy.md §24` — PUSH0 cross-chain compatibility (prior incident pattern, per-chain table)

---

## 1. EOF Overview & Activation Status

### What EOF Is

EIP-7692 is a **meta-EIP** bundling ~11 individual EIPs that collectively define the EVM Object Format.
The key component EIPs:

| EIP | Name | What It Does |
|-----|------|--------------|
| 3540 | EOF Container | New `0xEF00` magic-prefixed bytecode format with typed sections (header, type, code, data) |
| 3670 | Code Validation | Deploy-time validation rejects invalid opcodes, unreachable code, stack underflows |
| 4200 | Static Jumps | `RJUMP` / `RJUMPI` / `RJUMPV` replace dynamic `JUMP` / `JUMPI` |
| 4750 | Functions | Code sections act as subroutines with `CALLF` / `RETF` |
| 5450 | Stack Validation | Compile-time stack depth verification per code section |
| 7480 | Data Section | `DATALOAD` / `DATALOADN` / `DATASIZE` / `DATACOPY` for accessing the data section |
| 3855 | PUSH0 | Zero-cost push of `0x00` (already live since Shanghai, included for completeness) |
| 6206 | `JUMPF` Subroutines | Tail-call optimization via `JUMPF` to other code sections |
| 7069 | Revised Call Instructions | `EXTCALL` / `EXTDELEGATECALL` / `EXTSTATICCALL` replace legacy CALL variants |
| 7761 | `EXTCODETYPE` | Returns 0 (EOA), 1 (legacy), 2 (EOF) — replaces `EXTCODESIZE`-based EOA detection |
| 663 | `DUPN` / `SWAPN` / `EXCHANGE` | Unbounded stack access instructions |

### Activation Timeline

**Fusaka** (Fulu + Osaka) is the hardfork activating EOF on Ethereum mainnet.

| Milestone | Status (as of May 2026) |
|-----------|------------------------|
| Devnets | Active (Pectra+EOF devnets ran through 2025) |
| Testnet (Sepolia/Holesky) | Pending — expected H2 2026 |
| Mainnet | Pending — estimated late 2026 or early 2027 |

**Why this matters now:** Projects compiling with `--experimental-eof` today will deploy
EOF bytecode once Fusaka activates. Auditors reviewing code targeting Fusaka must
understand the migration surface even before mainnet activation.

### L2 Rollout Matrix

EOF activation is **not synchronous** across chains. Each L2 must independently adopt
the EOF-enabled EVM.

| Chain | EOF Support Status (May 2026) | Notes |
|-------|-------------------------------|-------|
| Ethereum L1 | Pending (Fusaka) | Reference implementation |
| Optimism (OP Stack) | Will follow L1 | OP Stack tracks L1 EVM closely; expect 1-3 months after L1 |
| Base | Will follow OP Stack | Same timeline as Optimism |
| Arbitrum (Nitro) | TBD | Arbitrum has custom EVM (Stylus); EOF adoption timeline unclear |
| zkSync Era | Unlikely near-term | Uses zkEVM with custom compilation; EOF requires compiler changes |
| Polygon zkEVM | TBD | Type 2 zkEVM may adopt, but ZK circuit changes needed |
| Scroll | TBD | Type 2 zkEVM; circuit updates required |
| Linea | TBD | Similar to other zkEVMs |

**Audit implication:** A protocol deploying the same Solidity source to multiple chains
may produce **different bytecode** (legacy on chains without EOF, EOF on chains with it)
depending on `evmVersion` settings. This creates a multi-chain compatibility gap.

---

## 2. Compiler & Tooling Support Matrix

All EOF tooling is **experimental** as of May 2026. Auditors must verify exact
versions before relying on any tool output.

### Solidity Compiler (solc)

| Version | EOF Support | Notes |
|---------|------------|-------|
| < 0.8.29 | None | No EOF output capability |
| 0.8.29 | `--experimental-eof` flag | First EOF output; limited opcode coverage |
| 0.8.30-0.8.33 | `--experimental-eof` flag | Improved but still experimental; `--via-ir` required for some features |
| 0.9.x (upcoming) | Expected stable EOF | Likely to make EOF the default output format |

**Key limitations:**
- `--experimental-eof` does **not** guarantee correct output for all Solidity patterns
- Inline assembly using EOF-removed opcodes (`JUMP`, `GAS`, `SELFDESTRUCT`, `EXTCODESIZE`) causes compilation errors — no graceful fallback
- `--via-ir` pipeline may be required; watch for TSTORE Poison interactions (see `vulnerability-taxonomy.md §19.6`)

### Foundry

| Component | Status | Notes |
|-----------|--------|-------|
| `forge build --eof` | Experimental | Compiles contracts to EOF containers (track progress in the foundry-rs/foundry tracker) |
| `forge test --eof` | Experimental | Runs tests in EOF-enabled EVM; gas costs differ from legacy |
| `forge script --eof` | Not available | Deployment scripts cannot target EOF yet (use manual deploy) |
| `cast` EOF inspection | Limited | `cast code` returns raw bytecode; no EOF-specific parsing |
| `chisel` EOF REPL | Not available | Interactive REPL does not support EOF mode |

**Practical setup:**
```bash
# Build with EOF
forge build --eof

# Run tests in EOF mode
forge test --eof -vvv

# Verify EOF container output
xxd out/Contract.sol/Contract.bin | head -1
# Should show: 0000000: ef00 01...  (EOF magic bytes)
```

### Other Tools

| Tool | EOF Support (May 2026) | Notes |
|------|----------------------|-------|
| **Hardhat** | Not supported | No `--eof` equivalent; compilation uses solc but does not enable experimental EOF flag |
| **Slither** | Partial | Can parse EOF-compiled Solidity source; does NOT analyze EOF bytecode directly |
| **Slang** (Nomic) | Parser only | Parses Solidity syntax; not EOF-bytecode-aware |
| **Aderyn** | Not supported | No EOF-specific detectors yet |
| **Echidna** | Not tested | Fuzzer operates at bytecode level; EOF bytecode support unconfirmed |
| **Halmos** | Not tested | Symbolic execution; EOF opcode semantics not modeled |
| **Etherscan** | Pending | Verification of EOF contracts not supported yet; flat bytecode display only |
| **Tenderly** | Pending | Simulation/debugging may not decode EOF containers correctly |

**Auditor takeaway:** As of mid-2026, Foundry with `--eof` is the only viable toolchain
for building and testing EOF contracts. All other tools operate on source code or legacy
bytecode. Plan accordingly.

---

## 3. Migration Playbook: Legacy to EOF

Each recipe below addresses a specific legacy pattern that breaks under EOF.
For the underlying vulnerability descriptions, see `vulnerability-taxonomy.md §22`.

### 3.1 Reentrancy Guards Using `.transfer()` / `.send()`

**Problem:** `.transfer()` and `.send()` forward exactly 2300 gas. The `GAS` opcode
is unavailable in EOF, and the 2300-gas stipend pattern is removed. These calls
fail to compile under `--experimental-eof`.

```solidity
// LEGACY — breaks under EOF
function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    payable(msg.sender).transfer(amount); // GAS opcode unavailable in EOF
}
```

```solidity
// MIGRATED — EOF-safe
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external nonReentrant {
        // Checks
        uint256 bal = balances[msg.sender];
        if (amount > bal) revert InsufficientBalance();

        // Effects
        balances[msg.sender] = bal - amount;

        // Interactions
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}
```

**Audit verification:** Confirm no `transfer()` or `send()` calls remain. Run:
```bash
grep -rn '\.transfer(\|\.send(' src/ --include="*.sol"
```

### 3.2 EOA Detection via `extcodesize == 0`

**Problem:** `EXTCODESIZE`, `EXTCODECOPY`, and `EXTCODEHASH` are unavailable in EOF.
The `extcodesize(addr) == 0` pattern for detecting EOAs fails to compile.

```solidity
// LEGACY — breaks under EOF
function onlyEOA(address caller) internal view {
    uint256 size;
    assembly { size := extcodesize(caller) }
    require(size == 0, "no contracts");
}
```

```solidity
// MIGRATED — EOF-safe using EXTCODETYPE (EIP-7761)
function onlyEOA(address caller) internal view {
    uint256 codeType;
    assembly { codeType := extcodetype(caller) }
    // 0 = EOA, 1 = legacy contract, 2 = EOF contract
    if (codeType != 0) revert ContractsNotAllowed();
}
```

**Alternative (remove check entirely):** The `extcodesize == 0` check was always
bypassable via constructor calls. If the check is not security-critical, consider
removing it rather than migrating to `EXTCODETYPE`.

**Audit verification:** Search for any `extcodesize` usage and verify the replacement
uses `extcodetype` correctly, or that the check has been intentionally removed with
a documented rationale.

### 3.3 Dynamic Jumps in Inline Assembly

**Problem:** EOF replaces `JUMP` / `JUMPI` with static relative jumps (`RJUMP` / `RJUMPI` / `RJUMPV`).
Computed jump destinations are invalid under EOF deploy-time validation.

```solidity
// LEGACY — breaks under EOF
function dispatch(uint256 selector) internal {
    assembly {
        let dest := add(pc(), mul(selector, 32))
        jump(dest) // Dynamic JUMP — rejected by EOF validation
    }
}
```

```solidity
// MIGRATED — EOF-safe using Solidity control flow
function dispatch(uint256 selector) internal {
    if (selector == 0) { _handleDeposit(); }
    else if (selector == 1) { _handleWithdraw(); }
    else if (selector == 2) { _handleClaim(); }
    else { revert InvalidSelector(); }
}
```

**Audit verification:** Grep for `jump(` and `jumpi(` in assembly blocks. All must be
replaced with Solidity-level control flow or static relative jumps.

### 3.4 Gas-Based Exit Conditions

**Problem:** `gasleft()` and the `GAS` opcode are unavailable in EOF. Any logic
that uses remaining gas for decisions (exit conditions, gas forwarding caps) breaks.

```solidity
// LEGACY — breaks under EOF
function processQueue(uint256[] calldata items) external {
    for (uint256 i; i < items.length; ++i) {
        if (gasleft() < 50_000) break; // GAS opcode unavailable
        _process(items[i]);
    }
}
```

```solidity
// MIGRATED — EOF-safe with explicit batch limit
function processQueue(uint256[] calldata items, uint256 batchSize) external {
    uint256 end = items.length < batchSize ? items.length : batchSize;
    for (uint256 i; i < end; ++i) {
        _process(items[i]);
    }
}
```

**Audit verification:** Search for `gasleft()` and `gas()` in assembly. Verify all
gas-dependent logic has been replaced with explicit bounds or batch parameters.

### 3.5 SELFDESTRUCT for Refund Logic

**Problem:** `SELFDESTRUCT` is removed in EOF. Contracts using it for emergency
fund recovery or gas refunds will fail to compile.

```solidity
// LEGACY — breaks under EOF
function emergencyRefund() external onlyOwner {
    selfdestruct(payable(owner));
}
```

```solidity
// MIGRATED — EOF-safe explicit drain + deactivation
contract Vault {
    bool public deactivated;

    function emergencyRefund() external onlyOwner {
        if (deactivated) revert AlreadyDeactivated();
        deactivated = true;
        uint256 balance = address(this).balance;
        (bool ok,) = owner.call{value: balance}("");
        if (!ok) revert TransferFailed();
        emit EmergencyRefund(owner, balance);
    }

    modifier whenActive() {
        if (deactivated) revert ContractDeactivated();
        _;
    }
}
```

**Audit verification:** Grep for `selfdestruct` and `SELFDESTRUCT`. Verify replacement
handles both ETH and ERC-20 token balances, and that the deactivation flag gates all
state-modifying functions.

### 3.6 Self-Modifying Code in Proxy Factories

**Problem:** Some proxy factory patterns deploy bytecode by computing it at runtime
or modifying creation code. EOF deploy-time validation rejects any bytecode that
does not conform to the EOF container structure.

```solidity
// LEGACY — may break under EOF
function deployClone(address impl) internal returns (address) {
    bytes memory code = abi.encodePacked(
        hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
        impl,
        hex"5af43d82803e903d91602b57fd5bf3"
    );
    address clone;
    assembly { clone := create(0, add(code, 0x20), mload(code)) }
    return clone;
}
```

```solidity
// MIGRATED — EOF-safe via deterministic CREATE2 of full EOF-compiled contracts
// IMPORTANT: as of mid-2026, OpenZeppelin Clones.clone() still emits the legacy
// EIP-1167 minimal-proxy bytecode (~45 bytes of legacy opcodes). That bytecode
// is REJECTED by EOF deploy-time validation, so it cannot be used on an
// EOF-only chain until OZ ships an EOF-compatible variant.
//
// Until then, the EOF-safe path is to deploy full EOF-compiled implementations
// (no minimal-proxy clones) via CREATE2 for deterministic addresses.

function deployImplementation(bytes32 salt) internal returns (address impl) {
    bytes memory eofBytecode = type(MyImpl).creationCode; // emitted as EOF container
    assembly {
        impl := create2(0, add(eofBytecode, 0x20), mload(eofBytecode), salt)
    }
    require(impl != address(0), "EOF deploy failed");
}
```

**Audit verification:** Check all `create()` / `create2()` assembly calls. Verify
the deployed bytecode is a valid EOF container if the deployment target enforces
EOF. Specifically reject any usage of `Clones.clone()` / `Clones.cloneDeterministic()`
on EOF-only chains until OpenZeppelin publishes EOF-compatible minimal proxies.

---

## 4. Proxy & Upgrade Path Strategy

This is the highest-risk area for EOF migration. The fundamental constraint:
**`EXTDELEGATECALL` (EOF) can only call other EOF contracts. `DELEGATECALL` (legacy)
cannot call EOF contracts.** Cross-format delegation always fails.

For the vulnerability pattern details, see `vulnerability-taxonomy.md §22.3`.
For the severity classification, see `severity-decision-tree.md → EOF`.

### Decision Matrix

| Proxy Format | Impl Format | Delegation | Works? | Recommendation |
|-------------|-------------|------------|--------|----------------|
| Legacy | Legacy | `DELEGATECALL` | Yes | No action needed; stays on legacy indefinitely |
| EOF | EOF | `EXTDELEGATECALL` | Yes | Cleanest path; deploy fresh as all-EOF |
| Legacy | EOF | `DELEGATECALL` | **No** | **Critical failure** — proxy permanently bricked for this impl |
| EOF | Legacy | `EXTDELEGATECALL` | **No** | EXTDELEGATECALL only targets EOF; legacy impl unreachable |

### Strategy A: All-EOF Deployment (Greenfield)

New projects should deploy everything as EOF from the start.

**Steps:**
1. Compile all contracts (proxy + implementation) with `--experimental-eof`
2. Verify all bytecode starts with `0xEF00` magic
3. Ensure `EXTDELEGATECALL` is used in the proxy fallback (solc handles this automatically for EOF target)
4. Test the full upgrade path with `forge test --eof`

**Risk:** Tooling is experimental. Verify bytecode correctness manually.

### Strategy B: All-Legacy Deployment (Status Quo)

Existing protocols on legacy bytecode with no EOF migration planned.

**Steps:**
1. Keep `evmVersion` at `paris` or `shanghai` to avoid accidental EOF compilation
2. Pin `solc` version to < 0.9.x until ready to migrate
3. Add `foundry.toml` guard:

```toml
[profile.default]
evm_version = "shanghai"  # Explicitly prevent EOF output
solc = "0.8.28"           # Pin to known-good legacy version
```

**Risk:** When Fusaka activates, legacy contracts continue to work. There is no
forced migration. However, new ecosystem tooling and patterns may assume EOF.

### Strategy C: Full Migration (Legacy to EOF)

The most complex scenario. An existing live protocol needs to move to EOF.

**Steps:**
1. **Audit current proxy architecture** — identify all proxy contracts, their implementations, and the delegation chain
2. **Compile new implementations as EOF** — `forge build --eof`
3. **Deploy new EOF proxy** — the existing legacy proxy cannot be reused; a new proxy using `EXTDELEGATECALL` must be deployed
4. **Migrate state** — either:
   - (a) Copy storage slots from old proxy to new proxy (complex, error-prone)
   - (b) Use a migration contract that reads old state and writes to new proxy
   - (c) If using ERC-1967 with standard slots, the new proxy can be initialized with the same state
5. **Redirect external references** — update all contracts, frontends, and integrations that point to the old proxy address
6. **Deprecate old proxy** — pause the old proxy to prevent split-state issues

**Risk:** State migration is the primary source of bugs. Storage layout must match
exactly between old and new proxies. Use `forge inspect Contract storage-layout` to
verify slot compatibility.

### Strategy D: Diamond Proxy (EIP-2535)

Diamond proxies use `DELEGATECALL` to multiple facets. Under EOF:

- **All facets must be the same format as the diamond** (all-EOF or all-legacy)
- A single legacy facet in an EOF diamond will cause `EXTDELEGATECALL` to fail
- Facet upgrades must ensure the new facet is EOF-compiled

**Migration:** Replace the diamond contract and all facets simultaneously. Partial
migration is not possible.

### UUPS-Specific Considerations

UUPS proxies contain upgrade logic in the implementation, not the proxy:

1. The `_authorizeUpgrade()` function in the current impl must authorize the upgrade
2. The **new EOF implementation** must be deployed first
3. The proxy itself must also be EOF for `EXTDELEGATECALL` to work
4. This means UUPS cannot do an in-place migration — the proxy must be redeployed

**Critical:** If a UUPS proxy is accidentally compiled as EOF while the implementation
remains legacy, the proxy is **permanently bricked**. There is no recovery path.

---

## 5. L2 / Multi-Chain EOF Rollout Considerations

### Asymmetric Activation Problem

When a protocol deploys the same Solidity source to 5 chains, and only 2 of those
chains support EOF, the compiled bytecode will differ:

```
Source: MyToken.sol (Solidity 0.8.33)
├─ Ethereum (Fusaka) → EOF bytecode (0xEF00...)
├─ Optimism (Fusaka) → EOF bytecode (0xEF00...)
├─ Arbitrum (no EOF)  → Legacy bytecode (0x60...)
├─ Base (Fusaka)      → EOF bytecode (0xEF00...)
└─ zkSync (no EOF)    → Legacy bytecode (0x60...)
```

**Implications:**
- `CREATE2` addresses will differ (bytecode hash differs between EOF and legacy)
- Cross-chain message replay may fail if contract address verification is used
- Block explorers may show different verification status per chain

### `evmVersion` Configuration

Set `evmVersion` explicitly per-chain in `foundry.toml`:

```toml
[profile.default]
evm_version = "shanghai"  # Safe default for all chains

[profile.ethereum-fusaka]
evm_version = "osaka"     # EOF-enabled for Ethereum post-Fusaka

[profile.arbitrum]
evm_version = "shanghai"  # Arbitrum without EOF
```

**Hardhat equivalent:**
```typescript
// hardhat.config.ts
const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.33",
    settings: {
      evmVersion: "shanghai", // Override per-network if needed
    },
  },
};
```

### PUSH0 Precedent

The PUSH0 incident (Solidity 0.8.20+ defaulting to Shanghai `evmVersion` on chains
that did not support PUSH0) is the template for how EOF deployment failures will
manifest. See `vulnerability-taxonomy.md §24` for the full pattern.

**Key lesson:** Contracts that compiled fine locally failed to deploy on non-Shanghai
chains with no clear error message. The same will happen with EOF bytecode deployed
to pre-Fusaka chains — `CREATE` / `CREATE2` will return `address(0)`.

### Sidechain / App-Chain Considerations

| Chain Type | EOF Expectation | Audit Action |
|-----------|----------------|--------------|
| OP Stack forks (Base, Zora, Mode) | Will follow Optimism | Verify fork is up-to-date with OP Stack version that includes EOF |
| Arbitrum Orbit chains | Follows Arbitrum Nitro | Verify Nitro version supports EOF before deploying |
| Polygon CDK chains | Uncertain | ZK circuit updates needed; verify with chain team |
| Berachain (EVM fork) | Follows upstream | Check if the fork includes Fusaka changes |
| Avalanche C-Chain | Independent | Verify Avalanche EVM version supports EOF |

### Cross-Chain Bytecode Hash Divergence

If a protocol uses `CREATE2` for deterministic addresses across chains, EOF vs legacy
compilation produces different bytecode hashes, resulting in **different contract
addresses** on different chains. This breaks:

- Counterfactual wallet deployments (ERC-4337)
- Cross-chain governance with address-based voting
- Bridge contracts that verify destination contract by address

**Mitigation:** Use `evmVersion` pinning per chain, or accept different addresses
and update all cross-chain references.

---

## 6. Audit Workflow for EOF-Aware Contracts

### Pre-Audit Questionnaire

Add these questions to the standard intake for any project mentioning EOF or Fusaka:

1. **Target chains:** Which chains will this deploy to? Do all support EOF?
2. **evmVersion setting:** What is the `evmVersion` in `foundry.toml` / `hardhat.config.ts`?
3. **EOF intent:** Is EOF compilation intentional, or was it accidentally enabled?
4. **Proxy architecture:** Is this upgradeable? What proxy pattern? (UUPS, Transparent, Diamond, Beacon)
5. **Legacy dependencies:** Does this contract call or delegate to any legacy (non-EOF) contracts?
6. **Multi-chain deployment:** Same bytecode on multiple chains with different EVM versions?
7. **Tooling versions:** Exact `solc` version, Foundry commit hash, and any custom build steps

### Bytecode Format Verification

After compilation, verify whether the output is EOF or legacy:

```bash
# Check first bytes of compiled contract
xxd out/Contract.sol/Contract.bin | head -1
# EOF:    0000000: ef00 01...  (magic bytes 0xEF0001)
# Legacy: 0000000: 6080 60...  (typical PUSH1 0x80 PUSH1 0x60)

# Batch check all contracts
for f in out/**/*.bin; do
    magic=$(xxd -l 2 -p "$f")
    if [ "$magic" = "ef00" ]; then
        echo "EOF: $f"
    else
        echo "LEGACY: $f"
    fi
done
```

### Tooling Setup

For an EOF audit engagement, ensure:

1. **solc**: Version 0.8.29+ with `--experimental-eof` confirmed working
2. **Foundry**: Latest nightly with `--eof` flag support (`foundryup --nightly`)
3. **Slither**: Run on source code (not bytecode) — Slither detectors work on AST regardless of EOF
4. **Manual review**: Use `vulnerability-taxonomy.md §22` checklist as the starting point

### Findings Categorization

EOF-specific findings should use a dedicated category tag:

| Category Tag | Description |
|-------------|-------------|
| `EOF-COMPAT` | Contract fails to compile or deploy under EOF |
| `EOF-MIGRATION` | Unsafe migration path from legacy to EOF |
| `EOF-PROXY` | Cross-format delegation issue |
| `EOF-TOOLING` | Finding dependent on experimental tooling behavior |
| `EOF-MULTICHAIN` | Different behavior on EOF vs non-EOF chains |

### Reporting Template Addition

Add this section to the audit report when EOF is in scope:

```markdown
## EOF Compatibility Assessment

### Compilation Target
- solc version: X.Y.Z
- EOF flag: --experimental-eof [enabled/disabled]
- evmVersion: [paris/shanghai/osaka]

### EOF Readiness
- [ ] All contracts compile under --eof without errors
- [ ] No removed opcodes (GAS, JUMP, SELFDESTRUCT, EXTCODESIZE) in use
- [ ] Proxy architecture is EOF-compatible (all-EOF or all-legacy)
- [ ] Multi-chain deployment uses correct evmVersion per chain
- [ ] Test suite passes under `forge test --eof`

### EOF-Specific Findings
[List findings with EOF-* category tags]
```

---

## 7. Common Pitfalls & Anti-Patterns Checklist

Flag any of these during review:

### Compilation & Build

- [ ] **Accidental EOF compilation** — `evmVersion` set to `osaka` without the team realizing it produces EOF bytecode
- [ ] **Mixed compilation targets** — some contracts built as EOF, others as legacy, in the same project
- [ ] **`--via-ir` + `--experimental-eof` interaction** — potential for TSTORE Poison (see `vulnerability-taxonomy.md §19.6`) in EOF builds
- [ ] **Test suite not re-run under `--eof`** — gas costs change, opcode availability changes; all tests must pass under the target EVM

### Proxy & Delegation

- [ ] **Legacy proxy upgraded to EOF impl** — `DELEGATECALL` from legacy to EOF fails silently (returns `success=false`)
- [ ] **EOF proxy calling legacy library** — `EXTDELEGATECALL` to legacy library fails
- [ ] **Diamond with mixed facets** — one legacy facet among EOF facets bricks that facet's functionality
- [ ] **UUPS impl deployed as EOF while proxy remains legacy** — proxy permanently bricked

### Storage & State

- [ ] **Storage layout assumption mismatch** — EOF does not change storage layout, but migration from old proxy to new EOF proxy requires exact slot alignment
- [ ] **`address(this).code` introspection** — EOF containers have a different structure than legacy bytecode; code parsing logic breaks
- [ ] **`type(X).creationCode` used in factory** — creation code for EOF contracts has EOF container format; ensure the deploying contract handles this

### External Integration

- [ ] **ABI stability** — function selectors are computed from function signatures, which are unchanged by EOF; ABI should be stable, but **verify** after compilation
- [ ] **Etherscan verification** — EOF contract verification is not supported on most block explorers as of mid-2026; document this limitation for the team
- [ ] **Tooling bytecode parsing** — `ethers.getCode()`, `viem getCode()`, and similar return raw bytecode; downstream parsers may not understand EOF container format
- [ ] **Tenderly / debugging** — transaction simulation and debugging tools may not decode EOF opcode traces correctly

### Deployment & Operations

- [ ] **`CREATE` / `CREATE2` on non-EOF chain** — deploying EOF bytecode to a chain without EOF support returns `address(0)` with no error
- [ ] **Deterministic address divergence** — same source code produces different bytecode hash (EOF vs legacy), breaking `CREATE2` address consistency across chains
- [ ] **Gas cost changes** — EOF may change gas costs for certain operations; hardcoded gas limits in contracts or scripts may fail

---

## 8. EOF Migration Audit Checklist

Organized by deployment phase. Use as a punch list for audit engagements
involving EOF migration or greenfield EOF deployment.

### Pre-Deployment (Items 1-10)

- [ ] **1.** `evmVersion` in build config matches target chain EVM version (`osaka` for EOF, `shanghai` for legacy)
- [ ] **2.** All contracts in the deployment set are the **same format** (all-EOF or all-legacy); no mixed sets
- [ ] **3.** No `JUMP` / `JUMPI` in inline assembly (replaced with Solidity control flow or `RJUMP` / `RJUMPI`)
- [ ] **4.** No `gasleft()` or `gas()` in assembly used for security decisions (replaced with explicit parameters)
- [ ] **5.** No `selfdestruct` (replaced with explicit balance transfer + deactivation flag)
- [ ] **6.** No `extcodesize` / `extcodecopy` / `extcodehash` for EOA detection (replaced with `EXTCODETYPE` or removed)
- [ ] **7.** Proxy pattern is EOF-compatible: proxy and ALL current + planned implementations are the same format
- [ ] **8.** All external library calls via `DELEGATECALL` target the same bytecode format as the caller
- [ ] **9.** `type(X).creationCode` usage verified to produce valid EOF containers when deploying sub-contracts
- [ ] **10.** `forge build --eof` succeeds with zero errors; `forge test --eof` passes all tests

### Deployment (Items 11-20)

- [ ] **11.** Compiled bytecode verified to start with `0xEF0001` (EOF) or `0x6080` (legacy) as intended
- [ ] **12.** Deployment script targets the correct chain and `evmVersion`; no cross-chain `evmVersion` mismatch
- [ ] **13.** `CREATE2` addresses pre-computed using the correct bytecode hash (EOF hash, not legacy hash)
- [ ] **14.** For proxy migration: new EOF proxy deployed before deprecating old legacy proxy
- [ ] **15.** State migration verified: all storage slots match between old and new proxy (use `forge inspect Contract storage-layout`)
- [ ] **16.** For UUPS: new EOF implementation deployed AND new EOF proxy deployed (both required)
- [ ] **17.** For Diamond: all facets are EOF-compiled and registered in the new diamond
- [ ] **18.** Multi-chain: each chain receives the correct bytecode format for its EVM version
- [ ] **19.** Deployment transaction simulated on testnet/devnet before mainnet
- [ ] **20.** Constructor arguments and initializer calls verified correct on the new EOF contracts

### Post-Deployment (Items 21-30)

- [ ] **21.** Contract verification submitted to block explorer (document if EOF verification is unsupported)
- [ ] **22.** All external integrations updated to point to new contract addresses (if proxy migration changed addresses)
- [ ] **23.** Frontend / SDK updated with new ABIs and addresses
- [ ] **24.** Old legacy proxy paused or deprecated to prevent split-state usage
- [ ] **25.** Monitoring / alerting updated for new contract addresses and event topics
- [ ] **26.** Upgrade path tested end-to-end: can the new EOF proxy be upgraded to a newer EOF implementation?
- [ ] **27.** Gas costs compared between legacy and EOF deployment; fee parameters adjusted if needed
- [ ] **28.** Cross-chain message handlers verified: contracts on non-EOF chains can still interact correctly
- [ ] **29.** Emergency procedures (pause, admin recovery) tested on the new EOF contracts
- [ ] **30.** Documentation updated: deployment addresses, proxy architecture diagram, EOF compatibility notes
