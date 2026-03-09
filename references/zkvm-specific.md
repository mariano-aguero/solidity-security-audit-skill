# ZK-VM and Zero-Knowledge Proof Security Reference

Security considerations specific to ZK-rollups, ZK-VMs, ZK-coprocessors,
and protocols that use zero-knowledge proofs for on-chain verification.

Covers: zkSync Era, Polygon zkEVM, Scroll, Risc0, SP1, Groth16/PLONK verifiers.

See `l2-crosschain.md` for general L2 security patterns.

---

## 1. ZK Proof Verification Vulnerabilities

### 1.1 Missing Public Input Validation

The most critical class: the verifier confirms a proof is valid for SOME inputs,
but doesn't verify the inputs match the expected on-chain state.

**Vulnerable:**
```solidity
function processProof(
    uint256[2] calldata a,
    uint256[2][2] calldata b,
    uint256[2] calldata c,
    uint256[] calldata publicInputs
) external {
    // Proof is valid — but for WHICH state? publicInputs not checked.
    require(verifier.verifyProof(a, b, c, publicInputs), "Invalid proof");
    // Attacker submits proof for a different state root / balance / block
    _applyStateTransition(publicInputs);
}
```

**Secure:**
```solidity
function processProof(
    uint256[2] calldata a,
    uint256[2][2] calldata b,
    uint256[2] calldata c,
    uint256[] calldata publicInputs
) external {
    // Validate inputs match expected on-chain state BEFORE verifying proof
    require(publicInputs[0] == uint256(lastConfirmedStateRoot), "Wrong state root");
    require(publicInputs[1] == block.chainid, "Wrong chain ID");
    require(publicInputs[2] <= block.number, "Future block");

    require(verifier.verifyProof(a, b, c, publicInputs), "Invalid proof");
    lastConfirmedStateRoot = bytes32(publicInputs[0]);
    _applyStateTransition(publicInputs);
}
```

### 1.2 Trusted Setup Vulnerabilities (Groth16)

Groth16 requires a circuit-specific trusted setup ceremony. If the toxic waste
(trapdoor scalar) is not properly destroyed, anyone holding it can forge valid proofs.

**Audit checks:**
- [ ] Was a multi-party ceremony conducted (Powers of Tau + Phase 2)? How many participants?
- [ ] Is the ceremony transcript publicly auditable?
- [ ] Does the protocol have a migration path to a universal SRS system (PLONK/Halo2)?
- [ ] Are verifier contracts pinned to specific deployed addresses, not upgradeable?

### 1.3 Verifier Contract Soundness

- [ ] Is the verifier generated from an audited tool (snarkjs, gnark, bellman)?
- [ ] Are BN254 curve parameters hardcoded correctly? (q = 21888...for BN254 Groth16)
- [ ] Is there overflow protection in the verifier's finite field arithmetic?
- [ ] Is the verifier contract itself immutable (no proxy, no admin keys)?

---

## 2. ZK-VM EVM Equivalence Gaps

ZK-EVMs may not be 100% EVM-equivalent. Opcodes may behave differently or be unsupported.

### 2.1 Known Differences by VM (2025)

| Feature | zkSync Era | Polygon zkEVM | Scroll | EVM |
|---------|-----------|---------------|--------|-----|
| `SELFDESTRUCT` | Disabled | Disabled | Disabled | Available |
| `BLOCKHASH` | Last 256 | Limited | Limited | Last 256 |
| `block.prevrandao` | Returns 0 | Returns constant | Varies | Beacon randomness |
| `CREATE` address | Different derivation | EVM standard | EVM standard | keccak-based |
| Custom precompiles | Yes | Yes | Yes | No |
| Inline assembly | Supported (with limits) | Supported | Supported | Full |

### 2.2 Critical Audit Checks for ZK-VM Deployments

```bash
# SELFDESTRUCT — fails silently or reverts on most ZK-VMs
grep -r "selfdestruct" src/ --include="*.sol"

# BLOCKHASH for randomness — dangerous on ZK-VMs with limited history
grep -r "blockhash\|block\.difficulty\|block\.prevrandao" src/ --include="*.sol"

# Hardcoded mainnet addresses — wrong on ZK-VMs
grep -r "0xC02aaA39b223\|0xA0b86991c621\|0xdAC17F958D2e" src/ --include="*.sol"

# Inline assembly blocks — may behave differently
grep -n "assembly {" src/ --include="*.sol" -r
```

**Per-network checklist:**
- [ ] Does the contract use `SELFDESTRUCT`? Must be removed for all ZK-VMs
- [ ] Does the contract rely on `block.prevrandao` / `DIFFICULTY` for randomness? Returns constant on ZK-VMs
- [ ] Are all Chainlink feed, WETH, USDC addresses overridden for the target network?
- [ ] Are inline assembly blocks reviewed against the specific ZK-VM's assembly dialect?

### 2.3 zkSync Era Specific

```solidity
// zkSync: All contract deployments use CREATE2 under the hood
// Address derivation differs from mainnet — cross-chain address matching fails

// zkSync: Native account abstraction — msg.sender can be a contract even for "EOA" txs
// Contracts that assume msg.sender.code.length == 0 for EOAs may break

// zkSync: Gas tokens include L1 data publication cost
// L2 execution gas + L1 calldata gas — cost model differs from mainnet
```

**zkSync-specific checks:**
- [ ] Does the contract assume `msg.sender.code.length == 0` means EOA? (Unsafe on zkSync)
- [ ] Are CREATE2 address derivations correct for zkSync's custom salt scheme?
- [ ] Is gas estimation adjusted for L1 data cost on zkSync?
- [ ] Are system contract calls (`ContractDeployer`, `NonceHolder`) handled correctly?

---

## 3. ZK Circuit Vulnerabilities

Relevant when auditing circuits in Circom, Halo2, Noir, or similar DSLs.

### 3.1 Under-Constrained Circuits

The most common ZK circuit bug: a missing constraint lets the prover choose a
witness value freely, including adversarial values.

**Vulnerable Circom — missing reconstruction constraint:**
```circom
template RangeCheck(n) {
    signal input in;
    signal bits[n];
    for (var i = 0; i < n; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (1 - bits[i]) === 0; // Binary: each bit is 0 or 1
        // MISSING: bits must reconstruct `in` — otherwise prover can use any bits
    }
    // Prover can claim any n-bit decomposition regardless of `in`'s actual value
}
```

**Secure — with reconstruction check:**
```circom
template RangeCheck(n) {
    signal input in;
    signal bits[n];
    var lc = 0;
    for (var i = 0; i < n; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (1 - bits[i]) === 0;
        lc += bits[i] * (2 ** i);
    }
    lc === in; // Critical: reconstructed value must equal input
}
```

### 3.2 Field Overflow in Circuit Arithmetic

ZK circuits operate in a finite field. Values that overflow `uint256` may
wrap silently at the field prime (BN254: ~2^254).

**Audit checks:**
- [ ] Are range checks present for all inputs that must be bounded (e.g., amounts < 2^128)?
- [ ] Are multi-precision operations (values > field size) correctly constrained?
- [ ] Does the circuit field prime match the proving system's requirement?

### 3.3 Non-Deterministic Witness Computation

The hint (witness computation) in `<--` is not constrained — only `<==` and `===` are.
Verify that all witness computations are correctly reflected in constraints.

---

## 4. ZK-Coprocessor Patterns (Risc0, SP1)

ZK-coprocessors allow off-chain computation with on-chain proof verification.
Common for storage proofs, historical data queries, and ML inference.

### 4.1 Journal/Output Validation

```solidity
// Risc0: verify proof and decode output
contract CoprocessorConsumer {
    IRisc0Verifier public immutable verifier;
    bytes32 public immutable IMAGE_ID; // Pinned circuit/program hash

    function processResult(bytes calldata seal, bytes calldata journal) external {
        // SECURE: verify both the proof AND that it's for the correct IMAGE_ID
        // Without IMAGE_ID check, attacker submits proof for a different (malicious) program
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        // Decode and validate journal (public outputs from the ZK program)
        (bytes32 stateRoot, uint256 blockNumber, bytes32 resultHash) =
            abi.decode(journal, (bytes32, uint256, bytes32));

        require(stateRoot == expectedStateRoot, "Wrong state root");
        require(blockNumber <= block.number, "Future block");
        require(!usedJournals[resultHash], "Replay"); // Prevent proof replay
        usedJournals[resultHash] = true;

        _applyResult(resultHash);
    }
}
```

**Audit checks:**
- [ ] Is `IMAGE_ID` (program hash) hardcoded or upgradeable? If upgradeable, who controls it?
- [ ] Are ALL journal outputs validated against expected on-chain state?
- [ ] Is there a freshness check on the block number used in the proof?
- [ ] Is proof replay prevented (nonce, journal hash tracking, or block number bounding)?

### 4.2 Guest Program Security

The guest program runs inside the ZK-VM:
- Committed inputs (public) must not be conflatable with private inputs
- Execution must be deterministic — no environment randomness
- Output encoding must match the on-chain journal decoder exactly

---

## 5. Proof System Comparison

| Proof System | Trusted Setup? | Post-Quantum? | Proof Size | Verify Gas (approx) |
|-------------|----------------|---------------|-----------|---------------------|
| Groth16 | Yes (circuit-specific) | No | ~200 bytes | ~300k |
| PLONK | Yes (universal SRS) | No | ~1 KB | ~500k |
| STARKs | No | Yes | 50–200 KB | 1–5M |
| Risc0 (STARK + Groth16 wrapper) | No (STARK) | Yes | ~200 bytes | ~300k |
| Halo2 | No | No | ~1 KB | ~400k |
| Nova/SuperNova | No | No | Small | Fast |

**Implications for auditors:**
- Groth16 ceremony integrity is the single point of failure — validate it thoroughly
- STARK-based systems (Risc0, Polygon Plonky2) require no ceremony and are post-quantum
- Verify gas costs may make frequent on-chain verification impractical for some systems

---

## 6. Detection Patterns

```bash
# Find ZK verifier calls
grep -r "verifyProof\|verify_proof\|verifier\.verify\|IGroth16Verifier" src/

# Find IMAGE_ID / circuit hash patterns (Risc0/SP1)
grep -r "IMAGE_ID\|imageId\|programHash\|guestId" src/

# Find journal decode patterns
grep -r "abi\.decode.*journal\|journal.*abi\.decode" src/

# Find SELFDESTRUCT (not available on ZK-VMs)
grep -r "selfdestruct\|SELFDESTRUCT" src/ --include="*.sol"

# Find hardcoded chain-specific addresses
grep -rE "0x[0-9a-fA-F]{40}" src/ --include="*.sol" | grep -v "test\|Test\|mock\|Mock"
```

---

## References

- [zkSync Era EVM Differences](https://docs.zksync.io/build/developer-reference/differences-with-ethereum)
- [Polygon zkEVM Differences](https://docs.polygon.technology/zkEVM/architecture/protocol/evm-differences/)
- [ZK Bug Tracker (0xPARC)](https://github.com/0xPARC/zk-bug-tracker)
- [Risc0 Proof Verification Docs](https://dev.risczero.com/api/verifier)
- [SP1 Docs](https://docs.succinct.xyz)
- [l2-crosschain.md](l2-crosschain.md) — L2 general patterns
- [poc-templates.md](poc-templates.md) — Foundry PoC templates
