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

## 7. Noir Language Security

Noir is an SNARK-friendly DSL for writing ZK circuits that compiles to ACIR
(Abstract Circuit Intermediate Representation). Commonly used with Barretenberg
(Aztec's proving backend) and Honk/UltraPlonk proof systems.

### 7.1 `unconstrained` Functions

`unconstrained` functions execute off-circuit as witness generation hints.
They are NOT constrained by the proof system — their outputs must be verified
by constrained code before being used.

**Vulnerable — unconstrained result used directly:**
```rust
// Noir
unconstrained fn compute_sqrt(x: Field) -> Field {
    // Runs off-circuit — result is NOT proven to be the correct square root
    std::hint::black_box(x.sqrt())
}

fn verify_sqrt(x: Field, claimed_result: Field) {
    let hint = compute_sqrt(x);
    // VULNERABLE: only checks that hint == claimed_result
    // Does NOT verify that hint^2 == x
    assert(hint == claimed_result);
}
```

**Secure — constrain the witness:**
```rust
fn verify_sqrt(x: Field, claimed_result: Field) {
    let hint = compute_sqrt(x); // Off-circuit hint
    assert(hint * hint == x);   // On-circuit constraint: result^2 == x
    assert(hint == claimed_result);
}
```

**Audit check:** Every `unconstrained` function's output must be verified by
a constrained assertion (using `==` or `assert`) before being used in business logic.

### 7.2 Public vs. Private Input Confusion

Noir distinguishes `pub` (public, visible in proof) from default private inputs.
Misclassifying inputs leaks secrets or allows input substitution by verifiers.

**Vulnerable — secret key declared public:**
```rust
// Secret should be private, but declared pub — leaks to the verifier
fn main(pub secret_key: Field, pub message_hash: Field) -> pub Field {
    // secret_key is now in the proof's public inputs — anyone can read it
    std::hash::pedersen_hash([secret_key, message_hash])[0]
}
```

**Secure:**
```rust
fn main(secret_key: Field, pub message_hash: Field) -> pub Field {
    // secret_key is private (default) — not visible in public outputs
    std::hash::pedersen_hash([secret_key, message_hash])[0]
}
```

**Audit checks:**
- [ ] Are all secret values (private keys, salts, hidden amounts) declared without `pub`?
- [ ] Are all values needed for on-chain verification declared as `pub`?
- [ ] Is the return value type (`pub` or private) consistent with verifier expectations?

### 7.3 Field Arithmetic Range Issues

Noir uses BN254 scalar field by default (p ≈ 2^254). Values that appear to be
safe `u64` or `u128` may overflow the field prime in ways that are not caught
without explicit range constraints.

**Audit checks:**
- [ ] Are range constraints applied to inputs that must be bounded (e.g., amounts < 2^64)?
- [ ] Are integer comparisons (`lt`, `gt`) using field arithmetic or bit-constrained arithmetic?
- [ ] Does the circuit field prime match the proving system's requirements (BN254 vs. BLS12-381)?

---

## 8. SP1 (Succinct) — Deep Dive

SP1 is a zkVM that proves RISC-V program execution (written in Rust or C).
Internally uses STARKs; wraps in Groth16 or PLONK proof for cost-effective on-chain verification.

### 8.1 Precompile Security

SP1 provides precompiles for expensive operations (SHA-256, Keccak-256, secp256k1 recovery, etc.).
Incorrect precompile usage produces constraint mismatches.

**Audit checks:**
- [ ] Are precompile inputs correctly formatted and sized per SP1's documentation?
- [ ] Is precompile output validated against expected on-chain computation?
- [ ] Are precompiles only used with supported SP1 versions? (ABI can change between SP1 releases)

### 8.2 Cycle Limits and Denial of Service

SP1 proofs have a maximum cycle count. A user-supplied input that causes excessive
execution cycles can make the proof unprovable — a DoS on the prover infrastructure.

**Vulnerable:**
```rust
// Guest program: unbounded loop driven by user input
fn main() {
    let n: u64 = sp1_zkvm::io::read();  // User-controlled
    for _ in 0..n {                      // n = u64::MAX → cycles exhausted
        // Expensive computation
        sp1_zkvm::io::commit(&heavy_hash());
    }
}
```

**Secure:**
```rust
const MAX_ITERATIONS: u64 = 1_000;

fn main() {
    let n: u64 = sp1_zkvm::io::read();
    assert!(n <= MAX_ITERATIONS, "Input exceeds cycle budget");
    for _ in 0..n {
        sp1_zkvm::io::commit(&heavy_hash());
    }
}
```

**Audit checks:**
- [ ] Are all user-controlled loop bounds capped to a safe maximum?
- [ ] Is the maximum cycle count profiled in CI against the on-chain proof budget?
- [ ] Is there a timeout / maximum proving time enforced by the off-chain proving service?

### 8.3 Committed Output Integrity

SP1 uses `sp1_zkvm::io::commit()` to write values to the public journal (output).
The on-chain verifier must validate ALL committed outputs — not just the final result.

**Vulnerable — partial output validation:**
```solidity
contract SP1Consumer {
    ISP1Verifier public immutable verifier;
    bytes32 public immutable PROGRAM_ID;

    function processProof(bytes calldata proof, bytes calldata publicValues) external {
        verifier.verifyProof(PROGRAM_ID, publicValues, proof);
        // VULNERABLE: only checks the last committed value
        (uint256 result) = abi.decode(publicValues, (uint256));
        // Missing: block number check, state root check, nonce check
        _apply(result);
    }
}
```

**Secure:**
```solidity
contract SP1Consumer {
    ISP1Verifier public immutable verifier;
    bytes32 public immutable PROGRAM_ID;
    mapping(bytes32 => bool) public usedProofs;

    function processProof(bytes calldata proof, bytes calldata publicValues) external {
        verifier.verifyProof(PROGRAM_ID, publicValues, proof);

        (
            bytes32 stateRoot,
            uint256 blockNumber,
            uint256 nonce,
            uint256 result
        ) = abi.decode(publicValues, (bytes32, uint256, uint256, uint256));

        require(stateRoot == expectedStateRoot, "Wrong state root");
        require(blockNumber <= block.number, "Future block");

        bytes32 proofHash = keccak256(publicValues);
        require(!usedProofs[proofHash], "Proof replay");
        usedProofs[proofHash] = true;

        _apply(result);
    }
}
```

---

## 9. Polygon CDK — Custom Chain Deployment

Polygon CDK allows teams to deploy custom ZK-rollup chains using Polygon's proving stack
(AggLayer, Plonky3, or Prover service). Each CDK chain has its own contracts on L1
and a centralized sequencer by default.

### 9.1 Sequencer Centralization

CDK chains ship with a centralized sequencer. Users must trust this sequencer
for liveness and censorship resistance unless a force-include mechanism exists.

**Audit checks:**
- [ ] Who controls the sequencer? Is the key a multisig or a single EOA?
- [ ] Is there a force-include mechanism so users can bypass a censoring sequencer?
- [ ] What is the force-include timelock? (should be ≤ 24 hours to limit censorship window)
- [ ] Is there an emergency halt mechanism and who controls it?

### 9.2 LxLy Bridge Security

CDK uses the LxLy (Layer-by-Layer) bridge for L1↔L2 and L2↔L2 communication.
The bridge is shared across all CDK chains connected to AggLayer — a bug affects all of them.

**Audit checks:**
- [ ] Is the LxLy bridge being used for arbitrary message passing (not just token transfers)?
- [ ] Are message origins validated on the destination chain (not just that a message arrived)?
- [ ] Is the bridge contract itself upgradeable? If so, who holds the upgrade key?
- [ ] Are bridge messages idempotent? Can a message be replayed after execution?

**Replay protection pattern:**
```solidity
// CDK bridge message handler — must prevent replay
contract CDKMessageReceiver {
    mapping(bytes32 => bool) public processedMessages;

    function onMessageReceived(
        address originAddress,
        uint32 originNetwork,
        bytes calldata data
    ) external onlyBridge {
        bytes32 messageId = keccak256(abi.encode(originAddress, originNetwork, data));
        require(!processedMessages[messageId], "Already processed");
        processedMessages[messageId] = true;
        _handleMessage(data);
    }
}
```

### 9.3 Proof Aggregation and Chain ID Isolation

AggLayer aggregates proofs from multiple CDK chains into a single L1 proof.
If chain ID isolation is incorrect, a proof from chain A could settle state for chain B.

**Audit checks:**
- [ ] Is the CDK chain's `chainId` included as a public input in every proof?
- [ ] Is the L1 verifier contract chain-specific, or shared across multiple CDK chains?
- [ ] Are cross-chain proofs rejected if their `chainId` doesn't match the verifier's expected chain?

---

## 10. Folding Schemes (Nova, SuperNova, ProtoStar, HyperNova)

Folding schemes enable Incrementally Verifiable Computation (IVC): proving a long sequential
computation by "folding" each step into an accumulator instead of constructing one large circuit.
The final folded instance produces a single succinct proof.

Used in: recursive zkVMs (many EVM steps), client-side proving, rollup aggregation pipelines.

### 10.1 What They Are

```
Step1 → Step2 → Step3 → ... → StepN
  ↓fold  ↓fold  ↓fold       ↓final proof

Each step folds its output into a "running instance" (accumulator).
Only the final accumulated instance requires a succinct proof.
```

### 10.2 Cross-Step State Consistency

Each step's output must equal the next step's input. An incomplete constraint
between steps allows state injection — a prover can "teleport" state across steps.

**Audit check for IVC-based systems:**
- [ ] Is the "running instance" (accumulated state hash) correctly constrained between steps?
- [ ] Are there checks that the initial state matches the known genesis/checkpoint state?
- [ ] Is the fold verification recursive — does step N verify step N-1's accumulator?

### 10.3 Accumulator Soundness

The accumulator must not allow substitution of a fake intermediate step
without the verifier detecting it. This is the core soundness property of the folding scheme.

**Audit checks:**
- [ ] Is the folding implementation from an audited library?
  (Nova by Microsoft Research, folding-schemes by Lita Foundation / PSE)
- [ ] Has the specific folding scheme (Nova vs. SuperNova vs. HyperNova) been independently audited?
- [ ] Are there constraints preventing a prover from "unwinding" the accumulator?

### 10.4 Trusted Setup Requirements

Different folding schemes have different ceremony requirements:

| Scheme | Trusted Setup? | Notes |
|--------|---------------|-------|
| Nova | No (relies on Pedersen commitments) | No ceremony required |
| SuperNova | No | Multi-circuit extension of Nova |
| ProtoStar | No | Generalized folding for arbitrary relations |
| HyperNova | No | Non-uniform IVC, more efficient |

**Audit check:**
- [ ] If the system uses a commitment scheme that requires a setup (e.g., KZG),
  was the ceremony conducted with sufficient participants?

---

## References

- [zkSync Era EVM Differences](https://docs.zksync.io/build/developer-reference/differences-with-ethereum)
- [Polygon zkEVM Differences](https://docs.polygon.technology/zkEVM/architecture/protocol/evm-differences/)
- [ZK Bug Tracker (0xPARC)](https://github.com/0xPARC/zk-bug-tracker)
- [Risc0 Proof Verification Docs](https://dev.risczero.com/api/verifier)
- [SP1 Docs](https://docs.succinct.xyz)
- [l2-crosschain.md](l2-crosschain.md) — L2 general patterns
- [poc-templates.md](poc-templates.md) — Foundry PoC templates
