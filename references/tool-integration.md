# Security Tool Integration Guide

How to leverage industry-standard smart contract security tools during audits.
Each tool serves a different purpose — use them in combination for maximum coverage.

---

## Tool Overview

| Tool | Type | Developer | Best For |
|------|------|-----------|----------|
| **Slither** | Static analyzer | Trail of Bits | Fast vulnerability detection, CI integration |
| **Aderyn** | Static analyzer | Cyfrin | Solidity-specific patterns, Foundry integration |
| **Echidna** | Property-based fuzzer | Trail of Bits | Invariant testing, complex state exploration |
| **Medusa** | Parallel fuzzer | Trail of Bits | Faster fuzzing via go-ethereum, multi-threaded |
| **Foundry (Forge)** | Testing/fuzzing framework | Paradigm | Unit tests, fuzz tests, gas reports, fork testing |
| **Halmos** | Symbolic testing | a16z | Formal verification of Solidity properties |
| **Certora Prover** | Formal verification | Certora | Mathematical proof of correctness |
| **Mythril** | Symbolic execution | Consensys | Automated vulnerability detection |
| **Manticore** | Symbolic execution | Trail of Bits | Complex multi-tx attacks, full EVM simulation |

---

## 1. Slither (Static Analysis)

**What it detects**: 90+ vulnerability patterns including reentrancy, uninitialized
variables, shadowing, unchecked calls, access control issues, and more.

### Usage

```bash
# Basic run
slither .

# JSON output for programmatic processing
slither . --json slither-report.json

# Run specific detectors only
slither . --detect reentrancy-eth,reentrancy-no-eth,uninitialized-state

# Print contract information
slither . --print human-summary
slither . --print contract-summary
slither . --print function-summary

# Check for upgrade safety
slither . --print upgradeability-checks
```

### Key Detectors by Severity

**High:**
- `reentrancy-eth` — Reentrancy with ETH transfer
- `suicidal` — Functions allowing anyone to selfdestruct
- `uninitialized-state` — State variables not initialized
- `arbitrary-send-eth` — Functions sending ETH to arbitrary addresses

**Medium:**
- `reentrancy-no-eth` — Reentrancy without ETH (state manipulation)
- `locked-ether` — Contracts that receive but cannot send ETH
- `controlled-delegatecall` — Delegatecall with user-controlled target
- `tx-origin` — Using tx.origin for authentication

**Low / Informational:**
- `pragma` — Floating pragma
- `solc-version` — Old Solidity version
- `naming-convention` — Non-standard naming
- `unused-state` — Unused state variables

### CI Integration

```yaml
# GitHub Actions example
- name: Run Slither
  uses: crytic/slither-action@v0.4.0
  with:
    target: '.'
    slither-args: '--json slither-report.json'
```

### Limitations

Slither is fast but may produce false positives. Always manually verify findings.
It cannot detect business logic errors or economic attack vectors.

---

## 2. Aderyn (Static Analysis)

**What it detects**: Solidity-specific patterns with Rust-based speed.
Focuses on AST analysis and produces markdown reports.

### Usage

```bash
# Basic run (scans current directory)
aderyn .

# Specify source directory
aderyn src/

# Output to specific file
aderyn . -o report.md
```

### Key Detectors

- Centralization risks (single owner patterns)
- Unsafe ERC20 operations (missing SafeERC20)
- Reentrancy patterns
- Unprotected initializers
- Missing zero-address checks
- Storage variable shadowing
- Dead code detection

### When to use over Slither

Aderyn is faster on large codebases and produces cleaner markdown reports.
Good as a first-pass complementary to Slither.

---

## 3. Foundry (Forge) — Testing & Fuzzing

**Purpose**: Development framework with built-in testing and fuzzing.
Essential for every audit.

### Unit Testing

```bash
# Run all tests
forge test

# Verbose output (show traces for failures)
forge test -vvvv

# Run specific test
forge test --match-test testWithdraw

# Gas report
forge test --gas-report

# Fork mainnet for integration testing
forge test --fork-url $ETH_RPC_URL
```

### Fuzz Testing

Forge automatically fuzzes any test function with parameters:

```solidity
function testFuzz_Withdraw(uint256 amount) public {
    amount = bound(amount, 1, 100 ether);
    vault.deposit{value: amount}();
    vault.withdraw(amount);
    assertEq(address(vault).balance, 0);
}
```

```bash
# Run with more fuzz iterations
forge test --fuzz-runs 10000
```

### Invariant Testing

Define system invariants that must hold across random sequences of calls:

```solidity
function invariant_totalSupplyMatchesBalances() public {
    uint256 sum = 0;
    for (uint i = 0; i < actors.length; i++) {
        sum += token.balanceOf(actors[i]);
    }
    assertEq(token.totalSupply(), sum);
}
```

```bash
# Run invariant tests
forge test --match-test invariant
```

### Invariant Testing with Handlers

Handlers provide controlled randomness for more effective invariant testing:

```solidity
contract VaultInvariantTest is Test {
    Vault vault;
    VaultHandler handler;

    function setUp() public {
        vault = new Vault();
        handler = new VaultHandler(vault);
        targetContract(address(handler));
    }

    function invariant_SharesEqualBalance() public view {
        assertEq(vault.totalSupply(), address(vault).balance);
    }
}

contract VaultHandler is Test {
    Vault vault;
    address[] public actors;

    constructor(Vault vault_) {
        vault = vault_;
        actors.push(makeAddr("actor1"));
        actors.push(makeAddr("actor2"));
    }

    function deposit(uint256 actorSeed, uint256 amount) public {
        address actor = actors[actorSeed % actors.length];
        amount = bound(amount, 0, 10 ether);
        vm.deal(actor, amount);
        vm.prank(actor);
        vault.deposit{value: amount}();
    }

    function withdraw(uint256 actorSeed, uint256 amount) public {
        address actor = actors[actorSeed % actors.length];
        uint256 balance = vault.balanceOf(actor);
        amount = bound(amount, 0, balance);
        vm.prank(actor);
        vault.withdraw(amount);
    }
}
```

### Fork Testing

Test against real mainnet state for integration scenarios:

```solidity
contract ForkTest is Test {
    uint256 mainnetFork;
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IUniswapV3Pool constant POOL = IUniswapV3Pool(0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8);

    function setUp() public {
        mainnetFork = vm.createFork(vm.envString("ETH_RPC_URL"));
    }

    function test_ForkMainnet() public {
        vm.selectFork(mainnetFork);
        vm.rollFork(18_000_000); // Specific block for reproducibility

        // Test against real Uniswap pool state
        (uint160 sqrtPriceX96,,,,,,) = POOL.slot0();
        assertGt(sqrtPriceX96, 0);
    }

    function test_SimulateSwap() public {
        vm.selectFork(mainnetFork);

        address whale = 0x47ac0Fb4F2D84898e4D9E7b4DaB3C24507a6D503;
        vm.prank(whale);

        // Simulate real swap behavior
        uint256 balanceBefore = USDC.balanceOf(whale);
        // ... perform swap
        uint256 balanceAfter = USDC.balanceOf(whale);

        assertLt(balanceAfter, balanceBefore);
    }
}
```

```bash
# Run fork tests
forge test --fork-url $ETH_RPC_URL -vvv

# Fork at specific block
forge test --fork-url $ETH_RPC_URL --fork-block-number 18000000
```

### Useful Cheatcodes for Security Testing

```solidity
// Impersonate addresses
vm.prank(attacker);
vm.startPrank(attacker);

// Manipulate time
vm.warp(block.timestamp + 1 days);
vm.roll(block.number + 100);

// Deal tokens/ETH
deal(address(token), attacker, 1000 ether);
deal(attacker, 100 ether);

// Expect reverts
vm.expectRevert("Unauthorized");
contract.adminFunction();

// Snapshot and revert state
uint256 snapshot = vm.snapshot();
// ... do stuff ...
vm.revertTo(snapshot);
```

---

## 4. Echidna (Property-Based Fuzzing)

**What it does**: Generates random sequences of transactions to try to
violate user-defined properties. More powerful than Forge fuzzing for
complex state-dependent bugs.

### Writing Properties

```solidity
contract EchidnaTest is MyContract {
    // Properties must start with echidna_
    function echidna_balance_positive() public view returns (bool) {
        return address(this).balance >= 0;
    }

    function echidna_no_unauthorized_mint() public view returns (bool) {
        return totalSupply() <= MAX_SUPPLY;
    }
}
```

### Running

```bash
# Basic run
echidna . --contract EchidnaTest

# With config file
echidna . --contract EchidnaTest --config echidna-config.yaml

# Assertion mode (checks for assert failures)
echidna . --contract EchidnaTest --test-mode assertion
```

### Config Example

```yaml
testLimit: 50000
seqLen: 100
deployer: "0x10000"
sender: ["0x20000", "0x30000"]
corpusDir: "echidna-corpus"
```

### When to Use

- Complex multi-step attack sequences
- Protocol invariants that span multiple functions
- Finding edge cases in mathematical operations
- Testing across many random inputs and call sequences

---

## 5. Medusa (Parallel Fuzzing)

**What it does**: Similar to Echidna but runs in parallel using go-ethereum.
Significantly faster for large codebases.

### Usage

```bash
# Initialize config
medusa init

# Run fuzzing
medusa fuzz

# With specific config
medusa fuzz --config medusa.json
```

### Key Advantage

Parallel execution across multiple workers/threads. Better for CI
environments and large-scale fuzzing campaigns.

---

## 6. Halmos (Symbolic Testing)

**What it does**: Formal verification using symbolic execution.
Proves properties hold for ALL possible inputs, not just random ones.

### Usage

```bash
# Run symbolic tests (functions starting with check_)
halmos --contract MyTest

# With specific solver timeout
halmos --contract MyTest --solver-timeout-assertion 600
```

### Writing Symbolic Tests

```solidity
function check_withdrawNeverExceedsBalance(uint256 amount) public {
    // Symbolic setup
    vm.assume(amount <= maxDeposit);
    deposit(amount);

    // This must hold for ALL valid amounts
    assert(balanceOf(address(this)) >= 0);
}
```

### When to Use

- Mathematical properties that must hold universally
- Token accounting invariants
- Access control completeness proofs
- When fuzzing hasn't found issues but confidence is needed

---

## 7. Certora Prover (Formal Verification)

**What it does**: Uses CVL (Certora Verification Language) to write
specifications and mathematically prove contract correctness.

### Writing Specifications (CVL)

```cvl
rule withdrawDoesNotExceedBalance(address user, uint256 amount) {
    uint256 balBefore = balanceOf(user);

    env e;
    require e.msg.sender == user;
    withdraw(e, amount);

    uint256 balAfter = balanceOf(user);
    assert balAfter <= balBefore;
}

invariant totalSupplyIsSumOfBalances()
    totalSupply() == sum(balanceOf(a) for all address a)
```

### When to Use

- High-value DeFi protocols (Aave, Compound use Certora)
- Critical mathematical invariants
- When the cost of a bug exceeds the cost of formal verification
- Regulatory or compliance requirements

---

## Recommended Audit Tool Pipeline

### Quick Scan (30 minutes)
1. `slither .` — Get immediate vulnerability flags
2. `aderyn .` — Complementary static analysis
3. `forge test --gas-report` — Run existing tests, check coverage

### Standard Audit (1-2 days)
1. Quick Scan pipeline above
2. Write targeted fuzz tests for critical functions in Foundry
3. Write Echidna properties for protocol invariants
4. Fork mainnet tests for integration scenarios
5. Manual review guided by tool findings

### Deep Audit (1+ weeks)
1. Standard Audit pipeline above
2. Formal verification with Halmos or Certora for critical paths
3. Economic modeling and game-theoretic analysis
4. Cross-contract interaction testing
5. Medusa parallel fuzzing campaigns (50K+ iterations)
6. Custom Slither detectors for protocol-specific patterns

---

## Tool Installation

```bash
# Slither
pip install slither-analyzer

# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Echidna (binary release or Docker)
docker pull ghcr.io/trailofbits/eth-security-toolbox:nightly

# Aderyn
cargo install aderyn

# Halmos
pip install halmos

# Medusa
# Download from https://github.com/crytic/medusa/releases
```

### All-in-One Docker Environment

Trail of Bits provides a preconfigured Docker image with Slither, Echidna,
Medusa, Foundry, and solc-select:

```bash
docker pull ghcr.io/trailofbits/eth-security-toolbox:nightly
docker run -it -v "$(pwd)":/src ghcr.io/trailofbits/eth-security-toolbox:nightly
```

---

## 8. Gas Benchmarking

### Measuring Gas Usage

```solidity
// test/Gas.t.sol
contract GasTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    function test_GasDeposit() public {
        uint256 gasBefore = gasleft();
        vault.deposit{value: 1 ether}();
        uint256 gasUsed = gasBefore - gasleft();
        console2.log("Deposit gas:", gasUsed);
    }

    function test_GasWithdraw() public {
        vault.deposit{value: 1 ether}();

        uint256 gasBefore = gasleft();
        vault.withdraw(1 ether);
        uint256 gasUsed = gasBefore - gasleft();
        console2.log("Withdraw gas:", gasUsed);
    }
}
```

### Gas Snapshots

```bash
# Generate gas snapshot
forge snapshot

# Compare with baseline
forge snapshot --check

# Diff two snapshots
forge snapshot --diff .gas-snapshot

# Run specific gas tests
forge test --match-test test_Gas -vvv --gas-report
```

### Gas Optimization Report Template

```markdown
# Gas Optimization Report

## Summary

| Function | Before | After | Savings |
|----------|--------|-------|---------|
| deposit() | 50,000 | 35,000 | 30% |
| withdraw() | 45,000 | 30,000 | 33% |
| transfer() | 25,000 | 18,000 | 28% |

## Optimizations Applied

### 1. Storage Packing
- Reduced slots from 5 to 3
- Estimated savings: 40,000 gas per tx

### 2. Unchecked Math
- Applied to loop counters and safe operations
- Estimated savings: 500 gas per iteration

### 3. Calldata vs Memory
- Changed function parameters to calldata
- Estimated savings: 200 gas per call

## Deployment Cost

| Contract | Before | After | Savings |
|----------|--------|-------|---------|
| Vault | 500,000 | 400,000 | 20% |
```

---

## 9. Custom Slither Detectors

Create protocol-specific detectors for patterns Slither doesn't catch by default.

### Detector Structure

```python
# detectors/my_detector.py
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function

class MyCustomDetector(AbstractDetector):
    ARGUMENT = "my-detector"  # slither . --detect my-detector
    HELP = "Description of what this detects"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://..."
    WIKI_TITLE = "My Custom Detector"
    WIKI_DESCRIPTION = "Detailed description"
    WIKI_RECOMMENDATION = "How to fix"

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_vulnerable(function):
                    info = [
                        function,
                        " has vulnerability X\n"
                    ]
                    results.append(self.generate_result(info))

        return results

    def _is_vulnerable(self, function: Function) -> bool:
        # Detection logic here
        return False
```

### Example: Detect Missing Slippage Protection

```python
class MissingSlippageProtection(AbstractDetector):
    ARGUMENT = "missing-slippage"
    HELP = "Swap functions without minAmountOut parameter"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []

        swap_keywords = ["swap", "exchange", "trade"]

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                name_lower = function.name.lower()

                # Check if it's a swap function
                if any(kw in name_lower for kw in swap_keywords):
                    # Check for slippage parameter
                    param_names = [p.name.lower() for p in function.parameters]
                    has_slippage = any(
                        "min" in p or "slippage" in p or "deadline" in p
                        for p in param_names
                    )

                    if not has_slippage:
                        info = [
                            function,
                            " lacks slippage protection\n"
                        ]
                        results.append(self.generate_result(info))

        return results
```

### Example: Detect Spot Price Usage

```python
class SpotPriceUsage(AbstractDetector):
    ARGUMENT = "spot-price"
    HELP = "Detects usage of getReserves for pricing"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                for node in function.nodes:
                    for ir in node.irs:
                        # Check for getReserves call
                        if hasattr(ir, 'function') and ir.function:
                            if ir.function.name == "getReserves":
                                info = [
                                    function,
                                    " uses getReserves() - potential price manipulation\n"
                                ]
                                results.append(self.generate_result(info))

        return results
```

### Running Custom Detectors

```bash
# Install detector
pip install -e ./my-detectors/

# Run with custom detector
slither . --detect my-detector,spot-price,missing-slippage

# Run all detectors including custom
slither . --detect all
```

### Useful Detector Patterns

| Pattern | What to Detect |
|---------|---------------|
| External calls in loops | DoS via gas |
| State read after external call | Read-only reentrancy |
| Missing events on state change | Poor monitoring |
| Hardcoded addresses | Deployment issues |
| Block.timestamp in comparisons | Timing manipulation |
| tx.origin usage | Phishing vulnerability |
| delegatecall to variable | Code injection |
| Unchecked array access | Out of bounds |
