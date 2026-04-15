# Spec: Expand poc-templates.md with ERC-7702 and Fusaka EOF Templates

**traceability_id:** `2026-04-15-ssas-poc-templates-erc7702-eof`  
**type:** improvement  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-06  
**project:** solidity-security-audit-skill  
**source:** `references/poc-templates.md`, `references/vulnerability-taxonomy.md §17.6, §22`  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

`references/poc-templates.md` provides Foundry PoC templates for common exploit scenarios (V4 hook drain, transient storage bypass, flash loan attacks). The vulnerability taxonomy has sections for ERC-7702 sweeper attacks (§17.6) and EOF opcode removal issues (§22), but no corresponding PoC templates exist.

## Problem

Auditors who identify ERC-7702 sweeper vulnerabilities or EOF compatibility issues need to write Foundry PoC tests to prove exploitability for audit reports. Without templates, they start from scratch. Contest submissions that include a working PoC are rated more favorably on Sherlock and Immunefi.

## Objectives

- Add 3 new Foundry PoC templates to `poc-templates.md`:
  1. ERC-7702 sweeper campaign simulation
  2. EOF `EXTDELEGATECALL` blocking legacy contract scenario
  3. GAS opcode removal breaking gas-dependent reentrancy guard

## Non-Objectives

- Does not add templates for categories already covered in `poc-templates.md`.
- Does not include non-Foundry test frameworks.

## Proposed Design

Each template follows the existing format in `poc-templates.md`:
- Setup section (contracts, test state)
- Attack function with annotations
- Expected output / assertion

### Template 1: ERC-7702 Sweeper Campaign

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

// Simulates: victim signs EIP-7702 authorization → attacker delegates victim EOA to
// MaliciousSweeper → drains victim's token balance in same tx

contract MaliciousSweeper {
    function sweep(address token, address to) external {
        IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
    }
}

contract ERC7702SweeperTest is Test {
    function test_sweeper_campaign() public {
        address victim = makeAddr("victim");
        uint256 victimKey = uint256(keccak256("victimKey")); // test private key
        
        // Victim signs EIP-7702 authorization for MaliciousSweeper
        // [authorization encoding per EIP-7702 spec]
        // ...
        
        // Attacker submits tx with authorization + sweep call
        // Assert: victim.balance == 0 after tx
    }
}
```

### Template 2: EOF EXTDELEGATECALL Legacy Block

```solidity
// Tests: EOF contract attempts EXTDELEGATECALL to legacy bytecode → reverts
contract EOFLegacyCallTest is Test {
    function test_extdelegatecall_blocks_legacy() public {
        // Deploy legacy contract (non-EOF bytecode)
        // Deploy EOF caller
        // Assert: EXTDELEGATECALL reverts with specific error
    }
}
```

### Template 3: GAS Opcode Removal Breaking Reentrancy Guard

```solidity
// Tests: contract using gasleft()-based guard fails in EOF context
// (GAS opcode removed in EOF — gasleft() always returns 0 or reverts)
contract GasOpcodeRemovalTest is Test {
    function test_gas_opcode_reentrancy_bypass() public {
        // Deploy GasBasedGuard contract in EOF simulation
        // Show gasleft() returns unexpected value
        // Demonstrate reentrancy is possible
    }
}
```

## Implementation Plan

1. Open `references/poc-templates.md`.
2. Add a new "ERC-7702 & EOF PoC Templates" section at the end.
3. Add all 3 templates with full Foundry boilerplate and annotated attack steps.
4. Update INDEX.md with an anchor entry for the new section.
5. Cross-reference from `vulnerability-taxonomy.md §17.6` and `§22`.

## Risks

- Medium. Template code must compile and run against Foundry. All templates should be tested locally before committing.
- ERC-7702 PoC depends on Foundry's EIP-7702 support (available in `forge` >= 0.2.0 with `--evm-version prague`).

## Testing / Acceptance Criteria

- `poc-templates.md` contains 3 new PoC templates under a new section.
- Each template compiles without errors (`forge build` passes).
- Each template has inline comments explaining the attack steps.
- INDEX.md has an anchor entry for the new section.

## Rollback

Remove the new PoC template section from `poc-templates.md` and revert INDEX.md.
