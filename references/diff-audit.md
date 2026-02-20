# Diff Audit & Re-Audit Methodology

Re-audits and change audits are structurally different from full audits. The goal is to
efficiently verify that: (1) previously reported findings were correctly remediated,
(2) no new vulnerabilities were introduced, and (3) the changes are consistent with the
intended fix.

---

## Modes of Diff Analysis

### 1. Remediation Verification
The most common re-audit type. A previous audit report exists; the team has applied fixes.
Focus: confirm each finding is properly addressed without regression.

### 2. Feature Addition Review
New functionality added to an existing audited codebase.
Focus: the new code surface + its interactions with existing audited code.

### 3. Dependency / Integration Update
An external library, oracle, or protocol dependency changed version.
Focus: interface changes, behavior changes in the dependency, compatibility breaks.

### 4. Upgrade Review (Proxy)
A new implementation contract is deployed behind an existing proxy.
Focus: storage layout compatibility, initialization safety, selector conflicts.

---

## Phase 0: Diff Setup

```bash
# Get all changed files between two commits/tags
git diff v1.0.0 v1.1.0 --name-only

# Show full diff of Solidity files only
git diff v1.0.0 v1.1.0 -- '*.sol'

# Diff between two branches
git diff main..feat/new-feature -- '*.sol'

# Generate diff stat (summary of changes per file)
git diff v1.0.0 v1.1.0 --stat -- '*.sol'

# Show only added/removed lines (no context)
git diff v1.0.0 v1.1.0 -U0 -- '*.sol'

# Check if storage layout changed (with forge)
forge inspect ContractName storage-layout > layout_before.txt
# After checkout to new version:
forge inspect ContractName storage-layout > layout_after.txt
diff layout_before.txt layout_after.txt
```

---

## Phase 1: Change Classification

Before reviewing code, classify every changed file:

| Change Type | Risk Level | Focus |
|-------------|-----------|-------|
| New contract | HIGH | Full audit of new surface |
| Modified core logic | HIGH | CEI, access control, invariants |
| Modified access control | CRITICAL | Permission escalation, bypass |
| New storage variables | HIGH | Layout collision, initialization |
| Removed safety checks | CRITICAL | Why removed? Was it intentional? |
| Interface change | HIGH | All callers updated correctly? |
| Bug fix (targeted) | MEDIUM | Fix correct? No regression? |
| Gas optimization | LOW | No semantic change introduced |
| Comments/events only | LOW | Verify truly no logic change |
| Dependency version bump | MEDIUM | Breaking changes in dep? |

---

## Phase 2: High-Risk Diff Patterns

These patterns in a diff are immediate red flags requiring deep review:

### Removed Safety Checks
```diff
- require(amount <= maxWithdraw, "exceeds max");
  token.transfer(msg.sender, amount);
```
**Action**: Verify the check was moved elsewhere or is genuinely unnecessary.

### CEI Order Change
```diff
- balances[msg.sender] -= amount;
- token.transfer(msg.sender, amount);
+ token.transfer(msg.sender, amount);
+ balances[msg.sender] -= amount;
```
**Action**: Instant reentrancy risk — escalate to Critical.

### Access Control Relaxation
```diff
- function setPrice(uint256 price) external onlyOwner {
+ function setPrice(uint256 price) external {
```
**Action**: Was this intentional? Who can now call this?

### New Storage Variable (Upgradeable Contract)
```diff
+ uint256 public newFee;          // slot X
  mapping(address => uint) balances; // previously at slot X → now at slot X+1
```
**Action**: Run storage layout diff — this is a storage collision risk.

### Initializer Change
```diff
- function initialize(address owner) external initializer {
+ function initialize(address owner, address feeRecipient) external initializer {
```
**Action**: Check if existing deployed proxies can be re-initialized.

### Reentrancy Guard Removal
```diff
- function withdraw() external nonReentrant {
+ function withdraw() external {
```
**Action**: Verify CEI pattern was applied as a replacement — or escalate.

### Oracle Source Change
```diff
- price = chainlinkFeed.latestAnswer();
+ price = (reserve0 * 1e18) / reserve1;
```
**Action**: Was a safe oracle replaced with a manipulable spot price?

### Timelock Bypass
```diff
- require(block.timestamp >= proposal.eta, "not ready");
  _execute(proposal);
```
**Action**: Governance timing assumptions broken.

### Unchecked Added to Previously Checked Math
```diff
- totalSupply += amount;
+ unchecked { totalSupply += amount; }
```
**Action**: Was overflow analysis done? Is the invariant still safe?

---

## Phase 3: Remediation Verification Checklist

For each finding in the original report:

```
[ ] Finding ID: ___________
[ ] Original severity: ___________
[ ] Status claimed by team: Fixed / Acknowledged / Won't Fix

IF Fixed:
  [ ] The vulnerable code is gone or modified
  [ ] The fix addresses the ROOT CAUSE (not just the symptom)
  [ ] The fix does not introduce new vulnerabilities
  [ ] Tests were added covering the fix
  [ ] The fix is consistent with the recommendation in the report (or a valid alternative)

IF Acknowledged:
  [ ] The risk is documented
  [ ] Mitigating controls exist
  [ ] Impact is acceptable

IF Won't Fix:
  [ ] Reason is technically sound
  [ ] Risk is actually low in context
```

### Common Incomplete Fixes

| Original Issue | Incomplete Fix | Correct Fix |
|----------------|---------------|-------------|
| Reentrancy via external call | Add `nonReentrant` but keep wrong order | CEI pattern + guard |
| Oracle spot price | Add TWAP check only on one path | TWAP on all price-consuming paths |
| Unprotected initializer | Add `initializer` modifier | `_disableInitializers()` in constructor too |
| Missing slippage | Add `minOut` param but not validated | Validate `amountOut >= minOut` with revert |
| Integer overflow | Add `unchecked` removal | Use SafeMath or verify bounds analytically |
| Access control missing | Add `onlyOwner` | Consider if role is too broad — use RBAC |

---

## Phase 4: New Code Surface Review

Any code not present in the original audit scope must receive a **full review**, not just a diff review. Apply the standard 5-phase workflow from SKILL.md to the new files.

Special attention for new code that interacts with previously audited code:

```
[ ] Does new code call into audited contracts with correct assumptions?
[ ] Does new code introduce new entry points that bypass audited logic?
[ ] Does new code share state (storage) with audited contracts?
[ ] Does new code change the trust model assumed in the original audit?
[ ] Does new code introduce new privileged roles?
```

---

## Phase 5: Regression Testing

```bash
# Run all existing tests — verify nothing broke
forge test -vv

# Run fuzz tests with high iteration count
forge test --match-test "testFuzz" --fuzz-runs 50000

# Run invariant tests
forge test --match-test "invariant_"

# Fork test against mainnet state
forge test --fork-url $ETH_RPC_URL --fork-block-number $BLOCK

# Check coverage delta (new code should have coverage)
forge coverage --report summary
```

---

## Phase 6: Storage Layout Verification (Upgradeable Contracts)

Critical for any upgrade diff. Storage collision silently corrupts state.

```bash
# Generate layout for both versions
forge inspect OldImplementation storage-layout --json > old_layout.json
forge inspect NewImplementation storage-layout --json > new_layout.json

# Manual comparison checklist:
[ ] All existing slots have the same variable at the same slot number
[ ] New variables are added AFTER all existing slots (append-only)
[ ] No existing variable types changed (uint256 → int256 is a bug)
[ ] No existing variable names reused for different types
[ ] Gap arrays were reduced correctly (if used)
[ ] ERC-7201 namespace hash is unchanged (if used)
```

### Safe vs Unsafe Layout Changes

```solidity
// SAFE: new variable appended at end
// Before:  slot 0: owner, slot 1: balance
// After:   slot 0: owner, slot 1: balance, slot 2: newFee  ✓

// UNSAFE: new variable inserted in middle
// Before:  slot 0: owner, slot 1: balance
// After:   slot 0: owner, slot 1: newFee, slot 2: balance  ✗

// UNSAFE: gap array incorrectly reduced
// Before:  uint256[50] __gap;  // reserves slots 10-59
// After:   uint256[49] __gap;  // added variable but gap not reduced → collision  ✗
// Correct: uint256[49] __gap;  // with new variable added BEFORE gap in same slot range ✓
```

---

## Diff Audit Report Template

```markdown
# Re-Audit Report: [Protocol Name]

**Original Audit**: [Link or date]
**Re-Audit Scope**: Commits [abc1234] → [def5678]
**Changed Files**: [N] files, [+X / -Y] lines
**Date**: [Date]

---

## Remediation Status Summary

| ID | Title | Severity | Status | Verified |
|----|-------|----------|--------|---------|
| H-01 | Reentrancy in withdraw | High | Fixed | ✓ |
| M-01 | Missing slippage | Medium | Fixed | ✓ |
| L-01 | Floating pragma | Low | Acknowledged | - |

---

## New Findings

### [NEW-H-01] Title
**Severity**: High
**Introduced in**: [commit hash] — [file:line]

**Description**:
[What changed and why it's vulnerable]

**Impact**:
[Concrete damage scenario]

**Recommendation**:
[Specific fix]

---

## Notes on Remediation Quality

[Any findings where the fix is technically correct but could be improved]

---

## Scope of New Code Reviewed

[Files added since last audit, whether fully reviewed or not]
```

---

## Automated Diff Scanning

```bash
# Slither on changed files only
git diff v1.0.0 HEAD --name-only -- '*.sol' | \
  xargs slither --json diff-report.json 2>/dev/null

# Compare Slither output between versions
slither . --json before.json  # on old version
git stash
slither . --json after.json   # on new version
# diff before.json after.json | grep '"impact"'

# Aderyn on full project (generates markdown report)
aderyn . --output diff-aderyn.md
```

---

## Cross-References

- `vulnerability-taxonomy.md` — Full list of vulnerability patterns to check in changed code
- `secure-patterns.md` — Reference implementations to compare fixes against
- `poc-templates.md` — PoC templates for proving regressions
- `report-template.md` — Full report format (use diff template above for re-audits)
- `tool-integration.md` — Tool commands and configuration
