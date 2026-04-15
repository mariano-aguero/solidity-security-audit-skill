# Spec: Add Severity Decision Trees for New Vulnerability Categories

**traceability_id:** `2026-04-15-ssas-severity-trees-new-categories`  
**type:** improvement  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-06  
**project:** solidity-security-audit-skill  
**source:** `references/severity-decision-tree.md`  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

`references/severity-decision-tree.md` provides structured decision trees for classifying vulnerability severity. Current trees cover classic categories: reentrancy, oracle manipulation, access control, integer issues. Vulnerability categories added in v3.4–v3.10 (EOF opcodes, ERC-7702 delegation, transient storage compiler bugs, ZK-VM proof failures) have no corresponding decision trees, leaving auditors without structured guidance for severity classification in these areas.

## Problem

Auditors encountering an ERC-7702 sweeper delegation attack or a transient storage guard bypass must improvise severity classification without a structured framework. This leads to inconsistent severity ratings across audit teams and contest submissions, particularly when submitting to Sherlock or Code4rena where severity affects payout.

## Objectives

- Add 4 new decision trees to `severity-decision-tree.md`:
  1. EOF opcode-removal vulnerabilities
  2. ERC-7702 delegation/sweeper attacks  
  3. Transient storage compiler bugs  
  4. ZK-VM proof input validation failures

## Non-Objectives

- Does not reorganize the existing decision tree structure.
- Does not create a standalone severity tool; all trees go in the existing file.

## Proposed Design

Each new tree follows the existing format in `severity-decision-tree.md`:

```
### [Category] Severity Decision Tree

START → Is funds at direct risk?
├── YES → Is exploitation unconditional (no special role/state)?
│   ├── YES → **CRITICAL**
│   └── NO  → Is loss > 1% TVL or permanent?
│       ├── YES → **HIGH**
│       └── NO  → **MEDIUM**
└── NO  → Does it enable privilege escalation?
    ├── YES → **MEDIUM**
    └── NO  → **LOW / INFORMATIONAL**
```

**ERC-7702 tree** key branch: "Is the victim's EOA already set to the malicious delegation?" — distinguishes pre-activation (Low) from post-activation with pending tx (Critical).

**Transient storage tree** key branch: "Does the compiler version use the buggy TSTORE clear?" — distinguishes theoretical (Medium) from proven exploitable version (High/Critical).

**ZK-VM tree** key branch: "Is the under-constrained input reachable by an untrusted prover?" — distinguishes internal test environment (Low) from production verifier (Critical).

## Implementation Plan

1. Open `references/severity-decision-tree.md`.
2. Add 4 new decision tree sections at the end of the file (before any appendix).
3. Add INDEX.md entry referencing each new tree's section anchor.
4. Cross-reference from `vulnerability-taxonomy.md §17` (ERC-7702), `§21` (transient storage), `§24` (ZK-VM) to the new trees.

## Risks

- Low-medium. Content quality risk: decision trees must be technically accurate. Peer review recommended before commit.

## Testing / Acceptance Criteria

- `severity-decision-tree.md` contains 4 new decision tree sections.
- Each tree has at least 3 decision branches.
- Each branch leads to a severity label (Critical/High/Medium/Low/Info).
- INDEX.md has entries pointing to each new tree section.
- Cross-references exist from relevant vulnerability taxonomy sections.

## Rollback

Revert the additions to `severity-decision-tree.md` and INDEX.md.
