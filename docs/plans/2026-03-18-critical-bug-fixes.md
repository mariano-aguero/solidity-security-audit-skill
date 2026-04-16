# Critical Bug Fixes — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 5 structural bugs in the skill that cause incorrect AI behavior: incomplete taxonomy ToC, duplicate SKILL.md triggers, inconsistent severity labels, undefined Quick Scan output, and missing ERC-7702 check in universal DeFi checklist.

**Architecture:** Documentation-only project. All changes are Markdown edits. No tests or build required. Each task is one file, one focused change, one commit.

**Tech Stack:** Markdown, YAML frontmatter (SKILL.md `description:` block), Foundry references (poc-templates).

---

### Task 1: Fix `vulnerability-taxonomy.md` ToC — add §21 and §22

**Files:**
- Modify: `references/vulnerability-taxonomy.md` lines 10–32

**Step 1: Make the edit**

Find the existing ToC block ending at line 31 (`20. [Supply Chain...]`).
Add two lines immediately after it:

```markdown
21. [ERC-6909 Multi-Token Standard Vulnerabilities](#21-erc-6909-multi-token-standard-vulnerabilities)
22. [EVM Object Format (EOF) Vulnerabilities](#22-evm-object-format-eof-vulnerabilities)
```

The exact anchor text must match the actual section headers at lines 2495 and 2744:
- `## 21. ERC-6909 Multi-Token Standard Vulnerabilities`
- `## 22. EVM Object Format (EOF) Vulnerabilities`

Markdown anchor for `## 21. ERC-6909 Multi-Token Standard Vulnerabilities`:
→ `#21-erc-6909-multi-token-standard-vulnerabilities`

Markdown anchor for `## 22. EVM Object Format (EOF) Vulnerabilities`:
→ `#22-evm-object-format-eof-vulnerabilities`

**Step 2: Verify visually**

Check the ToC now lists 22 entries (1–22) with no gaps.

**Step 3: Commit**

```bash
git add references/vulnerability-taxonomy.md
git commit -m "fix(taxonomy): add missing §21 ERC-6909 and §22 EOF to Table of Contents"
```

---

### Task 2: Deduplicate triggers in `SKILL.md`

**Files:**
- Modify: `SKILL.md` lines 69–74

**Step 1: Identify exact duplicates**

Lines 69–74 contain keywords already present on lines 31–68:

| Duplicate | First occurrence | Duplicate location |
|-----------|-----------------|-------------------|
| `"ePBS"` | line 69 | line 72 |
| `"EIP-7732"` | line 69 | line 72 |
| `"EIP-7928"` | line 69 | line 73 |
| `"block access lists"` (case variant of `"Block Access Lists"`) | line 69 | line 73 |
| `"AI-generated code"` | line 33 | semantic duplicate of `"AI-generated code audit"` line 70 |

**Step 2: Make the edit**

Replace the entire block at lines 69–74:

```yaml
  "ePBS", "EIP-7732", "block access lists", "EIP-7928", "Glamsterdam",
  "AI-generated code audit", "vibe coding security", "LLM contract review", "copilot Solidity",
  "hallucinated interface", "broken reentrancy guard AI", "incomplete access control AI",
  "EIP-7732", "enshrined PBS", "ePBS", "proposer builder separation consensus",
  "Block Access Lists", "BALs EIP-7928", "EIP-7928", "payload withholding attack",
  "preconfirmation timing", "preconf security",
```

With deduplicated version:

```yaml
  "ePBS", "EIP-7732", "enshrined PBS", "proposer builder separation consensus",
  "block access lists", "Block Access Lists", "BALs EIP-7928", "EIP-7928", "Glamsterdam",
  "payload withholding attack", "preconfirmation timing", "preconf security",
  "AI-generated code audit", "vibe coding security", "LLM contract review", "copilot Solidity",
  "hallucinated interface", "broken reentrancy guard AI", "incomplete access control AI",
```

This preserves all unique triggers, removes exact duplicates (`"EIP-7732"`, `"ePBS"`, `"EIP-7928"`), and groups Glamsterdam-related terms together.

**Step 3: Count check**

Before: 6 lines, several duplicates.
After: 5 lines, zero duplicates. All unique terms preserved.

**Step 4: Commit**

```bash
git add SKILL.md
git commit -m "fix(skill): remove duplicate triggers for EIP-7732, ePBS, EIP-7928, BALs"
```

---

### Task 3: Normalize severity label `Info` → `Informational` in `quick-reference.md`

**Files:**
- Modify: `references/quick-reference.md` lines 120 and 231

**Background:** All other files (`SKILL.md`, `report-template.md`, `severity-decision-tree.md`) use `Informational`. `quick-reference.md` uses the shortened `Info` in two places — the severity table and the audit output template. This inconsistency causes AI to generate reports with mismatched labels.

**Step 1: Fix the severity table (line 120)**

Change:
```markdown
| **Info** | Code quality | Naming, unused variables, gas |
```
To:
```markdown
| **Informational** | Code quality | Naming, unused variables, gas |
```

**Step 2: Fix the audit output template (line 231)**

Change:
```markdown
**Severity**: Critical/High/Medium/Low/Info
```
To:
```markdown
**Severity**: Critical/High/Medium/Low/Informational
```

**Step 3: Verify**

Run a quick grep to confirm no remaining `Info` label (excluding inline text):

```bash
grep -n "| \*\*Info\*\*\|/Info$" references/quick-reference.md
```

Expected: no matches.

**Step 4: Commit**

```bash
git add references/quick-reference.md
git commit -m "fix(quick-ref): normalize severity label Info → Informational for consistency"
```

---

### Task 4: Define Quick Scan output in `SKILL.md`

**Files:**
- Modify: `SKILL.md` line 106 (the Quick Scan row in the Mode Selection table)

**Background:** Quick Scan mode says what phases to run but doesn't define what output to produce. Full Audit produces a Phase 5 report. Quick Scan has no equivalent → AI generates inconsistent output.

**Step 1: Make the edit**

Current Quick Scan row:
```markdown
| **Quick Scan** | Rapid assessment, limited time | `references/quick-reference.md` — abbreviated Phase 0 (5 min max), run Phases 1–2 only, focus Phase 3 on Critical/High patterns from `quick-reference.md` |
```

Replace with:
```markdown
| **Quick Scan** | Rapid assessment, limited time | `references/quick-reference.md` — abbreviated Phase 0 (5 min max), run Phases 1–2 only, focus Phase 3 on Critical/High patterns from `quick-reference.md`. **Output:** bullet list of Critical/High findings only, each with: title, severity, location, one-line description, and remediation pointer. No full report structure required. |
```

**Step 2: Verify**

Check the Mode Selection table still has 4 rows and renders correctly as Markdown.

**Step 3: Commit**

```bash
git add SKILL.md
git commit -m "fix(skill): define Quick Scan output format — bullet list of Critical/High findings"
```

---

### Task 5: Add ERC-7702 / tx.origin check to Universal DeFi Checks in `defi-checklist.md`

**Files:**
- Modify: `references/defi-checklist.md` — the `### Access Control` subsection of `## Universal DeFi Checks` (lines 42–47)

**Background:** ERC-7702 (live post-Pectra) allows EOAs to delegate execution. Any contract that uses `tx.origin == msg.sender` or `tx.origin` as an auth guard is bypassed post-Pectra. This is not a AA-only issue — it affects any DeFi contract. The $2.5M+ sweeper campaign (May 2025) confirmed widespread impact. This belongs in Universal, not just in the account-abstraction reference.

**Step 1: Make the edit**

After the existing 5 `### Access Control` bullets, append:

```markdown
- [ ] Does any function use `tx.origin == msg.sender` or `tx.origin` as an auth guard? Post-Pectra (ERC-7702), EOAs can delegate execution — this check no longer reliably identifies EOA callers (see `vulnerability-taxonomy.md §17.6`)
- [ ] Does the protocol assume `msg.sender` cannot be a smart contract with EOA privileges? ERC-7702 delegated EOAs break this assumption.
```

**Step 2: Verify placement**

Confirm the new checks are inside `### Access Control` under `## Universal DeFi Checks` (before the `---` separator that precedes `## Lending Protocols`).

**Step 3: Commit**

```bash
git add references/defi-checklist.md
git commit -m "fix(checklist): add ERC-7702 tx.origin auth bypass to Universal DeFi Access Control checks"
```

---

## Completion Checklist

After all 5 tasks:

- [ ] `vulnerability-taxonomy.md` ToC has 22 entries (1–22)
- [ ] `SKILL.md` triggers block has zero duplicate terms
- [ ] `quick-reference.md` uses `Informational` in both severity table and output template
- [ ] Quick Scan mode in `SKILL.md` defines an output format
- [ ] `defi-checklist.md` Universal Access Control has ERC-7702 checks
- [ ] 5 clean commits in git log
