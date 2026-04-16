# Spec: Upgrade tool-integration.md with Aderyn v0.6 LSP and Halmos Recon

**traceability_id:** `2026-04-15-ssas-tool-integration-aderyn-halmos`  
**type:** improvement  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-06  
**project:** solidity-security-audit-skill  
**source:** `references/tool-integration.md`, `SKILL.md` (trigger keywords)  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

`SKILL.md` trigger keywords include `"Aderyn v0.6"`, `"Aderyn LSP server"`, `"halmos recon reproducer"`, and `"echidna verification mode"` — but `references/tool-integration.md` has no documentation for these capabilities. Users who trigger the skill with these keywords will get no actionable guidance.

## Problem

The tool-integration.md file is 1,806 lines and covers Slither, Foundry, Echidna, and Certora in detail, but it was last comprehensively updated before Aderyn v0.6 LSP server support shipped, and before Halmos added `--recon` mode. Auditors relying on these newer tool features for IDE-integrated security scanning get no guidance from the skill.

## Objectives

- Add Aderyn v0.6 LSP server setup instructions to `tool-integration.md`.
- Add Halmos `--recon` mode documentation with example output interpretation.
- Add Echidna verification mode (property confirmation post-fuzzing) with example workflow.

## Non-Objectives

- Does not replace or restructure existing Aderyn/Halmos/Echidna sections.
- Does not add tool integration for new tools not already mentioned in the skill.

## Proposed Design

### New Section: Aderyn v0.6 LSP Server

```markdown
### Aderyn v0.6 — LSP Server Integration

Aderyn v0.6 ships with a Language Server Protocol (LSP) server for IDE-native security diagnostics.

**Setup:**
```bash
cargo install aderyn --version 0.6
# or: npm install -g @cyfrin/aderyn@0.6

# Start LSP server (VS Code: add to .vscode/settings.json)
aderyn lsp
```

**VS Code settings.json:**
```json
{
  "aderyn.serverPath": "/path/to/aderyn",
  "aderyn.configFile": "aderyn.toml"
}
```

**What it catches inline:**
- Centralization risks (highlighted in real time)
- Unsafe ERC-20 patterns
- Missing access control on state-changing functions
- Unindexed event parameters

**Triage workflow:** Same SARIF-based approach as Slither. Suppress FPs with `// aderyn-disable-next-line DetectorName`.
```

### New Section: Halmos `--recon` Mode

```markdown
### Halmos Recon Mode

`halmos --recon` runs symbolic execution in reconnaissance mode — instead of proving properties,
it explores reachable states and surfaces potential counterexamples for auditor review.

**Command:**
```bash
halmos --recon --contract MyContract --function testSymbolicTransfer
```

**Output interpretation:**
- `REACHABLE` — The state was reached; review for exploit potential
- `UNREACHABLE` — The path is infeasible; likely false-positive mitigation
- `TIMEOUT` — Path too complex; narrow with `--loop` or `--array-lengths` limits
```

### New Section: Echidna Verification Mode

```markdown
### Echidna Verification Mode

After fuzzing confirms all properties pass, run Echidna in verification mode to produce
a proof certificate that the properties hold under bounded exploration.

```bash
echidna MyContract.sol --config echidna.yaml --mode assertion --verify
```

This produces a `verification_report.json` suitable for audit report appendices.
```

## Implementation Plan

1. Open `references/tool-integration.md`.
2. Locate the existing Aderyn section and append the LSP subsection.
3. Locate the existing Halmos section and append the `--recon` subsection.
4. Locate the existing Echidna section and append the verification mode subsection.
5. Update INDEX.md to add new subsection anchors.

## Risks

- Medium. Commands and output formats must be verified against the actual tool versions.
- Aderyn LSP API may have changed since this was written; validate against Aderyn v0.6 release notes.

## Testing / Acceptance Criteria

- `tool-integration.md` contains an Aderyn v0.6 LSP setup section with VS Code config example.
- Halmos `--recon` section includes example command and output interpretation table.
- Echidna verification mode section includes the `--verify` flag and output artifact name.
- INDEX.md has entries for each new subsection.

## Rollback

Revert additions to `tool-integration.md` and INDEX.md.
