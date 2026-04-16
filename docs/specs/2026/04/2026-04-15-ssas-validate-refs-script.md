# Spec: Add Automated Cross-Reference Validation Script

**traceability_id:** `2026-04-15-ssas-validate-refs-script`  
**type:** feature  
**criticality:** medium  
**created_at:** 2026-04-15T00:00:00-03:00  
**target_date:** 2026-05-13  
**project:** solidity-security-audit-skill  
**source:** `references/INDEX.md`, `SKILL.md`  
**status:** open  
**issue:** <!-- to be filled after GitHub issue creation -->

---

## Context

The skill has 24 reference files with cross-references in `file:§section` format and `See X.md §Y` inline references. As the skill grows, these references can become stale (deleted sections, renamed headings). There is currently no tooling to detect broken cross-references, and no CI validation.

## Problem

A broken cross-reference in INDEX.md (e.g., pointing to a section that was renamed or removed) causes agents to navigate to the wrong content or get a 404-equivalent. In a documentation-only project where navigability is the core value, broken references directly degrade the product.

## Objectives

- Create `docs/scripts/validate-refs.sh` (bash) that:
  1. Checks every `file:§section` reference in INDEX.md resolves to an existing heading in the target file.
  2. Reports broken inline `See X.md §Y` references across all reference files.
  3. Lists reference file sections that are not indexed in INDEX.md (coverage gaps).
  4. Exits with code 1 if any broken references are found.
- Add the script as a pre-commit hook or GitHub Actions step.

## Non-Objectives

- Does not validate content quality, only structural cross-references.
- Does not auto-fix broken references.

## Proposed Design

```bash
#!/usr/bin/env bash
# validate-refs.sh — Check cross-reference integrity in solidity-security-audit-skill

REFS_DIR="references"
INDEX="references/INDEX.md"
ERRORS=0

echo "=== Validating INDEX.md cross-references ==="

# Extract file:section pairs from INDEX.md (format: file.md | §N.N)
grep -oP '\w[\w-]+\.md \| §[\d.]+' "$INDEX" | while IFS=' | ' read -r file section; do
    # Normalize section: §1.2 → "### §1.2" or look for heading containing the section number
    section_num="${section#§}"
    if ! grep -qP "^#{1,4}.*${section_num}" "${REFS_DIR}/${file}" 2>/dev/null; then
        echo "BROKEN: ${INDEX}: ${file}:${section} — heading not found"
        ERRORS=$((ERRORS + 1))
    fi
done

echo "=== Validating inline 'See X.md §Y' references ==="

grep -rn 'See.*\.md §' "${REFS_DIR}"/ | grep -oP 'See \K[\w-]+\.md §[\d.]+' | while read -r ref; do
    file="${ref%% *}"
    section="${ref#* }"
    section_num="${section#§}"
    if ! grep -qP "^#{1,4}.*${section_num}" "${REFS_DIR}/${file}" 2>/dev/null; then
        echo "BROKEN inline ref: ${file}:${section}"
        ERRORS=$((ERRORS + 1))
    fi
done

if [ "$ERRORS" -gt 0 ]; then
    echo "❌ Found $ERRORS broken cross-references."
    exit 1
else
    echo "✅ All cross-references valid."
    exit 0
fi
```

**GitHub Actions integration** (`.github/workflows/validate-refs.yml`):
```yaml
name: Validate Cross-References
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: bash docs/scripts/validate-refs.sh
```

## Implementation Plan

1. Create `docs/scripts/` directory.
2. Create `docs/scripts/validate-refs.sh` with the script above.
3. Make the script executable (`chmod +x`).
4. Create `.github/workflows/validate-refs.yml` for CI integration.
5. Run the script against the current codebase and fix any discovered broken references.
6. Commit both the script and workflow.

## Risks

- Low-medium. Script relies on grep patterns that may need tuning for edge cases in heading formats.
- First run may reveal many existing broken references that need fixing before CI can be green.

## Testing / Acceptance Criteria

- `docs/scripts/validate-refs.sh` exists and is executable.
- Running the script on the current codebase exits 0 (all references valid).
- GitHub Actions workflow runs on PR and fails if broken references are introduced.
- Script detects at least one intentionally broken reference in a test run.

## Rollback

Delete `docs/scripts/validate-refs.sh` and `.github/workflows/validate-refs.yml`.
