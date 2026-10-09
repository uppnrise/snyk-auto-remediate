# Illustrative remediation PR

This example is documentation, not a real scan or a vulnerability claim about the example package.

**Title:** `fix(security): Snyk auto-remediation for main`

**Head branch:** `chore/security/snyk-remediation-main-api`

**Base branch:** `main`

## Dependency change

`example-package: 1.0.0 -> 2.0.0`

The version comes from an exact Snyk upgrade path. A CLI re-scan no longer contains the original
finding, and the selected repository tests passed before publication.

For a REST-evidenced action, describe the exact REST remedy and test outcome separately: there
is no CLI re-scan verification in that mode. A human should inspect the diff and required checks
before merging. The toolkit does not merge PRs automatically.
