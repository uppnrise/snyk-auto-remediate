# Changelog

## Unreleased

### Fixed

- Preserve actionable CLI findings and SARIF results after scoped REST access returns 403.
  Record the actual inventory source and isolate CLI/REST issue reconciliation with version 2 scopes.
- Add a deterministic hash to remediation branches so distinct branch/report IDs cannot collide
  after punctuation replacement or truncation. Retain older branches, PRs, and issue scopes for review.
- Upload SARIF to the scanned repository/ref/commit, including published remediation branches,
  and wait for GitHub processing before reporting success.
- Correct pip requirement matching for exact pins, ranges, bare packages, extras, markers, and
  comments; retain unsupported direct references for manual work and roll back failed installs.

## 1.0.0-rc.1

First tagged release candidate. Validate against disposable repositories before production use.

### Fixed

- Preserve fallback issues after failed/partial scans, unsupported projects, failed post-fix
  tests, and push/PR errors.
- Reject operational Snyk CLI failures and incomplete or malformed JSON scan results.
- Restrict issue updates and closures to the same repository/project/branch/report/inventory
  scope. Leave older issues without scope markers untouched.
- Suppress workflow failure-alert mutations during dry-run.
- Upload SARIF only after a successful engine step, retaining failed-run artifacts for diagnosis.

### Added

- Testable orchestration module and regression coverage for issue lifecycle, scan failures,
  exact remediation, verification rollback, and PR publication.
- CI coverage reports and minimum coverage requirements, including the orchestration module.
- Roadmap, contribution/security/conduct policies, bug and feature forms, and a PR template.
- Example monorepo workflow and illustrative remediation reports/PR.
- Release process and documentation of evidence, verification, and migration limits.

### Existing capabilities

Reusable GitHub Actions workflow; top-level detection for npm, Yarn, pnpm, pip, Poetry,
Maven, Gradle, Go, and Composer; exact Snyk-evidenced upgrades; managed PRs and fallback
issues; JSON/SARIF/Actions summaries. Scoped REST inventory skips local scans; only
CLI-evidenced changes receive CLI re-scan verification.

## Earlier untagged development

Development on `master` introduced the remediation engine and workflow reliability fixes.
The Snyk CLI installation failure reported in
[#18](https://github.com/uppnrise/snyk-auto-remediate/issues/18) was resolved by following the
`stable` channel and adding install smoke tests and workflow failure alerts.
