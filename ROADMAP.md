# Roadmap

This roadmap describes current priorities, not delivery dates. Changes are tracked through
[issues](https://github.com/uppnrise/snyk-auto-remediate/issues) and pull requests.

## 1.0 release candidate: safe operations and public documentation

- [x] Preserve fallback issues after failed, partial, or unsupported scans.
- [x] Reject operational CLI errors and incomplete JSON project results.
- [x] Isolate issue reconciliation by repository, project directory, branch, report ID,
  Snyk inventory scope, severity threshold, and package-manager selection.
- [x] Preserve legacy issues until a maintainer reviews their scope.
- [x] Exercise the orchestration pipeline with mocked Snyk and GitHub boundaries.
- [x] Include the engine in coverage and enforce coverage floors in CI.
- [x] Document CLI versus REST evidence and verification limits.
- [x] Add contribution, security, issue, PR, and release guidance.
- [x] Add example workflow, summary, JSON report, and remediation PR.
- [x] Preserve actionable findings and SARIF during REST-to-CLI fallback, with separate issue scopes.
- [x] Prevent remediation branch collisions and bind SARIF uploads to the scanned repo/ref/commit.
- [x] Cover pip manifest updates and failed-install rollback with file-based regression tests.

## Before the first stable release

- [ ] Validate the release candidate on disposable repositories with real Snyk credentials.
  Start with npm; record package-manager versions and actual PR/issue behavior.
- [ ] Add command-level fixture tests for every advertised package manager. Current detection
  and planning support is broader than real package-manager execution coverage.
- [ ] Test REST exact remedies against a real scoped Snyk project; define a post-change
  verification mechanism for that mode.
- [ ] Review release-candidate feedback and publish a stable, immutable workflow/engine tag.

## Subsequent improvements

- [ ] Add CLI JSON compatibility checks alongside the existing installation smoke test.
- [ ] Add opt-in migration tooling for legacy fallback issues, with preview and explicit scope.
- [ ] Improve monorepo ergonomics beyond one invocation per project directory.
- [ ] Report applied, verified, tested, and published changes as separate statuses.
- [ ] Increase fixer and GitHub retry-path coverage using disposable local repositories.

## Scope boundaries

Container images, IaC, Snyk Code, recursive project discovery, automatic PR merging, and
guessed upgrade versions are outside the current dependency-remediation workflow.
Proposals should include a concrete use case, evidence requirements, and verification strategy.
