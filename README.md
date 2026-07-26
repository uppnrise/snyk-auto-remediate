# snyk-auto-remediate

Automated, evidence-based dependency remediation for GitHub repositories.

The project combines a reusable GitHub Actions workflow with a TypeScript engine. It scans the
checked-out repository with the Snyk CLI, applies only exact upgrade paths reported by Snyk,
verifies each change with another scan, runs the repository's tests, and opens or updates one
remediation pull request per target branch.

Findings without a safe exact upgrade are represented by managed GitHub Issues. Those issues are
updated while a finding remains active and closed when it no longer requires fallback work.

## Quick start

Create a workflow in the repository you want to remediate:

```yaml
name: Snyk remediation

on:
  workflow_dispatch:
  schedule:
    - cron: '0 3 * * 1'

permissions:
  contents: write
  pull-requests: write
  issues: write
  security-events: write

jobs:
  remediate:
    uses: uppnrise/snyk-auto-remediate/.github/workflows/snyk-remediate.reusable.yml@master
    with:
      target-branches: main
      severity-threshold: high
      dry-run: true
    secrets:
      SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

Start with `dry-run: true`, inspect the workflow summary and artifacts, then disable dry-run when
the result matches the repository. Set `SNYK_ORG_ID` as a GitHub Actions variable only when using
explicit `snyk-project-ids`.

For production, pin the reusable workflow reference and `engine-ref` to a release tag or commit
SHA rather than `master`.

## Inventory and project scoping

Safety is repository-first:

- Without `snyk-project-ids`, the engine uses repository-local Snyk CLI findings. It does not
  import the entire organization's issue inventory into one GitHub repository.
- With `snyk-project-ids`, the engine fetches those exact Snyk REST projects. A REST finding must
  correlate to the same CLI project before it can produce a remediation action.
- A CLI result without project identity is accepted only when exactly one configured Snyk project
  is in scope.
- Findings verified as fixed are excluded from the SARIF uploaded for that run.

If scoped REST access returns `403`, the engine safely falls back to repository-local CLI
inventory.

## Remediation flow

For each target branch, the engine:

1. Detects one JavaScript package manager and any additional top-level ecosystems.
2. Prepares package managers that need local dependencies or Corepack.
3. Runs authenticated Snyk CLI scans.
4. Loads local inventory, or explicitly scoped REST inventory.
5. Correlates findings by Snyk key and project identity.
6. Builds only unambiguous, exact upgrade actions.
7. Applies changes with the native package manager.
8. Re-scans and rolls back an ecosystem batch if verification fails.
9. Commits verified changes to a stable remediation branch.
10. Runs every detected ecosystem's test suite, or one explicit custom command.
11. Pushes and creates or updates the remediation PR.
12. Creates, updates, and closes managed fallback issues.
13. Writes JSON, SARIF, and GitHub Actions summary reports.

## Supported package managers

| Manager | Detection | Exact remediation |
| --- | --- | --- |
| npm | `package-lock.json` or `package.json` | `npm install --save-exact` |
| Yarn | `yarn.lock` | `yarn add --exact` |
| pnpm | `pnpm-lock.yaml` | `pnpm add --save-exact` |
| pip | `requirements.txt` | pins a direct requirement, then installs it |
| Poetry | `poetry.lock` | `poetry add` |
| Maven | `pom.xml` | `versions:use-dep-version` |
| Gradle | `build.gradle`, `build.gradle.kts` | edits literal dependency coordinates |
| Go modules | `go.mod` | `go get`, then `go mod tidy` |
| Composer | `composer.json` or `composer.lock` | `composer require` |

Detection is intentionally top-level. For a monorepo, invoke the reusable workflow once per
project directory with a unique `report-id`.

Yarn and pnpm take precedence over the generic `package.json` npm signature. A standalone
`pyproject.toml` is not assumed to be Poetry; `poetry.lock` is required.

## Important inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `target-repository` | caller repository | Repository in `owner/repo` form |
| `target-branches` | `master` | Comma-separated branches |
| `engine-ref` | `master` | Engine tag, branch, or SHA |
| `report-id` | `scan` | Isolates branches, artifacts, and SARIF categories |
| `working-directory` | `.` | Project directory inside the target repository |
| `snyk-project-ids` | unset | Exact REST project scope; unset uses local CLI inventory |
| `severity-threshold` | `high` | `critical`, `high`, `medium`, or `low` |
| `package-managers` | auto-detect | Explicit manager allow-list |
| `dry-run` | `false` | Reports planned work without mutating GitHub or git |
| `max-issues-per-run` | `10` | Limits fallback issue creates/updates |
| `run-tests` | `true` | Runs detected test suites before push |
| `test-command` | unset | Shell command replacing automatic test selection |
| `enable-copilot-agent-fallback` | `true` | Manages fallback GitHub Issues |

For a different private target repository, provide `GH_PAT`. The caller's `github.token` normally
suffices when the caller and target are the same repository.

## Operational behavior

- Remediation branches are stable:
  `chore/security/snyk-remediation-{target-branch}-{report-id}`.
- Repeated runs reset that automation-owned branch from the requested target branch and update the
  existing PR.
- Workflow concurrency serializes runs for the same repository, branch, and report ID.
- Pushes use `--force-with-lease`.
- Custom labels are created when missing.
- If the configured Copilot assignee is unavailable, the fallback issue is created unassigned
  instead of failing the entire run. Assigning issues to Copilot requires the relevant GitHub
  Copilot plan and repository settings.
- Raw Snyk data in an issue is bounded to prevent GitHub body-size failures.

## Development

The executable package is under [`scripts/remediate`](scripts/remediate):

```bash
cd scripts/remediate
npm ci
npm test -- --run
npm run build
npm run lint
npm run format:check
npm audit --audit-level=moderate
```

See [`scripts/remediate/README.md`](scripts/remediate/README.md) for local execution details.
