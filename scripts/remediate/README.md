# Remediation engine

The TypeScript engine used by the repository's reusable GitHub Actions workflow.

## Requirements

- Node.js 20.19 or newer
- Snyk CLI
- Git
- The package managers used by the target project

The reusable workflow installs a pinned Snyk CLI and the required language toolchains. For local
execution, install the Snyk CLI separately.

## Run locally

```bash
npm ci

export SNYK_TOKEN=...
export GITHUB_REPOSITORY=owner/repo
export WORKING_DIRECTORY=/absolute/path/to/target
export DRY_RUN=true

npm start
```

`GITHUB_TOKEN` is optional during a dry run. It is required when the engine may push a branch or
mutate pull requests and issues.

Without `SNYK_PROJECT_IDS`, inventory comes exclusively from the checked-out repository's CLI
scan, and `SNYK_ORG_ID` is optional. Set both `SNYK_ORG_ID` and a comma-separated list of exact
project IDs to enable scoped REST inventory.

## Environment variables

| Variable | Required | Default |
| --- | --- | --- |
| `SNYK_TOKEN` | yes | — |
| `SNYK_ORG_ID` | with `SNYK_PROJECT_IDS` | `local-cli` |
| `GITHUB_REPOSITORY` | yes | — |
| `GITHUB_TOKEN` | unless dry-run | — |
| `SNYK_PROJECT_IDS` | no | local CLI inventory |
| `SEVERITY_THRESHOLD` | no | `high` |
| `PACKAGE_MANAGERS` | no | auto-detect |
| `DRY_RUN` | no | `false` |
| `MAX_ISSUES_PER_RUN` | no | `10` |
| `WORKING_DIRECTORY` | no | `.` |
| `ENABLE_COPILOT_AGENT_FALLBACK` | no | `true` |
| `COPILOT_ASSIGNEE` | no | `copilot` |
| `FAIL_ON_NO_FIX` | no | `false` |
| `RUN_TESTS` | no | `true` |
| `TEST_COMMAND` | no | detected suites |
| `TARGET_BRANCH` | no | `main` |
| `REMEDIATION_BRANCH_SUFFIX` | no | unset |
| `PR_LABELS` | no | `security,dependencies,snyk,automated` |
| `ISSUE_LABELS` | no | `security,snyk,ai-remediation` |
| `ISSUE_MANAGEMENT_LABEL` | no | `snyk` |
| `PR_REVIEWERS` | no | unset |
| `PR_TEAM_REVIEWERS` | no | unset |

Invalid booleans, severity values, package-manager names, repository names, and negative limits fail
fast with an actionable error.

Supported `PACKAGE_MANAGERS` values are:

```text
npm,yarn,pnpm,pip,poetry,maven,gradle,go,composer
```

`TEST_COMMAND` is executed as a shell expression, so quoted arguments and command chains work.
Without it, the engine runs every detected ecosystem's test command. npm, Yarn, and pnpm tests are
only selected when `package.json` contains a real `scripts.test` entry.

## Reports

Reports are written to `WORKING_DIRECTORY`:

- `snyk-remediation-report.json`
- `snyk-remediation-report.sarif`
- the GitHub step summary when `GITHUB_STEP_SUMMARY` is set

Dry-run reporting distinguishes planned issue work from created, updated, and closed issues.

## Validation

```bash
npm test -- --run
npm run build
npm run lint
npm run format:check
npm run test:coverage
npm audit --audit-level=moderate
```
