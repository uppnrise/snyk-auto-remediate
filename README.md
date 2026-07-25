# snyk-auto-remediate

This repository contains an automated dependency-remediation system built around Snyk findings and GitHub workflows. It is structured as a small product rather than a generic library:

- A reusable GitHub Actions workflow orchestrates checkout, language toolchain setup, Snyk authentication, engine execution, SARIF upload, and artifact retention.
- A TypeScript remediation engine in [`scripts/remediate`](scripts/remediate) fetches Snyk issues, classifies them, applies package-manager-specific upgrades where possible, opens a remediation pull request, and creates GitHub Issues for findings that cannot be auto-fixed.

The current implementation is intentionally pragmatic. It favors package-manager-native upgrade commands and GitHub automation over deep source-code rewriting.

## What The Project Does

For each target branch, the system runs this pipeline:

1. Fetch open Snyk issues from the Snyk REST API for one organization, optionally scoped to specific Snyk project IDs.
2. Validate the JSON:API response and filter findings by severity threshold.
3. Deduplicate findings by the REST resource ID.
4. Run an authenticated local Snyk CLI scan for each detected ecosystem and correlate findings by `attributes.key`.
5. Build an exact remediation action only when the CLI provides an unambiguous upgrade path or fixed version.
6. Detect which dependency ecosystems exist in the repository working directory.
7. Route exact actions to the matching fixer.
8. Apply exact dependency upgrades using the ecosystem’s native package manager.
9. Re-scan with the CLI and roll back changes when the correlated finding remains.
10. Commit verified changes to a generated remediation branch.
11. Optionally run post-fix tests.
12. Push the remediation branch and create one pull request back to the target branch.
13. Create or update GitHub Issues for findings without a safe exact action.
14. Emit JSON, SARIF, and GitHub Actions summary output.

## Repository Shape

There are two real cornerstones in this repository.

### 1. Workflow Layer

The top-level GitHub Actions workflows in [`.github/workflows`](.github/workflows) are the operational entrypoint:

- [`snyk-remediate.yml`](.github/workflows/snyk-remediate.yml) is the user-facing workflow. It supports manual dispatch and a weekly Monday 03:00 UTC schedule.
- [`snyk-remediate.reusable.yml`](.github/workflows/snyk-remediate.reusable.yml) is the reusable workflow that does the actual work.

The reusable workflow:

- checks out the requested target branch
- installs Node.js unconditionally
- installs Python, Java, and Go only when manifest detection suggests they are needed
- installs and authenticates the Snyk CLI
- installs the engine dependencies from `scripts/remediate`
- configures a bot Git identity
- runs the engine from the target repository working directory
- uploads SARIF to GitHub code scanning
- uploads the JSON and SARIF reports as artifacts

This makes the repo usable both as a scheduled security automation and as a reusable GitHub Actions component.

### 2. Engine Layer

The actual business logic lives in [`scripts/remediate/src`](scripts/remediate/src).

At a high level, the engine is composed of:

- `index.ts`: the orchestrator
- `snyk/`: Snyk data types and issue fetching
- `detectors/`: local ecosystem detection from manifests
- `fixers/`: package-manager-specific remediation strategies
- `github/`: issue and PR creation
- `reporting/`: JSON, SARIF, and markdown summary output
- `utils/`: config loading, logging, git, process execution, deduplication, and test execution

## Architecture And Control Flow

### Orchestrator

[`scripts/remediate/src/index.ts`](scripts/remediate/src/index.ts) is the runtime coordinator. It is responsible for:

- loading validated environment configuration
- fetching and deduplicating Snyk issues
- splitting them into fixable and unfixable groups
- detecting ecosystems in the repository
- selecting the matching fixer instances
- creating a remediation branch when not in dry-run mode
- committing successful dependency changes
- running tests before push/PR creation
- pushing the branch and opening a pull request
- creating fallback GitHub Issues for unfixable findings
- generating reports and exit codes

The design is linear and easy to reason about. Most of the complexity is pushed to specialized modules rather than hidden in a framework.

### Snyk Integration

[`scripts/remediate/src/snyk/api-client.ts`](scripts/remediate/src/snyk/api-client.ts) talks to `https://api.snyk.io/rest/orgs/{orgId}/issues` using:

- API version `2024-10-15`
- pagination via `links.next`
- retry with exponential backoff for `429` and `5xx`
- severity filtering after page retrieval

Important details:

- Findings are filtered using `effective_severity_level`, not just the raw `severity` field.
- Project scoping is implemented through repeated `scan_item.id` query parameters with `scan_item.type=project`.
- The engine only processes open issues.
- REST issue IDs are treated as opaque resource identifiers; the human-readable Snyk vulnerability key comes from `attributes.key`.
- `coordinates` and `problems` are optional. Code, IaC, Cloud, or sparse Open Source findings cannot crash classification.
- Multiple configured project IDs are fetched in separate requests because `scan_item.id` is scalar.
- Pagination is restricted to `https://api.snyk.io/rest` so the authentication token is never forwarded to another origin.

### Exact remediation evidence

The REST Issues API supplies inventory and reporting metadata, but its remedy schema does not contain a supported
`target_version`. The engine therefore uses the already-installed Snyk CLI as the authoritative source for
`upgradePath` and `fixedIn`. It never parses versions from remedy prose and never substitutes `latest`.

An action is sent to a fixer only when the REST key correlates to one unambiguous CLI vulnerability and produces an
exact target. Patch-only, ambiguous, computed-manifest, and uncorrelated findings use the GitHub Issue fallback.
After mutation, the matching CLI scan runs again; a finding is reported as fixed only when it is absent.

All advertised managers participate in this model: npm, Yarn, pip, Poetry, Maven, Gradle, Go modules, and Composer.
Gradle automation is intentionally limited to literal dependency coordinates, and pip automation is limited to a
direct unambiguous `requirements.txt` entry. Unsafe manifest shapes fall back instead of being guessed.

### Fixability And Ecosystem Mapping

[`scripts/remediate/src/utils/dedup.ts`](scripts/remediate/src/utils/dedup.ts) determines whether a finding is fixable by checking whether any coordinate is:

- `is_fixable_snyk`
- `is_fixable_upstream`
- `is_patchable`
- or has at least one remedy

The same module also contains the ecosystem-routing heuristics used before a fixer runs. It infers the issue’s ecosystem primarily from the Snyk issue ID prefix, then falls back to manifest-path heuristics such as `package.json`, `requirements.txt`, `pom.xml`, and `go.mod`.

That matters because the engine does not attach Snyk findings to a richer project metadata model. It uses lightweight inference to avoid sending a Java issue into an npm fixer.

### Ecosystem Detection

[`scripts/remediate/src/detectors/language-detector.ts`](scripts/remediate/src/detectors/language-detector.ts) detects supported ecosystems by looking for top-level manifest files in the configured working directory.

Current signatures:

- `yarn`: `yarn.lock`
- `npm`: `package-lock.json`, `package.json`
- `poetry`: `poetry.lock`, `pyproject.toml`
- `pip`: `requirements.txt`
- `maven`: `pom.xml`
- `gradle`: `build.gradle`, `build.gradle.kts`
- `go`: `go.mod`
- `composer`: `composer.json`, `composer.lock`

Detection is shallow by design. It does not crawl the repository recursively or model monorepo topology.

### Fixers

Each fixer is a thin wrapper around the package manager’s native command line.

Supported implementations:

- [`npm-fixer.ts`](scripts/remediate/src/fixers/npm-fixer.ts): `npm install ... --save`
- [`yarn-fixer.ts`](scripts/remediate/src/fixers/yarn-fixer.ts): `yarn upgrade ...`
- [`pip-fixer.ts`](scripts/remediate/src/fixers/pip-fixer.ts): `pip install --upgrade ...`
- [`poetry-fixer.ts`](scripts/remediate/src/fixers/poetry-fixer.ts): `poetry add ...`
- [`maven-fixer.ts`](scripts/remediate/src/fixers/maven-fixer.ts): `mvn versions:use-latest-releases`
- [`gradle-fixer.ts`](scripts/remediate/src/fixers/gradle-fixer.ts): `./gradlew dependencyUpdates -Drevision=release`
- [`go-fixer.ts`](scripts/remediate/src/fixers/go-fixer.ts): `go get ...` then `go mod tidy`
- [`composer-fixer.ts`](scripts/remediate/src/fixers/composer-fixer.ts): `composer require ...`

Most fixers extract dependency name, current version, and target version from the first Snyk coordinate representation and remedy they can interpret. They are command wrappers, not lockfile editors.

### Git And Pull Request Model

The git flow is centralized in [`scripts/remediate/src/utils/git.ts`](scripts/remediate/src/utils/git.ts):

- configure a bot user locally
- create or reuse a branch named `chore/security/snyk-remediation-{targetBranch}-{YYYYMMDD}`
- stage all changes
- commit per ecosystem when that fixer changed the tree
- push with `--force-with-lease`

PR creation lives in [`scripts/remediate/src/github/pr-creator.ts`](scripts/remediate/src/github/pr-creator.ts). It first checks whether an open PR already exists from the remediation branch to the base branch, then creates one if needed and optionally adds labels and reviewers.

Operationally, the current system creates one remediation branch per target branch per day and, in practice, at most one PR for that branch run.

### Unfixable-Finding Fallback

[`scripts/remediate/src/github/issue-creator.ts`](scripts/remediate/src/github/issue-creator.ts) is the fallback path for findings that the engine does not auto-remediate.

It:

- ensures a small label set exists
- fetches open GitHub Issues
- detects duplicates using an HTML comment marker carrying the Snyk finding ID
- updates an existing issue when the marker already exists
- otherwise creates a new issue assigned to the configured assignee

The generated issue body is intentionally rich: it includes severity, CVEs, CWEs, package details, suggested remediation text, raw Snyk payload, and instructions aimed at an assignee such as `@copilot`.

### Reporting

The reporting layer produces three outputs:

- [`snyk-remediation-report.json`](scripts/remediate/src/reporting/json-writer.ts): full machine-readable run report
- [`snyk-remediation-report.sarif`](scripts/remediate/src/reporting/sarif-writer.ts): SARIF 2.1.0 for code scanning ingestion
- GitHub step summary markdown via [`summary-writer.ts`](scripts/remediate/src/reporting/summary-writer.ts)

The SARIF writer maps:

- `critical` and `high` to `error`
- `medium` to `warning`
- `low` to `note`

## Runtime Configuration

The engine is configured entirely through environment variables loaded by [`scripts/remediate/src/utils/config.ts`](scripts/remediate/src/utils/config.ts).

The engine prefers the Snyk REST API for organization-wide issue inventory. If Snyk returns
`403 Forbidden` because the account plan does not include API access, it automatically falls back
to findings from authenticated local `snyk test --json` scans. CLI-only mode is limited to detected
projects in `WORKING_DIRECTORY`; it does not provide organization-wide inventory. Other REST
failures remain fatal.

### Required

| Variable | Purpose |
| --- | --- |
| `SNYK_TOKEN` | Snyk API authentication token |
| `SNYK_ORG_ID` | Snyk organization ID |
| `GITHUB_REPOSITORY` | GitHub repository in `owner/repo` form |
| `GITHUB_TOKEN` | Token used for issues and pull requests |

### Optional

| Variable | Default | Purpose |
| --- | --- | --- |
| `SNYK_PROJECT_IDS` | unset | Comma-separated Snyk project IDs |
| `SEVERITY_THRESHOLD` | `high` | One of `critical`, `high`, `medium`, `low` |
| `PACKAGE_MANAGERS` | auto-detect | Restrict remediation to specific managers |
| `DRY_RUN` | `false` | Skip git pushes, PR creation, and issue mutation |
| `MAX_PRS_PER_RUN` | `5` | Compatibility setting; the engine currently creates at most one PR per target branch |
| `MAX_ISSUES_PER_RUN` | `10` | Limit fallback issue processing |
| `WORKING_DIRECTORY` | `.` | Repository directory to inspect and mutate |
| `ENABLE_COPILOT_AGENT_FALLBACK` | `true` | Enable GitHub Issue creation for unfixable findings |
| `COPILOT_ASSIGNEE` | `copilot` | Assignee for fallback issues |
| `FAIL_ON_NO_FIX` | `false` | Exit with code `2` when fixable issues existed but none were fixed |
| `RUN_TESTS` | `true` | Run post-fix tests before push/PR creation |
| `TEST_COMMAND` | unset | Explicit test command, bypassing auto-detection |
| `TARGET_BRANCH` | `main` | Base branch being remediated |
| `PR_LABELS` | `security,dependencies,snyk,automated` | Labels for remediation PRs |
| `ISSUE_LABELS` | `security,snyk,ai-remediation` | Labels for fallback issues |
| `PR_REVIEWERS` | unset | Comma-separated GitHub usernames |
| `PR_TEAM_REVIEWERS` | unset | Comma-separated GitHub team slugs |
| `LOG_LEVEL` | `info` | Logger verbosity |

## Local Development

The repository has no root Node.js package. The executable package lives under [`scripts/remediate`](scripts/remediate).

```bash
cd scripts/remediate
npm ci
npm test
npm run build
```

To run the engine locally:

```bash
cd scripts/remediate
export SNYK_TOKEN=...
export SNYK_ORG_ID=...
export GITHUB_REPOSITORY=owner/repo
export GITHUB_TOKEN=...
export WORKING_DIRECTORY=/absolute/path/to/target/repo
export DRY_RUN=true
npx tsx src/index.ts
```

## Testing State

The project currently has passing tests and type-checking for the package in [`scripts/remediate`](scripts/remediate):

- `npm test`
- `npm run build`

The present automated coverage is strongest around:

- configuration loading
- issue deduplication and fixability partitioning
- ecosystem detection
- SARIF and summary generation
- git branch naming
- npm fixer behavior
- a lightweight end-to-end integration path

Coverage is lighter around live Snyk/GitHub API integration and the non-npm fixers, so those areas should still be treated as implementation-backed but less exhaustively tested.

## Important Design Limits

These are not necessarily bugs; they are the current architectural boundaries of the repository:

- Ecosystem detection is top-level and manifest-based, not recursive monorepo discovery.
- Issue-to-ecosystem routing is heuristic, not backed by a richer project graph.
- Fixers mostly rely on single-step package-manager commands, not precise lockfile surgery.
- `MAX_PRS_PER_RUN` does not currently correspond to multiple independently-created PRs. The engine batches fixes into one remediation branch/PR path per target branch run.
- Post-fix test auto-detection is best-effort and intentionally simple.
- The workflow conditionally installs Python, Java, and Go, but not PHP tooling; PHP remediation assumes `composer` already exists in the execution environment if needed.

## Security And Operational Notes

- Logging masks common token patterns for Snyk and GitHub credentials.
- Snyk API and GitHub issue/PR workflows include retry logic for rate limiting and transient failures.
- Git pushes use `--force-with-lease`, so the automation assumes ownership of its remediation branch.
- Reports are written into the configured working directory, not into `scripts/remediate`.

## Where To Start

If you need to change behavior, these files are the best entry points:

- orchestration: [`scripts/remediate/src/index.ts`](scripts/remediate/src/index.ts)
- workflow contract: [`.github/workflows/snyk-remediate.reusable.yml`](.github/workflows/snyk-remediate.reusable.yml)
- configuration surface: [`scripts/remediate/src/utils/config.ts`](scripts/remediate/src/utils/config.ts)
- fixer implementations: [`scripts/remediate/src/fixers`](scripts/remediate/src/fixers)
- GitHub fallback automation: [`scripts/remediate/src/github`](scripts/remediate/src/github)
