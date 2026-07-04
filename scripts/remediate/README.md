# Snyk Auto-Remediation Engine

A production-ready TypeScript engine for automatically remediating Snyk security findings in GitHub repositories.

## Overview

This engine:

1. **Fetches** Snyk security findings via the Snyk REST API (paginated, with retry/backoff)
2. **Classifies** findings into fixable and unfixable categories
3. **Auto-fixes** dependency-level issues using package-manager-native commands
4. **Creates GitHub Issues** assigned to `@copilot` for unfixable findings
5. **Generates** JSON, SARIF, and Markdown reports

## Requirements

- Node.js 20+
- `tsx` (installed via devDependencies)

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SNYK_TOKEN` | ✅ | — | Snyk API authentication token |
| `SNYK_ORG_ID` | ✅ | — | Snyk organization ID |
| `GITHUB_REPOSITORY` | ✅ | — | `owner/repo` format |
| `GITHUB_TOKEN` | ✅ | — | GitHub token (for creating issues/PRs) |
| `SNYK_PROJECT_IDS` | ❌ | — | Comma-separated Snyk project IDs to scope |
| `SEVERITY_THRESHOLD` | ❌ | `high` | Minimum severity: `critical`, `high`, `medium`, `low` |
| `PACKAGE_MANAGERS` | ❌ | auto-detect | Comma-separated: `npm,yarn,pip,poetry,maven,gradle,go,composer` |
| `DRY_RUN` | ❌ | `false` | If `true`, no changes are committed or PRs opened |
| `MAX_PRS_PER_RUN` | ❌ | `5` | Max PRs to open per run |
| `MAX_ISSUES_PER_RUN` | ❌ | `10` | Max GitHub Issues to create per run |
| `WORKING_DIRECTORY` | ❌ | `.` | Working directory for package manager commands |
| `ENABLE_COPILOT_AGENT_FALLBACK` | ❌ | `true` | Create Issues for unfixable findings |
| `COPILOT_ASSIGNEE` | ❌ | `copilot` | GitHub username to assign Issues to |
| `FAIL_ON_NO_FIX` | ❌ | `false` | Exit code 2 if no fixes were applied |
| `RUN_TESTS` | ❌ | `true` | Run tests after applying fixes |
| `TEST_COMMAND` | ❌ | — | Custom test command |
| `TARGET_BRANCH` | ❌ | `main` | Target branch being remediated |
| `PR_LABELS` | ❌ | `security,dependencies,snyk,automated` | Labels for PRs |
| `ISSUE_LABELS` | ❌ | `security,snyk,ai-remediation` | Labels for Issues |
| `PR_REVIEWERS` | ❌ | — | Comma-separated GitHub usernames for PR review |
| `PR_TEAM_REVIEWERS` | ❌ | — | Comma-separated GitHub team slugs for PR review |

## Running Locally

```bash
cd scripts/remediate
npm install
export SNYK_TOKEN=your-snyk-token
export SNYK_ORG_ID=your-org-id
export GITHUB_REPOSITORY=owner/repo
export GITHUB_TOKEN=your-github-token
export DRY_RUN=true
npx tsx src/index.ts
```

## Development

```bash
# Type check
npm run build

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint
npm run lint

# Format
npm run format
```

## Architecture

```
src/
├── index.ts                    # Main entry point
├── snyk/
│   ├── api-client.ts           # Snyk REST API client (paginated, retry/backoff)
│   ├── cli-runner.ts           # Snyk CLI wrapper + package info extraction
│   └── types.ts                # TypeScript types for Snyk API responses
├── detectors/
│   └── language-detector.ts    # Ecosystem auto-detection from manifest files
├── fixers/
│   ├── base-fixer.ts           # Abstract base class for all fixers
│   ├── npm-fixer.ts            # npm install --save <pkg>@<version>
│   ├── yarn-fixer.ts           # yarn upgrade <pkg>@<version>
│   ├── pip-fixer.ts            # pip install --upgrade <pkg>>=<version>
│   ├── poetry-fixer.ts         # poetry add <pkg>@^<version>
│   ├── maven-fixer.ts          # mvn versions:use-latest-releases
│   ├── gradle-fixer.ts         # ./gradlew dependencyUpdates
│   ├── go-fixer.ts             # go get <pkg>@v<version> && go mod tidy
│   └── composer-fixer.ts       # composer require <pkg>:^<version>
├── github/
│   ├── api-client.ts           # GitHub REST API client
│   ├── issue-creator.ts        # Create/update Issues for unfixable findings
│   └── pr-creator.ts           # Create/update PRs for fixed findings
├── reporting/
│   ├── json-writer.ts          # Write snyk-remediation-report.json
│   ├── sarif-writer.ts         # Write SARIF output for GitHub Security
│   └── summary-writer.ts       # Write GitHub Actions step summary
└── utils/
    ├── config.ts               # Load + validate config from env vars
    ├── dedup.ts                 # Deduplicate and partition issues
    ├── exec.ts                  # Spawn child processes with timeout
    ├── git.ts                   # Git operations (checkout, commit, push)
    └── logger.ts                # Structured logger with secret masking
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime error |
| `2` | No fixes applied when `FAIL_ON_NO_FIX=true` |

## Security

- Tokens are **never logged** — the logger automatically masks `****** `token TOKEN`, `ghp_*`, and `snyk_*` patterns.
- All API calls use HTTPS.
- Retry-with-exponential-backoff on Snyk API 429/5xx responses.

## Reports

After each run, the following files are written to the working directory:

| File | Format | Description |
|------|--------|-------------|
| `snyk-remediation-report.json` | JSON | Machine-readable remediation report |
| `snyk-remediation-report.sarif` | SARIF 2.1.0 | Uploaded to GitHub Security tab |

A rich Markdown summary is also written to `$GITHUB_STEP_SUMMARY` when running in GitHub Actions.
