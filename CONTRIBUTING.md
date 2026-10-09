# Contributing

Bug reports, documentation improvements, tests, and focused pull requests are welcome.
Read the [roadmap](ROADMAP.md) and [code of conduct](CODE_OF_CONDUCT.md) first.
Report vulnerabilities through the [security policy](SECURITY.md).

## Local setup

Use Node.js 20.19 or newer and Git. From the repository root:

```bash
cd scripts/remediate
npm ci
npm run test:coverage
npm run build
npm run lint
npm run format:check
```

`build` checks TypeScript types; it does not produce a bundled executable. Snyk credentials
are not needed for the mocked test suite. Local remediation requires Snyk CLI and the target
project's package managers; see the [engine guide](scripts/remediate/README.md).

## Making a change

1. Create a branch and describe the user-visible problem.
2. For behavior changes, add a regression test before the implementation.
3. Keep remediation based on exact Snyk evidence. Treat failed or incomplete inventory as
   unknown, and preserve existing issue state.
4. Use disposable repositories and dry-run for manual testing. Never include tokens, private
   repository data, or raw confidential scan output in commits or public reports.
5. Run the commands above. Run `npm run format` if formatting needs updating.
6. Update documentation and `CHANGELOG.md` when behavior or configuration changes.
7. Open a PR with the trigger, resulting behavior, validation, and remaining limitations.

CI validates workflows with actionlint, checks format/lint/types, runs tests with coverage,
and performs a secret-free Snyk CLI installation smoke test. Tests that reach Snyk/GitHub
must mock those boundaries; real credentialed checks belong in disposable repositories.

## Test layout

- `tests/unit`: configuration, parsing, planning, fixers, API clients, and reporting.
- `tests/integration/remediation-engine.test.ts`: real orchestration, detection, inventory,
  reconciliation, and report writing, with external service/command boundaries mocked.
- `tests/integration/end-to-end.test.ts`: fixture component checks, not a live end-to-end run.

Coverage includes `src/engine.ts`. Only the thin process-entry wrapper is excluded.
CI coverage artifacts show gaps; meeting a floor is not proof of package-manager compatibility.

See [release guidance](docs/RELEASING.md) for tagging and publishing a release.
