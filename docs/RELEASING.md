# Releasing

The workflow and engine must be released together from one reviewed commit. Package version,
Git tag, and release heading must agree. This repository is consumed through GitHub Actions;
there is no npm publishing step.

1. Update `scripts/remediate/package.json`, its lockfile, and `CHANGELOG.md`. Use a prerelease
   version for candidates (for example `1.0.0-rc.1`).
2. Run coverage, type, lint, format, and actionlint checks. Inspect the GitHub CI run for the
   exact commit, including the Snyk installation smoke test.
3. Complete the live validation items in the [roadmap](../ROADMAP.md) before a stable release.
4. Commit the final contents. Create an annotated `v<version>` tag at that commit and push it.
   A candidate may target its review branch; stable releases should target merged `master`.
5. Create a GitHub Release using the changelog entry. Mark candidates as prereleases and include
   known limits. Do not mark a candidate as the latest stable release.
6. Verify the remote tag resolves to the tested commit. Confirm the release is visible and
   both workflow and engine can be read at that tag.

Consumers should reference the same tag or commit twice:

```yaml
uses: uppnrise/snyk-auto-remediate/.github/workflows/snyk-remediate.reusable.yml@v1.0.0-rc.1
with:
  engine-ref: v1.0.0-rc.1
  target-branches: main
  dry-run: true
```

Do not move an existing release tag. If a candidate has a bug, publish a new candidate with a
new version. Monitor installation failures and credentialed test feedback after release.
