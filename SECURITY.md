# Security policy

## Supported code

Security fixes target the current development branch and the latest release candidate.
There is no stable release support commitment yet. Older commits and release candidates
may not receive backports. Check the [releases](https://github.com/uppnrise/snyk-auto-remediate/releases)
and [changelog](CHANGELOG.md) before upgrading.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/uppnrise/snyk-auto-remediate/security/advisories/new).
Include the affected commit/tag, reproduction steps, impact, and a sanitized example.
Do not include active tokens, private dependency inventories, or customer data.
Avoid publishing exploit details in a public issue before the maintainer has reviewed them.
There is no guaranteed response time; this is a maintainer-run open-source project.

## Operating the workflow

- Pin both the reusable workflow reference and `engine-ref` to the same reviewed tag or SHA.
- Start in dry-run and inspect report artifacts before enabling changes.
- Review remediation PRs and run the target repository's required checks before merging.
- Grant only the repository permissions needed for the selected target. Keep Snyk/GitHub
  tokens in Actions secrets and remove credentials from bug reports.
- Package installation and custom test commands execute target-repository code with workflow
  credentials available. Run the workflow only against repositories and branches you trust.
- The Snyk CLI follows the floating `stable` channel. Engine pinning does not pin that CLI;
  the installation smoke test checks availability, not JSON compatibility.
- Failed/incomplete scans preserve fallback issues, and failed engine runs do not upload
  partial SARIF as a replacement for existing code-scanning results.

REST exact remedies are not verified by a CLI re-scan. Review the evidence and test outcome;
an applied upgrade is not a claim that the vulnerability has been independently verified fixed.
