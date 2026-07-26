import { GitHubApiClient } from './api-client.js';
import { logger } from '../utils/logger.js';
import type { RemediationConfig, SnykIssue, Severity } from '../snyk/types.js';

const FINDING_MARKER_PREFIX = '<!-- snyk-finding-id:';
const FINDING_MARKER_SUFFIX = '-->';

function buildFindingMarker(findingId: string): string {
  return `${FINDING_MARKER_PREFIX} ${findingId} ${FINDING_MARKER_SUFFIX}`;
}

function extractFindingId(body: string): string | null {
  const regex = /<!-- snyk-finding-id:\s*([^\s]+)\s*-->/;
  const match = regex.exec(body);
  return match?.[1] ?? null;
}

interface ExistingManagedIssue {
  number: number;
  body: string | null;
  state: string;
}

export function buildIssueReconciliation(
  currentIssues: SnykIssue[],
  existingIssues: ExistingManagedIssue[],
): { existingByFindingId: Map<string, number>; toClose: number[] } {
  const activeIds = new Set(currentIssues.map((issue) => issue.id));
  const existingByFindingId = new Map<string, number>();
  const toClose: number[] = [];
  for (const existing of existingIssues) {
    if (!existing.body) continue;
    const findingId = extractFindingId(existing.body);
    if (!findingId) continue;
    existingByFindingId.set(findingId, existing.number);
    if (existing.state === 'open' && !activeIds.has(findingId)) toClose.push(existing.number);
  }
  return { existingByFindingId, toClose };
}

function severityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🟢',
    info: '🔵',
  };
  return colors[severity];
}

function buildIssueBody(issue: SnykIssue, config: RemediationConfig): string {
  const attrs = issue.attributes;
  const severity = attrs.effective_severity_level;
  const marker = buildFindingMarker(issue.id);

  const problems = attrs.problems ?? [];
  const cves = problems.filter((p) => p.cve).map((p) => p.cve as string);
  const cwes = problems.filter((p) => p.type === 'cwe').map((p) => p.id);
  const cvssScore = problems.find((p) => p.cvss_score != null)?.cvss_score;

  const affectedPackages =
    (attrs.coordinates ?? [])
      .flatMap((c) => c.representations ?? [])
      .filter((r) => r.dependency)
      .map((r) => `\`${r.dependency!.package_name}@${r.dependency!.package_version}\``)
      .join(', ') || 'Unknown';

  const remedyDescription =
    (attrs.coordinates ?? [])
      .flatMap((c) => c.remedies ?? [])
      .map((r) => r.description)
      .filter(Boolean)
      .join('\n') || 'No automated remedy available. Manual investigation required.';

  const snykUrl = problems.find((p) => p.url)?.url ?? `https://security.snyk.io/vuln/${attrs.key}`;

  const rawFinding = JSON.stringify({ id: issue.id, attributes: attrs }, null, 2);
  const boundedRawFinding =
    rawFinding.length > 20_000
      ? `${rawFinding.slice(0, 20_000)}\n... truncated by snyk-auto-remediate`
      : rawFinding;

  return `${marker}

## Snyk Security Finding: ${attrs.title}

> **This issue was automatically created by the Snyk Auto-Remediation toolkit and assigned to @${config.copilotAssignee} for code-level remediation.**

---

### 📋 Finding Details

| Field | Value |
|-------|-------|
| **Snyk ID** | [\`${attrs.key}\`](${snykUrl}) |
| **Severity** | ${severityColor(severity)} ${severity.toUpperCase()} |
| **CVSS Score** | ${cvssScore != null ? cvssScore.toFixed(1) : 'N/A'} |
| **CVE(s)** | ${cves.length > 0 ? cves.join(', ') : 'N/A'} |
| **CWE(s)** | ${cwes.length > 0 ? cwes.join(', ') : 'N/A'} |
| **Type** | ${attrs.type} |
| **Status** | ${attrs.status} |

---

### 📦 Affected Package(s)

${affectedPackages}

---

### 🔍 Description

${attrs.description ?? attrs.title}

---

### 🛠 Snyk's Suggested Remediation

${remedyDescription}

---

### 🤖 Instructions for @${config.copilotAssignee}

Please investigate and fix this security vulnerability. Here is what you need to do:

1. **Review the affected package(s):** ${affectedPackages}
2. **Apply the suggested fix:** ${remedyDescription}
3. **Test the fix:** Ensure all existing tests pass and no regressions are introduced
4. **Open a Pull Request** targeting the default branch with:
   - A clear title referencing this issue (e.g., \`fix: resolve ${attrs.title}\`)
   - A description explaining the change and linking back to this issue

**Acceptance criteria:**
- [ ] Vulnerable package version is updated or replaced
- [ ] All tests pass
- [ ] No new vulnerabilities introduced
- [ ] PR is opened and references this issue with \`Fixes #<issue-number>\`

---

<details>
<summary>Raw Snyk Finding Data</summary>

\`\`\`json
${boundedRawFinding}
\`\`\`

</details>`;
}

export async function createOrUpdateIssues(
  unfixableIssues: SnykIssue[],
  config: RemediationConfig,
): Promise<{ created: number; updated: number; closed: number; planned: number }> {
  const summary = { created: 0, updated: 0, closed: 0, planned: 0 };
  if (!config.enableCopilotAgentFallback) {
    logger.info('Copilot agent fallback disabled — skipping issue creation');
    return summary;
  }

  if (config.dryRun) {
    const count = Math.min(unfixableIssues.length, config.maxIssuesPerRun);
    for (const issue of unfixableIssues.slice(0, count)) {
      logger.info(`[dry-run] Would create or update fallback issue for ${issue.attributes.key}`);
    }
    summary.planned = count;
    return summary;
  }

  if (!config.githubToken) throw new Error('GITHUB_TOKEN is required to reconcile fallback issues');
  const client = new GitHubApiClient(config.githubToken, config.githubRepository);

  // Ensure required labels exist
  await ensureLabels(client, config.issueLabels);

  // Fetch existing open issues to check for duplicates
  logger.info('Fetching existing open issues to check for duplicates...');
  const existingIssues = await client.listIssues('open');

  const reconciliation = buildIssueReconciliation(unfixableIssues, existingIssues);
  for (const issueNumber of reconciliation.toClose) {
    await client.updateIssue(issueNumber, { state: 'closed' });
    logger.info(`Closed resolved fallback issue #${issueNumber}`);
    summary.closed++;
  }

  const issuesToProcess = unfixableIssues.slice(0, config.maxIssuesPerRun);

  for (const issue of issuesToProcess) {
    const severity = issue.attributes.effective_severity_level;
    const labels = [...config.issueLabels, `severity/${severity}`];

    const title = `[Snyk] ${issue.attributes.title}`;
    const body = buildIssueBody(issue, config);

    const existingIssueNumber = reconciliation.existingByFindingId.get(issue.id);

    if (existingIssueNumber !== undefined) {
      logger.info(`Updating existing issue #${existingIssueNumber} for finding ${issue.id}`);
      await client.updateIssue(existingIssueNumber, { title, body, labels });
      summary.updated++;
    } else {
      logger.info(`Creating new issue for finding ${issue.id}: ${title}`);
      let created;
      try {
        created = await client.createIssue({
          title,
          body,
          labels,
          assignees: [config.copilotAssignee],
        });
      } catch (error) {
        logger.warn(
          `Could not assign fallback issue to @${config.copilotAssignee}; creating it unassigned: ${String(error)}`,
        );
        created = await client.createIssue({ title, body, labels });
      }
      logger.info(`Created issue #${created.number}: ${created.html_url}`);
      summary.created++;
    }
  }

  return summary;
}

async function ensureLabels(client: GitHubApiClient, configuredLabels: string[]): Promise<void> {
  const labelDefs: Array<{ name: string; color: string; description: string }> = [
    { name: 'security', color: 'ee0701', description: 'Security vulnerability' },
    { name: 'snyk', color: '4c1a7e', description: 'Snyk security finding' },
    { name: 'ai-remediation', color: '0075ca', description: 'Assigned to AI for remediation' },
    { name: 'severity/critical', color: 'b60205', description: 'Critical severity' },
    { name: 'severity/high', color: 'e4e669', description: 'High severity' },
    { name: 'severity/medium', color: 'fbca04', description: 'Medium severity' },
    { name: 'severity/low', color: '0e8a16', description: 'Low severity' },
    { name: 'severity/info', color: '1d76db', description: 'Informational severity' },
  ];
  const knownNames = new Set(labelDefs.map((label) => label.name));
  for (const name of configuredLabels) {
    if (!knownNames.has(name)) {
      labelDefs.push({ name, color: '6f42c1', description: 'Snyk remediation workflow label' });
    }
  }

  for (const label of labelDefs) {
    try {
      await client.ensureLabel(label.name, label.color, label.description);
    } catch (error) {
      logger.warn(`Could not ensure label "${label.name}": ${String(error)}`);
    }
  }
}
