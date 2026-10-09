import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  buildIssueBody,
  buildIssueReconciliation,
  createOrUpdateIssues,
  buildIssueScope,
} from '../../../src/github/issue-creator.js';
import { GitHubApiClient } from '../../../src/github/api-client.js';
import type { RemediationConfig, SnykIssue } from '../../../src/snyk/types.js';

const issue = {
  id: 'finding-id',
  type: 'issue',
  attributes: {
    key: 'SNYK-JS-TEST-1',
    title: 'Finding',
    type: 'package_vulnerability',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    effective_severity_level: 'high',
    status: 'open',
    ignored: false,
  },
  relationships: {
    organization: { data: { id: 'org', type: 'organization' } },
    scan_item: { data: { id: 'project', type: 'project' } },
  },
} satisfies SnykIssue;

const config = {
  dryRun: true,
  enableCopilotAgentFallback: true,
  maxIssuesPerRun: 10,
  githubRepository: 'owner/repo',
  targetBranch: 'main',
  workingDirectory: 'packages/api',
  remediationBranchSuffix: 'api',
  snykOrgId: 'local-cli',
  severityThreshold: 'high',
  issueLabels: ['security'],
  issueManagementLabel: 'snyk',
} as RemediationConfig;

describe('fallback issue lifecycle', () => {
  afterEach(() => vi.restoreAllMocks());
  it('identifies the originating Snyk project in the issue body', () => {
    const body = buildIssueBody(issue, config);

    expect(body).toContain('`project`');
    expect(body).toContain('https://app.snyk.io/org/org/project/project');
  });

  it('reports planned work without claiming issues were created during dry-run', async () => {
    await expect(
      createOrUpdateIssues([issue], config, { inventoryComplete: true }),
    ).resolves.toEqual({
      created: 0,
      updated: 0,
      closed: 0,
      planned: 1,
    });
  });

  it('closes managed issues whose Snyk findings are no longer present', () => {
    const existing = [
      {
        number: 42,
        body: `<!-- snyk-finding-id: old-finding -->\n<!-- snyk-remediation-scope: ${buildIssueScope(config)} -->`,
        state: 'open',
      },
      {
        number: 43,
        body: buildIssueBody(issue, config),
        state: 'open',
      },
    ];

    expect(buildIssueReconciliation([issue], existing, buildIssueScope(config)).toClose).toEqual([
      42,
    ]);
  });

  it('leaves other directories, branches, report IDs, and legacy issues untouched', () => {
    const otherConfigs = [
      { ...config, workingDirectory: 'packages/web' },
      { ...config, targetBranch: 'release/1' },
      { ...config, remediationBranchSuffix: 'web' },
      { ...config, snykProjectIds: ['other-project'] },
      { ...config, severityThreshold: 'critical' as const },
    ];
    const existing = otherConfigs.map((other, index) => ({
      number: index + 1,
      body: buildIssueBody(issue, other),
      state: 'open',
    }));
    existing.push({ number: 99, body: '<!-- snyk-finding-id: finding-id -->', state: 'open' });
    const reconciliation = buildIssueReconciliation([], existing, buildIssueScope(config));
    expect(reconciliation.toClose).toEqual([]);
    expect(reconciliation.existingByFindingId.size).toBe(0);
  });

  it('normalizes project paths and project ID order within a scope', () => {
    expect(
      buildIssueScope({
        ...config,
        workingDirectory: './packages/api/',
        snykProjectIds: ['b', 'a'],
      }),
    ).toBe(buildIssueScope({ ...config, snykProjectIds: ['a', 'b'] }));
  });

  it('does not contact GitHub with incomplete inventory', async () => {
    const ensureLabel = vi.spyOn(GitHubApiClient.prototype, 'ensureLabel');
    const listIssues = vi.spyOn(GitHubApiClient.prototype, 'listIssues');
    await expect(
      createOrUpdateIssues(
        [],
        { ...config, dryRun: false, githubToken: 'test' },
        { inventoryComplete: false },
      ),
    ).resolves.toEqual({ created: 0, updated: 0, closed: 0, planned: 0 });
    expect(ensureLabel).not.toHaveBeenCalled();
    expect(listIssues).not.toHaveBeenCalled();
  });
});
