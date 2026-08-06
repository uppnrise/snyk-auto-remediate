import { describe, expect, it } from 'vitest';
import {
  buildManagedIssueLabels,
  buildIssueReconciliation,
  createOrUpdateIssues,
} from '../../../src/github/issue-creator.js';
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
} as RemediationConfig;

describe('fallback issue lifecycle', () => {
  it('reports planned work without claiming issues were created during dry-run', async () => {
    await expect(createOrUpdateIssues([issue], config)).resolves.toEqual({
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
        body: '<!-- snyk-finding-id: old-finding -->',
        state: 'open',
      },
      {
        number: 43,
        body: '<!-- snyk-finding-id: finding-id -->',
        state: 'open',
      },
    ];

    expect(buildIssueReconciliation([issue], existing).toClose).toEqual([42]);
  });

  it('always applies the explicit management label without duplicating it', () => {
    expect(buildManagedIssueLabels(['security', 'automation'], 'managed-by-snyk')).toEqual([
      'security',
      'automation',
      'managed-by-snyk',
    ]);
    expect(buildManagedIssueLabels(['security', 'snyk'], 'snyk')).toEqual(['security', 'snyk']);
  });
});
