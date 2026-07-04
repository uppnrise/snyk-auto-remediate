import { describe, it, expect } from 'vitest';
import { buildMarkdownSummary } from '../../../src/reporting/summary-writer.js';
import type { RemediationReport } from '../../../src/snyk/types.js';

const sampleReport: RemediationReport = {
  timestamp: '2024-01-01T00:00:00.000Z',
  repository: 'owner/repo',
  targetBranch: 'main',
  severityThreshold: 'high',
  totalFindings: 5,
  fixableFindings: 3,
  fixedFindings: 2,
  unfixableFindings: 2,
  dryRun: false,
  fixResults: [
    {
      success: true,
      packageManager: 'npm',
      fixedFindings: [],
      failedFindings: [],
      changesApplied: ['Upgraded: lodash@4.17.21'],
    },
  ],
  issuesCreated: 2,
  prsCreated: 1,
  errors: [],
};

describe('buildMarkdownSummary', () => {
  it('should include repository in output', () => {
    const summary = buildMarkdownSummary(sampleReport);
    expect(summary).toContain('owner/repo');
  });

  it('should include total findings count', () => {
    const summary = buildMarkdownSummary(sampleReport);
    expect(summary).toContain('5');
  });

  it('should include fixed findings count', () => {
    const summary = buildMarkdownSummary(sampleReport);
    expect(summary).toContain('2');
  });

  it('should mention PRs created', () => {
    const summary = buildMarkdownSummary(sampleReport);
    expect(summary).toContain('1');
  });

  it('should include package manager results', () => {
    const summary = buildMarkdownSummary(sampleReport);
    expect(summary).toContain('npm');
  });

  it('should show dry run status when enabled', () => {
    const dryRunReport = { ...sampleReport, dryRun: true };
    const summary = buildMarkdownSummary(dryRunReport);
    expect(summary).toContain('Yes');
  });

  it('should include errors section when errors exist', () => {
    const reportWithErrors = { ...sampleReport, errors: ['Something went wrong'] };
    const summary = buildMarkdownSummary(reportWithErrors);
    expect(summary).toContain('Something went wrong');
  });
});
