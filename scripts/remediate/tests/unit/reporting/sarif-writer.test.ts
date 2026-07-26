import { describe, it, expect } from 'vitest';
import { buildSarifOutput, selectReportableIssues } from '../../../src/reporting/sarif-writer.js';
import type { SnykIssue } from '../../../src/snyk/types.js';

const sampleIssue: SnykIssue = {
  id: 'SNYK-JS-TEST-001',
  type: 'issue',
  attributes: {
    key: 'SNYK-JS-TEST-001',
    title: 'Test Vulnerability',
    type: 'package_vulnerability',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    description: 'A test vulnerability for unit testing',
    severity: 'high',
    effective_severity_level: 'high',
    status: 'open',
    ignored: false,
    problems: [
      {
        id: 'CVE-2024-0001',
        source: 'NVD',
        url: 'https://security.snyk.io/vuln/SNYK-JS-TEST-001',
        cve: 'CVE-2024-0001',
        cvss_score: 7.5,
      },
    ],
    coordinates: [
      {
        is_fixable_snyk: true,
        representations: [
          {
            dependency: { package_name: 'test-pkg', package_version: '1.0.0' },
          },
        ],
      },
    ],
  },
  relationships: {
    organization: { data: { id: 'org', type: 'organization' } },
    scan_item: { data: { id: 'project', type: 'project' } },
  },
};

describe('buildSarifOutput', () => {
  it('should produce valid SARIF 2.1.0 structure', () => {
    const sarif = buildSarifOutput([sampleIssue], 'owner/repo');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema');
    expect(sarif.runs).toHaveLength(1);
  });

  it('should include tool information', () => {
    const sarif = buildSarifOutput([sampleIssue], 'owner/repo');
    const driver = sarif.runs[0]!.tool.driver;
    expect(driver.name).toBe('Snyk Auto-Remediation');
    expect(driver.version).toBeDefined();
  });

  it('should create rules from issues', () => {
    const sarif = buildSarifOutput([sampleIssue], 'owner/repo');
    const rules = sarif.runs[0]!.tool.driver.rules;
    expect(rules).toHaveLength(1);
    expect(rules[0]!.id).toBe('SNYK-JS-TEST-001');
  });

  it('should create results from issues', () => {
    const sarif = buildSarifOutput([sampleIssue], 'owner/repo');
    const results = sarif.runs[0]!.results;
    expect(results).toHaveLength(1);
    expect(results[0]!.ruleId).toBe('SNYK-JS-TEST-001');
    expect(results[0]!.level).toBe('error'); // high severity = error
  });

  it('should deduplicate rules for same issue ID', () => {
    const sarif = buildSarifOutput([sampleIssue, sampleIssue], 'owner/repo');
    const rules = sarif.runs[0]!.tool.driver.rules;
    expect(rules).toHaveLength(1); // deduped
    expect(sarif.runs[0]!.results).toHaveLength(2); // results not deduped
  });

  it('should handle empty issues array', () => {
    const sarif = buildSarifOutput([], 'owner/repo');
    expect(sarif.runs[0]!.results).toHaveLength(0);
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(0);
  });

  it('should map severity to SARIF levels correctly', () => {
    const criticalIssue: SnykIssue = {
      ...sampleIssue,
      id: 'CRITICAL-001',
      attributes: { ...sampleIssue.attributes, effective_severity_level: 'critical' },
    };
    const mediumIssue: SnykIssue = {
      ...sampleIssue,
      id: 'MEDIUM-001',
      attributes: { ...sampleIssue.attributes, effective_severity_level: 'medium' },
    };
    const lowIssue: SnykIssue = {
      ...sampleIssue,
      id: 'LOW-001',
      attributes: { ...sampleIssue.attributes, effective_severity_level: 'low' },
    };

    const sarif = buildSarifOutput([criticalIssue, mediumIssue, lowIssue], 'owner/repo');
    const results = sarif.runs[0]!.results;
    expect(results[0]!.level).toBe('error'); // critical
    expect(results[1]!.level).toBe('warning'); // medium
    expect(results[2]!.level).toBe('note'); // low
  });

  it('excludes findings verified as fixed from the uploaded report', () => {
    expect(selectReportableIssues([sampleIssue], [sampleIssue.id])).toEqual([]);
  });

  it('restricts report findings to explicitly scoped project IDs', () => {
    expect(selectReportableIssues([sampleIssue], [], ['another-project'])).toEqual([]);
    expect(
      selectReportableIssues([sampleIssue], [], [sampleIssue.relationships.scan_item.data.id]),
    ).toEqual([sampleIssue]);
  });
});
