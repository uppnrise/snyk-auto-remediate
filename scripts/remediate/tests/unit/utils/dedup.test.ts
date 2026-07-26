import { describe, it, expect } from 'vitest';
import { deduplicateIssues } from '../../../src/utils/dedup.js';
import type { SnykIssue } from '../../../src/snyk/types.js';

function makeIssue(id: string, fixable: boolean): SnykIssue {
  return {
    id,
    type: 'issue',
    attributes: {
      key: id,
      title: `Test Issue ${id}`,
      type: 'package_vulnerability',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
      severity: 'high',
      effective_severity_level: 'high',
      status: 'open',
      ignored: false,
      problems: [],
      coordinates: [
        {
          is_fixable_snyk: fixable,
          is_fixable_upstream: fixable,
          is_patchable: false,
          is_pinnable: false,
          remedies: fixable ? [{ type: 'upgrade', description: 'Upgrade to safe version' }] : [],
          representations: [{ dependency: { package_name: 'test-pkg', package_version: '1.0.0' } }],
        },
      ],
    },
  };
}

describe('deduplicateIssues', () => {
  it('should remove duplicate issues by ID', () => {
    const issues = [makeIssue('A', true), makeIssue('A', true), makeIssue('B', false)];
    const result = deduplicateIssues(issues);
    expect(result).toHaveLength(2);
    expect(result.map((i) => i.id)).toEqual(['A', 'B']);
  });

  it('should return empty array for empty input', () => {
    expect(deduplicateIssues([])).toEqual([]);
  });

  it('should preserve order', () => {
    const issues = [makeIssue('C', false), makeIssue('A', true), makeIssue('B', true)];
    const result = deduplicateIssues(issues);
    expect(result.map((i) => i.id)).toEqual(['C', 'A', 'B']);
  });
});
