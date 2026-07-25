import { describe, it, expect } from 'vitest';
import { deduplicateIssues, partitionByFixability } from '../../../src/utils/dedup.js';
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

describe('partitionByFixability', () => {
  it('should correctly partition fixable and unfixable issues', () => {
    const issues = [
      makeIssue('fix-1', true),
      makeIssue('nofix-1', false),
      makeIssue('fix-2', true),
    ];
    const { fixable, unfixable } = partitionByFixability(issues);
    expect(fixable).toHaveLength(2);
    expect(unfixable).toHaveLength(1);
    expect(fixable.map((i) => i.id)).toEqual(['fix-1', 'fix-2']);
    expect(unfixable.map((i) => i.id)).toEqual(['nofix-1']);
  });

  it('should return all as unfixable when none are fixable', () => {
    const issues = [makeIssue('a', false), makeIssue('b', false)];
    const { fixable, unfixable } = partitionByFixability(issues);
    expect(fixable).toHaveLength(0);
    expect(unfixable).toHaveLength(2);
  });

  it('should handle empty input', () => {
    const { fixable, unfixable } = partitionByFixability([]);
    expect(fixable).toHaveLength(0);
    expect(unfixable).toHaveLength(0);
  });
});
