import { describe, expect, it } from 'vitest';
import { buildManagedIssueLabels } from '../../../src/github/issue-creator.js';

describe('fallback issue management labels', () => {
  it('always applies the explicit management label without duplicating it', () => {
    expect(buildManagedIssueLabels(['security', 'automation'], 'managed-by-snyk')).toEqual([
      'security',
      'automation',
      'managed-by-snyk',
    ]);
    expect(buildManagedIssueLabels(['security', 'snyk'], 'snyk')).toEqual(['security', 'snyk']);
  });
});
