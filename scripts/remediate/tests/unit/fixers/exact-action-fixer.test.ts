import { describe, expect, it } from 'vitest';
import { ExactActionFixer } from '../../../src/fixers/exact-action-fixer.js';
import type { RemediationAction, SnykIssue } from '../../../src/snyk/types.js';

const issue: SnykIssue = {
  id: 'rest-id',
  type: 'issue',
  attributes: {
    key: 'SNYK-TEST-1',
    title: 'test',
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
};
const fixers = [
  new ExactActionFixer('npm'),
  new ExactActionFixer('yarn'),
  new ExactActionFixer('pnpm'),
  new ExactActionFixer('pip'),
  new ExactActionFixer('poetry'),
  new ExactActionFixer('maven'),
  new ExactActionFixer('gradle'),
  new ExactActionFixer('go'),
  new ExactActionFixer('composer'),
];

describe('exact action fixers', () => {
  it.each(fixers.map((fixer) => [fixer.packageManager, fixer] as const))(
    '%s accepts only a normalized exact action in dry-run',
    async (packageManager, fixer) => {
      const action: RemediationAction = {
        packageManager,
        packageName: 'example/package',
        currentVersion: '1.0.0',
        targetVersion: '1.2.3',
        findingIds: [issue.id],
        findingKeys: [issue.attributes.key],
        evidence: 'snyk-cli-upgrade-path',
      };
      const result = await fixer.applyFix(
        '/does/not/matter',
        [action],
        new Map([[issue.id, issue]]),
        true,
      );
      expect(result.success).toBe(true);
      expect(result.fixedFindings).toEqual([issue]);
      expect(result.changesApplied[0]).toContain('1.2.3');
    },
  );

  it('ignores actions belonging to another package manager', async () => {
    const action: RemediationAction = {
      packageManager: 'yarn',
      packageName: 'lodash',
      currentVersion: '1.0.0',
      targetVersion: '1.2.3',
      findingIds: [issue.id],
      findingKeys: [issue.attributes.key],
      evidence: 'snyk-cli-upgrade-path',
    };
    const result = await new ExactActionFixer('npm').applyFix(
      '.',
      [action],
      new Map([[issue.id, issue]]),
      true,
    );
    expect(result.attemptedActions).toEqual([]);
  });

  it('treats an irrelevant non-dry-run action list as a successful no-op', async () => {
    const action: RemediationAction = {
      packageManager: 'yarn',
      packageName: 'lodash',
      currentVersion: '1.0.0',
      targetVersion: '1.2.3',
      findingIds: [issue.id],
      findingKeys: [issue.attributes.key],
      evidence: 'snyk-cli-upgrade-path',
    };

    const result = await new ExactActionFixer('npm').applyFix(
      '/path/that/does/not/exist',
      [action],
      new Map([[issue.id, issue]]),
      false,
    );

    expect(result.success).toBe(true);
    expect(result.attemptedActions).toEqual([]);
    expect(result.changesApplied).toEqual([]);
  });
});
