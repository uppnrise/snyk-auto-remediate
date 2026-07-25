import { describe, expect, it } from 'vitest';
import { NpmFixer } from '../../../src/fixers/npm-fixer.js';
import { YarnFixer } from '../../../src/fixers/yarn-fixer.js';
import { PipFixer } from '../../../src/fixers/pip-fixer.js';
import { PoetryFixer } from '../../../src/fixers/poetry-fixer.js';
import { MavenFixer } from '../../../src/fixers/maven-fixer.js';
import { GradleFixer } from '../../../src/fixers/gradle-fixer.js';
import { GoFixer } from '../../../src/fixers/go-fixer.js';
import { ComposerFixer } from '../../../src/fixers/composer-fixer.js';
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
  new NpmFixer(),
  new YarnFixer(),
  new PipFixer(),
  new PoetryFixer(),
  new MavenFixer(),
  new GradleFixer(),
  new GoFixer(),
  new ComposerFixer(),
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
    const result = await new NpmFixer().applyFix('.', [action], new Map([[issue.id, issue]]), true);
    expect(result.attemptedActions).toEqual([]);
  });
});
