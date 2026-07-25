import { describe, expect, it } from 'vitest';
import { buildRemediationPlan, normalizeCliOutput } from '../../../src/snyk/correlation.js';
import type { DetectedEcosystem, SnykIssue } from '../../../src/snyk/types.js';

const issue: SnykIssue = {
  id: '73832c6c-19ff-4a92-850c-2e1ff2800c16',
  type: 'issue',
  attributes: {
    key: 'SNYK-JS-LODASH-590103',
    title: 'Prototype Pollution',
    type: 'package_vulnerability',
    effective_severity_level: 'high',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    status: 'open',
    ignored: false,
  },
  relationships: {
    organization: { data: { id: 'org', type: 'organization' } },
    scan_item: { data: { id: 'project', type: 'project' } },
  },
};
const ecosystem: DetectedEcosystem = {
  packageManager: 'npm',
  manifestFiles: ['package.json'],
  workingDirectory: '.',
};

describe('CLI correlation', () => {
  it('normalizes single and multi-project CLI JSON', () => {
    const result = {
      vulnerabilities: [
        {
          id: issue.attributes.key,
          packageName: 'lodash',
          version: '4.17.15',
          fixedIn: ['4.17.21'],
          upgradePath: ['root@1.0.0', 'lodash@4.17.21'],
          isUpgradable: true,
        },
      ],
      packageManager: 'npm',
      projectName: 'project',
    };
    expect(normalizeCliOutput(result, ecosystem)).toHaveLength(1);
    expect(normalizeCliOutput([result, result], ecosystem)).toHaveLength(2);
  });

  it('uses the Snyk key and an exact CLI upgrade path to build an action', () => {
    const cli = normalizeCliOutput(
      {
        vulnerabilities: [
          {
            id: 'SNYK-JS-LODASH-590103',
            packageName: 'lodash',
            version: '4.17.15',
            fixedIn: ['4.17.21'],
            upgradePath: ['root-dependency@2.0.0', 'lodash@4.17.21'],
            isUpgradable: true,
          },
        ],
        packageManager: 'npm',
        projectName: 'project',
      },
      ecosystem,
    );

    const plan = buildRemediationPlan([issue], cli);

    expect(plan.actions).toEqual([
      expect.objectContaining({
        packageManager: 'npm',
        packageName: 'root-dependency',
        targetVersion: '2.0.0',
        findingIds: [issue.id],
        findingKeys: [issue.attributes.key],
      }),
    ]);
  });

  it('does not guess when the upgrade path has no exact target', () => {
    const cli = normalizeCliOutput(
      {
        vulnerabilities: [
          {
            id: issue.attributes.key,
            packageName: 'lodash',
            version: '4.17.15',
            fixedIn: [],
            upgradePath: [],
            isUpgradable: true,
          },
        ],
        packageManager: 'npm',
      },
      ecosystem,
    );

    const plan = buildRemediationPlan([issue], cli);
    expect(plan.actions).toHaveLength(0);
    expect(plan.nonActionable[0]?.reason).toBe('missing_exact_target');
  });
});
