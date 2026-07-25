import { describe, expect, it } from 'vitest';
import {
  buildRemediationPlan,
  normalizeCliOutput,
  unresolvedFindingKeys,
} from '../../../src/snyk/correlation.js';
import type {
  CliVulnerability,
  DetectedEcosystem,
  RemediationAction,
  SnykIssue,
} from '../../../src/snyk/types.js';

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

  it.each(['1.2', '1.2.3.4', '2024.1', '1.2.3.post1'])(
    'accepts the exact ecosystem version %s',
    (targetVersion) => {
      const cli = normalizeCliOutput(
        {
          vulnerabilities: [
            {
              id: issue.attributes.key,
              packageName: 'example',
              version: '1.0',
              upgradePath: [`example@${targetVersion}`],
              isUpgradable: true,
            },
          ],
          packageManager: 'npm',
        },
        ecosystem,
      );

      expect(buildRemediationPlan([issue], cli).actions[0]?.targetVersion).toBe(targetVersion);
    },
  );

  it.each(['latest', '^1.2.3', '>=1.2', '1.x', '*'])(
    'rejects the non-exact ecosystem version %s',
    (targetVersion) => {
      const cli = normalizeCliOutput(
        {
          vulnerabilities: [
            {
              id: issue.attributes.key,
              packageName: 'example',
              version: '1.0',
              upgradePath: [`example@${targetVersion}`],
              isUpgradable: true,
            },
          ],
          packageManager: 'npm',
        },
        ecosystem,
      );

      expect(buildRemediationPlan([issue], cli).actions).toHaveLength(0);
    },
  );

  it('scopes verification by project ID and falls back to key-only without CLI project IDs', () => {
    const action: RemediationAction = {
      packageManager: 'npm',
      packageName: 'example',
      currentVersion: '1.0.0',
      targetVersion: '2.0.0',
      findingIds: [issue.id],
      findingKeys: [issue.attributes.key],
      projectId: 'project-a',
      evidence: 'snyk-cli-upgrade-path',
    };
    const remaining: CliVulnerability = {
      issueKey: issue.attributes.key,
      packageName: 'example',
      version: '1.0.0',
      packageManager: 'npm',
      projectId: 'project-b',
      fixedIn: [],
      upgradePath: [],
      dependencyPath: [],
      isUpgradable: true,
      isPatchable: false,
    };

    expect(unresolvedFindingKeys([action], [remaining])).toEqual([]);
    expect(unresolvedFindingKeys([action], [{ ...remaining, projectId: 'project-a' }])).toEqual([
      issue.attributes.key,
    ]);
    const withoutProject = { ...remaining };
    delete withoutProject.projectId;
    expect(unresolvedFindingKeys([action], [withoutProject])).toEqual([issue.attributes.key]);
    expect(unresolvedFindingKeys([action], [remaining, withoutProject])).toEqual([
      issue.attributes.key,
    ]);
  });
});
