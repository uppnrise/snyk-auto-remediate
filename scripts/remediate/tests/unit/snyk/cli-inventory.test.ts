import { describe, expect, it } from 'vitest';
import {
  buildCliInventory,
  loadIssueInventory,
  shouldCollectCliFindings,
} from '../../../src/snyk/cli-inventory.js';
import { SnykApiError } from '../../../src/snyk/api-client.js';
import { buildRemediationPlan } from '../../../src/snyk/correlation.js';
import type { CliVulnerability, RemediationConfig, SnykIssue } from '../../../src/snyk/types.js';

const upgradable: CliVulnerability = {
  issueKey: 'SNYK-JS-LODASH-590103',
  title: 'Prototype Pollution',
  severity: 'high',
  packageName: 'lodash',
  version: '4.17.15',
  packageManager: 'npm',
  projectName: 'local-project',
  fixedIn: ['4.17.21'],
  upgradePath: ['lodash@4.17.21'],
  dependencyPath: ['lodash@4.17.15'],
  isUpgradable: true,
  isPatchable: false,
};

describe('CLI-only issue inventory', () => {
  it('skips local CLI collection when REST projects explicitly scope the inventory', () => {
    expect(shouldCollectCliFindings({ snykProjectIds: ['project-id'] })).toBe(false);
    expect(shouldCollectCliFindings({})).toBe(true);
  });

  it('creates stable REST-shaped findings that retain exact CLI remediation evidence', () => {
    const first = buildCliInventory([upgradable], 'org-id', 'high');
    const second = buildCliInventory([upgradable], 'org-id', 'high');

    expect(first).toHaveLength(1);
    expect(first[0]?.id).toBe(second[0]?.id);
    expect(first[0]).toMatchObject({
      attributes: {
        key: upgradable.issueKey,
        title: upgradable.title,
        effective_severity_level: 'high',
      },
      relationships: {
        organization: { data: { id: 'org-id', type: 'organization' } },
      },
    });
    expect(buildRemediationPlan(first, [upgradable]).actions).toEqual([
      expect.objectContaining({
        packageName: 'lodash',
        targetVersion: '4.17.21',
        evidence: 'snyk-cli-upgrade-path',
      }),
    ]);
  });

  it('filters below-threshold findings and deduplicates identical CLI occurrences', () => {
    expect(
      buildCliInventory(
        [upgradable, upgradable, { ...upgradable, issueKey: 'LOW', severity: 'low' }],
        'org-id',
        'high',
      ),
    ).toHaveLength(1);
  });

  it('uses local CLI inventory when no REST project scope is configured', async () => {
    const config = {
      snykOrgId: 'org-id',
      severityThreshold: 'high',
    } as RemediationConfig;
    const restFetcher = (): Promise<SnykIssue[]> =>
      Promise.reject(new Error('REST must not be called without an explicit project scope'));

    await expect(loadIssueInventory(config, [upgradable], restFetcher)).resolves.toHaveLength(1);
  });

  it('falls back on REST 403 but keeps other scoped REST failures fatal', async () => {
    const config = {
      snykOrgId: 'org-id',
      snykProjectIds: ['project-id'],
      severityThreshold: 'high',
    } as RemediationConfig;
    const forbidden = (): Promise<SnykIssue[]> =>
      Promise.reject(new SnykApiError(403, 'Forbidden'));
    const unauthorized = (): Promise<SnykIssue[]> =>
      Promise.reject(new SnykApiError(401, 'Unauthorized'));

    await expect(loadIssueInventory(config, [upgradable], forbidden)).resolves.toHaveLength(1);
    await expect(loadIssueInventory(config, [upgradable], unauthorized)).rejects.toMatchObject({
      status: 401,
    });
  });

  it('collects CLI findings lazily when a scoped REST request is forbidden', async () => {
    const config = {
      snykOrgId: 'org-id',
      snykProjectIds: ['project-id'],
      severityThreshold: 'high',
    } as RemediationConfig;
    const forbidden = (): Promise<SnykIssue[]> =>
      Promise.reject(new SnykApiError(403, 'Forbidden'));
    let fallbackCalls = 0;

    const inventory = await loadIssueInventory(config, [], forbidden, () => {
      fallbackCalls++;
      return Promise.resolve([upgradable]);
    });

    expect(fallbackCalls).toBe(1);
    expect(inventory).toHaveLength(1);
  });
});
