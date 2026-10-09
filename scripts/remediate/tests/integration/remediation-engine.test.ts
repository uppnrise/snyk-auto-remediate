import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runRemediation } from '../../src/engine.js';
import { GitHubApiClient } from '../../src/github/api-client.js';
import { buildIssueBody } from '../../src/github/issue-creator.js';
import { buildCliInventory } from '../../src/snyk/cli-inventory.js';
import { scanWithSnykCli } from '../../src/snyk/cli-runner.js';
import * as git from '../../src/utils/git.js';
import { ExactActionFixer } from '../../src/fixers/exact-action-fixer.js';
import { runPostFixTests } from '../../src/utils/test-runner.js';
import * as snykApi from '../../src/snyk/api-client.js';
import type {
  CliVulnerability,
  RemediationConfig,
  RemediationReport,
} from '../../src/snyk/types.js';

vi.mock('../../src/snyk/cli-runner.js', () => ({ scanWithSnykCli: vi.fn() }));
vi.mock('../../src/utils/dependency-preparer.js', () => ({ prepareForSnykScan: vi.fn() }));
vi.mock('../../src/utils/test-runner.js', () => ({ runPostFixTests: vi.fn() }));

const finding: CliVulnerability = {
  issueKey: 'SNYK-JS-EXAMPLE-1',
  title: 'Example vulnerability',
  severity: 'high',
  packageName: 'example',
  version: '1.0.0',
  packageManager: 'npm',
  projectName: 'api',
  fixedIn: [],
  upgradePath: [],
  dependencyPath: ['api@1.0.0', 'example@1.0.0'],
  isUpgradable: false,
  isPatchable: false,
};

describe('remediation orchestration with external services mocked', () => {
  let directory: string;
  let config: RemediationConfig;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'snyk-engine-'));
    writeFileSync(
      join(directory, 'package.json'),
      JSON.stringify({ name: 'api', version: '1.0.0' }),
    );
    config = {
      snykToken: 'test',
      snykOrgId: 'local-cli',
      githubRepository: 'owner/repo',
      githubToken: 'test',
      severityThreshold: 'high',
      dryRun: false,
      maxIssuesPerRun: 10,
      workingDirectory: directory,
      enableCopilotAgentFallback: true,
      copilotAssignee: 'copilot',
      failOnNoFix: false,
      runTests: true,
      prLabels: ['security'],
      issueLabels: ['security'],
      issueManagementLabel: 'snyk',
      targetBranch: 'main',
      remediationBranchSuffix: 'api',
    };
    vi.mocked(scanWithSnykCli).mockReset().mockResolvedValue([]);
    vi.mocked(runPostFixTests).mockReset().mockResolvedValue({ ran: true, passed: true });
    vi.spyOn(git, 'gitProjectDirectory').mockResolvedValue('packages/api');
    vi.spyOn(git, 'gitConfigureUser').mockResolvedValue();
    vi.spyOn(git, 'gitCheckoutBranch').mockResolvedValue();
    vi.spyOn(git, 'gitHasChanges').mockResolvedValue(true);
    vi.spyOn(git, 'gitAddAll').mockResolvedValue();
    vi.spyOn(git, 'gitCommit').mockResolvedValue();
    vi.spyOn(git, 'gitPush').mockResolvedValue();
    vi.spyOn(GitHubApiClient.prototype, 'ensureLabel').mockResolvedValue();
    vi.spyOn(GitHubApiClient.prototype, 'listIssues').mockResolvedValue([]);
    vi.spyOn(GitHubApiClient.prototype, 'updateIssue').mockResolvedValue({ number: 42 } as never);
    vi.spyOn(GitHubApiClient.prototype, 'createIssue').mockResolvedValue({ number: 43 } as never);
    vi.spyOn(GitHubApiClient.prototype, 'listPulls').mockResolvedValue([]);
    vi.spyOn(GitHubApiClient.prototype, 'createPull').mockResolvedValue({
      number: 44,
      html_url: 'https://example.test/pr/44',
    } as never);
    vi.spyOn(GitHubApiClient.prototype, 'addLabels').mockResolvedValue();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(directory, { recursive: true, force: true });
  });

  function existingIssue(otherConfig = config): void {
    const issue = buildCliInventory([finding], 'local-cli', 'high')[0]!;
    vi.mocked(GitHubApiClient.prototype.listIssues).mockResolvedValue([
      {
        number: 42,
        state: 'open',
        body: buildIssueBody(issue, { ...otherConfig, workingDirectory: 'packages/api' }),
      } as never,
    ]);
  }

  function report(): RemediationReport {
    return JSON.parse(
      readFileSync(join(directory, 'snyk-remediation-report.json'), 'utf8'),
    ) as RemediationReport;
  }

  it('preserves open issues when the initial scan fails and reports failure', async () => {
    existingIssue();
    vi.mocked(scanWithSnykCli).mockRejectedValue(new Error('authentication failed'));
    expect(await runRemediation(config)).toBe(1);
    expect(GitHubApiClient.prototype.listIssues).not.toHaveBeenCalled();
    expect(GitHubApiClient.prototype.updateIssue).not.toHaveBeenCalled();
    expect(report().errors.join(' ')).toContain('authentication failed');
  });

  it('preserves all issues when one ecosystem in a mixed project fails', async () => {
    writeFileSync(join(directory, 'requirements.txt'), 'example==1.0.0');
    vi.mocked(scanWithSnykCli).mockImplementation((ecosystem) => {
      if (ecosystem.packageManager === 'pip') return Promise.reject(new Error('pip scan failed'));
      return Promise.resolve([finding]);
    });
    expect(await runRemediation(config)).toBe(1);
    expect(GitHubApiClient.prototype.updateIssue).not.toHaveBeenCalled();
    expect(GitHubApiClient.prototype.createIssue).not.toHaveBeenCalled();
    expect(report().totalFindings).toBe(1);
  });

  it('treats an unsupported project as incomplete inventory', async () => {
    config.packageManagers = ['maven'];
    existingIssue();
    expect(await runRemediation(config)).toBe(1);
    expect(GitHubApiClient.prototype.listIssues).not.toHaveBeenCalled();
    expect(report().errors.join(' ')).toContain('No supported ecosystems');
  });

  it('closes a resolved issue after a successful complete scan', async () => {
    existingIssue();
    expect(await runRemediation(config)).toBe(0);
    expect(GitHubApiClient.prototype.updateIssue).toHaveBeenCalledWith(42, { state: 'closed' });
    expect(report().issuesClosed).toBe(1);
  });

  it('updates an active issue within the same project scope', async () => {
    existingIssue();
    vi.mocked(scanWithSnykCli).mockResolvedValue([finding]);
    expect(await runRemediation(config)).toBe(0);
    expect(report().issuesUpdated).toBe(1);
    expect(report().issuesClosed).toBe(0);
    expect(GitHubApiClient.prototype.createIssue).not.toHaveBeenCalled();
  });

  it('does not close another branch or report scope', async () => {
    existingIssue({ ...config, targetBranch: 'release/1', remediationBranchSuffix: 'another' });
    expect(await runRemediation(config)).toBe(0);
    expect(GitHubApiClient.prototype.updateIssue).not.toHaveBeenCalled();
  });

  it('writes planned fallback work without GitHub or git mutations in dry-run', async () => {
    config.dryRun = true;
    vi.mocked(scanWithSnykCli).mockResolvedValue([finding]);
    expect(await runRemediation(config)).toBe(0);
    expect(report().issuesPlanned).toBe(1);
    expect(GitHubApiClient.prototype.ensureLabel).not.toHaveBeenCalled();
    expect(GitHubApiClient.prototype.createIssue).not.toHaveBeenCalled();
    expect(git.gitPush).not.toHaveBeenCalled();
  });

  function mockFix(): void {
    vi.mocked(scanWithSnykCli)
      .mockResolvedValueOnce([{ ...finding, isUpgradable: true, upgradePath: ['example@2.0.0'] }])
      .mockResolvedValue([]);
    vi.spyOn(ExactActionFixer.prototype, 'applyFix').mockImplementation((_cwd, actions, findings) =>
      Promise.resolve({
        success: true,
        packageManager: 'npm',
        fixedFindings: [...findings.values()],
        failedFindings: [],
        changesApplied: ['example: 1.0.0 -> 2.0.0'],
        attemptedActions: actions,
      }),
    );
  }

  it('re-scans an exact fix, runs tests, pushes and creates a PR', async () => {
    mockFix();
    expect(await runRemediation(config)).toBe(0);
    expect(scanWithSnykCli).toHaveBeenCalledTimes(2);
    expect(runPostFixTests).toHaveBeenCalled();
    expect(git.gitPush).toHaveBeenCalled();
    expect(GitHubApiClient.prototype.createPull).toHaveBeenCalled();
    expect(report().verifiedFixedFindings).toBe(1);
    expect(report().prsCreated).toBe(1);
  });

  it('preserves issues and blocks PR publication when post-fix tests fail', async () => {
    existingIssue();
    mockFix();
    vi.mocked(runPostFixTests).mockResolvedValue({ ran: true, passed: false, error: 'regression' });
    expect(await runRemediation(config)).toBe(1);
    expect(git.gitPush).not.toHaveBeenCalled();
    expect(GitHubApiClient.prototype.updateIssue).not.toHaveBeenCalled();
    expect(GitHubApiClient.prototype.createPull).not.toHaveBeenCalled();
  });

  it('preserves issues when pushing a verified fix fails', async () => {
    existingIssue();
    mockFix();
    vi.mocked(git.gitPush).mockRejectedValue(new Error('permission denied'));
    expect(await runRemediation(config)).toBe(1);
    expect(GitHubApiClient.prototype.updateIssue).not.toHaveBeenCalled();
    expect(report().errors.join(' ')).toContain('permission denied');
  });

  it('rolls back an unverified batch and keeps the finding as fallback work', async () => {
    mockFix();
    vi.mocked(scanWithSnykCli)
      .mockReset()
      .mockResolvedValue([{ ...finding, isUpgradable: true, upgradePath: ['example@2.0.0'] }]);
    const rollback = vi.spyOn(ExactActionFixer.prototype, 'rollback');
    expect(await runRemediation(config)).toBe(0);
    expect(rollback).toHaveBeenCalled();
    expect(git.gitPush).not.toHaveBeenCalled();
    expect(report().verifiedFixedFindings).toBe(0);
    expect(report().issuesCreated).toBe(1);
  });

  it('uses explicitly scoped REST inventory without claiming CLI verification', async () => {
    config.snykOrgId = 'org';
    config.snykProjectIds = ['api'];
    const inventory = buildCliInventory([finding], 'org', 'high');
    vi.spyOn(snykApi, 'fetchSnykIssues').mockResolvedValue(inventory);
    expect(await runRemediation(config)).toBe(0);
    expect(scanWithSnykCli).not.toHaveBeenCalled();
    expect(report().totalFindings).toBe(1);
    expect(report().verifiedFixedFindings).toBe(0);
    expect(report().issuesCreated).toBe(1);
  });

  it('preserves issues when REST access is forbidden and the local fallback scan fails', async () => {
    config.snykOrgId = 'org';
    config.snykProjectIds = ['api'];
    vi.spyOn(snykApi, 'fetchSnykIssues').mockRejectedValue(
      new snykApi.SnykApiError(403, 'forbidden'),
    );
    vi.mocked(scanWithSnykCli).mockRejectedValue(new Error('local scan failed'));
    expect(await runRemediation(config)).toBe(1);
    expect(GitHubApiClient.prototype.listIssues).not.toHaveBeenCalled();
    expect(report().errors.join(' ')).toContain('local scan failed');
  });
});
