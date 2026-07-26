import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../../../src/utils/config.js';

describe('loadConfig', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  function setRequiredEnv(): void {
    process.env['SNYK_TOKEN'] = 'test-snyk-token';
    process.env['SNYK_ORG_ID'] = 'test-org-id';
    process.env['GITHUB_REPOSITORY'] = 'owner/repo';
    process.env['GITHUB_TOKEN'] = 'test-github-token';
  }

  it('should load config from environment variables', () => {
    setRequiredEnv();
    const config = loadConfig();
    expect(config.snykToken).toBe('test-snyk-token');
    expect(config.snykOrgId).toBe('test-org-id');
    expect(config.githubRepository).toBe('owner/repo');
    expect(config.githubToken).toBe('test-github-token');
  });

  it('should apply defaults for optional vars', () => {
    setRequiredEnv();
    const config = loadConfig();
    expect(config.severityThreshold).toBe('high');
    expect(config.dryRun).toBe(false);
    expect(config.maxIssuesPerRun).toBe(10);
    expect(config.enableCopilotAgentFallback).toBe(true);
    expect(config.copilotAssignee).toBe('copilot');
    expect(config.failOnNoFix).toBe(false);
  });

  it('should parse DRY_RUN=true', () => {
    setRequiredEnv();
    process.env['DRY_RUN'] = 'true';
    const config = loadConfig();
    expect(config.dryRun).toBe(true);
  });

  it('should load a remediation branch suffix', () => {
    setRequiredEnv();
    process.env['REMEDIATION_BRANCH_SUFFIX'] = 'maven';
    const config = loadConfig();
    expect(config.remediationBranchSuffix).toBe('maven');
  });

  it('should parse SEVERITY_THRESHOLD', () => {
    setRequiredEnv();
    process.env['SEVERITY_THRESHOLD'] = 'critical';
    const config = loadConfig();
    expect(config.severityThreshold).toBe('critical');
  });

  it('should reject an invalid severity', () => {
    setRequiredEnv();
    process.env['SEVERITY_THRESHOLD'] = 'invalid';
    expect(() => loadConfig()).toThrow('SEVERITY_THRESHOLD');
  });

  it('should throw if SNYK_TOKEN is missing', () => {
    setRequiredEnv();
    delete process.env['SNYK_TOKEN'];
    expect(() => loadConfig()).toThrow('SNYK_TOKEN');
  });

  it('should require SNYK_ORG_ID only for scoped REST inventory', () => {
    setRequiredEnv();
    delete process.env['SNYK_ORG_ID'];
    expect(loadConfig().snykOrgId).toBe('local-cli');
    process.env['SNYK_PROJECT_IDS'] = 'project';
    expect(() => loadConfig()).toThrow('SNYK_ORG_ID');
  });

  it('should parse PR_LABELS as comma-separated list', () => {
    setRequiredEnv();
    process.env['PR_LABELS'] = 'security,deps,snyk';
    const config = loadConfig();
    expect(config.prLabels).toEqual(['security', 'deps', 'snyk']);
  });

  it('should parse SNYK_PROJECT_IDS as comma-separated list', () => {
    setRequiredEnv();
    process.env['SNYK_PROJECT_IDS'] = 'proj-1,proj-2';
    const config = loadConfig();
    expect(config.snykProjectIds).toEqual(['proj-1', 'proj-2']);
  });

  it('rejects unknown package managers instead of silently doing nothing', () => {
    setRequiredEnv();
    process.env['PACKAGE_MANAGERS'] = 'npm,not-a-manager';
    expect(() => loadConfig()).toThrow(/PACKAGE_MANAGERS.*not-a-manager/);
  });

  it.each([
    ['DRY_RUN', 'sometimes'],
    ['RUN_TESTS', 'yes'],
    ['ENABLE_COPILOT_AGENT_FALLBACK', 'enabled'],
  ])('rejects invalid boolean value for %s', (name, value) => {
    setRequiredEnv();
    process.env[name] = value;
    expect(() => loadConfig()).toThrow(name);
  });

  it('rejects negative issue limits', () => {
    setRequiredEnv();
    process.env['MAX_ISSUES_PER_RUN'] = '-1';
    expect(() => loadConfig()).toThrow('MAX_ISSUES_PER_RUN');
  });

  it('does not require a GitHub token for a dry run', () => {
    setRequiredEnv();
    process.env['DRY_RUN'] = 'true';
    delete process.env['GITHUB_TOKEN'];
    expect(loadConfig().githubToken).toBeUndefined();
  });
});
