import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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
    expect(config.maxPrsPerRun).toBe(5);
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

  it('should parse SEVERITY_THRESHOLD', () => {
    setRequiredEnv();
    process.env['SEVERITY_THRESHOLD'] = 'critical';
    const config = loadConfig();
    expect(config.severityThreshold).toBe('critical');
  });

  it('should default to high for invalid severity', () => {
    setRequiredEnv();
    process.env['SEVERITY_THRESHOLD'] = 'invalid';
    const config = loadConfig();
    expect(config.severityThreshold).toBe('high');
  });

  it('should throw if SNYK_TOKEN is missing', () => {
    setRequiredEnv();
    delete process.env['SNYK_TOKEN'];
    expect(() => loadConfig()).toThrow('SNYK_TOKEN');
  });

  it('should throw if SNYK_ORG_ID is missing', () => {
    setRequiredEnv();
    delete process.env['SNYK_ORG_ID'];
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
});
