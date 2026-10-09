import { describe, it, expect } from 'vitest';
import { buildRemediationBranchName } from '../../../src/utils/git.js';

describe('buildRemediationBranchName', () => {
  it('should produce a branch name with expected prefix', () => {
    const name = buildRemediationBranchName('main');
    expect(name).toMatch(/^chore\/security\/snyk-remediation-main-[a-f0-9]{16}$/);
  });

  it('should sanitize special characters in target branch', () => {
    const name = buildRemediationBranchName('release/v1.0');
    expect(name).not.toContain('/v1.0');
    expect(name).toMatch(/^chore\/security\/snyk-remediation-release-v1-0-[a-f0-9]{16}$/);
  });

  it('should remain stable across scheduled runs', () => {
    expect(buildRemediationBranchName('main')).toBe(buildRemediationBranchName('main'));
  });

  it('should isolate remediation branches by job identifier', () => {
    const maven = buildRemediationBranchName('main', 'maven');
    const dashboard = buildRemediationBranchName('main', 'dashboard');

    expect(maven).toMatch(/^chore\/security\/snyk-remediation-main-maven-[a-f0-9]{16}$/);
    expect(dashboard).toMatch(/^chore\/security\/snyk-remediation-main-dashboard-[a-f0-9]{16}$/);
    expect(maven).not.toBe(dashboard);
  });

  it('keeps report IDs distinct when their readable slugs collide', () => {
    expect(buildRemediationBranchName('main', 'api.v1')).not.toBe(
      buildRemediationBranchName('main', 'api-v1'),
    );
  });

  it('keeps target branches distinct when punctuation is normalized', () => {
    expect(buildRemediationBranchName('release/1.0', 'api')).not.toBe(
      buildRemediationBranchName('release-1-0', 'api'),
    );
  });
});
