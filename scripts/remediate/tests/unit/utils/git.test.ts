import { describe, it, expect } from 'vitest';
import { buildRemediationBranchName } from '../../../src/utils/git.js';

describe('buildRemediationBranchName', () => {
  it('should produce a branch name with expected prefix', () => {
    const name = buildRemediationBranchName('main');
    expect(name).toBe('chore/security/snyk-remediation-main');
  });

  it('should sanitize special characters in target branch', () => {
    const name = buildRemediationBranchName('release/v1.0');
    expect(name).not.toContain('/v1.0');
    expect(name).toBe('chore/security/snyk-remediation-release-v1-0');
  });

  it('should remain stable across scheduled runs', () => {
    expect(buildRemediationBranchName('main')).toBe(buildRemediationBranchName('main'));
  });

  it('should isolate remediation branches by job identifier', () => {
    const maven = buildRemediationBranchName('main', 'maven');
    const dashboard = buildRemediationBranchName('main', 'dashboard');

    expect(maven).toBe('chore/security/snyk-remediation-main-maven');
    expect(dashboard).toBe('chore/security/snyk-remediation-main-dashboard');
    expect(maven).not.toBe(dashboard);
  });
});
