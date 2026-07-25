import { describe, it, expect } from 'vitest';
import { buildRemediationBranchName } from '../../../src/utils/git.js';

describe('buildRemediationBranchName', () => {
  it('should produce a branch name with expected prefix', () => {
    const name = buildRemediationBranchName('main');
    expect(name).toMatch(/^chore\/security\/snyk-remediation-main-\d{8}$/);
  });

  it('should sanitize special characters in target branch', () => {
    const name = buildRemediationBranchName('release/v1.0');
    expect(name).not.toContain('/v1.0');
    expect(name).toMatch(/^chore\/security\/snyk-remediation-release-v1-0-\d{8}$/);
  });

  it("should include today's date in YYYYMMDD format", () => {
    const name = buildRemediationBranchName('main');
    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    expect(name).toContain(today);
  });
});
