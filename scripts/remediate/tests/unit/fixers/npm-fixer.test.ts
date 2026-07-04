import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NpmFixer } from '../../../src/fixers/npm-fixer.js';
import type { SnykIssue } from '../../../src/snyk/types.js';

vi.mock('../../../src/utils/exec.js', () => ({
  execCommand: vi.fn().mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 }),
}));

function makeFixableIssue(id: string, pkgName: string, targetVersion: string): SnykIssue {
  return {
    id,
    type: 'issue',
    attributes: {
      key: id,
      title: `Vulnerability in ${pkgName}`,
      type: 'package_vulnerability',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
      severity: 'high',
      effective_severity_level: 'high',
      status: 'open',
      ignored: false,
      problems: [],
      coordinates: [
        {
          is_fixable_snyk: true,
          is_fixable_upstream: true,
          is_patchable: false,
          is_pinnable: false,
          remedies: [
            {
              type: 'upgrade',
              description: `Upgrade to ${targetVersion}`,
              details: { upgrade_package: pkgName, target_version: targetVersion },
            },
          ],
          representations: [
            { dependency: { package_name: pkgName, package_version: '1.0.0' } },
          ],
        },
      ],
    },
  };
}

describe('NpmFixer', () => {
  let fixer: NpmFixer;

  beforeEach(() => {
    fixer = new NpmFixer();
    vi.clearAllMocks();
  });

  it('should have packageManager = npm', () => {
    expect(fixer.packageManager).toBe('npm');
  });

  it('canFix should return true for fixable issues', () => {
    const issue = makeFixableIssue('A', 'lodash', '4.17.21');
    expect(fixer.canFix(issue)).toBe(true);
  });

  it('canFix should return false for non-fixable issues', () => {
    const issue: SnykIssue = {
      id: 'B',
      type: 'issue',
      attributes: {
        key: 'B',
        title: 'Non-fixable',
        type: 'package_vulnerability',
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
        severity: 'high',
        effective_severity_level: 'high',
        status: 'open',
        ignored: false,
        problems: [],
        coordinates: [
          {
            is_fixable_snyk: false,
            is_fixable_upstream: false,
            is_patchable: false,
            is_pinnable: false,
            remedies: [],
            representations: [
              { dependency: { package_name: 'bad-pkg', package_version: '1.0.0' } },
            ],
          },
        ],
      },
    };
    expect(fixer.canFix(issue)).toBe(false);
  });

  it('applyFix in dry-run mode should not call execCommand', async () => {
    const { execCommand } = await import('../../../src/utils/exec.js');
    const issue = makeFixableIssue('C', 'lodash', '4.17.21');
    await fixer.applyFix('/tmp', [issue], true);
    expect(execCommand).not.toHaveBeenCalled();
  });

  it('applyFix should call npm install with package spec', async () => {
    const { execCommand } = await import('../../../src/utils/exec.js');
    const issue = makeFixableIssue('D', 'lodash', '4.17.21');
    const result = await fixer.applyFix('/tmp', [issue], false);
    expect(execCommand).toHaveBeenCalledWith(
      'npm',
      expect.arrayContaining(['install', 'lodash@4.17.21', '--save']),
      expect.objectContaining({ cwd: '/tmp' }),
    );
    expect(result.success).toBe(true);
  });

  it('applyFix should return error result when no fixable issues', async () => {
    const issue: SnykIssue = {
      id: 'E',
      type: 'issue',
      attributes: {
        key: 'E',
        title: 'Unfixable',
        type: 'package_vulnerability',
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
        severity: 'high',
        effective_severity_level: 'high',
        status: 'open',
        ignored: false,
        problems: [],
        coordinates: [
          {
            is_fixable_snyk: false,
            is_fixable_upstream: false,
            is_patchable: false,
            remedies: [],
            representations: [],
          },
        ],
      },
    };
    const result = await fixer.applyFix('/tmp', [issue], false);
    expect(result.success).toBe(false);
  });
});
