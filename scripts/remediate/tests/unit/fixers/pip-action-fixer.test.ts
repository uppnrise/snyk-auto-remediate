import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ExactActionFixer } from '../../../src/fixers/exact-action-fixer.js';
import { execCommand } from '../../../src/utils/exec.js';
import type { RemediationAction } from '../../../src/snyk/types.js';

vi.mock('../../../src/utils/exec.js', () => ({ execCommand: vi.fn() }));

describe('pip manifest updates outside dry-run', () => {
  let directory: string;
  const action: RemediationAction = {
    packageManager: 'pip',
    packageName: 'requests',
    currentVersion: '2.0.0',
    targetVersion: '2.1.0',
    findingIds: [],
    findingKeys: ['SNYK-DEMO'],
    evidence: 'snyk-cli-upgrade-path',
  };
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'snyk-pip-fixer-'));
    vi.mocked(execCommand).mockReset().mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
  });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  it.each([
    ['requests==2.0.0', 'requests==2.1.0'],
    ['requests>=2.0.0, <3', 'requests==2.1.0'],
    ['requests', 'requests==2.1.0'],
    [
      '  requests[security]==2.0.0 ; python_version >= "3.10" # keep',
      '  requests[security]==2.1.0 ; python_version >= "3.10" # keep',
    ],
  ])('pins a direct requirement: %s', async (before, after) => {
    const file = join(directory, 'requirements.txt');
    writeFileSync(file, `# dependencies\n${before}\nflask==3.0.0\n`);
    const result = await new ExactActionFixer('pip').applyFix(
      directory,
      [action],
      new Map(),
      false,
    );
    expect(result.success).toBe(true);
    expect(readFileSync(file, 'utf8')).toBe(`# dependencies\n${after}\nflask==3.0.0\n`);
    expect(execCommand).toHaveBeenCalledWith('pip', ['install', '-r', 'requirements.txt'], {
      cwd: directory,
    });
  });

  it('escapes dots in package names without matching another package', async () => {
    const file = join(directory, 'requirements.txt');
    writeFileSync(file, 'zopeXinterface==2.0.0\nzope.interface==2.0.0\n');
    expect(
      (
        await new ExactActionFixer('pip').applyFix(
          directory,
          [{ ...action, packageName: 'zope.interface' }],
          new Map(),
          false,
        )
      ).success,
    ).toBe(true);
    expect(readFileSync(file, 'utf8')).toBe('zopeXinterface==2.0.0\nzope.interface==2.1.0\n');
  });

  it.each(['snyk-cli-upgrade-path', 'snyk-rest-remedy'] as const)(
    'rejects conditional declarations without changing either platform (%s)',
    async (evidence) => {
      const file = join(directory, 'requirements.txt');
      const before =
        'requests==2.32.0 ; sys_platform == "win32"\nrequests==2.0.0 ; sys_platform == "linux"\n';
      writeFileSync(file, before);
      const result = await new ExactActionFixer('pip').applyFix(
        directory,
        [{ ...action, targetVersion: '2.31.0', evidence }],
        new Map(),
        false,
      );
      expect(result.success).toBe(false);
      expect(result.error).toContain('unsupported_manifest_shape');
      expect(readFileSync(file, 'utf8')).toBe(before);
      expect(execCommand).not.toHaveBeenCalled();
    },
  );

  it.each([
    'requests==2.0.0 ; sys_platform == "win32"\nrequests==2.0.0 ; sys_platform == "linux"\n',
    'requests @ https://example.test/requests.whl ; sys_platform == "win32"\nrequests==2.0.0 ; sys_platform == "linux"\n',
    'requests==2.0.0 ; sys_platform == "linux"\nrequests[security]>=2.32.0 ; sys_platform == "win32"\n',
  ])('preserves repeated declarations including unsupported shapes: %s', async (before) => {
    const file = join(directory, 'requirements.txt');
    writeFileSync(file, before);
    const result = await new ExactActionFixer('pip').applyFix(
      directory,
      [action],
      new Map(),
      false,
    );
    expect(result.success).toBe(false);
    expect(readFileSync(file, 'utf8')).toBe(before);
    expect(execCommand).not.toHaveBeenCalled();
  });

  it('does not treat comments or similarly named packages as repeated declarations', async () => {
    const file = join(directory, 'requirements.txt');
    const before =
      '# requests==2.32.0\nrequests-extra==2.32.0\nrequests==2.0.0 ; sys_platform == "linux"\n';
    writeFileSync(file, before);
    const result = await new ExactActionFixer('pip').applyFix(
      directory,
      [action],
      new Map(),
      false,
    );
    expect(result.success).toBe(true);
    expect(readFileSync(file, 'utf8')).toBe(before.replace('requests==2.0.0', 'requests==2.1.0'));
  });

  it('recognizes equivalent package names when checking for repeated declarations', async () => {
    const file = join(directory, 'requirements.txt');
    const before =
      'zope-interface==2.32.0 ; sys_platform == "win32"\nzope.interface==2.0.0 ; sys_platform == "linux"\n';
    writeFileSync(file, before);
    const result = await new ExactActionFixer('pip').applyFix(
      directory,
      [{ ...action, packageName: 'zope.interface' }],
      new Map(),
      false,
    );
    expect(result.success).toBe(false);
    expect(readFileSync(file, 'utf8')).toBe(before);
    expect(execCommand).not.toHaveBeenCalled();
  });

  it('restores the original requirement when installation fails', async () => {
    const file = join(directory, 'requirements.txt');
    writeFileSync(file, 'requests==2.0.0\n');
    vi.mocked(execCommand).mockRejectedValue(new Error('install failed'));
    const result = await new ExactActionFixer('pip').applyFix(
      directory,
      [action],
      new Map(),
      false,
    );
    expect(result.error).toContain('install failed');
    expect(result.success).toBe(false);
    expect(readFileSync(file, 'utf8')).toBe('requests==2.0.0\n');
  });

  it('leaves direct URL requirements for manual remediation', async () => {
    const file = join(directory, 'requirements.txt');
    writeFileSync(file, 'requests @ https://example.test/requests.whl\n');
    const result = await new ExactActionFixer('pip').applyFix(
      directory,
      [action],
      new Map(),
      false,
    );
    expect(result.success).toBe(false);
    expect(execCommand).not.toHaveBeenCalled();
  });
});
