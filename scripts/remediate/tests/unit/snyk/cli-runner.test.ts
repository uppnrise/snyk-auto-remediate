import { beforeEach, describe, expect, it, vi } from 'vitest';
import { execCommand } from '../../../src/utils/exec.js';
import { scanWithSnykCli } from '../../../src/snyk/cli-runner.js';

vi.mock('../../../src/utils/exec.js', () => ({
  execCommand: vi.fn(),
}));

describe('scanWithSnykCli', () => {
  beforeEach(() => {
    vi.mocked(execCommand).mockResolvedValue({
      stdout: '{"ok":true,"vulnerabilities":[]}',
      stderr: '',
      exitCode: 0,
    });
  });

  it('scans every Gradle subproject', async () => {
    await scanWithSnykCli(
      {
        packageManager: 'gradle',
        manifestFiles: ['build.gradle'],
        workingDirectory: '/repo',
      },
      'token',
    );

    expect(execCommand).toHaveBeenCalledWith(
      'snyk',
      ['test', '--json', '--package-manager=gradle', '--all-sub-projects'],
      expect.objectContaining({ cwd: '/repo' }),
    );
  });

  const ecosystem = {
    packageManager: 'npm' as const,
    manifestFiles: ['package.json'],
    workingDirectory: '/repo',
  };

  it('accepts exit code 1 for a valid vulnerability scan', async () => {
    vi.mocked(execCommand).mockRejectedValue(
      Object.assign(new Error('vulnerabilities found'), {
        exitCode: 1,
        stdout: JSON.stringify({
          vulnerabilities: [
            { id: 'SNYK-1', packageName: 'example', version: '1.0.0', severity: 'high' },
          ],
        }),
      }),
    );
    expect(await scanWithSnykCli(ecosystem, 'token')).toHaveLength(1);
  });

  it.each([
    { exitCode: 2, stdout: '{"error":"authentication failed"}' },
    { exitCode: 2, stdout: '{"vulnerabilities":[]}' },
    { exitCode: 3, stdout: '{"ok":true,"vulnerabilities":[]}' },
  ])('rejects operational CLI failure $exitCode', async (failure) => {
    vi.mocked(execCommand).mockRejectedValue(Object.assign(new Error('scan failed'), failure));
    await expect(scanWithSnykCli(ecosystem, 'token')).rejects.toThrow();
  });

  it.each([
    '[]',
    '{}',
    'null',
    '{"ok":false,"error":"scan failed"}',
    '{"ok":false,"vulnerabilities":[]}',
    '[{"vulnerabilities":[]},{"error":"subproject failed"}]',
    '{"vulnerabilities":[{"id":"missing-package"}]}',
    '{"vulnerabilities":[{"id":"SNYK-1","packageName":"example","version":"1.0.0"}]}',
    '{"vulnerabilities":[{"id":"SNYK-1","packageName":"example","version":"1.0.0","severity":"unknown"}]}',
  ])('rejects incomplete JSON inventory: %s', async (stdout) => {
    vi.mocked(execCommand).mockResolvedValue({ stdout, stderr: '', exitCode: 0 });
    await expect(scanWithSnykCli(ecosystem, 'token')).rejects.toThrow();
  });
});
