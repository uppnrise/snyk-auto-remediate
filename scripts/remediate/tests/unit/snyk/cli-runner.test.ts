import { beforeEach, describe, expect, it, vi } from 'vitest';
import { execCommand } from '../../../src/utils/exec.js';
import { scanWithSnykCli } from '../../../src/snyk/cli-runner.js';

vi.mock('../../../src/utils/exec.js', () => ({
  execCommand: vi.fn(),
}));

describe('scanWithSnykCli', () => {
  beforeEach(() => {
    vi.mocked(execCommand).mockResolvedValue({ stdout: '[]', stderr: '', exitCode: 0 });
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
});
