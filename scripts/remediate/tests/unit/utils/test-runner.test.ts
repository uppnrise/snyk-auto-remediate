import { describe, expect, it } from 'vitest';
import { resolveTestCommands } from '../../../src/utils/test-runner.js';
import type { DetectedEcosystem } from '../../../src/snyk/types.js';

function ecosystem(packageManager: DetectedEcosystem['packageManager']): DetectedEcosystem {
  return { packageManager, manifestFiles: [], workingDirectory: '/repo' };
}

describe('resolveTestCommands', () => {
  it('runs test suites for every detected ecosystem', () => {
    expect(resolveTestCommands('/repo', [ecosystem('pip'), ecosystem('go')])).toEqual([
      { command: 'pytest', args: ['-q'] },
      { command: 'go', args: ['test', './...'] },
    ]);
  });

  it('preserves a custom command as a shell expression', () => {
    expect(
      resolveTestCommands('/repo', [], 'npm test -- --name "security fix" && npm run lint'),
    ).toEqual([
      {
        command: 'sh',
        args: ['-c', 'npm test -- --name "security fix" && npm run lint'],
      },
    ]);
  });

  it('does not claim npm tests ran when package.json has no test script', () => {
    expect(
      resolveTestCommands('/repo', [ecosystem('npm')], undefined, {
        packageJson: JSON.stringify({ scripts: {} }),
      }),
    ).toEqual([]);
  });
});
