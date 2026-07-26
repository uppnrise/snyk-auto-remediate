import { describe, expect, it } from 'vitest';
import { resolvePreparationCommands } from '../../../src/utils/dependency-preparer.js';
import type { DetectedEcosystem } from '../../../src/snyk/types.js';

function ecosystem(packageManager: DetectedEcosystem['packageManager']): DetectedEcosystem {
  return { packageManager, manifestFiles: [], workingDirectory: '/repo' };
}

describe('resolvePreparationCommands', () => {
  it('installs pip dependencies before the initial Snyk scan', () => {
    expect(resolvePreparationCommands(ecosystem('pip'))).toEqual([
      { command: 'pip', args: ['install', '-r', 'requirements.txt'] },
    ]);
  });

  it('enables package managers supplied through Corepack', () => {
    expect(resolvePreparationCommands(ecosystem('yarn'))).toEqual([
      { command: 'corepack', args: ['enable'] },
    ]);
    expect(resolvePreparationCommands(ecosystem('pnpm'))).toEqual([
      { command: 'corepack', args: ['enable'] },
    ]);
  });
});
