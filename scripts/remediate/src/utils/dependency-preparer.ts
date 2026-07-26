import type { DetectedEcosystem } from '../snyk/types.js';
import { execCommand } from './exec.js';
import { logger } from './logger.js';
import type { ResolvedCommand } from './test-runner.js';

export function resolvePreparationCommands(ecosystem: DetectedEcosystem): ResolvedCommand[] {
  switch (ecosystem.packageManager) {
    case 'pip':
      return [{ command: 'pip', args: ['install', '-r', 'requirements.txt'] }];
    case 'yarn':
    case 'pnpm':
      return [{ command: 'corepack', args: ['enable'] }];
    default:
      return [];
  }
}

export async function prepareForSnykScan(ecosystem: DetectedEcosystem): Promise<void> {
  for (const item of resolvePreparationCommands(ecosystem)) {
    logger.info(
      `Preparing ${ecosystem.packageManager} scan: ${item.command} ${item.args.join(' ')}`,
    );
    await execCommand(item.command, item.args, { cwd: ecosystem.workingDirectory });
  }
}
