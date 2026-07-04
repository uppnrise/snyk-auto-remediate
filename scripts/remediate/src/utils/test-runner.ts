import { existsSync } from 'fs';
import { join } from 'path';
import { execCommand } from './exec.js';
import { logger } from './logger.js';
import type { DetectedEcosystem } from '../snyk/types.js';

/**
 * Determine the test command to run for a given working directory and set of
 * detected ecosystems. Prefers an explicit user-supplied command. Otherwise,
 * falls back to a best-effort per-ecosystem default. Returns `null` when no
 * suitable command can be determined.
 */
export function resolveTestCommand(
  workingDirectory: string,
  ecosystems: DetectedEcosystem[],
  explicitCommand?: string,
): { command: string; args: string[] } | null {
  if (explicitCommand && explicitCommand.trim().length > 0) {
    const parts = explicitCommand.trim().split(/\s+/);
    const command = parts[0];
    if (!command) return null;
    return { command, args: parts.slice(1) };
  }

  for (const eco of ecosystems) {
    switch (eco.packageManager) {
      case 'npm':
      case 'yarn': {
        const pkg = join(workingDirectory, 'package.json');
        if (existsSync(pkg)) {
          return {
            command: eco.packageManager,
            args: eco.packageManager === 'npm' ? ['test', '--if-present'] : ['test'],
          };
        }
        break;
      }
      case 'poetry':
        return { command: 'poetry', args: ['run', 'pytest', '-q'] };
      case 'pip':
        return { command: 'pytest', args: ['-q'] };
      case 'maven':
        return { command: 'mvn', args: ['-q', 'test'] };
      case 'gradle':
        return { command: './gradlew', args: ['test'] };
      case 'go':
        return { command: 'go', args: ['test', './...'] };
      case 'composer':
        return { command: 'composer', args: ['test'] };
    }
  }

  return null;
}

/**
 * Run tests after fixes have been applied. Returns true if tests passed (or no
 * command could be determined and `strict` is false), false otherwise.
 */
export async function runPostFixTests(
  workingDirectory: string,
  ecosystems: DetectedEcosystem[],
  explicitCommand: string | undefined,
): Promise<{ ran: boolean; passed: boolean; error?: string }> {
  const cmd = resolveTestCommand(workingDirectory, ecosystems, explicitCommand);
  if (!cmd) {
    logger.warn('RUN_TESTS=true but no test command could be resolved; skipping tests');
    return { ran: false, passed: true };
  }

  logger.info(`Running post-fix tests: ${cmd.command} ${cmd.args.join(' ')}`);
  try {
    await execCommand(cmd.command, cmd.args, { cwd: workingDirectory });
    logger.info('Post-fix tests passed');
    return { ran: true, passed: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Post-fix tests failed: ${msg}`);
    return { ran: true, passed: false, error: msg };
  }
}
