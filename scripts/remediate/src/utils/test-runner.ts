import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { execCommand } from './exec.js';
import { logger } from './logger.js';
import type { DetectedEcosystem } from '../snyk/types.js';

export interface ResolvedCommand {
  command: string;
  args: string[];
}

interface TestResolutionOverrides {
  packageJson?: string;
}

function hasNpmTestScript(workingDirectory: string, overrides: TestResolutionOverrides): boolean {
  const packageJsonPath = join(workingDirectory, 'package.json');
  const source =
    overrides.packageJson ??
    (existsSync(packageJsonPath) ? readFileSync(packageJsonPath, 'utf8') : undefined);
  if (!source) return false;
  try {
    const parsed = JSON.parse(source) as { scripts?: Record<string, unknown> };
    return typeof parsed.scripts?.test === 'string' && parsed.scripts.test.trim().length > 0;
  } catch {
    return false;
  }
}

export function resolveTestCommands(
  workingDirectory: string,
  ecosystems: DetectedEcosystem[],
  explicitCommand?: string,
  overrides: TestResolutionOverrides = {},
): ResolvedCommand[] {
  if (explicitCommand?.trim()) {
    return [{ command: 'sh', args: ['-c', explicitCommand.trim()] }];
  }

  const commands: ResolvedCommand[] = [];
  for (const ecosystem of ecosystems) {
    switch (ecosystem.packageManager) {
      case 'npm':
      case 'yarn':
      case 'pnpm':
        if (hasNpmTestScript(workingDirectory, overrides)) {
          commands.push({ command: ecosystem.packageManager, args: ['test'] });
        }
        break;
      case 'poetry':
        commands.push({ command: 'poetry', args: ['run', 'pytest', '-q'] });
        break;
      case 'pip':
        commands.push({ command: 'pytest', args: ['-q'] });
        break;
      case 'maven':
        commands.push({ command: 'mvn', args: ['-q', 'test'] });
        break;
      case 'gradle':
        commands.push({ command: './gradlew', args: ['test'] });
        break;
      case 'go':
        commands.push({ command: 'go', args: ['test', './...'] });
        break;
      case 'composer':
        commands.push({ command: 'composer', args: ['test'] });
        break;
    }
  }

  const unique = new Map(
    commands.map((item) => [`${item.command}\0${item.args.join('\0')}`, item]),
  );
  return [...unique.values()];
}

export async function runPostFixTests(
  workingDirectory: string,
  ecosystems: DetectedEcosystem[],
  explicitCommand: string | undefined,
): Promise<{ ran: boolean; passed: boolean; error?: string }> {
  const commands = resolveTestCommands(workingDirectory, ecosystems, explicitCommand);
  if (commands.length === 0) {
    logger.warn('RUN_TESTS=true but no test commands could be resolved; skipping tests');
    return { ran: false, passed: true };
  }

  const errors: string[] = [];
  for (const item of commands) {
    logger.info(`Running post-fix tests: ${item.command} ${item.args.join(' ')}`);
    try {
      await execCommand(item.command, item.args, { cwd: workingDirectory });
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  if (errors.length > 0) {
    const error = errors.join('\n');
    logger.error(`Post-fix tests failed: ${error}`);
    return { ran: true, passed: false, error };
  }
  logger.info('All post-fix tests passed');
  return { ran: true, passed: true };
}
