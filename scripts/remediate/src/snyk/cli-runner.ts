import { execCommand } from '../utils/exec.js';
import { logger } from '../utils/logger.js';
import type { DetectedEcosystem } from './types.js';
import { normalizeCliOutput } from './correlation.js';

const CLI_PACKAGE_MANAGER: Record<DetectedEcosystem['packageManager'], string> = {
  npm: 'npm',
  yarn: 'yarn',
  pnpm: 'pnpm',
  pip: 'pip',
  poetry: 'poetry',
  maven: 'maven',
  gradle: 'gradle',
  go: 'gomodules',
  composer: 'composer',
};

export async function scanWithSnykCli(
  ecosystem: DetectedEcosystem,
  snykToken: string,
  snykOrgId?: string,
): Promise<ReturnType<typeof normalizeCliOutput>> {
  const env = { ...process.env, SNYK_TOKEN: snykToken } as Record<string, string>;
  const args = [
    'test',
    '--json',
    `--package-manager=${CLI_PACKAGE_MANAGER[ecosystem.packageManager]}`,
  ];
  if (ecosystem.packageManager === 'gradle') args.push('--all-sub-projects');
  if (snykOrgId && snykOrgId !== 'local-cli') args.push(`--org=${snykOrgId}`);
  let stdout: string;
  try {
    stdout = (await execCommand('snyk', args, { cwd: ecosystem.workingDirectory, env })).stdout;
  } catch (error) {
    if (
      !(error instanceof Error) ||
      !('stdout' in error) ||
      typeof (error as { stdout?: unknown }).stdout !== 'string'
    ) {
      throw error;
    }
    stdout = (error as Error & { stdout: string }).stdout;
  }
  try {
    return normalizeCliOutput(JSON.parse(stdout) as unknown, ecosystem);
  } catch (error) {
    const message = `Could not parse Snyk CLI output for ${ecosystem.packageManager}: ${String(error)}`;
    logger.error(message);
    throw new Error(message, { cause: error });
  }
}
