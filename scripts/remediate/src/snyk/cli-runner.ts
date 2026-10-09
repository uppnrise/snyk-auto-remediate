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
      !('exitCode' in error) ||
      error.exitCode !== 1 ||
      !('stdout' in error) ||
      typeof (error as { stdout?: unknown }).stdout !== 'string'
    ) {
      throw error;
    }
    stdout = (error as Error & { stdout: string }).stdout;
  }
  try {
    const raw: unknown = JSON.parse(stdout);
    const results: unknown[] = Array.isArray(raw) ? raw : [raw];
    if (results.length === 0) throw new Error('Snyk returned no project results');
    for (const result of results) {
      if (
        typeof result !== 'object' ||
        result === null ||
        !('vulnerabilities' in result) ||
        !Array.isArray(result.vulnerabilities) ||
        ('error' in result && result.error) ||
        ('ok' in result && result.ok === false && result.vulnerabilities.length === 0)
      ) {
        throw new Error('Snyk returned an incomplete project result');
      }
      for (const vulnerability of result.vulnerabilities as unknown[]) {
        if (
          typeof vulnerability !== 'object' ||
          vulnerability === null ||
          !('id' in vulnerability) ||
          typeof vulnerability.id !== 'string' ||
          !('packageName' in vulnerability) ||
          typeof vulnerability.packageName !== 'string' ||
          !('version' in vulnerability) ||
          typeof vulnerability.version !== 'string' ||
          !('severity' in vulnerability) ||
          typeof vulnerability.severity !== 'string' ||
          !['info', 'low', 'medium', 'high', 'critical'].includes(vulnerability.severity)
        ) {
          throw new Error('Snyk returned a malformed vulnerability');
        }
      }
    }
    return normalizeCliOutput(raw, ecosystem);
  } catch (error) {
    const message = `Could not parse Snyk CLI output for ${ecosystem.packageManager}: ${String(error)}`;
    logger.error(message);
    throw new Error(message, { cause: error });
  }
}
