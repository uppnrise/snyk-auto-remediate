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

function cliErrorDetail(stdout: string): string | undefined {
  try {
    const output: unknown = JSON.parse(stdout);
    if (typeof output !== 'object' || output === null || Array.isArray(output)) return;
    const fields = output as Record<string, unknown>;
    const messages = [fields.error, fields.userMessage, fields.message]
      .flatMap((value) => {
        if (typeof value === 'string') return [value];
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          const nested = value as Record<string, unknown>;
          return [nested.message, nested.userMessage].filter(
            (item): item is string => typeof item === 'string',
          );
        }
        return [];
      })
      .filter((message) => message.trim().length > 0);
    return [...new Set(messages)].join('; ') || undefined;
  } catch {
    return;
  }
}

function describeCliError(error: unknown, snykToken: string): Error {
  const message = error instanceof Error ? error.message : String(error);
  const stdout =
    typeof error === 'object' &&
    error !== null &&
    'stdout' in error &&
    typeof error.stdout === 'string'
      ? error.stdout
      : '';
  const detail = cliErrorDetail(stdout);
  const combined = detail ? `${message}\nSnyk CLI error: ${detail}` : message;
  const redacted = snykToken ? combined.split(snykToken).join('[REDACTED]') : combined;
  return new Error(redacted.slice(0, 4000), { cause: error });
}

export async function scanWithSnykCli(
  ecosystem: DetectedEcosystem,
  snykToken: string,
  snykOrgId?: string,
  repositoryDirectory = '.',
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
      throw describeCliError(error, snykToken);
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
    return normalizeCliOutput(raw, ecosystem, repositoryDirectory);
  } catch (error) {
    const message = `Could not parse Snyk CLI output for ${ecosystem.packageManager}: ${String(error)}`;
    logger.error(message);
    throw new Error(message, { cause: error });
  }
}
