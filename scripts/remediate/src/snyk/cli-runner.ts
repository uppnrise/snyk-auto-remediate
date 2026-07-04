import { execCommand } from '../utils/exec.js';
import { logger } from '../utils/logger.js';
import type { PackageManager, SnykIssue } from './types.js';

export interface SnykTestResult {
  vulnerabilities: SnykCliVulnerability[];
  packageManager: string;
  projectName: string;
  ok: boolean;
}

export interface SnykCliVulnerability {
  id: string;
  title: string;
  severity: string;
  packageName: string;
  version: string;
  fixedIn?: string[];
  upgradePath?: string[];
  isUpgradable?: boolean;
  isPatchable?: boolean;
}

export async function runSnykTest(
  workingDirectory: string,
  packageManager: PackageManager,
  snykToken: string,
): Promise<SnykTestResult | null> {
  const env = { ...process.env, SNYK_TOKEN: snykToken };

  try {
    const result = await execCommand(
      'snyk',
      ['test', '--json', `--package-manager=${packageManager}`],
      { cwd: workingDirectory, env: env as Record<string, string> },
    );

    const parsed = JSON.parse(result.stdout) as SnykTestResult;
    return parsed;
  } catch (error) {
    // snyk test exits with non-zero if vulnerabilities found — parse JSON anyway
    if (error instanceof Error && 'stdout' in error) {
      try {
        const parsed = JSON.parse((error as { stdout: string }).stdout) as SnykTestResult;
        return parsed;
      } catch {
        logger.warn(`Could not parse snyk test output: ${error.message}`);
      }
    }
    return null;
  }
}

export function isFixableBySnykCli(issue: SnykIssue): boolean {
  return issue.attributes.coordinates.some(
    (coord) =>
      coord.is_fixable_snyk === true ||
      coord.is_fixable_upstream === true ||
      coord.is_patchable === true,
  );
}

export function extractPackageInfo(
  issue: SnykIssue,
): { packageName: string; currentVersion: string; targetVersion?: string } | null {
  for (const coord of issue.attributes.coordinates) {
    const dep = coord.representations?.[0]?.dependency;
    if (dep) {
      const remedy = coord.remedies?.[0];
      const targetVersion = remedy?.details?.target_version;
      return {
        packageName: dep.package_name,
        currentVersion: dep.package_version,
        ...(targetVersion !== undefined ? { targetVersion } : {}),
      };
    }
  }
  return null;
}
