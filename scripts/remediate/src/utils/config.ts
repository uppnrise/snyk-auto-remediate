import type { RemediationConfig, Severity, PackageManager } from '../snyk/types.js';
import { logger } from './logger.js';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Required environment variable ${name} is not set`);
  }
  return value;
}

function getEnv(name: string, defaultValue: string): string {
  return process.env[name] ?? defaultValue;
}

function parseBoolEnv(name: string, defaultValue: boolean): boolean {
  const value = process.env[name];
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

function parseIntEnv(name: string, defaultValue: number): number {
  const value = process.env[name];
  if (value === undefined) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

function parseListEnv(name: string, defaultValue: string[]): string[] {
  const value = process.env[name];
  if (!value) return defaultValue;
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseSeverity(value: string): Severity {
  const valid: Severity[] = ['critical', 'high', 'medium', 'low'];
  const lower = value.toLowerCase() as Severity;
  if (valid.includes(lower)) return lower;
  logger.warn(`Invalid severity threshold "${value}", defaulting to "high"`);
  return 'high';
}

export function loadConfig(): RemediationConfig {
  const snykToken = requireEnv('SNYK_TOKEN');
  const snykOrgId = requireEnv('SNYK_ORG_ID');
  const githubRepository = requireEnv('GITHUB_REPOSITORY');
  const githubToken = requireEnv('GITHUB_TOKEN');

  const snykProjectIdsRaw = process.env['SNYK_PROJECT_IDS'];
  const snykProjectIds = snykProjectIdsRaw
    ? snykProjectIdsRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;

  const packageManagersRaw = process.env['PACKAGE_MANAGERS'];
  const packageManagers: PackageManager[] | undefined = packageManagersRaw
    ? (packageManagersRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean) as PackageManager[])
    : undefined;

  const prReviewersList = parseListEnv('PR_REVIEWERS', []);
  const prTeamReviewersList = parseListEnv('PR_TEAM_REVIEWERS', []);
  const testCommandValue = process.env['TEST_COMMAND'];

  const base: RemediationConfig = {
    snykToken,
    snykOrgId,
    githubRepository,
    githubToken,
    severityThreshold: parseSeverity(getEnv('SEVERITY_THRESHOLD', 'high')),
    dryRun: parseBoolEnv('DRY_RUN', false),
    maxPrsPerRun: parseIntEnv('MAX_PRS_PER_RUN', 5),
    maxIssuesPerRun: parseIntEnv('MAX_ISSUES_PER_RUN', 10),
    workingDirectory: getEnv('WORKING_DIRECTORY', '.'),
    enableCopilotAgentFallback: parseBoolEnv('ENABLE_COPILOT_AGENT_FALLBACK', true),
    copilotAssignee: getEnv('COPILOT_ASSIGNEE', 'copilot'),
    failOnNoFix: parseBoolEnv('FAIL_ON_NO_FIX', false),
    runTests: parseBoolEnv('RUN_TESTS', true),
    prLabels: parseListEnv('PR_LABELS', ['security', 'dependencies', 'snyk', 'automated']),
    issueLabels: parseListEnv('ISSUE_LABELS', ['security', 'snyk', 'ai-remediation']),
    targetBranch: getEnv('TARGET_BRANCH', 'main'),
  };

  if (snykProjectIds !== undefined) base.snykProjectIds = snykProjectIds;
  if (packageManagers !== undefined) base.packageManagers = packageManagers;
  if (testCommandValue !== undefined) base.testCommand = testCommandValue;
  if (prReviewersList.length > 0) base.prReviewers = prReviewersList;
  if (prTeamReviewersList.length > 0) base.prTeamReviewers = prTeamReviewersList;

  return base;
}
