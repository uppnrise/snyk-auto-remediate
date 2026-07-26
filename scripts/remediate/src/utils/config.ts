import type { RemediationConfig, SeverityThreshold, PackageManager } from '../snyk/types.js';

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
  const normalized = value.toLowerCase();
  if (normalized === 'true' || normalized === '1') return true;
  if (normalized === 'false' || normalized === '0') return false;
  throw new Error(`${name} must be true, false, 1, or 0`);
}

function parseIntEnv(name: string, defaultValue: number): number {
  const value = process.env[name];
  if (value === undefined) return defaultValue;
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a non-negative integer`);
  return Number(value);
}

function parseListEnv(name: string, defaultValue: string[]): string[] {
  const value = process.env[name];
  if (!value) return defaultValue;
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseSeverity(value: string): SeverityThreshold {
  const valid: SeverityThreshold[] = ['critical', 'high', 'medium', 'low'];
  const lower = value.toLowerCase() as SeverityThreshold;
  if (valid.includes(lower)) return lower;
  throw new Error(
    `SEVERITY_THRESHOLD must be one of critical, high, medium, or low; received "${value}"`,
  );
}

export function loadConfig(): RemediationConfig {
  const snykToken = requireEnv('SNYK_TOKEN');
  const githubRepository = requireEnv('GITHUB_REPOSITORY');
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(githubRepository)) {
    throw new Error('GITHUB_REPOSITORY must use owner/repo syntax');
  }
  const dryRun = parseBoolEnv('DRY_RUN', false);
  const githubToken = process.env['GITHUB_TOKEN'];
  if (!dryRun && !githubToken) {
    throw new Error('Required environment variable GITHUB_TOKEN is not set');
  }

  const snykProjectIdsRaw = process.env['SNYK_PROJECT_IDS'];
  const snykProjectIds = snykProjectIdsRaw
    ? snykProjectIdsRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;
  const configuredOrgId = process.env['SNYK_ORG_ID']?.trim();
  const snykOrgId = configuredOrgId || (snykProjectIds?.length ? undefined : 'local-cli');
  if (!snykOrgId) {
    throw new Error(
      'Required environment variable SNYK_ORG_ID is not set for scoped REST inventory',
    );
  }

  const packageManagersRaw = process.env['PACKAGE_MANAGERS'];
  const packageManagers = packageManagersRaw
    ? packageManagersRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;
  const validPackageManagers: PackageManager[] = [
    'npm',
    'yarn',
    'pnpm',
    'pip',
    'poetry',
    'maven',
    'gradle',
    'go',
    'composer',
  ];
  const invalidPackageManagers = packageManagers?.filter(
    (manager) => !validPackageManagers.includes(manager as PackageManager),
  );
  if (invalidPackageManagers?.length) {
    throw new Error(
      `PACKAGE_MANAGERS contains unsupported values: ${invalidPackageManagers.join(', ')}`,
    );
  }

  const prReviewersList = parseListEnv('PR_REVIEWERS', []);
  const prTeamReviewersList = parseListEnv('PR_TEAM_REVIEWERS', []);
  const testCommandValue = process.env['TEST_COMMAND'];
  const remediationBranchSuffix = process.env['REMEDIATION_BRANCH_SUFFIX'];

  const base: RemediationConfig = {
    snykToken,
    snykOrgId,
    githubRepository,
    severityThreshold: parseSeverity(getEnv('SEVERITY_THRESHOLD', 'high')),
    dryRun,
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
  if (githubToken !== undefined) base.githubToken = githubToken;

  if (snykProjectIds !== undefined) base.snykProjectIds = snykProjectIds;
  if (packageManagers !== undefined) base.packageManagers = packageManagers as PackageManager[];
  if (testCommandValue !== undefined) base.testCommand = testCommandValue;
  if (remediationBranchSuffix !== undefined) {
    base.remediationBranchSuffix = remediationBranchSuffix;
  }
  if (prReviewersList.length > 0) base.prReviewers = prReviewersList;
  if (prTeamReviewersList.length > 0) base.prTeamReviewers = prTeamReviewersList;

  return base;
}
