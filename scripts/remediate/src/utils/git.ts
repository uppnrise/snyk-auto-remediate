import { execCommand } from './exec.js';
import { logger } from './logger.js';

export async function gitAddAll(workingDirectory: string): Promise<void> {
  await execCommand('git', ['add', '-A'], { cwd: workingDirectory });
}

export async function gitCommit(workingDirectory: string, message: string): Promise<void> {
  await execCommand('git', ['commit', '-m', message], { cwd: workingDirectory });
}

export async function gitCheckoutBranch(
  workingDirectory: string,
  branchName: string,
  createNew = false,
): Promise<void> {
  const args = createNew ? ['checkout', '-B', branchName] : ['checkout', branchName];
  await execCommand('git', args, { cwd: workingDirectory });
}

export async function gitHasChanges(workingDirectory: string): Promise<boolean> {
  try {
    const result = await execCommand('git', ['status', '--porcelain'], {
      cwd: workingDirectory,
    });
    return result.stdout.trim().length > 0;
  } catch {
    return false;
  }
}

export async function gitConfigureUser(
  workingDirectory: string,
  name = 'snyk-auto-remediate[bot]',
  email = 'snyk-auto-remediate@users.noreply.github.com',
): Promise<void> {
  await execCommand('git', ['config', 'user.name', name], { cwd: workingDirectory });
  await execCommand('git', ['config', 'user.email', email], { cwd: workingDirectory });
}

export async function gitCurrentBranch(workingDirectory: string): Promise<string> {
  const result = await execCommand('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
    cwd: workingDirectory,
  });
  return result.stdout.trim();
}

export async function gitBranchExists(
  workingDirectory: string,
  branchName: string,
): Promise<boolean> {
  try {
    await execCommand('git', ['rev-parse', '--verify', branchName], {
      cwd: workingDirectory,
    });
    return true;
  } catch {
    return false;
  }
}

export function buildRemediationBranchName(targetBranch: string, suffix?: string): string {
  const safeBranch = targetBranch.replace(/[^a-zA-Z0-9_-]/g, '-');
  const safeSuffix = suffix?.replace(/[^a-zA-Z0-9_-]/g, '-');
  const suffixSegment = safeSuffix ? `-${safeSuffix}` : '';
  return `chore/security/snyk-remediation-${safeBranch}${suffixSegment}`;
}

export async function gitPush(workingDirectory: string, branchName: string): Promise<void> {
  logger.info(`Pushing branch: ${branchName}`);
  try {
    await execCommand(
      'git',
      ['fetch', 'origin', `refs/heads/${branchName}:refs/remotes/origin/${branchName}`],
      { cwd: workingDirectory },
    );
  } catch {
    logger.debug(`No existing remote remediation branch found for ${branchName}`);
  }
  await execCommand('git', ['push', 'origin', branchName, '--force-with-lease'], {
    cwd: workingDirectory,
  });
}
