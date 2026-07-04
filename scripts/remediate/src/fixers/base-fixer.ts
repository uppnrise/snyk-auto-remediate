import type { FixResult, PackageManager, SnykIssue } from '../snyk/types.js';
import { logger } from '../utils/logger.js';
import { execCommand } from '../utils/exec.js';

export abstract class BaseFixer {
  abstract readonly packageManager: PackageManager;

  abstract canFix(issue: SnykIssue): boolean;

  abstract applyFix(
    workingDirectory: string,
    issues: SnykIssue[],
    dryRun: boolean,
  ): Promise<FixResult>;

  protected async runCommand(
    command: string,
    args: string[],
    cwd: string,
  ): Promise<{ stdout: string; stderr: string }> {
    logger.debug(`[${this.packageManager}] Running: ${command} ${args.join(' ')}`);
    const result = await execCommand(command, args, { cwd });
    return result;
  }

  protected createSuccessResult(
    fixedFindings: SnykIssue[],
    changesApplied: string[],
  ): FixResult {
    return {
      success: true,
      packageManager: this.packageManager,
      fixedFindings,
      failedFindings: [],
      changesApplied,
    };
  }

  protected createErrorResult(
    failedFindings: SnykIssue[],
    error: string,
  ): FixResult {
    return {
      success: false,
      packageManager: this.packageManager,
      fixedFindings: [],
      failedFindings,
      changesApplied: [],
      error,
    };
  }
}
