import type { FixResult, PackageManager, RemediationAction, SnykIssue } from '../snyk/types.js';
import { execCommand } from '../utils/exec.js';

export abstract class BaseFixer {
  abstract readonly packageManager: PackageManager;
  abstract applyFix(
    workingDirectory: string,
    actions: RemediationAction[],
    findings: Map<string, SnykIssue>,
    dryRun: boolean,
  ): Promise<FixResult>;
  rollback(): void {}

  protected async runCommand(command: string, args: string[], cwd: string): Promise<void> {
    await execCommand(command, args, { cwd });
  }
  protected result(
    actions: RemediationAction[],
    findings: Map<string, SnykIssue>,
    success: boolean,
    changes: string[],
    error?: string,
  ): FixResult {
    const affected = actions
      .flatMap((a) => a.findingIds)
      .map((id) => findings.get(id))
      .filter((x): x is SnykIssue => Boolean(x));
    return {
      success,
      packageManager: this.packageManager,
      fixedFindings: success ? affected : [],
      failedFindings: success ? [] : affected,
      changesApplied: changes,
      attemptedActions: actions,
      ...(error ? { error } : {}),
    };
  }
}
