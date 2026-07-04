import { BaseFixer } from './base-fixer.js';
import { extractPackageInfo } from '../snyk/cli-runner.js';
import { logger } from '../utils/logger.js';
import type { FixResult, SnykIssue } from '../snyk/types.js';

export class PoetryFixer extends BaseFixer {
  readonly packageManager = 'poetry' as const;

  canFix(issue: SnykIssue): boolean {
    return issue.attributes.coordinates.some(
      (c) => c.is_fixable_upstream === true || c.is_fixable_snyk === true,
    );
  }

  async applyFix(
    workingDirectory: string,
    issues: SnykIssue[],
    dryRun: boolean,
  ): Promise<FixResult> {
    const fixableIssues = issues.filter((i) => this.canFix(i));
    if (fixableIssues.length === 0) {
      return this.createErrorResult(issues, 'No fixable issues found');
    }

    const upgrades: string[] = [];
    const fixedIssues: SnykIssue[] = [];
    const failedIssues: SnykIssue[] = [];

    for (const issue of fixableIssues) {
      const info = extractPackageInfo(issue);
      if (!info) {
        failedIssues.push(issue);
        continue;
      }
      const pkg = info.targetVersion
        ? `${info.packageName}@^${info.targetVersion}`
        : info.packageName;
      upgrades.push(pkg);
      fixedIssues.push(issue);
    }

    if (upgrades.length === 0) {
      return this.createErrorResult(failedIssues, 'No packages to upgrade');
    }

    logger.info(`[poetry] Upgrading packages: ${upgrades.join(', ')}`);

    if (dryRun) {
      return this.createSuccessResult(fixedIssues, upgrades.map((p) => `Would upgrade: ${p}`));
    }

    try {
      for (const pkg of upgrades) {
        await this.runCommand('poetry', ['add', pkg], workingDirectory);
      }
      return this.createSuccessResult(
        fixedIssues,
        upgrades.map((p) => `Upgraded: ${p}`),
      );
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      logger.error(`[poetry] Fix failed: ${msg}`);
      return this.createErrorResult(fixableIssues, msg);
    }
  }
}
