import { BaseFixer } from './base-fixer.js';
import { extractPackageInfo } from '../snyk/cli-runner.js';
import { logger } from '../utils/logger.js';
import type { FixResult, SnykIssue } from '../snyk/types.js';

export class GradleFixer extends BaseFixer {
  readonly packageManager = 'gradle' as const;

  canFix(issue: SnykIssue): boolean {
    return issue.attributes.coordinates.some(
      (c) =>
        (c.is_fixable_upstream === true || c.is_fixable_snyk === true) &&
        c.remedies !== undefined &&
        c.remedies.length > 0,
    );
  }

  async applyFix(
    workingDirectory: string,
    issues: SnykIssue[],
    dryRun: boolean,
  ): Promise<FixResult> {
    const fixableIssues = issues.filter((i) => this.canFix(i));
    if (fixableIssues.length === 0) {
      return this.createErrorResult(issues, 'No automatically fixable Gradle issues found');
    }

    const changes: string[] = [];
    const fixedIssues: SnykIssue[] = [];

    for (const issue of fixableIssues) {
      const info = extractPackageInfo(issue);
      if (!info?.targetVersion) continue;
      changes.push(`Update ${info.packageName} to ${info.targetVersion}`);
      fixedIssues.push(issue);
    }

    if (dryRun) {
      logger.info('[gradle] Dry run — would apply dependency updates');
      return this.createSuccessResult(fixedIssues, changes.map((c) => `Would apply: ${c}`));
    }

    try {
      await this.runCommand(
        './gradlew',
        ['dependencyUpdates', '-Drevision=release'],
        workingDirectory,
      );
      return this.createSuccessResult(fixedIssues, changes);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      logger.error(`[gradle] Fix failed: ${msg}`);
      return this.createErrorResult(fixableIssues, msg);
    }
  }
}
