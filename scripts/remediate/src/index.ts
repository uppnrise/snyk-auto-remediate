import { loadConfig } from './utils/config.js';
import { logger } from './utils/logger.js';
import { fetchSnykIssues } from './snyk/api-client.js';
import { deduplicateIssues, partitionByFixability, filterIssuesForPackageManager } from './utils/dedup.js';
import { detectEcosystems } from './detectors/language-detector.js';
import { NpmFixer } from './fixers/npm-fixer.js';
import { YarnFixer } from './fixers/yarn-fixer.js';
import { PipFixer } from './fixers/pip-fixer.js';
import { PoetryFixer } from './fixers/poetry-fixer.js';
import { MavenFixer } from './fixers/maven-fixer.js';
import { GradleFixer } from './fixers/gradle-fixer.js';
import { GoFixer } from './fixers/go-fixer.js';
import { ComposerFixer } from './fixers/composer-fixer.js';
import type { BaseFixer } from './fixers/base-fixer.js';
import { createOrUpdateIssues } from './github/issue-creator.js';
import { createOrUpdatePr, buildPrBody } from './github/pr-creator.js';
import { writeJsonReport } from './reporting/json-writer.js';
import { writeSarifReport } from './reporting/sarif-writer.js';
import { writeStepSummary } from './reporting/summary-writer.js';
import { gitHasChanges, gitAddAll, gitCommit, gitCheckoutBranch, buildRemediationBranchName, gitConfigureUser, gitBranchExists, gitPush } from './utils/git.js';
import { runPostFixTests } from './utils/test-runner.js';
import type { FixResult, RemediationReport } from './snyk/types.js';
import { resolve } from 'path';

const FIXERS: BaseFixer[] = [
  new YarnFixer(),
  new NpmFixer(),
  new PoetryFixer(),
  new PipFixer(),
  new MavenFixer(),
  new GradleFixer(),
  new GoFixer(),
  new ComposerFixer(),
];

async function main(): Promise<void> {
  logger.info('🚀 Snyk Auto-Remediation Engine starting...');

  const config = loadConfig();
  const workingDir = resolve(config.workingDirectory);
  const errors: string[] = [];
  const fixResults: FixResult[] = [];
  let issuesCreated = 0;
  let prsCreated = 0;

  // 1. Fetch Snyk issues
  logger.info('Fetching Snyk issues...');
  let allIssues = await fetchSnykIssues(config);
  allIssues = deduplicateIssues(allIssues);
  logger.info(`Total unique issues: ${allIssues.length}`);

  // 2. Partition into fixable / unfixable
  const { fixable, unfixable } = partitionByFixability(allIssues);
  logger.info(`Fixable: ${fixable.length}, Unfixable: ${unfixable.length}`);

  // 3. Detect ecosystems
  const ecosystems = detectEcosystems(workingDir, config.packageManagers);

  // 4. Run fixers per detected ecosystem
  if (fixable.length > 0 && ecosystems.length > 0) {
    // Configure git user for commits
    if (!config.dryRun) {
      await gitConfigureUser(workingDir);
    }

    // Create remediation branch
    const branchName = buildRemediationBranchName(config.targetBranch);
    logger.info(`Using branch: ${branchName}`);

    if (!config.dryRun) {
      const branchExists = await gitBranchExists(workingDir, branchName);
      if (!branchExists) {
        await gitCheckoutBranch(workingDir, branchName, true);
      } else {
        await gitCheckoutBranch(workingDir, branchName);
      }
    }

    for (const ecosystem of ecosystems) {
      const fixer = FIXERS.find((f) => f.packageManager === ecosystem.packageManager);
      if (!fixer) {
        logger.warn(`No fixer found for ${ecosystem.packageManager}`);
        continue;
      }

      const relevantIssues = filterIssuesForPackageManager(fixable, ecosystem.packageManager).slice(
        0,
        config.maxPrsPerRun * 10,
      );
      if (relevantIssues.length === 0) {
        logger.info(`No ${ecosystem.packageManager} issues to fix, skipping`);
        continue;
      }
      logger.info(`Running ${ecosystem.packageManager} fixer on ${relevantIssues.length} issues...`);

      const result = await fixer.applyFix(workingDir, relevantIssues, config.dryRun);
      fixResults.push(result);

      if (result.success && !config.dryRun) {
        const hasChanges = await gitHasChanges(workingDir);
        if (hasChanges) {
          await gitAddAll(workingDir);
          await gitCommit(
            workingDir,
            `fix(security): auto-remediate ${ecosystem.packageManager} vulnerabilities via Snyk\n\nFixed: ${result.fixedFindings.map((f) => f.id).join(', ')}`,
          );
        }
      }
    }

    // Push and create PR only when there are actual commits to push
    const hasFixes = fixResults.some((r) => r.success && r.fixedFindings.length > 0);
    if (!config.dryRun && hasFixes) {
      // Run tests after fixes have been applied, before pushing / opening PR.
      if (config.runTests) {
        const testResult = await runPostFixTests(workingDir, ecosystems, config.testCommand);
        if (testResult.ran && !testResult.passed) {
          const msg = `Post-fix tests failed; aborting PR creation: ${testResult.error ?? 'unknown error'}`;
          logger.error(msg);
          errors.push(msg);
        }
      }

      const testsBlockedPush = errors.some((e) => e.startsWith('Post-fix tests failed'));
      if (!testsBlockedPush) {
        try {
          await gitPush(workingDir, branchName);

          const allFixedIds = fixResults.flatMap((r) => r.fixedFindings.map((f) => f.id));
          const allChanges = fixResults.flatMap((r) => r.changesApplied);

          const prDetails: import('./github/pr-creator.js').PrDetails = {
            title: `fix(security): Snyk auto-remediation for ${config.targetBranch}`,
            body: buildPrBody(allChanges, allFixedIds, config.targetBranch),
            head: branchName,
            base: config.targetBranch,
            labels: config.prLabels,
          };
          if (config.prReviewers) prDetails.reviewers = config.prReviewers;
          if (config.prTeamReviewers) prDetails.teamReviewers = config.prTeamReviewers;

          const pr = await createOrUpdatePr(prDetails, config);

          if (pr) prsCreated++;
        } catch (error) {
          const msg = `Failed to push/create PR: ${String(error)}`;
          logger.error(msg);
          errors.push(msg);
        }
      }
    }
  }

  // 5. Create GitHub Issues for unfixable findings
  try {
    issuesCreated = await createOrUpdateIssues(unfixable, config);
  } catch (error) {
    const msg = `Failed to create GitHub issues: ${String(error)}`;
    logger.error(msg);
    errors.push(msg);
  }

  // 6. Build report
  const fixedCount = fixResults.reduce((sum, r) => sum + r.fixedFindings.length, 0);
  const report: RemediationReport = {
    timestamp: new Date().toISOString(),
    repository: config.githubRepository,
    targetBranch: config.targetBranch,
    severityThreshold: config.severityThreshold,
    totalFindings: allIssues.length,
    fixableFindings: fixable.length,
    fixedFindings: fixedCount,
    unfixableFindings: unfixable.length,
    dryRun: config.dryRun,
    fixResults,
    issuesCreated,
    prsCreated,
    errors,
  };

  // 7. Write reports
  writeJsonReport(report, workingDir);
  writeSarifReport(allIssues, config.githubRepository, workingDir);
  writeStepSummary(report);

  // 8. Determine exit code
  if (errors.length > 0) {
    logger.error(`Completed with ${errors.length} error(s)`);
    process.exit(1);
  }

  if (config.failOnNoFix && fixedCount === 0 && fixable.length > 0) {
    logger.warn('FAIL_ON_NO_FIX=true and no fixes were applied');
    process.exit(2);
  }

  logger.info(`✅ Snyk Auto-Remediation complete. Fixed: ${fixedCount}, Issues created: ${issuesCreated}, PRs created: ${prsCreated}`);
  process.exit(0);
}

main().catch((error: unknown) => {
  logger.error(`Fatal error: ${String(error)}`);
  process.exit(1);
});
