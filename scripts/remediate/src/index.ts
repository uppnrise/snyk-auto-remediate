import { loadConfig } from './utils/config.js';
import { logger } from './utils/logger.js';
import { deduplicateIssues } from './utils/dedup.js';
import { detectEcosystems } from './detectors/language-detector.js';
import type { BaseFixer } from './fixers/base-fixer.js';
import { ExactActionFixer } from './fixers/exact-action-fixer.js';
import { createOrUpdateIssues } from './github/issue-creator.js';
import { createOrUpdatePr, buildPrBody } from './github/pr-creator.js';
import { writeJsonReport } from './reporting/json-writer.js';
import { selectReportableIssues, writeSarifReport } from './reporting/sarif-writer.js';
import { writeStepSummary } from './reporting/summary-writer.js';
import {
  gitHasChanges,
  gitAddAll,
  gitCommit,
  gitCheckoutBranch,
  buildRemediationBranchName,
  gitConfigureUser,
  gitPush,
} from './utils/git.js';
import { runPostFixTests } from './utils/test-runner.js';
import { prepareForSnykScan } from './utils/dependency-preparer.js';
import type { FixResult, RemediationReport } from './snyk/types.js';
import { scanWithSnykCli } from './snyk/cli-runner.js';
import { loadIssueInventory } from './snyk/cli-inventory.js';
import { buildRemediationPlan, unresolvedFindingKeys } from './snyk/correlation.js';
import { resolve } from 'path';

const FIXERS: BaseFixer[] = [
  new ExactActionFixer('yarn'),
  new ExactActionFixer('pnpm'),
  new ExactActionFixer('npm'),
  new ExactActionFixer('poetry'),
  new ExactActionFixer('pip'),
  new ExactActionFixer('maven'),
  new ExactActionFixer('gradle'),
  new ExactActionFixer('go'),
  new ExactActionFixer('composer'),
];

async function main(): Promise<void> {
  logger.info('🚀 Snyk Auto-Remediation Engine starting...');

  const config = loadConfig();
  const workingDir = resolve(config.workingDirectory);
  const errors: string[] = [];
  const fixResults: FixResult[] = [];
  let issuesCreated = 0;
  let issuesUpdated = 0;
  let issuesClosed = 0;
  let issuesPlanned = 0;
  let prsCreated = 0;

  // 1. Detect ecosystems and obtain exact remediation evidence from local CLI scans.
  const ecosystems = detectEcosystems(workingDir, config.packageManagers);
  const cliFindings = (
    await Promise.all(
      ecosystems.map(async (ecosystem) => {
        try {
          await prepareForSnykScan(ecosystem);
          return await scanWithSnykCli(ecosystem, config.snykToken, config.snykOrgId);
        } catch (error) {
          errors.push(`Snyk CLI scan failed for ${ecosystem.packageManager}: ${String(error)}`);
          return [];
        }
      }),
    )
  ).flat();

  // 2. Prefer organization REST inventory, but retain a local CLI-only mode for plans without
  // API entitlement. Authentication and all other REST failures remain fatal.
  logger.info('Fetching Snyk issues...');
  let allIssues = await loadIssueInventory(config, cliFindings);
  allIssues = deduplicateIssues(allIssues);
  logger.info(`Total unique issues: ${allIssues.length}`);

  const plan = buildRemediationPlan(allIssues, cliFindings, {
    ...(config.snykProjectIds ? { scopedProjectIds: config.snykProjectIds } : {}),
  });
  const runtimeNonActionable = [...plan.nonActionable];
  const findingsById = new Map(allIssues.map((issue) => [issue.id, issue]));
  const actionableIds = new Set(plan.actions.flatMap((action) => action.findingIds));
  const fixable = allIssues.filter((issue) => actionableIds.has(issue.id));
  const unfixable = plan.nonActionable.map((item) => item.issue);
  logger.info(`Actionable: ${fixable.length}, fallback: ${unfixable.length}`);

  // 3. Apply and verify exact actions per ecosystem.
  if (plan.actions.length > 0 && ecosystems.length > 0) {
    // Configure git user for commits
    if (!config.dryRun) {
      await gitConfigureUser(workingDir);
    }

    // Create remediation branch
    const branchName = buildRemediationBranchName(
      config.targetBranch,
      config.remediationBranchSuffix,
    );
    logger.info(`Using branch: ${branchName}`);

    if (!config.dryRun) {
      await gitCheckoutBranch(workingDir, branchName, true);
    }

    for (const ecosystem of ecosystems) {
      const fixer = FIXERS.find((f) => f.packageManager === ecosystem.packageManager);
      if (!fixer) {
        logger.warn(`No fixer found for ${ecosystem.packageManager}`);
        continue;
      }

      const relevantActions = plan.actions.filter(
        (action) => action.packageManager === ecosystem.packageManager,
      );
      if (relevantActions.length === 0) {
        logger.info(`No ${ecosystem.packageManager} issues to fix, skipping`);
        continue;
      }
      logger.info(
        `Running ${ecosystem.packageManager} fixer on ${relevantActions.length} exact actions...`,
      );

      const result = await fixer.applyFix(workingDir, relevantActions, findingsById, config.dryRun);
      if (result.success && !config.dryRun) {
        try {
          const after = await scanWithSnykCli(ecosystem, config.snykToken, config.snykOrgId);
          const unverified = unresolvedFindingKeys(relevantActions, after);
          if (unverified.length > 0) {
            fixer.rollback();
            result.success = false;
            result.error = `verification_failed: ${unverified.join(', ')}`;
            result.failedFindings = result.fixedFindings;
            result.fixedFindings = [];
            result.changesApplied = [];
          } else {
            result.verifiedFindingIds = relevantActions.flatMap((action) => action.findingIds);
          }
        } catch (error) {
          fixer.rollback();
          result.success = false;
          result.error = `verification_failed: ${String(error)}`;
          result.failedFindings = result.fixedFindings;
          result.fixedFindings = [];
          result.changesApplied = [];
        }
      }
      fixResults.push(result);
      if (!result.success) {
        const reason = result.error?.startsWith('verification_failed')
          ? ('verification_failed' as const)
          : result.error?.includes('unsupported_manifest_shape')
            ? ('unsupported_manifest_shape' as const)
            : ('apply_failed' as const);
        for (const issue of result.failedFindings) {
          runtimeNonActionable.push({
            issue,
            reason,
            ...(result.error ? { detail: result.error } : {}),
          });
        }
      }

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
          for (const result of fixResults.filter((item) => item.success)) {
            for (const issue of result.fixedFindings) {
              runtimeNonActionable.push({ issue, reason: 'tests_failed', detail: msg });
            }
          }
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

          if (pr?.created) prsCreated++;
        } catch (error) {
          const msg = `Failed to push/create PR: ${String(error)}`;
          logger.error(msg);
          errors.push(msg);
        }
      }
    }
  }

  const fallbackIssues = [
    ...new Map(runtimeNonActionable.map((item) => [item.issue.id, item.issue])).values(),
  ];

  // 4. Create GitHub Issues for findings without a safe exact action or a verified fix.
  try {
    const issueSummary = await createOrUpdateIssues(fallbackIssues, config);
    issuesCreated = issueSummary.created;
    issuesUpdated = issueSummary.updated;
    issuesClosed = issueSummary.closed;
    issuesPlanned = issueSummary.planned;
  } catch (error) {
    const msg = `Failed to create GitHub issues: ${String(error)}`;
    logger.error(msg);
    errors.push(msg);
  }

  // 6. Build report
  const fixedCount = config.dryRun
    ? 0
    : fixResults.reduce((sum, r) => sum + (r.verifiedFindingIds?.length ?? 0), 0);
  const report: RemediationReport = {
    timestamp: new Date().toISOString(),
    repository: config.githubRepository,
    targetBranch: config.targetBranch,
    severityThreshold: config.severityThreshold,
    totalFindings: allIssues.length,
    fixableFindings: fixable.length,
    fixedFindings: fixedCount,
    unfixableFindings: fallbackIssues.length,
    dryRun: config.dryRun,
    fixResults,
    issuesCreated,
    issuesUpdated,
    issuesClosed,
    issuesPlanned,
    prsCreated,
    errors,
    actionableFindings: fixable.length,
    ambiguousFindings: plan.nonActionable.filter((x) => x.reason === 'ambiguous_upgrade_path')
      .length,
    unsupportedFindings: plan.nonActionable.filter((x) =>
      ['missing_coordinates', 'unsupported_manifest_shape', 'patch_only'].includes(x.reason),
    ).length,
    attemptedFindings: new Set(
      fixResults.flatMap((r) => r.attemptedActions ?? []).flatMap((a) => a.findingIds),
    ).size,
    verifiedFixedFindings: new Set(fixResults.flatMap((r) => r.verifiedFindingIds ?? [])).size,
    verificationFailedFindings: fixResults.filter((r) => r.error?.startsWith('verification_failed'))
      .length,
    fallbackFindings: fallbackIssues.length,
    nonActionable: runtimeNonActionable.map((x) => ({
      id: x.issue.id,
      key: x.issue.attributes.key,
      reason: x.reason,
      ...(x.detail ? { detail: x.detail } : {}),
    })),
  };

  // 7. Write reports
  writeJsonReport(report, workingDir);
  const verifiedIds = fixResults.flatMap((result) => result.verifiedFindingIds ?? []);
  const reportableIssues = selectReportableIssues(allIssues, verifiedIds, config.snykProjectIds);
  writeSarifReport(reportableIssues, config.githubRepository, workingDir);
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

  logger.info(
    `✅ Snyk Auto-Remediation complete. Fixed: ${fixedCount}, Issues created: ${issuesCreated}, PRs created: ${prsCreated}`,
  );
  process.exit(0);
}

main().catch((error: unknown) => {
  logger.error(`Fatal error: ${String(error)}`);
  process.exit(1);
});
