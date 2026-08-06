import { createHash } from 'crypto';
import { logger } from '../utils/logger.js';
import { fetchSnykIssues, SnykApiError } from './api-client.js';
import type {
  CliVulnerability,
  RemediationConfig,
  Severity,
  SeverityThreshold,
  SnykIssue,
} from './types.js';

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function shouldCollectCliFindings(
  config: Pick<RemediationConfig, 'snykProjectIds'>,
): boolean {
  return !config.snykProjectIds?.length;
}

function stableIssueId(finding: CliVulnerability): string {
  const identity = [
    finding.projectId ?? finding.projectName ?? finding.packageManager,
    finding.issueKey,
    finding.packageName,
    finding.version,
  ].join('\0');
  const hash = createHash('sha256').update(identity).digest('hex').slice(0, 32);
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20)}`;
}

export function buildCliInventory(
  findings: CliVulnerability[],
  organizationId: string,
  threshold: SeverityThreshold,
): SnykIssue[] {
  const issues = new Map<string, SnykIssue>();
  for (const finding of findings) {
    const severity = finding.severity ?? 'low';
    if (severityRank[severity] < severityRank[threshold]) continue;
    const id = stableIssueId(finding);
    if (issues.has(id)) continue;
    const projectId =
      finding.projectId ?? finding.projectName ?? `local-${finding.packageManager}-project`;
    issues.set(id, {
      id,
      type: 'issue',
      attributes: {
        key: finding.issueKey,
        title: finding.title ?? finding.issueKey,
        type: 'package_vulnerability',
        created_at: '1970-01-01T00:00:00.000Z',
        updated_at: '1970-01-01T00:00:00.000Z',
        effective_severity_level: severity,
        status: 'open',
        ignored: false,
        coordinates: [
          {
            is_upgradeable: finding.isUpgradable,
            is_patchable: finding.isPatchable,
            representations: [
              {
                dependency: {
                  package_name: finding.packageName,
                  package_version: finding.version,
                },
              },
            ],
          },
        ],
      },
      relationships: {
        organization: { data: { id: organizationId, type: 'organization' } },
        scan_item: { data: { id: projectId, type: 'project' } },
      },
    });
  }
  return [...issues.values()];
}

export async function loadIssueInventory(
  config: RemediationConfig,
  cliFindings: CliVulnerability[],
  restFetcher: (config: RemediationConfig) => Promise<SnykIssue[]> = fetchSnykIssues,
  cliFallbackLoader: () => Promise<CliVulnerability[]> = () => Promise.resolve(cliFindings),
): Promise<SnykIssue[]> {
  if (!config.snykProjectIds?.length) {
    logger.info(
      'No SNYK_PROJECT_IDS configured; using repository-local CLI inventory to avoid organization-wide cross-repository findings',
    );
    return buildCliInventory(cliFindings, config.snykOrgId, config.severityThreshold);
  }
  try {
    return await restFetcher(config);
  } catch (error) {
    if (!(error instanceof SnykApiError) || error.status !== 403) throw error;
    logger.warn(
      'Snyk REST issue inventory is forbidden; using local CLI-only inventory for detected projects',
    );
    const fallbackFindings = cliFindings.length > 0 ? cliFindings : await cliFallbackLoader();
    return buildCliInventory(fallbackFindings, config.snykOrgId, config.severityThreshold);
  }
}
