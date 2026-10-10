import { writeFileSync } from 'fs';
import { isAbsolute, join, posix } from 'path';
import type { NonActionableFinding, SnykIssue } from '../snyk/types.js';
import { logger } from '../utils/logger.js';

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
}

export interface SarifLog {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  help?: { text: string; markdown: string };
  properties?: { tags: string[]; 'security-severity': string };
}

function severityToLevel(severity: string): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

function severityToCvss(severity: string): string {
  switch (severity) {
    case 'critical':
      return '9.0';
    case 'high':
      return '7.5';
    case 'medium':
      return '5.0';
    default:
      return '2.5';
  }
}

export function selectReportableIssues(
  issues: SnykIssue[],
  verifiedFindingIds: string[],
  scopedProjectIds?: string[],
): SnykIssue[] {
  const verified = new Set(verifiedFindingIds);
  const scoped = scopedProjectIds?.length ? new Set(scopedProjectIds) : undefined;
  return issues.filter(
    (issue) =>
      !verified.has(issue.id) &&
      (scoped === undefined || scoped.has(issue.relationships.scan_item.data.id)),
  );
}

export function buildSarifOutput(
  issues: SnykIssue[],
  repository: string,
  nonActionable: NonActionableFinding[] = [],
): SarifLog {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const ruleIds = new Set<string>();
  const reasons = new Map(nonActionable.map((finding) => [finding.issue.id, finding]));

  for (const issue of issues) {
    const attrs = issue.attributes;
    const ruleId = attrs.key;

    const advisory =
      attrs.problems?.find((problem) => problem.url)?.url ??
      `https://security.snyk.io/vuln/${ruleId}`;
    const cvss = attrs.problems
      ?.map((problem) => problem.cvss_score)
      .find(
        (score): score is number =>
          typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 10,
      );
    const score =
      cvss !== undefined ? String(cvss) : severityToCvss(attrs.effective_severity_level);
    const scoreContext =
      cvss !== undefined ? `CVSS: ${score} (upstream)` : `CVSS: ${score} (estimated from severity)`;
    const coordinates = attrs.coordinates ?? [];
    const representations = coordinates.flatMap((coordinate) => coordinate.representations ?? []);
    const dependencies = [
      ...new Set(
        representations.flatMap((representation) =>
          representation.dependency
            ? [
                `${representation.dependency.package_name}@${representation.dependency.package_version}`,
              ]
            : [],
        ),
      ),
    ];
    const remedyDescriptions = coordinates.flatMap((coordinate) =>
      (coordinate.remedies ?? []).flatMap((remedy) =>
        remedy.description ? [remedy.description] : [],
      ),
    );
    const reason = reasons.get(issue.id);
    const remediation = reason
      ? `Remediation: ${reason.reason}${reason.detail ? ` (${reason.detail})` : ''}`
      : `Remediation: ${remedyDescriptions.length ? 'fix not verified; review evidence below' : 'fix not verified; no exact upgrade evidence supplied'}`;

    if (!ruleIds.has(ruleId)) {
      ruleIds.add(ruleId);
      const rule: SarifRule = {
        id: ruleId,
        name: attrs.title.replace(/\s+/g, '_'),
        shortDescription: { text: attrs.title },
        fullDescription: { text: attrs.description || attrs.title },
        helpUri: advisory,
        help: {
          text: `${attrs.description || attrs.title}\nAdvisory: ${advisory}\n${scoreContext}\nReview the affected dependency and remediation evidence in the result.`,
          markdown: `${attrs.description || attrs.title}\n\n[Advisory](${advisory})\n\n${scoreContext}\n\nReview the affected dependency and remediation evidence in the result.`,
        },
        properties: {
          tags: ['security', attrs.effective_severity_level],
          'security-severity': score,
        },
      };
      rules.push(rule);
    }

    const affectedFile = representations
      .map((representation) => representation.resourcePath)
      .find((path) => {
        if (!path?.trim()) return false;
        const normalized = posix.normalize(path.replace(/\\/g, '/')).replace(/\/$/, '');
        return (
          normalized !== '.' &&
          normalized !== '..' &&
          !normalized.startsWith('../') &&
          !isAbsolute(normalized)
        );
      });
    const result: SarifResult = {
      ruleId,
      level: severityToLevel(attrs.effective_severity_level),
      message: {
        text: [
          `${attrs.title} — ${attrs.effective_severity_level} severity vulnerability found in ${repository}`,
          dependencies.length
            ? `Affected dependency: ${dependencies.join(', ')}`
            : 'Affected dependency: unknown',
          `Advisory: ${advisory}`,
          remediation,
          ...remedyDescriptions,
        ].join('. '),
      },
    };
    if (affectedFile) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: {
              uri: encodeURI(posix.normalize(affectedFile.replace(/\\/g, '/')))
                .replace(/#/g, '%23')
                .replace(/\?/g, '%3F'),
            },
          },
        },
      ];
    }
    results.push(result);
  }

  return {
    version: '2.1.0',
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Snyk Auto-Remediation',
            version: '1.0.0',
            informationUri: 'https://github.com/uppnrise/snyk-auto-remediate',
            rules,
          },
        },
        results,
      },
    ],
  };
}

export function writeSarifReport(
  issues: SnykIssue[],
  repository: string,
  outputPath: string,
  nonActionable: NonActionableFinding[] = [],
): void {
  const sarif = buildSarifOutput(issues, repository, nonActionable);
  const filePath = join(outputPath, 'snyk-remediation-report.sarif');
  writeFileSync(filePath, JSON.stringify(sarif, null, 2), 'utf-8');
  logger.info(`SARIF report written to: ${filePath}`);
}
