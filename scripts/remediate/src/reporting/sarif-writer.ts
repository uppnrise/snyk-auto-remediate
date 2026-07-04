import { writeFileSync } from 'fs';
import { join } from 'path';
import type { SnykIssue } from '../snyk/types.js';
import { logger } from '../utils/logger.js';

export interface SarifResult {
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

export interface SarifRun {
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

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  properties?: { tags: string[]; security_severity: string };
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

export function buildSarifOutput(issues: SnykIssue[], repository: string): SarifLog {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const ruleIds = new Set<string>();

  for (const issue of issues) {
    const attrs = issue.attributes;
    const ruleId = issue.id;

    if (!ruleIds.has(ruleId)) {
      ruleIds.add(ruleId);
      const problem = attrs.problems?.[0];
      const rule: SarifRule = {
        id: ruleId,
        name: attrs.title.replace(/\s+/g, '_'),
        shortDescription: { text: attrs.title },
        helpUri: problem?.url ?? `https://security.snyk.io/vuln/${ruleId}`,
        properties: {
          tags: ['security', attrs.effective_severity_level],
          security_severity: severityToCvss(attrs.effective_severity_level),
        },
      };
      if (attrs.description) {
        rule.fullDescription = { text: attrs.description };
      }
      rules.push(rule);
    }

    const affectedFile = attrs.coordinates?.[0]?.representations?.[0]?.resourcePath ?? '.';

    results.push({
      ruleId,
      level: severityToLevel(attrs.effective_severity_level),
      message: {
        text: `${attrs.title} — ${attrs.effective_severity_level} severity vulnerability found in ${repository}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: affectedFile },
          },
        },
      ],
    });
  }

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
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
): void {
  const sarif = buildSarifOutput(issues, repository);
  const filePath = join(outputPath, 'snyk-remediation-report.sarif');
  writeFileSync(filePath, JSON.stringify(sarif, null, 2), 'utf-8');
  logger.info(`SARIF report written to: ${filePath}`);
}
