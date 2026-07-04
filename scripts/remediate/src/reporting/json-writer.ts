import { writeFileSync } from 'fs';
import { join } from 'path';
import type { RemediationReport } from '../snyk/types.js';
import { logger } from '../utils/logger.js';

export function writeJsonReport(report: RemediationReport, outputPath: string): void {
  const filePath = join(outputPath, 'snyk-remediation-report.json');
  writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf-8');
  logger.info(`JSON report written to: ${filePath}`);
}
