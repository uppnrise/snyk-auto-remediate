import { join } from 'path';
import { resolveSarifTarget, uploadSarif } from './reporting/sarif-uploader.js';
import { logger } from './utils/logger.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required for SARIF upload`);
  return value;
}

async function main(): Promise<void> {
  const directory = required('WORKING_DIRECTORY');
  const target = await resolveSarifTarget(
    directory,
    required('GITHUB_REPOSITORY'),
    required('TARGET_BRANCH'),
  );
  const id = await uploadSarif(
    join(directory, 'snyk-remediation-report.sarif'),
    target,
    required('GITHUB_TOKEN'),
    { category: required('SARIF_CATEGORY') },
  );
  logger.info(`SARIF processed for ${target.repository}@${target.ref} (${target.sha}): ${id}`);
}

main().catch((error: unknown) => {
  logger.error(String(error));
  process.exitCode = 1;
});
