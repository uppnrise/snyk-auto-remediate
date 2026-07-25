import { existsSync } from 'fs';
import { join } from 'path';
import { logger } from '../utils/logger.js';
import type { DetectedEcosystem, PackageManager } from '../snyk/types.js';

interface EcosystemSignature {
  packageManager: PackageManager;
  manifestFiles: string[];
}

const ECOSYSTEM_SIGNATURES: EcosystemSignature[] = [
  { packageManager: 'yarn', manifestFiles: ['yarn.lock'] },
  { packageManager: 'npm', manifestFiles: ['package-lock.json', 'package.json'] },
  { packageManager: 'poetry', manifestFiles: ['poetry.lock', 'pyproject.toml'] },
  { packageManager: 'pip', manifestFiles: ['requirements.txt'] },
  { packageManager: 'maven', manifestFiles: ['pom.xml'] },
  { packageManager: 'gradle', manifestFiles: ['build.gradle', 'build.gradle.kts'] },
  { packageManager: 'go', manifestFiles: ['go.mod'] },
  { packageManager: 'composer', manifestFiles: ['composer.json', 'composer.lock'] },
];

export function detectEcosystems(
  workingDirectory: string,
  allowedManagers?: PackageManager[],
): DetectedEcosystem[] {
  const detected: DetectedEcosystem[] = [];

  for (const sig of ECOSYSTEM_SIGNATURES) {
    if (allowedManagers && !allowedManagers.includes(sig.packageManager)) {
      continue;
    }

    const foundFiles = sig.manifestFiles.filter((file) => existsSync(join(workingDirectory, file)));

    if (foundFiles.length > 0) {
      detected.push({
        packageManager: sig.packageManager,
        manifestFiles: foundFiles,
        workingDirectory,
      });
      logger.debug(`Detected ${sig.packageManager} ecosystem (files: ${foundFiles.join(', ')})`);
    }
  }

  logger.info(`Detected ecosystems: ${detected.map((d) => d.packageManager).join(', ') || 'none'}`);
  return detected;
}
