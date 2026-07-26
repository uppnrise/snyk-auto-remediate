import { existsSync } from 'fs';
import { join } from 'path';
import { logger } from '../utils/logger.js';
import type { DetectedEcosystem, PackageManager } from '../snyk/types.js';

interface EcosystemSignature {
  packageManager: PackageManager;
  manifestFiles: string[];
}

const ECOSYSTEM_SIGNATURES: EcosystemSignature[] = [
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
  const allowed = (manager: PackageManager): boolean =>
    allowedManagers === undefined || allowedManagers.includes(manager);
  const add = (packageManager: PackageManager, manifestFiles: string[]): void => {
    if (!allowed(packageManager)) return;
    detected.push({ packageManager, manifestFiles, workingDirectory });
    logger.debug(`Detected ${packageManager} ecosystem (files: ${manifestFiles.join(', ')})`);
  };

  if (allowed('pnpm') && existsSync(join(workingDirectory, 'pnpm-lock.yaml'))) {
    add(
      'pnpm',
      ['package.json', 'pnpm-lock.yaml'].filter((file) => existsSync(join(workingDirectory, file))),
    );
  } else if (allowed('yarn') && existsSync(join(workingDirectory, 'yarn.lock'))) {
    add(
      'yarn',
      ['package.json', 'yarn.lock'].filter((file) => existsSync(join(workingDirectory, file))),
    );
  } else if (
    allowed('npm') &&
    (existsSync(join(workingDirectory, 'package-lock.json')) ||
      existsSync(join(workingDirectory, 'package.json')))
  ) {
    add(
      'npm',
      ['package.json', 'package-lock.json'].filter((file) =>
        existsSync(join(workingDirectory, file)),
      ),
    );
  }

  if (existsSync(join(workingDirectory, 'poetry.lock'))) {
    add(
      'poetry',
      ['pyproject.toml', 'poetry.lock'].filter((file) => existsSync(join(workingDirectory, file))),
    );
  }

  for (const sig of ECOSYSTEM_SIGNATURES) {
    if (allowedManagers && !allowedManagers.includes(sig.packageManager)) {
      continue;
    }

    const foundFiles = sig.manifestFiles.filter((file) => existsSync(join(workingDirectory, file)));

    if (foundFiles.length > 0) {
      add(sig.packageManager, foundFiles);
    }
  }

  logger.info(`Detected ecosystems: ${detected.map((d) => d.packageManager).join(', ') || 'none'}`);
  return detected;
}
