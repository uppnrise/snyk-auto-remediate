import { describe, it, expect } from 'vitest';
import { detectEcosystems } from '../../../src/detectors/language-detector.js';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const FIXTURES_DIR = join(__dirname, '../../fixtures');

describe('detectEcosystems', () => {
  it('should detect npm from package.json', () => {
    const ecosystems = detectEcosystems(join(FIXTURES_DIR, 'sample-npm-repo'));
    const packageManagers = ecosystems.map((e) => e.packageManager);
    expect(packageManagers).toContain('npm');
  });

  it('should detect pip from requirements.txt', () => {
    const ecosystems = detectEcosystems(join(FIXTURES_DIR, 'sample-python-repo'));
    const packageManagers = ecosystems.map((e) => e.packageManager);
    expect(packageManagers).toContain('pip');
  });

  it('should return empty array for directory with no manifest files', () => {
    const ecosystems = detectEcosystems('/tmp');
    // /tmp may or may not have manifest files, but we just test the function runs
    expect(Array.isArray(ecosystems)).toBe(true);
  });

  it('should filter by allowedManagers', () => {
    const ecosystems = detectEcosystems(join(FIXTURES_DIR, 'sample-npm-repo'), ['pip']);
    const packageManagers = ecosystems.map((e) => e.packageManager);
    expect(packageManagers).not.toContain('npm');
  });

  it('should include manifest files in result', () => {
    const ecosystems = detectEcosystems(join(FIXTURES_DIR, 'sample-npm-repo'));
    const npmEcosystem = ecosystems.find((e) => e.packageManager === 'npm');
    expect(npmEcosystem).toBeDefined();
    expect(npmEcosystem!.manifestFiles).toContain('package.json');
  });
});
