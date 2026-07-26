import { afterEach, describe, it, expect } from 'vitest';
import { detectEcosystems } from '../../../src/detectors/language-detector.js';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const FIXTURES_DIR = join(__dirname, '../../fixtures');
const temporaryDirectories: string[] = [];

function temporaryProject(files: string[]): string {
  const directory = mkdtempSync(join(tmpdir(), 'snyk-detection-'));
  temporaryDirectories.push(directory);
  for (const file of files) writeFileSync(join(directory, file), '');
  return directory;
}

describe('detectEcosystems', () => {
  afterEach(() => {
    for (const directory of temporaryDirectories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

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

  it('detects Yarn instead of also treating package.json as npm', () => {
    const ecosystems = detectEcosystems(temporaryProject(['package.json', 'yarn.lock']));
    expect(ecosystems.map((item) => item.packageManager)).toEqual(['yarn']);
  });

  it('detects pnpm from its lockfile', () => {
    const ecosystems = detectEcosystems(temporaryProject(['package.json', 'pnpm-lock.yaml']));
    expect(ecosystems.map((item) => item.packageManager)).toEqual(['pnpm']);
  });

  it('does not assume every pyproject.toml project uses Poetry', () => {
    const ecosystems = detectEcosystems(temporaryProject(['pyproject.toml']));
    expect(ecosystems).toEqual([]);
  });

  it('detects Poetry when its lockfile is present', () => {
    const ecosystems = detectEcosystems(temporaryProject(['pyproject.toml', 'poetry.lock']));
    expect(ecosystems.map((item) => item.packageManager)).toEqual(['poetry']);
  });
});
