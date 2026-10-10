import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { normalizeCliOutput } from '../../src/snyk/correlation.js';
import { buildCliInventory } from '../../src/snyk/cli-inventory.js';
import { buildSarifOutput } from '../../src/reporting/sarif-writer.js';
import type { DetectedEcosystem, SnykIssue } from '../../src/snyk/types.js';

const directories: string[] = [];
afterEach(() =>
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true })),
);

function scan(directory: string, ecosystem: DetectedEcosystem, targetFile?: string): SnykIssue[] {
  const findings = normalizeCliOutput(
    {
      projectName: 'local-project',
      ...(targetFile === undefined ? {} : { targetFile }),
      vulnerabilities: [
        {
          id: 'SNYK-TEST-001',
          title: 'Dependency vulnerability',
          severity: 'high',
          packageName: 'affected-package',
          version: '1.0.0',
          description: 'Upstream advisory description',
          cvssScore: 8.1,
          fixedIn: ['2.0.0'],
          upgradePath: ['affected-package@2.0.0'],
          isUpgradable: true,
        },
      ],
    },
    ecosystem,
    directory,
  );
  return buildCliInventory(findings, 'org', 'low');
}

describe('CLI inventory to SARIF', () => {
  it.each([
    ['maven', '.', 'pom.xml'],
    ['npm', 'examples/web-dashboard', 'package.json'],
  ] as const)(
    'reports a real repository-relative manifest for %s',
    (packageManager, prefix, manifest) => {
      const root = mkdtempSync(join(tmpdir(), 'cli-sarif-'));
      directories.push(root);
      const workingDirectory = join(root, prefix);
      mkdirSync(workingDirectory, { recursive: true });
      writeFileSync(join(workingDirectory, manifest), '');
      const issues = scan(prefix, { packageManager, workingDirectory, manifestFiles: [manifest] });
      const sarif = buildSarifOutput(issues, 'owner/repo');
      const rule = sarif.runs[0]!.tool.driver.rules[0]!;
      const result = sarif.runs[0]!.results[0]!;
      expect(result.locations).toEqual([
        {
          physicalLocation: {
            artifactLocation: { uri: prefix === '.' ? manifest : `${prefix}/${manifest}` },
          },
        },
      ]);
      expect(rule.fullDescription?.text).toBe('Upstream advisory description');
      expect(rule.help?.text).toContain('Upstream advisory description');
      expect(rule.help?.markdown).toContain('https://security.snyk.io/vuln/SNYK-TEST-001');
      expect(rule.properties?.['security-severity']).toBe('8.1');
      expect(rule.properties).not.toHaveProperty('security_severity');
      expect(result.message.text).toContain('affected-package@1.0.0');
      expect(result.message.text).toContain('affected-package@2.0.0');
      expect(result.message.text).toContain('2.0.0');
    },
  );

  it('uses the CLI target file to distinguish multi-project manifests', () => {
    const root = mkdtempSync(join(tmpdir(), 'cli-sarif-'));
    directories.push(root);
    mkdirSync(join(root, 'module'));
    writeFileSync(join(root, 'pom.xml'), '');
    writeFileSync(join(root, 'module/pom.xml'), '');
    const issues = scan(
      'backend',
      { packageManager: 'maven', workingDirectory: root, manifestFiles: ['pom.xml'] },
      'module/pom.xml',
    );
    expect(
      buildSarifOutput(issues, 'owner/repo').runs[0]!.results[0]!.locations?.[0]?.physicalLocation
        .artifactLocation.uri,
    ).toBe('backend/module/pom.xml');
  });

  it.each([undefined, '.', 'missing.xml', '../outside.xml'])(
    'omits missing or invalid location evidence (%s)',
    (targetFile) => {
      const root = mkdtempSync(join(tmpdir(), 'cli-sarif-'));
      directories.push(root);
      const issues = scan(
        '.',
        { packageManager: 'maven', workingDirectory: root, manifestFiles: [] },
        targetFile,
      );
      const sarif = buildSarifOutput(issues, 'owner/repo', [
        { issue: issues[0]!, reason: 'missing_exact_target' },
      ]);
      expect(sarif.runs[0]!.results[0]).not.toHaveProperty('locations');
      expect(sarif.runs[0]!.results[0]!.message.text).toContain('missing_exact_target');
    },
  );
});
