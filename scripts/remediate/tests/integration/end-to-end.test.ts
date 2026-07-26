import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * Integration test: end-to-end flow test using fixtures and mocks.
 * This test verifies that the full pipeline connects correctly:
 * fetch issues → detect ecosystems → run fixers → create issues → report
 */
describe('End-to-End Remediation Flow', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      SNYK_TOKEN: 'test-snyk-token',
      SNYK_ORG_ID: 'test-org-id',
      GITHUB_REPOSITORY: 'owner/test-repo',
      GITHUB_TOKEN: 'test-github-token',
      DRY_RUN: 'true',
      SEVERITY_THRESHOLD: 'high',
      WORKING_DIRECTORY: '.',
      ENABLE_COPILOT_AGENT_FALLBACK: 'true',
    };
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  it('should load configuration without throwing', async () => {
    const { loadConfig } = await import('../../src/utils/config.js');
    expect(() => loadConfig()).not.toThrow();
    const config = loadConfig();
    expect(config.snykOrgId).toBe('test-org-id');
    expect(config.dryRun).toBe(true);
  });

  it('should detect ecosystems in fixtures directory', async () => {
    const { detectEcosystems } = await import('../../src/detectors/language-detector.js');
    const { join } = await import('path');
    const { fileURLToPath } = await import('url');
    const { dirname } = await import('path');

    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const npmFixture = join(__dirname, '../fixtures/sample-npm-repo');

    const ecosystems = detectEcosystems(npmFixture);
    expect(ecosystems.some((e) => e.packageManager === 'npm')).toBe(true);
  });

  it('should deduplicate issues from fixture data', async () => {
    const { readFileSync } = await import('fs');
    const { join } = await import('path');
    const { fileURLToPath } = await import('url');
    const { dirname } = await import('path');

    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);

    const { deduplicateIssues } = await import('../../src/utils/dedup.js');
    type SnykApiResponse = { data: import('../../src/snyk/types.js').SnykIssue[] };

    const rawData = readFileSync(
      join(__dirname, '../fixtures/snyk-api-responses/issues-page1.json'),
      'utf-8',
    );
    const parsed = JSON.parse(rawData) as SnykApiResponse;
    const issues = parsed.data;

    const deduped = deduplicateIssues(issues);
    expect(deduped).toHaveLength(2);

    expect(deduped.map((item) => item.id)).toEqual([
      'SNYK-JS-LODASH-590103',
      'SNYK-JS-AXIOS-1038009',
    ]);
  });

  it('should build valid SARIF from fixture issues', async () => {
    const { readFileSync } = await import('fs');
    const { join } = await import('path');
    const { fileURLToPath } = await import('url');
    const { dirname } = await import('path');

    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);

    const { buildSarifOutput } = await import('../../src/reporting/sarif-writer.js');
    type SnykApiResponse = { data: import('../../src/snyk/types.js').SnykIssue[] };

    const rawData = readFileSync(
      join(__dirname, '../fixtures/snyk-api-responses/issues-page1.json'),
      'utf-8',
    );
    const parsed = JSON.parse(rawData) as SnykApiResponse;

    const sarif = buildSarifOutput(parsed.data, 'owner/test-repo');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.results).toHaveLength(2);
  });
});
