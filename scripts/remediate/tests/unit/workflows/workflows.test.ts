import { readFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from 'vitest';

const currentDirectory = dirname(fileURLToPath(import.meta.url));
const workflowsDirectory = resolve(currentDirectory, '../../../../../.github/workflows');

function workflow(name: string): string {
  return readFileSync(resolve(workflowsDirectory, name), 'utf8');
}

describe('GitHub Actions workflows', () => {
  it('defaults remediation to the repository default branch', () => {
    expect(workflow('snyk-remediate.yml')).not.toContain("'main'");
    expect(workflow('snyk-remediate.yml')).toContain("'master'");
    expect(workflow('snyk-remediate.reusable.yml')).toContain("default: 'master'");
  });

  it('resolves a non-default working directory exactly once', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    const engineStep = reusable.slice(
      reusable.indexOf('- name: Run Snyk Auto-Remediation Engine'),
      reusable.indexOf('- name: Upload SARIF report'),
    );

    expect(engineStep).not.toContain("working-directory: ${{ inputs['working-directory'] }}");
    expect(engineStep).toContain("WORKING_DIRECTORY: ${{ inputs['working-directory'] }}");
  });

  it('uploads reports from the configured working directory', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain(
      "sarif_file: ${{ inputs['working-directory'] }}/snyk-remediation-report.sarif",
    );
    expect(reusable).toContain("${{ inputs['working-directory'] }}/snyk-remediation-report.json");
  });

  it('fails fast with an actionable error when the Snyk token is unavailable', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain('if [ -z "$SNYK_TOKEN" ]; then');
    expect(reusable).toContain('::error::SNYK_TOKEN is required');
  });

  it('runs the complete validation suite for pull requests and pushes to master', () => {
    const ci = workflow('ci.yml');
    expect(ci).toContain('pull_request:');
    expect(ci).toContain('branches: [master]');
    expect(ci).toContain('rhysd/actionlint:1.7.12');
    expect(ci).toContain('npm run format:check');
    expect(ci).toContain('npm run lint');
    expect(ci).toContain('npm test -- --run');
    expect(ci).toContain('npm run build');
  });
});
