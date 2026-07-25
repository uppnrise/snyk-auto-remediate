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
    const entry = workflow('snyk-remediate.yml');
    expect(entry).not.toContain("'main'");
    expect(entry).toContain("'master'");
    expect(entry).toContain("working-directory: 'scripts/remediate'");
    expect(workflow('snyk-remediate.reusable.yml')).toContain("default: 'master'");
  });

  it('resolves a non-default working directory exactly once', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    const engineStep = reusable.slice(
      reusable.indexOf('- name: Run Snyk Auto-Remediation Engine'),
      reusable.indexOf('- name: Upload SARIF report'),
    );

    expect(engineStep).toContain(
      "WORKING_DIRECTORY: ${{ github.workspace }}/target/${{ inputs['working-directory'] }}",
    );
  });

  it('uploads reports from the configured working directory', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain(
      "sarif_file: ${{ github.workspace }}/target/${{ inputs['working-directory'] }}/snyk-remediation-report.sarif",
    );
    expect(reusable).toContain(
      "${{ github.workspace }}/target/${{ inputs['working-directory'] }}/snyk-remediation-report.json",
    );
  });

  it('checks out the target and remediation engine independently', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain('target-repository:');
    expect(reusable).toContain('engine-ref:');
    expect(reusable).toContain(
      "repository: ${{ inputs['target-repository'] || github.repository }}",
    );
    expect(reusable).toContain('repository: uppnrise/snyk-auto-remediate');
    expect(reusable).toContain('path: target');
    expect(reusable).toContain('path: .snyk-auto-remediate');
    expect(reusable).toContain(
      "GITHUB_REPOSITORY: ${{ inputs['target-repository'] || github.repository }}",
    );
    expect(reusable).toContain('target-repository must use owner/repo syntax');
    expect(reusable).toContain('working-directory must stay inside the target repository');
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
