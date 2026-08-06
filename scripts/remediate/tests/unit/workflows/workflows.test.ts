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
      'WORKING_DIRECTORY: ${{ github.workspace }}/${{ needs.prepare.outputs.target-path }}',
    );
  });

  it('uploads reports from the configured working directory', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain(
      'sarif_file: ${{ github.workspace }}/${{ needs.prepare.outputs.target-path }}/snyk-remediation-report.sarif',
    );
    expect(reusable).toContain(
      '${{ github.workspace }}/${{ needs.prepare.outputs.target-path }}/snyk-remediation-report.json',
    );
    expect(reusable).toContain('report-id:');
    expect(reusable).toContain(
      "name: snyk-remediation-${{ inputs['report-id'] }}-${{ strategy.job-index }}-${{ github.run_id }}",
    );
    expect(reusable).toContain("REMEDIATION_BRANCH_SUFFIX: ${{ inputs['report-id'] }}");
  });

  it('normalizes the root working directory for report actions', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain('echo "target_path=target" >> "$GITHUB_OUTPUT"');
    expect(reusable).toContain('echo "target_path=target/$working_directory" >> "$GITHUB_OUTPUT"');
    expect(reusable).not.toContain("hashFiles(format('target/{0}/");
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

  it('passes an explicit stable label for fallback-issue reconciliation', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain('issue-management-label:');
    expect(reusable).toContain("default: 'snyk'");
    expect(reusable).toContain("ISSUE_MANAGEMENT_LABEL: ${{ inputs['issue-management-label'] }}");
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

  it('pins the Snyk CLI and serializes remediation for the same target branch', () => {
    const reusable = workflow('snyk-remediate.reusable.yml');
    expect(reusable).toContain('npm install -g snyk@1.1306.1');
    expect(reusable).toContain('concurrency:');
    expect(reusable).toContain('cancel-in-progress: false');
    expect(reusable).not.toContain('max-prs-per-run');
    expect(workflow('snyk-remediate.yml')).not.toContain('max-prs-per-run');
  });
});
