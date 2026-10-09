import { readFileSync } from 'fs';
import { pathToFileURL } from 'url';
import { gzipSync } from 'zlib';
import { GitHubApiClient } from '../github/api-client.js';
import { execCommand } from '../utils/exec.js';

export interface SarifTarget {
  repository: string;
  ref: string;
  sha: string;
  checkoutUri: string;
}

/** Associate results with the commit actually scanned, including unmerged fixes. */
export async function resolveSarifTarget(
  workingDirectory: string,
  repository: string,
  targetBranch: string,
): Promise<SarifTarget> {
  async function git(...args: string[]): Promise<string> {
    return (await execCommand('git', args, { cwd: workingDirectory })).stdout.trim();
  }
  const sha = await git('rev-parse', '--verify', 'HEAD');
  const originalSha = await git('rev-parse', '--verify', `refs/remotes/origin/${targetBranch}`);
  let ref = `refs/heads/${targetBranch}`;
  if (sha !== originalSha) {
    try {
      ref = await git('symbolic-ref', '--quiet', 'HEAD');
      if (!ref.startsWith('refs/heads/')) throw new Error('Expected a branch');
      const publishedSha = await git(
        'rev-parse',
        '--verify',
        `refs/remotes/origin/${ref.slice(11)}`,
      );
      if (publishedSha !== sha) throw new Error('Remote branch differs from scanned commit');
    } catch (error) {
      throw new Error(`SARIF requires a published scanned commit: ${String(error)}`, {
        cause: error,
      });
    }
  }
  return {
    repository,
    ref,
    sha,
    checkoutUri: pathToFileURL(await git('rev-parse', '--show-toplevel')).href,
  };
}

export async function uploadSarif(
  file: string,
  target: SarifTarget,
  token: string,
  options: { category?: string; pollIntervalMs?: number; maxPolls?: number } = {},
): Promise<string> {
  let report = readFileSync(file, 'utf8');
  if (options.category) {
    const parsed = JSON.parse(report) as { runs: Array<{ automationDetails?: { id: string } }> };
    for (const run of parsed.runs) {
      run.automationDetails = { id: `${options.category}/` };
    }
    report = JSON.stringify(parsed);
  }
  const client = new GitHubApiClient(token, target.repository);
  const id = await client.uploadSarif({
    commit_sha: target.sha,
    ref: target.ref,
    checkout_uri: target.checkoutUri,
    sarif: gzipSync(report).toString('base64'),
  });
  const maxPolls = options.maxPolls ?? 60;
  for (let attempt = 0; attempt < maxPolls; attempt++) {
    const status = await client.getSarifStatus(id);
    if (status.processing_status === 'complete') return id;
    if (status.processing_status === 'failed') {
      throw new Error(`SARIF processing failed: ${status.errors?.join('; ') ?? id}`);
    }
    if (attempt + 1 < maxPolls) {
      await new Promise((resolve) => setTimeout(resolve, options.pollIntervalMs ?? 2000));
    }
  }
  throw new Error(`SARIF processing timed out: ${id}`);
}
