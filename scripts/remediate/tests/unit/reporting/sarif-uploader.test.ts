import { execFileSync } from 'child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { gunzipSync } from 'zlib';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolveSarifTarget, uploadSarif } from '../../../src/reporting/sarif-uploader.js';

describe('SARIF upload targeting and processing', () => {
  let directory: string;
  let initialSha: string;
  const fetchMock = vi.fn<typeof fetch>();
  function git(...args: string[]): string {
    return execFileSync('git', args, { cwd: directory, encoding: 'utf8' }).trim();
  }
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'snyk-sarif-target-'));
    git('init', '-q', '--initial-branch=release/1.0');
    git('config', 'user.name', 'test');
    git('config', 'user.email', 'test@example.test');
    writeFileSync(join(directory, 'package.json'), '{"version":"1.0.0"}\n');
    git('add', 'package.json');
    git('commit', '-q', '-m', 'initial');
    initialSha = git('rev-parse', 'HEAD');
    git('update-ref', 'refs/remotes/origin/release/1.0', initialSha);
    writeFileSync(join(directory, 'report.sarif'), '{"version":"2.1.0","runs":[]}');
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    rmSync(directory, { recursive: true, force: true });
  });
  it('uses the target branch and checkout SHA for an unchanged detached checkout', async () => {
    git('checkout', '-q', '--detach');
    const target = await resolveSarifTarget(directory, 'target-owner/target-repo', 'release/1.0');
    expect(target).toMatchObject({
      repository: 'target-owner/target-repo',
      ref: 'refs/heads/release/1.0',
      sha: initialSha,
    });
  });
  it('uses the published remediation branch and scanned commit after a fix', async () => {
    git('checkout', '-q', '-b', 'chore/security/remediation');
    writeFileSync(join(directory, 'package.json'), '{"version":"2.0.0"}\n');
    git('commit', '-q', '-am', 'fix');
    const sha = git('rev-parse', 'HEAD');
    git('update-ref', 'refs/remotes/origin/chore/security/remediation', sha);
    expect(await resolveSarifTarget(directory, 'target/repo', 'release/1.0')).toMatchObject({
      ref: 'refs/heads/chore/security/remediation',
      sha,
    });
  });
  it('keeps the target ref when an unsuccessful remediation branch has no commits', async () => {
    git('checkout', '-q', '-b', 'chore/security/empty');
    expect(await resolveSarifTarget(directory, 'target/repo', 'release/1.0')).toMatchObject({
      ref: 'refs/heads/release/1.0',
      sha: initialSha,
    });
  });
  it('rejects an unpublished remediation commit', async () => {
    git('checkout', '-q', '-b', 'chore/security/unpublished');
    writeFileSync(join(directory, 'package.json'), '{"version":"2.0.0"}\n');
    git('commit', '-q', '-am', 'local fix');
    await expect(resolveSarifTarget(directory, 'target/repo', 'release/1.0')).rejects.toThrow(
      'published',
    );
  });
  it('uploads to the scanned repository/ref/SHA and waits until processing completes', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response('{"id":"upload-id"}', { status: 202 }))
      .mockResolvedValueOnce(new Response('{"processing_status":"pending"}'))
      .mockResolvedValueOnce(new Response('{"processing_status":"complete"}'));
    const target = await resolveSarifTarget(
      directory,
      'different-owner/scanned-repo',
      'release/1.0',
    );
    await expect(
      uploadSarif(join(directory, 'report.sarif'), target, 'test-token', {
        pollIntervalMs: 0,
        maxPolls: 3,
      }),
    ).resolves.toBe('upload-id');
    const [url, options] = fetchMock.mock.calls[0]!;
    expect(url).toBe(
      'https://api.github.com/repos/different-owner/scanned-repo/code-scanning/sarifs',
    );
    const payload = JSON.parse(options!.body as string) as {
      ref: string;
      commit_sha: string;
      sarif: string;
    };
    expect(payload.ref).toBe('refs/heads/release/1.0');
    expect(payload.commit_sha).toBe(initialSha);
    expect(gunzipSync(Buffer.from(payload.sarif, 'base64')).toString()).toBe(
      readFileSync(join(directory, 'report.sarif'), 'utf8'),
    );
    expect(fetchMock.mock.calls[2]![0]).toBe(
      'https://api.github.com/repos/different-owner/scanned-repo/code-scanning/sarifs/upload-id',
    );
  });
  it('reports asynchronous SARIF validation failures', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response('{"id":"upload-id"}', { status: 202 }))
      .mockResolvedValueOnce(
        new Response('{"processing_status":"failed","errors":["invalid SARIF"]}'),
      );
    const target = await resolveSarifTarget(directory, 'target/repo', 'release/1.0');
    await expect(
      uploadSarif(join(directory, 'report.sarif'), target, 'test-token'),
    ).rejects.toThrow('invalid SARIF');
  });
  it('isolates runs by the requested report category', async () => {
    writeFileSync(
      join(directory, 'report.sarif'),
      JSON.stringify({ version: '2.1.0', runs: [{ tool: {}, results: [] }] }),
    );
    fetchMock
      .mockResolvedValueOnce(new Response('{"id":"upload-id"}', { status: 202 }))
      .mockResolvedValueOnce(new Response('{"processing_status":"complete"}'));
    const target = await resolveSarifTarget(directory, 'target/repo', 'release/1.0');
    await uploadSarif(join(directory, 'report.sarif'), target, 'test-token', {
      category: 'snyk-api',
    });
    const payload = JSON.parse(fetchMock.mock.calls[0]![1]!.body as string) as { sarif: string };
    expect(JSON.parse(gunzipSync(Buffer.from(payload.sarif, 'base64')).toString())).toMatchObject({
      runs: [{ automationDetails: { id: 'snyk-api/' } }],
    });
  });
  it.each([
    ['{"id":null}', undefined, 'processing ID'],
    ['{"id":"upload-id"}', new Response('denied', { status: 403 }), '403'],
    ['{"id":"upload-id"}', new Response('{"processing_status":"unknown"}'), 'unknown'],
    ['{"id":"upload-id"}', new Response('{"processing_status":"failed"}'), 'processing failed'],
  ])('rejects malformed or failed processing responses (%s)', async (body, status, message) => {
    fetchMock.mockResolvedValueOnce(new Response(body, { status: 202 }));
    if (status) fetchMock.mockResolvedValueOnce(status);
    const target = await resolveSarifTarget(directory, 'target/repo', 'release/1.0');
    await expect(
      uploadSarif(join(directory, 'report.sarif'), target, 'test-token'),
    ).rejects.toThrow(message);
  });
  it('fails when SARIF processing does not finish within the polling limit', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response('{"id":"upload-id"}', { status: 202 }))
      .mockResolvedValue(new Response('{"processing_status":"pending"}'));
    const target = await resolveSarifTarget(directory, 'target/repo', 'release/1.0');
    await expect(
      uploadSarif(join(directory, 'report.sarif'), target, 'test-token', {
        pollIntervalMs: 0,
        maxPolls: 1,
      }),
    ).rejects.toThrow('timed out');
  });
  it('surfaces authorization failures against the target repository', async () => {
    fetchMock.mockResolvedValue(new Response('forbidden', { status: 403 }));
    const target = await resolveSarifTarget(directory, 'target/repo', 'release/1.0');
    await expect(
      uploadSarif(join(directory, 'report.sarif'), target, 'test-token'),
    ).rejects.toThrow('403');
  });
});
