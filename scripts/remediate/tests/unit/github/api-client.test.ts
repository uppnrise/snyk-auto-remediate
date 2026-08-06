import { afterEach, describe, expect, it, vi } from 'vitest';
import { GitHubApiClient } from '../../../src/github/api-client.js';

describe('GitHubApiClient', () => {
  afterEach(() => vi.restoreAllMocks());

  it('filters listed issues by the configured management label', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(JSON.stringify([]), { status: 200 }));
    const client = new GitHubApiClient('token', 'owner/repo');

    await client.listIssues('open', ['snyk']);

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      'https://api.github.com/repos/owner/repo/issues?state=open&per_page=100&page=1&labels=snyk',
    );
  });
});
