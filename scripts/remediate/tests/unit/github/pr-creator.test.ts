import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOrUpdatePr } from '../../../src/github/pr-creator.js';
import type { RemediationConfig } from '../../../src/snyk/types.js';

const config = {
  dryRun: false,
  githubToken: 'token',
  githubRepository: 'owner/repo',
} as RemediationConfig;

describe('pull request lifecycle', () => {
  afterEach(() => vi.restoreAllMocks());

  it('updates an existing remediation PR and reapplies metadata', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify([{ number: 7, html_url: 'https://example.test/pr/7', title: 'old' }]),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            number: 7,
            html_url: 'https://example.test/pr/7',
            title: 'new',
          }),
          { status: 200 },
        ),
      )
      .mockResolvedValueOnce(new Response('{}', { status: 200 }))
      .mockResolvedValueOnce(new Response('{}', { status: 200 }));

    const result = await createOrUpdatePr(
      {
        title: 'new',
        body: 'updated body',
        head: 'chore/security/snyk-remediation-main',
        base: 'main',
        labels: ['security'],
      },
      config,
    );

    expect(result?.created).toBe(false);
    expect(fetchMock.mock.calls.some((call) => call[1]?.method === 'PATCH')).toBe(true);
  });
});
