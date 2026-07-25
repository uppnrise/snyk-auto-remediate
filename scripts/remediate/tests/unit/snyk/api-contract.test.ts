import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  decodeIssuesResponse,
  fetchSnykIssues,
  SnykApiError,
} from '../../../src/snyk/api-client.js';
import type { RemediationConfig } from '../../../src/snyk/types.js';

const sparseIssue = {
  id: '73832c6c-19ff-4a92-850c-2e1ff2800c16',
  type: 'issue',
  attributes: {
    key: 'SNYK-JS-LODASH-590103',
    title: 'Prototype Pollution',
    type: 'package_vulnerability',
    effective_severity_level: 'high',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    status: 'open',
    ignored: false,
  },
  relationships: {
    organization: { data: { id: '11111111-1111-4111-8111-111111111111', type: 'organization' } },
    scan_item: { data: { id: '22222222-2222-4222-8222-222222222222', type: 'project' } },
  },
};

describe('Snyk REST contract', () => {
  afterEach(() => vi.restoreAllMocks());

  it('accepts a valid sparse JSON:API issue without coordinates or problems', () => {
    const decoded = decodeIssuesResponse({
      jsonapi: { version: '1.0' },
      data: [sparseIssue],
      links: {},
    });
    expect(decoded.data[0]?.attributes.key).toBe('SNYK-JS-LODASH-590103');
    expect(decoded.data[0]?.attributes.coordinates).toBeUndefined();
  });

  it('rejects malformed JSON:API responses', () => {
    expect(() => decodeIssuesResponse({ data: [{ id: 123 }] })).toThrow(
      /Invalid Snyk Issues API response/,
    );
  });

  it('fetches configured project IDs separately and deduplicates by REST resource ID', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ jsonapi: { version: '1.0' }, data: [sparseIssue] }), {
          status: 200,
          headers: { 'content-type': 'application/vnd.api+json' },
        }),
      ),
    );
    const config = {
      snykToken: 'token',
      snykOrgId: '11111111-1111-4111-8111-111111111111',
      snykProjectIds: ['project-a', 'project-b'],
      severityThreshold: 'high',
    } as RemediationConfig;

    const issues = await fetchSnykIssues(config);

    expect(issues).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0].toString()).toContain('scan_item.id=project-a');
    expect(fetchMock.mock.calls[1]?.[0].toString()).toContain('scan_item.id=project-b');
  });

  it('refuses to forward authentication to an untrusted pagination origin', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          jsonapi: { version: '1.0' },
          data: [sparseIssue],
          links: { next: 'https://attacker.invalid/issues?page=2' },
        }),
        { status: 200 },
      ),
    );
    const config = {
      snykToken: 'token',
      snykOrgId: '11111111-1111-4111-8111-111111111111',
      severityThreshold: 'high',
    } as RemediationConfig;

    await expect(fetchSnykIssues(config)).rejects.toThrow(/untrusted pagination/i);
  });

  it('exposes forbidden responses so callers can select CLI-only inventory', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          jsonapi: { version: '1.0' },
          errors: [{ status: '403', title: 'Forbidden' }],
        }),
        { status: 403 },
      ),
    );
    const config = {
      snykToken: 'token',
      snykOrgId: '11111111-1111-4111-8111-111111111111',
      severityThreshold: 'high',
    } as RemediationConfig;

    await expect(fetchSnykIssues(config)).rejects.toMatchObject<SnykApiError>({ status: 403 });
  });
});
