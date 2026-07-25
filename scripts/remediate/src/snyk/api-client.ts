import { logger } from '../utils/logger.js';
import type { RemediationConfig, Severity, SnykApiResponse, SnykIssue } from './types.js';

const API_ORIGIN = 'https://api.snyk.io';
const API_BASE = `${API_ORIGIN}/rest`;
const API_VERSION = '2024-10-15';
const MAX_RETRIES = 3;

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const isString = (value: unknown): value is string => typeof value === 'string';

function decodeIdentifier(value: unknown, path: string): { id: string; type: string } {
  if (!isObject(value) || !isString(value.id) || !isString(value.type)) {
    throw new Error(`Invalid Snyk Issues API response: ${path} must contain string id and type`);
  }
  return { id: value.id, type: value.type };
}

function decodeIssue(value: unknown, index: number): SnykIssue {
  const path = `data[${index}]`;
  if (
    !isObject(value) ||
    !isString(value.id) ||
    !isString(value.type) ||
    !isObject(value.attributes)
  ) {
    throw new Error(`Invalid Snyk Issues API response: ${path} is not an issue resource`);
  }
  const a = value.attributes;
  const requiredStrings = [
    'key',
    'title',
    'type',
    'created_at',
    'updated_at',
    'effective_severity_level',
    'status',
  ];
  if (requiredStrings.some((key) => !isString(a[key])) || typeof a.ignored !== 'boolean') {
    throw new Error(
      `Invalid Snyk Issues API response: ${path}.attributes is missing required fields`,
    );
  }
  if (
    !['info', 'low', 'medium', 'high', 'critical'].includes(a.effective_severity_level as string)
  ) {
    throw new Error(`Invalid Snyk Issues API response: ${path} has unknown severity`);
  }
  if (
    !isObject(value.relationships) ||
    !isObject(value.relationships.organization) ||
    !isObject(value.relationships.scan_item)
  ) {
    throw new Error(
      `Invalid Snyk Issues API response: ${path}.relationships is missing organization or scan_item`,
    );
  }
  const organization = decodeIdentifier(
    value.relationships.organization.data,
    `${path}.relationships.organization.data`,
  );
  const scanItem = decodeIdentifier(
    value.relationships.scan_item.data,
    `${path}.relationships.scan_item.data`,
  );
  const attrs = { ...a } as unknown as SnykIssue['attributes'];
  if (a.coordinates !== undefined && !Array.isArray(a.coordinates)) delete attrs.coordinates;
  if (a.problems !== undefined && !Array.isArray(a.problems)) delete attrs.problems;
  return {
    id: value.id,
    type: value.type,
    attributes: attrs,
    relationships: { organization: { data: organization }, scan_item: { data: scanItem } },
  };
}

export function decodeIssuesResponse(value: unknown): SnykApiResponse {
  if (!isObject(value) || !isObject(value.jsonapi) || !Array.isArray(value.data)) {
    throw new Error(
      'Invalid Snyk Issues API response: expected JSON:API object with jsonapi and data',
    );
  }
  const links = isObject(value.links)
    ? Object.fromEntries(Object.entries(value.links).filter(([, v]) => isString(v)))
    : undefined;
  return {
    jsonapi: value.jsonapi,
    data: value.data.map(decodeIssue),
    ...(links ? { links } : {}),
  };
}

const sleep = (ms: number): Promise<void> =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));
async function fetchWithRetry(url: string, options: RequestInit, attempt = 0): Promise<Response> {
  try {
    const response = await fetch(url, options);
    if ((response.status === 429 || response.status >= 500) && attempt < MAX_RETRIES) {
      await sleep(1000 * 2 ** attempt);
      return fetchWithRetry(url, options, attempt + 1);
    }
    return response;
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      await sleep(1000 * 2 ** attempt);
      return fetchWithRetry(url, options, attempt + 1);
    }
    throw error;
  }
}
function severityNumber(severity: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}
function safePageUrl(link: string, current: URL): string {
  const next = new URL(link, current);
  if (next.origin !== API_ORIGIN || !next.pathname.startsWith('/rest/')) {
    throw new Error(`Refusing untrusted pagination URL: ${next.toString()}`);
  }
  return next.toString();
}

async function fetchScope(config: RemediationConfig, projectId?: string): Promise<SnykIssue[]> {
  const params = new URLSearchParams({ version: API_VERSION, limit: '100', status: 'open' });
  if (projectId) {
    params.set('scan_item.id', projectId);
    params.set('scan_item.type', 'project');
  }
  let pageUrl: string | undefined =
    `${API_BASE}/orgs/${config.snykOrgId}/issues?${params.toString()}`;
  const issues: SnykIssue[] = [];
  while (pageUrl) {
    const current: URL = new URL(pageUrl);
    const response = await fetchWithRetry(current.toString(), {
      headers: { Authorization: `token ${config.snykToken}`, Accept: 'application/vnd.api+json' },
    });
    if (!response.ok)
      throw new Error(`Snyk API error ${response.status}: ${await response.text()}`);
    const decoded = decodeIssuesResponse(await response.json());
    issues.push(
      ...decoded.data.filter(
        (i) =>
          severityNumber(i.attributes.effective_severity_level) >=
          severityNumber(config.severityThreshold),
      ),
    );
    pageUrl = decoded.links?.next ? safePageUrl(decoded.links.next, current) : undefined;
  }
  return issues;
}

export async function fetchSnykIssues(config: RemediationConfig): Promise<SnykIssue[]> {
  const scopes = config.snykProjectIds?.length ? config.snykProjectIds : [undefined];
  const pages = await Promise.all(scopes.map((id) => fetchScope(config, id)));
  const unique = new Map(pages.flat().map((issue) => [issue.id, issue]));
  logger.info(`Total Snyk issues fetched: ${unique.size}`);
  return [...unique.values()];
}
