import { logger } from '../utils/logger.js';
import type { RemediationConfig, SnykApiResponse, SnykIssue, Severity } from './types.js';

const SNYK_API_BASE = 'https://api.snyk.io';
const SNYK_API_VERSION = '2024-10-15';
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000;

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  url: string,
  options: RequestInit,
  attempt = 0,
): Promise<Response> {
  try {
    const response = await fetch(url, options);

    if (response.status === 429 || response.status >= 500) {
      if (attempt < MAX_RETRIES) {
        const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
        logger.warn(`Request failed with status ${response.status}. Retrying in ${delay}ms...`);
        await sleep(delay);
        return fetchWithRetry(url, options, attempt + 1);
      }
    }

    return response;
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
      logger.warn(`Request failed with error. Retrying in ${delay}ms...`);
      await sleep(delay);
      return fetchWithRetry(url, options, attempt + 1);
    }
    throw error;
  }
}

function severityToNumber(severity: Severity): number {
  const map: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  return map[severity];
}

export async function fetchSnykIssues(config: RemediationConfig): Promise<SnykIssue[]> {
  const { snykToken, snykOrgId, snykProjectIds, severityThreshold } = config;

  const headers: Record<string, string> = {
    Authorization: `token ${snykToken}`,
    'Content-Type': 'application/vnd.api+json',
  };

  const allIssues: SnykIssue[] = [];
  const thresholdNum = severityToNumber(severityThreshold);

  // Build base URL params
  const params = new URLSearchParams({
    version: SNYK_API_VERSION,
    limit: '100',
    status: 'open',
  });

  if (snykProjectIds && snykProjectIds.length > 0) {
    snykProjectIds.forEach((id) => params.append('scan_item.id', id));
    params.set('scan_item.type', 'project');
  }

  let nextUrl: string | undefined =
    `${SNYK_API_BASE}/rest/orgs/${snykOrgId}/issues?${params.toString()}`;

  while (nextUrl) {
    logger.debug(`Fetching Snyk issues from: ${nextUrl.replace(snykToken, '***')}`);

    const response = await fetchWithRetry(nextUrl, { headers });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Snyk API error ${response.status}: ${body}`);
    }

    const data = (await response.json()) as SnykApiResponse;
    const pageIssues = data.data ?? [];

    // Filter by severity threshold
    const filtered = pageIssues.filter((issue) => {
      const issueSeverity = issue.attributes.effective_severity_level;
      return severityToNumber(issueSeverity) >= thresholdNum;
    });

    allIssues.push(...filtered);
    logger.debug(`Fetched ${pageIssues.length} issues (${filtered.length} above threshold)`);

    // Follow pagination
    if (data.links?.next) {
      nextUrl = data.links.next.startsWith('http')
        ? data.links.next
        : `${SNYK_API_BASE}${data.links.next}`;
    } else {
      nextUrl = undefined;
    }
  }

  logger.info(`Total Snyk issues fetched: ${allIssues.length}`);
  return allIssues;
}
