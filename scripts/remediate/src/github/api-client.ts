import { logger } from '../utils/logger.js';

const GITHUB_API_BASE = 'https://api.github.com';
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 1000;

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function githubFetchWithRetry(
  url: string,
  options: RequestInit,
  attempt = 0,
): Promise<Response> {
  try {
    const response = await fetch(url, options);

    if (response.status === 429 || response.status >= 500) {
      if (attempt < MAX_RETRIES) {
        const retryAfter = response.headers.get('retry-after');
        const delay = retryAfter
          ? parseInt(retryAfter, 10) * 1000
          : INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
        logger.warn(`GitHub API rate limited. Retrying in ${delay}ms...`);
        await sleep(delay);
        return githubFetchWithRetry(url, options, attempt + 1);
      }
    }

    return response;
  } catch (error) {
    if (attempt < MAX_RETRIES) {
      const delay = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
      await sleep(delay);
      return githubFetchWithRetry(url, options, attempt + 1);
    }
    throw error;
  }
}

export class GitHubApiClient {
  private readonly headers: Record<string, string>;
  private readonly owner: string;
  private readonly repo: string;

  constructor(token: string, repository: string) {
    const [owner, repo] = repository.split('/');
    if (!owner || !repo) {
      throw new Error(`Invalid repository format: ${repository}. Expected "owner/repo"`);
    }
    this.owner = owner;
    this.repo = repo;
    // Authorization value is masked in logs by logger.ts maskSecrets()
    const authValue = 'Bearer ' + token;
    this.headers = {
      Authorization: authValue,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    };
  }

  async createIssue(params: CreateIssueParams): Promise<GitHubIssue> {
    const url = `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/issues`;
    const response = await githubFetchWithRetry(url, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify(params),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`GitHub API error creating issue: ${response.status} ${body}`);
    }

    return (await response.json()) as GitHubIssue;
  }

  async updateIssue(issueNumber: number, params: UpdateIssueParams): Promise<GitHubIssue> {
    const url = `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/issues/${issueNumber}`;
    const response = await githubFetchWithRetry(url, {
      method: 'PATCH',
      headers: this.headers,
      body: JSON.stringify(params),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`GitHub API error updating issue: ${response.status} ${body}`);
    }

    return (await response.json()) as GitHubIssue;
  }

  async listIssues(
    state: 'open' | 'closed' | 'all' = 'open',
    labels: string[] = [],
  ): Promise<GitHubIssue[]> {
    const allIssues: GitHubIssue[] = [];
    let page = 1;

    for (;;) {
      const params = new URLSearchParams({ state, per_page: '100', page: String(page) });
      if (labels.length > 0) params.set('labels', labels.join(','));
      const url = `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/issues?${params.toString()}`;
      const response = await githubFetchWithRetry(url, { headers: this.headers });

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`GitHub API error listing issues: ${response.status} ${body}`);
      }

      const issues = (await response.json()) as GitHubIssue[];
      if (issues.length === 0) break;

      allIssues.push(...issues.filter((i) => !i.pull_request));
      if (issues.length < 100) break;
      page++;
    }

    return allIssues;
  }

  async ensureLabel(name: string, color: string, description: string): Promise<void> {
    const url = `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/labels/${encodeURIComponent(name)}`;

    const getResponse = await githubFetchWithRetry(url, { headers: this.headers });
    if (getResponse.ok) return; // Label already exists

    const createUrl = `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/labels`;
    const createResponse = await githubFetchWithRetry(createUrl, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify({ name, color, description }),
    });

    if (!createResponse.ok && createResponse.status !== 422) {
      logger.warn(`Could not create label "${name}": ${createResponse.status}`);
    }
  }

  async listPulls(head: string, base: string): Promise<GitHubPullRequest[]> {
    const params = new URLSearchParams({
      head: `${this.owner}:${head}`,
      base,
      state: 'open',
      per_page: '100',
    });
    const response = await githubFetchWithRetry(
      `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/pulls?${params.toString()}`,
      { headers: this.headers },
    );
    if (!response.ok) {
      throw new Error(
        `GitHub API error listing pull requests: ${response.status} ${await response.text()}`,
      );
    }
    return (await response.json()) as GitHubPullRequest[];
  }

  async createPull(params: CreatePullParams): Promise<GitHubPullRequest> {
    const response = await githubFetchWithRetry(
      `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/pulls`,
      {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(params),
      },
    );
    if (!response.ok) {
      throw new Error(
        `GitHub API error creating pull request: ${response.status} ${await response.text()}`,
      );
    }
    return (await response.json()) as GitHubPullRequest;
  }

  async updatePull(
    pullNumber: number,
    params: Pick<CreatePullParams, 'title' | 'body' | 'base'>,
  ): Promise<GitHubPullRequest> {
    const response = await githubFetchWithRetry(
      `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/pulls/${pullNumber}`,
      {
        method: 'PATCH',
        headers: this.headers,
        body: JSON.stringify(params),
      },
    );
    if (!response.ok) {
      throw new Error(
        `GitHub API error updating pull request: ${response.status} ${await response.text()}`,
      );
    }
    return (await response.json()) as GitHubPullRequest;
  }

  async addLabels(issueNumber: number, labels: string[]): Promise<void> {
    const response = await githubFetchWithRetry(
      `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/issues/${issueNumber}/labels`,
      {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify({ labels }),
      },
    );
    if (!response.ok) {
      throw new Error(
        `GitHub API error adding labels: ${response.status} ${await response.text()}`,
      );
    }
  }

  async requestReviewers(
    pullNumber: number,
    reviewers: string[],
    teamReviewers: string[],
  ): Promise<void> {
    const response = await githubFetchWithRetry(
      `${GITHUB_API_BASE}/repos/${this.owner}/${this.repo}/pulls/${pullNumber}/requested_reviewers`,
      {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify({ reviewers, team_reviewers: teamReviewers }),
      },
    );
    if (!response.ok) {
      throw new Error(
        `GitHub API error requesting reviewers: ${response.status} ${await response.text()}`,
      );
    }
  }
}

export interface CreateIssueParams {
  title: string;
  body: string;
  labels?: string[];
  assignees?: string[];
}

export interface UpdateIssueParams {
  title?: string;
  body?: string;
  state?: 'open' | 'closed';
  labels?: string[];
  assignees?: string[];
}

export interface GitHubIssue {
  id: number;
  number: number;
  title: string;
  body: string | null;
  state: string;
  html_url: string;
  labels: Array<{ name: string }>;
  assignees: Array<{ login: string }>;
  pull_request?: Record<string, unknown>;
}

export interface CreatePullParams {
  title: string;
  body: string;
  head: string;
  base: string;
  draft: boolean;
}

export interface GitHubPullRequest {
  number: number;
  html_url: string;
  title: string;
  body?: string | null;
}
