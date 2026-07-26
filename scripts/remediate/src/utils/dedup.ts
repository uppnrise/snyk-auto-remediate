import type { SnykIssue } from '../snyk/types.js';

/**
 * Deduplicate Snyk issues by their ID.
 */
export function deduplicateIssues(issues: SnykIssue[]): SnykIssue[] {
  const seen = new Set<string>();
  return issues.filter((issue) => {
    if (seen.has(issue.id)) return false;
    seen.add(issue.id);
    return true;
  });
}
