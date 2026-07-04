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

/**
 * Partition issues into fixable and unfixable based on coordinate flags.
 */
export function partitionByFixability(issues: SnykIssue[]): {
  fixable: SnykIssue[];
  unfixable: SnykIssue[];
} {
  const fixable: SnykIssue[] = [];
  const unfixable: SnykIssue[] = [];

  for (const issue of issues) {
    const canFix = issue.attributes.coordinates.some(
      (coord) =>
        coord.is_fixable_snyk === true ||
        coord.is_fixable_upstream === true ||
        coord.is_patchable === true ||
        (coord.remedies && coord.remedies.length > 0),
    );

    if (canFix) {
      fixable.push(issue);
    } else {
      unfixable.push(issue);
    }
  }

  return { fixable, unfixable };
}

/**
 * Group issues by their associated package manager (inferred from representations).
 */
export function groupByPackageManager(issues: SnykIssue[]): Map<string, SnykIssue[]> {
  const groups = new Map<string, SnykIssue[]>();

  for (const issue of issues) {
    // Use issue type as rough proxy; in real usage, we'd match against project metadata
    const key = issue.attributes.type ?? 'unknown';
    const existing = groups.get(key) ?? [];
    existing.push(issue);
    groups.set(key, existing);
  }

  return groups;
}
