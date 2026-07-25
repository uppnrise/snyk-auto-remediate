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
    const canFix = (issue.attributes.coordinates ?? []).some(
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

/**
 * Infer the package-manager family (js, python, java, go, php, ruby, other)
 * for a Snyk issue based on its ID prefix and, when present, the resourcePath
 * of the affected coordinate.
 *
 * Returns undefined when the family cannot be inferred.
 */
export function inferIssueEcosystem(issue: SnykIssue): string | undefined {
  // 1. Snyk issue IDs are typically prefixed with the ecosystem, e.g.
  //    SNYK-JS-LODASH-590103, SNYK-PYTHON-DJANGO-*, SNYK-JAVA-ORG*, SNYK-GOLANG-*.
  const idMatch = /^SNYK-([A-Z]+)-/.exec(issue.id);
  if (idMatch && idMatch[1]) {
    const token = idMatch[1].toLowerCase();
    const mapping: Record<string, string> = {
      js: 'js',
      python: 'python',
      java: 'java',
      golang: 'go',
      go: 'go',
      php: 'php',
      ruby: 'ruby',
      composer: 'php',
      cocoapods: 'swift',
      swift: 'swift',
    };
    if (mapping[token]) return mapping[token];
  }

  // 2. Fall back to resourcePath heuristics.
  for (const coord of issue.attributes.coordinates ?? []) {
    const path = coord.representations?.[0]?.resourcePath?.toLowerCase();
    if (!path) continue;
    if (
      path.endsWith('package.json') ||
      path.endsWith('package-lock.json') ||
      path.endsWith('yarn.lock')
    )
      return 'js';
    if (
      path.endsWith('requirements.txt') ||
      path.endsWith('pyproject.toml') ||
      path.endsWith('poetry.lock')
    )
      return 'python';
    if (
      path.endsWith('pom.xml') ||
      path.endsWith('build.gradle') ||
      path.endsWith('build.gradle.kts')
    )
      return 'java';
    if (path.endsWith('go.mod') || path.endsWith('go.sum')) return 'go';
    if (path.endsWith('composer.json') || path.endsWith('composer.lock')) return 'php';
  }

  return undefined;
}

/**
 * Map a PackageManager to its ecosystem family (see `inferIssueEcosystem`).
 */
export function packageManagerFamily(pm: string): string {
  switch (pm) {
    case 'npm':
    case 'yarn':
      return 'js';
    case 'pip':
    case 'poetry':
      return 'python';
    case 'maven':
    case 'gradle':
      return 'java';
    case 'go':
      return 'go';
    case 'composer':
      return 'php';
    default:
      return pm;
  }
}

/**
 * Filter issues that belong to the ecosystem of the given package manager.
 * Issues whose ecosystem cannot be inferred are excluded to avoid running the
 * wrong package manager against unrelated findings.
 */
export function filterIssuesForPackageManager(
  issues: SnykIssue[],
  packageManager: string,
): SnykIssue[] {
  const family = packageManagerFamily(packageManager);
  return issues.filter((i) => inferIssueEcosystem(i) === family);
}
