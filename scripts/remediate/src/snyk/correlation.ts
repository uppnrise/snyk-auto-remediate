import type {
  CliVulnerability,
  DetectedEcosystem,
  NonActionableFinding,
  RemediationAction,
  PackageManager,
  Severity,
  SnykIssue,
} from './types.js';

interface RawCliVulnerability {
  id?: unknown;
  title?: unknown;
  severity?: unknown;
  packageName?: unknown;
  version?: unknown;
  fixedIn?: unknown;
  upgradePath?: unknown;
  from?: unknown;
  isUpgradable?: unknown;
  isPatchable?: unknown;
}
interface RawCliResult {
  vulnerabilities?: unknown;
  packageManager?: unknown;
  projectName?: unknown;
  projectId?: unknown;
}
function normalizeExactVersion(value: string): string | undefined {
  const version = /^v\d/.test(value) ? value.slice(1) : value;
  if (
    version.length === 0 ||
    !/^\d[0-9A-Za-z._+~-]*$/.test(version) ||
    /(?:^|[._-])[xX](?:$|[._-])/.test(version) ||
    version.includes('*')
  ) {
    return undefined;
  }
  return version;
}

function parseCoordinate(value: string): { name: string; version: string } | undefined {
  const at = value.lastIndexOf('@');
  if (at <= 0) return undefined;
  const name = value.slice(0, at);
  const version = normalizeExactVersion(value.slice(at + 1));
  return version ? { name, version } : undefined;
}

export function normalizeCliOutput(raw: unknown, ecosystem: DetectedEcosystem): CliVulnerability[] {
  const results = (Array.isArray(raw) ? raw : [raw]).filter(
    (value): value is RawCliResult => typeof value === 'object' && value !== null,
  );
  return results.flatMap((result) => {
    const vulnerabilities = Array.isArray(result.vulnerabilities) ? result.vulnerabilities : [];
    return vulnerabilities.flatMap((entry): CliVulnerability[] => {
      const v = entry as RawCliVulnerability;
      if (
        typeof v.id !== 'string' ||
        typeof v.packageName !== 'string' ||
        typeof v.version !== 'string'
      )
        return [];
      const item: CliVulnerability = {
        issueKey: v.id,
        packageName: v.packageName,
        version: v.version,
        packageManager: ecosystem.packageManager,
        fixedIn: Array.isArray(v.fixedIn)
          ? v.fixedIn.filter((x): x is string => typeof x === 'string')
          : [],
        upgradePath: Array.isArray(v.upgradePath)
          ? v.upgradePath.filter((x): x is string => typeof x === 'string')
          : [],
        dependencyPath: Array.isArray(v.from)
          ? v.from.filter((x): x is string => typeof x === 'string')
          : [],
        isUpgradable: v.isUpgradable === true,
        isPatchable: v.isPatchable === true,
      };
      if (typeof v.title === 'string') item.title = v.title;
      if (
        typeof v.severity === 'string' &&
        ['info', 'low', 'medium', 'high', 'critical'].includes(v.severity)
      ) {
        item.severity = v.severity as Severity;
      }
      if (typeof result.projectName === 'string') item.projectName = result.projectName;
      if (typeof result.projectId === 'string') item.projectId = result.projectId;
      return [item];
    });
  });
}

function actionFrom(issue: SnykIssue, cli: CliVulnerability): RemediationAction | undefined {
  if (!cli.isUpgradable) return undefined;
  const coordinates = cli.upgradePath
    .map(parseCoordinate)
    .filter((x): x is NonNullable<typeof x> => Boolean(x));
  const root = coordinates[0];
  if (!root) return undefined;
  const currentRoot = cli.dependencyPath
    .map(parseCoordinate)
    .find((coordinate) => coordinate?.name === root.name);
  return {
    packageManager: cli.packageManager,
    packageName: root.name,
    currentVersion: currentRoot?.version ?? cli.version,
    targetVersion: root.version,
    findingIds: [issue.id],
    findingKeys: [issue.attributes.key],
    projectId: issue.relationships.scan_item.data.id,
    evidence: 'snyk-cli-upgrade-path',
  };
}

function actionsFromRestRemedies(
  issue: SnykIssue,
  packageManager: PackageManager,
): RemediationAction[] {
  return (issue.attributes.coordinates ?? []).flatMap((coordinate) =>
    (coordinate.remedies ?? []).flatMap((remedy): RemediationAction[] => {
      const packageName = remedy.details?.upgrade_package;
      const rawTarget = remedy.details?.target_version;
      if (typeof packageName !== 'string' || typeof rawTarget !== 'string') return [];
      const targetVersion = normalizeExactVersion(rawTarget);
      const dependency = coordinate.representations
        ?.map((representation) => representation.dependency)
        .find((candidate) => candidate?.package_name === packageName);
      const currentVersion = dependency && normalizeExactVersion(dependency.package_version);
      if (!targetVersion || !currentVersion) return [];
      return [
        {
          packageManager,
          packageName,
          currentVersion,
          targetVersion,
          findingIds: [issue.id],
          findingKeys: [issue.attributes.key],
          projectId: issue.relationships.scan_item.data.id,
          evidence: 'snyk-rest-remedy',
        },
      ];
    }),
  );
}

export function buildRemediationPlan(
  issues: SnykIssue[],
  cliVulnerabilities: CliVulnerability[],
  options: { scopedProjectIds?: string[]; restPackageManager?: PackageManager } = {},
): { actions: RemediationAction[]; nonActionable: NonActionableFinding[] } {
  const actions: RemediationAction[] = [];
  const nonActionable: NonActionableFinding[] = [];
  for (const issue of issues) {
    const projectId = issue.relationships.scan_item.data.id;
    const keyMatches = cliVulnerabilities.filter((v) => v.issueKey === issue.attributes.key);
    const matches = keyMatches.filter((v) => {
      if (v.projectId !== undefined) return v.projectId === projectId;
      if (options.scopedProjectIds?.length === 1) {
        return options.scopedProjectIds[0] === projectId;
      }
      return v.projectName === projectId;
    });
    if (matches.length === 0) {
      const restCandidates = options.restPackageManager
        ? actionsFromRestRemedies(issue, options.restPackageManager)
        : [];
      const restSignatures = new Set(
        restCandidates.map(
          (action) => `${action.packageManager}:${action.packageName}:${action.targetVersion}`,
        ),
      );
      if (restSignatures.size === 1 && restCandidates[0]) {
        actions.push(restCandidates[0]);
        continue;
      }
      if (restSignatures.size > 1) {
        nonActionable.push({ issue, reason: 'ambiguous_upgrade_path' });
        continue;
      }
      nonActionable.push({
        issue,
        reason:
          keyMatches.length > 0
            ? 'project_not_correlated'
            : issue.attributes.coordinates?.length
              ? 'cli_not_correlated'
              : 'missing_coordinates',
      });
      continue;
    }
    const candidates = matches
      .map((m) => actionFrom(issue, m))
      .filter((a): a is RemediationAction => Boolean(a));
    const signatures = new Set(
      candidates.map((a) => `${a.packageManager}:${a.packageName}:${a.targetVersion}`),
    );
    if (signatures.size > 1) {
      nonActionable.push({ issue, reason: 'ambiguous_upgrade_path' });
    } else if (candidates[0]) {
      actions.push(candidates[0]);
    } else {
      nonActionable.push({
        issue,
        reason: matches.every((m) => m.isPatchable && !m.isUpgradable)
          ? 'patch_only'
          : 'missing_exact_target',
      });
    }
  }
  const merged = new Map<string, RemediationAction>();
  for (const action of actions) {
    const key = `${action.projectId}:${action.packageManager}:${action.packageName}`;
    const prior = merged.get(key);
    if (!prior) merged.set(key, action);
    else {
      if (action.targetVersion.localeCompare(prior.targetVersion, undefined, { numeric: true }) > 0)
        prior.targetVersion = action.targetVersion;
      prior.findingIds.push(...action.findingIds);
      prior.findingKeys.push(...action.findingKeys);
    }
  }
  return { actions: [...merged.values()], nonActionable };
}

export function unresolvedFindingKeys(
  actions: RemediationAction[],
  remainingFindings: CliVulnerability[],
): string[] {
  const unresolved = new Set<string>();
  for (const action of actions) {
    for (const findingKey of action.findingKeys) {
      const keyMatches = remainingFindings.filter((finding) => finding.issueKey === findingKey);
      const cliHasProjectIds =
        keyMatches.length > 0 && keyMatches.every((finding) => finding.projectId !== undefined);
      const remains =
        cliHasProjectIds && action.projectId !== undefined
          ? keyMatches.some((finding) => finding.projectId === action.projectId)
          : keyMatches.length > 0;
      if (remains) unresolved.add(findingKey);
    }
  }
  return [...unresolved];
}
