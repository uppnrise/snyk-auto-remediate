import type {
  CliVulnerability,
  DetectedEcosystem,
  NonActionableFinding,
  RemediationAction,
  SnykIssue,
} from './types.js';

interface RawCliVulnerability {
  id?: unknown;
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
const exactVersion = /^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$/;
function parseCoordinate(value: string): { name: string; version: string } | undefined {
  const at = value.lastIndexOf('@');
  if (at <= 0) return undefined;
  const name = value.slice(0, at);
  const match = exactVersion.exec(value.slice(at + 1));
  return match?.[1] ? { name, version: match[1] } : undefined;
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

export function buildRemediationPlan(
  issues: SnykIssue[],
  cliVulnerabilities: CliVulnerability[],
): { actions: RemediationAction[]; nonActionable: NonActionableFinding[] } {
  const actions: RemediationAction[] = [];
  const nonActionable: NonActionableFinding[] = [];
  for (const issue of issues) {
    const projectId = issue.relationships.scan_item.data.id;
    const matches = cliVulnerabilities.filter(
      (v) =>
        v.issueKey === issue.attributes.key &&
        (v.projectId === undefined || v.projectId === projectId),
    );
    if (matches.length === 0) {
      nonActionable.push({
        issue,
        reason: issue.attributes.coordinates?.length ? 'cli_not_correlated' : 'missing_coordinates',
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
    const key = `${action.packageManager}:${action.packageName}`;
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
