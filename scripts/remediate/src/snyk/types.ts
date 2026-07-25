export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type SeverityThreshold = Exclude<Severity, 'info'>;
export type PackageManager =
  'npm' | 'yarn' | 'pip' | 'poetry' | 'maven' | 'gradle' | 'go' | 'composer';
export type NonActionableReason =
  | 'missing_coordinates'
  | 'cli_not_correlated'
  | 'ambiguous_upgrade_path'
  | 'missing_exact_target'
  | 'unsupported_manifest_shape'
  | 'patch_only'
  | 'apply_failed'
  | 'verification_failed'
  | 'tests_failed';

export interface ResourceIdentifier {
  id: string;
  type: string;
}
export interface SnykProblem {
  id: string;
  source?: string;
  url?: string;
  type?: string;
  cve?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
}
export interface SnykDependency {
  package_name: string;
  package_version: string;
}
export interface SnykRepresentation {
  resourcePath?: string;
  dependency?: SnykDependency;
  [key: string]: unknown;
}
export interface SnykRemedy {
  type: string;
  description?: string;
  correlation_id?: string;
  meta?: Record<string, unknown>;
}
export interface SnykCoordinate {
  remedies?: SnykRemedy[];
  representations?: SnykRepresentation[];
  is_fixable_manually?: boolean;
  is_fixable_snyk?: boolean;
  is_fixable_upstream?: boolean;
  is_patchable?: boolean;
  is_pinnable?: boolean;
  is_upgradeable?: boolean;
  reachability?: string;
}
export interface SnykIssueAttributes {
  key: string;
  title: string;
  type: string;
  created_at: string;
  updated_at: string;
  effective_severity_level: Severity;
  status: 'open' | 'resolved';
  ignored: boolean;
  description?: string;
  problems?: SnykProblem[];
  coordinates?: SnykCoordinate[];
  classes?: Array<Record<string, unknown>>;
  resolution?: Record<string, unknown>;
  [key: string]: unknown;
}
export interface SnykIssueRelationships {
  organization: { data: ResourceIdentifier };
  scan_item: { data: ResourceIdentifier };
  ignore?: { data: ResourceIdentifier };
  test_executions?: { data: ResourceIdentifier[] };
}
export interface SnykIssue {
  id: string;
  type: string;
  attributes: SnykIssueAttributes;
  relationships: SnykIssueRelationships;
}
export interface SnykApiResponse {
  jsonapi: Record<string, unknown>;
  data: SnykIssue[];
  links?: { next?: string; prev?: string; first?: string; last?: string; self?: string };
}
export interface CliVulnerability {
  issueKey: string;
  packageName: string;
  version: string;
  packageManager: PackageManager;
  projectName?: string;
  projectId?: string;
  fixedIn: string[];
  upgradePath: string[];
  dependencyPath: string[];
  isUpgradable: boolean;
  isPatchable: boolean;
}
export interface RemediationAction {
  packageManager: PackageManager;
  packageName: string;
  currentVersion: string;
  targetVersion: string;
  findingIds: string[];
  findingKeys: string[];
  projectId?: string;
  evidence: 'snyk-cli-upgrade-path';
}
export interface NonActionableFinding {
  issue: SnykIssue;
  reason: NonActionableReason;
  detail?: string;
}
export interface FixResult {
  success: boolean;
  packageManager: PackageManager;
  fixedFindings: SnykIssue[];
  failedFindings: SnykIssue[];
  changesApplied: string[];
  error?: string;
  attemptedActions?: RemediationAction[];
  verifiedFindingIds?: string[];
}
export interface DetectedEcosystem {
  packageManager: PackageManager;
  manifestFiles: string[];
  workingDirectory: string;
}
export interface RemediationConfig {
  snykToken: string;
  snykOrgId: string;
  snykProjectIds?: string[];
  githubRepository: string;
  githubToken: string;
  severityThreshold: SeverityThreshold;
  packageManagers?: PackageManager[];
  dryRun: boolean;
  maxPrsPerRun: number;
  maxIssuesPerRun: number;
  workingDirectory: string;
  enableCopilotAgentFallback: boolean;
  copilotAssignee: string;
  failOnNoFix: boolean;
  runTests: boolean;
  testCommand?: string;
  prLabels: string[];
  issueLabels: string[];
  prReviewers?: string[];
  prTeamReviewers?: string[];
  targetBranch: string;
}
export interface RemediationReport {
  timestamp: string;
  repository: string;
  targetBranch: string;
  severityThreshold: SeverityThreshold;
  totalFindings: number;
  fixableFindings: number;
  fixedFindings: number;
  unfixableFindings: number;
  dryRun: boolean;
  fixResults: FixResult[];
  issuesCreated: number;
  prsCreated: number;
  errors: string[];
  actionableFindings?: number;
  ambiguousFindings?: number;
  unsupportedFindings?: number;
  attemptedFindings?: number;
  verifiedFixedFindings?: number;
  verificationFailedFindings?: number;
  fallbackFindings?: number;
  nonActionable?: Array<{ id: string; key: string; reason: NonActionableReason; detail?: string }>;
}
