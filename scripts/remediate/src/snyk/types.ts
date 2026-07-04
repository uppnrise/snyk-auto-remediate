// Snyk REST API types

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface SnykIssueAttributes {
  key: string;
  title: string;
  type: string;
  created_at: string;
  updated_at: string;
  description?: string;
  severity: Severity;
  effective_severity_level: Severity;
  status: string;
  ignored: boolean;
  ignored_reason?: string;
  problems: SnykProblem[];
  coordinates: SnykCoordinate[];
  resolution?: SnykResolution;
  classes?: SnykClass[];
  slots?: SnykSlots;
}

export interface SnykProblem {
  id: string;
  source: string;
  url?: string;
  type?: string;
  disco_id?: string;
  cve?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
}

export interface SnykCoordinate {
  remedies?: SnykRemedy[];
  representations?: SnykRepresentation[];
  is_fixable_snyk?: boolean;
  is_fixable_upstream?: boolean;
  is_patchable?: boolean;
  is_pinnable?: boolean;
  reachability?: string;
}

export interface SnykRemedy {
  description?: string;
  type: string;
  details?: SnykRemedyDetails;
}

export interface SnykRemedyDetails {
  upgrade_package?: string;
  target_version?: string;
}

export interface SnykRepresentation {
  dependency?: SnykDependency;
  resourcePath?: string;
}

export interface SnykDependency {
  package_name: string;
  package_version: string;
}

export interface SnykResolution {
  type: string;
  details?: Record<string, unknown>;
}

export interface SnykClass {
  id: string;
  source: string;
  type: string;
}

export interface SnykSlots {
  disclosure_time?: string;
  exploit?: string;
  publication_time?: string;
  references?: SnykReference[];
}

export interface SnykReference {
  url: string;
  title?: string;
}

export interface SnykIssue {
  id: string;
  type: string;
  attributes: SnykIssueAttributes;
  relationships?: SnykIssueRelationships;
}

export interface SnykIssueRelationships {
  scan_item?: {
    data?: {
      id: string;
      type: string;
    };
  };
  organization?: {
    data?: {
      id: string;
      type: string;
    };
  };
}

export interface SnykApiResponse {
  data: SnykIssue[];
  links?: {
    next?: string;
    prev?: string;
    first?: string;
    last?: string;
    self?: string;
  };
  meta?: {
    count?: number;
  };
}

export interface SnykProject {
  id: string;
  attributes: {
    name: string;
    type: string;
    status: string;
    target_reference?: string;
  };
}

export interface FixResult {
  success: boolean;
  packageManager: PackageManager;
  fixedFindings: SnykIssue[];
  failedFindings: SnykIssue[];
  changesApplied: string[];
  error?: string;
}

export type PackageManager =
  | 'npm'
  | 'yarn'
  | 'pip'
  | 'poetry'
  | 'maven'
  | 'gradle'
  | 'go'
  | 'composer';

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
  severityThreshold: Severity;
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
  severityThreshold: Severity;
  totalFindings: number;
  fixableFindings: number;
  fixedFindings: number;
  unfixableFindings: number;
  dryRun: boolean;
  fixResults: FixResult[];
  issuesCreated: number;
  prsCreated: number;
  errors: string[];
}
