export type UserRole = "super_admin" | "org_admin" | "security_analyst" | "read_only";

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: UserRole;
  organization_id: string;
  totp_enabled: boolean;
}

export interface Organization {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  members?: User[];
}

export interface Website {
  id: string;
  name: string;
  url: string;
  domain: string;
  environment: "production" | "staging" | "development";
  business_criticality: "critical" | "high" | "medium" | "low";
  description?: string;
  contact_email: string;
  organization_id: string;
  verification_status: "verified" | "unverified" | "pending";
  verification_method?: string;
  verification_tokens?: {
    token: string;
    dns_record_name: string;
    dns_txt_value: string;
    http_challenge_path: string;
    http_challenge_content: string;
  };
  security_score: number;
  risk_level: string;
  excluded_paths?: string[];
  created_at: string;
  last_scanned_at?: string;
}

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled" | "stopped";
export type ScanProfile = "quick" | "standard" | "comprehensive" | "custom";

export interface ScanJob {
  id: string;
  website_id: string;
  website_name: string;
  target_url: string;
  domain: string;
  profile: ScanProfile;
  options?: Record<string, any>;
  status: ScanStatus;
  progress: number;
  current_stage: string;
  findings_count: number;
  security_score?: number;
  initiated_by: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface ScanEvent {
  id?: string;
  scan_id: string;
  stage_index: number;
  stage_name: string;
  message: string;
  progress: number;
  level: "info" | "warning" | "error";
  timestamp: string;
}

export type VulnerabilitySeverity = "critical" | "high" | "medium" | "low" | "info";
export type VulnerabilityStatus = "open" | "confirmed" | "in_progress" | "fixed" | "accepted_risk" | "false_positive" | "reopened";

export interface Vulnerability {
  id: string;
  title: string;
  vuln_type: string;
  severity: VulnerabilitySeverity;
  cvss_score: number;
  cwe_id: string;
  owasp_category: string;
  description: string;
  impact: string;
  remediation: string;
  evidence: string;
  affected_url: string;
  affected_domain: string;
  parameter?: string;
  confidence: "confirmed" | "high" | "medium" | "suspected" | "low";
  scanner_source: string;
  status: VulnerabilityStatus;
  website_id: string;
  last_scan_id: string;
  assigned_to?: string;
  comments?: Array<{
    id: string;
    user_id: string;
    user_name: string;
    comment: string;
    created_at: string;
  }>;
  created_at: string;
  last_observed_at: string;
}

export interface RemediationTask {
  id: string;
  vulnerability_id: string;
  vuln_title: string;
  severity: VulnerabilitySeverity;
  website_id: string;
  assigned_to: string;
  due_date: string;
  priority: "critical" | "high" | "medium" | "low";
  notes?: string;
  status: "in_progress" | "resolved" | "verified" | "closed";
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  website_name: string;
  domain: string;
  format: "pdf" | "html" | "json" | "csv";
  report_type: "detailed" | "executive";
  findings_count: number;
  security_score?: number;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  action: string;
  details: Record<string, any>;
  ip_address: string;
  created_at: string;
}
