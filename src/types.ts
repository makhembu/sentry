export type RuleSeverity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export type RuleStatus = 'active' | 'inactive' | 'draft';

export type IocType = 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'asn';

export interface RuleField {
  field: string;
  operator: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'matches' | 'gt' | 'lt' | 'in';
  value: string | string[] | number;
}

export interface RuleCondition {
  all?: RuleField[];
  any?: RuleField[];
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  status: RuleStatus;
  category: string;
  tactic?: string;
  technique?: string;
  iocTypes: IocType[];
  condition: RuleCondition;
  source?: string;
  references?: string[];
  tags: string[];
  falsePositives?: string[];
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  rule_id: string;
  rule_name: string;
  rule_severity: RuleSeverity;
  ioc_id: string;
  ioc_value: string;
  ioc_type: IocType;
  ioc_source: string;
  match_field: string;
  match_reason: string;
  confidence_at_match: number;
  created_at: string;
  acknowledged: number;
}

export interface MatchResult {
  rule: DetectionRule;
  matchedIocs: { ioc: string; field: string; reason: string }[];
  totalCandidates: number;
}

export interface RuleStats {
  total: number;
  active: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
}

export interface DashboardSummary {
  rules: RuleStats;
  findings: {
    total: number;
    open: number;
    bySeverity: Record<string, number>;
    topRules: { rule_name: string; count: number }[];
    recent: Finding[];
  };
  lastMatchRun: string | null;
}
