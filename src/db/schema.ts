const SCHEMA = `
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('informational','low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive','draft')),
  category TEXT NOT NULL DEFAULT 'other',
  tactic TEXT,
  technique TEXT,
  ioc_types TEXT NOT NULL DEFAULT '[]',
  condition_json TEXT NOT NULL DEFAULT '{}',
  source TEXT,
  references_json TEXT DEFAULT '[]',
  tags TEXT DEFAULT '[]',
  false_positives TEXT DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  rule_severity TEXT NOT NULL,
  ioc_id TEXT NOT NULL,
  ioc_value TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  ioc_source TEXT,
  match_field TEXT NOT NULL,
  match_reason TEXT NOT NULL,
  confidence_at_match REAL NOT NULL DEFAULT 0.5,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(rule_severity);
CREATE INDEX IF NOT EXISTS idx_findings_acknowledged ON findings(acknowledged);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);

CREATE TABLE IF NOT EXISTS match_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_at TEXT NOT NULL DEFAULT (datetime('now')),
  rules_matched INTEGER NOT NULL DEFAULT 0,
  findings_generated INTEGER NOT NULL DEFAULT 0,
  iocs_scanned INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0
);
`;

export function getSchema(): string {
  return SCHEMA;
}
